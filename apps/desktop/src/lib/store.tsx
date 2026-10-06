import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { api, errorText, events, type CoreStatus, type Profile, type ProfileState, type Snapshot, type Traffic } from "./ipc";

export interface Toast {
  id: number;
  kind: "info" | "error" | "success";
  text: string;
}

interface AppContextValue {
  snapshot: Snapshot | null;
  profile: Profile | null;
  core: CoreStatus;
  /** From the backend: does the running core lag the profile, is the profile usable at all. */
  profileState: ProfileState;
  busy: boolean;
  /**
   * The single way to change the profile: applied locally at once, then saved in order.
   * The backend applies live-switchable choices to the running core itself.
   * Resolves to whether the save succeeded.
   */
  updateProfile: (fn: (p: Profile) => Profile) => Promise<boolean>;
  connect: () => Promise<void>;
  disconnect: () => Promise<void>;
  refresh: () => Promise<void>;
  toast: (text: string, kind?: Toast["kind"]) => void;
  toasts: Toast[];
  dismissToast: (id: number) => void;
}

const AppContext = createContext<AppContextValue | null>(null);

export function AppProvider({ children }: { children: ReactNode }) {
  const [snapshot, setSnapshotState] = useState<Snapshot | null>(null);
  const [core, setCore] = useState<CoreStatus>({ state: "stopped" });
  const [profileState, setProfileState] = useState<ProfileState>({ stale: false, invalid: null });
  const [busy, setBusy] = useState(false);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const toastId = useRef(0);

  const toast = useCallback((text: string, kind: Toast["kind"] = "info") => {
    const id = ++toastId.current;
    setToasts((t) => [...t, { id, kind, text }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), kind === "error" ? 8000 : 3500);
  }, []);
  const dismissToast = useCallback((id: number) => setToasts((t) => t.filter((x) => x.id !== id)), []);

  // The ref is the source of truth for back-to-back updates before a re-render; every write
  // goes through `setSnapshot` so the two never diverge.
  const snapshotRef = useRef<Snapshot | null>(null);
  const setSnapshot = useCallback((s: Snapshot) => {
    snapshotRef.current = s;
    setSnapshotState(s);
  }, []);
  // Saves run one after another, in the order the user made them.
  const saveChain = useRef<Promise<unknown>>(Promise.resolve());
  const pendingSaves = useRef(0);

  const refresh = useCallback(async () => {
    const s = await api.snapshot();
    // Keep the profile edits still on their way to the backend; take everything else.
    const current = snapshotRef.current;
    setSnapshot(pendingSaves.current > 0 && current ? { ...s, profile: current.profile } : s);
    setCore(s.core);
    setProfileState(s.state);
  }, [setSnapshot]);

  useEffect(() => {
    refresh().catch((e) => toast(errorText(e), "error"));
    const subs = [
      events.coreStatus((s) => {
        setCore(s);
        // Staleness depends on what the core runs; ask the backend again.
        api.snapshot().then((snap) => setProfileState(snap.state), () => {});
      }),
      events.coreError((m) => toast(m, "error")),
    ];
    return () => subs.forEach((p) => p.then((un) => un()));
  }, [refresh, toast]);

  const updateProfile = useCallback(
    (fn: (p: Profile) => Profile): Promise<boolean> => {
      const current = snapshotRef.current;
      if (!current) return Promise.resolve(false);
      const next = fn(current.profile);
      setSnapshot({ ...current, profile: next });
      pendingSaves.current++;
      const run = saveChain.current.then(async () => {
        try {
          setProfileState(await api.saveProfile(next));
          return true;
        } catch (e) {
          toast(errorText(e), "error");
          return false;
        } finally {
          pendingSaves.current--;
        }
      });
      saveChain.current = run;
      return run.then(async (ok) => {
        if (!ok) await refresh().catch(() => {});
        return ok;
      });
    },
    [toast, refresh, setSnapshot],
  );

  const connect = useCallback(async () => {
    setBusy(true);
    try {
      await saveChain.current; // start from what the user last chose
      await api.start();
    } catch (e) {
      toast(errorText(e), "error");
    } finally {
      setBusy(false);
    }
  }, [toast]);

  const disconnect = useCallback(async () => {
    setBusy(true);
    try {
      await api.stop();
    } catch (e) {
      toast(errorText(e), "error");
    } finally {
      setBusy(false);
    }
  }, [toast]);

  const value = useMemo<AppContextValue>(
    () => ({
      snapshot,
      profile: snapshot?.profile ?? null,
      core,
      profileState,
      busy,
      updateProfile,
      connect,
      disconnect,
      refresh,
      toast,
      toasts,
      dismissToast,
    }),
    [snapshot, core, profileState, busy, updateProfile, connect, disconnect, refresh, toast, toasts, dismissToast],
  );
  return <AppContext.Provider value={value}>{children}</AppContext.Provider>;
}

export function useApp(): AppContextValue {
  const v = useContext(AppContext);
  if (!v) throw new Error("useApp outside AppProvider");
  return v;
}

/** Runs `fn` every `ms` while `enabled`, immediately on enable. */
export function useInterval(fn: () => void, ms: number, enabled = true) {
  const ref = useRef(fn);
  ref.current = fn;
  useEffect(() => {
    if (!enabled) return;
    ref.current();
    const t = setInterval(() => ref.current(), ms);
    return () => clearInterval(t);
  }, [ms, enabled]);
}

/** Latest backend `traffic` sample while mounted; cleared when the core is not running. */
export function useTraffic(paused = false): Traffic | null {
  const { core } = useApp();
  const [traffic, setTraffic] = useState<Traffic | null>(null);
  const pausedRef = useRef(paused);
  pausedRef.current = paused;
  useEffect(() => {
    const un = events.traffic((t) => !pausedRef.current && setTraffic(t));
    return () => {
      un.then((f) => f());
    };
  }, []);
  useEffect(() => {
    if (core.state !== "running") setTraffic(null);
  }, [core.state]);
  return traffic;
}
