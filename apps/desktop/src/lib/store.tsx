import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { api, errorText, events, type CoreStatus, type Profile, type Snapshot } from "./ipc";

export interface Toast {
  id: number;
  kind: "info" | "error" | "success";
  text: string;
}

interface AppContextValue {
  snapshot: Snapshot | null;
  profile: Profile | null;
  core: CoreStatus;
  /** Profile changed while connected; reconnect to apply. */
  needsApply: boolean;
  busy: boolean;
  updateProfile: (fn: (p: Profile) => Profile) => Promise<void>;
  /** Local-only update for changes the backend already persisted (selection, mode). */
  patchLocal: (fn: (p: Profile) => Profile) => void;
  connect: () => Promise<void>;
  disconnect: () => Promise<void>;
  refresh: () => Promise<void>;
  toast: (text: string, kind?: Toast["kind"]) => void;
  toasts: Toast[];
  dismissToast: (id: number) => void;
}

const AppContext = createContext<AppContextValue | null>(null);

export function AppProvider({ children }: { children: ReactNode }) {
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [core, setCore] = useState<CoreStatus>({ state: "stopped" });
  const [needsApply, setNeedsApply] = useState(false);
  const [busy, setBusy] = useState(false);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const toastId = useRef(0);

  const toast = useCallback((text: string, kind: Toast["kind"] = "info") => {
    const id = ++toastId.current;
    setToasts((t) => [...t, { id, kind, text }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), kind === "error" ? 8000 : 3500);
  }, []);
  const dismissToast = useCallback((id: number) => setToasts((t) => t.filter((x) => x.id !== id)), []);

  const refresh = useCallback(async () => {
    const s = await api.snapshot();
    setSnapshot(s);
    setCore(s.core);
  }, []);

  useEffect(() => {
    refresh().catch((e) => toast(errorText(e), "error"));
    const subs = [
      events.coreStatus((s) => {
        setCore(s);
        if (s.state === "running" || s.state === "stopped") setNeedsApply(false);
      }),
      events.coreError((m) => toast(m, "error")),
    ];
    return () => subs.forEach((p) => p.then((un) => un()));
  }, [refresh, toast]);

  // Latest snapshot for back-to-back updates that happen before a re-render.
  const snapshotRef = useRef(snapshot);
  snapshotRef.current = snapshot;

  const updateProfile = useCallback(
    async (fn: (p: Profile) => Profile) => {
      const current = snapshotRef.current;
      if (!current) return;
      const next = fn(current.profile);
      snapshotRef.current = { ...current, profile: next };
      setSnapshot(snapshotRef.current);
      try {
        const restart = await api.saveProfile(next);
        if (restart) setNeedsApply(true);
      } catch (e) {
        toast(errorText(e), "error");
        await refresh();
      }
    },
    [toast, refresh],
  );

  const patchLocal = useCallback((fn: (p: Profile) => Profile) => {
    const current = snapshotRef.current;
    if (!current) return;
    snapshotRef.current = { ...current, profile: fn(current.profile) };
    setSnapshot(snapshotRef.current);
  }, []);

  const connect = useCallback(async () => {
    setBusy(true);
    try {
      await api.start();
      setNeedsApply(false);
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
      needsApply,
      busy,
      updateProfile,
      patchLocal,
      connect,
      disconnect,
      refresh,
      toast,
      toasts,
      dismissToast,
    }),
    [snapshot, core, needsApply, busy, updateProfile, patchLocal, connect, disconnect, refresh, toast, toasts, dismissToast],
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
