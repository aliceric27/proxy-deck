import { useEffect, useRef, useState, type ReactNode } from "react";
import { Loader2 } from "lucide-react";
import { api, errorText, type CustomNodeInput, type ProxyNode, type ProxyProtocol } from "../lib/ipc";
import { useApp } from "../lib/store";
import { Button, cx, Input, Modal, Segmented } from "./ui";

const FORM_ID = "custom-node-form";

function Field({ label, children, className }: { label: string; children: ReactNode; className?: string }) {
  return (
    <label className={cx("block", className)}>
      <span className="mb-1 block text-xs font-medium">{label}</span>
      {children}
    </label>
  );
}

/**
 * Adds (no `node`) or edits a hand-added HTTP/SOCKS5 node. The node goes into the profile through
 * `updateProfile` first; its account is stored afterwards, and only if the profile then holds
 * exactly that node, so a failed save never leaves an account that disagrees with the profile.
 */
export function CustomNodeDialog({ node, onClose }: { node?: ProxyNode; onClose: () => void }) {
  const { updateProfile, toast, core } = useApp();
  const tag = node?.tag;
  /** The node's tag once it is in the profile: the edited one, or a new one after its first save, so a retry edits it instead of adding it twice. */
  const [savedTag, setSavedTag] = useState(tag);
  const [link, setLink] = useState("");
  const [linkError, setLinkError] = useState<string | null>(null);
  const [name, setName] = useState(node?.name ?? "");
  const [protocol, setProtocol] = useState<ProxyProtocol>(node?.custom?.protocol ?? "http");
  const [server, setServer] = useState(node?.server ?? "");
  const [port, setPort] = useState(node ? String(node.port) : "");
  const [udp, setUdp] = useState(node?.udp ?? false);
  const [username, setUsername] = useState("");
  /** Editing: the stored username (`""`: no authentication); `undefined` while loading, `null` when there is no readable account. */
  const [storedUsername, setStoredUsername] = useState<string | null | undefined>(node ? undefined : null);
  /** `null` keeps the stored password. A pasted link's empty password is an explicit "none". */
  const [password, setPassword] = useState<string | null>(node ? null : "");
  const [saving, setSaving] = useState(false);
  const parseSeq = useRef(0);

  // Editing: the stored username fills in; the password stays in Credential Manager.
  useEffect(() => {
    if (!tag) return;
    const missing = () => {
      setStoredUsername(null);
      setPassword((p) => p ?? ""); // nothing stored to keep
    };
    api.customNodeUsername(tag).then((u) => {
      if (u === null) return missing();
      setStoredUsername(u);
      setUsername((typed) => typed || u); // a link pasted meanwhile wins
    }, missing);
  }, [tag]);

  const loadingAccount = storedUsername === undefined;
  const canKeepPassword = typeof storedUsername === "string";
  const portValid = /^\d{1,5}$/.test(port) && Number(port) >= 1 && Number(port) <= 65535;
  const canSave = !saving && !loadingAccount && server.trim() !== "" && portValid;

  /** A pasted link fills in the fields; only the latest answer counts while typing. */
  const onLink = async (text: string) => {
    setLink(text);
    const seq = ++parseSeq.current;
    if (!text.trim()) {
      setLinkError(null);
      return;
    }
    try {
      const l = await api.parseProxyLink(text);
      if (seq !== parseSeq.current) return;
      setProtocol(l.protocol);
      setServer(l.server);
      setPort(String(l.port));
      setUsername(l.username);
      setPassword(l.password);
      setLinkError(null);
    } catch (e) {
      if (seq === parseSeq.current) setLinkError(errorText(e));
    }
  };

  const save = async () => {
    setSaving(true);
    const input: CustomNodeInput = {
      name: name.trim(),
      protocol,
      server: server.trim(),
      port: Number(port),
      udp: protocol === "socks5" && udp,
      username: username.trim(),
      password,
    };
    try {
      const built = await api.customNodeBuild(savedTag ?? null, input);
      const ok = await updateProfile((p) => ({
        ...p,
        nodes: p.nodes.some((n) => n.tag === built.tag) ? p.nodes.map((n) => (n.tag === built.tag ? built : n)) : [...p.nodes, built],
      }));
      if (ok) setSavedTag(built.tag);
      // Asked even after a failed save, which may still have written the profile (only the live
      // apply failed): the backend stores the account exactly when the profile holds this node.
      const stored = await api.customNodeStoreAuth(built.tag, input).then(
        () => true,
        (e) => {
          if (ok) toast(`節點已儲存，但帳號密碼沒有存進認證管理員：${errorText(e)}`, "error");
          return false;
        },
      );
      if (!stored) return;
      if (!node) {
        toast(`已加入「${built.name}」。自訂節點不會加入「自動選擇」，請在群組、GeoIP、final 或全域模式中直接選用。`, "success");
      } else {
        // The account is not part of what decides a reconnect, so say it here.
        const accountChanged = password !== null || username.trim() !== (storedUsername ?? "");
        toast(`已更新「${built.name}」${accountChanged && core.state === "running" ? "。帳號密碼的變更要重新連線才會生效。" : ""}`, "success");
      }
      onClose();
    } catch (e) {
      toast(errorText(e), "error");
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal
      title={node ? `編輯「${node.name}」` : "新增自訂節點"}
      width={520}
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>取消</Button>
          <Button type="submit" form={FORM_ID} variant="primary" disabled={!canSave} icon={saving ? <Loader2 size={14} className="animate-spin" /> : undefined}>
            {node ? "儲存" : "加入"}
          </Button>
        </>
      }
    >
      <form
        id={FORM_ID}
        className="space-y-3 px-4 py-3"
        onSubmit={(e) => {
          e.preventDefault();
          if (canSave) save();
        }}
      >
        <Field label="代理連結（選填）">
          <Input
            className="w-full font-mono"
            value={link}
            autoFocus={!node}
            spellCheck={false}
            autoComplete="off"
            placeholder="http://帳號:密碼@主機:連接埠、socks5://…，或 主機:連接埠:帳號:密碼"
            onChange={(e) => onLink(e.target.value)}
          />
          <span className={linkError ? "mt-1 block text-[11px] text-danger" : "mt-1 block text-[11px] text-muted"}>
            {linkError ?? "貼上後會自動填入下方欄位，也可以直接手動填寫。"}
          </span>
        </Field>

        <Field label="名稱">
          <Input className="w-full" value={name} autoFocus={!!node} placeholder={server.trim() ? `${server.trim()}:${port}` : "例如 Webshare US"} onChange={(e) => setName(e.target.value)} />
        </Field>

        <div>
          <span className="mb-1 block text-xs font-medium">協定</span>
          <Segmented<ProxyProtocol>
            value={protocol}
            onChange={setProtocol}
            options={[
              { value: "http", label: "HTTP", hint: "HTTP CONNECT 代理，只轉送 TCP" },
              { value: "socks5", label: "SOCKS5" },
            ]}
          />
        </div>

        <div className="flex gap-2">
          <Field label="伺服器" className="flex-1">
            <Input className="w-full font-mono" value={server} spellCheck={false} autoComplete="off" placeholder="IP 或主機名稱" onChange={(e) => setServer(e.target.value)} />
          </Field>
          <Field label="連接埠" className="w-28">
            <Input className="w-full font-mono" value={port} inputMode="numeric" autoComplete="off" placeholder="1–65535" onChange={(e) => setPort(e.target.value.trim())} />
          </Field>
        </div>

        <div className="flex gap-2">
          <Field label="使用者名稱" className="flex-1">
            <Input
              className="w-full"
              value={username}
              spellCheck={false}
              autoComplete="off"
              placeholder={loadingAccount ? "讀取中…" : "不需認證可留空"}
              onChange={(e) => setUsername(e.target.value)}
            />
          </Field>
          <Field label="密碼" className="flex-1">
            <Input
              className="w-full"
              type="password"
              value={password ?? ""}
              autoComplete="new-password"
              placeholder={canKeepPassword ? (password === null ? "留空表示不變更" : "無密碼") : ""}
              // Clearing the field while editing goes back to keeping the stored password.
              onChange={(e) => setPassword(e.target.value === "" && canKeepPassword ? null : e.target.value)}
            />
          </Field>
        </div>
        {node && storedUsername === null && (
          <p className="text-[11px] text-warn">認證管理員裡找不到這個節點的帳號密碼，請重新輸入；不需認證就留空。</p>
        )}

        {protocol === "socks5" ? (
          <label className="flex items-center gap-2 text-[13px]">
            <input type="checkbox" checked={udp} onChange={(e) => setUdp(e.target.checked)} className="h-3.5 w-3.5 accent-[var(--accent)]" />
            轉送 UDP（供應商要支援 SOCKS5 UDP，Webshare 不支援）
          </label>
        ) : (
          <p className="text-[11px] text-muted">HTTP 代理只轉送 TCP。</p>
        )}

        <p className="rounded-md bg-surface-2 px-3 py-2 text-[11px] leading-relaxed text-muted">
          帳號密碼只存在 Windows 認證管理員，不會寫進設定檔或日誌。自訂節點不會加入「自動選擇」，要在群組、GeoIP、final 或全域模式中直接選用。只轉送 TCP 的節點無法傳遞 UDP，遊戲等 UDP 流量請把群組的 UDP 設為直連或阻擋。
        </p>
      </form>
    </Modal>
  );
}
