import { useState, type ReactNode } from "react";
import { FolderOpen, KeyRound, LogOut } from "lucide-react";
import { api, errorText, type LogLevel } from "../lib/ipc";
import { useApp } from "../lib/store";
import { Badge, Button, Card, Input, PageHeader, Select, Toggle } from "../components/ui";

export default function Settings() {
  const { snapshot, profile, updateProfile, refresh, toast } = useApp();
  if (!snapshot || !profile) return null;

  return (
    <div className="flex h-full flex-col">
      <PageHeader title="設定" />
      <div className="min-h-0 flex-1 space-y-4 overflow-auto p-6">
        <AccountCard username={snapshot.username} onChanged={refresh} />

        <Card title="網路">
          <Row label="嚴格路由（strict_route）" hint="防止 Windows 多網卡 DNS 查詢繞過 TUN 造成洩漏。若 VirtualBox 等軟體異常可關閉。">
            <Toggle checked={profile.tun.strict_route} onChange={(v) => updateProfile((p) => ({ ...p, tun: { ...p.tun, strict_route: v } }))} />
          </Row>
          <Row label="區域網路直連" hint="私有 IP（192.168.x.x、10.x.x.x 等）一律直連，不經過代理。">
            <Toggle checked={profile.tun.bypass_lan} onChange={(v) => updateProfile((p) => ({ ...p, tun: { ...p.tun, bypass_lan: v } }))} />
          </Row>
          <Row label="走代理的網域使用 FakeIP" hint="讓 Mudfish 節點負責解析網域，避免本地 DNS 洩漏或解析到錯誤地區。關閉後改由經代理的 DoH 解析，但連線只會帶 IP 給節點。">
            <Toggle checked={profile.dns.fakeip} onChange={(v) => updateProfile((p) => ({ ...p, dns: { ...p.dns, fakeip: v } }))} />
          </Row>
          <Row label="只使用 IPv4（建議）" hint="Mudfish 節點只支援 IPv4。程式若選用 IPv6 位址，走代理的連線會被節點中斷，所以 DNS 只回傳 IPv4。只有在需要直連 IPv6 專用網站時才關閉。">
            <Toggle checked={profile.dns.ipv4_only} onChange={(v) => updateProfile((p) => ({ ...p, dns: { ...p.dns, ipv4_only: v } }))} />
          </Row>
          <Row label="阻擋走代理網域的 QUIC" hint="讓瀏覽器對這些網域改用 TCP，確保經過代理。">
            <Toggle
              checked={profile.dns.block_quic_for_proxied}
              onChange={(v) => updateProfile((p) => ({ ...p, dns: { ...p.dns, block_quic_for_proxied: v } }))}
            />
          </Row>
          <Row label="TUN MTU" hint="預設 9000。遇到特定網站無法連線時可試著改成 1500。" last>
            <Input
              type="number"
              min={1280}
              max={65535}
              className="w-28 text-right"
              defaultValue={profile.tun.mtu}
              onBlur={(e) => {
                const mtu = Math.min(65535, Math.max(1280, Number(e.target.value) || 9000));
                e.target.value = String(mtu);
                if (mtu !== profile.tun.mtu) updateProfile((p) => ({ ...p, tun: { ...p.tun, mtu } }));
              }}
            />
          </Row>
        </Card>

        <Card title="日誌">
          <Row label="sing-box 日誌等級" hint="「資訊」會記錄每一條連線與 DNS 查詢，適合排查分流問題；平常用「警告」即可。重新連線後生效。" last>
            <Select
              label="日誌等級"
              value={profile.log_level}
              onChange={(v: LogLevel) => updateProfile((p) => ({ ...p, log_level: v }))}
              className="w-28"
              options={[
                { value: "error", label: "錯誤" },
                { value: "warn", label: "警告" },
                { value: "info", label: "資訊" },
                { value: "debug", label: "除錯" },
              ]}
            />
          </Row>
        </Card>

        <Card title="關於">
          <Row label="ProxyDesk" hint="關閉視窗時會縮到系統匣繼續運作；要完全結束請從系統匣選單選「結束 ProxyDesk」。">
            <Badge>v{snapshot.version}</Badge>
          </Row>
          <Row label="權限" hint="建立 TUN 介面卡需要系統管理員權限。">
            <Badge tone={snapshot.elevated ? "ok" : "danger"}>{snapshot.elevated ? "系統管理員" : "一般使用者"}</Badge>
          </Row>
          <Row label="資料資料夾" hint="profile.json（設定，不含密碼）與節點清單快取。">
            <Button size="sm" icon={<FolderOpen size={12} />} onClick={() => api.openDataDir().catch((e) => toast(errorText(e), "error"))}>
              開啟
            </Button>
          </Row>
          <Row label="第三方元件" hint="內含未修改的 sing-box 1.14.2（GPL-3.0，以獨立程式執行）與 geosite / geoip / ACL4SSR 規則集。詳見安裝目錄的 THIRD_PARTY_NOTICES.txt。" last>
            <span />
          </Row>
        </Card>
      </div>
    </div>
  );
}

function Row({ label, hint, children, last }: { label: string; hint?: string; children: ReactNode; last?: boolean }) {
  return (
    <div className={`flex items-center justify-between gap-6 px-4 py-3 ${last ? "" : "border-b border-border"}`}>
      <div className="min-w-0">
        <div className="text-[13px]">{label}</div>
        {hint && <div className="mt-0.5 text-[11px] leading-relaxed text-muted">{hint}</div>}
      </div>
      <div className="shrink-0">{children}</div>
    </div>
  );
}

function AccountCard({ username, onChanged }: { username: string | null; onChanged: () => Promise<void> }) {
  const { toast } = useApp();
  const [editing, setEditing] = useState(!username);
  const [user, setUser] = useState(username ?? "");
  const [pass, setPass] = useState("");
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);

  const save = async () => {
    setSaving(true);
    try {
      await api.setCredentials(user, pass);
      setPass("");
      setEditing(false);
      await onChanged();
      toast("已儲存 Mudfish 帳號", "success");
    } catch (e) {
      toast(errorText(e), "error");
    } finally {
      setSaving(false);
    }
  };

  /** Auth only, so it costs no traffic. Mudfish answers a wrong password and an account without credit the same way. */
  const verify = async () => {
    setTesting(true);
    try {
      const result = await api.verifyAccount();
      if (result === "usable") toast("帳號可用（已通過節點認證）", "success");
      else if (result === "unusable") toast("帳號無法使用：密碼錯誤，或 Mudfish 餘額不足。兩者的回應相同，請一併確認密碼與餘額。", "error");
      else toast("目前連不到任何節點，無法測試，請稍後再試。", "error");
    } catch (e) {
      toast(errorText(e), "error");
    } finally {
      setTesting(false);
    }
  };

  const clear = async () => {
    try {
      await api.clearCredentials();
      setUser("");
      setEditing(true);
      await onChanged();
    } catch (e) {
      toast(errorText(e), "error");
    }
  };

  return (
    <Card title="Mudfish 帳號">
      <div className="space-y-3 px-4 py-3">
        <p className="text-[11px] leading-relaxed text-muted">
          Mudfish 的 SOCKS5 以帳號 ID 與密碼認證。帳密只存在 Windows 認證管理員，不會寫進設定檔或日誌。
        </p>
        {editing ? (
          <form
            className="flex items-end gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              save();
            }}
          >
            <label className="flex-1 space-y-1">
              <span className="text-xs font-medium">Mudfish ID</span>
              <Input className="w-full" autoComplete="username" value={user} onChange={(e) => setUser(e.target.value)} />
            </label>
            <label className="flex-1 space-y-1">
              <span className="text-xs font-medium">密碼</span>
              <Input className="w-full" type="password" autoComplete="current-password" value={pass} onChange={(e) => setPass(e.target.value)} />
            </label>
            <Button type="submit" variant="primary" disabled={saving || !user.trim() || !pass} icon={<KeyRound size={14} />}>
              儲存
            </Button>
            {username && (
              <Button type="button" variant="ghost" onClick={() => setEditing(false)}>
                取消
              </Button>
            )}
          </form>
        ) : (
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Badge tone="ok">已設定</Badge>
              <span className="font-medium">{username}</span>
            </div>
            <div className="flex gap-2">
              <Button size="sm" disabled={testing} onClick={verify}>
                {testing ? "測試中…" : "測試帳號"}
              </Button>
              <Button size="sm" onClick={() => setEditing(true)}>
                變更
              </Button>
              <Button size="sm" variant="danger" icon={<LogOut size={12} />} onClick={clear}>
                移除
              </Button>
            </div>
          </div>
        )}
      </div>
    </Card>
  );
}
