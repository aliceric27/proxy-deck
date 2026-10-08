import { useEffect, useRef, useState } from "react";
import { FileJson, Loader2 } from "lucide-react";
import { api, errorText, type RuleGroup } from "../lib/ipc";
import { useApp } from "../lib/store";
import { newId } from "../lib/format";
import { Badge, Button, cx, Modal } from "./ui";
import { MatcherSummary, matcherPreview, OutboundSelect } from "./groups";

/** Mirrors `import::MAX_IMPORT_BYTES`: longer lists belong in a built-in rule set. */
const MAX_BYTES = 5 * 1024 * 1024;

const PLACEHOLDER = `例如群組編輯器「複製 JSON」的內容：
{
  "name": "遊戲",
  "process_names": ["game.exe"],
  "domain_suffixes": ["example.com"]
}`;

/** A parsed group: its fresh id and outbound (changeable here) are already in `group`. */
type Row = { group: RuleGroup; notes: string[]; picked: boolean };
type Parsed = { format: string; notes: string[]; rows: Row[] };

/**
 * 「新增群組 → 匯入設定」: pasted or uploaded JSON becomes groups. The backend reads and checks it
 * (`parse_group_import`); nothing is stored until「加入」puts the picked groups at the top of the
 * list through `updateProfile`.
 */
export function GroupImportDialog({ onClose, onImported }: { onClose: () => void; onImported: (ids: string[]) => void }) {
  const { profile, updateProfile, toast } = useApp();
  const [text, setText] = useState("");
  /** The uploaded file's name without its extension: it names a group the JSON leaves unnamed. */
  const [fileName, setFileName] = useState<string | null>(null);
  const [parsed, setParsed] = useState<Parsed | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [parsing, setParsing] = useState(false);
  const [saving, setSaving] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);

  // Parsed once the text settles; an answer for an older text is dropped. The last preview stays
  // up meanwhile, but cannot be added until the new answer replaces it.
  useEffect(() => {
    if (!text.trim()) {
      setParsed(null);
      setError(null);
      setParsing(false);
      return;
    }
    let current = true;
    setParsing(true);
    const timer = setTimeout(() => {
      api.parseGroupImport(text, fileName).then(
        (r) => {
          if (!current) return;
          // The ids are fixed per parse, so retrying after a failed save replaces instead of adding twice.
          setParsed({ format: r.format, notes: r.notes, rows: r.groups.map((g) => ({ group: { ...g.group, id: newId() }, notes: g.notes, picked: true })) });
          setError(null);
          setParsing(false);
        },
        (e) => {
          if (!current) return;
          setParsed(null);
          setError(errorText(e));
          setParsing(false);
        },
      );
    }, 300);
    return () => {
      current = false;
      clearTimeout(timer);
    };
  }, [text, fileName]);

  if (!profile) return null;

  const rows = parsed?.rows ?? [];
  const chosen = rows.filter((r) => r.picked);
  const disabled = chosen.filter((r) => !r.group.enabled).length;
  const setRow = (i: number, p: Partial<Row>) => setParsed((s) => s && { ...s, rows: s.rows.map((r, j) => (j === i ? { ...r, ...p } : r)) });
  const setAll = (picked: boolean) => setParsed((s) => s && { ...s, rows: s.rows.map((r) => ({ ...r, picked })) });

  const onFile = async (file: File | undefined) => {
    if (!file) return;
    if (file.size > MAX_BYTES) return toast("檔案超過 5 MB。大型清單請改用內建規則集。", "error");
    try {
      const content = await file.text();
      setFileName(file.name.replace(/\.[^.]*$/, "") || null);
      setText(content);
    } catch (e) {
      toast(errorText(e), "error");
    }
  };

  const add = async () => {
    const groups = chosen.map((r) => r.group);
    const mine = new Set(rows.map((r) => r.group.id));
    setSaving(true);
    const ok = await updateProfile((p) => ({ ...p, groups: [...groups, ...p.groups.filter((g) => !mine.has(g.id))] }));
    setSaving(false);
    if (!ok) return; // updateProfile has said why; the dialog stays for a retry
    toast(`已匯入 ${groups.length} 個群組，放在列表最上面（最優先），可以拖曳調整順序。`, "success");
    onImported(groups.map((g) => g.id));
  };

  const status = error ?? (parsing ? "解析中…" : parsed ? `辨識為「${parsed.format}」，找到 ${rows.length} 個群組。` : null);

  return (
    <Modal
      title="匯入群組設定"
      width={680}
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>取消</Button>
          <Button variant="primary" disabled={!chosen.length || parsing || saving} onClick={add} icon={saving ? <Loader2 size={14} className="animate-spin" /> : undefined}>
            {chosen.length ? `加入 ${chosen.length} 個群組` : "加入"}
          </Button>
        </>
      }
    >
      <div className="space-y-3 px-4 py-3">
        <div className="flex items-center justify-between gap-2">
          <span className="text-xs font-medium">貼上 JSON{fileName && <span className="font-normal text-muted">（已載入「{fileName}」）</span>}</span>
          <Button size="sm" icon={<FileJson size={12} />} onClick={() => fileInput.current?.click()}>
            選擇 JSON 檔…
          </Button>
          <input
            ref={fileInput}
            type="file"
            accept=".json,application/json"
            className="hidden"
            onChange={(e) => {
              onFile(e.target.files?.[0]);
              e.target.value = ""; // the same file can be picked again
            }}
          />
        </div>
        <textarea
          aria-label="JSON 內容"
          value={text}
          autoFocus
          spellCheck={false}
          onChange={(e) => {
            setText(e.target.value);
            if (!e.target.value.trim()) setFileName(null); // emptied: the file is gone
          }}
          placeholder={PLACEHOLDER}
          className="h-40 w-full resize-y rounded-md border border-border bg-surface px-2.5 py-2 font-mono text-xs placeholder:text-muted focus:border-accent focus:outline-none"
        />
        <p className={cx("text-[11px] leading-relaxed", error ? "text-danger" : "text-muted")}>
          {status ?? "可匯入 ProxyDesk 群組（群組編輯器的「複製 JSON」，一個或多個）、Karing 分流規則與預設檔，以及 sing-box 規則集（source 格式）或設定檔的路由規則。"}
        </p>

        {parsed && (
          <div className="space-y-2">
            {parsed.notes.map((n) => (
              <p key={n} className="text-[11px] leading-relaxed text-warn">
                {n}
              </p>
            ))}
            <div className="flex items-center justify-between gap-2 text-xs">
              <label className="flex items-center gap-2 font-medium">
                <input type="checkbox" checked={chosen.length === rows.length} onChange={(e) => setAll(e.target.checked)} className="h-3.5 w-3.5 accent-[var(--accent)]" />
                要加入的群組（{chosen.length} / {rows.length}）
              </label>
              <span className="text-[11px] text-muted">出口可以先在這裡選好</span>
            </div>
            <ul className="max-h-72 divide-y divide-border overflow-auto rounded-md border border-border">
              {rows.map((r, i) => (
                <li key={r.group.id} className={cx("flex items-start gap-3 px-3 py-2", !r.picked && "opacity-55")}>
                  <input
                    type="checkbox"
                    checked={r.picked}
                    onChange={(e) => setRow(i, { picked: e.target.checked })}
                    aria-label={`加入「${r.group.name}」`}
                    className="mt-1 h-3.5 w-3.5 shrink-0 accent-[var(--accent)]"
                  />
                  <div className="min-w-0 flex-1 space-y-0.5">
                    <div className="flex items-center gap-2">
                      <span className="truncate font-medium">{r.group.name}</span>
                      <MatcherSummary group={r.group} />
                      {!r.group.enabled && <Badge>停用</Badge>}
                    </div>
                    <div className="truncate font-mono text-[11px] text-muted" title={matcherPreview(r.group, 30)}>
                      {matcherPreview(r.group)}
                    </div>
                    {r.notes.map((n) => (
                      <p key={n} className="text-[11px] leading-relaxed text-warn">
                        {n}
                      </p>
                    ))}
                  </div>
                  <OutboundSelect profile={profile} value={r.group.outbound} onChange={(outbound) => setRow(i, { group: { ...r.group, outbound } })} className="w-44 shrink-0" />
                </li>
              ))}
            </ul>
            <p className="text-[11px] leading-relaxed text-muted">
              匯入的群組會放在列表最上面（最優先）。{disabled > 0 && `其中 ${disabled} 個原本是停用的，匯入後維持停用，可以在列表中開啟。`}
            </p>
          </div>
        )}
      </div>
    </Modal>
  );
}
