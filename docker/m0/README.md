# M0 Docker 驗證環境

在 Linux 容器裡跑 sing-box 1.14.2（TUN 模式），連到真實的 Mudfish SOCKS5 節點，驗證分流規則、UDP、FakeIP 與 Clash API。容器內用 Linux 程序名稱（`curl`、`stunprobe`…）模擬 per-app 規則。

**這個環境攔截不到 Windows 主機上的程式流量**；Windows 專屬項目（`.exe` 比對、wintun、`pktmon` 洩漏測試）要在主機上用 `sing-box.exe` 驗證。

## 前置

專案根目錄要有 `.env.local`（不得提交）：

```
MUDFISH_USER=<Mudfish ID>
MUDFISH_PASS=<Mudfish 密碼>
```

帳密只在容器啟動時由 `entrypoint.sh` 填進 `/run/m0/config.json`（tmpfs），不會寫到主機。

## 指令

在 Git Bash 中，`docker compose exec` 前要加 `MSYS_NO_PATHCONV=1`，否則 `/m0/...` 路徑會被轉成 Windows 路徑。

```bash
cd docker/m0
docker compose up -d --build                                   # 建置並啟動
MSYS_NO_PATHCONV=1 docker compose exec -T m0 python3 /m0/tests.py   # 驗收測試
docker compose logs -f m0                                      # sing-box 日誌（debug 等級）
docker compose down                                            # 停止
```

改了 `config.template.json`、`tests.py` 等檔案後，要重新 `up -d --build`（檔案是 COPY 進 image 的）。

## 檔案

| 檔案 | 用途 |
|---|---|
| `config.template.json` | sing-box 設定；`${MUDFISH_USER}` 等變數由 `envsubst` 代入 |
| `entrypoint.sh` | 代入帳密 → `sing-box check` → `sing-box run`，日誌同時寫入 `/run/m0/sing-box.log` |
| `tests.py` | 驗收測試（PASS / FAIL / INFO） |
| `stun_probe.py` | 用 STUN 查詢 UDP 出口 IP |
| `rulesets/geosite/*.srs` | 從 Karing 複製的規則集，僅供開發期使用 |

`stunprobe`、`stunfallback` 是改名的 `python3` 執行檔，讓 `process_name` 規則能分別比對「UDP 走代理」和「UDP fallback 直連」兩種情境。
