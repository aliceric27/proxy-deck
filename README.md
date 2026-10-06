# ProxyDesk

Windows 桌面代理客戶端：從 Mudfish 取得 SOCKS5 節點，用 sing-box 的 TUN 模式讓**指定的應用程式或網域**走代理，其他流量直連。

分流以「群組」為單位：一個群組可以同時包含程式、網域、規則集與 IP 範圍，各自指定出口節點，並依優先順序比對。

- 介面：Tauri v2（Rust）+ React + Tailwind，桌面優先的佈局
- 核心：未修改的 sing-box 1.14.2，以獨立子程序執行（GPL-3.0，不連結）
- 規劃與決策紀錄：[`docs/PLAN.md`](docs/PLAN.md)

## 開發環境（Windows）

需要：Rust（stable，MSVC）、Visual Studio Build Tools（C++ 工作負載）、Node.js 22+、WebView2。

```powershell
pwsh -File scripts/fetch-singbox.ps1   # 下載 sing-box 並核對 SHA-256，放到 src-tauri/binaries/
cd apps/desktop
npm install
npm run tauri dev                       # 開發模式；TUN 需要系統管理員權限的終端機
npm run tauri build                     # 產出 target/release/bundle/nsis/ProxyDesk_<ver>_x64-setup.exe
```

app 的 manifest 要求系統管理員權限（v1 用這個方式取得 TUN 權限，見 PLAN §6.1）。從非系統管理員的終端機啟動時，會跳出 UAC 提示。

## 測試

```powershell
cargo test -p proxy-core                # 設定產生器與 Mudfish 清單解析
$env:SINGBOX_BIN = "apps\desktop\src-tauri\binaries\sing-box-x86_64-pc-windows-msvc.exe"
cargo test -p proxy-core                # 另外用真的 `sing-box check` 驗證產生的設定
cd apps/desktop; npx tsc --noEmit       # 前端型別檢查
```

M0 驗證環境：`docker/m0/`（Linux 容器，見該目錄 README）與 `docs/m0-spike/windows/run-m0.ps1`（Windows 主機）。兩者都從專案根目錄的 `.env.local`（`MUDFISH_USER=` / `MUDFISH_PASS=`，不得提交）讀取帳密。

## 專案結構

```
crates/proxy-core/        設定模型（Profile）、Mudfish 清單解析、Profile → sing-box JSON（純邏輯，有單元測試）
apps/desktop/src-tauri/   Tauri 後端：sing-box 子程序管理、Clash API client、認證管理員、系統匣
apps/desktop/src/         React 前端：總覽、節點、分流規則、連線、日誌、設定
docker/m0/                M0 Docker 驗證環境
docs/                     PLAN.md 與 M0 驗證腳本
```

## 資料位置

| 內容 | 位置 |
|---|---|
| Mudfish 帳密 | Windows 認證管理員（`ProxyDesk` / `mudfish-account`） |
| 設定（不含密碼）、節點清單快取 | `%APPDATA%\tw.proxydesk.desktop\` |
| 產生的 sing-box 設定（含帳密，只在連線期間存在；沿用使用者資料夾的預設權限：本人、SYSTEM、系統管理員）、cache.db | `%LOCALAPPDATA%\tw.proxydesk.desktop\run\` |
