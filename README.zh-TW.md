<div align="center">

<img src="apps/desktop/src-tauri/icons/128x128.png" width="96" alt="ProxyDesk" />

# ProxyDesk

**只讓指定的程式與網域走代理的 Windows 分流客戶端**

[English](README.md) | 繁體中文

[![Release](https://img.shields.io/github/v/release/aliceric27/proxy-deck?include_prereleases&sort=semver)](https://github.com/aliceric27/proxy-deck/releases)
[![CI](https://github.com/aliceric27/proxy-deck/actions/workflows/ci.yml/badge.svg)](https://github.com/aliceric27/proxy-deck/actions/workflows/ci.yml)
[![Downloads](https://img.shields.io/github/downloads/aliceric27/proxy-deck/total)](https://github.com/aliceric27/proxy-deck/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
<br />
[![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011%20x64-0078D6?logo=windows&logoColor=white)](#安裝)
[![Tauri](https://img.shields.io/badge/Tauri-v2-24C8DB?logo=tauri&logoColor=white)](https://tauri.app)
[![sing-box](https://img.shields.io/badge/sing--box-1.14.2-4B5563)](https://github.com/SagerNet/sing-box)
[![Rust](https://img.shields.io/badge/Rust-stable-B7410E?logo=rust&logoColor=white)](https://www.rust-lang.org)
[![React](https://img.shields.io/badge/React-19-61DAFB?logo=react&logoColor=black)](https://react.dev)

</div>

---

Windows 桌面代理客戶端：從 Mudfish 取得 SOCKS5 節點，用 sing-box 的 TUN 模式讓**指定的應用程式或網域**走代理，其餘流量依 GeoIP 與 final 處理（預設直連）。

## 功能

- **依程式、網域分流**：一個群組可以同時包含程式、網域、規則集與 IP 範圍，各自指定出口（直接連線、阻擋、自動選擇或某個節點），並依優先順序比對。條件可設為「任一符合」或「全部符合」。
- **三種節點來源**：Mudfish 節點、產生的 Cloudflare WARP 節點，以及手動加入的 HTTP / SOCKS5 代理（例如 Webshare，可直接貼上 `http://帳號:密碼@主機:連接埠`）。
- **自動選擇**：加入多個 Mudfish 節點時挑延遲最低的一個。
- **匯入設定**：從「新增群組 → 匯入設定」貼上或選擇 JSON 檔，一次加入多個群組（ProxyDesk 群組、Karing 分流規則、sing-box 規則集或設定檔的路由規則）。
- **流量統計**：記錄每一次連線的上傳、下載用量，並依出口與程式分類。
- **即時切換**：多數出口變更不必重新連線。
- **帳密不落地**：Mudfish 帳號、WARP 私鑰與自訂節點帳密只存在 Windows 認證管理員，不寫進設定檔或日誌；產生的 sing-box 設定經 stdin 傳遞，不寫入磁碟。

> 介面目前只有繁體中文。

## 安裝

1. 到 [Releases](https://github.com/aliceric27/proxy-deck/releases) 下載 `ProxyDesk_<版本>_x64-setup.exe`。
2. 執行安裝程式。安裝程式沒有程式碼簽章，Windows SmartScreen 可能會攔下；確認來源後點「其他資訊 → 仍要執行」。
3. 每次開啟 ProxyDesk 都會跳出 UAC 提示：TUN 模式需要系統管理員權限。

需求：Windows 10 / 11 x64、WebView2（Windows 11 內建；Windows 10 由安裝程式自動下載）。使用 Mudfish 節點需要有餘額的 [Mudfish](https://mudfish.net) 帳號。

## 快速開始

1. **設定 → Mudfish 帳號**：輸入 Mudfish ID 與密碼，按「測試帳號」。測試只做 SOCKS5 認證，不會消耗流量。
2. **節點**：從左側清單勾選要用的 Mudfish 節點，也可以產生 WARP 節點或新增自訂節點。
3. **分流群組**：新增群組，加入要走代理的程式（例如 `game.exe`，會自動補上 `.exe`）或網域，出口選節點或「自動選擇」。
4. 按左下角的 **連線**。

## 分流方式

分流由上而下比對：自訂群組 → GeoIP → final。

- **自訂群組**：見上方「功能」。
- **GeoIP**：目的地 IP 屬於所選國家或地區（預設台灣）的流量，套用一個出口。
- **final**：以上都不符合的流量，套用一個出口（預設直接連線）。

GeoIP 與 final 是固定的群組，不能刪除或停用。它們在直接連線與節點之間切換時立即完整生效，不必重新連線；自訂群組在節點之間也是即時切換，但在直接連線與代理之間互換時，網域解析、QUIC 與 UDP 的部分規則要重新連線才會完整生效。改成或離開「阻擋」一律需要重新連線。全域模式另有自己的出口。

手動加入的節點不會參與「自動選擇」，要在群組或出口中直接選用。

Mudfish 節點清單每次開啟程式都會重新取得，已加入的 Mudfish 節點會跟著清單更新位址與名稱；連不到 Mudfish 時沿用上次的清單，節點頁會註明。

## 流量統計

「流量統計」頁記錄每一次連線（從按下連線到中斷或重新連線）的上傳、下載用量，以圖表呈現每次連線的用量、經代理與直連的比例、用量隨時間的變化，以及依出口（節點）與依程式的分布。縮到系統匣時也會記錄；紀錄存在資料夾的 `traffic-history.json`，保留最近 200 次，內容只有用量、時間、節點名稱與程式檔名，不含網址或 IP。

## 資料位置

| 內容 | 位置 |
|---|---|
| Mudfish 帳密 | Windows 認證管理員（`ProxyDesk` / `mudfish-account`） |
| 設定（不含密碼）、節點清單快取、流量紀錄 | `%APPDATA%\tw.proxydesk.desktop\` |
| WARP 私鑰與裝置 token | Windows 認證管理員（`ProxyDesk` / `node-<tag>`） |
| 手動加入節點的帳號密碼 | Windows 認證管理員（`ProxyDesk` / `node-<tag>`）；移除節點時一併刪除 |
| sing-box 工作目錄（cache.db），只有系統管理員能寫入。產生的設定（含帳密）經 stdin 傳給 sing-box，不寫入磁碟 | `%ProgramData%\ProxyDesk\run\` |

升級設定檔格式時，原檔會先備份在同一個資料夾，檔名為 `profile.v<舊版本>-backup.json`（已存在就不覆蓋）。升級後流量維持原樣，只有兩處小差異：

- 預設節點原本是「直接連線」時，全域模式會改成直連模式（同樣是所有流量直連）。
- 原本跟隨「直接連線」預設節點的群組，現在是直連群組，所以它原先設定的 UDP 策略不再生效（直連群組沒有 UDP 與 QUIC 規則）。

設定檔無法讀取（內容損壞，或被其他程式鎖住）時，有兩種結果：

- 能把原檔改名移開：原檔改名為 `profile.json.bad`（已存在就依序用 `.bad-2`、`.bad-3`，不會覆蓋），程式改用預設設定，並在畫面上方提示。
- 連改名都做不到（通常是檔案暫時被防毒軟體或其他程式占用）：ProxyDesk 會顯示錯誤並拒絕啟動，原檔完全不動，以免第一次儲存就把它蓋掉。關閉占用的程式後重新啟動即可。

## 從原始碼建置

- 介面：Tauri v2（Rust）+ React + Tailwind，桌面優先的佈局
- 核心：未修改的 sing-box 1.14.2，以獨立子程序執行（GPL-3.0，不連結）
- 規劃與決策紀錄：[`docs/PLAN.md`](docs/PLAN.md)

需要：Rust（stable，MSVC）、Visual Studio Build Tools（C++ 工作負載）、Node.js 22+、WebView2。

```powershell
pwsh -File scripts/fetch-singbox.ps1   # 下載 sing-box 並核對 SHA-256，放到 src-tauri/binaries/
cd apps/desktop
npm install
npm run tauri dev                       # 開發模式；TUN 需要系統管理員權限的終端機
npm run tauri build                     # 產出 target/release/bundle/nsis/ProxyDesk_<ver>_x64-setup.exe
```

app 的 manifest 要求系統管理員權限（v1 用這個方式取得 TUN 權限，見 PLAN §6.1）。從非系統管理員的終端機啟動時，會跳出 UAC 提示。

### 測試

```powershell
cargo test -p proxy-core                # 設定產生器與 Mudfish 清單解析
$env:SINGBOX_BIN = "apps\desktop\src-tauri\binaries\sing-box-x86_64-pc-windows-msvc.exe"
cargo test -p proxy-core                # 另外用真的 `sing-box check` 驗證產生的設定
cargo test --workspace                  # 含核心狀態機（假 launcher）與權限目錄測試（需系統管理員終端機），並重新產生前端型別
cd apps/desktop; npx tsc --noEmit       # 前端型別檢查
```

M0 驗證環境：`docker/m0/`（Linux 容器，見該目錄 README）與 `docs/m0-spike/windows/run-m0.ps1`（Windows 主機）。兩者都從專案根目錄的 `.env.local`（`MUDFISH_USER=` / `MUDFISH_PASS=`，不得提交）讀取帳密。

### 發布

推送 `v*` tag（例如 `v0.9.0`）後，GitHub Actions 會在 Windows 上建置 NSIS 安裝檔，並建立一個 **draft** Release 附上安裝檔；確認內容後再手動發布。

```powershell
git tag v0.9.0
git push origin v0.9.0
```

### 專案結構

```
crates/proxy-core/        設定模型（Profile）、Mudfish 清單解析、手動節點（連結解析）、群組匯入（JSON）、Profile → sing-box JSON（純邏輯，有單元測試）
apps/desktop/src-tauri/   Tauri 後端：sing-box 子程序管理、Clash API client、認證管理員、流量統計、系統匣
apps/desktop/src/         React 前端：總覽、節點、分流群組、連線、流量統計、日誌、設定
docker/m0/                M0 Docker 驗證環境
docs/                     PLAN.md 與 M0 驗證腳本
```

## 授權

ProxyDesk 以 [MIT](LICENSE) 授權釋出。

安裝檔內附未修改的 [sing-box](https://github.com/SagerNet/sing-box) 官方執行檔（GPL-3.0-or-later），以獨立程序執行，ProxyDesk 不與它連結；規則集等其他第三方元件與其授權見 [`THIRD_PARTY_NOTICES.txt`](apps/desktop/src-tauri/resources/THIRD_PARTY_NOTICES.txt)。

ProxyDesk 與 Mudfish、Cloudflare 沒有任何關係。
