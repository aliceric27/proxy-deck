# Downloads the pinned sing-box release and installs it as the Tauri sidecar.
# Usage: pwsh -File scripts/fetch-singbox.ps1
$ErrorActionPreference = 'Stop'

$version = '1.14.2'
# SHA-256 of sing-box-1.14.2-windows-amd64.zip (upstream publishes no checksum file; recorded on first download).
$zipSha256 = 'c2d8bfff918755808781dfdeeb8581b6c91eb3a243d9a7b55483cfc0c0684d32'

$root = Resolve-Path "$PSScriptRoot\.."
$dest = Join-Path $root 'apps\desktop\src-tauri\binaries\sing-box-x86_64-pc-windows-msvc.exe'
$tmp = Join-Path ([IO.Path]::GetTempPath()) "proxydesk-singbox-$version"
New-Item -ItemType Directory -Force $tmp, (Split-Path $dest) | Out-Null

$zip = Join-Path $tmp "sing-box-$version-windows-amd64.zip"
Invoke-WebRequest "https://github.com/SagerNet/sing-box/releases/download/v$version/sing-box-$version-windows-amd64.zip" -OutFile $zip
$actual = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
if ($actual -ne $zipSha256) { throw "SHA-256 mismatch: expected $zipSha256, got $actual" }

Expand-Archive $zip -DestinationPath $tmp -Force
# libcronet.dll is only needed by the naive outbound, which ProxyDesk does not use.
Copy-Item (Join-Path $tmp "sing-box-$version-windows-amd64\sing-box.exe") $dest -Force
Remove-Item $tmp -Recurse -Force
Write-Host "sing-box $version -> $dest"
