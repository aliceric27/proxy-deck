# Downloads the pinned rule-set snapshot (geosite / geoip / acl .srs files) into src-tauri/resources/rulesets/.
# Usage: pwsh -File scripts/fetch-rulesets.ps1
# The snapshot is taken from Karing's rule sets (https://github.com/KaringX/karing-ruleset, branch `sing`), which
# keeps no history, so it is pinned as an asset of this repo's `rulesets-<date>` release.
$ErrorActionPreference = 'Stop'

$snapshot = '20261006'
$zipSha256 = '7cbc89efa7e710a81006ee0eb31e0636611c462fd902459abfbe158a77f2358b'
$url = "https://github.com/aliceric27/proxy-deck/releases/download/rulesets-$snapshot/proxydesk-rulesets-$snapshot.zip"

$root = Resolve-Path "$PSScriptRoot\.."
$dest = Join-Path $root 'apps\desktop\src-tauri\resources\rulesets'
$tmp = Join-Path ([IO.Path]::GetTempPath()) "proxydesk-rulesets-$snapshot"
New-Item -ItemType Directory -Force $tmp | Out-Null

$zip = Join-Path $tmp "proxydesk-rulesets-$snapshot.zip"
Invoke-WebRequest $url -OutFile $zip
$actual = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
if ($actual -ne $zipSha256) { throw "SHA-256 mismatch: expected $zipSha256, got $actual" }

# Replace, not merge: a rule set dropped from the snapshot must not linger.
if (Test-Path $dest) { Remove-Item $dest -Recurse -Force }
Expand-Archive $zip -DestinationPath $dest
Remove-Item $tmp -Recurse -Force
Write-Host "rule sets $snapshot -> $dest ($((Get-ChildItem $dest -Recurse -File).Count) files)"
