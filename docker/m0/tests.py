"""M0 acceptance checks, run inside the container: docker compose exec m0 python3 /m0/tests.py

python3 itself matches no process rule, so its own traffic goes direct (unless a domain rule applies).
"""
import json
import os
import re
import socket
import subprocess
import time
import urllib.request

API = "http://127.0.0.1:19090"
SECRET = os.environ.get("CLASH_SECRET", "m0-dev-secret")
NODES = {"mudfish-tw-1": "35.236.137.214", "mudfish-jp-1": "47.74.24.154"}
LOG = "/run/m0/sing-box.log"
results = []


def record(status, name, detail=""):
    results.append(status)
    print(f"[{status}] {name}" + (f" — {detail}" if detail else ""), flush=True)


def check(name, ok, detail=""):
    record("PASS" if ok else "FAIL", name, detail)


def api(method, path, body=None):
    req = urllib.request.Request(API + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": f"Bearer {SECRET}", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as r:
        raw = r.read()
        return json.loads(raw) if raw else None


def fetch(url, timeout=15):
    req = urllib.request.Request(url, headers={"User-Agent": "curl/8"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode().strip()


def sh(*cmd, timeout=30):
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return p.stdout.strip() or p.stderr.strip()


def log_since(offset):
    with open(LOG, encoding="utf-8", errors="replace") as f:
        f.seek(offset)
        return f.read()


def log_size():
    return os.path.getsize(LOG)


def section(title):
    print(f"\n== {title}", flush=True)


def main():
    section("基本")
    ver = api("GET", "/version")
    check("Clash API /version", bool(ver), json.dumps(ver))
    direct_ip = fetch("https://api.ipify.org")
    check("python3（無規則）直連", direct_ip not in NODES.values(), f"出口 {direct_ip}")

    section("per-app（process_name）")
    ip = sh("curl", "-s", "-m", "15", "https://api.ipify.org")
    check("curl 走代理（auto）", ip in NODES.values(), f"出口 {ip}")

    for tag, node_ip in NODES.items():
        api("PUT", "/proxies/proxy", {"name": tag})
        ip = sh("curl", "-s", "-m", "15", "https://api.ipify.org")
        check(f"Clash API 切換到 {tag}，不重啟", ip == node_ip, f"出口 {ip}")
    api("PUT", "/proxies/proxy", {"name": "mudfish-tw-1"})

    section("per-domain + FakeIP")
    a = sh("dig", "+short", "ifconfig.me", "A", "@1.1.1.1")
    check("ifconfig.me 的 A 記錄回 FakeIP", re.match(r"^198\.1[89]\.", a or "") is not None, a)
    ip = fetch("https://ifconfig.me/ip")
    check("python3 連 ifconfig.me 走代理（domain_suffix）", ip == NODES["mudfish-tw-1"], f"出口 {ip}")
    a = sh("dig", "+short", "api.ipify.org", "A", "@1.1.1.1")
    check("非代理網域回真實 IP", re.match(r"^198\.1[89]\.", a.splitlines()[0] if a else "") is None, a.replace("\n", ", "))

    section("UDP")
    ip = sh("stunprobe", "/m0/stun_probe.py", timeout=15)
    check("stunprobe 的 UDP 走代理（STUN 看到節點 IP）", ip == NODES["mudfish-tw-1"], f"STUN 對應位址 {ip}")
    ip = sh("stunfallback", "/m0/stun_probe.py", timeout=15)
    check("stunfallback 的 UDP fallback 走直連", ip not in NODES.values(), f"STUN 對應位址 {ip}（TCP 直連出口 {direct_ip}）")

    section("Clash API")
    proxies = api("GET", "/proxies")["proxies"]
    check("/proxies 含 proxy 與 auto 群組", "proxy" in proxies and "auto" in proxies,
          f"proxy.now={proxies.get('proxy', {}).get('now')}, auto.now={proxies.get('auto', {}).get('now')}")
    delay = api("GET", "/proxies/mudfish-tw-1/delay?url=https%3A%2F%2Fwww.gstatic.com%2Fgenerate_204&timeout=5000")
    check("延遲測試 /proxies/{tag}/delay", isinstance(delay, dict) and "delay" in delay, json.dumps(delay))

    bg = subprocess.Popen(["curl", "-s", "-o", "/dev/null", "--limit-rate", "50k",
                           "https://speed.cloudflare.com/__down?bytes=2000000"])
    time.sleep(3)
    conns = api("GET", "/connections").get("connections") or []
    bg.kill()
    mine = [c for c in conns if "curl" in (c.get("metadata", {}).get("processPath") or "")]
    if mine:
        c = mine[0]
        check("/connections 帶 processPath", True,
              f"processPath={c['metadata']['processPath']}, host={c['metadata'].get('host')}, "
              f"rule={c.get('rule')} {c.get('rulePayload')}, chains={c.get('chains')}")
    else:
        check("/connections 帶 processPath", False, f"{len(conns)} 筆連線中找不到 curl")

    section("待驗證：sniff 後交給 SOCKS5 的是網域還是 IP")
    off = log_size()
    sh("curl", "-s", "-m", "15", "-o", "/dev/null", "https://icanhazip.com")
    time.sleep(1)
    lines = [l for l in log_since(off).splitlines() if "outbound connection to" in l]
    record("INFO", "curl https://icanhazip.com（真實 IP + TLS sniff）的出站紀錄",
           " | ".join(re.sub(r"^.*?(outbound/\S+.*)$", r"\1", l) for l in lines) or "（日誌中沒有找到）")

    section("待驗證：FakeIP IPv6 與 ip_is_private")
    aaaa = sh("dig", "+short", "ifconfig.me", "AAAA", "@1.1.1.1")
    record("INFO", "ifconfig.me 的 AAAA", aaaa or "（空）")
    if aaaa.startswith("fc00:"):
        try:
            s = socket.create_connection((aaaa, 80), timeout=8)
            s.sendall(b"GET /ip HTTP/1.1\r\nHost: ifconfig.me\r\nUser-Agent: curl/8\r\nConnection: close\r\n\r\n")
            body = s.recv(4096).split(b"\r\n\r\n", 1)[-1].decode().strip()
            record("INFO", "經 IPv6 FakeIP 連 ifconfig.me",
                   f"出口 {body} → " + ("網域在比對前已還原，沒有被 ip_is_private 攔走" if body in NODES.values() else "結果異常，需檢查"))
        except OSError as e:
            record("INFO", "經 IPv6 FakeIP 連 ifconfig.me 失敗", f"{e}（可能被 ip_is_private 判為私有而直連，或容器沒有 IPv6）")

    section("rule_set")
    for code, domain, expect in [("category-ads-all", "doubleclick.net", "reject"),
                                 ("category-games", "steampowered.com", "proxy")]:
        m = sh("sing-box", "rule-set", "match", "-f", "binary", f"/m0/rulesets/geosite/{code}.srs", domain)
        record("INFO", f"{domain} 是否在 {code}", m or "（無輸出）")
        off = log_size()
        try:
            fetch(f"https://{domain}", timeout=8)
            outcome = "連線成功"
        except Exception as e:
            outcome = f"連線失敗：{type(e).__name__}"
        time.sleep(1)
        hits = [l for l in log_since(off).splitlines() if "rule_set=" in l or "=> " in l]
        record("INFO", f"python3 連 {domain}（預期 {expect}），{outcome}",
               " | ".join(re.sub(r"^.*?(match.*)$", r"\1", l) for l in hits[:3]) or "（日誌中沒有比對紀錄）")

    api("PUT", "/proxies/proxy", {"name": "auto"})
    print(f"\n總結：PASS {results.count('PASS')}，FAIL {results.count('FAIL')}，INFO {results.count('INFO')}")


if __name__ == "__main__":
    main()
