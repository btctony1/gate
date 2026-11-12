#!/usr/bin/env python3
"""VPN Gate residential-node generator.

Fetches the official VPN Gate server list and publishes two product lines:

1. Residential VLESS nodes (primary): the Cloudflare edgetunnel entry node
   chains each connection through a VPN Gate server via SSTP, so the exit IP
   is the (residential) VPN Gate server. Candidates are ranked by score and
   tested for SSTP reachability (<hostname>.opengw.net:443) from Cloudflare's
   network through the check worker. Output: docs/vless.txt (one link per
   line) plus a section on the index page.

2. OpenVPN configs (secondary): TCP-mode servers tested through the check
   worker, published as direct configs and local-SOCKS chained configs under
   docs/ovpn/ and docs/ovpn-chain/.

Runs on GitHub Actions every 30 minutes. If fewer than MIN_OK nodes pass a
check line, that line's previous published output is left untouched.
"""
import base64
import concurrent.futures
import html
import json
import os
import re
import shutil
import sys
import tempfile
import time
import urllib.parse
import urllib.request

API_URL = "https://www.vpngate.net/api/iphone/"
CHECK_URL = os.environ.get("CHECK_URL", "https://chk.coo.qzz.io/check")
OUT_DIR = os.environ.get("OUT_DIR", "docs")
PAGES_BASE = os.environ.get("PAGES_BASE", "")

EDT_HOST = os.environ.get("EDT_HOST", "edt.coo.qzz.io")
EDT_UUID = os.environ.get("EDT_UUID", "dee9bf42-5ecc-4e32-a49e-bd4458a08082")

CANDIDATES = 60
MAX_NODES = 12
MIN_OK = 3
ACADEMIC_PREFIX = "219.100.37."  # VPNGate's own university block, not residential
UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}


def fetch(url, timeout=30):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def parse_servers(raw):
    text = raw.decode("utf-8", "replace")
    servers = []
    for line in text.splitlines():
        if not line or line.startswith("*") or line.startswith("#"):
            continue
        f = line.split(",")
        if len(f) < 15:
            continue
        try:
            servers.append({
                "host_name": f[0],
                "ip": f[1],
                "score": int(f[2]),
                "ping": int(f[3]) if f[3].isdigit() else 9999,
                "speed": int(f[4]),
                "country": f[5],
                "cc": f[6],
                "sessions": f[7],
                "config_b64": f[-1],
            })
        except (ValueError, IndexError):
            continue
    return servers


def decode_config(b64):
    try:
        return base64.b64decode(b64).decode("utf-8", "replace")
    except Exception:
        return ""


def config_remote(cfg):
    proto = "udp"
    remotes = []
    for line in cfg.splitlines():
        line = line.strip()
        if line.startswith("proto "):
            proto = line.split()[1].lower()
        elif line.startswith("remote "):
            parts = line.split()
            if len(parts) >= 3:
                remotes.append((parts[1], int(parts[2])))
    return proto, remotes


def check(host, port):
    url = f"{CHECK_URL}?host={urllib.parse.quote(host)}&port={port}"
    try:
        data = json.loads(fetch(url, timeout=15).decode("utf-8", "replace"))
        return bool(data.get("ok")), int(data.get("ms", 99999))
    except Exception:
        return False, 99999


def check_many(items):
    """items: list of (server, host, port). Returns servers with check_ms set."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        results = list(ex.map(lambda it: check(it[1], it[2]), items))
    alive = []
    for (s, _h, _p), (ok, ms) in zip(items, results):
        if ok:
            s["check_ms"] = ms
            alive.append(s)
    return alive


def vless_link(s):
    sstp_host = f"{s['host_name']}.opengw.net"
    path = "/?ed=2048&sstp=" + urllib.parse.quote(f"vpn:vpn@{sstp_host}", safe="")
    q = (
        "encryption=none&security=tls"
        f"&sni={EDT_HOST}&fp=randomized&type=ws&host={EDT_HOST}"
        f"&path={urllib.parse.quote(path, safe='')}"
    )
    remark = urllib.parse.quote(f"{s['cc']}-jiakuan-{s['host_name']}", safe="")
    return f"vless://{EDT_UUID}@{EDT_HOST}:443?{q}#{remark}"


def build_vless(servers):
    ranked = sorted(servers, key=lambda x: -x["score"])
    seen, items = set(), []
    for s in ranked:
        if s["ip"] in seen or not s["host_name"]:
            continue
        seen.add(s["ip"])
        items.append((s, f"{s['host_name']}.opengw.net", 443))
        if len(items) >= CANDIDATES:
            break
    alive = check_many(items)
    # residential first, then by measured latency + list ping, then speed
    alive.sort(key=lambda x: (x["ip"].startswith(ACADEMIC_PREFIX),
                              x["check_ms"] + x["ping"], -x["speed"]))
    return alive[:MAX_NODES]


def build_ovpn(servers):
    seen, items = set(), []
    for s in sorted(servers, key=lambda x: -x["score"]):
        if s["ip"] in seen:
            continue
        cfg = decode_config(s["config_b64"])
        proto, remotes = config_remote(cfg)
        if proto != "tcp" or not remotes:
            continue
        seen.add(s["ip"])
        s["config"] = cfg
        s["remote_host"], s["remote_port"] = remotes[0]
        items.append((s, s["remote_host"], s["remote_port"]))
        if len(items) >= CANDIDATES:
            break
    alive = check_many(items)
    alive.sort(key=lambda x: (x["check_ms"] + x["ping"], -x["speed"]))
    return alive[:MAX_NODES]


def main():
    print("fetching VPN Gate list ...", flush=True)
    servers = parse_servers(fetch(API_URL, timeout=60))
    print(f"{len(servers)} servers in list", flush=True)

    vless_nodes = build_vless(servers)
    print(f"vless: {len(vless_nodes)} SSTP nodes passed", flush=True)
    ovpn_nodes = build_ovpn(servers)
    print(f"ovpn: {len(ovpn_nodes)} TCP nodes passed", flush=True)
    if len(vless_nodes) < MIN_OK and len(ovpn_nodes) < MIN_OK:
        print("too few alive nodes on both lines; keeping previous output", flush=True)
        return 0

    tmp = tempfile.mkdtemp(prefix="gate-out-")
    os.makedirs(os.path.join(tmp, "ovpn"))
    os.makedirs(os.path.join(tmp, "ovpn-chain"))

    if len(vless_nodes) >= MIN_OK:
        with open(os.path.join(tmp, "vless.txt"), "w") as fh:
            fh.write("\n".join(vless_link(s) for s in vless_nodes) + "\n")

    rows_v, rows_o, hosts_lines, sub_lines = [], [], [], []
    for i, s in enumerate(vless_nodes, 1):
        rows_v.append(
            "<tr><td>{i}</td><td>{cc} {country}</td><td>{host}</td>"
            "<td>{speed:.1f} Mbps</td><td>{ping} ms</td><td>{ms} ms</td></tr>".format(
                i=i, cc=html.escape(s["cc"]), country=html.escape(s["country"]),
                host=html.escape(s["host_name"] + ".opengw.net"),
                speed=s["speed"] / 1_000_000, ping=s["ping"], ms=s["check_ms"]))
    for i, s in enumerate(ovpn_nodes, 1):
        name = f"{i:02d}-{s['cc']}-{s['remote_host']}.ovpn"
        with open(os.path.join(tmp, "ovpn", name), "w") as fh:
            fh.write(s["config"])
        chained = s["config"].rstrip() + (
            "\n# chained: OpenVPN reaches its server through the local SOCKS proxy\n"
            "# exposed by the VLESS client running the edgetunnel entry node.\n"
            "socks-proxy 127.0.0.1 10808\n"
        )
        with open(os.path.join(tmp, "ovpn-chain", name), "w") as fh:
            fh.write(chained)
        hosts_lines.append(f"{s['remote_host']}:{s['remote_port']}")
        if PAGES_BASE:
            sub_lines.append(f"{PAGES_BASE}/ovpn-chain/{name}")
        rows_o.append(
            "<tr><td>{i}</td><td>{cc} {country}</td><td>{host}</td>"
            "<td>{speed:.1f} Mbps</td><td>{ping} ms</td><td>{ms} ms</td>"
            "<td><a href=\"ovpn/{name}\">直连</a> · <a href=\"ovpn-chain/{name}\">链式</a></td></tr>".format(
                i=i, cc=html.escape(s["cc"]), country=html.escape(s["country"]),
                host=html.escape(s["remote_host"]), speed=s["speed"] / 1_000_000,
                ping=s["ping"], ms=s["check_ms"], name=name))
    with open(os.path.join(tmp, "hosts.txt"), "w") as fh:
        fh.write("\n".join(hosts_lines) + "\n")
    with open(os.path.join(tmp, "sub.txt"), "w") as fh:
        fh.write("\n".join(sub_lines) + ("\n" if sub_lines else ""))

    now = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())
    vless_note = (f'<p><a href="vless.txt">vless.txt</a> — {len(vless_nodes)} 条家宽 VLESS 节点，'
                  "整段复制到 v2rayNG 从剪贴板导入，或作为订阅地址添加。流量经 CF 入口后由 VPN Gate 家宽服务器出站。</p>"
                  if len(vless_nodes) >= MIN_OK else "<p>本轮家宽 VLESS 节点不足，保留上一版 vless.txt。</p>")
    page = """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VPN Gate 家宽节点</title></head><body>
<h1>VPN Gate 家宽节点（自动更新）</h1>
<p>更新时间：{now}</p>
<h2>家宽 VLESS 节点（SSTP 链式）</h2>
{vless_note}
<table border="1" cellspacing="0" cellpadding="6">
<tr><th>#</th><th>国家</th><th>家宽服务器（SSTP）</th><th>速度</th><th>列表Ping</th><th>实测</th></tr>
{rows_v}
</table>
<h2>OpenVPN 节点</h2>
<p>直连 = OpenVPN 应用直接导入；链式 = 先在本机开着 VLESS 客户端（SOCKS 10808）再导入链式配置。</p>
<table border="1" cellspacing="0" cellpadding="6">
<tr><th>#</th><th>国家</th><th>服务器</th><th>速度</th><th>列表Ping</th><th>实测</th><th>配置</th></tr>
{rows_o}
</table>
</body></html>
""".format(now=now, vless_note=vless_note, rows_v="\n".join(rows_v), rows_o="\n".join(rows_o))
    with open(os.path.join(tmp, "index.html"), "w") as fh:
        fh.write(page)

    os.makedirs(OUT_DIR, exist_ok=True)
    for item in os.listdir(tmp):
        src = os.path.join(tmp, item)
        dst = os.path.join(OUT_DIR, item)
        if item == "vless.txt" and len(vless_nodes) < MIN_OK:
            continue
        if os.path.isdir(src):
            shutil.rmtree(dst, ignore_errors=True)
            shutil.copytree(src, dst)
        else:
            shutil.copy2(src, dst)
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"published vless={len(vless_nodes)} ovpn={len(ovpn_nodes)} to {OUT_DIR}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
