#!/usr/bin/env python3
"""VPN Gate residential-node generator.

Fetches the official VPN Gate server list, keeps TCP-mode servers, tests each
candidate's reachability from Cloudflare's network through the check worker,
and publishes the survivors as:
  docs/index.html            node list page
  docs/ovpn/*.ovpn           direct OpenVPN configs (official bytes)
  docs/ovpn-chain/*.ovpn     chained configs: OpenVPN via a local SOCKS proxy
                             (a VLESS client running the edgetunnel node with
                             its SOCKS inbound on 127.0.0.1:10808)
  docs/hosts.txt             host:port of every published node
  docs/sub.txt               download URLs of the chained configs, one per line

Runs on GitHub Actions every 30 minutes. If fewer than MIN_OK nodes pass the
check, the previous published output is left untouched.
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
import urllib.request

API_URL = "https://www.vpngate.net/api/iphone/"
CHECK_URL = os.environ.get("CHECK_URL", "https://chk.coo.qzz.io/check")
OUT_DIR = os.environ.get("OUT_DIR", "docs")
PAGES_BASE = os.environ.get("PAGES_BASE", "")  # e.g. https://user.github.io/repo
CANDIDATES = 60
MAX_NODES = 12
MIN_OK = 3
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
    url = f"{CHECK_URL}?host={host}&port={port}"
    try:
        data = json.loads(fetch(url, timeout=15).decode("utf-8", "replace"))
        return bool(data.get("ok")), int(data.get("ms", 99999))
    except Exception:
        return False, 99999


def main():
    print("fetching VPN Gate list ...", flush=True)
    servers = parse_servers(fetch(API_URL, timeout=60))
    print(f"{len(servers)} servers in list", flush=True)

    seen = set()
    candidates = []
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
        candidates.append(s)
        if len(candidates) >= CANDIDATES:
            break
    print(f"{len(candidates)} TCP candidates", flush=True)

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        results = list(ex.map(lambda s: check(s["remote_host"], s["remote_port"]), candidates))
    alive = []
    for s, (ok, ms) in zip(candidates, results):
        if ok:
            s["check_ms"] = ms
            alive.append(s)
    alive.sort(key=lambda x: (x["check_ms"] + x["ping"], -x["speed"]))
    alive = alive[:MAX_NODES]
    print(f"{len(alive)} nodes passed the check", flush=True)
    if len(alive) < MIN_OK:
        print("too few alive nodes; keeping previous output", flush=True)
        return 0

    tmp = tempfile.mkdtemp(prefix="gate-out-")
    os.makedirs(os.path.join(tmp, "ovpn"))
    os.makedirs(os.path.join(tmp, "ovpn-chain"))
    rows = []
    hosts_lines = []
    sub_lines = []
    for i, s in enumerate(alive, 1):
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
        rows.append(
            "<tr><td>{i}</td><td>{cc} {country}</td><td>{host}</td>"
            "<td>{speed:.1f} Mbps</td><td>{ping} ms</td><td>{ms} ms</td>"
            "<td><a href=\"ovpn/{name}\">直连</a> · <a href=\"ovpn-chain/{name}\">链式</a></td></tr>".format(
                i=i, cc=html.escape(s["cc"]), country=html.escape(s["country"]),
                host=html.escape(s["remote_host"]), speed=s["speed"] / 1_000_000,
                ping=s["ping"], ms=s["check_ms"], name=name))

    now = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())
    page = """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VPN Gate 家宽节点</title></head><body>
<h1>VPN Gate 家宽节点（自动更新）</h1>
<p>更新时间：{now} · 共 {n} 个已测活节点。直连 = OpenVPN 应用直接导入；
链式 = 先在本机开着 VLESS 客户端（edgetunnel 入口，SOCKS 10808），再导入链式配置，
出口为住宅 IP。</p>
<table border="1" cellspacing="0" cellpadding="6">
<tr><th>#</th><th>国家</th><th>服务器</th><th>速度</th><th>列表Ping</th><th>实测</th><th>配置</th></tr>
{rows}
</table>
</body></html>
""".format(now=now, n=len(alive), rows="\n".join(rows))
    with open(os.path.join(tmp, "index.html"), "w") as fh:
        fh.write(page)
    with open(os.path.join(tmp, "hosts.txt"), "w") as fh:
        fh.write("\n".join(hosts_lines) + "\n")
    with open(os.path.join(tmp, "sub.txt"), "w") as fh:
        fh.write("\n".join(sub_lines) + ("\n" if sub_lines else ""))

    os.makedirs(OUT_DIR, exist_ok=True)
    for item in os.listdir(tmp):
        src = os.path.join(tmp, item)
        dst = os.path.join(OUT_DIR, item)
        if os.path.isdir(src):
            shutil.rmtree(dst, ignore_errors=True)
            shutil.copytree(src, dst)
        else:
            shutil.copy2(src, dst)
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"published {len(alive)} nodes to {OUT_DIR}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
