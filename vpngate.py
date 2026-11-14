#!/usr/bin/env python3
"""VPN Gate residential-node generator.

Fetches the official VPN Gate server list and publishes:

1. Residential VLESS nodes (primary). Screening is three-stage and the
   final stage tests the DEFINING property end to end:
     a. Candidates: volunteer servers only (the VPNGate project's own
        219.100.37.0/24 university block and public-vpn-* hosts excluded).
     b. Protocol-level SSTP probe via the gatecheck Worker
        (chk.coo.qzz.io/sstp — requires a real Call Connect Ack).
     c. FULL-CHAIN verification: a real VLESS request is sent through the
        edgetunnel entry with the node's sstp path parameter to an IP-echo
        service; the node is published ONLY if real traffic comes back and
        the observed exit IP classifies as residential (ip-api: not
        hosting, not SoftEther, not the academic block).
   Output: docs/vless.txt + docs/vless.json (with exit IP / ISP evidence).

2. OpenVPN configs (secondary): TCP-mode servers tested through the check
   worker, published as direct and local-SOCKS chained configs.

Runs on GitHub Actions every 30 minutes. If a line produces too few nodes,
its previous published output is left untouched.
"""
import base64
import concurrent.futures
import html
import json
import os
import re
import shutil
import socket
import ssl
import struct
import sys
import tempfile
import time
import urllib.parse
import urllib.request

API_URL = "https://www.vpngate.net/api/iphone/"
CHECK_URL = os.environ.get("CHECK_URL", "https://chk.coo.qzz.io/check")
SSTP_URL = os.environ.get("SSTP_CHECK_URL") or CHECK_URL.replace("/check", "/sstp")
IPAPI_BATCH = "http://ip-api.com/batch"
OUT_DIR = os.environ.get("OUT_DIR", "docs")
PAGES_BASE = os.environ.get("PAGES_BASE", "")

EDT_HOST = os.environ.get("EDT_HOST", "edt.coo.qzz.io")
EDT_UUID = os.environ.get("EDT_UUID", "dee9bf42-5ecc-4e32-a49e-bd4458a08082")

CANDIDATES = 60            # OpenVPN line
SSTP_CANDIDATES = 150      # VLESS stage-1 pool (volunteer servers)
CHAIN_TEST_CAP = 36        # max full-chain verifications per run
MAX_NODES = 12
MIN_OK = 3                 # OpenVPN line keep-previous threshold
ACADEMIC_PREFIX = "219.100.37."  # VPNGate's own university block, not residential
UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


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


def check_sstp(host):
    """Protocol-level SSTP probe: ok only if the server completes the
    MS-SSTP Call Connect handshake (stronger than a raw TCP check)."""
    url = f"{SSTP_URL}?host={urllib.parse.quote(host)}"
    try:
        data = json.loads(fetch(url, timeout=25).decode("utf-8", "replace"))
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


# ---------------------------------------------------------------------------
# Full-chain verification: speak VLESS over WebSocket to the edgetunnel entry
# with the node's sstp path parameter and read the exit IP from an echo
# service. This tests the whole path a real client would use.
# ---------------------------------------------------------------------------

def _ws_connect(path, timeout=20):
    ctx = ssl.create_default_context()
    raw = socket.create_connection((EDT_HOST, 443), timeout=timeout)
    sock = ctx.wrap_socket(raw, server_hostname=EDT_HOST)
    key = base64.b64encode(os.urandom(16)).decode()
    req = (
        f"GET {path} HTTP/1.1\r\nHost: {EDT_HOST}\r\nUpgrade: websocket\r\n"
        f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n"
    )
    sock.sendall(req.encode())
    buf = b""
    sock.settimeout(timeout)
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("handshake closed")
        buf += chunk
    head, rest = buf.split(b"\r\n\r\n", 1)
    if b"101" not in head.split(b"\r\n")[0]:
        raise ConnectionError("handshake not 101: " + head.split(b"\r\n")[0].decode("utf-8", "replace"))
    return sock, rest


def _ws_send(sock, data):
    mask = os.urandom(4)
    n = len(data)
    if n < 126:
        hdr = bytes([0x82, 0x80 | n])
    elif n < 65536:
        hdr = bytes([0x82, 0x80 | 126]) + struct.pack(">H", n)
    else:
        hdr = bytes([0x82, 0x80 | 127]) + struct.pack(">Q", n)
    sock.sendall(hdr + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))


def _read_frames(sock, initial, deadline):
    """Accumulate WS payload bytes until the HTTP body looks complete or the
    deadline passes. PPP negotiation is silent, so timeouts never abort."""
    stream = bytearray()
    buf = bytearray(initial)
    sock.settimeout(5)
    while time.time() < deadline:
        # parse as many complete frames as the buffer holds
        while True:
            if len(buf) < 2:
                break
            opcode = buf[0] & 0x0F
            ln = buf[1] & 0x7F
            off = 2
            if ln == 126:
                if len(buf) < 4:
                    break
                ln = struct.unpack(">H", bytes(buf[2:4]))[0]
                off = 4
            elif ln == 127:
                if len(buf) < 10:
                    break
                ln = struct.unpack(">Q", bytes(buf[2:10]))[0]
                off = 10
            if len(buf) < off + ln:
                break
            payload = bytes(buf[off:off + ln])
            del buf[:off + ln]
            if opcode in (0, 1, 2):
                stream += payload
        if b"\r\n\r\n" in stream:
            body = bytes(stream).split(b"\r\n\r\n", 1)[1].strip()
            token = body.split()[0].decode("utf-8", "replace") if body else ""
            if IP_RE.match(token):
                return token
        try:
            chunk = sock.recv(65536)
            if not chunk:
                break
            buf += chunk
        except socket.timeout:
            continue
        except OSError:
            break
    if b"\r\n\r\n" in stream:
        body = bytes(stream).split(b"\r\n\r\n", 1)[1].strip()
        token = body.split()[0].decode("utf-8", "replace") if body else ""
        if IP_RE.match(token):
            return token
    return None


def chain_exit_ip(sstp_host, echo_host, echo_path, deadline_s=35):
    """One full-chain attempt. Returns the observed exit IP or None."""
    path = "/?ed=2048&sstp=" + urllib.parse.quote(f"vpn:vpn@{sstp_host}", safe="")
    sock = None
    try:
        sock, rest = _ws_connect(path)
        uid = bytes.fromhex(EDT_UUID.replace("-", ""))
        tgt = echo_host.encode()
        payload = (
            b"\x00" + uid + b"\x00\x01" + struct.pack(">H", 80) + b"\x02"
            + bytes([len(tgt)]) + tgt
            + f"GET {echo_path} HTTP/1.0\r\nHost: {echo_host}\r\n\r\n".encode()
        )
        _ws_send(sock, payload)
        ip = _read_frames(sock, rest, time.time() + deadline_s)
        print(f"chain {sstp_host} via {echo_host}: {'exit ' + ip if ip else 'no response'}", flush=True)
        return ip
    except Exception as e:
        print(f"chain {sstp_host} via {echo_host}: error {type(e).__name__} {str(e)[:80]}", flush=True)
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def verify_chain(s):
    """Try both echo services; record exit_ip and chain_ms on success."""
    host = f"{s['host_name']}.opengw.net"
    started = time.time()
    for echo_host, echo_path in (("api.ipify.org", "/"), ("ifconfig.me", "/ip")):
        ip = chain_exit_ip(host, echo_host, echo_path)
        if ip:
            s["exit_ip"] = ip
            s["chain_ms"] = int((time.time() - started) * 1000)
            return True
    return False


def classify_exits(ips):
    """ip-api batch lookup. Returns {ip: info} for exits that classify as
    residential (not hosting, not SoftEther, not the academic block)."""
    out = {}
    ips = sorted(set(ips))
    for i in range(0, len(ips), 100):
        batch = ips[i:i + 100]
        body = json.dumps([{"query": ip, "fields": "query,isp,org,as,hosting,proxy"}
                           for ip in batch]).encode()
        req = urllib.request.Request(IPAPI_BATCH, data=body,
                                     headers={"Content-Type": "application/json", **UA})
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                rows = json.loads(resp.read())
        except Exception:
            rows = []
        for row in rows:
            ip = row.get("query", "")
            ident = (row.get("isp", "") + " " + row.get("org", "")).lower()
            if row.get("hosting"):
                continue
            if "softether" in ident or ip.startswith(ACADEMIC_PREFIX):
                continue
            out[ip] = {"isp": row.get("isp", ""), "org": row.get("org", ""), "as": row.get("as", "")}
    return out


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
    # Stage (a): volunteer servers only — academic block and the project's
    # own public-vpn-* hosts are NOT residential and never enter the pool.
    pool = [s for s in servers
            if s["host_name"] and not s["ip"].startswith(ACADEMIC_PREFIX)
            and not s["host_name"].lower().startswith("public-vpn-")]
    pool.sort(key=lambda x: -x["score"])
    seen, items = set(), []
    for s in pool:
        if s["ip"] in seen:
            continue
        seen.add(s["ip"])
        items.append((s, f"{s['host_name']}.opengw.net"))
        if len(items) >= SSTP_CANDIDATES:
            break
    print(f"vless stage a: {len(items)} volunteer candidates", flush=True)
    # Stage (b): protocol-level SSTP probe.
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        results = list(ex.map(lambda it: check_sstp(it[1]), items))
    probed = []
    for (s, _h), (ok, ms) in zip(items, results):
        if ok:
            s["check_ms"] = ms
            probed.append(s)
    probed.sort(key=lambda x: x["check_ms"])
    probed = probed[:CHAIN_TEST_CAP]
    print(f"vless stage b: {len(probed)} passed SSTP probe: "
          + ", ".join(s["host_name"] for s in probed), flush=True)
    # Stage (c): full-chain verification — real traffic, real exit IP.
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        oks = list(ex.map(verify_chain, probed))
    chained = [s for s, ok in zip(probed, oks) if ok]
    print(f"vless stage c: {len(chained)} completed the full chain", flush=True)
    # Classification: the exit must be a residential IP.
    good = classify_exits([s["exit_ip"] for s in chained])
    verified = []
    for s in chained:
        info = good.get(s["exit_ip"])
        if info:
            s["exit_isp"] = info["isp"] or info["org"]
            verified.append(s)
    verified.sort(key=lambda x: x["chain_ms"])
    print(f"vless: {len(verified)} verified residential exits", flush=True)
    return verified[:MAX_NODES]


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
    ovpn_nodes = build_ovpn(servers)
    print(f"ovpn: {len(ovpn_nodes)} TCP nodes passed", flush=True)
    if not vless_nodes and len(ovpn_nodes) < MIN_OK:
        print("nothing publishable on either line; keeping previous output", flush=True)
        return 0

    tmp = tempfile.mkdtemp(prefix="gate-out-")
    os.makedirs(os.path.join(tmp, "ovpn"))
    os.makedirs(os.path.join(tmp, "ovpn-chain"))

    if vless_nodes:
        with open(os.path.join(tmp, "vless.txt"), "w") as fh:
            fh.write("\n".join(vless_link(s) for s in vless_nodes) + "\n")
        details = [{
            "remark": f"{s['cc']}-jiakuan-{s['host_name']}",
            "sstp_host": f"{s['host_name']}.opengw.net",
            "country": s["country"],
            "exit_ip": s["exit_ip"],
            "exit_isp": s.get("exit_isp", ""),
            "chain_ms": s["chain_ms"],
        } for s in vless_nodes]
        with open(os.path.join(tmp, "vless.json"), "w") as fh:
            json.dump(details, fh, ensure_ascii=False, indent=1)

    rows_v, rows_o, hosts_lines, sub_lines = [], [], [], []
    for i, s in enumerate(vless_nodes, 1):
        rows_v.append(
            "<tr><td>{i}</td><td>{cc} {country}</td><td>{host}</td>"
            "<td>{exit_ip}</td><td>{isp}</td><td>{cms} ms</td></tr>".format(
                i=i, cc=html.escape(s["cc"]), country=html.escape(s["country"]),
                host=html.escape(s["host_name"] + ".opengw.net"),
                exit_ip=html.escape(s["exit_ip"]), isp=html.escape(s.get("exit_isp", "")),
                cms=s["chain_ms"]))
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
    if vless_nodes:
        vless_note = (f'<p><a href="vless.txt">vless.txt</a> — {len(vless_nodes)} 条家宽 VLESS 节点。'
                      "每条都经过全链路实测：真实流量经 CF 入口 + SSTP 链到该服务器出网，"
                      "下表出口 IP 为实测值且已核为住宅运营商（非机房/非学术网）。</p>")
    else:
        vless_note = ("<p>本轮没有节点通过全链路住宅出口验证，vless.txt 保留上一版。</p>")
    page = """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VPN Gate 家宽节点</title></head><body>
<h1>VPN Gate 家宽节点（自动更新）</h1>
<p>更新时间：{now}</p>
<h2>家宽 VLESS 节点（SSTP 链式 · 全链路实测）</h2>
{vless_note}
<table border="1" cellspacing="0" cellpadding="6">
<tr><th>#</th><th>国家</th><th>家宽服务器（SSTP）</th><th>实测出口 IP</th><th>出口运营商</th><th>链路耗时</th></tr>
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
