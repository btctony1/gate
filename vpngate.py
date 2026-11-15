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
        hosting, not SoftEther, not the academic block). PPP completion is
        a per-attempt lottery, so each candidate gets one retry per run.
   Output: docs/vless.txt + docs/vless.json (with exit IP / ISP evidence
   and a per-node verified_at timestamp). Availability policy: a round
   that verifies nothing keeps the previous verified list (labelled with
   its original verification time on the page) instead of blanking the
   subscription; the list is replaced as soon as a round verifies anew.

2. OpenVPN configs (secondary): TCP-mode servers tested through the check
   worker, published as direct and local-SOCKS chained configs. On top of
   that, an exit-verification stage (v5) actually connects to a diverse
   subset of the reachable servers with a real OpenVPN client on the
   runner, measures the exit IP through the tunnel, and publishes the
   residential-classified ones separately (docs/ovpn-verified/,
   docs/ovpn-verified-chain/, docs/ovpn.json) with the same
   keep-last-good policy as the VLESS line. The stage is fail-soft: if
   openvpn or /dev/net/tun is unavailable on the runner it logs the fact
   and the run continues with reachability-only publishing.

Runs on GitHub Actions every 30 minutes. If a line produces too few nodes,
its previous published output is left untouched.
"""
import base64
import concurrent.futures
import html
import json
import os
import queue
import re
import shutil
import socket
import ssl
import struct
import subprocess
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
CHAIN_TEST_CAP = 48        # max full-chain verifications per run
OVPN_VERIFY_CAP = 24       # max OpenVPN exit verifications per run
OVPN_VERIFY_SLOTS = 3      # parallel OpenVPN tunnels while exit-testing
OVPN_TUN_TIMEOUT_S = 40    # deadline for a tunnel to come up
MAX_NODES = 12
MIN_OK = 3                 # OpenVPN line keep-previous threshold
CHAIN_TRAILER = (
    "\n# chained: OpenVPN reaches its server through the local SOCKS proxy\n"
    "# exposed by the VLESS client running the edgetunnel entry node.\n"
    "socks-proxy 127.0.0.1 10808\n"
)
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
    # PPP completion is a per-attempt lottery: every candidate that fails
    # its first draw gets exactly one retry later in the same run.
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
        oks = list(ex.map(verify_chain, probed))
    chained = [s for s, ok in zip(probed, oks) if ok]
    failed = [s for s, ok in zip(probed, oks) if not ok]
    print(f"vless stage c: {len(chained)} completed the full chain "
          f"({len(failed)} failed, retrying once)", flush=True)
    if failed:
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
            oks2 = list(ex.map(verify_chain, failed))
        chained += [s for s, ok in zip(failed, oks2) if ok]
        print(f"vless stage c retry: {len(chained)} total completed", flush=True)
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
    return alive


# ---------------------------------------------------------------------------
# OpenVPN exit verification (v5): connect to reachable servers with a real
# OpenVPN client on this machine, measure the exit IP through the tunnel,
# and keep only the exits that classify as residential. Fail-soft by
# design — any systemic problem (no openvpn binary, no TUN device) logs a
# clear line and the caller falls back to reachability-only publishing.
# ---------------------------------------------------------------------------

def _diverse_pick(alive, cap):
    """Round-robin across countries so the exit-test pool is not all
    servers from the single biggest country."""
    groups, order = {}, []
    for s in alive:
        cc = s["cc"]
        if cc not in groups:
            groups[cc] = []
            order.append(cc)
        groups[cc].append(s)
    picks, idx = [], 0
    while len(picks) < cap:
        progressed = False
        for cc in order:
            if idx < len(groups[cc]):
                picks.append(groups[cc][idx])
                progressed = True
                if len(picks) >= cap:
                    break
        if not progressed:
            break
        idx += 1
    return picks


def _read_pid(pid_path):
    try:
        with open(pid_path) as fh:
            return int(fh.read().strip())
    except Exception:
        return None


def _pid_alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except PermissionError:
        return True
    except OSError:
        return False


def _ovpn_exit_test(s, slot, workdir):
    """One tunnel attempt. Records exit_ip/ovpn_ms on success."""
    dev = f"tun{10 + slot}"
    cfg_path = os.path.join(workdir, "c.ovpn")
    log_path = os.path.join(workdir, "openvpn.log")
    pid_path = os.path.join(workdir, "openvpn.pid")
    with open(cfg_path, "w") as fh:
        fh.write(s["config"])
    started = time.time()
    try:
        r = subprocess.run(["sudo", "openvpn", "--config", cfg_path, "--dev", dev,
                            "--route-nopull", "--daemon", "--log", log_path,
                            "--writepid", pid_path],
                           timeout=20, capture_output=True, text=True)
        if r.returncode not in (0, None):
            print(f"ovpn verify {s['remote_host']}: openvpn exited rc={r.returncode} "
                  f"stderr: {(r.stderr or '').strip()[:200]}", flush=True)
            _dump_ovpn_log(s, log_path)
            return False
    except Exception as e:
        print(f"ovpn verify {s['remote_host']}: start error "
              f"{type(e).__name__} {str(e)[:80]}", flush=True)
        return False
    up = False
    deadline = time.time() + OVPN_TUN_TIMEOUT_S
    fatal = (b"Exiting due to fatal error", b"Cannot open TUN/TAP dev",
             b"Options error:")
    while time.time() < deadline:
        try:
            with open(log_path, "rb") as fh:
                content = fh.read()
            if b"Initialization Sequence Completed" in content:
                up = True
                break
            if any(marker in content for marker in fatal):
                break
        except OSError:
            pass
        time.sleep(1.5)
    ip = None
    if up:
        for echo in ("http://ifconfig.me/ip", "http://icanhazip.com"):
            try:
                r = subprocess.run(["curl", "--interface", dev, "-s", "-m", "15", echo],
                                   timeout=25, capture_output=True, text=True)
                tok = (r.stdout or "").strip().split()
                tok = tok[0] if tok else ""
                if IP_RE.match(tok):
                    ip = tok
                    break
            except Exception:
                continue
    pid = _read_pid(pid_path)
    if pid:
        try:
            subprocess.run(["sudo", "kill", str(pid)], timeout=10, capture_output=True)
            for _ in range(10):
                if not _pid_alive(pid):
                    break
                time.sleep(0.5)
            if _pid_alive(pid):
                subprocess.run(["sudo", "kill", "-9", str(pid)],
                               timeout=10, capture_output=True)
        except Exception:
            pass
    if ip:
        s["exit_ip"] = ip
        s["ovpn_ms"] = int((time.time() - started) * 1000)
        print(f"ovpn verify {s['remote_host']}: tunnel up, exit {ip}", flush=True)
        return True
    print(f"ovpn verify {s['remote_host']}: "
          f"{'tunnel up but no exit IP measured' if up else 'tunnel did not come up'}",
          flush=True)
    if not up:
        _dump_ovpn_log(s, log_path)
    return False


def _dump_ovpn_log(s, log_path):
    """Print the tail of a failed tunnel's openvpn log into the run log so
    the failure cause is visible without runner access."""
    try:
        with open(log_path, "rb") as fh:
            lines = fh.read().decode("utf-8", "replace").splitlines()
    except OSError as e:
        print(f"ovpn log {s['remote_host']}: unreadable ({e})", flush=True)
        return
    for line in lines[-12:]:
        print(f"ovpn log {s['remote_host']}: {line[:200]}", flush=True)


def verify_ovpn_exits(alive):
    """Exit-test a country-diverse subset of the reachable servers.
    Returns the verified residential servers (possibly empty)."""
    if not alive:
        return []
    if not shutil.which("openvpn"):
        print("ovpn verify: openvpn binary not found; "
              "skipping exit verification (fallback: reachability only)", flush=True)
        return []
    if not os.path.exists("/dev/net/tun"):
        print("ovpn verify: /dev/net/tun unavailable; "
              "skipping exit verification (fallback: reachability only)", flush=True)
        return []
    try:
        ver = subprocess.run(["openvpn", "--version"], timeout=10,
                             capture_output=True, text=True).stdout.splitlines()
        print(f"ovpn verify: {ver[0] if ver else 'openvpn version unknown'}", flush=True)
    except Exception:
        pass
    picks = _diverse_pick(alive, OVPN_VERIFY_CAP)
    print(f"ovpn verify: exit-testing {len(picks)} candidates "
          f"({len(alive)} reachable)", flush=True)
    workroot = tempfile.mkdtemp(prefix="gate-ovpn-")
    slots = queue.Queue()
    for i in range(OVPN_VERIFY_SLOTS):
        slots.put(i)

    def run_one(s):
        slot = slots.get()
        try:
            wd = os.path.join(workroot, f"s{slot}-{s['remote_host']}")
            os.makedirs(wd, exist_ok=True)
            return _ovpn_exit_test(s, slot, wd)
        except Exception as e:
            print(f"ovpn verify {s.get('remote_host')}: error "
                  f"{type(e).__name__} {str(e)[:80]}", flush=True)
            return False
        finally:
            slots.put(slot)

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=OVPN_VERIFY_SLOTS) as ex:
            oks = list(ex.map(run_one, picks))
    finally:
        shutil.rmtree(workroot, ignore_errors=True)
    tested = [s for s, ok in zip(picks, oks) if ok]
    print(f"ovpn verify: {len(tested)} of {len(picks)} tunnels measured an exit IP",
          flush=True)
    good = classify_exits([s["exit_ip"] for s in tested])
    verified = []
    for s in tested:
        info = good.get(s["exit_ip"])
        if info:
            s["exit_isp"] = info["isp"] or info["org"]
            verified.append(s)
    verified.sort(key=lambda x: x.get("ovpn_ms", 999999999))
    print(f"ovpn verify: {len(verified)} verified residential exits", flush=True)
    return verified[:MAX_NODES]


def main():
    print("fetching VPN Gate list ...", flush=True)
    servers = parse_servers(fetch(API_URL, timeout=60))
    print(f"{len(servers)} servers in list", flush=True)

    vless_nodes = build_vless(servers)
    ovpn_all = build_ovpn(servers)
    ovpn_nodes = ovpn_all[:MAX_NODES]
    print(f"ovpn: {len(ovpn_nodes)} TCP nodes passed", flush=True)
    if not vless_nodes and len(ovpn_nodes) < MIN_OK:
        print("nothing publishable on either line; keeping previous output", flush=True)
        return 0

    # OpenVPN exit verification (v5). Fail-soft: any failure here leaves
    # ovpn_verified empty and the run publishes exactly what v4 did.
    try:
        ovpn_verified = verify_ovpn_exits(ovpn_all)
    except Exception as e:
        print(f"ovpn verify: stage error {type(e).__name__} {str(e)[:100]}; "
              "continuing without exit verification", flush=True)
        ovpn_verified = []

    tmp = tempfile.mkdtemp(prefix="gate-out-")
    os.makedirs(os.path.join(tmp, "ovpn"))
    os.makedirs(os.path.join(tmp, "ovpn-chain"))

    # Availability-first publishing: if this round verified nodes, publish
    # them (stamped with verified_at). If it verified none but a previous
    # verified list exists, keep that list untouched — the page labels it
    # with its original verification time, never as fresh. Only when no
    # previous list exists is an empty result published.
    verified_at = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())
    prev_details = []
    if not vless_nodes:
        try:
            with open(os.path.join(OUT_DIR, "vless.json")) as fh:
                prev_details = json.load(fh)
        except Exception:
            prev_details = []
    keep_prev = not vless_nodes and bool(prev_details)
    if vless_nodes or not keep_prev:
        with open(os.path.join(tmp, "vless.txt"), "w") as fh:
            fh.write("\n".join(vless_link(s) for s in vless_nodes) + ("\n" if vless_nodes else ""))
        details = [{
            "remark": f"{s['cc']}-jiakuan-{s['host_name']}",
            "sstp_host": f"{s['host_name']}.opengw.net",
            "country": s["country"],
            "exit_ip": s["exit_ip"],
            "exit_isp": s.get("exit_isp", ""),
            "chain_ms": s["chain_ms"],
            "verified_at": verified_at,
        } for s in vless_nodes]
        with open(os.path.join(tmp, "vless.json"), "w") as fh:
            json.dump(details, fh, ensure_ascii=False, indent=1)

    # Same availability-first policy for the exit-verified OpenVPN set:
    # publish this round's verified configs, or keep the previous set
    # untouched when this round verified none.
    prev_ovpn = []
    if not ovpn_verified:
        try:
            with open(os.path.join(OUT_DIR, "ovpn.json")) as fh:
                prev_ovpn = json.load(fh)
        except Exception:
            prev_ovpn = []
    keep_prev_ovpn = not ovpn_verified and bool(prev_ovpn)
    if ovpn_verified or not keep_prev_ovpn:
        os.makedirs(os.path.join(tmp, "ovpn-verified"))
        os.makedirs(os.path.join(tmp, "ovpn-verified-chain"))
        odetails = []
        for i, s in enumerate(ovpn_verified, 1):
            name = f"{i:02d}-{s['cc']}-{s['remote_host']}.ovpn"
            with open(os.path.join(tmp, "ovpn-verified", name), "w") as fh:
                fh.write(s["config"])
            with open(os.path.join(tmp, "ovpn-verified-chain", name), "w") as fh:
                fh.write(s["config"].rstrip() + CHAIN_TRAILER)
            odetails.append({
                "remark": f"{s['cc']}-jiakuan-{s['remote_host']}",
                "remote_host": s["remote_host"],
                "remote_port": s["remote_port"],
                "country": s["country"],
                "exit_ip": s["exit_ip"],
                "exit_isp": s.get("exit_isp", ""),
                "verified_at": verified_at,
                "file": name,
            })
        with open(os.path.join(tmp, "ovpn.json"), "w") as fh:
            json.dump(odetails, fh, ensure_ascii=False, indent=1)

    rows_v, rows_o, rows_ov, hosts_lines, sub_lines = [], [], [], [], []
    for i, s in enumerate(vless_nodes, 1):
        rows_v.append(
            "<tr><td>{i}</td><td>{cc} {country}</td><td>{host}</td>"
            "<td>{exit_ip}</td><td>{isp}</td><td>{cms} ms</td></tr>".format(
                i=i, cc=html.escape(s["cc"]), country=html.escape(s["country"]),
                host=html.escape(s["host_name"] + ".opengw.net"),
                exit_ip=html.escape(s["exit_ip"]), isp=html.escape(s.get("exit_isp", "")),
                cms=s["chain_ms"]))
    if keep_prev:
        for i, d in enumerate(prev_details, 1):
            rows_v.append(
                "<tr><td>{i}</td><td>{country}</td><td>{host}</td>"
                "<td>{exit_ip}</td><td>{isp}</td><td>{cms} ms</td></tr>".format(
                    i=i, country=html.escape(d.get("country", "")),
                    host=html.escape(d.get("sstp_host", "")),
                    exit_ip=html.escape(d.get("exit_ip", "")),
                    isp=html.escape(d.get("exit_isp", "")),
                    cms=d.get("chain_ms", "")))
    for i, s in enumerate(ovpn_verified, 1):
        name = f"{i:02d}-{s['cc']}-{s['remote_host']}.ovpn"
        rows_ov.append(
            "<tr><td>{i}</td><td>{cc} {country}</td><td>{host}</td>"
            "<td>{exit_ip}</td><td>{isp}</td>"
            "<td><a href=\"ovpn-verified/{name}\">直连</a> · "
            "<a href=\"ovpn-verified-chain/{name}\">链式</a></td></tr>".format(
                i=i, cc=html.escape(s["cc"]), country=html.escape(s["country"]),
                host=html.escape(s["remote_host"]),
                exit_ip=html.escape(s["exit_ip"]), isp=html.escape(s.get("exit_isp", "")),
                name=name))
    if keep_prev_ovpn:
        for i, d in enumerate(prev_ovpn, 1):
            rows_ov.append(
                "<tr><td>{i}</td><td>{country}</td><td>{host}</td>"
                "<td>{exit_ip}</td><td>{isp}</td>"
                "<td><a href=\"ovpn-verified/{name}\">直连</a> · "
                "<a href=\"ovpn-verified-chain/{name}\">链式</a></td></tr>".format(
                    i=i, country=html.escape(d.get("country", "")),
                    host=html.escape(d.get("remote_host", "")),
                    exit_ip=html.escape(d.get("exit_ip", "")),
                    isp=html.escape(d.get("exit_isp", "")),
                    name=html.escape(d.get("file", ""))))
    for i, s in enumerate(ovpn_nodes, 1):
        name = f"{i:02d}-{s['cc']}-{s['remote_host']}.ovpn"
        with open(os.path.join(tmp, "ovpn", name), "w") as fh:
            fh.write(s["config"])
        with open(os.path.join(tmp, "ovpn-chain", name), "w") as fh:
            fh.write(s["config"].rstrip() + CHAIN_TRAILER)
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
    elif keep_prev:
        prev_at = max((d.get("verified_at", "") for d in prev_details), default="")
        vless_note = (f'<p><a href="vless.txt">vless.txt</a> — 本轮没有新节点通过全链路住宅出口验证；'
                      f"下表为上次验证通过的 {len(prev_details)} 条节点（验证时间："
                      f"{html.escape(prev_at or '较早')}），可能已部分失效；"
                      "系统会继续自动筛选，验出新节点后自动替换。</p>")
    else:
        vless_note = ("<p>本轮没有节点通过全链路住宅出口验证，vless.txt 为空；"
                      "系统每 30 分钟自动重新筛选，出现合格节点会自动发布。</p>")
    if ovpn_verified:
        ovpn_v_note = (f"<p>{len(ovpn_verified)} 条 OpenVPN 配置经过真实隧道出口实测："
                       "检测机实际连上该服务器后从隧道内测得出口 IP，"
                       "下表出口 IP 为实测值且已核为住宅运营商（非机房/非学术网）。</p>")
    elif keep_prev_ovpn:
        prev_at_o = max((d.get("verified_at", "") for d in prev_ovpn), default="")
        ovpn_v_note = (f"<p>本轮没有新的 OpenVPN 节点通过出口实测；下表为上次实测通过的 "
                       f"{len(prev_ovpn)} 条配置（验证时间："
                       f"{html.escape(prev_at_o or '较早')}），可能已部分失效；"
                       "系统会继续自动筛选，验出新的后自动替换。</p>")
    else:
        ovpn_v_note = ("<p>本轮没有 OpenVPN 节点通过出口实测；下方普通 OpenVPN 列表"
                       "只做过连通性测试，未验出口。</p>")
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
<h2>OpenVPN 家宽节点（出口实测）</h2>
{ovpn_v_note}
<table border="1" cellspacing="0" cellpadding="6">
<tr><th>#</th><th>国家</th><th>服务器</th><th>实测出口 IP</th><th>出口运营商</th><th>配置</th></tr>
{rows_ov}
</table>
<h2>OpenVPN 节点（仅连通性测试）</h2>
<p>直连 = OpenVPN 应用直接导入；链式 = 先在本机开着 VLESS 客户端（SOCKS 10808）再导入链式配置。</p>
<table border="1" cellspacing="0" cellpadding="6">
<tr><th>#</th><th>国家</th><th>服务器</th><th>速度</th><th>列表Ping</th><th>实测</th><th>配置</th></tr>
{rows_o}
</table>
</body></html>
""".format(now=now, vless_note=vless_note, rows_v="\n".join(rows_v),
           ovpn_v_note=ovpn_v_note, rows_ov="\n".join(rows_ov),
           rows_o="\n".join(rows_o))
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
    print(f"published vless={len(vless_nodes)} ovpn={len(ovpn_nodes)} "
          f"ovpn_verified={len(ovpn_verified)} to {OUT_DIR}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
