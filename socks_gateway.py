#!/usr/bin/env python3
import argparse
import asyncio
import hmac
import ipaddress
import os
import random
import socket
import ssl
import struct
import time
from urllib.parse import urlparse

CONNECT_TIMEOUT = 8
HANDSHAKE_TIMEOUT = 10
IDLE_TIMEOUT = 600
WRITE_TIMEOUT = 60
MAX_RETRIES = 3
COOLDOWN_SECS = 60
FAILS_BEFORE_COOLDOWN = 3
EXPLORE_RATE = 0.10
HEALTH_INTERVAL = 30
HEALTH_TARGET = ("1.1.1.1", 443)
AUTH = None
UDP = None
UDP_PORT = 1080
PUBLIC_IP = None
UDP_IDLE = 60
UDP_CTRL_IDLE = 600
UDPGW_PORT = 7300
UDPGW_MAX_FLOWS = 64
UDPGW_TASKS = 32
UDP_TASKS = 128
UDP_ASSOCIATE = True
UDP_DIRECT = False
MAX_CONNS = 200
MAX_CONNS_PER_IP = 20
MAX_GLOBAL_FLOWS = 500
MAX_PEERS_PER_FLOW = 32
BLOCKED_PORTS = {25, 465, 587, 135, 137, 138, 139, 445}
LOG_DEST = False
AUTH_MAX_FAILS = 5
AUTH_WINDOW = 300
AUTH_BAN_SECS = 600

STATE = {"conns": 0, "flows": 0}
PER_IP = {}
AUTH_FAILS = {}
AUTH_BANS = {}
TASKS = set()

class BlockedError(ConnectionError):
    pass

def log(msg):
    if LOG_DEST:
        print(msg)

def spawn(coro):
    t = asyncio.ensure_future(coro)
    TASKS.add(t)
    t.add_done_callback(TASKS.discard)
    return t

class Limiter:
    def __init__(self, limit):
        self.limit, self.n = limit, 0
    def spawn(self, fn, *args):
        if self.n >= self.limit:
            return False
        self.n += 1
        async def run():
            try:
                await fn(*args)
            except Exception:
                pass
            finally:
                self.n -= 1
        spawn(run())
        return True

def close_flow(tr):
    try:
        tr.close()
    finally:
        STATE["flows"] = max(0, STATE["flows"] - 1)

def _norm_ip(ip):
    if ip.version == 6:
        if ip.ipv4_mapped: return ip.ipv4_mapped
        if ip.sixtofour: return ip.sixtofour
        if ip.teredo: return ip.teredo[1]
    return ip

def ip_is_public(ip):
    return _norm_ip(ip).is_global

def is_blocked_dest(host):
    h = host.lower().rstrip(".")
    if h == "localhost" or h.endswith((".localhost", ".local", ".internal", ".localdomain", ".lan", ".home.arpa")):
        return True
    try:
        return not ip_is_public(ipaddress.ip_address(h))
    except ValueError:
        return False

def port_blocked(port):
    return port in BLOCKED_PORTS or port == 0

async def resolve_public(host, v4_only=False):
    h = host.rstrip(".")
    if is_blocked_dest(h):
        return None
    try:
        ip = ipaddress.ip_address(h)
        return [str(ip)]
    except ValueError:
        pass
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(h, None, family=socket.AF_INET if v4_only else socket.AF_UNSPEC, type=socket.SOCK_STREAM)
    except Exception:
        return None
    ips = []
    for info in infos:
        a = info[4][0].split("%")[0]
        try:
            if not ip_is_public(ipaddress.ip_address(a)):
                return None
        except ValueError:
            return None
        if a not in ips:
            ips.append(a)
    return ips or None

def is_banned(ip):
    until = AUTH_BANS.get(ip)
    if until and until > time.time():
        return True
    AUTH_BANS.pop(ip, None)
    return False

def register_fail(ip):
    now = time.time()
    lst = [t for t in AUTH_FAILS.get(ip, []) if now - t < AUTH_WINDOW]
    lst.append(now)
    AUTH_FAILS[ip] = lst
    if len(lst) >= AUTH_MAX_FAILS:
        AUTH_BANS[ip] = now + AUTH_BAN_SECS
        AUTH_FAILS.pop(ip, None)
        log(f"[auth] banned {ip}")

def cleanup_auth():
    now = time.time()
    for ip, until in list(AUTH_BANS.items()):
        if until <= now: AUTH_BANS.pop(ip, None)
    for ip, lst in list(AUTH_FAILS.items()):
        if not lst or now - lst[-1] >= AUTH_WINDOW: AUTH_FAILS.pop(ip, None)

class Proxy:
    def __init__(self, line):
        self.line = line
        toks = line.split()
        spec = toks[0]
        self.tier = 1
        for t in toks[1:]:
            if t.lower().startswith("tier="):
                try: self.tier = int(t[5:])
                except ValueError: pass
        self.direct = spec.lower() == "direct"
        self.host = self.port = self.user = self.pw = None
        if not self.direct:
            u = urlparse(spec if "://" in spec else "socks5://" + spec)
            self.host, self.port = u.hostname, u.port or 1080
            self.user, self.pw = u.username, u.password
        self.alive = True
        self.latency = 1.0
        self.stats = {}
        self.cooldown = {}

    def name(self):
        return "direct" if self.direct else f"{self.host}:{self.port}"
    def score(self, host):
        ok, bad, _ = self.stats.get(host, [0, 0, 0])
        rate = (ok + 1) / (ok + bad + 2)
        return rate / (0.5 + self.latency)
    def available(self, host):
        return self.alive and self.cooldown.get(host, 0) < time.time()
    def record(self, host, success, latency=None):
        s = self.stats.setdefault(host, [0, 0, 0])
        if success:
            s[0] += 1; s[2] = 0
            if latency is not None: self.latency = 0.7 * self.latency + 0.3 * latency
        else:
            s[1] += 1; s[2] += 1
            if s[2] >= FAILS_BEFORE_COOLDOWN:
                self.cooldown[host] = time.time() + COOLDOWN_SECS
                s[2] = 0

_SLD = {"co", "com", "org", "net", "gov", "edu", "ac", "or", "ne", "go", "me", "ltd", "plc", "gob", "mil"}

def site_key(host):
    try:
        ipaddress.ip_address(host); return host
    except ValueError: pass
    parts = host.lower().rstrip(".").split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in _SLD:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])

def pick(proxies, host, exclude):
    key = site_key(host)
    cands = [p for p in proxies if p not in exclude and p.available(key)]
    if not cands: cands = [p for p in proxies if p not in exclude and p.alive]
    if not cands: return None
    best = min(p.tier for p in cands)
    cands = [p for p in cands if p.tier == best]
    if random.random() < EXPLORE_RATE: return random.choice(cands)
    return max(cands, key=lambda p: p.score(key))

def encode_addr(host):
    try:
        ip = ipaddress.ip_address(host)
        return (b"\x01" if ip.version == 4 else b"\x04") + ip.packed
    except ValueError:
        h = host.encode()
        return b"\x03" + bytes([len(h)]) + h

async def read_addr(r, atyp):
    if atyp == 1: return str(ipaddress.IPv4Address(await r.readexactly(4)))
    if atyp == 3:
        n = (await r.readexactly(1))[0]
        return (await r.readexactly(n)).decode()
    if atyp == 4: return str(ipaddress.IPv6Address(await r.readexactly(16)))
    raise ValueError("bad atyp")

async def upstream_connect(proxy, host, port):
    if proxy.direct:
        ips = await resolve_public(host)
        if not ips: raise BlockedError("blocked destination")
        last_err = None
        for ip in ips[:3]:
            try:
                return await asyncio.wait_for(asyncio.open_connection(ip, port), CONNECT_TIMEOUT)
            except Exception as e: last_err = e
        raise last_err

    r, w = await asyncio.wait_for(asyncio.open_connection(proxy.host, proxy.port), CONNECT_TIMEOUT)
    try:
        async def step():
            if proxy.user: w.write(b"\x05\x02\x00\x02")
            else: w.write(b"\x05\x01\x00")
            await w.drain()
            ver, method = await r.readexactly(2)
            if ver != 5 or method == 0xFF: raise ConnectionError("upstream auth method rejected")
            if method == 2:
                u, p = proxy.user.encode(), (proxy.pw or "").encode()
                w.write(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
                await w.drain()
                if (await r.readexactly(2))[1] != 0: raise ConnectionError("upstream auth failed")
            w.write(b"\x05\x01\x00" + encode_addr(host) + struct.pack(">H", port))
            await w.drain()
            _, rep, _, atyp = await r.readexactly(4)
            if rep != 0: raise ConnectionError(f"upstream replied {rep}")
            await read_addr(r, atyp)
            await r.readexactly(2)
        await asyncio.wait_for(step(), CONNECT_TIMEOUT)
        return r, w
    except Exception:
        w.close()
        raise

def udp_header(host, port):
    return b"\x00\x00\x00" + encode_addr(host) + struct.pack(">H", port)

def parse_udp(data):
    try:
        if len(data) < 10 or data[2] != 0: return None
        atyp = data[3]
        if atyp == 1: host, i = str(ipaddress.IPv4Address(data[4:8])), 8
        elif atyp == 3:
            n = data[4]
            host, i = data[5:5 + n].decode(errors="ignore"), 5 + n
        elif atyp == 4: host, i = str(ipaddress.IPv6Address(data[4:20])), 20
        else: return None
        port = struct.unpack(">H", data[i:i + 2])[0]
        return host, port, data[i + 2:]
    except Exception: return None

async def resolve_ok(host):
    ips = await resolve_public(host, v4_only=True)
    return ips[0] if ips else None

class Outbound(asyncio.DatagramProtocol):
    def __init__(self, relay, client):
        self.relay, self.client = relay, client
        self.transport, self.last = None, time.time()
        self.peers = set()
    def connection_made(self, t): self.transport = t
    def datagram_received(self, data, addr):
        if (addr[0], addr[1]) not in self.peers: return
        rt = self.relay.transport
        if rt is None or rt.is_closing(): return
        self.last = time.time()
        rt.sendto(udp_header(addr[0], addr[1]) + data, self.client)

class UDPRelay(asyncio.DatagramProtocol):
    def __init__(self, proxies):
        self.proxies = proxies
        self.allowed = {}
        self.seen = {}
        self.out = {}
        self.transport = None
        self.limiter = Limiter(UDP_TASKS)
    def connection_made(self, t): self.transport = t
    def allow(self, ip):
        self.allowed[ip] = self.allowed.get(ip, 0) + 1
        self.seen[ip] = time.time()
    def release(self, ip):
        n = self.allowed.get(ip, 0) - 1
        if n > 0:
            self.allowed[ip] = n
            return
        self.allowed.pop(ip, None)
        self.seen.pop(ip, None)
        for c in [c for c in self.out if c[0] == ip]:
            close_flow(self.out.pop(c).transport)
    def datagram_received(self, data, addr):
        if addr[0] not in self.allowed: return
        p = parse_udp(data)
        if p:
            self.seen[addr[0]] = time.time()
            self.limiter.spawn(self.forward, addr, *p)
    async def forward(self, client, host, port, payload):
        if port_blocked(port): return
        ip = await resolve_ok(host)
        if not ip: return
        if port == 53 and await self.dns_via_pool(client, ip, payload): return
        if not UDP_DIRECT or ":" in ip: return
        ob = self.out.get(client)
        if ob is None:
            if STATE["flows"] >= MAX_GLOBAL_FLOWS: return
            _, proto = await asyncio.get_running_loop().create_datagram_endpoint(lambda: Outbound(self, client), local_addr=("0.0.0.0", 0))
            if client in self.out:
                proto.transport.close()
                proto = self.out[client]
            else:
                STATE["flows"] += 1
                self.out[client] = proto
            ob = proto
        if (ip, port) not in ob.peers:
            if len(ob.peers) >= MAX_PEERS_PER_FLOW: return
            ob.peers.add((ip, port))
        if ob.transport.is_closing(): return
        ob.last = time.time()
        ob.transport.sendto(payload, (ip, port))
    async def dns_via_pool(self, client, ip, payload):
        resp = await dns_over_pool(self.proxies, ip, payload)
        if resp is None: return False
        if self.transport is not None and not self.transport.is_closing():
            self.transport.sendto(udp_header(ip, 53) + resp, client)
        return True
    async def gc(self):
        while True:
            await asyncio.sleep(15)
            now = time.time()
            for c in [c for c, o in self.out.items() if now - o.last > UDP_IDLE]:
                close_flow(self.out.pop(c).transport)

async def dns_over_pool(proxies, ip, payload):
    tried, key = set(), site_key(ip)
    for _ in range(MAX_RETRIES):
        p = pick(proxies, ip, tried)
        if p is None: break
        tried.add(p)
        t0 = time.time()
        try:
            r, w = await upstream_connect(p, ip, 53)
            try:
                w.write(struct.pack(">H", len(payload)) + payload)
                await asyncio.wait_for(w.drain(), CONNECT_TIMEOUT)
                n = struct.unpack(">H", await asyncio.wait_for(r.readexactly(2), CONNECT_TIMEOUT))[0]
                resp = await asyncio.wait_for(r.readexactly(n), CONNECT_TIMEOUT)
            finally:
                w.close()
            p.record(key, True, time.time() - t0)
            return resp
        except BlockedError: return None
        except Exception: p.record(key, False)
    return None

async def udpgw_session(cr, cw, proxies):
    loop = asyncio.get_running_loop()
    flows, peers, last = {}, {}, {}
    limiter = Limiter(UDPGW_TASKS)
    def send(conid, ip, port, data):
        if cw.transport.is_closing(): return
        v6 = ":" in ip
        body = (struct.pack("<BH", 8 if v6 else 0, conid) + ipaddress.ip_address(ip).packed + struct.pack(">H", port) + data)
        if len(body) <= 0xFFFF: cw.write(struct.pack("<H", len(body)) + body)
    def drop(c):
        tr = flows.pop(c, None); peers.pop(c, None); last.pop(c, None)
        if tr is not None: close_flow(tr)
    class Flow(asyncio.DatagramProtocol):
        def __init__(self, conid): self.conid = conid
        def datagram_received(self, data, addr):
            if (addr[0], addr[1]) not in peers.get(self.conid, ()): return
            last[self.conid] = time.time()
            send(self.conid, addr[0], addr[1], data)
    async def on_pkt(flags, conid, ip, port, data):
        if is_blocked_dest(ip) or port_blocked(port): return
        if port == 53 or flags & 4:
            resp = await dns_over_pool(proxies, ip, data)
            if resp is not None:
                send(conid, ip, port, resp)
                return
        if not UDP_DIRECT or ":" in ip: return
        if flags & 2 and conid in flows: drop(conid)
        tr = flows.get(conid)
        if tr is None:
            if len(flows) >= UDPGW_MAX_FLOWS or STATE["flows"] >= MAX_GLOBAL_FLOWS: return
            tr, _ = await loop.create_datagram_endpoint(lambda: Flow(conid), local_addr=("0.0.0.0", 0))
            if conid in flows:
                tr.close(); tr = flows[conid]
            else:
                flows[conid] = tr; peers[conid] = set(); STATE["flows"] += 1
        pr = peers.setdefault(conid, set())
        if (ip, port) not in pr:
            if len(pr) >= MAX_PEERS_PER_FLOW: return
            pr.add((ip, port))
        last[conid] = time.time()
        tr.sendto(data, (ip, port))
    async def gc():
        while True:
            await asyncio.sleep(15)
            now = time.time()
            for c in [c for c, t in last.items() if now - t > UDP_IDLE]: drop(c)
    gc_task = spawn(gc())
    try:
        while True:
            n = struct.unpack("<H", await asyncio.wait_for(cr.readexactly(2), IDLE_TIMEOUT))[0]
            pkt = await asyncio.wait_for(cr.readexactly(n), HANDSHAKE_TIMEOUT)
            if n < 3: continue
            flags, conid = struct.unpack("<BH", pkt[:3])
            if flags & 1: continue
            if flags & 8:
                if n < 21: continue
                ip = str(ipaddress.IPv6Address(pkt[3:19]))
                port, data = struct.unpack(">H", pkt[19:21])[0], pkt[21:]
            else:
                if n < 9: continue
                ip = str(ipaddress.IPv4Address(pkt[3:7]))
                port, data = struct.unpack(">H", pkt[7:9])[0], pkt[9:]
            limiter.spawn(on_pkt, flags, conid, ip, port, data)
    except (asyncio.IncompleteReadError, ConnectionError, asyncio.TimeoutError):
        pass
    finally:
        gc_task.cancel()
        for c in list(flows): drop(c)

async def pipe(src, dst, act):
    try:
        while True:
            try:
                data = await asyncio.wait_for(src.read(65536), IDLE_TIMEOUT)
            except asyncio.TimeoutError:
                if time.time() - act[0] < IDLE_TIMEOUT: continue
                break
            if not data:
                try:
                    if dst.can_write_eof(): dst.write_eof()
                    else: dst.close()
                except Exception: pass
                return
            act[0] = time.time()
            dst.write(data)
            await asyncio.wait_for(dst.drain(), WRITE_TIMEOUT)
    except Exception:
        pass
    try: dst.close()
    except Exception: pass

def reply(code):
    return b"\x05" + bytes([code]) + b"\x00\x01\x00\x00\x00\x00\x00\x00"

async def negotiate(cr, cw, cip):
    ver, n = await cr.readexactly(2)
    if ver != 5: return None
    methods = await cr.readexactly(n)
    if AUTH:
        if 2 not in methods:
            cw.write(b"\x05\xff")
            return None
        cw.write(b"\x05\x02")
        await cw.drain()
        v, ul = await cr.readexactly(2)
        u = await cr.readexactly(ul)
        pl = (await cr.readexactly(1))[0]
        pw = await cr.readexactly(pl)
        ok_u = hmac.compare_digest(u, AUTH[0].encode())
        ok_p = hmac.compare_digest(pw, AUTH[1].encode())
        if not (v == 1 and ok_u and ok_p):
            register_fail(cip)
            await asyncio.sleep(1)
            cw.write(b"\x01\x01")
            return None
        AUTH_FAILS.pop(cip, None)
        cw.write(b"\x01\x00")
    else:
        cw.write(b"\x05\x00")
    await cw.drain()
    ver, cmd, _, atyp = await cr.readexactly(4)
    host = await read_addr(cr, atyp)
    port = struct.unpack(">H", await cr.readexactly(2))[0]
    return cmd, host, port

async def udp_control_loop(cr, cip):
    while True:
        try:
            data = await asyncio.wait_for(cr.read(1024), 30)
        except asyncio.TimeoutError:
            if time.time() - UDP.seen.get(cip, 0) > UDP_CTRL_IDLE: return
            continue
        if not data: return

async def handle(cr, cw, proxies):
    peer = cw.get_extra_info("peername") or ("?", 0)
    cip = peer[0]
    if (STATE["conns"] >= MAX_CONNS or PER_IP.get(cip, 0) >= MAX_CONNS_PER_IP or is_banned(cip)):
        cw.close()
        return
    STATE["conns"] += 1
    PER_IP[cip] = PER_IP.get(cip, 0) + 1
    try:
        try:
            res = await asyncio.wait_for(negotiate(cr, cw, cip), HANDSHAKE_TIMEOUT)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError, ValueError, UnicodeDecodeError):
            return
        if res is None: return
        cmd, host, port = res
        if cmd == 3:
            if UDP is None or not UDP_ASSOCIATE:
                cw.write(reply(7)); return
            bnd = PUBLIC_IP or cw.get_extra_info("sockname")[0]
            UDP.allow(cip)
            try:
                cw.write(b"\x05\x00\x00" + encode_addr(bnd) + struct.pack(">H", UDP_PORT))
                await cw.drain()
                await udp_control_loop(cr, cip)
            finally:
                UDP.release(cip)
            return
        if cmd != 1:
            cw.write(reply(7)); return
        if UDPGW_PORT and port == UDPGW_PORT and host in ("127.0.0.1", "localhost"):
            cw.write(reply(0)); await cw.drain()
            await udpgw_session(cr, cw, proxies)
            return
        if is_blocked_dest(host) or port_blocked(port):
            cw.write(reply(2)); return
        tried = set()
        for _ in range(MAX_RETRIES):
            p = pick(proxies, host, tried)
            if p is None: break
            tried.add(p)
            key = site_key(host)
            t0 = time.time()
            try:
                ur, uw = await upstream_connect(p, host, port)
            except BlockedError:
                cw.write(reply(2)); return
            except Exception as e:
                p.record(key, False)
                log(f"[fail] {host}:{port} via {p.name()} ({e})")
                continue
            p.record(key, True, time.time() - t0)
            log(f"[ok]   {host}:{port} via {p.name()}")
            cw.write(reply(0)); await cw.drain()
            act = [time.time()]
            await asyncio.gather(pipe(cr, uw, act), pipe(ur, cw, act))
            try: uw.close()
            except Exception: pass
            return
        cw.write(reply(4)); await cw.drain()
    except (asyncio.IncompleteReadError, ConnectionError, asyncio.TimeoutError):
        pass
    except Exception as e:
        print(f"[error] {type(e).__name__}: {e}")
    finally:
        STATE["conns"] -= 1
        n = PER_IP.get(cip, 1) - 1
        if n > 0: PER_IP[cip] = n
        else: PER_IP.pop(cip, None)
        try: cw.close()
        except Exception: pass

async def health_loop(proxies):
    last_up = [None]
    async def check(p):
        t0 = time.time()
        try:
            _, w = await upstream_connect(p, *HEALTH_TARGET)
            w.close()
            if not p.alive: print(f"[health] {p.name()} UP")
            p.alive = True
            p.latency = 0.7 * p.latency + 0.3 * (time.time() - t0)
        except Exception:
            if p.alive: print(f"[health] {p.name()} DOWN")
            p.alive = False
    while True:
        await asyncio.gather(*(check(p) for p in proxies))
        up = sum(p.alive for p in proxies)
        if up != last_up[0]:
            print(f"[health] {up}/{len(proxies)} proxies alive")
            last_up[0] = up
        cleanup_auth()
        await asyncio.sleep(HEALTH_INTERVAL)

def env_flag(name, default):
    v = os.environ.get(name)
    return default if v is None else v.lower() in ("1", "true", "yes", "on")

def flag(x): return x.lower() in ("1", "true", "yes", "on")

async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--proxies", default="proxies.txt")
    ap.add_argument("--host", default=os.environ.get("HOST", "127.0.0.1"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("PORT", 1080)))
    ap.add_argument("--udpgw-port", type=int, default=int(os.environ.get("UDPGW_PORT", 7300)))
    ap.add_argument("--udp-associate", default=env_flag("UDP_ASSOCIATE", True), type=flag)
    ap.add_argument("--udp-direct", default=env_flag("UDP_DIRECT", False), type=flag)
    ap.add_argument("--max-conns", type=int, default=int(os.environ.get("MAX_CONNS", 200)))
    ap.add_argument("--max-per-ip", type=int, default=int(os.environ.get("MAX_PER_IP", 20)))
    ap.add_argument("--max-flows", type=int, default=int(os.environ.get("MAX_FLOWS", 500)))
    ap.add_argument("--idle", type=int, default=int(os.environ.get("IDLE_TIMEOUT", 600)))
    ap.add_argument("--udp-ctrl-idle", type=int, default=int(os.environ.get("UDP_CTRL_IDLE", 600)))
    ap.add_argument("--udp-tasks", type=int, default=int(os.environ.get("UDP_TASKS", 128)))
    ap.add_argument("--udpgw-tasks", type=int, default=int(os.environ.get("UDPGW_TASKS", 32)))
    ap.add_argument("--block-ports", default=os.environ.get("BLOCK_PORTS", "25,465,587,135,137,138,139,445"))
    ap.add_argument("--log-dest", default=env_flag("LOG_DEST", False), type=flag)
    ap.add_argument("--tls-cert", default=os.environ.get("TLS_CERT"))
    ap.add_argument("--tls-key", default=os.environ.get("TLS_KEY"))
    ap.add_argument("--public-ip", default=os.environ.get("PUBLIC_IP"))
    ap.add_argument("--user", default=os.environ.get("SOCKS_USER"))
    a = ap.parse_args()

    password = os.environ.get("SOCKS_PASS")
    pf = os.environ.get("SOCKS_PASS_FILE")
    if not password and pf:
        with open(pf, encoding="utf-8") as f: password = f.read().strip()

    global AUTH, UDP, UDP_PORT, PUBLIC_IP, UDPGW_PORT, UDP_ASSOCIATE, UDP_DIRECT
    global MAX_CONNS, MAX_CONNS_PER_IP, MAX_GLOBAL_FLOWS, IDLE_TIMEOUT
    global BLOCKED_PORTS, LOG_DEST, UDP_CTRL_IDLE, UDP_TASKS, UDPGW_TASKS
    UDPGW_PORT, UDP_ASSOCIATE, UDP_DIRECT = a.udpgw_port, a.udp_associate, a.udp_direct
    MAX_CONNS, MAX_CONNS_PER_IP, MAX_GLOBAL_FLOWS = a.max_conns, a.max_per_ip, a.max_flows
    IDLE_TIMEOUT, LOG_DEST = a.idle, a.log_dest
    UDP_CTRL_IDLE, UDP_TASKS, UDPGW_TASKS = a.udp_ctrl_idle, a.udp_tasks, a.udpgw_tasks
    BLOCKED_PORTS = {int(x) for x in a.block_ports.split(",") if x.strip()}
    UDP_PORT, PUBLIC_IP = a.port, a.public_ip
    if a.user and password: AUTH = (a.user, password)
    local = a.host in ("127.0.0.1", "::1", "localhost")
    if not local and not AUTH:
        raise SystemExit("رفض التشغيل: لا يمكن فتح الخادم للإنترنت بدون SOCKS_USER و SOCKS_PASS.")

    ssl_ctx = None
    if a.tls_cert and a.tls_key:
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ssl_ctx.load_cert_chain(a.tls_cert, a.tls_key)
    elif not local:
        print("[تحذير] لا يوجد TLS: اسم المستخدم وكلمة المرور تُرسل نصًا واضحًا.")

    with open(a.proxies, encoding="utf-8") as f:
        lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    proxies = [Proxy(l) for l in lines]
    if not proxies: raise SystemExit("proxies.txt فارغ")

    spawn(health_loop(proxies))
    if UDP_ASSOCIATE:
        _, UDP = await asyncio.get_running_loop().create_datagram_endpoint(lambda: UDPRelay(proxies), local_addr=(a.host, a.port))
        spawn(UDP.gc())
    server = await asyncio.start_server(lambda r, w: handle(r, w, proxies), a.host, a.port, ssl=ssl_ctx)
    print(f"SOCKS5 gateway on {a.host}:{a.port} | auth={'on' if AUTH else 'off'} | udpgw={UDPGW_PORT or 'off'} | {len(proxies)} upstreams")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass