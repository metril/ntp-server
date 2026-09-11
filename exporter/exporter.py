#!/usr/bin/env python3
"""ntp-server-exporter: passive NTP capture + pool.ntp.org score sidecar.

Two collectors share one prometheus_client HTTP endpoint:
  - capture: reads NTP packets off a raw AF_PACKET socket with a kernel-side
    cBPF `udp port 123` filter, geo/ASN-enriches each client IP with
    GeoLite2, and flushes country/ASN counters every CLIENTS_POLL_INTERVAL
    seconds. chronyd is never queried.
  - ntppool: polls ntppool.org's score JSON every NTPPOOL_POLL_INTERVAL
    seconds, exports score/offset/rtt gauges.

Frame parsing, the cBPF program, the HyperLogLog sketch, geo lookup and
ntppool-JSON parsing are pure functions/objects so they're testable without
root, real MMDB files, or network access; the collector classes wire them up
to real socket/maxminddb/requests calls.
"""

import ctypes
import hashlib
import logging
import math
import os
import socket
import struct
import threading
import time
from functools import lru_cache

import requests
from prometheus_client import (
    GC_COLLECTOR,
    PLATFORM_COLLECTOR,
    PROCESS_COLLECTOR,
    REGISTRY,
    Counter,
    Gauge,
    start_http_server,
)

log = logging.getLogger("ntp-server-exporter")

# --- Config -------------------------------------------------------------

NTPPOOL_IPV4 = os.environ.get("NTPPOOL_IPV4", "").strip()
NTP_ASN_TOP_N = int(os.environ.get("NTP_ASN_TOP_N", "25"))
GEOIP_DIR = os.environ.get("GEOIP_DIR", "/geoip")
LISTEN_ADDR = os.environ.get("LISTEN_ADDR", "127.0.0.1")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "9124"))
CLIENTS_POLL_INTERVAL = int(os.environ.get("CLIENTS_POLL_INTERVAL", "15"))
NTPPOOL_POLL_INTERVAL = int(os.environ.get("NTPPOOL_POLL_INTERVAL", "300"))

CAPTURE_RCVBUF_BYTES = 4 << 20
SOL_PACKET = 263
PACKET_STATISTICS = 6

NTPPOOL_USER_AGENT = "ntp-server-exporter/1.0 (+github.com/metril/ntp-server)"
NTPPOOL_URL_TEMPLATE = "https://www.ntppool.org/scores/{ip}/json?limit=10&monitor=*"
NTPPOOL_OVERALL_URL_TEMPLATE = "https://www.ntppool.org/scores/{ip}/json?limit=1"

ACTIVE_WINDOW_SECONDS = 300

# --- Pure functions: geo/ASN lookup -------------------------------------


def resolve_geo(ip, country_lookup, asn_lookup):
    """Resolve country/continent/ASN for `ip` via injected lookup callables.

    country_lookup(ip) / asn_lookup(ip) should return a maxminddb-style
    record dict, or None/raise on miss. Returns
    (country_iso, continent_code, asn, as_org); unresolved fields fall back
    to "unknown" (asn falls back to None).
    """
    country = "unknown"
    continent = "unknown"
    try:
        rec = country_lookup(ip)
    except Exception:
        rec = None
    if rec:
        country = (rec.get("country") or {}).get("iso_code") or "unknown"
        continent = (rec.get("continent") or {}).get("code") or "unknown"

    asn = None
    as_org = "unknown"
    try:
        arec = asn_lookup(ip)
    except Exception:
        arec = None
    if arec:
        asn = arec.get("autonomous_system_number")
        as_org = arec.get("autonomous_system_organization") or "unknown"

    return country, continent, asn, as_org


def top_n_asns(cumulative_totals, top_n):
    """Return the set of ASN keys ranked in the top `top_n` by total count."""
    ranked = sorted(cumulative_totals.items(), key=lambda kv: (-kv[1], str(kv[0])))
    return {asn for asn, _ in ranked[:top_n]}


def fold_asn(asn, as_org, cumulative_totals, top_n):
    """Fold `asn` to ("other", "other") if it's not in the top-N by
    cumulative total; otherwise pass through (asn, as_org) unchanged.
    Unknown ASN (None) folds to ("unknown", "unknown").
    """
    if asn is None:
        return "unknown", "unknown"
    if asn in top_n_asns(cumulative_totals, top_n):
        return asn, as_org
    return "other", "other"


# --- Pure functions: ntppool JSON parsing -------------------------------


def parse_ntppool(data):
    """Parse the per-monitor (`monitor=*`) ntppool.org score JSON body into a
    flat result dict: {"score": <float|None>, "monitors": {name: {"score",
    "offset_seconds", "rtt_seconds"}}}. "score" here is only the newest
    per-monitor history entry overall and must NOT be used as the pool's
    overall score (use parse_ntppool_overall_score with the non-monitor=*
    response for that); "monitors" holds the newest history entry per
    monitor_id. rtt is converted from ms to seconds. Monitor ids are
    resolved to names via the `monitors` list, falling back to the
    stringified id if unknown.
    """
    monitors_by_id = {}
    for m in data.get("monitors") or []:
        mid = m.get("id")
        if mid is not None:
            monitors_by_id[mid] = m.get("name") or str(mid)

    history = data.get("history") or []
    result = {"score": None, "monitors": {}}

    if history:
        newest = max(history, key=lambda h: h.get("ts") or "")
        result["score"] = newest.get("score")

    latest_by_monitor = {}
    for h in history:
        mid = h.get("monitor_id")
        if mid is None:
            continue
        ts = h.get("ts") or ""
        if mid not in latest_by_monitor or ts > (latest_by_monitor[mid].get("ts") or ""):
            latest_by_monitor[mid] = h

    for mid, h in latest_by_monitor.items():
        name = monitors_by_id.get(mid, str(mid))
        rtt = h.get("rtt")
        result["monitors"][name] = {
            "score": h.get("score"),
            "offset_seconds": h.get("offset"),
            "rtt_seconds": (rtt / 1000.0) if rtt is not None else None,
        }

    return result


def parse_ntppool_overall_score(data):
    """Parse the *overall* ntppool.org score JSON body (fetched without
    `monitor=*`, `limit=1`) into the pool's overall score, or None if there's
    no history. In this response shape, history entries represent the
    overall score over time and `monitor_id` may be absent or null.
    """
    history = data.get("history") or []
    if not history:
        return None
    newest = max(history, key=lambda h: h.get("ts") or "")
    return newest.get("score")


# --- Pure functions: frame parsing ---------------------------------------

ETH_HDR_LEN = 14
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_VLAN = 0x8100
IPPROTO_UDP = 17
NTP_PORT = 123


def parse_frame(frame):
    """Classify one captured Ethernet frame as NTP request or response.

    Returns ("request", src_ip) when the UDP destination port is 123,
    ("response", dst_ip) when the UDP source port is 123, else None.
    Handles an optional 802.1Q tag, IPv4 with a variable IHL, and IPv6 with
    next-header UDP only (extension headers are not walked). Pure: takes
    bytes, returns a tuple of text, touches no global state.
    """
    n = len(frame)
    if n < ETH_HDR_LEN:
        return None
    ethertype = int.from_bytes(frame[12:14], "big")
    off = ETH_HDR_LEN
    if ethertype == ETHERTYPE_VLAN:
        if n < off + 4:
            return None
        ethertype = int.from_bytes(frame[off + 2 : off + 4], "big")
        off += 4

    if ethertype == ETHERTYPE_IPV4:
        if n < off + 20:
            return None
        ihl = (frame[off] & 0x0F) * 4
        if ihl < 20 or n < off + ihl:
            return None
        if frame[off + 9] != IPPROTO_UDP:
            return None
        src = socket.inet_ntop(socket.AF_INET, frame[off + 12 : off + 16])
        dst = socket.inet_ntop(socket.AF_INET, frame[off + 16 : off + 20])
        off += ihl
    elif ethertype == ETHERTYPE_IPV6:
        if n < off + 40:
            return None
        if frame[off + 6] != IPPROTO_UDP:
            return None
        src = socket.inet_ntop(socket.AF_INET6, frame[off + 8 : off + 24])
        dst = socket.inet_ntop(socket.AF_INET6, frame[off + 24 : off + 40])
        off += 40
    else:
        return None

    if n < off + 8:
        return None
    sport = int.from_bytes(frame[off : off + 2], "big")
    dport = int.from_bytes(frame[off + 2 : off + 4], "big")
    if dport == NTP_PORT:
        return "request", src
    if sport == NTP_PORT:
        return "response", dst
    return None


# --- cBPF filter: "udp port 123" over IPv4 and IPv6 -----------------------

SO_ATTACH_FILTER = 26

# struct sock_filter { __u16 code; __u8 jt; __u8 jf; __u32 k; }
_BPF_INSN = struct.Struct("HBBI")

# Opcodes used below.
_LD_H_ABS = 0x28  # ldh  [k]
_LD_B_ABS = 0x30  # ldb  [k]
_LD_H_IND = 0x48  # ldh  [x + k]
_LDX_B_MSH = 0xB1  # ldxb 4*([k]&0xf)
_JEQ_K = 0x15  # jeq  #k
_JSET_K = 0x45  # jset #k
_RET_K = 0x06  # ret  #k


def build_ntp_bpf():
    """Build the packed classic-BPF program equivalent to `udp port 123`.

    Accepts an unfragmented IPv4 UDP datagram (IHL honoured via ldxb) or an
    IPv6 datagram whose next header is UDP, with source or destination port
    123; returns 0xFFFF (accept whole frame) or 0 (drop). Jump targets are
    relative to the instruction after the jump, so the indices below are the
    absolute instruction numbers: 18 = accept, 19 = reject.
    """
    prog = [
        # 0: ethertype
        (_LD_H_ABS, 0, 0, 12),
        (_JEQ_K, 1, 0, ETHERTYPE_IPV4),  # 1 -> 3 (v4) else 2
        (_JEQ_K, 9, 16, ETHERTYPE_IPV6),  # 2 -> 12 (v6) else 19
        # IPv4
        (_LD_B_ABS, 0, 0, 23),  # 3: protocol
        (_JEQ_K, 0, 14, IPPROTO_UDP),  # 4 -> 5 else 19
        (_LD_H_ABS, 0, 0, 20),  # 5: flags + fragment offset
        (_JSET_K, 12, 0, 0x1FFF),  # 6: fragment -> 19 else 7
        (_LDX_B_MSH, 0, 0, ETH_HDR_LEN),  # 7: X = IHL * 4
        (_LD_H_IND, 0, 0, 14),  # 8: source port
        (_JEQ_K, 8, 0, NTP_PORT),  # 9 -> 18 else 10
        (_LD_H_IND, 0, 0, 16),  # 10: destination port
        (_JEQ_K, 6, 7, NTP_PORT),  # 11 -> 18 else 19
        # IPv6
        (_LD_B_ABS, 0, 0, 20),  # 12: next header
        (_JEQ_K, 0, 5, IPPROTO_UDP),  # 13 -> 14 else 19
        (_LD_H_ABS, 0, 0, 54),  # 14: source port
        (_JEQ_K, 2, 0, NTP_PORT),  # 15 -> 18 else 16
        (_LD_H_ABS, 0, 0, 56),  # 16: destination port
        (_JEQ_K, 0, 1, NTP_PORT),  # 17 -> 18 else 19
        (_RET_K, 0, 0, 0xFFFF),  # 18: accept
        (_RET_K, 0, 0, 0),  # 19: reject
    ]
    return b"".join(_BPF_INSN.pack(*insn) for insn in prog)


class _SockFprog(ctypes.Structure):
    # struct sock_fprog { unsigned short len; struct sock_filter *filter; }
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]


def attach_filter(sock, program):
    """Attach a packed cBPF `program` to `sock` via SO_ATTACH_FILTER.

    Returns the ctypes buffer holding the program; the kernel copies it
    during setsockopt, but the buffer must outlive the call itself.
    """
    buf = ctypes.create_string_buffer(program, len(program))
    fprog = _SockFprog(len(program) // _BPF_INSN.size, ctypes.cast(buf, ctypes.c_void_p))
    sock.setsockopt(
        socket.SOL_SOCKET,
        SO_ATTACH_FILTER,
        ctypes.string_at(ctypes.addressof(fprog), ctypes.sizeof(fprog)),
    )
    return buf


# --- HyperLogLog ----------------------------------------------------------


class HyperLogLog:
    """Fixed-precision HyperLogLog over SHA-1-hashed string keys.

    p=14 gives m=16384 one-byte registers (16 KiB) and ~0.81 % standard
    error. Only the small-range linear-counting correction is applied; with
    a 64-bit hash the large-range correction is unnecessary.
    """

    __slots__ = ("p", "m", "_alpha", "_bits", "registers")

    def __init__(self, p=14):
        if not 4 <= p <= 16:
            raise ValueError("p must be between 4 and 16")
        self.p = p
        self.m = 1 << p
        self._bits = 64 - p
        self._alpha = 0.7213 / (1.0 + 1.079 / self.m)
        self.registers = bytearray(self.m)

    def add(self, key):
        h = int.from_bytes(
            hashlib.sha1(key.encode("utf-8"), usedforsecurity=False).digest()[:8], "big"
        )
        idx = h >> self._bits
        w = h & ((1 << self._bits) - 1)
        rho = self._bits + 1 if w == 0 else self._bits - w.bit_length() + 1
        if rho > self.registers[idx]:
            self.registers[idx] = rho

    def merge(self, other):
        if other.p != self.p:
            raise ValueError("cannot merge HyperLogLog sketches of different precision")
        mine = self.registers
        theirs = other.registers
        for i in range(self.m):
            if theirs[i] > mine[i]:
                mine[i] = theirs[i]

    def count(self):
        raw = 0.0
        zeros = 0
        for r in self.registers:
            raw += 1.0 / (1 << r)
            if r == 0:
                zeros += 1
        estimate = self._alpha * self.m * self.m / raw
        if estimate <= 2.5 * self.m and zeros:
            return self.m * math.log(self.m / zeros)
        return estimate


# --- Metrics -------------------------------------------------------------

for _c in (PROCESS_COLLECTOR, PLATFORM_COLLECTOR, GC_COLLECTOR):
    try:
        REGISTRY.unregister(_c)
    except KeyError:
        pass

ntp_client_requests_total = Counter(
    "ntp_client_requests_total", "NTP client requests by country", ["country", "continent"]
)
ntp_client_drops_total = Counter(
    "ntp_client_drops_total", "NTP client dropped requests by country", ["country", "continent"]
)
ntp_client_requests_by_asn_total = Counter(
    "ntp_client_requests_by_asn_total",
    "NTP client requests by ASN (top-N, rest folded to 'other')",
    ["asn", "as_org"],
)
ntp_clients_active = Gauge("ntp_clients_active", "Distinct client IPs seen in the last 300s")
ntp_clients_unique_daily = Gauge(
    "ntp_clients_unique_daily", "Distinct client IPs seen in the last 24h"
)
ntp_clients_scrape_success = Gauge(
    "ntp_clients_scrape_success", "1 while the NTP capture socket is open"
)
ntp_capture_packets_total = Counter(
    "ntp_capture_packets_total", "NTP frames captured, by direction", ["direction"]
)
ntp_capture_parse_errors_total = Counter(
    "ntp_capture_parse_errors_total",
    "Frames that passed the BPF filter but could not be parsed",
)
ntp_capture_loop_errors_total = Counter(
    "ntp_capture_loop_errors_total",
    "Unexpected exceptions in the capture loop (geo/prometheus errors etc.), swallowed to keep the daemon alive",
)
ntp_capture_kernel_drops_total = Counter(
    "ntp_capture_kernel_drops_total",
    "Packets the kernel dropped before the capture socket could read them (PACKET_STATISTICS)",
)

ntppool_score = Gauge("ntppool_score", "Latest pool.ntp.org score", ["ip"])
ntppool_monitor_score = Gauge(
    "ntppool_monitor_score", "Latest pool.ntp.org score per monitor", ["ip", "monitor"]
)
ntppool_monitor_offset_seconds = Gauge(
    "ntppool_monitor_offset_seconds",
    "Latest pool.ntp.org offset per monitor, seconds",
    ["ip", "monitor"],
)
ntppool_monitor_rtt_seconds = Gauge(
    "ntppool_monitor_rtt_seconds", "Latest pool.ntp.org RTT per monitor, seconds", ["ip", "monitor"]
)
ntppool_scrape_success = Gauge(
    "ntppool_scrape_success", "1 if the last ntppool.org poll succeeded"
)


# --- GeoIP reader with reopen-on-mtime + LRU cache ----------------------


class GeoIPResolver:
    """Wraps two maxminddb readers (country + ASN), reopening each when its
    file's mtime changes, with an LRU-cached lookup per IP.
    """

    def __init__(self, geoip_dir, cache_size=8192):
        import maxminddb

        self._maxminddb = maxminddb
        self._country_path = os.path.join(geoip_dir, "GeoLite2-Country.mmdb")
        self._asn_path = os.path.join(geoip_dir, "GeoLite2-ASN.mmdb")
        self._country_reader = None
        self._asn_reader = None
        self._country_mtime = None
        self._asn_mtime = None
        self._cache_size = cache_size
        self._resolve_cached = lru_cache(maxsize=cache_size)(self._resolve_uncached)

    def _reopen_if_needed(self):
        try:
            mtime = os.path.getmtime(self._country_path)
        except OSError:
            mtime = None
        if mtime != self._country_mtime:
            self._country_mtime = mtime
            old_reader = self._country_reader
            try:
                self._country_reader = self._maxminddb.open_database(self._country_path)
            except Exception:
                log.warning("failed to open %s", self._country_path)
                self._country_reader = None
            if old_reader is not None:
                try:
                    old_reader.close()
                except Exception:
                    log.warning("failed to close old %s reader", self._country_path)
            self._resolve_cached.cache_clear()

        try:
            mtime = os.path.getmtime(self._asn_path)
        except OSError:
            mtime = None
        if mtime != self._asn_mtime:
            self._asn_mtime = mtime
            old_reader = self._asn_reader
            try:
                self._asn_reader = self._maxminddb.open_database(self._asn_path)
            except Exception:
                log.warning("failed to open %s", self._asn_path)
                self._asn_reader = None
            if old_reader is not None:
                try:
                    old_reader.close()
                except Exception:
                    log.warning("failed to close old %s reader", self._asn_path)
            self._resolve_cached.cache_clear()

    def _country_lookup(self, ip):
        return self._country_reader.get(ip) if self._country_reader else None

    def _asn_lookup(self, ip):
        return self._asn_reader.get(ip) if self._asn_reader else None

    def _resolve_uncached(self, ip):
        return resolve_geo(ip, self._country_lookup, self._asn_lookup)

    def resolve(self, ip):
        self._reopen_if_needed()
        return self._resolve_cached(ip)


# --- Capture collector ----------------------------------------------------


def open_capture_socket():
    """Open an unbound AF_PACKET/SOCK_RAW socket filtered to udp port 123."""
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, CAPTURE_RCVBUF_BYTES)
        attach_filter(sock, build_ntp_bpf())  # buffer only needs to outlive setsockopt
        sock.settimeout(1.0)
    except Exception:
        sock.close()
        raise
    return sock


class PacketCollector:
    """Aggregates captured NTP frames in memory and flushes to prometheus.

    The hot path (handle_frame) only touches plain dicts and the hourly HLL
    sketches; the registry is written once per flush.
    """

    def __init__(self, geo_resolver, asn_top_n, sock_factory, clock=time.monotonic, wall=time.time):
        self._geo = geo_resolver
        self._asn_top_n = asn_top_n
        self._sock_factory = sock_factory
        self._clock = clock
        self._wall = wall
        self._requests = {}  # (country, continent) -> count since last flush
        self._responses = {}  # (country, continent) -> count since last flush
        self._asn_requests = {}  # (asn, as_org) -> count since last flush
        self._asn_totals = {}  # asn -> cumulative requests, for top-N ranking
        self._active = {}  # ip -> last-seen monotonic time
        self._hourly = [HyperLogLog() for _ in range(24)]
        self._hour = None
        self._sock = None

    def _current_bucket(self):
        hour = time.gmtime(self._wall()).tm_hour
        if self._hour is None:
            self._hour = hour
        elif hour != self._hour:
            # Clear every bucket skipped since the last update (quiet period
            # or capture socket down), not just the newly-current one, so a
            # multi-hour gap can't leave stale same-hour-yesterday data.
            h = (self._hour + 1) % 24
            while True:
                self._hourly[h] = HyperLogLog()
                if h == hour:
                    break
                h = (h + 1) % 24
            self._hour = hour
        return self._hourly[hour]

    def handle_frame(self, frame):
        parsed = parse_frame(frame)
        if parsed is None:
            ntp_capture_parse_errors_total.inc()
            return
        direction, ip = parsed
        ntp_capture_packets_total.labels(direction=direction).inc()

        country, continent, asn, as_org = self._geo.resolve(ip)
        key = (country, continent)
        if direction == "request":
            self._requests[key] = self._requests.get(key, 0) + 1
            akey = (asn, as_org)
            self._asn_requests[akey] = self._asn_requests.get(akey, 0) + 1
            self._active[ip] = self._clock()
            self._current_bucket().add(ip)
        else:
            self._responses[key] = self._responses.get(key, 0) + 1

    def _read_kernel_drops(self):
        """Read and reset the kernel's AF_PACKET drop counter for self._sock.

        Returns 0 if there's no socket, it doesn't support getsockopt (fakes
        in tests), or the read fails.
        """
        sock = self._sock
        if sock is None:
            return 0
        getsockopt = getattr(sock, "getsockopt", None)
        if getsockopt is None:
            return 0
        try:
            raw = getsockopt(SOL_PACKET, PACKET_STATISTICS, 8)
        except OSError:
            return 0
        _tp_packets, tp_drops = struct.unpack("II", raw)
        return tp_drops

    def flush(self):
        self._current_bucket()

        drops = self._read_kernel_drops()
        if drops:
            ntp_capture_kernel_drops_total.inc(drops)

        requests, self._requests = self._requests, {}
        responses, self._responses = self._responses, {}
        asn_requests, self._asn_requests = self._asn_requests, {}

        for (country, continent), n in requests.items():
            ntp_client_requests_total.labels(country=country, continent=continent).inc(n)
            drops = n - responses.get((country, continent), 0)
            if drops > 0:
                ntp_client_drops_total.labels(country=country, continent=continent).inc(drops)

        for (asn, _org), n in asn_requests.items():
            if asn is not None:
                self._asn_totals[asn] = self._asn_totals.get(asn, 0) + n
        for (asn, as_org), n in asn_requests.items():
            fasn, forg = fold_asn(asn, as_org, self._asn_totals, self._asn_top_n)
            ntp_client_requests_by_asn_total.labels(asn=str(fasn), as_org=forg).inc(n)

        cutoff = self._clock() - ACTIVE_WINDOW_SECONDS
        for ip in [ip for ip, seen in self._active.items() if seen < cutoff]:
            del self._active[ip]
        ntp_clients_active.set(len(self._active))

        merged = HyperLogLog()
        for sketch in self._hourly:
            merged.merge(sketch)
        ntp_clients_unique_daily.set(merged.count())

    def run_forever(self, interval):
        sock = None
        last_flush = self._clock()
        while True:
            if sock is None:
                try:
                    sock = self._sock_factory()
                except Exception:
                    log.exception("failed to open NTP capture socket; retrying in 30s")
                    ntp_clients_scrape_success.set(0)
                    time.sleep(30)
                    continue
                self._sock = sock
                log.info("NTP capture socket open")
                ntp_clients_scrape_success.set(1)

            try:
                try:
                    frame = sock.recv(65535)
                except TimeoutError:
                    frame = None
                except OSError:
                    log.exception("NTP capture socket read failed; reopening")
                    ntp_clients_scrape_success.set(0)
                    try:
                        sock.close()
                    except OSError:
                        pass
                    sock = None
                    self._sock = None
                    frame = None

                if frame:
                    self.handle_frame(frame)

                now = self._clock()
                if now - last_flush >= interval:
                    self.flush()
                    last_flush = now
            except Exception:
                log.exception("capture loop error")
                ntp_capture_loop_errors_total.inc()
                continue


# --- ntppool collector -----------------------------------------------------


class NtpPoolCollector:
    def __init__(self, ipv4, session=None):
        self._ipv4 = ipv4
        self._session = session or requests.Session()

    def _get_json(self, url):
        resp = self._session.get(url, headers={"User-Agent": NTPPOOL_USER_AGENT}, timeout=10)
        resp.raise_for_status()
        return resp.json()

    def poll_once(self):
        if not self._ipv4:
            return
        monitor_url = NTPPOOL_URL_TEMPLATE.format(ip=self._ipv4)
        overall_url = NTPPOOL_OVERALL_URL_TEMPLATE.format(ip=self._ipv4)
        try:
            data = self._get_json(monitor_url)
            overall_data = self._get_json(overall_url)
        except Exception:
            log.exception("ntppool.org poll failed")
            ntppool_scrape_success.set(0)
            return  # keep last values

        parsed = parse_ntppool(data)
        overall_score = parse_ntppool_overall_score(overall_data)
        if overall_score is not None:
            ntppool_score.labels(ip=self._ipv4).set(overall_score)
        for monitor, vals in parsed["monitors"].items():
            if vals["score"] is not None:
                ntppool_monitor_score.labels(ip=self._ipv4, monitor=monitor).set(vals["score"])
            if vals["offset_seconds"] is not None:
                ntppool_monitor_offset_seconds.labels(ip=self._ipv4, monitor=monitor).set(
                    vals["offset_seconds"]
                )
            if vals["rtt_seconds"] is not None:
                ntppool_monitor_rtt_seconds.labels(ip=self._ipv4, monitor=monitor).set(
                    vals["rtt_seconds"]
                )
        ntppool_scrape_success.set(1)

    def run_forever(self, interval):
        while True:
            self.poll_once()
            time.sleep(interval)


# --- Entrypoint -------------------------------------------------------------


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    start_http_server(LISTEN_PORT, addr=LISTEN_ADDR)
    log.info("listening on %s:%s", LISTEN_ADDR, LISTEN_PORT)

    geo = GeoIPResolver(GEOIP_DIR)
    capture = PacketCollector(geo, NTP_ASN_TOP_N, open_capture_socket)
    ntppool = NtpPoolCollector(NTPPOOL_IPV4)

    if not NTPPOOL_IPV4:
        log.info("NTPPOOL_IPV4 not set; ntppool collector disabled")

    t = threading.Thread(target=capture.run_forever, args=(CLIENTS_POLL_INTERVAL,), daemon=True)
    t.start()

    ntppool.run_forever(NTPPOOL_POLL_INTERVAL)


if __name__ == "__main__":
    main()
