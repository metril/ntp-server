#!/usr/bin/env python3
"""ntp-server-exporter: passive NTP capture + pool.ntp.org score sidecar.

Two collectors share one prometheus_client HTTP endpoint:
  - capture: reads NTP packets off a raw AF_PACKET socket with a kernel-side
    cBPF `udp port 123` filter, geo/ASN-enriches each client IP with
    GeoLite2, and flushes country/ASN/version/family counters every
    CLIENTS_POLL_INTERVAL seconds. chronyd is never queried. Kernel receive
    timestamps (SO_TIMESTAMPNS) pair each request with its response by NTP
    transmit/origin timestamp to measure passive request-to-response
    latency, and per-client request spacing feeds an active-client interval
    histogram.
  - ntppool: polls ntppool.org's score JSON every NTPPOOL_POLL_INTERVAL
    seconds, exports score/offset/rtt gauges.

Frame parsing, the cBPF program, the HyperLogLog sketch, geo lookup and
ntppool-JSON parsing are pure functions/objects so they're testable without
root, real MMDB files, or network access; the collector classes wire them up
to real socket/maxminddb/requests calls.
"""

import ctypes
import hashlib
import heapq
import logging
import math
import os
import socket
import struct
import threading
import time
from functools import lru_cache
from typing import NamedTuple

import requests
from prometheus_client import (
    GC_COLLECTOR,
    PLATFORM_COLLECTOR,
    PROCESS_COLLECTOR,
    REGISTRY,
    Counter,
    Gauge,
    Histogram,
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

CAPTURE_RCVBUF_BYTES = 8 << 20  # ~4k frames / 2.5s of traffic; see scripts/check-host.sh
SOL_PACKET = 263
PACKET_STATISTICS = 6
GEOIP_REOPEN_CHECK_SECONDS = 30

# Cap on the cumulative per-ASN totals table used to rank the top-N. Ranking
# only needs the head of the distribution, so once the table grows past
# this, flush() prunes it back down by keeping the largest totals -- that
# can't change which ASNs are in the top-N.
ASN_TOTALS_MAX = 4096

NTPPOOL_USER_AGENT = "ntp-server-exporter/1.0 (+github.com/metril/ntp-server)"
NTPPOOL_URL_TEMPLATE = "https://www.ntppool.org/scores/{ip}/json?limit=10&monitor=*"
NTPPOOL_OVERALL_URL_TEMPLATE = "https://www.ntppool.org/scores/{ip}/json?limit=1"

ACTIVE_WINDOW_SECONDS = 300
PENDING_MAX = 50000
PENDING_TTL_SECONDS = 2
PENDING_SWEEP_EVERY = 1024

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


class _AscendingStr:
    """Wraps a string so it compares as "larger" when it sorts earlier in
    plain ascending order. Lets heapq.nlargest() reproduce the tie-break of
    the old `sorted(..., key=lambda kv: (-count, str(asn)))` (ties broken by
    the smaller string) while still maximizing on count for the primary key.
    """

    __slots__ = ("s",)

    def __init__(self, s):
        self.s = s

    def __lt__(self, other):
        return self.s > other.s

    def __eq__(self, other):
        return self.s == other.s


def top_n_asns(cumulative_totals, top_n):
    """Return the set of ASN keys ranked in the top `top_n` by total count.

    Uses heapq.nlargest instead of sorting the whole table, since this is
    called once per flush rather than once per distinct ASN -- sorting the
    full cumulative table on every flush is what caused the capture drops
    this is fixing. Same tie-break as before: ties broken by ascending
    str(asn).
    """
    ranked = heapq.nlargest(
        top_n, cumulative_totals.items(), key=lambda kv: (kv[1], _AscendingStr(str(kv[0])))
    )
    return {asn for asn, _ in ranked}


def fold_asn(asn, as_org, top_asns):
    """Fold `asn` to ("other", "other") if it's not in `top_asns`;
    otherwise pass through (asn, as_org) unchanged. Unknown ASN (None) folds
    to ("unknown", "unknown"). Takes the already-computed top-N set (see
    top_n_asns) so callers don't recompute it once per distinct ASN.
    """
    if asn is None:
        return "unknown", "unknown"
    if asn in top_asns:
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


NTP_PAYLOAD_MIN = 48


class ParsedFrame(NamedTuple):
    direction: str
    ip: str
    family: str
    version: "str | None"
    xid: "bytes | None"


def _ntp_version(payload):
    v = (payload[0] >> 3) & 7
    if 1 <= v <= 4:
        return str(v)
    return "other"


def parse_ntp_frame(frame):
    """Classify one captured Ethernet frame as an NTP request or response
    and extract its NTP-layer fields.

    Returns a ParsedFrame(direction, ip, family, version, xid), or None if
    the frame isn't a parseable NTP-over-UDP packet. `ip` is the client IP
    (src for a request, dst for a response); `family` is "ipv4"/"ipv6".
    When the UDP payload is shorter than a full 48-byte NTP header, version
    and xid are None. `version` is the NTP version field as text, clamped to
    "other" outside 1..4. `xid` pairs a request with its response: for a
    request it's the transmit timestamp (bytes 40:48), which the server
    echoes back as the response's origin timestamp (bytes 24:32).

    Handles an optional 802.1Q tag, IPv4 with a variable IHL, and IPv6 with
    next-header UDP only (extension headers are not walked). Pure: takes
    bytes, returns a namedtuple, touches no global state.
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
        family = "ipv4"
    elif ethertype == ETHERTYPE_IPV6:
        if n < off + 40:
            return None
        if frame[off + 6] != IPPROTO_UDP:
            return None
        src = socket.inet_ntop(socket.AF_INET6, frame[off + 8 : off + 24])
        dst = socket.inet_ntop(socket.AF_INET6, frame[off + 24 : off + 40])
        off += 40
        family = "ipv6"
    else:
        return None

    if n < off + 8:
        return None
    sport = int.from_bytes(frame[off : off + 2], "big")
    dport = int.from_bytes(frame[off + 2 : off + 4], "big")
    off += 8
    payload = frame[off:]

    if dport == NTP_PORT:
        direction, ip = "request", src
    elif sport == NTP_PORT:
        direction, ip = "response", dst
    else:
        return None

    version = None
    xid = None
    if len(payload) >= NTP_PAYLOAD_MIN:
        version = _ntp_version(payload)
        xid = payload[40:48] if direction == "request" else payload[24:32]

    return ParsedFrame(direction, ip, family, version, xid)


def parse_frame(frame):
    """Classify one captured Ethernet frame as NTP request or response.

    Returns ("request", src_ip) when the UDP destination port is 123,
    ("response", dst_ip) when the UDP source port is 123, else None.
    Thin wrapper over parse_ntp_frame() for callers that only need
    direction/IP. Pure: takes bytes, returns a tuple of text, touches no
    global state.
    """
    parsed = parse_ntp_frame(frame)
    return None if parsed is None else (parsed.direction, parsed.ip)


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
ntp_capture_pending_overflow_total = Counter(
    "ntp_capture_pending_overflow_total",
    "Requests dropped from the request/response pairing table because it was full (PENDING_MAX)",
)
ntp_capture_rcvbuf_bytes = Gauge(
    "ntp_capture_rcvbuf_bytes",
    "Effective SO_RCVBUF on the capture socket, as reported by getsockopt after the request",
)
ntp_client_requests_by_version_total = Counter(
    "ntp_client_requests_by_version_total", "NTP client requests by NTP version", ["version"]
)
ntp_client_requests_by_family_total = Counter(
    "ntp_client_requests_by_family_total", "NTP client requests by IP family", ["family"]
)
ntp_client_request_interval_seconds = Histogram(
    "ntp_client_request_interval_seconds",
    "Seconds between consecutive requests from the same client IP; intervals longer than "
    "roughly 300s are not observed because the client has left the active window",
    buckets=(0.5, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, float("inf")),
)
ntp_response_latency_seconds = Histogram(
    "ntp_response_latency_seconds",
    "Server request-to-response latency measured passively",
    buckets=(20e-6, 50e-6, 100e-6, 200e-6, 500e-6, 1e-3, 2e-3, 5e-3, 10e-3, 25e-3, 50e-3, float("inf")),
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


ntp_geoip_database_loaded = Gauge(
    "ntp_geoip_database_loaded",
    "1 if the GeoLite2 mmdb is open and readable",
    ["db"],
)


# --- GeoIP reader with reopen-on-mtime + LRU cache ----------------------


class GeoIPResolver:
    """Wraps two maxminddb readers (country + ASN), reopening each when its
    file's mtime changes, with an LRU-cached lookup per IP.
    """

    def __init__(self, geoip_dir, cache_size=8192, clock=time.monotonic):
        import maxminddb

        self._maxminddb = maxminddb
        self._country_path = os.path.join(geoip_dir, "GeoLite2-Country.mmdb")
        self._asn_path = os.path.join(geoip_dir, "GeoLite2-ASN.mmdb")
        self._country_reader = None
        self._asn_reader = None
        self._country_mtime = None
        self._asn_mtime = None
        self._country_missing_warned = False
        self._asn_missing_warned = False
        self._cache_size = cache_size
        self._resolve_cached = lru_cache(maxsize=cache_size)(self._resolve_uncached)
        self._clock = clock
        self._last_reopen_check = None

    def _reopen_one(self, path, reader, mtime_attr, missing_warned_attr, db_label):
        old_mtime = getattr(self, mtime_attr)
        try:
            mtime = os.path.getmtime(path)
        except OSError as exc:
            setattr(self, mtime_attr, None)
            if reader is None and not getattr(self, missing_warned_attr):
                log.warning("GeoIP database missing: %s (%s)", path, exc)
                setattr(self, missing_warned_attr, True)
            ntp_geoip_database_loaded.labels(db=db_label).set(1 if reader is not None else 0)
            return reader

        setattr(self, missing_warned_attr, False)
        if mtime != old_mtime:
            setattr(self, mtime_attr, mtime)
            old_reader = reader
            try:
                reader = self._maxminddb.open_database(path)
            except Exception:
                log.warning("failed to open %s", path)
                reader = None
            if old_reader is not None:
                try:
                    old_reader.close()
                except Exception:
                    log.warning("failed to close old %s reader", path)
            self._resolve_cached.cache_clear()

        ntp_geoip_database_loaded.labels(db=db_label).set(1 if reader is not None else 0)
        return reader

    def _reopen_if_needed(self):
        self._country_reader = self._reopen_one(
            self._country_path,
            self._country_reader,
            "_country_mtime",
            "_country_missing_warned",
            "country",
        )
        self._asn_reader = self._reopen_one(
            self._asn_path,
            self._asn_reader,
            "_asn_mtime",
            "_asn_missing_warned",
            "asn",
        )

    def _country_lookup(self, ip):
        return self._country_reader.get(ip) if self._country_reader else None

    def _asn_lookup(self, ip):
        return self._asn_reader.get(ip) if self._asn_reader else None

    def _resolve_uncached(self, ip):
        return resolve_geo(ip, self._country_lookup, self._asn_lookup)

    def resolve(self, ip):
        now = self._clock()
        if (
            self._last_reopen_check is None
            or now - self._last_reopen_check >= GEOIP_REOPEN_CHECK_SECONDS
        ):
            self._reopen_if_needed()
            self._last_reopen_check = now
        return self._resolve_cached(ip)


# --- Capture collector ----------------------------------------------------


SO_TIMESTAMPNS = 35
SCM_TIMESTAMPNS = 35
PACKET_HOST = 0
PACKET_OUTGOING = 4


def open_capture_socket():
    """Open an unbound AF_PACKET/SOCK_RAW socket filtered to udp port 123."""
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, CAPTURE_RCVBUF_BYTES)
        sock.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMPNS, 1)
        attach_filter(sock, build_ntp_bpf())  # buffer only needs to outlive setsockopt

        # The kernel may silently cap SO_RCVBUF below what we asked for (via
        # net.core.rmem_max), which starves the socket buffer under load --
        # this is what caused the 56% capture drop this is fixing. Surface
        # the effective value and warn once so it's visible without a
        # packet-drop postmortem.
        effective_rcvbuf = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        ntp_capture_rcvbuf_bytes.set(effective_rcvbuf)
        # getsockopt reports double the request when it was honoured, so
        # anything below 2x means rmem_max capped it.
        if effective_rcvbuf < 2 * CAPTURE_RCVBUF_BYTES and not open_capture_socket.warned:
            log.warning(
                "capture socket SO_RCVBUF is only %d bytes (requested %d); raise "
                "net.core.rmem_max (see scripts/check-host.sh) to fix this",
                effective_rcvbuf,
                CAPTURE_RCVBUF_BYTES,
            )
            open_capture_socket.warned = True

        sock.settimeout(1.0)
    except Exception:
        sock.close()
        raise
    return sock


open_capture_socket.warned = False  # warn about a capped SO_RCVBUF only once


def recv_frame(sock):
    """Read one frame plus its kernel receive timestamp (CLOCK_REALTIME) and
    AF_PACKET pkttype (PACKET_HOST / PACKET_OUTGOING / ...).

    Uses recvmsg()+SCM_TIMESTAMPNS when the socket supports it (requires
    SO_TIMESTAMPNS to have been set, as open_capture_socket() does). Returns
    (frame, ts, pkttype); ts is a float unix timestamp or None if no
    timestamp cmsg was attached; pkttype is None when the socket lacks
    recvmsg (test fakes using plain recv) since there's no sockaddr_ll to
    read it from -- callers should fall back to their own wall clock / skip
    pkttype-based filtering in that case.
    """
    recvmsg = getattr(sock, "recvmsg", None)
    if recvmsg is None:
        return sock.recv(65535), None, None
    frame, ancdata, _flags, addr = recvmsg(65535, socket.CMSG_SPACE(16))
    ts = None
    for level, cmsg_type, data in ancdata:
        if level == socket.SOL_SOCKET and cmsg_type == SCM_TIMESTAMPNS and len(data) >= 16:
            sec, nsec = struct.unpack("qq", data[:16])
            ts = sec + nsec / 1e9
            break
    pkttype = addr[2] if addr is not None and len(addr) > 2 else None
    return frame, ts, pkttype


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
        # Guards all the mutable state below. handle_frame() runs on the
        # capture thread; flush() now runs on its own thread (see
        # flush_forever) so its O(n log n) ASN fold / HLL merge / Prometheus
        # updates never stall packet capture. Per-packet uncontended
        # acquire is ~0.3us, negligible next to the 6us/pkt parse cost.
        self._lock = threading.Lock()
        self._requests = {}  # (country, continent) -> count since last flush
        self._responses = {}  # (country, continent) -> count since last flush
        self._asn_requests = {}  # (asn, as_org) -> count since last flush
        self._asn_totals = {}  # asn -> cumulative requests, for top-N ranking
        self._version_requests = {}  # version -> count since last flush
        self._family_requests = {}  # family -> count since last flush
        self._active = {}  # ip -> last-seen monotonic time
        self._pending = {}  # (ip, xid) -> wall-clock request time, for latency pairing
        self._frames_since_sweep = 0  # triggers an incremental _pending TTL sweep every PENDING_SWEEP_EVERY
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

    def handle_frame(self, frame, ts=None, pkttype=None):
        parsed = parse_ntp_frame(frame)
        if parsed is None:
            ntp_capture_parse_errors_total.inc()
            return
        direction, ip, family, version, xid = parsed

        if pkttype is not None:
            # The capture socket is unbound, so it also sees chronyd's own
            # outgoing polls to upstream servers and their replies. A real
            # client request arrives (not PACKET_OUTGOING); our own reply to
            # a client is what we transmit (PACKET_OUTGOING). Anything else
            # matching dport/sport 123 is our own upstream traffic, not
            # client traffic, and must not be counted.
            if direction == "request" and pkttype == PACKET_OUTGOING:
                return
            if direction == "response" and pkttype != PACKET_OUTGOING:
                return

        if ts is None:
            ts = self._wall()

        with self._lock:
            self._frames_since_sweep += 1
            if self._frames_since_sweep >= PENDING_SWEEP_EVERY:
                self._frames_since_sweep = 0
                pending_cutoff = ts - PENDING_TTL_SECONDS
                for pending_key in [k for k, t in self._pending.items() if t < pending_cutoff]:
                    del self._pending[pending_key]

            ntp_capture_packets_total.labels(direction=direction).inc()

            country, continent, asn, as_org = self._geo.resolve(ip)
            key = (country, continent)
            if direction == "request":
                self._requests[key] = self._requests.get(key, 0) + 1
                akey = (asn, as_org)
                self._asn_requests[akey] = self._asn_requests.get(akey, 0) + 1
                v = version if version is not None else "other"
                self._version_requests[v] = self._version_requests.get(v, 0) + 1
                self._family_requests[family] = self._family_requests.get(family, 0) + 1

                now_clock = self._clock()
                prev = self._active.get(ip)
                if prev is not None:
                    ntp_client_request_interval_seconds.observe(now_clock - prev)
                self._active[ip] = now_clock
                self._current_bucket().add(ip)
                if xid is not None:
                    pending_key = (ip, xid)
                    if pending_key not in self._pending and len(self._pending) >= PENDING_MAX:
                        ntp_capture_pending_overflow_total.inc()
                    else:
                        self._pending[pending_key] = ts
            else:
                self._responses[key] = self._responses.get(key, 0) + 1
                if xid is not None:
                    req_ts = self._pending.pop((ip, xid), None)
                    if req_ts is not None:
                        delta = ts - req_ts
                        if delta >= 0:
                            ntp_response_latency_seconds.observe(delta)

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
        # Snapshot phase: O(1) dict swaps and shallow list() copies only, so
        # the capture thread is blocked for microseconds -- not for the
        # O(n log n) ASN fold / HLL merge / Prometheus updates below, which
        # is what used to stall packet capture for most of every interval.
        with self._lock:
            self._current_bucket()
            requests, self._requests = self._requests, {}
            responses, self._responses = self._responses, {}
            asn_requests, self._asn_requests = self._asn_requests, {}
            version_requests, self._version_requests = self._version_requests, {}
            family_requests, self._family_requests = self._family_requests, {}
            active_snapshot = list(self._active.items())
            pending_snapshot = list(self._pending.items())
            hourly_snapshot = list(self._hourly)  # sketch refs; see HLL merge below

        drops = self._read_kernel_drops()
        if drops:
            ntp_capture_kernel_drops_total.inc(drops)

        for (country, continent), n in requests.items():
            ntp_client_requests_total.labels(country=country, continent=continent).inc(n)
            drops = n - responses.get((country, continent), 0)
            if drops > 0:
                ntp_client_drops_total.labels(country=country, continent=continent).inc(drops)

        for (asn, _org), n in asn_requests.items():
            if asn is not None:
                self._asn_totals[asn] = self._asn_totals.get(asn, 0) + n
        if len(self._asn_totals) > ASN_TOTALS_MAX:
            # Ranking only needs the head of the distribution, so pruning
            # the tail down to the ASN_TOTALS_MAX largest totals can't
            # change the top-N set.
            self._asn_totals = dict(
                heapq.nlargest(ASN_TOTALS_MAX, self._asn_totals.items(), key=lambda kv: kv[1])
            )
        top_asns = top_n_asns(self._asn_totals, self._asn_top_n)
        for (asn, as_org), n in asn_requests.items():
            fasn, forg = fold_asn(asn, as_org, top_asns)
            ntp_client_requests_by_asn_total.labels(asn=str(fasn), as_org=forg).inc(n)

        for v, n in version_requests.items():
            ntp_client_requests_by_version_total.labels(version=v).inc(n)
        for f, n in family_requests.items():
            ntp_client_requests_by_family_total.labels(family=f).inc(n)

        cutoff = self._clock() - ACTIVE_WINDOW_SECONDS
        expired_active = [(ip, seen) for ip, seen in active_snapshot if seen < cutoff]
        with self._lock:
            for ip, seen in expired_active:
                # Only delete if handle_frame() hasn't refreshed this IP
                # since the snapshot was taken above.
                if self._active.get(ip) == seen:
                    del self._active[ip]
            ntp_clients_active.set(len(self._active))

        pending_cutoff = self._wall() - PENDING_TTL_SECONDS
        expired_pending = [(k, t) for k, t in pending_snapshot if t < pending_cutoff]
        with self._lock:
            for pending_key, t in expired_pending:
                if self._pending.get(pending_key) == t:
                    del self._pending[pending_key]

        # Merging the live current-hour sketch while the capture thread
        # concurrently .add()s to it is a benign read race: registers are
        # plain ints that only ever increase, so merge() sees either the old
        # or the new value, never a torn one.
        merged = HyperLogLog()
        for sketch in hourly_snapshot:
            merged.merge(sketch)
        ntp_clients_unique_daily.set(merged.count())

    def run_forever(self):
        sock = None
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
                    frame, ts, pkttype = recv_frame(sock)
                except TimeoutError:
                    frame, ts, pkttype = None, None, None
                except OSError:
                    log.exception("NTP capture socket read failed; reopening")
                    ntp_clients_scrape_success.set(0)
                    try:
                        sock.close()
                    except OSError:
                        pass
                    sock = None
                    self._sock = None
                    frame, ts, pkttype = None, None, None

                if frame:
                    self.handle_frame(frame, ts, pkttype)
            except Exception:
                log.exception("capture loop error")
                ntp_capture_loop_errors_total.inc()
                continue

    def flush_forever(self, interval):
        """Flush on its own thread/interval, decoupled from packet capture
        so a slow flush (large ASN table, HLL merge) can never stall
        recv_frame() and overflow the kernel socket buffer.
        """
        while True:
            time.sleep(interval)
            try:
                self.flush()
            except Exception:
                log.exception("flush loop error")
                ntp_capture_loop_errors_total.inc()


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

    threading.Thread(target=capture.run_forever, daemon=True).start()
    threading.Thread(
        target=capture.flush_forever, args=(CLIENTS_POLL_INTERVAL,), daemon=True
    ).start()

    ntppool.run_forever(NTPPOOL_POLL_INTERVAL)


if __name__ == "__main__":
    main()
