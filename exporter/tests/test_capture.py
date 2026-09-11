import socket
import struct

from exporter import build_ntp_bpf, parse_frame


def eth(payload, ethertype=0x0800, vlan=False):
    hdr = b"\xaa" * 6 + b"\xbb" * 6
    if vlan:
        return hdr + struct.pack("!HHH", 0x8100, 0x0064, ethertype) + payload
    return hdr + struct.pack("!H", ethertype) + payload


def udp(sport, dport, payload=b"\x00" * 48):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def ipv4(src, dst, payload, ihl=5):
    opts = b"\x00" * ((ihl - 5) * 4)
    total = ihl * 4 + len(payload)
    hdr = struct.pack("!BBHHHBBH", (4 << 4) | ihl, 0, total, 0, 0, 64, 17, 0)
    hdr += socket.inet_aton(src) + socket.inet_aton(dst) + opts
    return hdr + payload


def ipv6(src, dst, payload, nxt=17):
    hdr = struct.pack("!IHBB", 6 << 28, len(payload), nxt, 64)
    hdr += socket.inet_pton(socket.AF_INET6, src)
    hdr += socket.inet_pton(socket.AF_INET6, dst)
    return hdr + payload


def test_parse_frame_ipv4_request_keeps_source_ip():
    frame = eth(ipv4("203.0.113.5", "198.51.100.1", udp(41234, 123)))
    assert parse_frame(frame) == ("request", "203.0.113.5")


def test_parse_frame_ipv4_response_keeps_destination_ip():
    frame = eth(ipv4("198.51.100.1", "203.0.113.5", udp(123, 41234)))
    assert parse_frame(frame) == ("response", "203.0.113.5")


def test_parse_frame_ipv4_honours_ihl_with_options():
    frame = eth(ipv4("203.0.113.5", "198.51.100.1", udp(41234, 123), ihl=6))
    assert parse_frame(frame) == ("request", "203.0.113.5")


def test_parse_frame_ipv6_request_keeps_source_ip():
    frame = eth(ipv6("2001:db8::1", "2001:db8::2", udp(41234, 123)), ethertype=0x86DD)
    assert parse_frame(frame) == ("request", "2001:db8::1")


def test_parse_frame_ipv6_response_keeps_destination_ip():
    frame = eth(ipv6("2001:db8::2", "2001:db8::1", udp(123, 41234)), ethertype=0x86DD)
    assert parse_frame(frame) == ("response", "2001:db8::1")


def test_parse_frame_skips_vlan_tag():
    frame = eth(ipv4("203.0.113.9", "198.51.100.1", udp(41234, 123)), vlan=True)
    assert parse_frame(frame) == ("request", "203.0.113.9")


def test_parse_frame_ipv6_extension_header_is_not_parsed():
    frame = eth(ipv6("2001:db8::1", "2001:db8::2", udp(41234, 123), nxt=44), ethertype=0x86DD)
    assert parse_frame(frame) is None


def test_parse_frame_non_ntp_port_returns_none():
    frame = eth(ipv4("203.0.113.5", "198.51.100.1", udp(41234, 53)))
    assert parse_frame(frame) is None


def test_parse_frame_non_ip_ethertype_returns_none():
    assert parse_frame(eth(b"\x00" * 40, ethertype=0x0806)) is None


def test_parse_frame_truncated_frame_returns_none():
    frame = eth(ipv4("203.0.113.5", "198.51.100.1", udp(41234, 123)))
    assert parse_frame(frame[:20]) is None
    assert parse_frame(b"\x00" * 6) is None
    assert parse_frame(frame[:-50]) is None  # UDP header cut short


# --- cBPF program ---------------------------------------------------------


def test_build_ntp_bpf_is_a_whole_number_of_instructions():
    prog = build_ntp_bpf()
    assert len(prog) % 8 == 0
    assert len(prog) // 8 == 20


def test_build_ntp_bpf_first_instruction_is_ldh_ethertype():
    code, jt, jf, k = struct.unpack("HBBI", build_ntp_bpf()[:8])
    assert (code, jt, jf, k) == (0x28, 0, 0, 12)  # ldh [12]


def test_build_ntp_bpf_last_two_instructions_are_accept_then_reject():
    prog = build_ntp_bpf()
    accept = struct.unpack("HBBI", prog[-16:-8])
    reject = struct.unpack("HBBI", prog[-8:])
    assert accept == (0x06, 0, 0, 0xFFFF)  # ret #65535
    assert reject == (0x06, 0, 0, 0)  # ret #0


# --- parse_ntp_frame -------------------------------------------------------

from exporter import parse_ntp_frame


def ntp_payload(version=4, xmt=b"\x11" * 8, org=b"\x22" * 8):
    li_vn_mode = (0 << 6) | ((version & 7) << 3) | 3  # client mode
    body = bytes([li_vn_mode]) + b"\x00" * 39  # up to offset 40
    body = body[:1] + b"\x00" * 23 + org + b"\x00" * 8 + xmt
    assert len(body) == 48
    return body


def test_parse_ntp_frame_v4_request_reports_version_and_family():
    payload = ntp_payload(version=4)
    frame = eth(ipv4("203.0.113.5", "198.51.100.1", udp(41234, 123, payload)))
    parsed = parse_ntp_frame(frame)
    assert parsed.direction == "request"
    assert parsed.ip == "203.0.113.5"
    assert parsed.family == "ipv4"
    assert parsed.version == "4"
    assert parsed.xid == payload[40:48]


def test_parse_ntp_frame_v3_request_reports_version():
    payload = ntp_payload(version=3)
    frame = eth(ipv4("203.0.113.5", "198.51.100.1", udp(41234, 123, payload)))
    parsed = parse_ntp_frame(frame)
    assert parsed.version == "3"


def test_parse_ntp_frame_out_of_range_version_is_other():
    payload = ntp_payload(version=7)
    frame = eth(ipv4("203.0.113.5", "198.51.100.1", udp(41234, 123, payload)))
    parsed = parse_ntp_frame(frame)
    assert parsed.version == "other"


def test_parse_ntp_frame_ipv6_family():
    payload = ntp_payload(version=4)
    frame = eth(
        ipv6("2001:db8::1", "2001:db8::2", udp(41234, 123, payload)), ethertype=0x86DD
    )
    parsed = parse_ntp_frame(frame)
    assert parsed.family == "ipv6"


def test_parse_ntp_frame_request_and_response_xid_match_for_echoed_pair():
    xmt = b"\xab" * 8
    req_payload = ntp_payload(version=4, xmt=xmt)
    req_frame = eth(ipv4("203.0.113.5", "198.51.100.1", udp(41234, 123, req_payload)))
    req = parse_ntp_frame(req_frame)

    resp_payload = ntp_payload(version=4, org=xmt)
    resp_frame = eth(ipv4("198.51.100.1", "203.0.113.5", udp(123, 41234, resp_payload)))
    resp = parse_ntp_frame(resp_frame)

    assert req.xid == resp.xid == xmt


def test_parse_ntp_frame_short_payload_has_no_version_or_xid():
    frame = eth(ipv4("203.0.113.5", "198.51.100.1", udp(41234, 123, b"\x23" * 10)))
    parsed = parse_ntp_frame(frame)
    assert parsed.direction == "request"
    assert parsed.version is None
    assert parsed.xid is None


def test_parse_ntp_frame_malformed_frame_returns_none():
    assert parse_ntp_frame(b"\x00" * 6) is None
