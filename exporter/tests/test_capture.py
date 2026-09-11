import socket
import struct

from exporter import parse_frame


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
