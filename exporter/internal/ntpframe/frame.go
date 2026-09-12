// Package ntpframe parses captured Ethernet frames into NTP request/response
// records. Faithful port of parse_ntp_frame / parse_frame / build_ntp_bpf
// from the original exporter.py.
package ntpframe

import (
	"net"

	"golang.org/x/net/bpf"
)

const (
	EthHdrLen     = 14
	EthertypeIPv4 = 0x0800
	EthertypeIPv6 = 0x86DD
	EthertypeVLAN = 0x8100
	IPProtoUDP    = 17
	NTPPort       = 123
	NTPPayloadMin = 48
)

// Parsed mirrors ParsedFrame from exporter.py, plus SrcIP/DstIP which the Go
// direction filter needs (Python used PACKET_OUTGOING instead).
type Parsed struct {
	Direction  string // "request" or "response"
	IP         net.IP // client IP: src for request, dst for response
	SrcIP      net.IP
	DstIP      net.IP
	Family     string // "ipv4" or "ipv6"
	Version    string // "" (unset), "1".."4", or "other"
	HasVersion bool
	XID        []byte // nil if payload shorter than NTPPayloadMin
}

func ntpVersion(payload []byte) string {
	v := (payload[0] >> 3) & 7
	if v >= 1 && v <= 4 {
		return string('0' + v)
	}
	return "other"
}

// ParseNTPFrame classifies one captured Ethernet frame as an NTP request or
// response and extracts its NTP-layer fields. Returns (Parsed{}, false) if
// the frame isn't a parseable NTP-over-UDP packet.
func ParseNTPFrame(frame []byte) (Parsed, bool) {
	n := len(frame)
	if n < EthHdrLen {
		return Parsed{}, false
	}
	ethertype := int(frame[12])<<8 | int(frame[13])
	off := EthHdrLen
	if ethertype == EthertypeVLAN {
		if n < off+4 {
			return Parsed{}, false
		}
		ethertype = int(frame[off+2])<<8 | int(frame[off+3])
		off += 4
	}

	var src, dst net.IP
	var family string

	switch ethertype {
	case EthertypeIPv4:
		if n < off+20 {
			return Parsed{}, false
		}
		ihl := int(frame[off]&0x0F) * 4
		if ihl < 20 || n < off+ihl {
			return Parsed{}, false
		}
		if frame[off+9] != IPProtoUDP {
			return Parsed{}, false
		}
		src = net.IP(append([]byte(nil), frame[off+12:off+16]...))
		dst = net.IP(append([]byte(nil), frame[off+16:off+20]...))
		off += ihl
		family = "ipv4"
	case EthertypeIPv6:
		if n < off+40 {
			return Parsed{}, false
		}
		if frame[off+6] != IPProtoUDP {
			return Parsed{}, false
		}
		src = net.IP(append([]byte(nil), frame[off+8:off+24]...))
		dst = net.IP(append([]byte(nil), frame[off+24:off+40]...))
		off += 40
		family = "ipv6"
	default:
		return Parsed{}, false
	}

	if n < off+8 {
		return Parsed{}, false
	}
	sport := int(frame[off])<<8 | int(frame[off+1])
	dport := int(frame[off+2])<<8 | int(frame[off+3])
	off += 8
	payload := frame[off:]

	var direction, ip string
	if dport == NTPPort {
		direction, ip = "request", src.String()
	} else if sport == NTPPort {
		direction, ip = "response", dst.String()
	} else {
		return Parsed{}, false
	}

	p := Parsed{
		Direction: direction,
		IP:        net.ParseIP(ip),
		SrcIP:     src,
		DstIP:     dst,
		Family:    family,
	}

	if len(payload) >= NTPPayloadMin {
		p.HasVersion = true
		p.Version = ntpVersion(payload)
		if direction == "request" {
			p.XID = append([]byte(nil), payload[40:48]...)
		} else {
			p.XID = append([]byte(nil), payload[24:32]...)
		}
	}

	return p, true
}

// ParseFrame is a thin wrapper for callers that only need direction/IP, like
// parse_frame() in exporter.py.
func ParseFrame(frame []byte) (direction, ip string, ok bool) {
	p, ok := ParseNTPFrame(frame)
	if !ok {
		return "", "", false
	}
	return p.Direction, p.IP.String(), true
}

// --- cBPF filter: "udp port 123" over IPv4 and IPv6, ported verbatim from
// build_ntp_bpf() in exporter.py. Jump targets are relative to the
// instruction after the jump; instruction 18 = accept, 19 = reject.

// BuildNTPBPF returns the classic-BPF program as raw instructions, ready for
// afpacket.TPacket.SetBPF.
func BuildNTPBPF() []bpf.RawInstruction {
	prog := []bpf.RawInstruction{
		{Op: 0x28, Jt: 0, Jf: 0, K: 12},             // 0: ldh [12] ethertype
		{Op: 0x15, Jt: 1, Jf: 0, K: EthertypeIPv4},  // 1 -> 3 (v4) else 2
		{Op: 0x15, Jt: 9, Jf: 16, K: EthertypeIPv6}, // 2 -> 12 (v6) else 19
		// IPv4
		{Op: 0x30, Jt: 0, Jf: 0, K: 23},          // 3: ldb [23] protocol
		{Op: 0x15, Jt: 0, Jf: 14, K: IPProtoUDP}, // 4 -> 5 else 19
		{Op: 0x28, Jt: 0, Jf: 0, K: 20},          // 5: ldh [20] flags+frag offset
		{Op: 0x45, Jt: 12, Jf: 0, K: 0x1FFF},     // 6: jset fragment -> 19 else 7
		{Op: 0xB1, Jt: 0, Jf: 0, K: EthHdrLen},   // 7: ldxb 4*([14]&0xf)
		{Op: 0x48, Jt: 0, Jf: 0, K: 14},          // 8: ldh [x+14] source port
		{Op: 0x15, Jt: 8, Jf: 0, K: NTPPort},     // 9 -> 18 else 10
		{Op: 0x48, Jt: 0, Jf: 0, K: 16},          // 10: ldh [x+16] dest port
		{Op: 0x15, Jt: 6, Jf: 7, K: NTPPort},     // 11 -> 18 else 19
		// IPv6
		{Op: 0x30, Jt: 0, Jf: 0, K: 20},         // 12: ldb [20] next header
		{Op: 0x15, Jt: 0, Jf: 5, K: IPProtoUDP}, // 13 -> 14 else 19
		{Op: 0x28, Jt: 0, Jf: 0, K: 54},         // 14: ldh [54] source port
		{Op: 0x15, Jt: 2, Jf: 0, K: NTPPort},    // 15 -> 18 else 16
		{Op: 0x28, Jt: 0, Jf: 0, K: 56},         // 16: ldh [56] dest port
		{Op: 0x15, Jt: 0, Jf: 1, K: NTPPort},    // 17 -> 18 else 19
		{Op: 0x06, Jt: 0, Jf: 0, K: 0xFFFF},     // 18: ret accept
		{Op: 0x06, Jt: 0, Jf: 0, K: 0},          // 19: ret reject
	}
	return prog
}
