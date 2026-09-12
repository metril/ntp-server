package ntpframe

import (
	"encoding/binary"
	"net"
	"testing"
)

func eth(payload []byte, ethertype uint16, vlan bool) []byte {
	hdr := append(append([]byte{}, bytes(0xaa, 6)...), bytes(0xbb, 6)...)
	if vlan {
		tag := make([]byte, 6)
		binary.BigEndian.PutUint16(tag[0:2], 0x8100)
		binary.BigEndian.PutUint16(tag[2:4], 0x0064)
		binary.BigEndian.PutUint16(tag[4:6], ethertype)
		return append(append(hdr, tag...), payload...)
	}
	et := make([]byte, 2)
	binary.BigEndian.PutUint16(et, ethertype)
	return append(append(hdr, et...), payload...)
}

func bytes(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func udp(sport, dport uint16, payload []byte) []byte {
	if payload == nil {
		payload = bytes(0, 48)
	}
	hdr := make([]byte, 8)
	binary.BigEndian.PutUint16(hdr[0:2], sport)
	binary.BigEndian.PutUint16(hdr[2:4], dport)
	binary.BigEndian.PutUint16(hdr[4:6], uint16(8+len(payload)))
	return append(hdr, payload...)
}

func ipv4(src, dst string, payload []byte, ihl int) []byte {
	if ihl == 0 {
		ihl = 5
	}
	opts := bytes(0, (ihl-5)*4)
	total := ihl*4 + len(payload)
	hdr := make([]byte, 20)
	hdr[0] = byte((4 << 4) | ihl)
	hdr[1] = 0
	binary.BigEndian.PutUint16(hdr[2:4], uint16(total))
	hdr[8] = 64
	hdr[9] = 17
	copy(hdr[12:16], net.ParseIP(src).To4())
	copy(hdr[16:20], net.ParseIP(dst).To4())
	out := append(hdr, opts...)
	return append(out, payload...)
}

func ipv6(src, dst string, payload []byte, nxt byte) []byte {
	if nxt == 0 {
		nxt = 17
	}
	hdr := make([]byte, 40)
	hdr[0] = 6 << 4
	binary.BigEndian.PutUint16(hdr[4:6], uint16(len(payload)))
	hdr[6] = nxt
	hdr[7] = 64
	copy(hdr[8:24], net.ParseIP(src).To16())
	copy(hdr[24:40], net.ParseIP(dst).To16())
	return append(hdr, payload...)
}

func TestParseFrameIPv4RequestKeepsSourceIP(t *testing.T) {
	frame := eth(ipv4("203.0.113.5", "198.51.100.1", udp(41234, 123, nil), 0), EthertypeIPv4, false)
	dir, ip, ok := ParseFrame(frame)
	if !ok || dir != "request" || ip != "203.0.113.5" {
		t.Fatalf("got %q %q %v", dir, ip, ok)
	}
}

func TestParseFrameIPv4ResponseKeepsDestinationIP(t *testing.T) {
	frame := eth(ipv4("198.51.100.1", "203.0.113.5", udp(123, 41234, nil), 0), EthertypeIPv4, false)
	dir, ip, ok := ParseFrame(frame)
	if !ok || dir != "response" || ip != "203.0.113.5" {
		t.Fatalf("got %q %q %v", dir, ip, ok)
	}
}

func TestParseFrameIPv4HonoursIHLWithOptions(t *testing.T) {
	frame := eth(ipv4("203.0.113.5", "198.51.100.1", udp(41234, 123, nil), 6), EthertypeIPv4, false)
	dir, ip, ok := ParseFrame(frame)
	if !ok || dir != "request" || ip != "203.0.113.5" {
		t.Fatalf("got %q %q %v", dir, ip, ok)
	}
}

func TestParseFrameIPv6RequestKeepsSourceIP(t *testing.T) {
	frame := eth(ipv6("2001:db8::1", "2001:db8::2", udp(41234, 123, nil), 0), EthertypeIPv6, false)
	dir, ip, ok := ParseFrame(frame)
	if !ok || dir != "request" || ip != "2001:db8::1" {
		t.Fatalf("got %q %q %v", dir, ip, ok)
	}
}

func TestParseFrameIPv6ResponseKeepsDestinationIP(t *testing.T) {
	frame := eth(ipv6("2001:db8::2", "2001:db8::1", udp(123, 41234, nil), 0), EthertypeIPv6, false)
	dir, ip, ok := ParseFrame(frame)
	if !ok || dir != "response" || ip != "2001:db8::1" {
		t.Fatalf("got %q %q %v", dir, ip, ok)
	}
}

func TestParseFrameSkipsVLANTag(t *testing.T) {
	frame := eth(ipv4("203.0.113.9", "198.51.100.1", udp(41234, 123, nil), 0), EthertypeIPv4, true)
	dir, ip, ok := ParseFrame(frame)
	if !ok || dir != "request" || ip != "203.0.113.9" {
		t.Fatalf("got %q %q %v", dir, ip, ok)
	}
}

func TestParseFrameIPv6ExtensionHeaderIsNotParsed(t *testing.T) {
	frame := eth(ipv6("2001:db8::1", "2001:db8::2", udp(41234, 123, nil), 44), EthertypeIPv6, false)
	if _, _, ok := ParseFrame(frame); ok {
		t.Fatal("expected not ok")
	}
}

func TestParseFrameNonNTPPortReturnsNone(t *testing.T) {
	frame := eth(ipv4("203.0.113.5", "198.51.100.1", udp(41234, 53, nil), 0), EthertypeIPv4, false)
	if _, _, ok := ParseFrame(frame); ok {
		t.Fatal("expected not ok")
	}
}

func TestParseFrameNonIPEthertypeReturnsNone(t *testing.T) {
	if _, _, ok := ParseFrame(eth(bytes(0, 40), 0x0806, false)); ok {
		t.Fatal("expected not ok")
	}
}

func TestParseFrameTruncatedFrameReturnsNone(t *testing.T) {
	frame := eth(ipv4("203.0.113.5", "198.51.100.1", udp(41234, 123, nil), 0), EthertypeIPv4, false)
	if _, _, ok := ParseFrame(frame[:20]); ok {
		t.Fatal("expected not ok (too short)")
	}
	if _, _, ok := ParseFrame(bytes(0, 6)); ok {
		t.Fatal("expected not ok (too short)")
	}
	if _, _, ok := ParseFrame(frame[:len(frame)-50]); ok {
		t.Fatal("expected not ok (udp header cut short)")
	}
}

// --- cBPF program ---

func TestBuildNTPBPFIsAWholeNumberOfInstructions(t *testing.T) {
	prog := BuildNTPBPF()
	if len(prog) != 20 {
		t.Fatalf("expected 20 instructions, got %d", len(prog))
	}
}

func TestBuildNTPBPFFirstInstructionIsLdhEthertype(t *testing.T) {
	prog := BuildNTPBPF()
	if prog[0].Op != 0x28 || prog[0].Jt != 0 || prog[0].Jf != 0 || prog[0].K != 12 {
		t.Fatalf("got %+v", prog[0])
	}
}

func TestBuildNTPBPFLastTwoInstructionsAreAcceptThenReject(t *testing.T) {
	prog := BuildNTPBPF()
	accept := prog[len(prog)-2]
	reject := prog[len(prog)-1]
	if accept.Op != 0x06 || accept.K != 0xFFFF {
		t.Fatalf("accept: %+v", accept)
	}
	if reject.Op != 0x06 || reject.K != 0 {
		t.Fatalf("reject: %+v", reject)
	}
}

// --- ParseNTPFrame ---

func ntpPayload(version byte, xmt, org []byte) []byte {
	if xmt == nil {
		xmt = bytes(0x11, 8)
	}
	if org == nil {
		org = bytes(0x22, 8)
	}
	liVnMode := byte((version&7)<<3) | 3
	body := make([]byte, 48)
	body[0] = liVnMode
	copy(body[24:32], org)
	copy(body[40:48], xmt)
	return body
}

func TestParseNTPFrameV4RequestReportsVersionAndFamily(t *testing.T) {
	payload := ntpPayload(4, nil, nil)
	frame := eth(ipv4("203.0.113.5", "198.51.100.1", udp(41234, 123, payload), 0), EthertypeIPv4, false)
	p, ok := ParseNTPFrame(frame)
	if !ok {
		t.Fatal("expected ok")
	}
	if p.Direction != "request" || p.IP.String() != "203.0.113.5" || p.Family != "ipv4" || p.Version != "4" {
		t.Fatalf("got %+v", p)
	}
	if string(p.XID) != string(payload[40:48]) {
		t.Fatalf("xid mismatch")
	}
}

func TestParseNTPFrameV3RequestReportsVersion(t *testing.T) {
	payload := ntpPayload(3, nil, nil)
	frame := eth(ipv4("203.0.113.5", "198.51.100.1", udp(41234, 123, payload), 0), EthertypeIPv4, false)
	p, _ := ParseNTPFrame(frame)
	if p.Version != "3" {
		t.Fatalf("got %q", p.Version)
	}
}

func TestParseNTPFrameOutOfRangeVersionIsOther(t *testing.T) {
	payload := ntpPayload(7, nil, nil)
	frame := eth(ipv4("203.0.113.5", "198.51.100.1", udp(41234, 123, payload), 0), EthertypeIPv4, false)
	p, _ := ParseNTPFrame(frame)
	if p.Version != "other" {
		t.Fatalf("got %q", p.Version)
	}
}

func TestParseNTPFrameIPv6Family(t *testing.T) {
	payload := ntpPayload(4, nil, nil)
	frame := eth(ipv6("2001:db8::1", "2001:db8::2", udp(41234, 123, payload), 0), EthertypeIPv6, false)
	p, _ := ParseNTPFrame(frame)
	if p.Family != "ipv6" {
		t.Fatalf("got %q", p.Family)
	}
}

func TestParseNTPFrameRequestAndResponseXidMatchForEchoedPair(t *testing.T) {
	xmt := bytes(0xab, 8)
	reqPayload := ntpPayload(4, xmt, nil)
	reqFrame := eth(ipv4("203.0.113.5", "198.51.100.1", udp(41234, 123, reqPayload), 0), EthertypeIPv4, false)
	req, _ := ParseNTPFrame(reqFrame)

	respPayload := ntpPayload(4, nil, xmt)
	respFrame := eth(ipv4("198.51.100.1", "203.0.113.5", udp(123, 41234, respPayload), 0), EthertypeIPv4, false)
	resp, _ := ParseNTPFrame(respFrame)

	if string(req.XID) != string(xmt) || string(resp.XID) != string(xmt) {
		t.Fatalf("xid mismatch: req=%x resp=%x want=%x", req.XID, resp.XID, xmt)
	}
}

func TestParseNTPFrameShortPayloadHasNoVersionOrXid(t *testing.T) {
	frame := eth(ipv4("203.0.113.5", "198.51.100.1", udp(41234, 123, bytes(0x23, 10)), 0), EthertypeIPv4, false)
	p, ok := ParseNTPFrame(frame)
	if !ok {
		t.Fatal("expected ok")
	}
	if p.Direction != "request" || p.HasVersion || p.XID != nil {
		t.Fatalf("got %+v", p)
	}
}

func TestParseNTPFrameMalformedFrameReturnsNone(t *testing.T) {
	if _, ok := ParseNTPFrame(bytes(0, 6)); ok {
		t.Fatal("expected not ok")
	}
}
