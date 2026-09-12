package capture

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/metril/ntp-server/exporter/internal/aggregate"
	"github.com/metril/ntp-server/exporter/internal/ntpframe"
)

// --- frame builders (mirrors internal/ntpframe's test helpers) ---

func ethIPv4(src, dst string, sport, dport uint16, payload []byte) []byte {
	if payload == nil {
		payload = make([]byte, 48)
	}
	udpHdr := make([]byte, 8)
	binary.BigEndian.PutUint16(udpHdr[0:2], sport)
	binary.BigEndian.PutUint16(udpHdr[2:4], dport)
	binary.BigEndian.PutUint16(udpHdr[4:6], uint16(8+len(payload)))
	udp := append(udpHdr, payload...)

	ipHdr := make([]byte, 20)
	ipHdr[0] = (4 << 4) | 5
	binary.BigEndian.PutUint16(ipHdr[2:4], uint16(20+len(udp)))
	ipHdr[8] = 64
	ipHdr[9] = 17
	copy(ipHdr[12:16], net.ParseIP(src).To4())
	copy(ipHdr[16:20], net.ParseIP(dst).To4())
	ip := append(ipHdr, udp...)

	eth := append(append([]byte{}, make([]byte, 12)...), 0x08, 0x00)
	return append(eth, ip...)
}

type fakeGeo struct{}

func (fakeGeo) Resolve(ip string) aggregate.GeoResult {
	return aggregate.GeoResult{Country: "US", Continent: "NA"}
}

func newTestCollector() *aggregate.Collector {
	now := time.Unix(1000, 0)
	return aggregate.New(fakeGeo{}, 25, 1, func() time.Time { return now }, func() time.Time { return now })
}

// A real client's request to our server: dst is one of our local IPs.
func TestClientRequestIsAccepted(t *testing.T) {
	local := NewFixedLocalIPs("198.51.100.1")
	c := newTestCollector()
	before := c.PendingLen()
	frame := ethIPv4("203.0.113.5", "198.51.100.1", 41234, 123, nil)
	ProcessFrame(c, local, 0, frame, time.Now())
	if c.ActiveLen() == 0 {
		t.Fatal("expected the client request to register as active")
	}
	_ = before
}

// Our reply to that client: src is one of our local IPs.
func TestOurReplyToClientIsAccepted(t *testing.T) {
	local := NewFixedLocalIPs("198.51.100.1")
	c := newTestCollector()
	frame := ethIPv4("198.51.100.1", "203.0.113.5", 123, 41234, nil)
	// Responses aren't tracked in "active", so use the packet counter via a
	// request first, then confirm no panic/parse-error path -- direction
	// filter acceptance is what this test cares about, checked indirectly
	// through ShouldAccept below (kept for documentation/parity, but the
	// authoritative check is TestShouldAccept*).
	ProcessFrame(c, local, 0, frame, time.Now())
}

// chronyd's own outgoing poll to an upstream server: dst is NOT one of our
// IPs, so it must not be counted as a client request.
func TestOurUpstreamPollIsNotAClientRequest(t *testing.T) {
	local := NewFixedLocalIPs("198.51.100.1")
	c := newTestCollector()
	frame := ethIPv4("198.51.100.1", "203.0.113.9", 41234, 123, nil) // src=us, dst=upstream
	ProcessFrame(c, local, 0, frame, time.Now())
	if c.ActiveLen() != 0 {
		t.Fatal("expected upstream poll to be ignored (dst is not local)")
	}
}

// The upstream server's reply to our poll: src is NOT one of our IPs, so it
// must not be counted as a response from a client's perspective.
func TestUpstreamReplyIsNotAClientResponse(t *testing.T) {
	local := NewFixedLocalIPs("198.51.100.1")
	frame := ethIPv4("203.0.113.9", "198.51.100.1", 123, 41234, nil) // src=upstream, dst=us
	p, ok := ntpframe.ParseNTPFrame(frame)
	if !ok {
		t.Fatal("expected frame to parse")
	}
	if ShouldAccept(p, local) {
		t.Fatal("expected upstream reply (src not local) to be rejected")
	}
}

func TestShouldAcceptRequestRequiresLocalDst(t *testing.T) {
	local := NewFixedLocalIPs("198.51.100.1")
	req := ethIPv4("203.0.113.5", "198.51.100.1", 41234, 123, nil)
	p, _ := ntpframe.ParseNTPFrame(req)
	if !ShouldAccept(p, local) {
		t.Fatal("expected genuine client request to be accepted")
	}
}

func TestShouldAcceptResponseRequiresLocalSrc(t *testing.T) {
	local := NewFixedLocalIPs("198.51.100.1")
	resp := ethIPv4("198.51.100.1", "203.0.113.5", 123, 41234, nil)
	p, _ := ntpframe.ParseNTPFrame(resp)
	if !ShouldAccept(p, local) {
		t.Fatal("expected our own reply to be accepted")
	}
}
