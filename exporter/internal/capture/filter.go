// Package capture reads NTP frames off AF_PACKET TPACKET_V3 sockets (one
// per NTP_CAPTURE_WORKERS, fanned out by flow hash) and feeds them to an
// aggregate.Collector. This file holds the OS-independent parts (the
// request/response direction filter) so they're unit-testable without
// root or a real socket.
package capture

import (
	"net"
	"time"

	"github.com/metril/ntp-server/exporter/internal/aggregate"
	"github.com/metril/ntp-server/exporter/internal/metrics"
	"github.com/metril/ntp-server/exporter/internal/ntpframe"
)

// ShouldAccept applies the direction filter that replaces Python's
// PACKET_OUTGOING pkttype check (not exposed by gopacket's afpacket
// binding): the capture socket is unbound, so it also sees chronyd's own
// outgoing polls to upstream servers and their replies. A real client
// request's destination is one of our own IPs; our own reply to a client
// is sent from one of our own IPs. Anything else matching dport/sport 123
// is our own upstream traffic and must not be counted.
func ShouldAccept(p ntpframe.Parsed, local *LocalIPs) bool {
	if p.Direction == "request" {
		return local.Contains(p.DstIP)
	}
	return local.Contains(p.SrcIP)
}

// ProcessFrame is the OS-independent body of the capture loop: parse, apply
// the BPF-filter-error counter, apply the direction filter, and hand
// accepted frames to the collector. Pulled out of RunWorker so it's
// unit-testable without a real socket.
func ProcessFrame(collector *aggregate.Collector, local *LocalIPs, workerIdx int, data []byte, ts time.Time) {
	parsed, ok := ntpframe.ParseNTPFrame(data)
	if !ok {
		metrics.NtpCaptureParseErrorsTotal.Inc()
		return
	}
	if !ShouldAccept(parsed, local) {
		return
	}
	version := ""
	if parsed.HasVersion {
		version = parsed.Version
	}
	collector.HandleFrame(workerIdx, parsed.Direction, parsed.IP.String(), parsed.Family, version, parsed.XID, ts)
}

// NewFixedLocalIPs builds a LocalIPs-shaped set for tests, without touching
// net.InterfaceAddrs or ever reloading.
func NewFixedLocalIPs(ips ...string) *LocalIPs {
	set := map[string]struct{}{}
	for _, ip := range ips {
		if parsed := net.ParseIP(ip); parsed != nil {
			set[parsed.String()] = struct{}{}
		}
	}
	now := time.Now
	l := &LocalIPs{
		set:      set,
		interval: 24 * time.Hour,
		now:      now,
		lookup:   func() ([]net.Addr, error) { return nil, nil },
		lastLoad: now(),
	}
	return l
}
