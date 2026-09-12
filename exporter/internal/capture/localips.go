package capture

import (
	"net"
	"sync"
	"time"
)

// LocalIPs caches this host's interface IPs, refreshed periodically, so the
// capture workers can classify a frame as a genuine client request/response
// instead of the exporter's own upstream chrony traffic. gopacket's afpacket
// binding doesn't expose AF_PACKET's PACKET_OUTGOING pkttype (which the
// Python version used for this), so direction is inferred instead: a
// "request" (dst port 123) only counts if its destination IP is one of
// ours, and a "response" (src port 123) only counts if its source IP is one
// of ours.
type LocalIPs struct {
	mu       sync.RWMutex
	set      map[string]struct{}
	lastLoad time.Time
	interval time.Duration
	now      func() time.Time
	lookup   func() ([]net.Addr, error)
}

// NewLocalIPs creates a LocalIPs cache refreshed every interval. It performs
// an initial synchronous load so the very first packet is classified
// correctly.
func NewLocalIPs(interval time.Duration) *LocalIPs {
	l := &LocalIPs{
		set:      map[string]struct{}{},
		interval: interval,
		now:      time.Now,
		lookup:   net.InterfaceAddrs,
	}
	l.reload()
	return l
}

func (l *LocalIPs) reload() {
	addrs, err := l.lookup()
	next := map[string]struct{}{}
	if err == nil {
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil {
				next[ip.String()] = struct{}{}
			}
		}
	}
	l.mu.Lock()
	if err == nil {
		l.set = next
	}
	l.lastLoad = l.now()
	l.mu.Unlock()
}

func (l *LocalIPs) maybeReload() {
	l.mu.RLock()
	stale := l.now().Sub(l.lastLoad) >= l.interval
	l.mu.RUnlock()
	if stale {
		l.reload()
	}
}

// Contains reports whether ip is one of this host's interface addresses,
// reloading the cache first if it's older than the refresh interval.
func (l *LocalIPs) Contains(ip net.IP) bool {
	l.maybeReload()
	l.mu.RLock()
	defer l.mu.RUnlock()
	_, ok := l.set[ip.String()]
	return ok
}
