package aggregate

import (
	"fmt"
	"testing"
	"time"
)

// BenchmarkHandleFrame1M feeds 1M synthetic request frames through
// HandleFrame across NTP_CAPTURE_WORKERS-many worker shards, reporting
// ns/frame -- a regression check for the flush-under-capture-thread stall
// this rewrite (and the Python fix it was based on) is meant to avoid.
func BenchmarkHandleFrame1M(b *testing.B) {
	clock := func() time.Time { return time.Now() }
	c := New(fakeGeo{asn: 64500, org: "BenchOrg", hasASN: true}, 25, 4, clock, clock)

	const n = 1_000_000
	ips := make([]string, 256)
	for i := range ips {
		ips[i] = fmt.Sprintf("203.0.%d.%d", i/256, i%256)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for iter := 0; iter < b.N; iter++ {
		for i := 0; i < n; i++ {
			ip := ips[i%len(ips)]
			c.HandleFrame(i%4, "request", ip, "ipv4", "4", nil, time.Now())
		}
	}
	b.StopTimer()
	nsPerFrame := float64(b.Elapsed().Nanoseconds()) / float64(b.N*n)
	b.ReportMetric(nsPerFrame, "ns/frame")
}
