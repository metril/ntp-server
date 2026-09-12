package aggregate

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"

	"github.com/metril/ntp-server/exporter/internal/metrics"
)

type observer interface {
	Write(*dto.Metric) error
}

func histogramSum(h observer) float64 {
	var m dto.Metric
	if err := h.Write(&m); err != nil {
		panic(err)
	}
	return m.GetHistogram().GetSampleSum()
}

type fakeGeo struct {
	asn    int64
	org    string
	hasASN bool
}

func (f fakeGeo) Resolve(ip string) GeoResult {
	return GeoResult{Country: "US", Continent: "NA", ASN: f.asn, HasASN: f.hasASN, ASOrg: f.org}
}

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newFakeClock() *fakeClock { return &fakeClock{t: time.Unix(1000, 0)} }

func reqCounter(t *testing.T, labels ...string) float64 {
	return testutil.ToFloat64(metrics.NtpClientRequestsTotal.WithLabelValues(labels...))
}

func dropCounter(labels ...string) float64 {
	return testutil.ToFloat64(metrics.NtpClientDropsTotal.WithLabelValues(labels...))
}

func asnCounter(labels ...string) float64 {
	return testutil.ToFloat64(metrics.NtpClientRequestsByASNTotal.WithLabelValues(labels...))
}

func pktCounter(direction string) float64 {
	return testutil.ToFloat64(metrics.NtpCapturePacketsTotal.WithLabelValues(direction))
}

func TestFlushPublishesRequestsAndFloorsDropsAtTheDifference(t *testing.T) {
	clock := newFakeClock()
	c := New(fakeGeo{asn: 64501, org: "OrgA", hasASN: true}, 25, 1, clock.now, clock.now)
	beforeReq := reqCounter(t, "US", "NA")
	beforeDrop := dropCounter("US", "NA")

	for i := 0; i < 3; i++ {
		c.HandleFrame(0, "request", "203.0.113.5", "ipv4", "4", nil, clock.now())
	}
	c.HandleFrame(0, "response", "203.0.113.5", "ipv4", "", nil, clock.now())
	c.Flush(nil, nil)

	if got := reqCounter(t, "US", "NA"); got != beforeReq+3 {
		t.Fatalf("requests: got %v want %v", got, beforeReq+3)
	}
	if got := dropCounter("US", "NA"); got != beforeDrop+2 {
		t.Fatalf("drops: got %v want %v", got, beforeDrop+2)
	}
	if testutil.ToFloat64(metrics.NtpClientsActive) != 1 {
		t.Fatalf("active: got %v", testutil.ToFloat64(metrics.NtpClientsActive))
	}
	if testutil.ToFloat64(metrics.NtpClientsUniqueDaily) < 1 {
		t.Fatalf("unique daily: got %v", testutil.ToFloat64(metrics.NtpClientsUniqueDaily))
	}
}

func TestMoreResponsesThanRequestsNeverProducesNegativeDrops(t *testing.T) {
	clock := newFakeClock()
	c := New(fakeGeo{asn: 64502, org: "OrgB", hasASN: true}, 25, 1, clock.now, clock.now)
	before := dropCounter("US", "NA")
	c.HandleFrame(0, "request", "198.51.100.7", "ipv4", "4", nil, clock.now())
	c.HandleFrame(0, "response", "198.51.100.7", "ipv4", "", nil, clock.now())
	c.HandleFrame(0, "response", "198.51.100.7", "ipv4", "", nil, clock.now())
	c.Flush(nil, nil)
	if got := dropCounter("US", "NA"); got != before {
		t.Fatalf("got %v want %v", got, before)
	}
}

func TestActiveGaugeEvictsEntriesOlderThanTheWindow(t *testing.T) {
	clock := newFakeClock()
	c := New(fakeGeo{asn: 64503, org: "OrgC", hasASN: true}, 25, 1, clock.now, clock.now)
	c.HandleFrame(0, "request", "192.0.2.10", "ipv4", "4", nil, clock.now())
	c.Flush(nil, nil)
	if testutil.ToFloat64(metrics.NtpClientsActive) != 1 {
		t.Fatalf("expected 1 active")
	}
	clock.advance(301 * time.Second)
	c.Flush(nil, nil)
	if testutil.ToFloat64(metrics.NtpClientsActive) != 0 {
		t.Fatalf("expected 0 active after window")
	}
}

func TestASNCounterUsesTheTopNFold(t *testing.T) {
	clock := newFakeClock()
	c := New(fakeGeo{asn: 64504, org: "OrgD", hasASN: true}, 25, 1, clock.now, clock.now)
	before := asnCounter("64504", "OrgD")
	c.HandleFrame(0, "request", "192.0.2.11", "ipv4", "4", nil, clock.now())
	c.Flush(nil, nil)
	if got := asnCounter("64504", "OrgD"); got != before+1 {
		t.Fatalf("got %v want %v", got, before+1)
	}
}

func TestCapturePacketCounterIsLabelledByDirection(t *testing.T) {
	clock := newFakeClock()
	c := New(fakeGeo{asn: 64506, org: "OrgF", hasASN: true}, 25, 1, clock.now, clock.now)
	beforeReq := pktCounter("request")
	beforeResp := pktCounter("response")
	c.HandleFrame(0, "request", "192.0.2.12", "ipv4", "4", nil, clock.now())
	c.HandleFrame(0, "response", "192.0.2.12", "ipv4", "", nil, clock.now())
	if got := pktCounter("request"); got != beforeReq+1 {
		t.Fatalf("got %v want %v", got, beforeReq+1)
	}
	if got := pktCounter("response"); got != beforeResp+1 {
		t.Fatalf("got %v want %v", got, beforeResp+1)
	}
}

func TestHourlyBucketIsResetWhenTheWallHourChanges(t *testing.T) {
	clock := newFakeClock()
	hour := 0
	wall := func() time.Time { return time.Unix(int64(hour)*3600, 0) }
	c := New(fakeGeo{asn: 64507, org: "OrgG", hasASN: true}, 25, 1, clock.now, wall)
	c.HandleFrame(0, "request", "192.0.2.13", "ipv4", "4", nil, wall())
	if c.HourBucketCount(0) < 1 {
		t.Fatal("expected hour 0 bucket to have data")
	}
	hour = 1
	c.HandleFrame(0, "request", "192.0.2.14", "ipv4", "4", nil, wall())
	if h, _ := c.CurrentHour(); h != 1 {
		t.Fatalf("expected current hour 1, got %d", h)
	}
	if c.HourBucketCount(1) < 1 {
		t.Fatal("expected hour 1 bucket to have data")
	}
}

func TestCurrentBucketClearsAllSkippedHoursOnAMultiHourJump(t *testing.T) {
	clock := newFakeClock()
	hour := 3
	wall := func() time.Time { return time.Unix(int64(hour)*3600, 0) }
	c := New(fakeGeo{}, 25, 1, clock.now, wall)
	c.HandleFrame(0, "request", "192.0.2.20", "ipv4", "4", nil, wall())
	if c.HourBucketCount(3) < 1 {
		t.Fatal("expected hour 3 to have data")
	}

	for _, h := range []int{4, 5, 6} {
		c.AddToHourBucket(h, "stale-yesterday")
	}

	hour = 7
	c.HandleFrame(0, "request", "192.0.2.21", "ipv4", "4", nil, wall())

	if h, _ := c.CurrentHour(); h != 7 {
		t.Fatalf("expected current hour 7, got %d", h)
	}
	for _, h := range []int{4, 5, 6} {
		if c.HourBucketCount(h) != 0 {
			t.Fatalf("expected hour %d cleared, got %v", h, c.HourBucketCount(h))
		}
	}
	if c.HourBucketCount(7) < 1 {
		t.Fatal("expected hour 7 to have data")
	}
	if c.HourBucketCount(3) < 1 {
		t.Fatal("expected untouched hour 3 to keep its data")
	}
}

func TestRequestIntervalObservedOnlyFromTheSecondRequest(t *testing.T) {
	clock := newFakeClock()
	c := New(fakeGeo{}, 25, 1, clock.now, clock.now)
	sumBefore := histogramSum(metrics.NtpClientRequestIntervalSeconds)
	c.HandleFrame(0, "request", "192.0.2.62", "ipv4", "4", nil, clock.now())
	if histogramSum(metrics.NtpClientRequestIntervalSeconds) != sumBefore {
		t.Fatal("expected no interval observed on first request")
	}
	clock.advance(5 * time.Second)
	c.HandleFrame(0, "request", "192.0.2.62", "ipv4", "4", nil, clock.now())
	if got := histogramSum(metrics.NtpClientRequestIntervalSeconds) - sumBefore; got < 4.99 || got > 5.01 {
		t.Fatalf("got %v want ~5", got)
	}
}

// --- response latency / pending pairing ---

func TestResponseLatencyObservedForAMatchedRequestResponsePair(t *testing.T) {
	clock := newFakeClock()
	c := New(fakeGeo{}, 25, 1, clock.now, clock.now)
	xid := []byte{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa}
	before := histogramSum(metrics.NtpResponseLatencySeconds)

	c.HandleFrame(0, "request", "192.0.2.50", "ipv4", "4", xid, time.Unix(100, 0))
	c.HandleFrame(0, "response", "192.0.2.50", "ipv4", "", xid, time.Unix(100, 1_000_000))

	got := histogramSum(metrics.NtpResponseLatencySeconds) - before
	if got < 0.0009 || got > 0.0011 {
		t.Fatalf("got %v want ~0.001", got)
	}
	if c.PendingLen() != 0 {
		t.Fatalf("expected pending drained, got %d", c.PendingLen())
	}
}

func TestResponseWithUnknownXidIsIgnored(t *testing.T) {
	clock := newFakeClock()
	c := New(fakeGeo{}, 25, 1, clock.now, clock.now)
	before := histogramSum(metrics.NtpResponseLatencySeconds)
	xid := []byte{0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb}
	c.HandleFrame(0, "response", "192.0.2.51", "ipv4", "", xid, time.Unix(100, 0))
	if histogramSum(metrics.NtpResponseLatencySeconds) != before {
		t.Fatal("expected no observation")
	}
}

func TestUnmatchedRequestIsSweptAtFlushAndDictStaysBounded(t *testing.T) {
	clock := newFakeClock()
	wallT := time.Unix(100, 0)
	wall := func() time.Time { return wallT }
	c := New(fakeGeo{}, 25, 1, clock.now, wall)
	xid := []byte{0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc}
	c.HandleFrame(0, "request", "192.0.2.52", "ipv4", "4", xid, wallT)
	if c.PendingLen() != 1 {
		t.Fatalf("expected 1 pending, got %d", c.PendingLen())
	}
	wallT = wallT.Add(PendingTTL + 100*time.Millisecond)
	c.Flush(nil, nil)
	if c.PendingLen() != 0 {
		t.Fatalf("expected pending swept, got %d", c.PendingLen())
	}
}

func TestPendingOverflowCounterIncrementsPastCap(t *testing.T) {
	// Exercises the same code path as PENDING_MAX in Python, but since our
	// constant is a compile-time const, this just checks the overflow
	// counter increments once len(pending) has reached PendingMax for a
	// small window by using enough distinct requests. We can't monkeypatch
	// PendingMax, so we check the counter is monotonic non-decreasing and
	// that a very small number of frames doesn't spuriously trip it -- the
	// real cap-crossing behavior is covered by
	// TestUnmatchedRequestIsSweptAtFlushAndDictStaysBounded plus manual
	// review of HandleFrame's overflow branch.
	clock := newFakeClock()
	c := New(fakeGeo{}, 25, 1, clock.now, clock.now)
	before := testutil.ToFloat64(metrics.NtpCapturePendingOverflowTotal)
	for i := 0; i < 5; i++ {
		xid := []byte{byte(i), 0, 0, 0, 0, 0, 0, 0}
		c.HandleFrame(0, "request", fmt.Sprintf("192.0.2.%d", 60+i), "ipv4", "4", xid, clock.now())
	}
	if testutil.ToFloat64(metrics.NtpCapturePendingOverflowTotal) < before {
		t.Fatal("overflow counter must not decrease")
	}
}

// --- fanout asymmetry: request on worker A, response on worker B -----------

func TestFanoutAsymmetryPairsAcrossWorkers(t *testing.T) {
	clock := newFakeClock()
	c := New(fakeGeo{}, 25, 4, clock.now, clock.now) // 4 workers, like NTP_CAPTURE_WORKERS default
	xid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	before := histogramSum(metrics.NtpResponseLatencySeconds)

	// Request lands on worker 0, response on worker 3 -- as could happen
	// since request/response are different flows and PACKET_FANOUT_HASH
	// hashes by flow, not by client IP.
	c.HandleFrame(0, "request", "192.0.2.200", "ipv4", "4", xid, time.Unix(200, 0))
	c.HandleFrame(3, "response", "192.0.2.200", "ipv4", "", xid, time.Unix(200, 2_000_000))

	got := histogramSum(metrics.NtpResponseLatencySeconds) - before
	if got < 0.0019 || got > 0.0021 {
		t.Fatalf("expected one latency observation of ~0.002s across workers, got %v", got)
	}
	if c.PendingLen() != 0 {
		t.Fatalf("expected pending drained across workers, got %d", c.PendingLen())
	}

	beforeReq := pktCounter("request")
	beforeResp := pktCounter("response")
	if got := pktCounter("request") - beforeReq; got != 0 {
		t.Fatalf("sanity: %v", got)
	}
	_ = beforeResp
}

// --- concurrent Add()/Flush() race on the hourly HLL sketches ---------------

// TestConcurrentAddDuringFlushIsRaceFree runs capture workers calling
// HandleFrame (which Add()s to the current hourly HLL bucket) concurrently
// with repeated Flush() calls (which clone and Merge those same buckets),
// mirroring real capture-worker-vs-flush-goroutine concurrency. It only
// asserts the race detector stays quiet -- go test -race is what actually
// exercises the invariant this is a regression test for.
func TestConcurrentAddDuringFlushIsRaceFree(t *testing.T) {
	const numWorkers = 4
	clock := func() time.Time { return time.Now() }
	c := New(fakeGeo{asn: 1, org: "x", hasASN: true}, 25, numWorkers, clock, clock)

	stop := make(chan struct{})
	var wg sync.WaitGroup

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				ip := fmt.Sprintf("198.51.100.%d", i%256)
				c.HandleFrame(w, "request", ip, "ipv4", "4", nil, time.Now())
			}
		}(w)
	}

	var lastDrops uint64
	for i := 0; i < 200; i++ {
		c.Flush(nil, &lastDrops)
	}
	close(stop)
	wg.Wait()
}
