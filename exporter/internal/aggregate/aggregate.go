// Package aggregate is the passive-capture hot path: turns parsed NTP
// frames into per-country/ASN/version/family counters, active/unique-client
// tracking, and request/response latency pairing, then flushes to
// Prometheus on a timer. Port of PacketCollector in exporter.py, split into
// per-worker counter shards (one per capture goroutine) and IP-sharded
// pending/active tables so that request/response pairing and active-client
// tracking work correctly even when a client's request and response land on
// different capture workers (AF_PACKET fanout hashes on flow, and a
// request/response pair is different flows in each direction).
package aggregate

import (
	"hash/fnv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metril/ntp-server/exporter/internal/hll"
	"github.com/metril/ntp-server/exporter/internal/metrics"
)

const (
	ActiveWindow      = 300 * time.Second
	PendingMax        = 50000
	PendingTTL        = 2 * time.Second
	PendingSweepEvery = 1024
	ASNTotalsMax      = 4096
	NumShards         = 16
)

// GeoResolver resolves an IP to country/continent/ASN/org. Implemented by
// internal/geoip.Resolver in production; fakeable in tests.
type GeoResolver interface {
	Resolve(ip string) GeoResult
}

// GeoResult mirrors geoip.Result without importing that package (avoids a
// dependency cycle risk and keeps this package's test doubles simple).
type GeoResult struct {
	Country   string
	Continent string
	ASN       int64
	HasASN    bool
	ASOrg     string
}

type countryKey struct {
	country, continent string
}

type asnKey struct {
	asn    int64
	hasASN bool
	asOrg  string
}

// workerCounters is per-capture-worker state that only that worker's
// goroutine touches when handling frames; flush() reads/resets it under its
// own lock.
type workerCounters struct {
	mu              sync.Mutex
	requests        map[countryKey]int64
	responses       map[countryKey]int64
	asnRequests     map[asnKey]int64
	versionRequests map[string]int64
	familyRequests  map[string]int64
}

func newWorkerCounters() *workerCounters {
	return &workerCounters{
		requests:        map[countryKey]int64{},
		responses:       map[countryKey]int64{},
		asnRequests:     map[asnKey]int64{},
		versionRequests: map[string]int64{},
		familyRequests:  map[string]int64{},
	}
}

type pendingEntry struct {
	reqTS time.Time
}

type shard struct {
	mu      sync.Mutex
	pending map[string]pendingEntry // key: ip+"|"+xid
	active  map[string]time.Time    // ip -> last-seen clock time
}

func shardIndex(ip string) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(ip))
	return int(h.Sum32() % NumShards)
}

func pendingKey(ip string, xid []byte) string {
	return ip + "|" + string(xid)
}

// Collector aggregates captured NTP frames from any number of capture
// workers (goroutines) and flushes to Prometheus on a timer.
type Collector struct {
	geo     GeoResolver
	asnTopN int
	clock   func() time.Time // monotonic-ish; used for active-window bookkeeping
	wall    func() time.Time // wall clock; used for latency pairing + HLL hour bucketing

	workers []*workerCounters
	shards  [NumShards]*shard

	framesSinceSweep int64 // accessed only via sync/atomic

	asnTotalsMu sync.Mutex
	asnTotals   map[int64]int64

	hourlyMu sync.Mutex
	hourly   [24]*hll.HyperLogLog
	hour     int
	hourSet  bool
}

// New creates a Collector with numWorkers per-worker counter shards.
func New(geo GeoResolver, asnTopN, numWorkers int, clock, wall func() time.Time) *Collector {
	if numWorkers < 1 {
		numWorkers = 1
	}
	c := &Collector{
		geo:       geo,
		asnTopN:   asnTopN,
		clock:     clock,
		wall:      wall,
		asnTotals: map[int64]int64{},
	}
	for i := 0; i < numWorkers; i++ {
		c.workers = append(c.workers, newWorkerCounters())
	}
	for i := range c.shards {
		c.shards[i] = &shard{
			pending: map[string]pendingEntry{},
			active:  map[string]time.Time{},
		}
	}
	for i := range c.hourly {
		c.hourly[i] = hll.NewDefault()
	}
	return c
}

func (c *Collector) currentBucketLocked(wallNow time.Time) *hll.HyperLogLog {
	hour := wallNow.UTC().Hour()
	if !c.hourSet {
		c.hour = hour
		c.hourSet = true
	} else if hour != c.hour {
		h := (c.hour + 1) % 24
		for {
			c.hourly[h] = hll.NewDefault()
			if h == hour {
				break
			}
			h = (h + 1) % 24
		}
		c.hour = hour
	}
	return c.hourly[hour]
}

// HandleFrame processes one parsed frame on capture worker workerIdx.
// direction is "request" or "response"; version is "" if unknown (folds to
// "other"); xid may be nil.
func (c *Collector) HandleFrame(workerIdx int, direction, ip, family, version string, xid []byte, ts time.Time) {
	wc := c.workers[workerIdx]

	n := atomic.AddInt64(&c.framesSinceSweep, 1)
	// Only the goroutine that wins the CAS (resetting the counter back to
	// 0) performs the sweep; others that also crossed the threshold before
	// the reset just continue without sweeping again.
	doSweep := n >= PendingSweepEvery && atomic.CompareAndSwapInt64(&c.framesSinceSweep, n, 0)

	if doSweep {
		cutoff := ts.Add(-PendingTTL)
		for _, sh := range c.shards {
			sh.mu.Lock()
			for k, e := range sh.pending {
				if e.reqTS.Before(cutoff) {
					delete(sh.pending, k)
				}
			}
			sh.mu.Unlock()
		}
	}

	metrics.NtpCapturePacketsTotal.WithLabelValues(direction).Inc()

	geo := c.geo.Resolve(ip)
	ckey := countryKey{geo.Country, geo.Continent}

	sh := c.shards[shardIndex(ip)]

	if direction == "request" {
		wc.mu.Lock()
		wc.requests[ckey]++
		akey := asnKey{geo.ASN, geo.HasASN, geo.ASOrg}
		wc.asnRequests[akey]++
		v := version
		if v == "" {
			v = "other"
		}
		wc.versionRequests[v]++
		wc.familyRequests[family]++
		wc.mu.Unlock()

		now := c.clock()
		sh.mu.Lock()
		if prev, ok := sh.active[ip]; ok {
			metrics.NtpClientRequestIntervalSeconds.Observe(now.Sub(prev).Seconds())
		}
		sh.active[ip] = now
		sh.mu.Unlock()

		c.hourlyMu.Lock()
		c.currentBucketLocked(c.wall()).Add(ip)
		c.hourlyMu.Unlock()

		if xid != nil {
			pk := pendingKey(ip, xid)
			sh.mu.Lock()
			if _, exists := sh.pending[pk]; !exists && len(sh.pending) >= PendingMax {
				metrics.NtpCapturePendingOverflowTotal.Inc()
			} else {
				sh.pending[pk] = pendingEntry{reqTS: ts}
			}
			sh.mu.Unlock()
		}
	} else {
		wc.mu.Lock()
		wc.responses[ckey]++
		wc.mu.Unlock()

		if xid != nil {
			pk := pendingKey(ip, xid)
			sh.mu.Lock()
			e, ok := sh.pending[pk]
			if ok {
				delete(sh.pending, pk)
			}
			sh.mu.Unlock()
			if ok {
				delta := ts.Sub(e.reqTS).Seconds()
				if delta >= 0 {
					metrics.NtpResponseLatencySeconds.Observe(delta)
				}
			}
		}
	}
}

// KernelDropsReader returns the current cumulative kernel drop count; the
// caller (capture package) is responsible for summing tp_drops across all
// fanout sockets. Flush() calls this once per flush and increments the
// counter by the delta since the last call.
type KernelDropsReader func() uint64

// Flush snapshots and clears per-worker/shard state, publishes counters to
// Prometheus, and recomputes the active/unique-daily gauges. readDrops, if
// non-nil, is called to get the current cumulative kernel-drop count;
// Flush tracks the delta itself.
func (c *Collector) Flush(readDrops KernelDropsReader, lastDrops *uint64) {
	// Snapshot phase.
	requests := map[countryKey]int64{}
	responses := map[countryKey]int64{}
	asnRequests := map[asnKey]int64{}
	versionRequests := map[string]int64{}
	familyRequests := map[string]int64{}

	for _, wc := range c.workers {
		wc.mu.Lock()
		for k, v := range wc.requests {
			requests[k] += v
		}
		for k, v := range wc.responses {
			responses[k] += v
		}
		for k, v := range wc.asnRequests {
			asnRequests[k] += v
		}
		for k, v := range wc.versionRequests {
			versionRequests[k] += v
		}
		for k, v := range wc.familyRequests {
			familyRequests[k] += v
		}
		wc.requests = map[countryKey]int64{}
		wc.responses = map[countryKey]int64{}
		wc.asnRequests = map[asnKey]int64{}
		wc.versionRequests = map[string]int64{}
		wc.familyRequests = map[string]int64{}
		wc.mu.Unlock()
	}

	if readDrops != nil {
		cur := readDrops()
		if lastDrops != nil {
			if cur >= *lastDrops {
				delta := cur - *lastDrops
				if delta > 0 {
					metrics.NtpCaptureKernelDropsTotal.Add(float64(delta))
				}
			}
			*lastDrops = cur
		}
	}

	for k, n := range requests {
		metrics.NtpClientRequestsTotal.WithLabelValues(k.country, k.continent).Add(float64(n))
		drops := n - responses[k]
		if drops > 0 {
			metrics.NtpClientDropsTotal.WithLabelValues(k.country, k.continent).Add(float64(drops))
		}
	}

	c.asnTotalsMu.Lock()
	for k, n := range asnRequests {
		if k.hasASN {
			c.asnTotals[k.asn] += n
		}
	}
	if len(c.asnTotals) > ASNTotalsMax {
		c.asnTotals = pruneToLargest(c.asnTotals, ASNTotalsMax)
	}
	topASNs := topNASNs(c.asnTotals, c.asnTopN)
	c.asnTotalsMu.Unlock()

	for k, n := range asnRequests {
		fasn, forg := foldASN(k.asn, k.hasASN, k.asOrg, topASNs)
		metrics.NtpClientRequestsByASNTotal.WithLabelValues(fasn, forg).Add(float64(n))
	}

	for v, n := range versionRequests {
		metrics.NtpClientRequestsByVersionTotal.WithLabelValues(v).Add(float64(n))
	}
	for f, n := range familyRequests {
		metrics.NtpClientRequestsByFamilyTotal.WithLabelValues(f).Add(float64(n))
	}

	// Active-client eviction.
	cutoff := c.clock().Add(-ActiveWindow)
	activeCount := 0
	for _, sh := range c.shards {
		sh.mu.Lock()
		for ip, seen := range sh.active {
			if seen.Before(cutoff) {
				delete(sh.active, ip)
			}
		}
		activeCount += len(sh.active)
		sh.mu.Unlock()
	}
	metrics.NtpClientsActive.Set(float64(activeCount))

	// Pending TTL sweep at flush time too (in addition to the incremental
	// sweep in HandleFrame), matching flush()'s own pending_cutoff pass in
	// exporter.py.
	pendingCutoff := c.wall().Add(-PendingTTL)
	for _, sh := range c.shards {
		sh.mu.Lock()
		for k, e := range sh.pending {
			if e.reqTS.Before(pendingCutoff) {
				delete(sh.pending, k)
			}
		}
		sh.mu.Unlock()
	}

	// Merge hourly sketches. Each sketch is deep-cloned while still holding
	// hourlyMu, so the clone (and the Merge below, which reads its
	// registers) never races with a concurrent Add() from HandleFrame,
	// which also mutates registers under hourlyMu.
	c.hourlyMu.Lock()
	c.currentBucketLocked(c.wall())
	snapshot := make([]*hll.HyperLogLog, len(c.hourly))
	for i, s := range c.hourly {
		snapshot[i] = s.Clone()
	}
	c.hourlyMu.Unlock()

	merged := hll.NewDefault()
	for _, s := range snapshot {
		merged.Merge(s)
	}
	metrics.NtpClientsUniqueDaily.Set(merged.Count())
}

// PendingLen returns the total size of all pending shards; for tests.
func (c *Collector) PendingLen() int {
	n := 0
	for _, sh := range c.shards {
		sh.mu.Lock()
		n += len(sh.pending)
		sh.mu.Unlock()
	}
	return n
}

// ActiveLen returns the total size of all active shards; for tests.
func (c *Collector) ActiveLen() int {
	n := 0
	for _, sh := range c.shards {
		sh.mu.Lock()
		n += len(sh.active)
		sh.mu.Unlock()
	}
	return n
}

// HourBucketCount returns hourly[hour].Count(); for tests.
func (c *Collector) HourBucketCount(hour int) float64 {
	c.hourlyMu.Lock()
	defer c.hourlyMu.Unlock()
	return c.hourly[hour].Count()
}

// AddToHourBucket adds a key directly to hourly[hour]; for tests simulating
// stale data.
func (c *Collector) AddToHourBucket(hour int, key string) {
	c.hourlyMu.Lock()
	defer c.hourlyMu.Unlock()
	c.hourly[hour].Add(key)
}

// CurrentHour returns the collector's tracked wall-clock hour; for tests.
func (c *Collector) CurrentHour() (int, bool) {
	c.hourlyMu.Lock()
	defer c.hourlyMu.Unlock()
	return c.hour, c.hourSet
}
