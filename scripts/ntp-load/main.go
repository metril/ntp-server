// Command ntp-load is a simple NTP load generator. Run it from a LAN host
// against an ntp-server instance to exercise its capture and stats paths
// under a controlled request rate.
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"math"
	"net"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Config holds the parameters for a load-generation run.
type Config struct {
	Server   string        // host:port of the NTP server under test
	Rate     float64       // total requests per second across all workers
	Duration time.Duration // how long to send requests
	Workers  int           // number of UDP sockets / sender goroutines
	Timeout  time.Duration // how long to wait for stragglers after Duration
}

// Stats summarizes the outcome of a run.
type Stats struct {
	Sent         uint64
	Received     uint64
	LossPercent  float64
	AchievedRate float64 // sent per second, measured
	P50US        float64
	P95US        float64
	P99US        float64
	MaxUS        float64
}

// ntpPacket builds a 48-byte NTP mode-3 (client), version-4 packet whose
// Transmit Timestamp field (bytes 40-47) carries cookie as a big-endian
// uint64. A conforming NTP server echoes whatever the client sent in its
// Transmit Timestamp back into the reply's Origin Timestamp field (bytes
// 24-31), which lets us match replies to sends without needing real wall
// clock timestamps.
func ntpPacket(cookie uint64) []byte {
	buf := make([]byte, 48)
	buf[0] = 0x23 // LI=0, VN=4, Mode=3 (client)
	binary.BigEndian.PutUint64(buf[40:48], cookie)
	return buf
}

// resolveServer appends the default NTP port (123) if addr has none.
func resolveServer(addr string) (string, error) {
	_, _, err := net.SplitHostPort(addr)
	if err == nil {
		return addr, nil
	}
	// net.SplitHostPort fails on a bare host (or bare port) with no colon,
	// or on a bare IPv6 literal without brackets. Try appending :123.
	if _, _, err2 := net.SplitHostPort(addr + ":123"); err2 == nil {
		return addr + ":123", nil
	}
	return "", fmt.Errorf("invalid -server value %q: %w", addr, err)
}

// worker owns one UDP socket and paces its own share of the send rate.
type worker struct {
	conn *net.UDPConn

	mu      sync.Mutex
	pending map[uint64]time.Time
	rtts    []time.Duration

	sent atomic.Uint64
}

func newWorker(raddr *net.UDPAddr, rttsCap int) (*worker, error) {
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, err
	}
	return &worker{
		conn:    conn,
		pending: make(map[uint64]time.Time),
		rtts:    make([]time.Duration, 0, rttsCap),
	}, nil
}

// batchSleepFloor is the interval below which we stop trying to sleep for
// individual send deadlines (sub-millisecond sleeps are unreliable on most
// schedulers) and instead batch up however many sends are currently due.
const batchSleepFloor = 200 * time.Microsecond

// maxBatch caps how many sends we issue back-to-back in one catch-up burst,
// so a long stall can't turn into an unbounded write storm.
const maxBatch = 64

// sendLoop paces sends against a deadline computed from start and the
// worker's send index (start + n*interval) rather than a time.Ticker, whose
// ticks are dropped (not queued) when the receiver falls behind -- at high
// -rate that silently undershoots the requested rate. Falling behind here
// instead causes immediate catch-up sends, and very short intervals are
// batched so we don't try to sleep for durations the scheduler can't honor.
func (w *worker) sendLoop(stop <-chan struct{}, start time.Time, interval time.Duration, cookieBase uint64, counter *atomic.Uint64) {
	var n uint64
	for {
		select {
		case <-stop:
			return
		default:
		}

		next := start.Add(time.Duration(n) * interval)
		now := time.Now()
		if now.Before(next) {
			if interval >= batchSleepFloor {
				time.Sleep(next.Sub(now))
			}
			continue
		}

		batch := 1
		if interval < batchSleepFloor {
			behind := now.Sub(next)
			batch = int(behind/interval) + 1
			if batch > maxBatch {
				batch = maxBatch
			}
		}

		for i := 0; i < batch; i++ {
			select {
			case <-stop:
				return
			default:
			}
			cookie := cookieBase | counter.Add(1)
			pkt := ntpPacket(cookie)
			sendTime := time.Now()
			w.mu.Lock()
			w.pending[cookie] = sendTime
			w.mu.Unlock()
			if _, err := w.conn.Write(pkt); err != nil {
				// Send failed; drop the pending entry so it doesn't count
				// as an in-flight reply we're waiting on.
				w.mu.Lock()
				delete(w.pending, cookie)
				w.mu.Unlock()
			} else {
				w.sent.Add(1)
			}
			n++
		}
	}
}

func (w *worker) recvLoop(done <-chan struct{}, recvCount *atomic.Uint64) {
	buf := make([]byte, 128)
	for {
		select {
		case <-done:
			return
		default:
		}
		w.conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, err := w.conn.Read(buf)
		if err != nil {
			continue
		}
		if n < 48 {
			continue
		}
		cookie := binary.BigEndian.Uint64(buf[24:32])
		w.mu.Lock()
		sentAt, ok := w.pending[cookie]
		if ok {
			delete(w.pending, cookie)
		}
		w.mu.Unlock()
		if !ok {
			continue
		}
		rtt := time.Since(sentAt)
		recvCount.Add(1)
		w.mu.Lock()
		w.rtts = append(w.rtts, rtt)
		w.mu.Unlock()
	}
}

// run executes one full load-generation pass and returns the resulting
// stats. It performs no printing or process-exit side effects, so it can be
// exercised directly from tests.
func run(cfg Config) (Stats, error) {
	if cfg.Workers < 1 {
		cfg.Workers = 1
	}
	if cfg.Rate <= 0 {
		return Stats{}, fmt.Errorf("rate must be positive")
	}

	server, err := resolveServer(cfg.Server)
	if err != nil {
		return Stats{}, err
	}
	raddr, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		return Stats{}, fmt.Errorf("resolve %q: %w", server, err)
	}

	// Reserve the top bits of each cookie per worker so cookies never
	// collide across workers even though each worker's counter starts at 1.
	estimatedSends := uint64(cfg.Rate*cfg.Duration.Seconds()) + 1024
	perWorkerCap := int(estimatedSends/uint64(cfg.Workers)) + 1024

	workers := make([]*worker, cfg.Workers)
	for i := range workers {
		w, err := newWorker(raddr, perWorkerCap)
		if err != nil {
			for _, prev := range workers[:i] {
				if prev != nil {
					prev.conn.Close()
				}
			}
			return Stats{}, fmt.Errorf("worker %d: dial: %w", i, err)
		}
		workers[i] = w
	}
	defer func() {
		for _, w := range workers {
			w.conn.Close()
		}
	}()

	perWorkerRate := cfg.Rate / float64(cfg.Workers)
	if perWorkerRate <= 0 {
		perWorkerRate = 1
	}
	interval := time.Duration(float64(time.Second) / perWorkerRate)
	if interval <= 0 {
		interval = time.Nanosecond
	}

	var recvCount atomic.Uint64
	stop := make(chan struct{})
	done := make(chan struct{})

	start := time.Now()
	var wg sync.WaitGroup
	counters := make([]atomic.Uint64, cfg.Workers)
	for i, w := range workers {
		wg.Add(2)
		cookieBase := uint64(i) << 48
		go func(w *worker, counter *atomic.Uint64, cookieBase uint64) {
			defer wg.Done()
			w.sendLoop(stop, start, interval, cookieBase, counter)
		}(w, &counters[i], cookieBase)
		go func(w *worker) {
			defer wg.Done()
			w.recvLoop(done, &recvCount)
		}(w)
	}

	time.Sleep(cfg.Duration)
	close(stop) // stop sending

	// Give in-flight replies time to arrive.
	time.Sleep(cfg.Timeout)
	close(done) // stop receiving
	wg.Wait()

	elapsed := time.Since(start) - cfg.Timeout
	if elapsed <= 0 {
		elapsed = cfg.Duration
	}

	var sent uint64
	rttsLen := 0
	for _, w := range workers {
		sent += w.sent.Load()
		rttsLen += len(w.rtts)
	}
	received := recvCount.Load()

	rtts := make([]float64, 0, rttsLen)
	for _, w := range workers {
		for _, d := range w.rtts {
			rtts = append(rtts, float64(d.Microseconds()))
		}
	}
	sort.Float64s(rtts)

	stats := Stats{
		Sent:         sent,
		Received:     received,
		AchievedRate: float64(sent) / elapsed.Seconds(),
		P50US:        percentile(rtts, 0.50),
		P95US:        percentile(rtts, 0.95),
		P99US:        percentile(rtts, 0.99),
	}
	if len(rtts) > 0 {
		stats.MaxUS = rtts[len(rtts)-1]
	}
	if sent > 0 {
		lost := sent - received
		stats.LossPercent = 100 * float64(lost) / float64(sent)
	}
	return stats, nil
}

func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(math.Ceil(p*float64(len(sorted)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func main() {
	server := flag.String("server", "", "NTP server address, host:port (:123 appended if no port)")
	rate := flag.Float64("rate", 1000, "total requests per second across all workers")
	duration := flag.Duration("duration", 30*time.Second, "how long to send requests")
	workers := flag.Int("workers", 8, "number of UDP sockets / sender goroutines")
	timeout := flag.Duration("timeout", 2*time.Second, "how long to wait for replies after -duration elapses")
	flag.Parse()

	if *server == "" {
		fmt.Fprintln(os.Stderr, "error: -server is required, e.g. -server 192.0.2.10:123")
		flag.Usage()
		os.Exit(2)
	}

	cfg := Config{
		Server:   *server,
		Rate:     *rate,
		Duration: *duration,
		Workers:  *workers,
		Timeout:  *timeout,
	}

	stats, err := run(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}

	fmt.Printf("sent=%d received=%d loss=%.2f%% achieved_rate=%.1f req/s\n",
		stats.Sent, stats.Received, stats.LossPercent, stats.AchievedRate)
	fmt.Printf("rtt_us p50=%.0f p95=%.0f p99=%.0f max=%.0f\n",
		stats.P50US, stats.P95US, stats.P99US, stats.MaxUS)

	if stats.AchievedRate < 0.95*cfg.Rate {
		fmt.Fprintf(os.Stderr, "WARNING: achieved rate %.1f req/s is below 95%% of requested %.1f req/s\n",
			stats.AchievedRate, cfg.Rate)
	}

	if stats.LossPercent > 1.0 {
		fmt.Fprintf(os.Stderr, "FAIL: loss %.2f%% exceeds 1%% threshold\n", stats.LossPercent)
		os.Exit(1)
	}
}
