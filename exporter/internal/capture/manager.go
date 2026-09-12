//go:build linux

package capture

import (
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gopacket/gopacket/afpacket"
	"golang.org/x/net/bpf"

	"github.com/metril/ntp-server/exporter/internal/aggregate"
	"github.com/metril/ntp-server/exporter/internal/metrics"
	"github.com/metril/ntp-server/exporter/internal/ntpframe"
)

const (
	blockSize    = 1 << 20 // 1 MiB blocks
	blockTimeout = 1 * time.Millisecond
	fanoutID     = 0x4E54 // "NT" -- arbitrary, just needs to be shared by all workers in this process

	loopErrBackoffMin  = 10 * time.Millisecond
	loopErrBackoffMax  = 1 * time.Second
	loopErrLogInterval = 1 * time.Second // log at most once per error burst
	loopErrReopenAfter = 32              // consecutive non-timeout errors before reopening the socket
)

// ClampWorkers returns n clamped to a minimum of 1, logging when it had to
// clamp. It is the single source of truth for the effective worker count:
// Open() calls it on m.NumWorkers, and callers that also need the count
// before Open() runs (e.g. to size aggregate.New's per-worker shards)
// should call it themselves on the same input so both stay in sync.
func ClampWorkers(n int) int {
	if n <= 0 {
		log.Printf("NTP_CAPTURE_WORKERS=%d invalid; clamping to 1", n)
		return 1
	}
	return n
}

// Manager owns one AF_PACKET TPACKET_V3 socket per capture worker, all
// joined into one PACKET_FANOUT_HASH group so the kernel load-balances
// flows across them while frames from the same flow (and so the same
// client IP for our purposes) stay on one worker -- except that a
// request/response pair is two different flows (different port tuples),
// which is why aggregate.Collector shards its pending/active tables by
// client IP rather than by worker.
type Manager struct {
	Collector  *aggregate.Collector
	NumWorkers int
	RingBytes  int
	LocalIPs   *LocalIPs

	numBlocks int
	prog      []bpf.RawInstruction

	// socketsMu guards sockets: RunWorker's reopen path replaces its own
	// slot under it, while KernelDrops (called from the flush goroutine)
	// and Close read the slice concurrently.
	socketsMu sync.Mutex
	sockets   []*afpacket.TPacket
}

// Open opens NumWorkers AF_PACKET sockets, attaches the NTP BPF filter to
// each, and joins them into one fanout group. Splits RingBytes evenly
// across workers. NumWorkers <= 0 is clamped to 1 (and logged) here, which
// is the single place that happens -- callers that need the same clamped
// count before Open() runs (e.g. to size aggregate.New's shards) should
// call ClampWorkers on the same input.
func (m *Manager) Open() error {
	m.NumWorkers = ClampWorkers(m.NumWorkers)

	perWorker := m.RingBytes / m.NumWorkers
	numBlocks := perWorker / blockSize
	if numBlocks < 1 {
		numBlocks = 1
	}
	m.numBlocks = numBlocks
	m.prog = ntpframe.BuildNTPBPF()

	sockets := make([]*afpacket.TPacket, 0, m.NumWorkers)
	for i := 0; i < m.NumWorkers; i++ {
		tp, err := m.newSocket()
		if err != nil {
			for _, s := range sockets {
				s.Close()
			}
			return err
		}
		sockets = append(sockets, tp)
	}

	m.sockets = sockets
	metrics.NtpCaptureRcvbufBytes.Set(float64(numBlocks * blockSize * m.NumWorkers))
	return nil
}

// newSocket opens one AF_PACKET TPACKET_V3 socket with the NTP BPF filter
// and joins it to the shared fanout group, using the block sizing and BPF
// program captured by Open(). Used both for the initial Open() and for
// reopening a single worker's socket after repeated read errors.
func (m *Manager) newSocket() (*afpacket.TPacket, error) {
	tp, err := afpacket.NewTPacket(
		afpacket.OptTPacketVersion(afpacket.TPacketVersion3),
		afpacket.OptBlockSize(blockSize),
		afpacket.OptNumBlocks(m.numBlocks),
		afpacket.OptBlockTimeout(blockTimeout),
		afpacket.OptPollTimeout(1*time.Second),
	)
	if err != nil {
		return nil, err
	}
	if err := tp.SetBPF(m.prog); err != nil {
		tp.Close()
		return nil, err
	}
	if err := tp.SetFanout(afpacket.FanoutHash, fanoutID); err != nil {
		tp.Close()
		return nil, err
	}
	return tp, nil
}

// Close closes all worker sockets.
func (m *Manager) Close() {
	m.socketsMu.Lock()
	defer m.socketsMu.Unlock()
	for _, s := range m.sockets {
		s.Close()
	}
}

// KernelDrops sums tp_drops (TPACKET_V3 socket stats) across all workers.
func (m *Manager) KernelDrops() uint64 {
	m.socketsMu.Lock()
	defer m.socketsMu.Unlock()
	var total uint64
	for _, s := range m.sockets {
		_, statsV3, err := s.SocketStats()
		if err != nil {
			continue
		}
		total += uint64(statsV3.Drops())
	}
	return total
}

// RunWorker reads frames from worker i forever, applying the BPF-filtered
// direction classification and feeding accepted frames to the collector.
// Intended to run on its own goroutine; it does not return on ordinary
// socket errors -- it logs (rate-limited), counts, backs off, and after
// loopErrReopenAfter consecutive non-timeout errors closes and reopens its
// own socket (re-applying the BPF filter and fanout join). It returns only
// when stop is closed.
func (m *Manager) RunWorker(i int, stop <-chan struct{}) {
	m.socketsMu.Lock()
	sock := m.sockets[i]
	m.socketsMu.Unlock()

	backoff := loopErrBackoffMin
	consecutiveErrs := 0
	var lastLog time.Time

	for {
		select {
		case <-stop:
			return
		default:
		}

		data, ci, err := sock.ZeroCopyReadPacketData()
		if err != nil {
			if err == afpacket.ErrTimeout {
				continue
			}

			consecutiveErrs++
			metrics.NtpCaptureLoopErrorsTotal.Inc()
			if lastLog.IsZero() || time.Since(lastLog) >= loopErrLogInterval {
				log.Printf("capture worker %d: read failed (%d consecutive): %v", i, consecutiveErrs, err)
				lastLog = time.Now()
			}

			if consecutiveErrs >= loopErrReopenAfter {
				if newSock, rerr := m.reopenWorker(i); rerr != nil {
					log.Printf("capture worker %d: socket reopen failed, will keep retrying: %v", i, rerr)
				} else {
					sock = newSock
					log.Printf("capture worker %d: socket reopened after %d consecutive errors", i, consecutiveErrs)
				}
				consecutiveErrs = 0
				backoff = loopErrBackoffMin
				continue
			}

			select {
			case <-stop:
				return
			case <-time.After(backoff):
			}
			backoff *= 2
			if backoff > loopErrBackoffMax {
				backoff = loopErrBackoffMax
			}
			continue
		}

		consecutiveErrs = 0
		backoff = loopErrBackoffMin

		ts := ci.Timestamp
		if ts.IsZero() {
			ts = time.Now()
		}
		ProcessFrame(m.Collector, m.LocalIPs, i, data, ts)
	}
}

// reopenWorker closes worker i's current socket and opens a fresh one with
// the same BPF filter and fanout group, atomically replacing it in
// m.sockets so KernelDrops/Close observe a consistent slice.
func (m *Manager) reopenWorker(i int) (*afpacket.TPacket, error) {
	newSock, err := m.newSocket()
	if err != nil {
		return nil, err
	}
	m.socketsMu.Lock()
	old := m.sockets[i]
	m.sockets[i] = newSock
	m.socketsMu.Unlock()
	old.Close()
	return newSock, nil
}

// Run starts one goroutine per worker and blocks until stop is closed.
func (m *Manager) Run(stop <-chan struct{}) {
	done := make(chan struct{})
	var running int32
	atomic.StoreInt32(&running, int32(len(m.sockets)))
	for i := range m.sockets {
		go func(i int) {
			m.RunWorker(i, stop)
			if atomic.AddInt32(&running, -1) == 0 {
				close(done)
			}
		}(i)
	}
	<-stop
	<-done
}
