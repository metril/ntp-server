// Command exporter is ntp-server-exporter: passive NTP capture + pool.ntp.org
// score sidecar. Go port of exporter.py; see internal/aggregate for the
// capture/flush hot path and internal/ntppool for the pool.ntp.org poller.
package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/metril/ntp-server/exporter/internal/aggregate"
	"github.com/metril/ntp-server/exporter/internal/capture"
	"github.com/metril/ntp-server/exporter/internal/geoip"
	"github.com/metril/ntp-server/exporter/internal/metrics"
	"github.com/metril/ntp-server/exporter/internal/ntppool"
)

func getenv(key, def string) string {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	return v
}

func getenvInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		log.Printf("invalid %s=%q, using default %d", key, v, def)
		return def
	}
	return n
}

// geoResolverAdapter adapts geoip.Resolver to aggregate.GeoResolver.
type geoResolverAdapter struct {
	r *geoip.Resolver
}

func (a geoResolverAdapter) Resolve(ip string) aggregate.GeoResult {
	res := a.r.Resolve(ip)
	return aggregate.GeoResult{
		Country:   res.Country,
		Continent: res.Continent,
		ASN:       res.ASN,
		HasASN:    res.HasASN,
		ASOrg:     res.ASOrg,
	}
}

func main() {
	log.SetFlags(log.LstdFlags)

	ntppoolIPv4 := getenv("NTPPOOL_IPV4", "")
	asnTopN := getenvInt("NTP_ASN_TOP_N", 25)
	geoipDir := getenv("GEOIP_DIR", "/geoip")
	listenAddr := getenv("LISTEN_ADDR", "127.0.0.1")
	listenPort := getenvInt("LISTEN_PORT", 9124)
	clientsPollInterval := getenvInt("CLIENTS_POLL_INTERVAL", 15)
	ntppoolPollInterval := getenvInt("NTPPOOL_POLL_INTERVAL", 300)
	captureWorkers := capture.ClampWorkers(getenvInt("NTP_CAPTURE_WORKERS", 4))
	captureRingBytes := getenvInt("NTP_CAPTURE_RING_BYTES", 64<<20)
	captureDisabled := getenv("NTP_CAPTURE_DISABLED", "") == "1"

	addr := fmt.Sprintf("%s:%d", listenAddr, listenPort)
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(metrics.Registry, promhttp.HandlerOpts{}))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("failed to listen on %s: %v", addr, err)
	}
	go func() {
		if err := http.Serve(ln, mux); err != nil {
			log.Fatalf("http server failed: %v", err)
		}
	}()
	log.Printf("listening on %s", addr)

	geo := geoip.New(geoipDir, 8192, func(db string, loaded bool) {
		v := 0.0
		if loaded {
			v = 1.0
		}
		metrics.NtpGeoipDatabaseLoaded.WithLabelValues(db).Set(v)
	})

	collector := aggregate.New(geoResolverAdapter{geo}, asnTopN, captureWorkers, time.Now, time.Now)

	poller := ntppool.NewPoller(ntppoolIPv4, ntppool.Setters{
		Score: func(ip string, v float64) {
			metrics.NtppoolScore.WithLabelValues(ip).Set(v)
		},
		MonitorScore: func(ip, monitor string, v float64) {
			metrics.NtppoolMonitorScore.WithLabelValues(ip, monitor).Set(v)
		},
		MonitorOffset: func(ip, monitor string, v float64) {
			metrics.NtppoolMonitorOffsetSeconds.WithLabelValues(ip, monitor).Set(v)
		},
		MonitorRTT: func(ip, monitor string, v float64) {
			metrics.NtppoolMonitorRttSeconds.WithLabelValues(ip, monitor).Set(v)
		},
		ScrapeSuccess: func(v float64) {
			metrics.NtppoolScrapeSuccess.Set(v)
		},
	})

	if ntppoolIPv4 == "" {
		log.Println("NTPPOOL_IPV4 not set; ntppool collector disabled")
	}

	var currentMgr atomic.Pointer[capture.Manager]

	// stop is closed exactly once, on SIGINT/SIGTERM, and propagates down to
	// every capture worker goroutine so they all exit before main returns.
	stop := make(chan struct{})
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("received %v; shutting down", sig)
		close(stop)
	}()

	if captureDisabled {
		log.Println("NTP_CAPTURE_DISABLED=1; capture disabled (test/parity mode)")
		metrics.NtpClientsScrapeSuccess.Set(0)
	} else {
		go runCapture(collector, captureWorkers, captureRingBytes, &currentMgr, stop)
	}

	var lastDrops uint64
	go flushForever(collector, time.Duration(clientsPollInterval)*time.Second, &currentMgr, &lastDrops, stop)

	poller.RunForever(time.Duration(ntppoolPollInterval) * time.Second)
}

func flushForever(collector *aggregate.Collector, interval time.Duration, mgrPtr *atomic.Pointer[capture.Manager], lastDrops *uint64, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
		}
		var readDrops aggregate.KernelDropsReader
		if mgr := mgrPtr.Load(); mgr != nil {
			readDrops = func() uint64 { return mgr.KernelDrops() }
		}
		collector.Flush(readDrops, lastDrops)
	}
}

// runCapture opens capture sockets and runs the worker goroutines,
// reconnecting on open failure and after a capture manager exits, until
// stop is closed. ntp_clients_scrape_success reflects capture health:
// 1 while workers are running, 0 whenever they are not (open failed,
// mid-reconnect, or shutting down).
func runCapture(collector *aggregate.Collector, numWorkers, ringBytes int, mgrPtr *atomic.Pointer[capture.Manager], stop <-chan struct{}) {
	local := capture.NewLocalIPs(30 * time.Second)
	for {
		select {
		case <-stop:
			return
		default:
		}

		mgr := &capture.Manager{
			Collector:  collector,
			NumWorkers: numWorkers,
			RingBytes:  ringBytes,
			LocalIPs:   local,
		}
		if err := mgr.Open(); err != nil {
			log.Printf("failed to open NTP capture sockets; retrying in 30s: %v", err)
			metrics.NtpClientsScrapeSuccess.Set(0)
			select {
			case <-stop:
				return
			case <-time.After(30 * time.Second):
			}
			continue
		}
		log.Println("NTP capture sockets open")
		metrics.NtpClientsScrapeSuccess.Set(1)
		mgrPtr.Store(mgr)

		mgr.Run(stop)
		mgrPtr.Store(nil)
		mgr.Close()
		metrics.NtpClientsScrapeSuccess.Set(0)
	}
}
