// Package metrics declares every Prometheus collector used by the exporter.
// Names, labels, help strings, and histogram buckets are copied verbatim
// from exporter.py:474-554, with one deliberate change: the
// ntp_capture_rcvbuf_bytes help text now describes the total capture ring
// size instead of a single socket's SO_RCVBUF, since capture now uses N
// AF_PACKET TPACKET_V3 sockets under one fanout group instead of one socket.
package metrics

import (
	"math"

	"github.com/prometheus/client_golang/prometheus"
)

// Registry is a fresh registry containing only the metrics below -- no Go
// runtime/process collectors, matching main()'s unregistration of
// PROCESS_COLLECTOR/PLATFORM_COLLECTOR/GC_COLLECTOR in exporter.py.
var Registry = prometheus.NewRegistry()

var (
	NtpClientRequestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ntp_client_requests_total",
		Help: "NTP client requests by country",
	}, []string{"country", "continent"})

	NtpClientDropsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ntp_client_drops_total",
		Help: "NTP client dropped requests by country",
	}, []string{"country", "continent"})

	NtpClientRequestsByASNTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ntp_client_requests_by_asn_total",
		Help: "NTP client requests by ASN (top-N, rest folded to 'other')",
	}, []string{"asn", "as_org"})

	NtpClientsActive = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ntp_clients_active",
		Help: "Distinct client IPs seen in the last 300s",
	})

	NtpClientsUniqueDaily = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ntp_clients_unique_daily",
		Help: "Distinct client IPs seen in the last 24h",
	})

	NtpClientsScrapeSuccess = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ntp_clients_scrape_success",
		Help: "1 while the NTP capture socket is open",
	})

	NtpCapturePacketsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ntp_capture_packets_total",
		Help: "NTP frames captured, by direction",
	}, []string{"direction"})

	NtpCaptureParseErrorsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ntp_capture_parse_errors_total",
		Help: "Frames that passed the BPF filter but could not be parsed",
	})

	NtpCaptureLoopErrorsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ntp_capture_loop_errors_total",
		Help: "Unexpected exceptions in the capture loop (geo/prometheus errors etc.), swallowed to keep the daemon alive",
	})

	NtpCaptureKernelDropsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ntp_capture_kernel_drops_total",
		Help: "Packets the kernel dropped before the capture socket could read them (PACKET_STATISTICS)",
	})

	NtpCapturePendingOverflowTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ntp_capture_pending_overflow_total",
		Help: "Requests dropped from the request/response pairing table because it was full (PENDING_MAX)",
	})

	NtpCaptureRcvbufBytes = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ntp_capture_rcvbuf_bytes",
		Help: "Total TPACKET_V3 ring bytes allocated across all capture workers",
	})

	NtpClientRequestsByVersionTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ntp_client_requests_by_version_total",
		Help: "NTP client requests by NTP version",
	}, []string{"version"})

	NtpClientRequestsByFamilyTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ntp_client_requests_by_family_total",
		Help: "NTP client requests by IP family",
	}, []string{"family"})

	NtpClientRequestIntervalSeconds = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "ntp_client_request_interval_seconds",
		Help:    "Seconds between consecutive requests from the same client IP; intervals longer than roughly 300s are not observed because the client has left the active window",
		Buckets: []float64{0.5, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, math.Inf(1)},
	})

	NtpResponseLatencySeconds = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "ntp_response_latency_seconds",
		Help:    "Server request-to-response latency measured passively",
		Buckets: []float64{20e-6, 50e-6, 100e-6, 200e-6, 500e-6, 1e-3, 2e-3, 5e-3, 10e-3, 25e-3, 50e-3, math.Inf(1)},
	})

	NtppoolScore = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ntppool_score",
		Help: "Latest pool.ntp.org score",
	}, []string{"ip"})

	NtppoolMonitorScore = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ntppool_monitor_score",
		Help: "Latest pool.ntp.org score per monitor",
	}, []string{"ip", "monitor"})

	NtppoolMonitorOffsetSeconds = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ntppool_monitor_offset_seconds",
		Help: "Latest pool.ntp.org offset per monitor, seconds",
	}, []string{"ip", "monitor"})

	NtppoolMonitorRttSeconds = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ntppool_monitor_rtt_seconds",
		Help: "Latest pool.ntp.org RTT per monitor, seconds",
	}, []string{"ip", "monitor"})

	NtppoolScrapeSuccess = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ntppool_scrape_success",
		Help: "1 if the last ntppool.org poll succeeded",
	})

	NtpGeoipDatabaseLoaded = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ntp_geoip_database_loaded",
		Help: "1 if the GeoLite2 mmdb is open and readable",
	}, []string{"db"})
)

// Pre-seed only label combinations that are real and always meaningful, so
// rate() works from the first scrape. Never seed empty-label placeholders:
// they would render as blank rows in the dashboards. Other Vecs appear on
// first observation, same as the old Python exporter did.
func init() {
	NtpCapturePacketsTotal.WithLabelValues("request")
	NtpCapturePacketsTotal.WithLabelValues("response")
	NtpGeoipDatabaseLoaded.WithLabelValues("country")
	NtpGeoipDatabaseLoaded.WithLabelValues("asn")

	Registry.MustRegister(
		NtpClientRequestsTotal,
		NtpClientDropsTotal,
		NtpClientRequestsByASNTotal,
		NtpClientsActive,
		NtpClientsUniqueDaily,
		NtpClientsScrapeSuccess,
		NtpCapturePacketsTotal,
		NtpCaptureParseErrorsTotal,
		NtpCaptureLoopErrorsTotal,
		NtpCaptureKernelDropsTotal,
		NtpCapturePendingOverflowTotal,
		NtpCaptureRcvbufBytes,
		NtpClientRequestsByVersionTotal,
		NtpClientRequestsByFamilyTotal,
		NtpClientRequestIntervalSeconds,
		NtpResponseLatencySeconds,
		NtppoolScore,
		NtppoolMonitorScore,
		NtppoolMonitorOffsetSeconds,
		NtppoolMonitorRttSeconds,
		NtppoolScrapeSuccess,
		NtpGeoipDatabaseLoaded,
	)
}
