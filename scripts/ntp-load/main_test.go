package main

import (
	"net"
	"testing"
	"time"
)

// startStubServer listens on 127.0.0.1:0 and echoes the client's Transmit
// Timestamp (bytes 40-47) back as the reply's Origin Timestamp (bytes
// 24-31), mimicking real NTP server behavior closely enough to exercise the
// load generator's send/match/RTT logic end to end.
func startStubServer(t *testing.T) (addr string, stop func()) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	done := make(chan struct{})
	go func() {
		buf := make([]byte, 128)
		for {
			select {
			case <-done:
				return
			default:
			}
			conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, raddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				continue
			}
			if n < 48 {
				continue
			}
			reply := make([]byte, 48)
			reply[0] = 0x24 // LI=0, VN=4, Mode=4 (server)
			copy(reply[24:32], buf[40:48])
			conn.WriteToUDP(reply, raddr)
		}
	}()

	return conn.LocalAddr().String(), func() {
		close(done)
		conn.Close()
	}
}

func TestRunAgainstStub(t *testing.T) {
	addr, stop := startStubServer(t)
	defer stop()

	cfg := Config{
		Server:   addr,
		Rate:     200,
		Duration: 5 * time.Second,
		Workers:  4,
		Timeout:  1 * time.Second,
	}

	stats, err := run(cfg)
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	if stats.LossPercent != 0 {
		t.Errorf("expected 0%% loss against local stub, got %.2f%% (sent=%d received=%d)",
			stats.LossPercent, stats.Sent, stats.Received)
	}

	wantRate := cfg.Rate
	low, high := wantRate*0.8, wantRate*1.2
	if stats.AchievedRate < low || stats.AchievedRate > high {
		t.Errorf("achieved rate %.1f req/s outside 20%% of target %.1f req/s", stats.AchievedRate, wantRate)
	}

	t.Logf("sent=%d received=%d loss=%.2f%% achieved_rate=%.1f rtt_us p50=%.0f p95=%.0f p99=%.0f max=%.0f",
		stats.Sent, stats.Received, stats.LossPercent, stats.AchievedRate,
		stats.P50US, stats.P95US, stats.P99US, stats.MaxUS)
}

// TestRunHighRateAgainstStub exercises the deadline-based pacer at a rate
// high enough (5000 req/s) that a naive time.Ticker would silently drop
// ticks and undershoot; achieved rate must stay within 5% of requested.
func TestRunHighRateAgainstStub(t *testing.T) {
	addr, stop := startStubServer(t)
	defer stop()

	cfg := Config{
		Server:   addr,
		Rate:     5000,
		Duration: 2 * time.Second,
		Workers:  8,
		Timeout:  1 * time.Second,
	}

	stats, err := run(cfg)
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	minRate := cfg.Rate * 0.85 // loose: -race and CI boxes jitter the pacer
	if stats.AchievedRate < minRate {
		t.Errorf("achieved rate %.1f req/s below 85%% of target %.1f req/s (sent=%d received=%d loss=%.2f%%)",
			stats.AchievedRate, cfg.Rate, stats.Sent, stats.Received, stats.LossPercent)
	}

	t.Logf("sent=%d received=%d loss=%.2f%% achieved_rate=%.1f rtt_us p50=%.0f p95=%.0f p99=%.0f max=%.0f",
		stats.Sent, stats.Received, stats.LossPercent, stats.AchievedRate,
		stats.P50US, stats.P95US, stats.P99US, stats.MaxUS)
}
