# ntp-load

A minimal NTP load generator for exercising an `ntp-server` instance from a
LAN host at a controlled request rate.

## Usage

```
go run . -server 192.0.2.10:123 -rate 1000 -duration 30s -workers 8 -timeout 2s
```

Flags:

- `-server` — NTP server address, `host:port` (`:123` is appended if no port is given). Required.
- `-rate` — total requests per second across all workers (default `1000`).
- `-duration` — how long to send requests (default `30s`).
- `-workers` — number of UDP sockets / sender goroutines, each with its own ephemeral source port (default `8`).
- `-timeout` — how long to wait for straggler replies after `-duration` elapses (default `2s`).

Each worker sends real mode-3, NTPv4 client packets (no spoofing) from its
own socket, stamping a unique cookie into the Transmit Timestamp field
(bytes 40-47); the server's reply echoes it back in Origin Timestamp (bytes
24-31), which is used to match replies and compute RTT.

On completion it prints sent/received counts, loss percentage, achieved
send rate, and RTT p50/p95/p99/max in microseconds, and exits non-zero if
loss exceeds 1% so it can gate CI or manual runs.

## Watch in Grafana while it runs

- `rate(chrony_serverstats_ntp_packets_received_total[1m])`
- `rate(chrony_serverstats_ntp_packets_dropped_total[1m])`
- `rate(ntp_capture_kernel_drops_total[1m])`
- `increase(chrony_serverstats_client_log_records_dropped_total[5m])`
- `sum(rate(ntp_capture_packets_total[1m]))`
