import socket
from types import SimpleNamespace

import pytest

import exporter
from exporter import PacketCollector

from test_capture import eth, ipv4, udp


class FakeClock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


def fake_geo(asn=64500, org="TestOrg"):
    return SimpleNamespace(resolve=lambda ip: ("US", "NA", asn, org))


def request_frame(ip="203.0.113.5"):
    return eth(ipv4(ip, "198.51.100.1", udp(41234, 123)))


def response_frame(ip="203.0.113.5"):
    return eth(ipv4("198.51.100.1", ip, udp(123, 41234)))


def counter(metric, **labels):
    return metric.labels(**labels)._value.get()


def make(clock, asn=64500, org="TestOrg"):
    return PacketCollector(fake_geo(asn, org), 25, lambda: None, clock=clock, wall=lambda: 0.0)


def test_flush_publishes_requests_and_floors_drops_at_the_difference():
    clock = FakeClock()
    c = make(clock, asn=64501, org="OrgA")
    before_req = counter(exporter.ntp_client_requests_total, country="US", continent="NA")
    before_drop = counter(exporter.ntp_client_drops_total, country="US", continent="NA")

    for _ in range(3):
        c.handle_frame(request_frame())
    c.handle_frame(response_frame())
    c.flush()

    assert counter(exporter.ntp_client_requests_total, country="US", continent="NA") == before_req + 3
    assert counter(exporter.ntp_client_drops_total, country="US", continent="NA") == before_drop + 2
    assert exporter.ntp_clients_active._value.get() == 1
    assert exporter.ntp_clients_unique_daily._value.get() >= 1


def test_more_responses_than_requests_never_produces_negative_drops():
    clock = FakeClock()
    c = make(clock, asn=64502, org="OrgB")
    before = counter(exporter.ntp_client_drops_total, country="US", continent="NA")
    c.handle_frame(request_frame("198.51.100.7"))
    c.handle_frame(response_frame("198.51.100.7"))
    c.handle_frame(response_frame("198.51.100.7"))
    c.flush()
    assert counter(exporter.ntp_client_drops_total, country="US", continent="NA") == before


def test_active_gauge_evicts_entries_older_than_the_window():
    clock = FakeClock()
    c = make(clock, asn=64503, org="OrgC")
    c.handle_frame(request_frame("192.0.2.10"))
    c.flush()
    assert exporter.ntp_clients_active._value.get() == 1

    clock.advance(301)
    c.flush()
    assert exporter.ntp_clients_active._value.get() == 0


def test_asn_counter_uses_the_top_n_fold():
    clock = FakeClock()
    c = make(clock, asn=64504, org="OrgD")
    before = counter(exporter.ntp_client_requests_by_asn_total, asn="64504", as_org="OrgD")
    c.handle_frame(request_frame("192.0.2.11"))
    c.flush()
    assert counter(exporter.ntp_client_requests_by_asn_total, asn="64504", as_org="OrgD") == before + 1


def test_unparseable_frame_increments_the_parse_error_counter():
    clock = FakeClock()
    c = make(clock, asn=64505, org="OrgE")
    before = exporter.ntp_capture_parse_errors_total._value.get()
    c.handle_frame(b"\x00" * 10)
    assert exporter.ntp_capture_parse_errors_total._value.get() == before + 1


def test_capture_packet_counter_is_labelled_by_direction():
    clock = FakeClock()
    c = make(clock, asn=64506, org="OrgF")
    before_req = counter(exporter.ntp_capture_packets_total, direction="request")
    before_resp = counter(exporter.ntp_capture_packets_total, direction="response")
    c.handle_frame(request_frame("192.0.2.12"))
    c.handle_frame(response_frame("192.0.2.12"))
    assert counter(exporter.ntp_capture_packets_total, direction="request") == before_req + 1
    assert counter(exporter.ntp_capture_packets_total, direction="response") == before_resp + 1


def test_hourly_bucket_is_reset_when_the_wall_hour_changes():
    clock = FakeClock()
    hour = [0]
    c = PacketCollector(
        fake_geo(64507, "OrgG"), 25, lambda: None, clock=clock, wall=lambda: hour[0] * 3600.0
    )
    c.handle_frame(request_frame("192.0.2.13"))
    assert c._hourly[0].count() >= 1
    hour[0] = 1
    c.handle_frame(request_frame("192.0.2.14"))
    assert c._hour == 1
    assert c._hourly[1].count() >= 1


def test_current_bucket_clears_all_skipped_hours_on_a_multi_hour_jump():
    clock = FakeClock()
    hour = [3]
    c = PacketCollector(fake_geo(), 25, lambda: None, clock=clock, wall=lambda: hour[0] * 3600.0)
    c.handle_frame(request_frame("192.0.2.20"))
    assert c._hourly[3].count() >= 1

    # Simulate stale same-hour-yesterday data sitting in the buckets that a
    # multi-hour jump skips over.
    for h in (4, 5, 6):
        c._hourly[h].add("stale-yesterday")
        assert c._hourly[h].count() >= 1

    hour[0] = 7
    c.handle_frame(request_frame("192.0.2.21"))

    assert c._hour == 7
    for h in (4, 5, 6):
        assert c._hourly[h].count() == 0  # cleared, not left stale
    assert c._hourly[7].count() >= 1
    assert c._hourly[3].count() >= 1  # untouched buckets keep their data


# --- open_capture_socket ---------------------------------------------------


def test_open_capture_socket_attaches_filter_and_returns_the_socket(monkeypatch):
    setsockopt_calls = []

    class FakeSock:
        def setsockopt(self, level, optname, value):
            setsockopt_calls.append((level, optname))

        def settimeout(self, t):
            self.timeout = t

        def close(self):
            pass

    fake = FakeSock()
    monkeypatch.setattr(exporter.socket, "socket", lambda *a, **k: fake)

    result = exporter.open_capture_socket()

    assert result is fake
    assert (socket.SOL_SOCKET, exporter.SO_ATTACH_FILTER) in setsockopt_calls
    assert (socket.SOL_SOCKET, socket.SO_RCVBUF) in setsockopt_calls
    assert fake.timeout == 1.0


# --- run_forever -------------------------------------------------------


def test_run_forever_recovers_from_a_sock_factory_error(monkeypatch):
    clock = FakeClock()
    sleeps = []
    monkeypatch.setattr(exporter.time, "sleep", lambda s: sleeps.append(s))

    class StopCapture(BaseException):
        # Not an Exception subclass: run_forever's per-iteration body now
        # swallows plain Exceptions (see the loop-error test below), so the
        # test needs a BaseException to still break out of the `while True`.
        pass

    class FakeSock:
        def recv(self, n):
            raise StopCapture()

        def close(self):
            pass

    attempts = [0]

    def factory():
        attempts[0] += 1
        if attempts[0] == 1:
            raise RuntimeError("boom")  # non-OSError: exercises the widened except
        return FakeSock()

    c = PacketCollector(fake_geo(), 25, factory, clock=clock, wall=lambda: 0.0)

    success_values = []
    monkeypatch.setattr(
        exporter.ntp_clients_scrape_success,
        "set",
        lambda v: success_values.append(v),
    )

    with pytest.raises(StopCapture):
        c.run_forever(15)

    assert sleeps == [30]
    assert success_values == [0, 1]


def test_run_forever_survives_a_geo_exception_and_keeps_capturing(monkeypatch):
    clock = FakeClock()

    calls = [0]

    def flaky_resolve(ip):
        calls[0] += 1
        if calls[0] == 2:
            raise RuntimeError("geoip exploded")
        return ("US", "NA", 64500, "TestOrg")

    geo = SimpleNamespace(resolve=flaky_resolve)

    class StopCapture(BaseException):
        pass

    frames = [request_frame("192.0.2.1"), request_frame("192.0.2.2"), None]

    class FakeSock:
        def recv(self, n):
            if not frames:
                raise StopCapture()
            f = frames.pop(0)
            if f is None:
                raise TimeoutError()
            return f

        def close(self):
            pass

    c = PacketCollector(geo, 25, lambda: FakeSock(), clock=clock, wall=lambda: 0.0)

    before = exporter.ntp_capture_loop_errors_total._value.get()
    before_req = counter(exporter.ntp_capture_packets_total, direction="request")

    with pytest.raises(StopCapture):
        c.run_forever(15)

    assert exporter.ntp_capture_loop_errors_total._value.get() == before + 1
    # first frame raised on geo.resolve and was swallowed; second frame (the
    # third recv() call, after the exception) was handled and counted.
    assert counter(exporter.ntp_capture_packets_total, direction="request") == before_req + 2


# --- kernel drop counter ------------------------------------------------


def test_flush_reads_kernel_drops_from_a_socket_with_getsockopt():
    import struct

    clock = FakeClock()
    c = make(clock)

    class FakeSock:
        def getsockopt(self, level, optname, buflen):
            assert level == exporter.SOL_PACKET
            assert optname == exporter.PACKET_STATISTICS
            return struct.pack("II", 100, 7)

    c._sock = FakeSock()
    before = exporter.ntp_capture_kernel_drops_total._value.get()
    c.flush()
    assert exporter.ntp_capture_kernel_drops_total._value.get() == before + 7


def test_flush_treats_a_socket_without_getsockopt_as_zero_drops():
    clock = FakeClock()
    c = make(clock)
    c._sock = object()  # no getsockopt attribute, like the fakes in other tests
    before = exporter.ntp_capture_kernel_drops_total._value.get()
    c.flush()
    assert exporter.ntp_capture_kernel_drops_total._value.get() == before


def test_flush_with_no_socket_reads_zero_drops():
    clock = FakeClock()
    c = make(clock)
    assert c._sock is None
    before = exporter.ntp_capture_kernel_drops_total._value.get()
    c.flush()
    assert exporter.ntp_capture_kernel_drops_total._value.get() == before


# --- hourly bucket rotation on flush -------------------------------------


def test_flush_rotates_hourly_buckets_even_during_a_silent_period():
    clock = FakeClock()
    hour = [3]
    c = PacketCollector(fake_geo(), 25, lambda: None, clock=clock, wall=lambda: hour[0] * 3600.0)
    c.handle_frame(request_frame("192.0.2.30"))
    assert c._hourly[3].count() >= 1

    for h in (4, 5, 6, 7):
        c._hourly[h].add("stale-yesterday")

    hour[0] = 7
    c.flush()  # no frames arrived; only flush() advances the wall clock view

    assert c._hour == 7
    for h in (4, 5, 6, 7):
        assert c._hourly[h].count() == 0
    assert c._hourly[3].count() >= 1
    assert exporter.ntp_clients_unique_daily._value.get() >= 1
