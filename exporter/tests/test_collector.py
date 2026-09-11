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


# --- recv_frame (SCM_TIMESTAMPNS) ----------------------------------------


def test_recv_frame_parses_scm_timestampns():
    import struct

    class FakeSock:
        def recvmsg(self, bufsize, ancsize):
            ancdata = [(socket.SOL_SOCKET, exporter.SCM_TIMESTAMPNS, struct.pack("qq", 100, 250_000_000))]
            return b"frame-bytes", ancdata, 0, None

    frame, ts, _pkttype = exporter.recv_frame(FakeSock())
    assert frame == b"frame-bytes"
    assert ts == 100.25


def test_recv_frame_returns_none_ts_when_no_cmsg():
    class FakeSock:
        def recvmsg(self, bufsize, ancsize):
            return b"frame-bytes", [], 0, None

    frame, ts, _pkttype = exporter.recv_frame(FakeSock())
    assert frame == b"frame-bytes"
    assert ts is None


def test_recv_frame_falls_back_to_recv_when_no_recvmsg():
    class FakeSock:
        def recv(self, n):
            return b"legacy-frame"

    frame, ts, pkttype = exporter.recv_frame(FakeSock())
    assert frame == b"legacy-frame"
    assert ts is None


def test_open_capture_socket_sets_so_timestampns(monkeypatch):
    setsockopt_calls = []

    class FakeSock:
        def setsockopt(self, level, optname, value):
            setsockopt_calls.append((level, optname))

        def settimeout(self, t):
            pass

        def close(self):
            pass

    fake = FakeSock()
    monkeypatch.setattr(exporter.socket, "socket", lambda *a, **k: fake)

    exporter.open_capture_socket()

    assert (socket.SOL_SOCKET, exporter.SO_TIMESTAMPNS) in setsockopt_calls


def test_run_forever_passes_recvmsg_timestamp_to_handle_frame(monkeypatch):
    import struct

    clock = FakeClock()

    class StopCapture(BaseException):
        pass

    calls = []
    real_handle_frame = exporter.PacketCollector.handle_frame

    def spy_handle_frame(self, frame, ts=None, pkttype=None):
        calls.append(ts)
        raise StopCapture()

    monkeypatch.setattr(exporter.PacketCollector, "handle_frame", spy_handle_frame)

    class FakeSock:
        def recvmsg(self, bufsize, ancsize):
            ancdata = [(socket.SOL_SOCKET, exporter.SCM_TIMESTAMPNS, struct.pack("qq", 42, 500_000_000))]
            return request_frame(), ancdata, 0, None

        def close(self):
            pass

    c = PacketCollector(fake_geo(), 25, lambda: FakeSock(), clock=clock, wall=lambda: 0.0)

    with pytest.raises(StopCapture):
        c.run_forever(15)

    assert calls == [42.5]


# --- response latency histogram / pending dict ----------------------------


def _histogram_sum(metric):
    return metric.labels()._sum.get() if metric._labelnames else metric._sum.get()


def request_frame_with_xid(ip, xid):
    payload = b"\x23" + b"\x00" * 39 + xid
    return eth(ipv4(ip, "198.51.100.1", udp(41234, 123, payload)))


def response_frame_with_xid(ip, xid):
    payload = b"\x23" + b"\x00" * 23 + xid + b"\x00" * 16
    return eth(ipv4("198.51.100.1", ip, udp(123, 41234, payload)))


def test_response_latency_observed_for_a_matched_request_response_pair():
    clock = FakeClock()
    c = make(clock)
    xid = b"\xaa" * 8
    before = exporter.ntp_response_latency_seconds._sum.get()

    c.handle_frame(request_frame_with_xid("192.0.2.50", xid), ts=100.0)
    c.handle_frame(response_frame_with_xid("192.0.2.50", xid), ts=100.001)

    after = exporter.ntp_response_latency_seconds._sum.get()
    assert after - before == pytest.approx(0.001)
    assert ("192.0.2.50", xid) not in c._pending


def test_response_with_unknown_xid_is_ignored():
    clock = FakeClock()
    c = make(clock)
    before = exporter.ntp_response_latency_seconds._sum.get()
    c.handle_frame(response_frame_with_xid("192.0.2.51", b"\xbb" * 8), ts=100.0)
    assert exporter.ntp_response_latency_seconds._sum.get() == before


def test_unmatched_request_is_swept_at_flush_and_dict_stays_bounded():
    clock = FakeClock()
    c = make(clock)
    xid = b"\xcc" * 8
    c.handle_frame(request_frame_with_xid("192.0.2.52", xid), ts=100.0)
    assert ("192.0.2.52", xid) in c._pending

    c._wall = lambda: 100.0 + exporter.PENDING_TTL_SECONDS + 0.1
    c.flush()
    assert ("192.0.2.52", xid) not in c._pending


def test_pending_overflow_counter_increments_past_cap(monkeypatch):
    clock = FakeClock()
    c = make(clock)
    monkeypatch.setattr(exporter, "PENDING_MAX", 2)
    before = exporter.ntp_capture_pending_overflow_total._value.get()

    c.handle_frame(request_frame_with_xid("192.0.2.53", b"\x01" * 8), ts=100.0)
    c.handle_frame(request_frame_with_xid("192.0.2.54", b"\x02" * 8), ts=100.0)
    c.handle_frame(request_frame_with_xid("192.0.2.55", b"\x03" * 8), ts=100.0)

    assert exporter.ntp_capture_pending_overflow_total._value.get() == before + 1
    assert len(c._pending) == 2


# --- version/family counters + request-interval histogram -----------------


def test_flush_publishes_version_and_family_counters():
    clock = FakeClock()
    c = make(clock)
    before_v4 = counter(exporter.ntp_client_requests_by_version_total, version="4")
    before_ipv4 = counter(exporter.ntp_client_requests_by_family_total, family="ipv4")

    c.handle_frame(request_frame_with_xid("192.0.2.60", b"\x01" * 8))
    c.flush()

    assert counter(exporter.ntp_client_requests_by_version_total, version="4") == before_v4 + 1
    assert counter(exporter.ntp_client_requests_by_family_total, family="ipv4") == before_ipv4 + 1


def test_unknown_version_folds_to_other():
    clock = FakeClock()
    c = make(clock)
    before = counter(exporter.ntp_client_requests_by_version_total, version="other")
    frame = eth(ipv4("192.0.2.61", "198.51.100.1", udp(41234, 123, b"\x00" * 10)))
    c.handle_frame(frame)
    c.flush()
    assert counter(exporter.ntp_client_requests_by_version_total, version="other") == before + 1


def test_request_interval_observed_only_from_the_second_request():
    clock = FakeClock()
    c = make(clock)
    before = exporter.ntp_client_request_interval_seconds._sum.get()

    c.handle_frame(request_frame("192.0.2.62"))
    assert exporter.ntp_client_request_interval_seconds._sum.get() == before

    clock.advance(5)
    c.handle_frame(request_frame("192.0.2.62"))
    after = exporter.ntp_client_request_interval_seconds._sum.get()
    assert after - before == pytest.approx(5)


# --- pkttype filtering (ignore chronyd's own upstream polls) --------------


def test_outgoing_frame_with_dport_123_is_not_a_request():
    clock = FakeClock()
    c = make(clock)
    before_req = counter(exporter.ntp_capture_packets_total, direction="request")
    before_active = len(c._active)

    c.handle_frame(request_frame("192.0.2.70"), pkttype=exporter.PACKET_OUTGOING)

    assert counter(exporter.ntp_capture_packets_total, direction="request") == before_req
    assert len(c._active) == before_active


def test_incoming_frame_with_sport_123_is_not_a_response():
    clock = FakeClock()
    c = make(clock)
    before_resp = counter(exporter.ntp_capture_packets_total, direction="response")

    c.handle_frame(response_frame("192.0.2.71"), pkttype=exporter.PACKET_HOST)

    assert counter(exporter.ntp_capture_packets_total, direction="response") == before_resp


def test_none_pkttype_keeps_old_behaviour():
    clock = FakeClock()
    c = make(clock)
    before_req = counter(exporter.ntp_capture_packets_total, direction="request")
    c.handle_frame(request_frame("192.0.2.72"), pkttype=None)
    assert counter(exporter.ntp_capture_packets_total, direction="request") == before_req + 1


def test_pkttype_filtered_frame_does_not_count_as_parse_error():
    clock = FakeClock()
    c = make(clock)
    before = exporter.ntp_capture_parse_errors_total._value.get()
    c.handle_frame(request_frame("192.0.2.73"), pkttype=exporter.PACKET_OUTGOING)
    assert exporter.ntp_capture_parse_errors_total._value.get() == before


def test_recv_frame_returns_pkttype_from_recvmsg_address():
    class FakeSock:
        def recvmsg(self, bufsize, ancsize):
            return b"frame-bytes", [], 0, ("eth0", 3, exporter.PACKET_OUTGOING, 1, b"\x00" * 6)

    frame, ts, pkttype = exporter.recv_frame(FakeSock())
    assert pkttype == exporter.PACKET_OUTGOING


def test_recv_frame_pkttype_is_none_on_recv_fallback():
    class FakeSock:
        def recv(self, n):
            return b"legacy-frame"

    frame, ts, pkttype = exporter.recv_frame(FakeSock())
    assert pkttype is None


# --- incremental pending sweep (bounded without waiting for flush) --------


def test_pending_is_swept_incrementally_without_flush():
    clock = FakeClock()
    c = make(clock)
    for i in range(1023):
        xid = i.to_bytes(8, "big")
        c.handle_frame(request_frame_with_xid("192.0.2.100", xid), ts=100.0)
    assert len(c._pending) == 1023

    c.handle_frame(
        request_frame_with_xid("192.0.2.100", b"\xff" * 8),
        ts=100.0 + exporter.PENDING_TTL_SECONDS + 5,
    )

    assert len(c._pending) == 1


# --- HELP text -------------------------------------------------------------


def test_request_interval_help_text_explains_the_active_window():
    assert (
        exporter.ntp_client_request_interval_seconds._documentation
        == "Seconds between consecutive requests from the same client IP; intervals "
        "longer than roughly 300s are not observed because the client has left the "
        "active window"
    )
