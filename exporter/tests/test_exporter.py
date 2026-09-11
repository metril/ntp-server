import json
import os
from types import SimpleNamespace

import pytest

import exporter
from exporter import (
    GeoIPResolver,
    fold_asn,
    parse_ntppool,
    parse_ntppool_overall_score,
    resolve_geo,
    top_n_asns,
)

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def read_fixture(name):
    with open(os.path.join(FIXTURES, name)) as f:
        return f.read()


# --- resolve_geo -----------------------------------------------------------


def test_resolve_geo_hit():
    country_db = {"1.1.1.1": {"country": {"iso_code": "AU"}, "continent": {"code": "OC"}}}
    asn_db = {"1.1.1.1": {"autonomous_system_number": 13335, "autonomous_system_organization": "Cloudflare"}}
    result = resolve_geo("1.1.1.1", country_db.get, asn_db.get)
    assert result == ("AU", "OC", 13335, "Cloudflare")


def test_resolve_geo_miss_falls_back_to_unknown():
    result = resolve_geo("9.9.9.9", lambda ip: None, lambda ip: None)
    assert result == ("unknown", "unknown", None, "unknown")


def test_resolve_geo_lookup_exception_is_treated_as_miss():
    def boom(ip):
        raise RuntimeError("db closed")

    result = resolve_geo("1.1.1.1", boom, boom)
    assert result == ("unknown", "unknown", None, "unknown")


# --- ASN top-N folding ------------------------------------------------------


def test_top_n_asns_ranks_by_cumulative_total():
    totals = {"A": 100, "B": 50, "C": 10}
    assert top_n_asns(totals, 2) == {"A", "B"}


def test_fold_asn_keeps_top_n_labels():
    totals = {13335: 100, 15169: 50, 64512: 10}
    assert fold_asn(13335, "Cloudflare", totals, 2) == (13335, "Cloudflare")


def test_fold_asn_folds_rest_to_other():
    totals = {13335: 100, 15169: 50, 64512: 10}
    assert fold_asn(64512, "Small ISP", totals, 2) == ("other", "other")


def test_fold_asn_unknown_asn_is_unknown():
    assert fold_asn(None, "unknown", {}, 25) == ("unknown", "unknown")


# --- parse_ntppool -----------------------------------------------------------


@pytest.fixture
def ntppool_data():
    return json.loads(read_fixture("ntppool.json"))


def test_parse_ntppool_top_level_score_is_newest_history_entry(ntppool_data):
    result = parse_ntppool(ntppool_data)
    assert result["score"] == 17.8  # newest overall entry: monitor 2 @ 11:15


def test_parse_ntppool_per_monitor_uses_newest_entry_per_monitor_id(ntppool_data):
    result = parse_ntppool(ntppool_data)
    assert set(result["monitors"]) == {"mon-lax", "mon-fra"}
    lax = result["monitors"]["mon-lax"]
    assert lax["score"] == 18.4
    assert lax["offset_seconds"] == 0.0002
    assert lax["rtt_seconds"] == pytest.approx(0.0135)

    fra = result["monitors"]["mon-fra"]
    assert fra["score"] == 17.8
    assert fra["rtt_seconds"] == pytest.approx(0.0462)


def test_parse_ntppool_unknown_monitor_id_falls_back_to_stringified_id():
    data = {
        "monitors": [],
        "history": [
            {"ts": "2026-01-01T00:00:00Z", "offset": 0.0, "rtt": 10.0, "score": 15.0, "monitor_id": 99}
        ],
    }
    result = parse_ntppool(data)
    assert "99" in result["monitors"]


def test_parse_ntppool_empty_history():
    result = parse_ntppool({"monitors": [], "history": []})
    assert result["score"] is None
    assert result["monitors"] == {}


# --- parse_ntppool_overall_score ---------------------------------------------


def test_parse_ntppool_overall_score_uses_newest_entry_monitor_id_optional():
    data = json.loads(read_fixture("ntppool_overall.json"))
    # newest entry (11:15) has no monitor_id key at all; an older entry has
    # monitor_id explicitly null. Neither should break picking the newest.
    assert parse_ntppool_overall_score(data) == 17.95


def test_parse_ntppool_overall_score_empty_history():
    assert parse_ntppool_overall_score({"monitors": [], "history": []}) is None


# --- GeoIPResolver reader lifecycle -------------------------------------------


def test_reopen_if_needed_closes_old_readers_before_replacing(monkeypatch, tmp_path):
    resolver = GeoIPResolver(str(tmp_path))

    opened = []

    class FakeReader:
        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True

    resolver._maxminddb = SimpleNamespace(open_database=lambda path: opened.append(FakeReader()) or opened[-1])

    mtimes = iter([1.0, 1.0, 2.0, 2.0])
    monkeypatch.setattr(exporter.os.path, "getmtime", lambda p: next(mtimes))

    resolver._reopen_if_needed()
    resolver._reopen_if_needed()

    assert len(opened) == 4
    assert opened[0].closed and opened[1].closed  # old country/asn readers closed on reopen
    assert not opened[2].closed and not opened[3].closed  # current readers left open
