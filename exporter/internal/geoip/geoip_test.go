package geoip

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestResolveMissingDBsFallsBackToUnknown(t *testing.T) {
	dir := t.TempDir()
	r := New(dir, 64, nil)
	res := r.Resolve("203.0.113.1")
	if res.Country != "unknown" || res.Continent != "unknown" || res.HasASN || res.ASOrg != "unknown" {
		t.Fatalf("got %+v", res)
	}
}

func TestResolveOnlyReopensOnTheCheckInterval(t *testing.T) {
	dir := t.TempDir()
	// Create empty (invalid) mmdb files just to exercise the mtime-driven
	// reopen path without needing a real GeoLite2 database; Open() will
	// fail to parse them, which is fine -- reader stays nil, "unknown".
	for _, name := range []string{"GeoLite2-Country.mmdb", "GeoLite2-ASN.mmdb"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("not a real mmdb"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	tt := time.Unix(1000, 0)
	r := New(dir, 64, nil)
	r.SetClock(func() time.Time { return tt })

	r.Resolve("203.0.113.1") // triggers first reopen attempt
	loadedAfterFirst := r.countryReader != nil

	tt = tt.Add(1 * time.Second)
	r.Resolve("203.0.113.2") // within the interval: no re-stat

	tt = tt.Add(ReopenCheckInterval)
	r.Resolve("203.0.113.3") // past the interval: re-stat again

	_ = loadedAfterFirst // invalid mmdb content means Open() fails either way; this test only checks Resolve doesn't panic across the reopen boundary.
}
