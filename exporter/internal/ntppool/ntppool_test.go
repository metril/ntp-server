package ntppool

import (
	"os"
	"path/filepath"
	"testing"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", name))
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}
	return data
}

func TestParseTopLevelScoreIsNewestHistoryEntry(t *testing.T) {
	data := fixture(t, "ntppool.json")
	result, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if result.Score == nil || *result.Score != 17.8 {
		t.Fatalf("got %v", result.Score)
	}
}

func TestParsePerMonitorUsesNewestEntryPerMonitorID(t *testing.T) {
	data := fixture(t, "ntppool.json")
	result, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Monitors) != 2 {
		t.Fatalf("got %d monitors", len(result.Monitors))
	}
	lax := result.Monitors["mon-lax"]
	if lax.Score == nil || *lax.Score != 18.4 {
		t.Fatalf("lax score: %v", lax.Score)
	}
	if lax.OffsetSeconds == nil || *lax.OffsetSeconds != 0.0002 {
		t.Fatalf("lax offset: %v", lax.OffsetSeconds)
	}
	if lax.RTTSeconds == nil || !approx(*lax.RTTSeconds, 0.0135) {
		t.Fatalf("lax rtt: %v", lax.RTTSeconds)
	}

	fra := result.Monitors["mon-fra"]
	if fra.Score == nil || *fra.Score != 17.8 {
		t.Fatalf("fra score: %v", fra.Score)
	}
	if fra.RTTSeconds == nil || !approx(*fra.RTTSeconds, 0.0462) {
		t.Fatalf("fra rtt: %v", fra.RTTSeconds)
	}
}

func approx(a, b float64) bool {
	d := a - b
	if d < 0 {
		d = -d
	}
	return d < 1e-9
}

func TestParseUnknownMonitorIDFallsBackToStringifiedID(t *testing.T) {
	data := []byte(`{"monitors":[],"history":[{"ts":"2026-01-01T00:00:00Z","offset":0.0,"rtt":10.0,"score":15.0,"monitor_id":99}]}`)
	result, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := result.Monitors["99"]; !ok {
		t.Fatalf("expected monitor '99', got %v", result.Monitors)
	}
}

func TestParseEmptyHistory(t *testing.T) {
	data := []byte(`{"monitors":[],"history":[]}`)
	result, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if result.Score != nil {
		t.Fatalf("expected nil score, got %v", result.Score)
	}
	if len(result.Monitors) != 0 {
		t.Fatalf("expected no monitors, got %v", result.Monitors)
	}
}

func TestParseOverallScoreUsesNewestEntryMonitorIDOptional(t *testing.T) {
	data := fixture(t, "ntppool_overall.json")
	score, err := ParseOverallScore(data)
	if err != nil {
		t.Fatal(err)
	}
	if score == nil || *score != 17.95 {
		t.Fatalf("got %v", score)
	}
}

func TestParseOverallScoreEmptyHistory(t *testing.T) {
	score, err := ParseOverallScore([]byte(`{"monitors":[],"history":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if score != nil {
		t.Fatalf("expected nil, got %v", *score)
	}
}
