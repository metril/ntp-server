package hll

import (
	"fmt"
	"math/rand"
	"testing"
)

func ips(n int, seed int64) map[string]struct{} {
	rnd := rand.New(rand.NewSource(seed))
	out := map[string]struct{}{}
	for len(out) < n {
		ip := fmt.Sprintf("%d.%d.%d.%d", rnd.Intn(256), rnd.Intn(256), rnd.Intn(256), rnd.Intn(256))
		out[ip] = struct{}{}
	}
	return out
}

func within(estimate, truth, pct float64) bool {
	d := estimate - truth
	if d < 0 {
		d = -d
	}
	return d <= truth*pct
}

func TestEmptySketchCountsZero(t *testing.T) {
	if NewDefault().Count() != 0 {
		t.Fatal("expected 0")
	}
}

func TestEstimates1kDistinctWithin3Percent(t *testing.T) {
	h := NewDefault()
	keys := ips(1000, 1)
	for k := range keys {
		h.Add(k)
	}
	if !within(h.Count(), float64(len(keys)), 0.03) {
		t.Fatalf("estimate %v not within 3%% of %d", h.Count(), len(keys))
	}
}

func TestEstimates100kDistinctWithin3Percent(t *testing.T) {
	h := NewDefault()
	keys := ips(100000, 2)
	for k := range keys {
		h.Add(k)
	}
	if !within(h.Count(), float64(len(keys)), 0.03) {
		t.Fatalf("estimate %v not within 3%% of %d", h.Count(), len(keys))
	}
}

func TestDuplicatesDoNotInflateTheEstimate(t *testing.T) {
	h := NewDefault()
	keys := ips(1000, 3)
	for i := 0; i < 50; i++ {
		for k := range keys {
			h.Add(k)
		}
	}
	if !within(h.Count(), 1000, 0.03) {
		t.Fatalf("estimate %v not within 3%% of 1000", h.Count())
	}
}

func TestMergeOfDisjointSetsMatchesUnionEstimate(t *testing.T) {
	// Sized well clear of the m=16384 linear-counting crossover (2.5*m ~=
	// 40960) in both directions so the test isn't flaky depending on which
	// estimator branch a given random draw lands in near the boundary.
	aKeys := ips(30000, 4)
	bKeysAll := ips(30000, 5)
	bKeys := map[string]struct{}{}
	for k := range bKeysAll {
		if _, dup := aKeys[k]; !dup {
			bKeys[k] = struct{}{}
		}
	}
	a, b, union := NewDefault(), NewDefault(), NewDefault()
	for k := range aKeys {
		a.Add(k)
		union.Add(k)
	}
	for k := range bKeys {
		b.Add(k)
		union.Add(k)
	}
	a.Merge(b)
	total := float64(len(aKeys) + len(bKeys))
	if !within(a.Count(), total, 0.03) {
		t.Fatalf("estimate %v not within 3%% of %v", a.Count(), total)
	}
	if !within(a.Count(), union.Count(), 0.03) {
		t.Fatalf("merged estimate %v not within 3%% of union estimate %v", a.Count(), union.Count())
	}
}

func TestMergeRejectsMismatchedPrecision(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic merging mismatched precisions")
		}
	}()
	New(14).Merge(New(12))
}
