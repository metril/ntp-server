package aggregate

import "testing"

func TestTopNASNsRanksByCumulativeTotal(t *testing.T) {
	totals := map[int64]int64{1: 100, 2: 50, 3: 10}
	got := topNASNs(totals, 2)
	if len(got) != 2 || !got[1] || !got[2] {
		t.Fatalf("got %v", got)
	}
}

func TestFoldASNKeepsTopNLabels(t *testing.T) {
	top := map[int64]bool{13335: true, 15169: true}
	asn, org := foldASN(13335, true, "Cloudflare", top)
	if asn != "13335" || org != "Cloudflare" {
		t.Fatalf("got %q %q", asn, org)
	}
}

func TestFoldASNFoldsRestToOther(t *testing.T) {
	top := map[int64]bool{13335: true, 15169: true}
	asn, org := foldASN(64512, true, "Small ISP", top)
	if asn != "other" || org != "other" {
		t.Fatalf("got %q %q", asn, org)
	}
}

func TestFoldASNUnknownASNIsUnknown(t *testing.T) {
	asn, org := foldASN(0, false, "unknown", map[int64]bool{})
	if asn != "unknown" || org != "unknown" {
		t.Fatalf("got %q %q", asn, org)
	}
}
