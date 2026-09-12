package aggregate

import (
	"sort"
	"strconv"
)

// topNASNs returns the set of ASNs ranked in the top n by cumulative total,
// ties broken by ascending decimal string of the ASN -- matches
// top_n_asns()'s heapq.nlargest(..., key=(count, _AscendingStr(str(asn))))
// in exporter.py.
func topNASNs(totals map[int64]int64, n int) map[int64]bool {
	type kv struct {
		asn   int64
		count int64
	}
	items := make([]kv, 0, len(totals))
	for k, v := range totals {
		items = append(items, kv{k, v})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].count != items[j].count {
			return items[i].count > items[j].count
		}
		return strconv.FormatInt(items[i].asn, 10) < strconv.FormatInt(items[j].asn, 10)
	})
	if n > len(items) {
		n = len(items)
	}
	out := make(map[int64]bool, n)
	for i := 0; i < n; i++ {
		out[items[i].asn] = true
	}
	return out
}

// pruneToLargest keeps only the max largest cumulative totals, matching
// flush()'s ASN_TOTALS_MAX pruning (heapq.nlargest by count only, no
// tie-break needed since pruning the tail can't change the top-N set).
func pruneToLargest(totals map[int64]int64, max int) map[int64]int64 {
	type kv struct {
		asn   int64
		count int64
	}
	items := make([]kv, 0, len(totals))
	for k, v := range totals {
		items = append(items, kv{k, v})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].count > items[j].count })
	if max > len(items) {
		max = len(items)
	}
	out := make(map[int64]int64, max)
	for i := 0; i < max; i++ {
		out[items[i].asn] = items[i].count
	}
	return out
}

// foldASN folds asn to ("other", "other") if it's not in topASNs; unknown
// ASN (hasASN == false) folds to ("unknown", "unknown"). Matches fold_asn()
// in exporter.py.
func foldASN(asn int64, hasASN bool, asOrg string, topASNs map[int64]bool) (string, string) {
	if !hasASN {
		return "unknown", "unknown"
	}
	if topASNs[asn] {
		return strconv.FormatInt(asn, 10), asOrg
	}
	return "other", "other"
}
