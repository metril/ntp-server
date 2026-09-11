import random

from exporter import HyperLogLog


def ips(n, seed):
    rnd = random.Random(seed)
    out = set()
    while len(out) < n:
        out.add(".".join(str(rnd.randrange(256)) for _ in range(4)))
    return out


def within(estimate, truth, pct=0.03):
    return abs(estimate - truth) <= truth * pct


def test_empty_sketch_counts_zero():
    assert HyperLogLog().count() == 0


def test_estimates_1k_distinct_within_3_percent():
    hll = HyperLogLog()
    keys = ips(1000, seed=1)
    for k in keys:
        hll.add(k)
    assert within(hll.count(), len(keys))


def test_estimates_100k_distinct_within_3_percent():
    hll = HyperLogLog()
    keys = ips(100000, seed=2)
    for k in keys:
        hll.add(k)
    assert within(hll.count(), len(keys))


def test_duplicates_do_not_inflate_the_estimate():
    hll = HyperLogLog()
    for _ in range(50):
        for k in ips(1000, seed=3):
            hll.add(k)
    assert within(hll.count(), 1000)


def test_merge_of_disjoint_sets_matches_union_estimate():
    a_keys = ips(20000, seed=4)
    b_keys = ips(20000, seed=5) - a_keys
    a, b, union = HyperLogLog(), HyperLogLog(), HyperLogLog()
    for k in a_keys:
        a.add(k)
        union.add(k)
    for k in b_keys:
        b.add(k)
        union.add(k)
    a.merge(b)
    assert within(a.count(), len(a_keys) + len(b_keys))
    assert within(a.count(), union.count())


def test_merge_rejects_mismatched_precision():
    try:
        HyperLogLog(p=14).merge(HyperLogLog(p=12))
    except ValueError:
        return
    raise AssertionError("merge across precisions must raise ValueError")
