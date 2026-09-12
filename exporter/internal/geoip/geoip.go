// Package geoip wraps two maxminddb readers (country + ASN), reopening each
// when its file's mtime changes, with an LRU-cached lookup per IP. Port of
// GeoIPResolver / resolve_geo from exporter.py.
package geoip

import (
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/oschwald/maxminddb-golang/v2"
)

const ReopenCheckInterval = 30 * time.Second

// Result mirrors resolve_geo()'s return tuple.
type Result struct {
	Country   string
	Continent string
	ASN       int64 // 0 with HasASN=false means "unknown" (Python's None)
	HasASN    bool
	ASOrg     string
}

type countryRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	Continent struct {
		Code string `maxminddb:"code"`
	} `maxminddb:"continent"`
}

type asnRecord struct {
	ASN   uint32 `maxminddb:"autonomous_system_number"`
	AsOrg string `maxminddb:"autonomous_system_organization"`
}

// Resolver is safe for concurrent use.
type Resolver struct {
	countryPath string
	asnPath     string
	clock       func() time.Time

	mu                 sync.RWMutex
	countryReader      *maxminddb.Reader
	asnReader          *maxminddb.Reader
	countryMtime       time.Time
	asnMtime           time.Time
	countryMtimeSet    bool
	asnMtimeSet        bool
	countryMissWarn    bool
	asnMissWarn        bool
	lastReopenCheck    time.Time
	lastReopenCheckSet bool

	cache *lru.Cache[string, Result]

	loadedGauge func(db string, loaded bool)
}

// New creates a Resolver rooted at geoipDir, containing
// GeoLite2-Country.mmdb and GeoLite2-ASN.mmdb. loadedGauge, if non-nil, is
// called whenever a database's loaded state is (re)computed, to drive the
// ntp_geoip_database_loaded gauge.
func New(geoipDir string, cacheSize int, loadedGauge func(db string, loaded bool)) *Resolver {
	cache, _ := lru.New[string, Result](cacheSize)
	return &Resolver{
		countryPath: filepath.Join(geoipDir, "GeoLite2-Country.mmdb"),
		asnPath:     filepath.Join(geoipDir, "GeoLite2-ASN.mmdb"),
		clock:       time.Now,
		cache:       cache,
		loadedGauge: loadedGauge,
	}
}

func (r *Resolver) reopenOne(path string, reader *maxminddb.Reader, mtime time.Time, mtimeSet bool, missWarned bool, dbLabel string) (*maxminddb.Reader, time.Time, bool, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		if reader == nil && !missWarned {
			log.Printf("GeoIP database missing: %s (%v)", path, err)
			missWarned = true
		}
		if r.loadedGauge != nil {
			r.loadedGauge(dbLabel, reader != nil)
		}
		return reader, time.Time{}, false, missWarned
	}

	missWarned = false
	newMtime := fi.ModTime()
	if !mtimeSet || !newMtime.Equal(mtime) {
		mtime = newMtime
		mtimeSet = true
		oldReader := reader
		newReader, oerr := maxminddb.Open(path)
		if oerr != nil {
			log.Printf("failed to open %s: %v", path, oerr)
			reader = nil
		} else {
			reader = newReader
		}
		if oldReader != nil {
			if cerr := oldReader.Close(); cerr != nil {
				log.Printf("failed to close old %s reader: %v", path, cerr)
			}
		}
		r.cache.Purge()
	}

	if r.loadedGauge != nil {
		r.loadedGauge(dbLabel, reader != nil)
	}
	return reader, mtime, mtimeSet, missWarned
}

func (r *Resolver) reopenIfNeeded() {
	r.countryReader, r.countryMtime, r.countryMtimeSet, r.countryMissWarn = r.reopenOne(
		r.countryPath, r.countryReader, r.countryMtime, r.countryMtimeSet, r.countryMissWarn, "country")
	r.asnReader, r.asnMtime, r.asnMtimeSet, r.asnMissWarn = r.reopenOne(
		r.asnPath, r.asnReader, r.asnMtime, r.asnMtimeSet, r.asnMissWarn, "asn")
}

func (r *Resolver) resolveUncached(ip string) Result {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return Result{Country: "unknown", Continent: "unknown", ASOrg: "unknown"}
	}

	res := Result{Country: "unknown", Continent: "unknown", ASOrg: "unknown"}

	if r.countryReader != nil {
		var rec countryRecord
		result := r.countryReader.Lookup(addr)
		if err := result.Decode(&rec); err == nil {
			if rec.Country.ISOCode != "" {
				res.Country = rec.Country.ISOCode
			}
			if rec.Continent.Code != "" {
				res.Continent = rec.Continent.Code
			}
		}
	}

	if r.asnReader != nil {
		var rec asnRecord
		result := r.asnReader.Lookup(addr)
		if err := result.Decode(&rec); err == nil && rec.ASN != 0 {
			res.ASN = int64(rec.ASN)
			res.HasASN = true
			if rec.AsOrg != "" {
				res.ASOrg = rec.AsOrg
			}
		}
	}

	return res
}

// Resolve returns the cached geo/ASN lookup for ip, reopening the mmdb files
// first if the reopen-check interval has elapsed. The LRU cache is
// concurrency-safe on its own, so the hot (cache-hit) path never takes the
// db mutex at all; only a cache miss takes a brief RLock to read the
// reader handles, and only the periodic reopen check takes the full Lock.
func (r *Resolver) Resolve(ip string) Result {
	now := r.clock()

	r.mu.Lock()
	if !r.lastReopenCheckSet || now.Sub(r.lastReopenCheck) >= ReopenCheckInterval {
		r.reopenIfNeeded()
		r.lastReopenCheck = now
		r.lastReopenCheckSet = true
	}
	r.mu.Unlock()

	if v, ok := r.cache.Get(ip); ok {
		return v
	}

	r.mu.RLock()
	v := r.resolveUncached(ip)
	r.mu.RUnlock()

	r.cache.Add(ip, v)
	return v
}

// SetClock overrides the monotonic clock used for the reopen-check interval;
// for tests.
func (r *Resolver) SetClock(clock func() time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.clock = clock
}
