// Package ntppool polls ntppool.org's score JSON and exports score/offset/
// rtt values. Port of parse_ntppool / parse_ntppool_overall_score /
// NtpPoolCollector from exporter.py.
package ntppool

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

const (
	UserAgent          = "ntp-server-exporter/1.0 (+github.com/metril/ntp-server)"
	URLTemplate        = "https://www.ntppool.org/scores/%s/json?limit=10&monitor=*"
	OverallURLTemplate = "https://www.ntppool.org/scores/%s/json?limit=1"
)

// Monitor is one monitor's latest score/offset/rtt.
type Monitor struct {
	Score         *float64
	OffsetSeconds *float64
	RTTSeconds    *float64
}

// Parsed is the result of Parse(): the newest overall history score (only
// meaningful within the monitor=* response; NOT the pool's overall score)
// plus the latest per-monitor entries.
type Parsed struct {
	Score    *float64
	Monitors map[string]Monitor
}

type monitorMeta struct {
	ID   *int64  `json:"id"`
	Name *string `json:"name"`
}

// flexTS accepts history[].ts as either an epoch number (what ntppool.org
// actually sends) or an ISO-8601 string (older/other renderings). Numeric
// values compare numerically; strings compare lexically; a number always
// sorts after a string so mixed payloads still pick a deterministic newest.
type flexTS struct {
	num   float64
	str   string
	isNum bool
	set   bool
}

func (t *flexTS) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		return nil
	}
	if b[0] == '"' {
		if err := json.Unmarshal(b, &t.str); err != nil {
			return err
		}
		t.set = true
		return nil
	}
	if err := json.Unmarshal(b, &t.num); err != nil {
		return err
	}
	t.isNum, t.set = true, true
	return nil
}

// less reports whether t sorts before o.
func (t flexTS) less(o flexTS) bool {
	switch {
	case !t.set:
		return o.set
	case !o.set:
		return false
	case t.isNum && o.isNum:
		return t.num < o.num
	case t.isNum != o.isNum:
		return !t.isNum
	default:
		return t.str < o.str
	}
}

type historyEntry struct {
	TS        flexTS   `json:"ts"`
	Score     *float64 `json:"score"`
	Offset    *float64 `json:"offset"`
	RTT       *float64 `json:"rtt"`
	MonitorID *int64   `json:"monitor_id"`
}

type scoreResponse struct {
	Monitors []monitorMeta  `json:"monitors"`
	History  []historyEntry `json:"history"`
}

// newer reports whether a's timestamp is strictly after b's.
func newer(a, b historyEntry) bool {
	return b.TS.less(a.TS)
}

// Parse parses the per-monitor (monitor=*) ntppool.org score JSON body.
func Parse(data []byte) (Parsed, error) {
	var resp scoreResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return Parsed{}, err
	}

	monitorsByID := map[int64]string{}
	for _, m := range resp.Monitors {
		if m.ID == nil {
			continue
		}
		name := fmt.Sprintf("%d", *m.ID)
		if m.Name != nil && *m.Name != "" {
			name = *m.Name
		}
		monitorsByID[*m.ID] = name
	}

	result := Parsed{Monitors: map[string]Monitor{}}

	if len(resp.History) > 0 {
		newest := resp.History[0]
		for _, h := range resp.History[1:] {
			if newer(h, newest) {
				newest = h
			}
		}
		result.Score = newest.Score
	}

	latestByMonitor := map[int64]historyEntry{}
	for _, h := range resp.History {
		if h.MonitorID == nil {
			continue
		}
		mid := *h.MonitorID
		cur, ok := latestByMonitor[mid]
		if !ok || newer(h, cur) {
			latestByMonitor[mid] = h
		}
	}

	for mid, h := range latestByMonitor {
		name, ok := monitorsByID[mid]
		if !ok {
			name = fmt.Sprintf("%d", mid)
		}
		var rtt *float64
		if h.RTT != nil {
			v := *h.RTT / 1000.0
			rtt = &v
		}
		result.Monitors[name] = Monitor{
			Score:         h.Score,
			OffsetSeconds: h.Offset,
			RTTSeconds:    rtt,
		}
	}

	return result, nil
}

// ParseOverallScore parses the *overall* ntppool.org score JSON body
// (fetched without monitor=*, limit=1) into the pool's overall score, or
// nil if there's no history.
func ParseOverallScore(data []byte) (*float64, error) {
	var resp scoreResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	if len(resp.History) == 0 {
		return nil, nil
	}
	newest := resp.History[0]
	for _, h := range resp.History[1:] {
		if newer(h, newest) {
			newest = h
		}
	}
	return newest.Score, nil
}

// Setters is the set of gauge-setting callbacks Poller uses to publish
// results, so this package doesn't need to import the metrics package.
type Setters struct {
	Score         func(ip string, v float64)
	MonitorScore  func(ip, monitor string, v float64)
	MonitorOffset func(ip, monitor string, v float64)
	MonitorRTT    func(ip, monitor string, v float64)
	ScrapeSuccess func(v float64)
}

// Poller polls ntppool.org for one IPv4 address on an interval.
type Poller struct {
	IPv4    string
	Client  *http.Client
	Setters Setters
}

func NewPoller(ipv4 string, setters Setters) *Poller {
	return &Poller{
		IPv4:    ipv4,
		Client:  &http.Client{Timeout: 10 * time.Second},
		Setters: setters,
	}
}

func (p *Poller) getJSON(url string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", UserAgent)
	resp, err := p.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("ntppool.org returned status %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// PollOnce performs one poll cycle, mirroring NtpPoolCollector.poll_once.
func (p *Poller) PollOnce() {
	if p.IPv4 == "" {
		return
	}
	monitorURL := fmt.Sprintf(URLTemplate, p.IPv4)
	overallURL := fmt.Sprintf(OverallURLTemplate, p.IPv4)

	data, err := p.getJSON(monitorURL)
	if err != nil {
		log.Printf("ntppool.org poll failed: %v", err)
		p.Setters.ScrapeSuccess(0)
		return
	}
	overallData, err := p.getJSON(overallURL)
	if err != nil {
		log.Printf("ntppool.org poll failed: %v", err)
		p.Setters.ScrapeSuccess(0)
		return
	}

	parsed, err := Parse(data)
	if err != nil {
		log.Printf("ntppool.org poll failed: %v", err)
		p.Setters.ScrapeSuccess(0)
		return
	}
	overallScore, err := ParseOverallScore(overallData)
	if err != nil {
		log.Printf("ntppool.org poll failed: %v", err)
		p.Setters.ScrapeSuccess(0)
		return
	}

	if overallScore != nil {
		p.Setters.Score(p.IPv4, *overallScore)
	}
	for monitor, vals := range parsed.Monitors {
		if vals.Score != nil {
			p.Setters.MonitorScore(p.IPv4, monitor, *vals.Score)
		}
		if vals.OffsetSeconds != nil {
			p.Setters.MonitorOffset(p.IPv4, monitor, *vals.OffsetSeconds)
		}
		if vals.RTTSeconds != nil {
			p.Setters.MonitorRTT(p.IPv4, monitor, *vals.RTTSeconds)
		}
	}
	p.Setters.ScrapeSuccess(1)
}

// RunForever polls on the given interval, forever.
func (p *Poller) RunForever(interval time.Duration) {
	for {
		p.PollOnce()
		time.Sleep(interval)
	}
}
