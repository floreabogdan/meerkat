// Package shipper publishes detections to the public threat map at threats.example.net.
//
// The wire contract is mirrored in the website's src/lib/threats.ts and the two
// must change together. What ships is deliberately narrow:
//
//   - The destination is a SITE NAME and a port, never a customer address. The
//     payload type has no field for one. That page is public, and publishing
//     which hosts inside our ranges are live and being probed would be free
//     reconnaissance.
//   - A source inside our own networks is never published at all. An infected
//     internal host calling out trips a rule with OUR address as the source,
//     and that is the same leak from the other direction.
//   - An alert is "detected". Only an address actually banned in nftables is
//     "blocked". The mapping lives in store.Shippable.Action and nowhere else.
//
// It reads forward from a cursor persisted in the database rather than tapping
// the ingest pipeline in memory, so a restart neither re-publishes history nor
// silently drops what arrived while it was down. The cursor advances only after
// the collector has accepted a batch.
package shipper

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/floreabogdan/meerkat/internal/store"
)

const (
	// maxBatch is the collector's hard cap (MAX_EVENTS_PER_BATCH in its route
	// handler). Exceeding it earns a 413, so stay well under.
	maxBatch = 2000
	// defaultBatch is what one POST carries. These compress ~10x, so this is a
	// few tens of KB on the wire.
	defaultBatch = 500
	// defaultInterval is how often the shipper looks for new events. The map
	// polls every 5s, so anything tighter than this is wasted.
	defaultInterval = 10 * time.Second
)

// Site identifies the router reporting events. It rides along with every batch
// so bringing a new site online needs no change at the collector.
type Site struct {
	Name    string  `json:"name"`
	Country string  `json:"country"`
	Lat     float64 `json:"lat"`
	Lng     float64 `json:"lng"`
}

// Event is one alert in the collector's wire format. The field names are short
// because these ship in the thousands; see the matching TypeScript interface
// IngestEvent in the website's src/lib/threats.ts.
type Event struct {
	TS     string  `json:"ts"`
	Sig    string  `json:"sig"`
	SID    int     `json:"sid"`
	Sev    int     `json:"sev"`
	Proto  string  `json:"proto"`
	DPort  int     `json:"dport"`
	SrcIP  string  `json:"srcIP"`
	SrcCC  string  `json:"srcCC,omitempty"`
	SrcCit string  `json:"srcCity,omitempty"`
	SrcLat float64 `json:"srcLat,omitempty"`
	SrcLng float64 `json:"srcLng,omitempty"`
	SrcASN uint32  `json:"srcASN,omitempty"`
	SrcOrg string  `json:"srcOrg,omitempty"`
	Action string  `json:"action"`
}

type payload struct {
	Site   Site    `json:"site"`
	Events []Event `json:"events"`
}

// Config is what a Shipper needs.
type Config struct {
	Store *store.Store
	Log   *slog.Logger

	// URL is the collector's ingest endpoint; Token is the bearer it expects.
	URL   string
	Token string
	Site  Site

	// HomeNets are our own prefixes. A source inside them is never published.
	HomeNets []netip.Prefix

	// UserAgent identifies this build to the collector.
	UserAgent string

	// Batch and Interval override the defaults; tests use them.
	Batch    int
	Interval time.Duration
}

// Stats is what the shipper will admit to, for the settings page.
type Stats struct {
	Shipped   int64
	Withheld  int64 // suppressed because the source is ours
	Batches   int64
	Failures  int64
	Cursor    int64
	Backlog   int64
	LastOK    time.Time
	LastError string
}

// Shipper publishes batches to the collector.
type Shipper struct {
	cfg    Config
	log    *slog.Logger
	client *http.Client

	mu    sync.RWMutex
	stats Stats
}

// New builds a Shipper. It does not touch the network until Run.
func New(cfg Config) *Shipper {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Batch <= 0 || cfg.Batch > maxBatch {
		cfg.Batch = defaultBatch
	}
	if cfg.Interval <= 0 {
		cfg.Interval = defaultInterval
	}
	return &Shipper{
		cfg:    cfg,
		log:    cfg.Log,
		client: &http.Client{Timeout: 45 * time.Second},
	}
}

// Stats reports a consistent snapshot.
func (s *Shipper) Stats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.stats
}

// Run ships until ctx is done.
func (s *Shipper) Run(ctx context.Context) {
	tick := time.NewTicker(s.cfg.Interval)
	defer tick.Stop()

	s.log.Info("threat map shipping enabled", "url", s.cfg.URL, "site", s.cfg.Site.Name,
		"home_nets", len(s.cfg.HomeNets))

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			// Keep draining while full batches keep coming, so a backlog after
			// an outage clears instead of trickling one batch per tick.
			for range 20 {
				n, err := s.shipOnce(ctx)
				if err != nil || n < s.cfg.Batch {
					break
				}
			}
		}
	}
}

// shipOnce reads one batch forward from the cursor, publishes it, and advances
// the cursor. It returns how many rows were read (not how many were published —
// a batch entirely of our own addresses still moves the cursor).
func (s *Shipper) shipOnce(ctx context.Context) (int, error) {
	settings, ok, err := s.cfg.Store.GetSettings()
	if err != nil || !ok {
		return 0, err
	}
	cursor := settings.ThreatsCursor

	rows, err := s.cfg.Store.ShippableAfter(cursor, s.cfg.Batch)
	if err != nil {
		s.fail("read: " + err.Error())
		return 0, err
	}
	if len(rows) == 0 {
		s.setBacklog(0)
		return 0, nil
	}

	// The highest id read is the cursor's next value whether or not every row
	// survived filtering — otherwise a run of suppressed events would be
	// re-read forever.
	highest := rows[len(rows)-1].ID

	events := make([]Event, 0, len(rows))
	var withheld int64
	for _, r := range rows {
		if s.isOurs(r.SrcIP) {
			withheld++
			continue
		}
		events = append(events, Event{
			TS:     r.Ts.UTC().Format(time.RFC3339Nano),
			Sig:    r.Sig,
			SID:    r.SID,
			Sev:    r.Severity,
			Proto:  r.Proto,
			DPort:  r.DestPort,
			SrcIP:  r.SrcIP,
			SrcCC:  r.SrcCC,
			SrcCit: r.SrcCity,
			SrcLat: r.SrcLat,
			SrcLng: r.SrcLon,
			SrcASN: r.SrcASN,
			SrcOrg: r.SrcOrg,
			Action: r.Action(),
		})
	}

	if len(events) > 0 {
		if err := s.post(ctx, events); err != nil {
			// The cursor stays put, so this batch is retried on the next tick.
			s.fail(err.Error())
			s.log.Error("threat batch failed", "count", len(events), "err", err)
			return len(rows), err
		}
	}

	if err := s.cfg.Store.SetThreatsCursor(highest); err != nil {
		// Published but not recorded. Say so loudly: the next pass will
		// re-publish this batch, and the collector deduplicates rather than
		// this being silently wrong.
		s.log.Error("shipped a batch but could not advance the cursor; it will be re-sent",
			"cursor", highest, "err", err)
		s.fail("cursor: " + err.Error())
		return len(rows), err
	}

	s.succeed(int64(len(events)), withheld, highest)
	s.log.Debug("shipped threat batch", "events", len(events), "withheld", withheld, "cursor", highest)
	return len(rows), nil
}

// isOurs reports whether a source address falls inside our own networks.
func (s *Shipper) isOurs(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		// An unparseable address cannot be checked against our ranges, so it
		// cannot be shown to be safe to publish. Withhold it.
		return true
	}
	addr = addr.Unmap()
	for _, p := range s.cfg.HomeNets {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func (s *Shipper) post(ctx context.Context, events []Event) error {
	body, err := json.Marshal(payload{Site: s.cfg.Site, Events: events})
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	// These batches are highly repetitive (same signatures, same ASNs) and
	// compress by roughly 10x, which matters on a metered uplink. The collector
	// gunzips transparently when Content-Encoding says so.
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := zw.Write(body); err != nil {
		return fmt.Errorf("gzip: %w", err)
	}
	if err := zw.Close(); err != nil {
		return fmt.Errorf("gzip close: %w", err)
	}
	compressed := gz.Bytes()

	const maxAttempts = 4
	backoff := 2 * time.Second

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.URL, bytes.NewReader(compressed))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Content-Encoding", "gzip")
		req.Header.Set("Authorization", "Bearer "+s.cfg.Token)
		req.Header.Set("User-Agent", s.cfg.UserAgent)

		resp, err := s.client.Do(req)
		if err == nil {
			respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
			resp.Body.Close()

			switch {
			case resp.StatusCode >= 200 && resp.StatusCode < 300:
				return nil
			case resp.StatusCode == http.StatusUnauthorized,
				resp.StatusCode == http.StatusBadRequest,
				resp.StatusCode == http.StatusRequestEntityTooLarge:
				// A bad token or a malformed batch will not fix itself by
				// being sent again.
				return fmt.Errorf("collector rejected the batch (%d): %s",
					resp.StatusCode, truncate(string(respBody), 200))
			default:
				err = fmt.Errorf("collector returned %d: %s",
					resp.StatusCode, truncate(string(respBody), 200))
			}
		}

		if attempt == maxAttempts {
			return err
		}
		if !sleepCtx(ctx, backoff) {
			return ctx.Err()
		}
		backoff *= 2
	}
	return nil
}

// Test publishes a single synthetic detection so the settings page can report
// whether the endpoint, token and site are actually right. It uses a plainly
// documentation-range address (RFC 5737) so a test never puts a real host on
// the public map.
func (s *Shipper) Test(ctx context.Context) error {
	return s.post(ctx, []Event{{
		TS:     time.Now().UTC().Format(time.RFC3339Nano),
		Sig:    "meerkat connectivity test",
		SID:    0,
		Sev:    3,
		Proto:  "TCP",
		DPort:  0,
		SrcIP:  "192.0.2.1",
		SrcCC:  "",
		Action: "detected",
	}})
}

func (s *Shipper) succeed(shipped, withheld, cursor int64) {
	s.mu.Lock()
	s.stats.Shipped += shipped
	s.stats.Withheld += withheld
	s.stats.Batches++
	s.stats.Cursor = cursor
	s.stats.LastOK = time.Now()
	s.stats.LastError = ""
	s.mu.Unlock()
}

func (s *Shipper) fail(msg string) {
	s.mu.Lock()
	s.stats.Failures++
	s.stats.LastError = msg
	s.mu.Unlock()
}

func (s *Shipper) setBacklog(n int64) {
	s.mu.Lock()
	s.stats.Backlog = n
	s.mu.Unlock()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// DefaultHomeNets is what meerkat withholds from the public map when nobody has
// said otherwise: the private and carrier-internal ranges, which are never
// anybody's public detection anyway.
//
// It deliberately contains no public space. **Your own public prefixes are yours
// to add** under Settings → Threat map before you enable publishing — meerkat
// cannot guess them, and a default that shipped one operator's ranges would be
// worse than useless to everyone else.
const DefaultHomeNets = `10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
100.64.0.0/10
169.254.0.0/16
fc00::/7
fe80::/10`

// ParseHomeNets reads the configured prefixes, falling back to the defaults
// when nothing is set — failing open here would publish customer addresses.
func ParseHomeNets(text string) ([]netip.Prefix, []string) {
	if strings.TrimSpace(text) == "" {
		text = DefaultHomeNets
	}
	return store.ParsePrefixList(text)
}
