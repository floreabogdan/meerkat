// Package ingest is meerkat's reader: it follows Suricata's eve.json, keeps the
// alerts, enriches them, and writes them into the store in batches.
//
// Three things about the shape here are deliberate.
//
// It rejects a line before decoding it. On a busy router 98.5% of eve.json is
// flow and stats records, and JSON-decoding a 40 KB stats blob only to discard
// it would dominate the whole program's cost.
//
// It writes in batches. The reference sensor produced 891 alerts in 4 minutes and can burst far
// harder; a transaction per alert would mean an fsync per alert.
//
// It applies backpressure rather than dropping. When the writer falls behind,
// the tailer stops reading — the data is still on disk in eve.json, so pausing
// costs nothing, whereas dropping would lose alerts silently. That matters:
// a console that quietly discards under load is worse than no console.
package ingest

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/floreabogdan/meerkat/internal/eve"
	"github.com/floreabogdan/meerkat/internal/geo"
	"github.com/floreabogdan/meerkat/internal/store"
	"github.com/floreabogdan/meerkat/internal/suricata"
)

const (
	// defaultBatchSize is how many alerts one transaction carries at most.
	defaultBatchSize = 500
	// defaultBatchWait bounds how long an alert waits to be written when the
	// stream is slow — the live view should feel live.
	defaultBatchWait = time.Second
	// queueDepth absorbs a burst without making the tailer wait on SQLite.
	queueDepth = 4096
	// retentionInterval is how often the pruner runs. Retention is measured in
	// days, so anything under a few hours is pure churn.
	retentionInterval = 6 * time.Hour
)

// Reactor is the operator's standing policy over signatures, consulted as
// alerts arrive. internal/triage implements it; ingest deliberately knows
// nothing about how a block is made or what a rule policy looks like.
type Reactor interface {
	// SeverityFor returns an override for a signature's severity, or 0 for
	// none. Called for every alert, so it must be cheap.
	SeverityFor(sid int) int
	// Consider is handed each batch after it has been written. It must not
	// block: alert storage applies backpressure, and reacting to alerts must
	// never be able to stall reading them.
	Consider(alerts []store.Alert)
}

// Config is what an Ingester needs.
type Config struct {
	Store *store.Store
	Geo   *geo.Enricher
	Log   *slog.Logger

	// Reactions applies per-signature severity overrides and blocks sources for
	// rules set to block on sight. Nil disables both.
	Reactions Reactor

	// EvePath is the file to follow; StatePath persists the read offset so a
	// restart neither replays nor skips. FromStart replays existing content.
	EvePath   string
	StatePath string
	FromStart bool

	// Retention prunes events older than this; MaxEvents is the flood backstop.
	// Zero on either disables that half.
	Retention time.Duration
	MaxEvents int64

	// BatchSize and BatchWait override the defaults; tests use them.
	BatchSize int
	BatchWait time.Duration
}

// Stats is what the ingester will admit to, for the status dot and the doctor.
type Stats struct {
	LinesRead   uint64
	Alerts      uint64
	Written     uint64
	ParseErrors uint64
	Batches     uint64
	// LastLineAt is when a line — any line, including the flow records — last
	// arrived. Silence from a sensor is indistinguishable from peace and quiet
	// unless something is watching the clock.
	LastLineAt  time.Time
	LastAlertAt time.Time
	LastWriteAt time.Time
	LastError   string
}

// Ingester follows one eve.json into one store.
type Ingester struct {
	cfg   Config
	log   *slog.Logger
	queue chan store.Alert

	linesRead   atomic.Uint64
	alerts      atomic.Uint64
	written     atomic.Uint64
	parseErrors atomic.Uint64
	batches     atomic.Uint64

	mu          sync.RWMutex
	lastLineAt  time.Time
	lastAlertAt time.Time
	lastWriteAt time.Time
	lastError   string
}

// New builds an Ingester. It does not touch the filesystem until Run.
func New(cfg Config) *Ingester {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = defaultBatchSize
	}
	if cfg.BatchWait <= 0 {
		cfg.BatchWait = defaultBatchWait
	}
	return &Ingester{cfg: cfg, log: cfg.Log, queue: make(chan store.Alert, queueDepth)}
}

// Stats reports a consistent snapshot.
func (in *Ingester) Stats() Stats {
	in.mu.RLock()
	defer in.mu.RUnlock()
	return Stats{
		LinesRead:   in.linesRead.Load(),
		Alerts:      in.alerts.Load(),
		Written:     in.written.Load(),
		ParseErrors: in.parseErrors.Load(),
		Batches:     in.batches.Load(),
		LastLineAt:  in.lastLineAt,
		LastAlertAt: in.lastAlertAt,
		LastWriteAt: in.lastWriteAt,
		LastError:   in.lastError,
	}
}

// Run follows eve.json until ctx is done, then drains what it has already read
// before returning. Blocks; callers run it in a goroutine.
func (in *Ingester) Run(ctx context.Context) error {
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		in.writeLoop()
	}()

	if in.cfg.Retention > 0 || in.cfg.MaxEvents > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			in.retentionLoop(ctx)
		}()
	}

	tailer := eve.NewTailer(in.cfg.EvePath, in.cfg.StatePath, in.cfg.FromStart, in.log)
	err := tailer.Run(ctx, in.handleLine)

	// The tailer has stopped, so no more alerts can be queued. Closing here is
	// what lets the writer flush its partial batch and exit rather than dropping
	// whatever was in flight at shutdown.
	close(in.queue)
	wg.Wait()
	return err
}

// handleLine is the hot path: it runs for every line in eve.json, the vast
// majority of which are flow records to be rejected as cheaply as possible.
func (in *Ingester) handleLine(line []byte) {
	in.linesRead.Add(1)
	in.stamp(&in.lastLineAt)

	// meerkat stores alerts only. The other event types are Suricata telling us
	// about traffic, not about a rule firing, and rolling them into per-source
	// state would drown the thing the rollup exists to surface.
	if eve.TypeOf(line) != "alert" {
		return
	}

	ev, err := eve.Parse(line)
	if err != nil {
		in.parseErrors.Add(1)
		in.setError("unparseable eve.json line: " + err.Error())
		in.log.Debug("skipping unparseable line", "err", err)
		return
	}
	in.alerts.Add(1)
	in.stamp(&in.lastAlertAt)

	// Backpressure, not loss: if the writer is behind, this send blocks and the
	// tailer stops reading. eve.json is the buffer, so pausing costs nothing.
	//
	// A plain blocking send is safe (it cannot deadlock): the writer runs until
	// the queue closes, and the queue is only closed after the tailer's Run has
	// returned — which cannot happen while this call is still in flight. Giving
	// up on ctx.Done() here would instead discard an alert already read from
	// disk and already counted in the saved offset, losing it across a restart.
	in.queue <- in.enrich(ev)
}

// enrich turns a decoded eve record into the row the store writes.
func (in *Ingester) enrich(ev *eve.Event) store.Alert {
	a := store.Alert{
		Ts:       ev.Time(),
		SrcIP:    ev.SrcIP,
		SrcPort:  ev.SrcPort,
		DestIP:   ev.DestIP,
		DestPort: ev.DestPort,
		Proto:    ev.Proto,
		AppProto: ev.AppProto,
		Iface:    ev.InIface,
		SID:      ev.Alert.SignatureID,
		GID:      ev.Alert.GID,
		Rev:      ev.Alert.Rev,
		Sig:      ev.Alert.Signature,
		Category: ev.Alert.Category,
		// The message-prefix category ("ET CINS"). Suricata's own category
		// field above is the classtype description ("Misc Attack"), which
		// cannot tell a reputation-list hit from a real intrusion — they are
		// both "Misc Attack". Rule management needs the other axis.
		RuleCategory: suricata.CategoryOf(ev.Alert.Signature),
		Severity:     ev.Alert.Severity,
		Action:       ev.Alert.Action,
		FlowID:       ev.FlowID,
		Extra:        protocolContext(ev),
	}
	if in.cfg.Geo != nil {
		applyGeo(&a, in.cfg.Geo.Lookup(ev.SrcIP))
	}
	// A severity override applies from here on, not retroactively. The stored
	// severity is what meerkat thought at the time, and the source rollups —
	// worst severity, and the sort order the console leads with — are built
	// from it as the alerts arrive.
	if in.cfg.Reactions != nil && a.SID != 0 {
		if sev := in.cfg.Reactions.SeverityFor(a.SID); sev > 0 {
			a.Severity = sev
		}
	}
	return a
}

// applyGeo copies an enrichment onto an alert.
//
// It is a separate function purely so it can be tested exhaustively. It was
// once four lines inline in enrich, and the coordinates were silently missing
// from them: every source got a city and no position, so the threat map had
// nothing to plot and nothing anywhere reported an error. A missed field here
// cannot fail loudly — it just yields a zero — so the test enumerates them.
func applyGeo(a *store.Alert, g geo.Geo) {
	a.ASN, a.ASOrg = g.ASN, g.ASOrg
	a.Country, a.CountryName = g.Country, g.CountryName
	a.Continent, a.City = g.Continent, g.City
	a.Lat, a.Lon = g.Lat, g.Lon
	a.IsLocal = g.Private
}

// extra is the protocol context worth keeping per event: the fields that differ
// between two alerts on the same rule from the same host and actually help
// triage. Everything else the record carries is already a column.
type extra struct {
	HTTPHost  string `json:"http_host,omitempty"`
	HTTPURL   string `json:"http_url,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
	Method    string `json:"http_method,omitempty"`
	Status    int    `json:"http_status,omitempty"`
	TLSSNI    string `json:"tls_sni,omitempty"`
	DNSName   string `json:"dns_rrname,omitempty"`
	SSHClient string `json:"ssh_client,omitempty"`
}

func protocolContext(ev *eve.Event) string {
	var x extra
	if ev.HTTP != nil {
		x.HTTPHost, x.HTTPURL = ev.HTTP.Hostname, ev.HTTP.URL
		x.UserAgent, x.Method, x.Status = ev.HTTP.UserAgent, ev.HTTP.Method, ev.HTTP.Status
	}
	if ev.TLS != nil {
		x.TLSSNI = ev.TLS.SNI
	}
	if ev.DNS != nil {
		x.DNSName = ev.DNS.RRName
	}
	if ev.SSH != nil {
		x.SSHClient = ev.SSH.Client.SoftwareVersion
	}
	if x == (extra{}) {
		return "" // the common case: nothing but the alert itself
	}
	b, err := json.Marshal(x)
	if err != nil {
		return ""
	}
	return string(b)
}

// writeLoop batches queued alerts into transactions. It deliberately watches
// the queue rather than ctx: closing the queue is the shutdown signal, and
// draining it to the end is what guarantees an alert already read from eve.json
// is never lost to a restart.
func (in *Ingester) writeLoop() {
	batch := make([]store.Alert, 0, in.cfg.BatchSize)
	timer := time.NewTimer(in.cfg.BatchWait)
	defer timer.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := in.cfg.Store.RecordAlerts(batch); err != nil {
			// Deliberately not retried. A write failure here is a broken disk or
			// a broken database, not a transient; retrying in a loop would spin
			// and bury the cause. Say so loudly and keep reading, so the console
			// reports the outage rather than dying silently.
			in.log.Error("failed to write alerts", "count", len(batch), "err", err)
			in.setError("could not write alerts: " + err.Error())
		} else {
			in.written.Add(uint64(len(batch)))
			in.batches.Add(1)
			in.stamp(&in.lastWriteAt)
			// Only after the write: an auto-block re-reads the source row to
			// check nobody has just allowlisted it, and that row does not exist
			// until the batch lands.
			if in.cfg.Reactions != nil {
				in.cfg.Reactions.Consider(batch)
			}
		}
		batch = batch[:0]
	}

	for {
		select {
		case a, ok := <-in.queue:
			if !ok {
				flush() // shutdown: whatever was read gets written
				return
			}
			batch = append(batch, a)
			if len(batch) >= in.cfg.BatchSize {
				flush()
				resetTimer(timer, in.cfg.BatchWait)
			}
		case <-timer.C:
			flush()
			resetTimer(timer, in.cfg.BatchWait)
		}
	}
}

// retentionLoop prunes on a slow cadence, starting shortly after boot so a
// restart of a long-stopped service tidies up without delaying startup.
func (in *Ingester) retentionLoop(ctx context.Context) {
	first := time.NewTimer(time.Minute)
	defer first.Stop()
	select {
	case <-ctx.Done():
		return
	case <-first.C:
		in.prune()
	}

	tick := time.NewTicker(retentionInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			in.prune()
		}
	}
}

func (in *Ingester) prune() {
	cutoff := time.Now().UTC()
	if in.cfg.Retention > 0 {
		cutoff = cutoff.Add(-in.cfg.Retention)
	} else {
		cutoff = time.Time{} // age-based pruning off; the cap still applies
	}
	res, err := in.cfg.Store.Prune(cutoff, in.cfg.MaxEvents)
	if err != nil {
		in.log.Error("retention pass failed", "err", err)
		in.setError("retention: " + err.Error())
		return
	}
	if res.Events == 0 && res.Sources == 0 && res.OverCap == 0 {
		return
	}
	in.log.Info("retention", "events", res.Events, "over_cap", res.OverCap, "sources", res.Sources)
	_ = in.cfg.Store.InsertSystemAudit(store.AuditRetention, retentionMessage(res))
}

func retentionMessage(r store.PruneResult) string {
	msg := "pruned " + plural(r.Events, "event")
	if r.OverCap > 0 {
		msg += " (" + plural(r.OverCap, "event") + " over the cap)"
	}
	if r.Sources > 0 {
		msg += " and " + plural(r.Sources, "untriaged source")
	}
	return msg
}

func plural(n int64, noun string) string {
	s := noun
	if n != 1 {
		s += "s"
	}
	return itoa(n) + " " + s
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func (in *Ingester) stamp(field *time.Time) {
	now := time.Now()
	in.mu.Lock()
	*field = now
	in.mu.Unlock()
}

func (in *Ingester) setError(msg string) {
	in.mu.Lock()
	in.lastError = msg
	in.mu.Unlock()
}

func resetTimer(t *time.Timer, d time.Duration) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
	t.Reset(d)
}
