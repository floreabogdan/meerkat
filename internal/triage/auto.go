package triage

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/floreabogdan/meerkat/internal/store"
)

// auto.go implements "this rule should always block its source".
//
// The important thing about it is what it is NOT. suricata-update can rewrite a
// rule's action to `drop`, and that would be the obvious implementation — one
// line in a config file. meerkat does not do it, and no code path here can be
// made to. Suricata runs inline on NFQUEUE on these routers, and left to drop
// it once ate 258,101 of 2,676,291 packets — 9.6% of transit traffic — from an
// exception policy, not from any rule. Blocking is nftables' job.
//
// So "always block" means: when this rule fires, meerkat pushes the source to
// nftably, exactly as if an operator had clicked the button. It goes through
// the same Block call, hits the same refusals, and lands in the same ledger
// with `auto` as the actor. A standing instruction to change the firewall
// deserves a record indistinguishable from a person doing it by hand.

const (
	// autoQueueDepth absorbs a burst. A flood is thousands of alerts from a
	// handful of addresses, and the dedup below collapses those long before
	// they reach here, so this is generous.
	autoQueueDepth = 256

	// cooldown is how long a source is left alone after being considered. The
	// same rule firing 500 times in one batch is one decision, not 500.
	cooldown = 15 * time.Minute

	// policyRefresh is how often the auto-block rules are re-read. Turning a
	// rule on should take effect promptly; re-reading per alert would put a
	// query in the hot path.
	policyRefresh = 30 * time.Second
)

// Auto blocks sources on sight for the rules configured to do so.
type Auto struct {
	mgr   *Manager
	store *store.Store
	log   *slog.Logger
	queue chan candidate

	mu        sync.Mutex
	enabled   bool
	hourlyCap int
	reactions store.RuleReactions
	loadedAt  time.Time
	recent    map[string]time.Time
	window    []time.Time

	considered atomic.Uint64
	blocked    atomic.Uint64
	dropped    atomic.Uint64
	limited    atomic.Uint64
}

type candidate struct {
	ip     string
	sid    int
	sig    string
	policy store.RulePolicy
}

// NewAuto builds the auto-blocker. It does nothing until Run.
func NewAuto(m *Manager, st *store.Store, log *slog.Logger) *Auto {
	if log == nil {
		log = slog.Default()
	}
	return &Auto{
		mgr:    m,
		store:  st,
		log:    log,
		queue:  make(chan candidate, autoQueueDepth),
		recent: map[string]time.Time{},
	}
}

// AutoStats is what the console reports about the feature.
type AutoStats struct {
	Considered  uint64
	Blocked     uint64
	Dropped     uint64
	RateLimited uint64
}

func (a *Auto) Stats() AutoStats {
	return AutoStats{
		Considered:  a.considered.Load(),
		Blocked:     a.blocked.Load(),
		Dropped:     a.dropped.Load(),
		RateLimited: a.limited.Load(),
	}
}

// SeverityFor returns the operator's severity override for a signature, or 0
// for none. Called on the ingest hot path, so it is a map lookup behind a
// mutex and nothing else.
func (a *Auto) SeverityFor(sid int) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.reactions.Severity[sid]
}

// Consider hands a written batch of alerts to the auto-blocker.
//
// It never blocks the caller. Ingest applies backpressure for alert storage —
// eve.json is the buffer and losing an alert is not acceptable — but an
// auto-block is not storage, and stalling the reader on an HTTP call to nftably
// would turn a firewall hiccup into an ingest outage. A full queue is counted
// and reported rather than waited on.
func (a *Auto) Consider(alerts []store.Alert) {
	a.mu.Lock()
	enabled := a.enabled
	reactions := a.reactions.AutoBlock
	a.mu.Unlock()
	if !enabled || len(reactions) == 0 {
		return
	}

	for _, alert := range alerts {
		p, ok := reactions[alert.SID]
		if !ok {
			continue
		}
		// A private, loopback or CGNAT source is one of ours. Block refuses
		// these too, but catching it here keeps the ledger free of a refusal
		// per alert for a rule that fires on internal traffic.
		if alert.IsLocal || alert.SrcIP == "" {
			continue
		}
		if !a.claim(alert.SrcIP) {
			continue
		}
		a.considered.Add(1)
		select {
		case a.queue <- candidate{ip: alert.SrcIP, sid: alert.SID, sig: alert.Sig, policy: p}:
		default:
			a.dropped.Add(1)
			a.log.Warn("auto-block queue is full; a source was not blocked", "ip", alert.SrcIP, "sid", alert.SID)
		}
	}
}

// claim reports whether this source is due for consideration, and marks it.
func (a *Auto) claim(ip string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	if last, ok := a.recent[ip]; ok && now.Sub(last) < cooldown {
		return false
	}
	a.recent[ip] = now
	return true
}

// Run processes candidates until ctx is done.
func (a *Auto) Run(ctx context.Context) {
	a.refresh()
	refresh := time.NewTicker(policyRefresh)
	defer refresh.Stop()
	tidy := time.NewTicker(cooldown)
	defer tidy.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-refresh.C:
			a.refresh()
		case <-tidy.C:
			a.forget()
		case c := <-a.queue:
			a.handle(ctx, c)
		}
	}
}

func (a *Auto) handle(ctx context.Context, c candidate) {
	if !a.allow() {
		a.limited.Add(1)
		a.log.Warn("auto-block rate limit reached; not blocking", "ip", c.ip, "sid", c.sid)
		_ = a.store.InsertSystemAudit(store.AuditSourceChange,
			"auto-block rate limit reached — "+c.ip+" was not blocked; raise the limit under Settings → Suricata or review the rules set to block on sight")
		return
	}

	// Re-read the source: a great deal can have happened between the alert
	// being written and this running, and blocking something an operator has
	// just allowlisted would be exactly the wrong move.
	src, err := a.store.GetSource(c.ip)
	if err != nil {
		return
	}
	switch src.State {
	case store.StateBlocked, store.StateAllowlisted:
		return
	}

	ttl := time.Duration(c.policy.AutoBlockTTL) * time.Second
	reason := autoReason(c)
	if _, err := a.mgr.Block(ctx, c.ip, reason, ttl, "auto"); err != nil {
		// Block has already written the failure to the ledger. Nothing here
		// retries: a rule set to block on sight will fire again, and a retry
		// loop against a broken nftably would fill the ledger with the same
		// failure.
		a.log.Warn("auto-block failed", "ip", c.ip, "sid", c.sid, "err", err)
		return
	}
	a.blocked.Add(1)
	a.log.Info("auto-blocked a source", "ip", c.ip, "sid", c.sid, "rule", c.sig)
}

func autoReason(c candidate) string {
	reason := "rule " + itoa(c.sid)
	if c.sig != "" {
		reason += " (" + c.sig + ")"
	}
	reason += " is set to block on sight"
	if c.policy.Note != "" {
		reason += " — " + c.policy.Note
	}
	return reason
}

// allow implements the hourly rate limit.
//
// It is the safety net on a feature whose whole point is acting without a
// person. One badly chosen rule — a reputation feed with a false positive, a
// signature that matches an upstream resolver — could otherwise blackhole a
// large part of the internet before anyone noticed.
func (a *Auto) allow() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.hourlyCap <= 0 {
		return false
	}
	cutoff := time.Now().Add(-time.Hour)
	kept := a.window[:0]
	for _, t := range a.window {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	a.window = kept
	if len(a.window) >= a.hourlyCap {
		return false
	}
	a.window = append(a.window, time.Now())
	return true
}

// refresh re-reads the settings and the per-rule policy.
func (a *Auto) refresh() {
	settings, ok, err := a.store.GetSettings()
	if err != nil || !ok {
		return
	}
	reactions, err := a.store.Reactions()
	if err != nil {
		a.log.Warn("could not read the rule reactions", "err", err)
		return
	}
	a.mu.Lock()
	a.enabled = settings.AutoBlockEnabled
	a.hourlyCap = settings.AutoBlockMaxHour
	a.reactions = reactions
	a.loadedAt = time.Now()
	a.mu.Unlock()
}

// forget drops cooldown entries that have expired, so the map does not grow
// with every address ever seen.
func (a *Auto) forget() {
	a.mu.Lock()
	defer a.mu.Unlock()
	cutoff := time.Now().Add(-cooldown)
	for ip, t := range a.recent {
		if t.Before(cutoff) {
			delete(a.recent, ip)
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
