// Package triage turns a decision about a source into an action on the network
// and a record of it.
//
// The rule the whole package exists to enforce: a source is only ever marked
// blocked after nftably has confirmed the address is on its blacklist. A failed
// call leaves the source in whatever state it was really in, and the failure is
// written to the ledger rather than swallowed. "detected" and "blocked" mean
// exactly what they say, so the console can never claim credit for a block that
// did not happen.
//
// It also reconciles, which is the other half of that promise. A block recorded
// an hour ago is a memory; the firewall is the fact. Reconcile compares what
// meerkat claims against what nftably actually holds and corrects meerkat —
// never the other way round — so the console cannot drift into lying because
// somebody edited the blacklist by hand.
package triage

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/floreabogdan/meerkat/internal/nftably"
	"github.com/floreabogdan/meerkat/internal/store"
)

// reconcileInterval is how often the claimed and actual block sets are
// compared. Blocking is infrequent and out-of-band edits rarer still, so this
// is about eventual honesty, not latency.
const reconcileInterval = 2 * time.Minute

// Manager performs triage actions and keeps the block state honest.
type Manager struct {
	store *store.Store
	nft   *nftably.Client
	log   *slog.Logger
}

func New(st *store.Store, nft *nftably.Client, log *slog.Logger) *Manager {
	if log == nil {
		log = slog.Default()
	}
	return &Manager{store: st, nft: nft, log: log}
}

// CanBlock reports whether blocking is wired up at all, so the UI can explain
// itself instead of offering a button that always fails.
func (m *Manager) CanBlock() bool { return m.nft.Configured() }

// Outcome is what happened, in words fit to show an operator.
type Outcome struct {
	Message string
	// Live is true when traffic is being dropped right now, as opposed to the
	// change being queued for nftably's next apply.
	Live bool
}

// Block asks nftably to ban an address, then records it. ttl of zero means
// indefinite.
//
// Order matters and is the point: nftably first, meerkat's state second. If the
// call fails, nothing here claims the address is blocked.
func (m *Manager) Block(ctx context.Context, ip, reason string, ttl time.Duration, actor string) (Outcome, error) {
	// Checked before anything else: "blocking is not set up" is the more useful
	// answer than "no such source", and it is true regardless of the target.
	if !m.nft.Configured() {
		return Outcome{}, errors.New("blocking is not configured — set nftably's URL and API token under Settings")
	}
	src, err := m.store.GetSource(ip)
	if err != nil {
		return Outcome{}, err
	}
	// A private, loopback or CGNAT source is one of ours. Blocking it at the
	// edge would be a self-inflicted outage, so refuse rather than warn.
	if src.IsLocal {
		return Outcome{}, fmt.Errorf("%s is a private or internal address — blocking it at the edge would cut off one of our own hosts", ip)
	}
	if reason == "" {
		reason = "blocked from meerkat"
	}

	res, err := m.nft.Block(ctx, ip, reason)
	if err != nil {
		m.record(actor, store.ActionBlock, ip, reason, err.Error(), false, int(ttl.Seconds()))
		return Outcome{}, err
	}

	var until time.Time
	if ttl > 0 {
		until = time.Now().Add(ttl)
	}
	note := reason
	if ttl > 0 {
		note += fmt.Sprintf(" (expires %s)", until.Local().Format("2006-01-02 15:04"))
	}
	if err := m.store.SetSourceStateUntil(ip, store.StateBlocked, note, actor, until); err != nil {
		// nftably is holding the block but meerkat could not record it. Say so
		// loudly: the next reconcile will restore the state, and until then the
		// console under-claims rather than over-claims, which is the safe way
		// round.
		m.log.Error("blocked in nftably but could not record it locally", "ip", ip, "err", err)
		m.record(actor, store.ActionBlock, ip, reason, "blocked in nftably, but meerkat could not record it: "+err.Error(), false, int(ttl.Seconds()))
		return Outcome{}, err
	}
	m.record(actor, store.ActionBlock, ip, reason, res.Detail, true, int(ttl.Seconds()))

	msg := ip + " is blocked — " + res.Detail
	if res.Already {
		msg = ip + " was already on nftably's blacklist"
	}
	return Outcome{Message: msg, Live: res.InKernel}, nil
}

// Unblock lifts a block, then records it.
func (m *Manager) Unblock(ctx context.Context, ip, reason, actor string) (Outcome, error) {
	if !m.nft.Configured() {
		return Outcome{}, errors.New("blocking is not configured — set nftably's URL and API token under Settings")
	}
	res, err := m.nft.Unblock(ctx, ip)
	if err != nil {
		m.record(actor, store.ActionUnblock, ip, reason, err.Error(), false, 0)
		return Outcome{}, err
	}
	// An unblocked source is not "new" — it has been looked at. Acknowledged is
	// the honest resting state.
	if err := m.store.SetSourceStateUntil(ip, store.StateAcknowledged, reason, actor, time.Time{}); err != nil {
		return Outcome{}, err
	}
	m.record(actor, store.ActionUnblock, ip, reason, res.Detail, true, 0)
	return Outcome{Message: ip + " is no longer blocked — " + res.Detail}, nil
}

// Acknowledge and Allowlist are local decisions: they change how meerkat treats
// a source, and touch nothing on the network.
func (m *Manager) Acknowledge(ip, note, actor string) error {
	if err := m.store.SetSourceState(ip, store.StateAcknowledged, note, actor); err != nil {
		return err
	}
	m.record(actor, store.ActionAcknowledge, ip, note, "marked as reviewed", true, 0)
	return nil
}

func (m *Manager) Allowlist(ip, note, actor string) error {
	if err := m.store.SetSourceState(ip, store.StateAllowlisted, note, actor); err != nil {
		return err
	}
	m.record(actor, store.ActionAllowlist, ip, note, "will not be alerted on again", true, 0)
	return nil
}

// Run keeps the block state honest until ctx is done: it expires timed blocks
// and reconciles against nftably.
func (m *Manager) Run(ctx context.Context) {
	if !m.nft.Configured() {
		return
	}
	tick := time.NewTicker(reconcileInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			m.ExpireBlocks(ctx)
			if err := m.Reconcile(ctx); err != nil {
				m.log.Warn("could not reconcile blocks with nftably", "err", err)
			}
		}
	}
}

// ExpireBlocks lifts timed blocks whose expiry has passed. nftably's API has no
// TTL of its own, so meerkat holds the clock and issues the unblock.
func (m *Manager) ExpireBlocks(ctx context.Context) {
	due, err := m.store.ExpiredBlocks(time.Now())
	if err != nil {
		m.log.Warn("could not read expired blocks", "err", err)
		return
	}
	for _, src := range due {
		if _, err := m.Unblock(ctx, src.IP, "timed block expired", "meerkat"); err != nil {
			m.log.Warn("could not lift an expired block", "ip", src.IP, "err", err)
			continue
		}
		m.log.Info("timed block expired and was lifted", "ip", src.IP)
	}
}

// Reconcile makes meerkat's claim match nftably's reality.
//
// nftably is the authority in both directions. If it no longer holds an address
// meerkat calls blocked, meerkat stops calling it blocked; if it holds one
// meerkat does not, meerkat starts. Either way the drift is written to the
// ledger, because a state that changed without an operator asking is exactly
// what somebody will later want to explain.
func (m *Manager) Reconcile(ctx context.Context) error {
	if !m.nft.Configured() {
		return nil
	}
	actual, err := m.nft.Blocked(ctx)
	if err != nil {
		return err
	}
	inNftably := make(map[string]bool, len(actual))
	for _, ip := range actual {
		inNftably[ip] = true
	}

	claimed, err := m.store.BlockedSources()
	if err != nil {
		return err
	}
	for _, src := range claimed {
		if inNftably[src.IP] {
			continue
		}
		// Gone from the firewall — meerkat must stop claiming it.
		if err := m.store.SetSourceStateUntil(src.IP, store.StateAcknowledged,
			"unblocked outside meerkat", "reconcile", time.Time{}); err != nil {
			m.log.Warn("could not clear a stale block", "ip", src.IP, "err", err)
			continue
		}
		m.record("reconcile", store.ActionUnblock, src.IP, "drift",
			"no longer in nftably's blacklist; meerkat stopped reporting it as blocked", true, 0)
		m.log.Info("a source was unblocked outside meerkat", "ip", src.IP)
	}

	// The other direction: an address banned by hand, or by another tool, that
	// meerkat happens to have a source row for.
	for ip := range inNftably {
		src, err := m.store.GetSource(ip)
		if err != nil {
			continue // not a source meerkat knows about; nothing to say
		}
		if src.State == store.StateBlocked {
			continue
		}
		if err := m.store.SetSourceState(ip, store.StateBlocked, "blocked outside meerkat", "reconcile"); err != nil {
			m.log.Warn("could not record an external block", "ip", ip, "err", err)
			continue
		}
		m.record("reconcile", store.ActionBlock, ip, "drift",
			"found in nftably's blacklist; meerkat now reports it as blocked", true, 0)
		m.log.Info("a source was blocked outside meerkat", "ip", ip)
	}
	return nil
}

// record writes to the actions ledger. Best-effort: a failure to record must not
// undo the action, but it is logged rather than dropped.
func (m *Manager) record(actor, action, target, reason, result string, ok bool, ttlSecs int) {
	if err := m.store.RecordAction(store.Action{
		Actor: actor, Action: action, Target: target,
		Reason: reason, Result: result, OK: ok, TTLSecs: ttlSecs,
	}); err != nil {
		m.log.Warn("could not record an action", "action", action, "target", target, "err", err)
	}
}
