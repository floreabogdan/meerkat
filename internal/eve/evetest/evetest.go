// Package evetest serves the alert fixture the ingest-side tests run against:
// 386 alerts captured from a live sensor, spanning 14 minutes, from 66 distinct
// source addresses. The record shapes, the timestamps and above all the *skew*
// are real — a synthetic eve.json is too tidy to be worth testing against, and
// the skew is the premise the whole per-source rollup rests on.
//
// **Every address in it has been rewritten** into RFC 5737 documentation space:
// sources into 198.51.100.0/24, destinations into 192.0.2.0/24, injectively, so
// counts and per-source grouping are exactly what was captured while no real
// network appears anywhere. The offset was normalised to +0000 by a uniform
// shift, which leaves every span and every ordering untouched.
//
// Know what this fixture is NOT, before drawing conclusions from it: it was
// captured before HOME_NET was corrected, so every record comes from two
// hand-written local rules ("SSH connection" / "RDP connection", sid 1000001 and
// 1000002) and carries no alert category. The ET CINS / ET DROP reputation
// flood quoted in PLAN.md — 891 alerts in 4 minutes, 68.8% of it one reputation
// rule — was measured live and never captured to a file. Anything that needs
// that traffic mix (per-signature dispositions, the category breakdown) wants a
// fresh capture first.
//
// It is a package rather than a plain testdata/ directory so that any package
// can use the fixture: //go:embed cannot reach outside its own directory, and a
// second copy of the file would drift.
package evetest

import (
	_ "embed"
	"strings"
	"testing"
)

//go:embed testdata/alerts.jsonl
var alertsJSONL string

// AlertLines returns every captured alert as a raw eve.json line.
func AlertLines(tb testing.TB) []string {
	tb.Helper()
	var out []string
	for line := range strings.SplitSeq(alertsJSONL, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	if len(out) == 0 {
		tb.Skip("alert fixture is empty")
	}
	return out
}
