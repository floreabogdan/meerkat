package suricata

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var at = time.Date(2026, 7, 22, 9, 0, 0, 0, time.UTC)

func TestRenderRoundTripsThroughSuricataUpdateSyntax(t *testing.T) {
	f := Filters{
		Disable: []Filter{
			{Scope: ScopeSID, Key: "2100387", Note: "ICMP is not an attack we care about"},
			{Scope: ScopeCategory, Key: "ET CINS"},
		},
		Enable: []Filter{{Scope: ScopeSID, Key: "2009172"}},
	}

	// Rendering marks the file as meerkat's, and adoption deliberately refuses
	// to re-import its own output. Strip the marker to test the syntax itself.
	got := ParseFilters(strings.NewReader(stripMarker(string(f.DisableConf(at)))))

	if len(got.Filters) != 2 {
		t.Fatalf("round-tripped %d filters %+v, want 2", len(got.Filters), got.Filters)
	}
	if len(got.Unsupported) != 0 {
		t.Fatalf("its own output came back as unsupported: %q", got.Unsupported)
	}
	// Sorted by scope then key: the category sorts before the sid.
	if got.Filters[0].Scope != ScopeCategory || got.Filters[0].Key != "ET CINS" {
		t.Errorf("first filter = %+v, want the ET CINS category", got.Filters[0])
	}
	if got.Filters[1].Scope != ScopeSID || got.Filters[1].Key != "2100387" {
		t.Errorf("second filter = %+v, want sid 2100387", got.Filters[1])
	}
	if got.Filters[1].Note != "ICMP is not an attack we care about" {
		t.Errorf("the reason did not survive: %q", got.Filters[1].Note)
	}
}

// A category filter has to actually match the rules in that category, or the
// operator disables ET CINS and nothing happens. The matcher is a regex
// suricata-update runs against the rule text, so the test runs it against the
// real fixture rules the same way.
func TestCategoryMatcherMatchesItsRulesAndNothingElse(t *testing.T) {
	body := Filter{Scope: ScopeCategory, Key: "ET CINS"}.Matcher()
	pattern := strings.TrimPrefix(body, "re:")

	var matched, missed []string
	for _, r := range readFixture(t) {
		line := `msg:"` + r.Msg + `"`
		if strings.Contains(line, pattern) {
			matched = append(matched, r.Msg)
		} else if r.Category == "ET CINS" {
			missed = append(missed, r.Msg)
		}
	}
	if len(missed) > 0 {
		t.Errorf("the ET CINS matcher missed its own rules: %q", missed)
	}
	if len(matched) != 1 {
		t.Fatalf("matched %d rules %q, want exactly the one ET CINS rule", len(matched), matched)
	}
	// The trailing space is what stops "ET CINS" from also matching a
	// hypothetical "ET CINSFOO" category.
	if !strings.HasSuffix(pattern, " ") {
		t.Errorf("matcher %q has no trailing space, so it is a prefix match on the category name", pattern)
	}
}

// An operator's reason becomes a comment in a config file. A newline in it
// would end the comment and turn the rest into a filter line of its own —
// config injection by typo.
func TestRenderNeutralisesNewlinesInAReason(t *testing.T) {
	out := string(Render("disable", []Filter{{
		Scope: ScopeSID, Key: "1000001",
		Note: "noisy\n2403300\nre:.",
	}}, at))
	for line := range strings.SplitSeq(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line != "1000001" {
			t.Errorf("a reason produced an extra filter line: %q", line)
		}
	}
}

// The house rule, enforced rather than remembered: meerkat manages which rules
// alert, and never asks Suricata to drop. Suricata here is inline on NFQUEUE
// and dropping from it once cost 9.6% of transit traffic; blocking belongs to
// nftables. suricata-update's drop.conf is the mechanism that would undo that,
// so the package must never learn to write one.
func TestPackageNeverWritesADropFilter(t *testing.T) {
	entries, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range entries {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		// Comments are stripped first. The rule is about what the code does,
		// and the doc comment that explains why drop.conf is absent has to be
		// allowed to name the thing it is explaining.
		for i, line := range strings.Split(string(body), "\n") {
			code, _, _ := strings.Cut(line, "//")
			for _, banned := range []string{"drop.conf", "--drop-conf", "DropConf"} {
				if strings.Contains(code, banned) {
					t.Errorf("%s:%d references %q — meerkat must not make Suricata drop; blocking goes through nftably",
						path, i+1, banned)
				}
			}
		}
	}
}

func TestAdoptionKeepsWhatItCanAndReportsWhatItCannot(t *testing.T) {
	// edge1's real /etc/suricata/disable.conf held exactly one bare sid when
	// meerkat arrived. The group: line is the shape meerkat cannot represent.
	in := strings.Join([]string{
		"# some notes from a previous admin",
		"2210057",
		"1:2100387",
		"group:emerging-icmp.rules",
		"re:something we did not write",
		"",
	}, "\n")

	got := ParseFilters(strings.NewReader(in))
	if len(got.Filters) != 2 {
		t.Fatalf("adopted %+v, want the two sids", got.Filters)
	}
	if got.Filters[0].Key != "2210057" || got.Filters[1].Key != "2100387" {
		t.Errorf("adopted keys = %q, %q", got.Filters[0].Key, got.Filters[1].Key)
	}
	if got.Filters[0].Note != "some notes from a previous admin" {
		t.Errorf("the comment above a filter was not kept as its reason: %q", got.Filters[0].Note)
	}
	if len(got.Unsupported) != 2 {
		t.Fatalf("unsupported = %q, want the group: and the foreign re: line", got.Unsupported)
	}
}

func TestAdoptionRefusesToReimportItsOwnOutput(t *testing.T) {
	out := Filters{Disable: []Filter{{Scope: ScopeSID, Key: "2100387"}}}.DisableConf(at)
	if got := ParseFilters(strings.NewReader(string(out))); len(got.Filters) != 0 {
		t.Errorf("adopted %d filters from meerkat's own file; that is a loop", len(got.Filters))
	}
}

// Taking over a file somebody else wrote must keep a copy. On edge1 that file
// held a disabled rule; overwriting it would have switched the rule back on
// with nobody asking and no record.
func TestInstallBacksUpAHandWrittenFilterFileExactlyOnce(t *testing.T) {
	dir := t.TempDir()
	p := Paths{Staging: filepath.Join(dir, "staging"), ConfDir: filepath.Join(dir, "etc")}.Defaults()
	mkdirs(t, p.Staging, p.ConfDir)

	original := "2210057\n"
	write(t, p.LiveDisable(), original)
	write(t, p.StagedDisable(), string(Filters{}.DisableConf(at)))

	if err := installFilters(p); err != nil {
		t.Fatal(err)
	}
	if got := read(t, p.LiveDisable()+".pre-meerkat"); got != original {
		t.Errorf("backup = %q, want the original %q", got, original)
	}
	if got := read(t, p.LiveDisable()); !strings.Contains(got, generatedMarker) {
		t.Error("the live file was not replaced by meerkat's")
	}

	// A second apply must not overwrite the backup with meerkat's own file —
	// that would destroy the only copy of what was there before.
	write(t, p.StagedDisable(), string(Filters{Disable: []Filter{{Scope: ScopeSID, Key: "1"}}}.DisableConf(at)))
	if err := installFilters(p); err != nil {
		t.Fatal(err)
	}
	if got := read(t, p.LiveDisable()+".pre-meerkat"); got != original {
		t.Errorf("backup after a second apply = %q, want it untouched", got)
	}
}

func TestRequestAndResultRoundTrip(t *testing.T) {
	p := Paths{Staging: t.TempDir()}.Defaults()

	if _, ok, err := ReadRequest(p); err != nil || ok {
		t.Fatalf("a fresh staging dir reported a pending request (ok=%v err=%v)", ok, err)
	}
	req := Request{RequestedAt: at, Actor: "admin", Reason: "muted ET CINS", Force: true}
	if err := WriteRequest(p, req); err != nil {
		t.Fatal(err)
	}
	got, ok, err := ReadRequest(p)
	if err != nil || !ok {
		t.Fatalf("ReadRequest: ok=%v err=%v", ok, err)
	}
	if got.Actor != "admin" || got.Reason != "muted ET CINS" || !got.Force {
		t.Errorf("round-tripped %+v", got)
	}
	if err := ClearRequest(p); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := ReadRequest(p); ok {
		t.Error("the request survived being cleared, so the path unit would fire forever")
	}
	// Clearing twice is what happens when a run is retried; it must not error.
	if err := ClearRequest(p); err != nil {
		t.Errorf("clearing an absent request: %v", err)
	}
}

func stripMarker(s string) string {
	var keep []string
	for line := range strings.SplitSeq(s, "\n") {
		if strings.Contains(line, generatedMarker) {
			continue
		}
		keep = append(keep, line)
	}
	return strings.Join(keep, "\n")
}

func mkdirs(t *testing.T, dirs ...string) {
	t.Helper()
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
