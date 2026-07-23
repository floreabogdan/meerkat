package suricata

import (
	"os"
	"strings"
	"testing"
)

// The fixture is 12 rules taken from a real built ruleset: two ET SCAN, one each
// of the ET CINS / ET COMPROMISED / ET DROP reputation rules (the ones carrying
// long address groups inline), two disabled GPL ICMP rules, two disabled
// SURICATA decoder events, an ET ACTIVEX rule with a pcre, a disabled ET MALWARE
// rule, and a SURICATA STREAM event. Between them they cover every shape the
// parser has to survive.
//
// The address groups in the three reputation rules have been replaced with
// documentation space (RFC 5737). Nothing here asserts on their contents — they
// are there so the parser meets a realistic line length and a bracketed group.
const fixture = "testdata/sample.rules"

func TestParseRealRuleset(t *testing.T) {
	f, err := os.Open(fixture)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	byID := map[int]Rule{}
	counts, err := Scan(f, func(r Rule) error {
		byID[r.SID] = r
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if counts.Total != 12 {
		t.Fatalf("parsed %d rules from the fixture, want 12 (counts %+v)", counts.Total, counts)
	}
	// Five of the twelve are commented out. A disabled rule must still parse:
	// it is the one an operator can turn back on, so losing it would hide
	// exactly the rules this feature exists to manage.
	if counts.Enabled != 7 || counts.Disabled != 5 {
		t.Errorf("enabled/disabled split = %d/%d, want 7/5", counts.Enabled, counts.Disabled)
	}
	if counts.Skipped != 0 {
		t.Errorf("skipped %d lines of a file that is all rules", counts.Skipped)
	}

	scan := byID[2010371]
	if scan.Msg != "ET SCAN Amap TCP Service Scan Detected" {
		t.Errorf("msg = %q", scan.Msg)
	}
	if scan.Category != "ET SCAN" {
		t.Errorf("category = %q, want %q", scan.Category, "ET SCAN")
	}
	if !scan.Enabled || scan.Action != "alert" || scan.Proto != "tcp" {
		t.Errorf("header = %v %q %q", scan.Enabled, scan.Action, scan.Proto)
	}
	if scan.Rev != 2 || scan.GID != 1 {
		t.Errorf("rev/gid = %d/%d, want 2/1", scan.Rev, scan.GID)
	}
	if scan.Classtype != "attempted-recon" {
		t.Errorf("classtype = %q", scan.Classtype)
	}
	if scan.Severity != "Informational" {
		t.Errorf("metadata signature_severity = %q, want Informational", scan.Severity)
	}
	if scan.UpdatedAt != "2019_07_26" {
		t.Errorf("metadata updated_at = %q", scan.UpdatedAt)
	}

	// The reputation rules are the ones that matter most to a triage console —
	// on edge1 they were 85% of the alert volume — and they are also the longest
	// lines in the file by three orders of magnitude.
	cins := byID[2403300]
	if cins.Category != "ET CINS" {
		t.Errorf("CINS category = %q", cins.Category)
	}
	if cins.Severity != "Major" {
		t.Errorf("CINS severity = %q", cins.Severity)
	}
	if !strings.HasPrefix(cins.Source, "[") {
		t.Errorf("CINS source address list did not survive parsing: %.40q", cins.Source)
	}

	icmp := byID[2100387]
	if icmp.Enabled {
		t.Error("a commented-out rule parsed as enabled")
	}
	if icmp.Category != "GPL ICMP" {
		t.Errorf("disabled rule category = %q, want %q", icmp.Category, "GPL ICMP")
	}
	if icmp.Msg != "GPL ICMP Address Mask Reply undefined code" {
		t.Errorf("disabled rule msg = %q", icmp.Msg)
	}
}

// The ET ACTIVEX fixture rule carries a pcre full of escapes. Splitting a rule
// body on every semicolon would cut it in the middle of that pattern and lose
// everything after it — including the sid, which would drop the rule from the
// catalogue entirely rather than fail in any visible way.
func TestParseKeepsOptionsAfterAPCRE(t *testing.T) {
	rules := readFixture(t)
	var got Rule
	for _, r := range rules {
		if r.SID == 2010943 {
			got = r
		}
	}
	if got.SID == 0 {
		t.Fatal("the rule with a pcre was not parsed at all")
	}
	if got.Classtype != "web-application-attack" {
		t.Errorf("classtype = %q — options after the pcre were lost", got.Classtype)
	}
	if got.Rev != 2 {
		t.Errorf("rev = %d, want 2", got.Rev)
	}
}

// An option ends at the first semicolon that is not backslash-escaped. Quotes
// play no part — see the note on splitOptions.
func TestSplitOptionsRespectsBackslashEscapes(t *testing.T) {
	body := `msg:"has a \; and a \" in it"; content:"v=DKIM1\; p="; sid:99; rev:1`
	got := splitOptions(body)
	want := []string{`msg:"has a \; and a \" in it"`, `content:"v=DKIM1\; p="`, "sid:99", "rev:1"}
	if len(got) != len(want) {
		t.Fatalf("split into %d options %q, want %d", len(got), got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("option %d = %q, want %q", i, got[i], want[i])
		}
	}

	r, ok := Parse("alert tcp any any -> any any (" + body + ";)")
	if !ok {
		t.Fatal("rule did not parse")
	}
	if r.Msg != `has a ; and a " in it` {
		t.Errorf("msg = %q — the escapes were not undone", r.Msg)
	}
}

// An even run of backslashes before a semicolon is escaped backslashes, which
// leaves the semicolon itself a separator.
func TestSplitOptionsCountsBackslashRuns(t *testing.T) {
	got := splitOptions(`content:"ends with a backslash\\"; sid:1`)
	want := []string{`content:"ends with a backslash\\"`, "sid:1"}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("split = %q, want %q", got, want)
	}
	if u := unquote(`"ends with a backslash\\"`); u != `ends with a backslash\` {
		t.Errorf("unquote = %q", u)
	}
}

// The bug this parser actually had, kept as a fixture.
//
// A rule value may contain an unescaped double quote — ET Open ships several.
// A splitter that tracks quotes desynchronises at that point and swallows the
// rest of the rule including its sid, so the rule disappears from the catalogue
// with nothing anywhere reporting an error. Eight rules on edge1 did this, two of
// them enabled, and the only visible symptom was the console's enabled count
// being 2 short of what Suricata itself reported.
func TestParseRuleWithAnUnescapedQuoteInsideAPCRE(t *testing.T) {
	const real = `alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET PHISHING Common Unhidebody Function Observed in Phishing Landing"; flow:established,to_client; file.data; content:"function unhideBody()"; nocase; content:"method="; nocase; pcre:"/^["']?post/Ri"; classtype:social-engineering; sid:2029732; rev:2; metadata:created_at 2020_03_24, signature_severity Minor, updated_at 2020_03_24;)`

	r, ok := Parse(real)
	if !ok {
		t.Fatal("a real ET rule with an unescaped quote in its pcre did not parse")
	}
	if r.SID != 2029732 {
		t.Errorf("sid = %d, want 2029732 — the options after the pcre were swallowed", r.SID)
	}
	if r.Classtype != "social-engineering" {
		t.Errorf("classtype = %q", r.Classtype)
	}
	if r.Category != "ET PHISHING" {
		t.Errorf("category = %q", r.Category)
	}
	if r.Severity != "Minor" {
		t.Errorf("metadata severity = %q", r.Severity)
	}
}

func TestParseRejectsThingsThatAreNotRules(t *testing.T) {
	for _, line := range []string{
		"",
		"   ",
		"# This file is generated by suricata-update",
		"#",
		"# a comment mentioning alert tcp but with no parentheses",
		"alert tcp any any -> any any (msg:\"no sid here\";)",
		"not-a-rule (msg:\"x\"; sid:1;)",
	} {
		if r, ok := Parse(line); ok {
			t.Errorf("Parse(%q) accepted it as sid %d", line, r.SID)
		}
	}
}

func TestCategoryOf(t *testing.T) {
	cases := map[string]string{
		"ET SCAN Amap TCP Service Scan Detected":      "ET SCAN",
		"GPL ICMP Address Mask Reply undefined code":  "GPL ICMP",
		"ETPRO MALWARE Something Proprietary":         "ETPRO MALWARE",
		"SURICATA Applayer Mismatch protocol":         "SURICATA",
		"SURICATA STREAM 3way handshake with ack":     "SURICATA",
		"Custom rule for the office VPN":              "local",
		"":                                            "uncategorised",
		"ET":                                          "ET",
		"ET COMPROMISED Known Compromised or Hostile": "ET COMPROMISED",
	}
	for msg, want := range cases {
		if got := CategoryOf(msg); got != want {
			t.Errorf("CategoryOf(%q) = %q, want %q", msg, got, want)
		}
	}
}

// ET's reputation rules inline every address they match. The largest on edge1 is
// well past bufio.Scanner's default 64 KB limit, and the default would not
// error — it would stop the scan at that line, silently losing the rest of the
// ruleset from the catalogue. This is the guard on that.
func TestScanHandlesLinesBiggerThanTheDefaultBuffer(t *testing.T) {
	var b strings.Builder
	b.WriteString("alert ip [")
	for i := range 20000 {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString("10.0.0.1")
	}
	b.WriteString(`] any -> $HOME_NET any (msg:"ET CINS Enormous Group"; sid:2403999; rev:1;)` + "\n")
	b.WriteString(`alert tcp any any -> any any (msg:"ET SCAN After The Giant"; sid:2000001; rev:1;)` + "\n")

	if b.Len() < 64<<10 {
		t.Fatalf("the fixture line is only %d bytes; it must exceed the 64 KB default to be a test", b.Len())
	}

	var seen []int
	counts, err := Scan(strings.NewReader(b.String()), func(r Rule) error {
		seen = append(seen, r.SID)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if counts.Total != 2 {
		t.Fatalf("parsed %d rules, want 2 — the rule after the oversized line was lost", counts.Total)
	}
	if seen[1] != 2000001 {
		t.Errorf("second sid = %d", seen[1])
	}
}

// A sensor somebody else configured may hold drop rules. meerkat never writes
// one, but it must report what is there rather than flattening every action to
// "alert" — the console claiming a rule only alerts when it actually drops is
// the exact class of quiet lie this project refuses.
func TestParseReportsANonAlertActionVerbatim(t *testing.T) {
	r, ok := Parse(`drop tcp any any -> any any (msg:"ET DROP Somebody Else's Idea"; sid:2400777; rev:1;)`)
	if !ok {
		t.Fatal("drop rule did not parse")
	}
	if r.Action != "drop" {
		t.Errorf("action = %q, want %q", r.Action, "drop")
	}
}

func readFixture(t *testing.T) []Rule {
	t.Helper()
	var out []Rule
	if _, err := ScanFile(fixture, func(r Rule) error {
		out = append(out, r)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}
