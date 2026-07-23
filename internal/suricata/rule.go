// Package suricata is the sensor-management half of meerkat: reading the
// ruleset Suricata is actually running, rendering the filter files
// suricata-update consumes, running the updater, and asking Suricata to reload.
//
// It deliberately knows nothing about meerkat's database or its UI. Everything
// here is mechanics against files, a process and a socket, so it can be tested
// against real ET Open rules without a store, and so the privileged half — the
// only part that writes /etc/suricata and talks to the control socket — stays
// small enough to read in one sitting.
//
// One rule of the house applies throughout: meerkat never makes Suricata drop
// anything. It manages which rules ALERT. Dropping is nftables' job, pushed
// through nftably, and no code path here writes a drop filter.
package suricata

import (
	"strconv"
	"strings"
)

// Rule is one signature as it stands in the built ruleset.
//
// Only the fields triage actually uses are kept. A rule's detection body —
// content, pcre, flowbits — is what makes the file 45 MB, and meerkat has
// nothing useful to say about it; the operator's questions are "what is this,
// how loud is it, and do I want it on".
type Rule struct {
	// Enabled is false for a rule commented out in the file. suricata-update
	// writes disabled rules as "# alert ..." rather than dropping them, which is
	// what makes a disabled rule still visible and re-enableable here.
	Enabled bool

	Action string // alert, drop, pass, reject — see the note in Parse
	Proto  string
	Source string
	Dest   string

	SID int
	GID int
	Rev int

	Msg       string
	Classtype string
	Priority  int

	// Severity is Emerging Threats' own metadata rating
	// (Informational/Minor/Major/Critical), which is not the same axis as the
	// numeric priority Suricata puts in eve.json. Both are shown; neither is
	// invented.
	Severity  string
	CreatedAt string
	UpdatedAt string

	// Category is derived from the message prefix — "ET SCAN", "GPL ICMP",
	// "SURICATA". It is the unit an operator actually reasons about ("I do not
	// care about ICMP"), and it is not stored anywhere in the rule itself.
	Category string
}

// Parse reads one line of a rules file.
//
// It returns ok=false for blank lines and for comments that are not rules, and
// ok=true with Enabled=false for a rule that has been commented out — that
// distinction is the whole point of reading the file rather than counting it,
// because a disabled rule is something the operator can turn back on.
//
// The Action field is read verbatim rather than assumed. meerkat never writes a
// drop rule, but it can be pointed at a sensor somebody else configured, and
// reporting "alert" for a rule that says "drop" would be exactly the kind of
// quiet lie this project refuses to tell.
func Parse(line string) (Rule, bool) {
	s := strings.TrimSpace(line)
	if s == "" {
		return Rule{}, false
	}

	enabled := true
	if s[0] == '#' {
		// A disabled rule and a prose comment look identical for one character.
		// Strip the marker and let the parse itself decide which this is.
		enabled = false
		s = strings.TrimSpace(strings.TrimLeft(s, "#"))
		if s == "" {
			return Rule{}, false
		}
	}

	open := strings.IndexByte(s, '(')
	closed := strings.LastIndexByte(s, ')')
	if open < 0 || closed < open {
		return Rule{}, false
	}

	r := Rule{Enabled: enabled, GID: 1}
	if !parseHeader(s[:open], &r) {
		return Rule{}, false
	}
	parseOptions(s[open+1:closed], &r)

	// A signature without an sid is not addressable: nothing can be said about
	// it, and no filter can name it. Treat it as noise in the file.
	if r.SID == 0 {
		return Rule{}, false
	}
	r.Category = CategoryOf(r.Msg)
	return r, true
}

// parseHeader reads "alert tcp $EXTERNAL_NET any -> $HOME_NET any".
//
// Address lists in ET rules are bracketed and never contain spaces, even when
// they run to several thousand addresses, so splitting on whitespace is safe.
func parseHeader(head string, r *Rule) bool {
	f := strings.Fields(head)
	if len(f) < 2 {
		return false
	}
	switch f[0] {
	case "alert", "drop", "pass", "reject", "rejectsrc", "rejectdst", "rejectboth":
	default:
		return false // a comment that happened to contain a bracket
	}
	r.Action, r.Proto = f[0], f[1]
	if len(f) >= 7 {
		r.Source, r.Dest = f[2], f[5]
	}
	return true
}

func parseOptions(body string, r *Rule) {
	for _, opt := range splitOptions(body) {
		key, val, _ := strings.Cut(opt, ":")
		val = strings.TrimSpace(val)
		switch strings.TrimSpace(key) {
		case "msg":
			r.Msg = unquote(val)
		case "sid":
			r.SID = atoi(val)
		case "gid":
			if g := atoi(val); g > 0 {
				r.GID = g
			}
		case "rev":
			r.Rev = atoi(val)
		case "classtype":
			r.Classtype = val
		case "priority":
			r.Priority = atoi(val)
		case "metadata":
			parseMetadata(val, r)
		}
	}
}

// parseMetadata reads "created_at 2010_07_30, signature_severity Major, ...".
func parseMetadata(val string, r *Rule) {
	for pair := range strings.SplitSeq(val, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(pair), " ")
		if !ok {
			continue
		}
		switch k {
		case "signature_severity":
			r.Severity = strings.TrimSpace(v)
		case "created_at":
			r.CreatedAt = strings.TrimSpace(v)
		case "updated_at":
			r.UpdatedAt = strings.TrimSpace(v)
		}
	}
}

// splitOptions splits a rule body into its options.
//
// This is the one piece of the parser that has to be exact, and the obvious
// implementation is wrong. Tracking quotes and splitting on semicolons outside
// them looks right and passes on almost every rule — but a value may contain an
// unescaped double quote, and ET Open ships some that do:
//
//	pcre:"/^["']?post/Ri"
//
// A quote-tracking splitter desynchronises there and swallows the rest of the
// rule, including the sid, so the rule silently vanishes from the catalogue
// rather than failing in any visible way. Eight rules on edge1 did exactly that.
//
// Suricata's own grammar does not consider quotes at all: an option ends at the
// first semicolon that is not backslash-escaped. A literal semicolon inside a
// value is written "\;", which every rule in ET Open that needs one does —
// content:"v=DKIM1\; p=" and pcre:"/{64}\;\d\;\d$/" are both real.
func splitOptions(s string) []string {
	var out []string
	start := 0
	for i := range len(s) {
		if s[i] != ';' || escapedAt(s, i) {
			continue
		}
		if opt := strings.TrimSpace(s[start:i]); opt != "" {
			out = append(out, opt)
		}
		start = i + 1
	}
	if opt := strings.TrimSpace(s[start:]); opt != "" {
		out = append(out, opt)
	}
	return out
}

// escapedAt reports whether the byte at i is backslash-escaped. An even run of
// backslashes before it is a sequence of escaped backslashes, which leaves the
// character itself unescaped.
func escapedAt(s string, i int) bool {
	n := 0
	for j := i - 1; j >= 0 && s[j] == '\\'; j-- {
		n++
	}
	return n%2 == 1
}

// unquote strips a value's surrounding quotes and undoes Suricata's escapes.
// It is a single pass: doing it as successive replacements turns the escaped
// backslash in `\\"` into a quote.
func unquote(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case '"', ';', '\\':
				i++
				b.WriteByte(s[i])
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func atoi(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0
	}
	return n
}

// vendorPrefixes are the rule sources whose messages start with a two-word
// category. Everything Emerging Threats and the GPL set ships is one of these.
var vendorPrefixes = map[string]bool{"ET": true, "ETPRO": true, "GPL": true}

// CategoryOf derives a rule's category from its message.
//
// "ET SCAN Amap TCP Service Scan Detected" is category "ET SCAN"; Suricata's
// own engine events are "SURICATA". This is how the ruleset gets grouped into
// the few dozen things an operator has an opinion about, out of 52,000 rules.
func CategoryOf(msg string) string {
	f := strings.Fields(msg)
	if len(f) == 0 {
		return "uncategorised"
	}
	if vendorPrefixes[f[0]] && len(f) > 1 {
		return f[0] + " " + f[1]
	}
	// A single all-caps token is a vendor of its own — "SURICATA". Anything else
	// is a rule somebody wrote here, and grouping those by their first word
	// would invent categories out of English.
	if f[0] == strings.ToUpper(f[0]) && strings.IndexFunc(f[0], isLower) < 0 {
		return f[0]
	}
	return "local"
}

func isLower(r rune) bool { return r >= 'a' && r <= 'z' }
