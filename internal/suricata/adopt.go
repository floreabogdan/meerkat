package suricata

import (
	"bufio"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
)

// Adoption is what meerkat found in a filter file somebody else wrote.
//
// Taking over /etc/suricata/disable.conf means the file meerkat generates from
// its own policy becomes the whole truth. Anything already in there that is not
// carried across would be silently switched back on — so it is read first, what
// can be represented is adopted, and what cannot is reported rather than
// quietly dropped. edge1 had exactly one hand-added sid in that file when meerkat
// arrived; a tool that claims to manage rules must not lose it.
type Adoption struct {
	Filters []Filter
	// Unsupported are lines meerkat cannot express in its policy model —
	// suricata-update's group: filters, and regexes that are not one of
	// meerkat's own category matchers. Surfaced so the operator decides,
	// instead of meerkat deciding by forgetting.
	Unsupported []string
}

// ParseFilterFile reads an existing disable.conf or enable.conf.
//
// A file meerkat generated returns nothing to adopt: it is already a rendering
// of the policy, and re-adopting it would be a loop.
func ParseFilterFile(path string) (Adoption, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return Adoption{}, nil
	}
	if err != nil {
		return Adoption{}, err
	}
	defer f.Close()
	return ParseFilters(f), nil
}

// ParseFilters reads filter lines in suricata-update's syntax.
func ParseFilters(r io.Reader) Adoption {
	var a Adoption
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4<<10), 1<<20)

	var note string
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.Contains(line, generatedMarker) {
			return Adoption{} // ours already; nothing to take over
		}
		if line == "" {
			note = ""
			continue
		}
		if strings.HasPrefix(line, "#") {
			// A comment directly above a filter is its reason; keep it so an
			// adopted entry arrives with whatever explanation it had.
			note = strings.TrimSpace(strings.TrimLeft(line, "# "))
			continue
		}
		f, ok := parseFilterLine(line)
		if !ok {
			a.Unsupported = append(a.Unsupported, line)
			note = ""
			continue
		}
		f.Note = note
		a.Filters = append(a.Filters, f)
		note = ""
	}
	return a
}

func parseFilterLine(line string) (Filter, bool) {
	// Strip a trailing comment, which suricata-update allows.
	if i := strings.Index(line, " #"); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	switch {
	case strings.HasPrefix(line, "re:"):
		// meerkat writes categories as a regex against the message. Recognising
		// its own shape lets a policy survive a round trip through the file.
		if cat, ok := categoryFromRegex(strings.TrimPrefix(line, "re:")); ok {
			return Filter{Scope: ScopeCategory, Key: cat}, true
		}
		return Filter{}, false
	case strings.HasPrefix(line, "group:"), strings.HasPrefix(line, "filename:"):
		return Filter{}, false
	}
	// "2010371" or "1:2010371".
	sid := line
	if _, after, ok := strings.Cut(line, ":"); ok {
		sid = after
	}
	if n, err := strconv.Atoi(strings.TrimSpace(sid)); err == nil && n > 0 {
		return Filter{Scope: ScopeSID, Key: strconv.Itoa(n)}, true
	}
	return Filter{}, false
}

// categoryFromRegex reverses Filter.Matcher for the category form.
func categoryFromRegex(re string) (string, bool) {
	const prefix = `msg:"`
	if !strings.HasPrefix(re, prefix) {
		return "", false
	}
	body := strings.TrimSuffix(strings.TrimPrefix(re, prefix), " ")
	if body == "" {
		return "", false
	}
	// Undo regexp.QuoteMeta's backslashes. Categories are two plain words, so
	// anything left escaped means this regex was not one of ours.
	var b strings.Builder
	for i := 0; i < len(body); i++ {
		if body[i] == '\\' && i+1 < len(body) {
			i++
		}
		b.WriteByte(body[i])
	}
	out := b.String()
	if strings.ContainsAny(out, `"()[]{}|*+?^$`) {
		return "", false
	}
	return out, true
}
