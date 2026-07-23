package suricata

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"time"
)

// maxRuleBytes bounds one line. ET's reputation rules carry thousands of
// addresses inline — the largest on edge1 is comfortably over 100 KB — so the
// default bufio.Scanner limit of 64 KB would truncate exactly the rules that
// produce most of the alert volume. 4 MB is far past anything real and still
// bounds a corrupt file.
const maxRuleBytes = 4 << 20

// Counts is what a scan of the built ruleset found.
type Counts struct {
	Total    int
	Enabled  int
	Disabled int
	// Skipped is lines that were not rules: comments, blanks, and anything
	// unparseable. Reported rather than swallowed, because a jump in it means
	// the parser has met a rule shape it does not understand.
	Skipped int
}

// RulesetInfo describes the file Suricata is running, for change detection.
type RulesetInfo struct {
	Path    string
	Size    int64
	ModTime time.Time
	Counts
}

// Scan reads a rules file and calls fn for every rule it contains, enabled or
// not. It streams: the file is tens of megabytes and there is no reason to hold
// it, or a slice of every rule in it, in memory at once.
//
// fn returning an error stops the scan and returns it.
func Scan(r io.Reader, fn func(Rule) error) (Counts, error) {
	var c Counts
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), maxRuleBytes)
	for sc.Scan() {
		rule, ok := Parse(sc.Text())
		if !ok {
			c.Skipped++
			continue
		}
		c.Total++
		if rule.Enabled {
			c.Enabled++
		} else {
			c.Disabled++
		}
		if err := fn(rule); err != nil {
			return c, err
		}
	}
	if err := sc.Err(); err != nil {
		return c, fmt.Errorf("suricata: read ruleset: %w", err)
	}
	return c, nil
}

// ScanFile is Scan over a path.
func ScanFile(path string, fn func(Rule) error) (Counts, error) {
	f, err := os.Open(path)
	if err != nil {
		return Counts{}, fmt.Errorf("suricata: open ruleset: %w", err)
	}
	defer f.Close()
	return Scan(f, fn)
}

// Stat describes the ruleset file without parsing it — enough to decide whether
// a re-index is worth doing.
func Stat(path string) (RulesetInfo, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return RulesetInfo{}, fmt.Errorf("suricata: stat ruleset: %w", err)
	}
	return RulesetInfo{Path: path, Size: fi.Size(), ModTime: fi.ModTime().UTC()}, nil
}
