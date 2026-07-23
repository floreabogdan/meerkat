package eve

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// collector gathers lines delivered by the tailer.
type collector struct {
	mu    sync.Mutex
	lines []string
}

func (c *collector) add(b []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lines = append(c.lines, string(b))
}

func (c *collector) snapshot() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.lines...)
}

// waitFor polls until cond holds or the deadline passes.
func waitFor(t *testing.T, d time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return cond()
}

// startTailer runs a tailer in the background and returns its collector plus a
// stop function.
func startTailer(t *testing.T, path, statePath string, fromStart bool) (*collector, func()) {
	t.Helper()
	c := &collector{}
	ctx, cancel := context.WithCancel(context.Background())
	tl := NewTailer(path, statePath, fromStart, testLogger())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = tl.Run(ctx, c.add)
	}()
	return c, func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("tailer did not stop")
		}
	}
}

func appendTo(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	if _, err := f.WriteString(s); err != nil {
		t.Fatalf("write: %v", err)
	}
	f.Close()
}

func TestTailerReadsAppendedLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "eve.json")
	appendTo(t, path, "old line, should be skipped\n")

	c, stop := startTailer(t, path, "", false)
	defer stop()

	// Give the tailer time to open and seek to the end.
	time.Sleep(300 * time.Millisecond)

	appendTo(t, path, "one\ntwo\n")

	if !waitFor(t, 3*time.Second, func() bool { return len(c.snapshot()) >= 2 }) {
		t.Fatalf("expected 2 lines, got %v", c.snapshot())
	}
	got := c.snapshot()
	if got[0] != "one" || got[1] != "two" {
		t.Fatalf("unexpected lines: %v", got)
	}
	for _, l := range got {
		if strings.Contains(l, "skipped") {
			t.Fatalf("tailer replayed pre-existing content: %v", got)
		}
	}
}

// A record written in two syscalls must be delivered once, whole, and only
// after its newline arrives.
func TestTailerHandlesPartialLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "eve.json")
	appendTo(t, path, "")

	c, stop := startTailer(t, path, "", false)
	defer stop()
	time.Sleep(300 * time.Millisecond)

	appendTo(t, path, `{"event_type":"al`)
	time.Sleep(400 * time.Millisecond)
	if n := len(c.snapshot()); n != 0 {
		t.Fatalf("emitted an incomplete line: %v", c.snapshot())
	}

	appendTo(t, path, "ert\"}\n")
	if !waitFor(t, 3*time.Second, func() bool { return len(c.snapshot()) == 1 }) {
		t.Fatalf("expected 1 line, got %v", c.snapshot())
	}
	if got := c.snapshot()[0]; got != `{"event_type":"alert"}` {
		t.Fatalf("line not reassembled: %q", got)
	}
}

// Suricata restarting truncates eve.json in place; the tailer must notice and
// re-read from zero rather than waiting for the file to grow past a stale offset.
func TestTailerHandlesTruncation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "eve.json")
	appendTo(t, path, strings.Repeat("padding line\n", 50))

	c, stop := startTailer(t, path, "", false)
	defer stop()
	time.Sleep(300 * time.Millisecond)

	appendTo(t, path, "before\n")
	if !waitFor(t, 3*time.Second, func() bool { return len(c.snapshot()) == 1 }) {
		t.Fatalf("setup failed, got %v", c.snapshot())
	}

	if err := os.Truncate(path, 0); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	time.Sleep(400 * time.Millisecond)
	appendTo(t, path, "after truncate\n")

	if !waitFor(t, 4*time.Second, func() bool {
		for _, l := range c.snapshot() {
			if l == "after truncate" {
				return true
			}
		}
		return false
	}) {
		t.Fatalf("missed post-truncation line: %v", c.snapshot())
	}
}

// logrotate renames the file and Suricata creates a new one; the tailer must
// follow the path, not the old descriptor.
func TestTailerHandlesRotation(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Windows refuses to rename a file that still has an open handle, so
		// the rotation this simulates cannot happen there. The deployment
		// target is Linux; this runs there.
		t.Skip("cannot rename an open file on windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "eve.json")
	appendTo(t, path, "")

	c, stop := startTailer(t, path, "", false)
	defer stop()
	time.Sleep(300 * time.Millisecond)

	appendTo(t, path, "before rotate\n")
	if !waitFor(t, 3*time.Second, func() bool { return len(c.snapshot()) == 1 }) {
		t.Fatalf("setup failed: %v", c.snapshot())
	}

	if err := os.Rename(path, filepath.Join(dir, "eve.json.1")); err != nil {
		t.Fatalf("rename: %v", err)
	}
	appendTo(t, path, "after rotate\n")

	if !waitFor(t, 5*time.Second, func() bool {
		for _, l := range c.snapshot() {
			if l == "after rotate" {
				return true
			}
		}
		return false
	}) {
		t.Fatalf("missed post-rotation line: %v", c.snapshot())
	}
}

// The file may not exist yet when the service starts (Suricata down) — which is
// exactly the state a stopped sensor leaves behind.
func TestTailerWaitsForMissingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "eve.json")

	c, stop := startTailer(t, path, "", false)
	defer stop()
	time.Sleep(300 * time.Millisecond)

	appendTo(t, path, "appeared\n")

	if !waitFor(t, 6*time.Second, func() bool { return len(c.snapshot()) >= 1 }) {
		t.Fatalf("did not pick up a file created after start")
	}
	if got := c.snapshot()[0]; got != "appeared" {
		t.Fatalf("got %q", got)
	}
}

// A restart must resume at the saved offset: no replay, no gap.
func TestTailerResumesFromState(t *testing.T) {
	if _, _, ok := fileID(fakeFileInfo(t)); !ok {
		t.Skip("file identity unavailable on this platform")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "eve.json")
	statePath := filepath.Join(dir, "state.json")
	appendTo(t, path, "line1\nline2\n")

	// First run: read from the start so state records both lines.
	c1, stop1 := startTailer(t, path, statePath, true)
	if !waitFor(t, 3*time.Second, func() bool { return len(c1.snapshot()) == 2 }) {
		stop1()
		t.Fatalf("first run got %v", c1.snapshot())
	}
	// State is flushed on shutdown.
	stop1()

	appendTo(t, path, "line3\n")

	// Second run: fromStart=false, but saved state should win and yield only line3.
	c2, stop2 := startTailer(t, path, statePath, false)
	defer stop2()
	if !waitFor(t, 3*time.Second, func() bool { return len(c2.snapshot()) >= 1 }) {
		t.Fatalf("second run read nothing")
	}
	time.Sleep(300 * time.Millisecond)
	got := c2.snapshot()
	if len(got) != 1 || got[0] != "line3" {
		t.Fatalf("expected exactly [line3] after resume, got %v", got)
	}
}

func fakeFileInfo(t *testing.T) os.FileInfo {
	t.Helper()
	f := filepath.Join(t.TempDir(), "probe")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(f)
	if err != nil {
		t.Fatal(err)
	}
	return fi
}

// An absurdly long line must be dropped without desynchronising the stream:
// the line after it still has to arrive intact.
func TestTailerDropsOversizedLineButStaysInSync(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "eve.json")
	appendTo(t, path, "")

	c, stop := startTailer(t, path, "", false)
	defer stop()
	time.Sleep(300 * time.Millisecond)

	appendTo(t, path, strings.Repeat("A", maxLineBytes+1024)+"\n")
	appendTo(t, path, "still here\n")

	if !waitFor(t, 8*time.Second, func() bool {
		for _, l := range c.snapshot() {
			if l == "still here" {
				return true
			}
		}
		return false
	}) {
		t.Fatalf("stream desynchronised after oversized line (%d lines seen)", len(c.snapshot()))
	}
	for _, l := range c.snapshot() {
		if len(l) > maxLineBytes {
			t.Fatalf("oversized line was delivered (%d bytes)", len(l))
		}
	}
}
