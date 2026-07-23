package eve

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

const (
	pollInterval  = 250 * time.Millisecond
	reopenBackoff = 2 * time.Second
	// maxLineBytes guards against a corrupt/partial file making us buffer
	// forever. Suricata stats records are the biggest legitimate lines and run
	// well under 1 MB.
	maxLineBytes = 4 << 20
)

// state is persisted so a restart resumes where we stopped rather than
// replaying a 1 GB file or silently skipping whatever arrived while we were down.
type state struct {
	Offset int64  `json:"offset"`
	Inode  uint64 `json:"inode"`
	Dev    uint64 `json:"dev"`
	Size   int64  `json:"size"`
}

// Tailer follows a file the way `tail -F` does: it survives the file being
// truncated (Suricata restarting), rotated (logrotate), or missing entirely
// (Suricata stopped), and reports each complete line exactly once.
type Tailer struct {
	path      string
	statePath string
	fromStart bool
	log       *slog.Logger

	f      *os.File
	r      *bufio.Reader
	offset int64
	// pending holds a trailing fragment written without its newline yet, and
	// pendingLen counts that fragment's true size even when we stop buffering
	// it. offset advances only when a line completes, so a restart re-reads a
	// half-written record from its start rather than losing or splitting it.
	pending    []byte
	pendingLen int64
	// discard suppresses the remainder of a line that blew past maxLineBytes,
	// so its tail is never mistaken for a complete record of its own.
	discard bool
	// positioned records that the one-time "where do we start reading?"
	// decision has been made. Only that first decision may skip an existing
	// backlog by seeking to the end. Every file opened afterwards either
	// appeared, rotated, or was truncated while we were watching, so all of
	// its content is new and must be read from byte zero.
	positioned bool
}

// NewTailer follows path, persisting its read offset to statePath (empty
// disables resume). fromStart replays the file's existing contents instead of
// starting at its end.
func NewTailer(path, statePath string, fromStart bool, log *slog.Logger) *Tailer {
	return &Tailer{path: path, statePath: statePath, fromStart: fromStart, log: log}
}

// Run follows the file and calls fn for every complete line until ctx is done.
// fn must not retain the slice it is given.
func (t *Tailer) Run(ctx context.Context, fn func([]byte)) error {
	defer t.close()

	saveTicker := time.NewTicker(5 * time.Second)
	defer saveTicker.Stop()

	for {
		if err := ctx.Err(); err != nil {
			t.saveState()
			return nil
		}

		if t.f == nil {
			if err := t.open(); err != nil {
				if errors.Is(err, os.ErrNotExist) {
					// Suricata is not running yet. Whatever it eventually
					// creates is new in its entirety, so give up the right to
					// skip a backlog — there is none to skip.
					t.positioned = true
				} else {
					t.log.Warn("open eve.json failed", "path", t.path, "err", err)
				}
				if !sleepCtx(ctx, reopenBackoff) {
					t.saveState()
					return nil
				}
				continue
			}
		}

		n, err := t.readAvailable(fn)
		if err != nil {
			t.log.Warn("read eve.json failed, reopening", "err", err)
			t.close()
			if !sleepCtx(ctx, reopenBackoff) {
				return nil
			}
			continue
		}

		select {
		case <-saveTicker.C:
			t.saveState()
		default:
		}

		if n > 0 {
			continue // more may be waiting; don't sleep
		}

		// Caught up. Check whether the file was replaced or truncated under us
		// before going back to sleep.
		if err := t.checkRotation(); err != nil {
			t.log.Info("eve.json rotated or truncated, reopening", "reason", err)
			t.saveState()
			t.close()
			continue
		}
		if !sleepCtx(ctx, pollInterval) {
			t.saveState()
			return nil
		}
	}
}

// readAvailable drains every complete line currently buffered and returns how
// many it delivered.
func (t *Tailer) readAvailable(fn func([]byte)) (int, error) {
	count := 0
	for {
		chunk, err := t.r.ReadSlice('\n')
		switch {
		case err == nil:
			t.offset += t.pendingLen + int64(len(chunk))
			// The cap must be re-checked here, not just on the buffer-full
			// path: a line can cross the limit on the very chunk that carries
			// its newline, and would otherwise slip through whole.
			if t.discard || t.pendingLen+int64(len(chunk)) > maxLineBytes {
				if !t.discard {
					t.log.Warn("dropping oversized eve.json line",
						"limit_bytes", maxLineBytes,
						"seen_bytes", t.pendingLen+int64(len(chunk)))
				}
				t.resetLine() // newline terminates the oversized line
				continue
			}
			line := chunk
			if len(t.pending) > 0 {
				t.pending = append(t.pending, chunk...)
				line = t.pending
			}
			if trimmed := trimEOL(line); len(trimmed) > 0 {
				fn(trimmed)
			}
			t.resetLine()
			count++
			if count >= 10000 {
				return count, nil // yield so state gets saved periodically
			}

		case errors.Is(err, bufio.ErrBufferFull), errors.Is(err, io.EOF):
			// No newline yet: either the line is longer than the read buffer,
			// or Suricata has not finished writing it. Either way offset stays
			// put; only pendingLen grows.
			t.pendingLen += int64(len(chunk))
			if !t.discard {
				if t.pendingLen > maxLineBytes {
					t.log.Warn("dropping oversized eve.json line",
						"limit_bytes", maxLineBytes, "seen_bytes", t.pendingLen)
					t.discard = true
					t.pending = nil
				} else if len(chunk) > 0 {
					t.pending = append(t.pending, chunk...)
				}
			}
			if errors.Is(err, io.EOF) {
				return count, nil
			}

		default:
			return count, err
		}
	}
}

func (t *Tailer) open() error {
	f, err := os.Open(t.path)
	if err != nil {
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}

	// Anything opened after the first time is a file whose entire contents
	// arrived while we were watching, so none of it may be skipped.
	start := int64(0)
	if !t.positioned {
		// Cold start: default to the tail so a 1 GB backlog is not replayed.
		start = fi.Size()
		if t.fromStart {
			start = 0
		}

		// Resume from saved state only if it plausibly refers to this same file.
		if st, err := t.loadState(); err == nil {
			dev, ino, ok := fileID(fi)
			sameFile := ok && st.Dev == dev && st.Inode == ino
			switch {
			case sameFile && st.Offset <= fi.Size():
				start = st.Offset
			case sameFile:
				// File shrank while we were down: it was truncated in place.
				t.log.Info("eve.json truncated while stopped, restarting from 0",
					"saved_offset", st.Offset, "size", fi.Size())
				start = 0
			default:
				// Different file (rotated while we were down). The old content
				// is gone; take whatever this new file already holds.
				t.log.Info("eve.json replaced while stopped, reading new file from start",
					"size", fi.Size())
				start = 0
			}
		}
	}

	if _, err := f.Seek(start, io.SeekStart); err != nil {
		f.Close()
		return err
	}

	t.f = f
	t.r = bufio.NewReaderSize(f, 256<<10)
	t.offset = start
	t.positioned = true
	t.resetLine()
	t.log.Info("following eve.json", "path", t.path, "offset", start, "size", fi.Size())
	return nil
}

// checkRotation reports a non-nil reason when the open descriptor no longer
// corresponds to the live path, or the file was truncated beneath our offset.
func (t *Tailer) checkRotation() error {
	cur, err := t.f.Stat()
	if err != nil {
		return err
	}
	if cur.Size() < t.offset {
		return errors.New("truncated")
	}

	onDisk, err := os.Stat(t.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errors.New("path removed")
		}
		return err
	}
	if !os.SameFile(cur, onDisk) {
		return errors.New("replaced")
	}
	return nil
}

func (t *Tailer) resetLine() {
	t.pending = t.pending[:0]
	t.pendingLen = 0
	t.discard = false
}

func (t *Tailer) close() {
	if t.f != nil {
		t.f.Close()
		t.f = nil
		t.r = nil
	}
	t.resetLine()
}

func (t *Tailer) loadState() (*state, error) {
	if t.statePath == "" {
		return nil, os.ErrNotExist
	}
	b, err := os.ReadFile(t.statePath)
	if err != nil {
		return nil, err
	}
	var st state
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

func (t *Tailer) saveState() {
	if t.statePath == "" || t.f == nil {
		return
	}
	fi, err := t.f.Stat()
	if err != nil {
		return
	}
	dev, ino, _ := fileID(fi)
	st := state{Offset: t.offset, Inode: ino, Dev: dev, Size: fi.Size()}

	b, err := json.Marshal(st)
	if err != nil {
		return
	}
	// Write via a temp file + rename so a crash can never leave a half-written
	// state file that would be unparseable on restart.
	dir := filepath.Dir(t.statePath)
	tmp, err := os.CreateTemp(dir, ".state-*")
	if err != nil {
		t.log.Warn("cannot write state file", "path", t.statePath, "err", err)
		return
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return
	}
	if err := os.Rename(tmpName, t.statePath); err != nil {
		os.Remove(tmpName)
		t.log.Warn("cannot commit state file", "path", t.statePath, "err", err)
	}
}

func trimEOL(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
