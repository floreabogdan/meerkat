//go:build unix

package suricata

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeSuricata speaks Suricata's unix command protocol: a version handshake,
// then one JSON object per command.
//
// It enforces the framing the real sensor enforces. Messages are newline
// terminated, and a client that omits the terminator gets exactly what Suricata
// gives it — silence, then a closed connection. meerkat shipped without that
// newline and every reload failed with an unexplained EOF, so this fake reads
// lines rather than "whatever turned up in one packet": a fake that tolerates a
// malformed client is a fake that certifies a broken one.
//
// acceptVersion is the protocol version it will accept; anything else is
// refused the way the real one refuses.
func fakeSuricata(t *testing.T, acceptVersion string, reply func(cmd string) Reply) string {
	t.Helper()
	// Unix socket paths are limited to ~108 bytes and t.TempDir() can be longer
	// than that on some runners.
	dir, err := os.MkdirTemp("", "sc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "cmd.sock")

	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	send := func(conn net.Conn, r Reply) {
		b, err := json.Marshal(r)
		if err != nil {
			return
		}
		_, _ = conn.Write(append(b, '\n'))
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				lines := bufio.NewReader(conn)

				line, err := lines.ReadBytes('\n')
				if err != nil {
					return // unterminated: the real one hangs up too
				}
				var handshake struct {
					Version string `json:"version"`
				}
				if json.Unmarshal(line, &handshake) != nil {
					return
				}
				if handshake.Version != acceptVersion {
					send(conn, Reply{Return: "NOK", Message: json.RawMessage(`"unknown protocol version"`)})
					return // and the connection closes, as Suricata's does
				}
				send(conn, Reply{Return: "OK"})

				line, err = lines.ReadBytes('\n')
				if err != nil {
					return
				}
				var req struct {
					Command string `json:"command"`
				}
				if json.Unmarshal(line, &req) != nil {
					return
				}
				send(conn, reply(req.Command))
			}()
		}
	}()
	return path
}

func TestReloadTalksToSuricata(t *testing.T) {
	var got string
	path := fakeSuricata(t, protocolVersion, func(cmd string) Reply {
		got = cmd
		return Reply{Return: "OK", Message: json.RawMessage(`"done"`)}
	})

	ctl := NewControl(path, 5*time.Second)
	if !ctl.Available() {
		t.Fatal("a listening socket reported as unavailable")
	}
	reply, err := ctl.Reload(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !reply.OK() {
		t.Errorf("reply = %+v", reply)
	}
	if reply.Text() != "done" {
		t.Errorf("text = %q", reply.Text())
	}
	// The blocking form, deliberately: the non-blocking one always answers OK
	// immediately, so meerkat would report "reloaded" for a ruleset Suricata
	// went on to reject.
	if got != CommandReload {
		t.Errorf("sent %q, want %q", got, CommandReload)
	}
}

func TestReloadSurfacesARefusal(t *testing.T) {
	path := fakeSuricata(t, protocolVersion, func(string) Reply {
		return Reply{Return: "NOK", Message: json.RawMessage(`"Live rule reload failed"`)}
	})
	reply, err := NewControl(path, 5*time.Second).Reload(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if reply.OK() {
		t.Error("a refusal was reported as success")
	}
	if reply.Text() != "Live rule reload failed" {
		t.Errorf("text = %q, want Suricata's own words", reply.Text())
	}
}

// A rejected handshake has to be reported as itself.
//
// Suricata closes the connection after refusing a version, so a client that
// ignores the handshake reply reports the *next* command failing with a bare
// EOF. That is precisely how a one-byte framing bug survived a deployment: the
// error said "no reply: EOF" on a socket that had answered a moment earlier,
// which points at everything except the missing terminator.
func TestHandshakeRefusalIsReportedAsItself(t *testing.T) {
	path := fakeSuricata(t, "9.9", func(string) Reply { return Reply{Return: "OK"} })

	_, err := NewControl(path, 5*time.Second).Reload(context.Background())
	if err == nil {
		t.Fatal("a refused protocol version returned no error")
	}
	if !strings.Contains(err.Error(), "protocol version") {
		t.Errorf("error = %q, want it to name the protocol version rather than an EOF", err)
	}
}

// The other bug this file guards. A stopped Suricata leaves its socket file on
// disk: the path exists, the socket mode bit is still set, and every connection
// is refused. Checking only for the file made the console report a running
// sensor for three hours after the sensor had been stopped — and would have let
// it claim a rule change was reloaded when nothing loaded it.
func TestAvailableIsFalseForAStaleSocketFile(t *testing.T) {
	dir, err := os.MkdirTemp("", "sc")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "cmd.sock")

	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	ctl := NewControl(path, 2*time.Second)
	if !ctl.Available() {
		t.Fatal("a live socket reported as unavailable")
	}

	// Suricata stops. Go's listener unlinks the path on Close, so put the file
	// back exactly as a killed process leaves it.
	unix := ln.(*net.UnixListener)
	unix.SetUnlinkOnClose(false)
	ln.Close()

	fi, err := os.Stat(path)
	if err != nil {
		t.Skipf("could not leave a stale socket behind on this platform: %v", err)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		t.Skip("the stale path is not a socket on this platform")
	}
	if ctl.Available() {
		t.Error("a socket file with nothing listening reported the sensor as running")
	}
	if _, err := ctl.Reload(context.Background()); err == nil {
		t.Error("Reload against a stale socket returned no error")
	}
}

func TestAvailableIsFalseForARegularFileOrAMissingPath(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "not-a-socket")
	if err := os.WriteFile(regular, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if NewControl(regular, time.Second).Available() {
		t.Error("a regular file reported as a control socket")
	}
	if NewControl(filepath.Join(dir, "absent"), time.Second).Available() {
		t.Error("a missing path reported as a control socket")
	}
	if NewControl("", time.Second).Available() {
		t.Error("an empty path reported as a control socket")
	}
}
