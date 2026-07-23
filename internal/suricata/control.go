package suricata

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"syscall"
	"time"
)

// Suricata's unix command protocol, as spoken by suricatasc. The client opens
// the socket, sends a version, and gets an "OK" back; after that each command is
// one JSON object and each reply is another.
//
// Messages are newline terminated. That one byte is the whole protocol's
// framing and omitting it does not produce an error — Suricata simply waits for
// a message that never completes and eventually hangs up, so the client sees an
// EOF on a socket that answered its handshake a moment before.
const (
	protocolVersion = "0.2"

	// CommandReload rebuilds the detection engine from the rules on disk while
	// Suricata keeps forwarding packets. This is the whole reason meerkat can
	// change rules on a live edge router at all: the alternative is restarting
	// the sensor, and Suricata sits inline on NFQUEUE here.
	CommandReload = "ruleset-reload-rules"

	// CommandStats reports how the last reload went.
	CommandStats = "ruleset-stats"
)

// ErrNoSocket means Suricata's command socket is not there: either the sensor
// is stopped, or unix-command is disabled in suricata.yaml. The two are worth
// telling apart in the UI, so it is a distinct error rather than a dial failure.
var ErrNoSocket = errors.New("suricata's command socket is not available")

// Control talks to a running Suricata over its unix command socket.
type Control struct {
	Path    string
	Timeout time.Duration
}

// NewControl returns a client for the socket at path.
func NewControl(path string, timeout time.Duration) *Control {
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	return &Control{Path: path, Timeout: timeout}
}

// Reach is how the control socket answered a probe. The three failures are
// genuinely different situations with different fixes, and collapsing them into
// "not running" sends the operator to restart a sensor that is running fine.
type Reach int

const (
	// ReachOK: connected. Suricata is running and will take commands.
	ReachOK Reach = iota
	// ReachAbsent: no socket at all — Suricata is stopped, or unix-command is
	// disabled in suricata.yaml.
	ReachAbsent
	// ReachRefused: the socket file is there but nothing is listening. A
	// stopped Suricata leaves its socket behind, so this is the usual shape of
	// "it died".
	ReachRefused
	// ReachDenied: something is listening and we are not allowed to talk to it.
	// Suricata creates the socket 0660 root:root, and meerkat's console runs
	// unprivileged — so this is the normal state for the console, and it does
	// NOT mean the sensor is unhealthy. The privileged apply step runs as root
	// and reaches it fine.
	ReachDenied
)

// Probe reports whether the control socket can be reached, and why not.
//
// It connects rather than only stat-ing the path, because a stopped Suricata
// leaves its socket file behind: the path still exists, the socket mode bit is
// still set, and every connection is refused. Checking only for the file made
// the console report a running sensor for three hours after the sensor had been
// stopped.
func (c *Control) Probe() (Reach, error) {
	if c.Path == "" {
		return ReachAbsent, errors.New("no control socket configured")
	}
	fi, err := os.Stat(c.Path)
	if err != nil {
		if os.IsPermission(err) {
			return ReachDenied, err
		}
		return ReachAbsent, err
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return ReachAbsent, fmt.Errorf("%s is not a socket", c.Path)
	}
	// Short: this runs on every page render, and a local unix socket either
	// accepts or fails immediately.
	conn, err := net.DialTimeout("unix", c.Path, 2*time.Second)
	if err != nil {
		if errors.Is(err, fs.ErrPermission) || errors.Is(err, syscall.EACCES) {
			return ReachDenied, err
		}
		return ReachRefused, err
	}
	_ = conn.Close()
	return ReachOK, nil
}

// Available reports whether a command sent now would be answered.
func (c *Control) Available() bool {
	r, _ := c.Probe()
	return r == ReachOK
}

// Reply is Suricata's answer to a command.
type Reply struct {
	Return  string          `json:"return"`
	Message json.RawMessage `json:"message"`
}

// OK reports whether Suricata accepted the command.
func (r Reply) OK() bool { return r.Return == "OK" }

// Text renders the message for a human, whether Suricata sent a bare string or
// a structure.
func (r Reply) Text() string {
	if len(r.Message) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(r.Message, &s); err == nil {
		return s
	}
	return string(r.Message)
}

// Reload asks Suricata to rebuild its detection engine from the rules on disk.
//
// It uses the blocking form deliberately. The non-blocking one returns
// immediately and always says OK, which would let meerkat report "reloaded"
// for a ruleset Suricata went on to reject — the sensor would keep running the
// old rules and the console would show the new ones. Waiting costs a few
// seconds of one background goroutine and buys an answer that is true.
func (c *Control) Reload(ctx context.Context) (Reply, error) {
	return c.Command(ctx, CommandReload, nil)
}

// Command sends one command and returns Suricata's reply.
func (c *Control) Command(ctx context.Context, cmd string, args map[string]any) (Reply, error) {
	if c.Path == "" {
		return Reply{}, fmt.Errorf("%w: none configured", ErrNoSocket)
	}
	// One connection, not a probe followed by a real one: the dial error already
	// says everything a pre-check could, and classifying it here keeps the
	// distinction between "stopped" and "not allowed to talk to it".
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "unix", c.Path)
	if err != nil {
		if errors.Is(err, fs.ErrPermission) || errors.Is(err, syscall.EACCES) {
			return Reply{}, fmt.Errorf("suricata: not allowed to open %s — it is created 0660 root:root, and this process is not root: %w", c.Path, err)
		}
		if errors.Is(err, fs.ErrNotExist) {
			return Reply{}, fmt.Errorf("%w at %s — suricata is stopped, or unix-command is disabled in suricata.yaml", ErrNoSocket, c.Path)
		}
		return Reply{}, fmt.Errorf("suricata: connect to %s: %w", c.Path, err)
	}
	defer conn.Close()

	deadline := time.Now().Add(c.Timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)

	// The handshake. Suricata answers this before it will accept anything else,
	// and the answer is CHECKED — a rejected version closes the connection, so
	// ignoring it here turns a clear "wrong protocol version" into an
	// unexplained EOF on the next command, which is exactly how the newline
	// above went undiagnosed for as long as it did.
	hello, err := send(conn, map[string]any{"version": protocolVersion})
	if err != nil {
		return Reply{}, fmt.Errorf("suricata: handshake: %w", err)
	}
	if !hello.OK() {
		return Reply{}, fmt.Errorf("suricata: refused protocol version %s: %s", protocolVersion, hello.Text())
	}

	payload := map[string]any{"command": cmd}
	if len(args) > 0 {
		payload["arguments"] = args
	}
	reply, err := send(conn, payload)
	if err != nil {
		return Reply{}, fmt.Errorf("suricata: %s: %w", cmd, err)
	}
	return reply, nil
}

// send writes one JSON object and reads one back.
func send(conn net.Conn, payload map[string]any) (Reply, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return Reply{}, err
	}
	// The newline is the message terminator, and leaving it off is not a
	// cosmetic difference: under protocol 0.2 Suricata waits for it, never
	// sees a complete message, and closes the connection. The symptom is an
	// EOF on a socket that answered the handshake a moment earlier, which
	// looks like anything but a missing byte. (Suricata terminates its own
	// replies the same way — that trailing "\n" on its OK is the tell.)
	b = append(b, '\n')
	if _, err := conn.Write(b); err != nil {
		return Reply{}, err
	}

	// Read until what has arrived parses as a complete JSON value. Suricata
	// terminates its replies with a newline, which json.Unmarshal accepts as
	// trailing whitespace — and parsing rather than scanning for the delimiter
	// also copes with the older protocol version, which does not send one.
	var buf []byte
	chunk := make([]byte, 8192)
	for {
		n, err := conn.Read(chunk)
		if n > 0 {
			buf = append(buf, chunk[:n]...)
			var r Reply
			if json.Unmarshal(buf, &r) == nil {
				return r, nil
			}
		}
		if err != nil {
			if len(buf) == 0 {
				return Reply{}, fmt.Errorf("no reply: %w", err)
			}
			return Reply{}, fmt.Errorf("truncated reply %q: %w", string(buf), err)
		}
		if len(buf) > 1<<20 {
			return Reply{}, errors.New("reply too large")
		}
	}
}
