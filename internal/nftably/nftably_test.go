package nftably

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// fake stands in for nftably, applying the same rules its real handler does.
type fake struct {
	token   string
	blocked map[string]bool
	// inKernel mirrors nftably's own distinction: it pushes to the live set when
	// the model is otherwise in sync, and otherwise only records the change.
	inKernel bool
	status   int
	srv      *httptest.Server
	calls    int
}

func newFake(t *testing.T, token string) *fake {
	t.Helper()
	f := &fake{token: token, blocked: map[string]bool{}, inKernel: true}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls++
		if f.status != 0 {
			w.WriteHeader(f.status)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+f.token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var body struct{ IP, Note string }
		if r.Method == http.MethodPost {
			_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
		}
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/block":
			if body.IP == "" {
				_ = json.NewEncoder(w).Encode(map[string]any{"error": "enter an IP address or CIDR"})
				return
			}
			if f.blocked[body.IP] {
				_ = json.NewEncoder(w).Encode(map[string]any{"blocked": body.IP, "already": true})
				return
			}
			f.blocked[body.IP] = true
			note := "takes effect on the next apply"
			if f.inKernel {
				note = "applied to the kernel"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"blocked": body.IP, "note": note})
		case "/api/unblock":
			if !f.blocked[body.IP] {
				_ = json.NewEncoder(w).Encode(map[string]any{"unblocked": false, "reason": "not in the block list"})
				return
			}
			delete(f.blocked, body.IP)
			_ = json.NewEncoder(w).Encode(map[string]any{"unblocked": body.IP})
		case "/api/blocked":
			list := []map[string]string{}
			for ip := range f.blocked {
				list = append(list, map[string]string{"ip": ip, "note": "blocked via API"})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"blocked": list})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func client(f *fake, token string) *Client {
	return New(f.srv.URL, token, "meerkat/test")
}

func TestBlockAndUnblock(t *testing.T) {
	f := newFake(t, "secret")
	c := client(f, "secret")
	ctx := context.Background()

	res, err := c.Block(ctx, "198.51.100.7", "scanning ssh")
	if err != nil {
		t.Fatalf("block: %v", err)
	}
	if res.Address != "198.51.100.7" || res.Already {
		t.Errorf("block result = %+v", res)
	}
	if !res.InKernel {
		t.Error("nftably said it applied to the kernel; that must not be lost")
	}

	// A second block is not an error — it is "already", and the console must be
	// able to say so rather than claiming it just did something.
	res, err = c.Block(ctx, "198.51.100.7", "scanning ssh")
	if err != nil {
		t.Fatalf("re-block: %v", err)
	}
	if !res.Already {
		t.Error("a repeat block should report Already")
	}

	res, err = c.Unblock(ctx, "198.51.100.7")
	if err != nil {
		t.Fatalf("unblock: %v", err)
	}
	if res.Already {
		t.Errorf("unblock of a blocked address reported Already: %+v", res)
	}
	if list, _ := c.Blocked(ctx); len(list) != 0 {
		t.Errorf("still blocked: %v", list)
	}
}

// Queued and live are different truths, and the ledger has to keep them apart.
func TestPendingApplyIsNotReportedAsLive(t *testing.T) {
	f := newFake(t, "secret")
	f.inKernel = false
	res, err := client(f, "secret").Block(context.Background(), "198.51.100.7", "")
	if err != nil {
		t.Fatalf("block: %v", err)
	}
	if res.InKernel {
		t.Error("a block awaiting apply was reported as live in the kernel")
	}
	if res.Detail == "" {
		t.Error("nftably's own wording should be kept for the ledger")
	}
}

// Unblocking something that was never blocked is the desired end state, not a
// failure — the address is not blocked.
func TestUnblockOfUnknownAddressSucceeds(t *testing.T) {
	f := newFake(t, "secret")
	res, err := client(f, "secret").Unblock(context.Background(), "203.0.113.9")
	if err != nil {
		t.Fatalf("unblock: %v", err)
	}
	if !res.Already {
		t.Error("expected Already for an address that was not on the list")
	}
}

func TestBlockedListsCurrentState(t *testing.T) {
	f := newFake(t, "secret")
	c := client(f, "secret")
	ctx := context.Background()
	for _, ip := range []string{"198.51.100.7", "203.0.113.49"} {
		if _, err := c.Block(ctx, ip, ""); err != nil {
			t.Fatalf("block %s: %v", ip, err)
		}
	}
	list, err := c.Blocked(ctx)
	if err != nil {
		t.Fatalf("blocked: %v", err)
	}
	if len(list) != 2 {
		t.Errorf("got %v, want 2 addresses", list)
	}
}

// The two auth failures need different fixes, so they must not collapse into
// one error: 401 is a wrong token, 404 is an API that was never switched on.
func TestAuthFailuresAreDistinguished(t *testing.T) {
	f := newFake(t, "secret")
	if _, err := client(f, "wrong").Block(context.Background(), "198.51.100.7", ""); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("bad token gave %v, want ErrUnauthorized", err)
	}

	f.status = http.StatusNotFound
	if _, err := client(f, "secret").Block(context.Background(), "198.51.100.7", ""); !errors.Is(err, ErrAPIDisabled) {
		t.Errorf("disabled API gave %v, want ErrAPIDisabled", err)
	}
}

func TestUnconfiguredClientIsUsable(t *testing.T) {
	c := New("", "", "meerkat/test")
	if c.Configured() {
		t.Error("a blank client should not report itself configured")
	}
	if _, err := c.Block(context.Background(), "198.51.100.7", ""); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("got %v, want ErrNotConfigured", err)
	}
	if _, err := c.Blocked(context.Background()); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("got %v, want ErrNotConfigured", err)
	}
}

// A malformed address must never reach nftably's blacklist.
func TestGarbageAddressIsRejectedLocally(t *testing.T) {
	f := newFake(t, "secret")
	c := client(f, "secret")
	before := f.calls
	if _, err := c.Block(context.Background(), "not-an-address", ""); err == nil {
		t.Fatal("expected a rejection")
	}
	if f.calls != before {
		t.Error("a malformed address was sent to nftably instead of being refused locally")
	}
}
