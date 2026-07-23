// Package nftably is the client for nftably's token-gated automation API — the
// one seam through which meerkat changes the network.
//
// meerkat never touches netfilter itself. Suricata here runs alert-only (its
// defaults dropped 9.6% of transit traffic on this router), so dropping is
// nftables' job, and nftably owns that decision. Everything in this package is
// an authenticated HTTP call to it; a compromise of the console cannot alter the
// firewall directly, and every attempt lands in meerkat's actions ledger.
//
// The API is nftably's internal/web/api.go. Its responses are deliberately
// distinguished here, because "already blocked", "queued for the next apply" and
// "in the kernel now" are three different truths and the console must not
// flatten them into a green tick.
package nftably

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// ErrNotConfigured is returned when no URL or token has been set. It is not a
// failure so much as a state: blocking is simply unavailable.
var ErrNotConfigured = errors.New("nftably is not configured")

// ErrUnauthorized means the token was rejected; ErrAPIDisabled means nftably has
// no token minted at all, so its API answers 404 rather than 401. Those need
// different fixes, so they are different errors.
var (
	ErrUnauthorized = errors.New("nftably rejected the API token")
	ErrAPIDisabled  = errors.New("nftably's automation API is disabled — no token has been minted in its Settings")
)

// Client talks to one nftably instance.
type Client struct {
	url   string
	token string
	http  *http.Client
	agent string
}

// New builds a client. A blank url or token yields a client whose every call
// returns ErrNotConfigured, so callers never have to nil-check it.
func New(url, token, userAgent string) *Client {
	return &Client{
		url:   strings.TrimRight(strings.TrimSpace(url), "/"),
		token: strings.TrimSpace(token),
		agent: userAgent,
		http:  &http.Client{Timeout: 15 * time.Second},
	}
}

// Configured reports whether blocking is available at all.
func (c *Client) Configured() bool { return c != nil && c.url != "" && c.token != "" }

// Result is what nftably said about a block.
type Result struct {
	// Address as nftably normalised it (a bare host or a masked prefix).
	Address string
	// Already is true when the address was in the set before this call.
	Already bool
	// InKernel is true when nftably pushed the change to the live kernel set,
	// false when it only recorded it for the next apply. The distinction
	// matters: only the first means traffic is being dropped right now.
	InKernel bool
	// Detail is nftably's own wording, kept verbatim for the ledger.
	Detail string
}

// Block adds an address to nftably's blacklist set.
func (c *Client) Block(ctx context.Context, ip, reason string) (Result, error) {
	if !c.Configured() {
		return Result{}, ErrNotConfigured
	}
	if _, err := netip.ParseAddr(ip); err != nil {
		// Refuse before the call: an unparseable address here would be a bug in
		// meerkat, and nftably's blacklist is not the place to discover it.
		return Result{}, fmt.Errorf("nftably: %q is not an IP address", ip)
	}

	var body struct {
		Blocked string `json:"blocked"`
		Already bool   `json:"already"`
		Note    string `json:"note"`
		Error   string `json:"error"`
	}
	if err := c.post(ctx, "/api/block", map[string]string{"ip": ip, "note": reason}, &body); err != nil {
		return Result{}, err
	}
	if body.Error != "" {
		return Result{}, fmt.Errorf("nftably rejected the block: %s", body.Error)
	}
	return Result{
		Address:  body.Blocked,
		Already:  body.Already,
		InKernel: strings.Contains(body.Note, "kernel"),
		Detail:   detailOf(body.Note, body.Already),
	}, nil
}

// Unblock removes an address from nftably's blacklist set.
func (c *Client) Unblock(ctx context.Context, ip string) (Result, error) {
	if !c.Configured() {
		return Result{}, ErrNotConfigured
	}
	// nftably answers {"unblocked": false, "reason": ...} when the address was
	// not on the list, which is a success from meerkat's point of view: the
	// address is not blocked, which is what was asked for.
	var body struct {
		Unblocked any    `json:"unblocked"`
		Reason    string `json:"reason"`
		Error     string `json:"error"`
	}
	if err := c.post(ctx, "/api/unblock", map[string]string{"ip": ip}, &body); err != nil {
		return Result{}, err
	}
	if body.Error != "" {
		return Result{}, fmt.Errorf("nftably rejected the unblock: %s", body.Error)
	}
	if addr, ok := body.Unblocked.(string); ok {
		return Result{Address: addr, Detail: "removed from the blacklist"}, nil
	}
	return Result{Address: ip, Already: true, Detail: orDefault(body.Reason, "was not blocked")}, nil
}

// Blocked lists the addresses currently in nftably's blacklist. It is what makes
// meerkat's "blocked" state verifiable rather than merely remembered.
func (c *Client) Blocked(ctx context.Context) ([]string, error) {
	if !c.Configured() {
		return nil, ErrNotConfigured
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url+"/api/blocked", nil)
	if err != nil {
		return nil, err
	}
	c.auth(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := statusError(resp); err != nil {
		return nil, err
	}

	var body struct {
		Blocked []struct{ IP, Note string } `json:"blocked"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&body); err != nil {
		return nil, fmt.Errorf("nftably: could not read the block list: %w", err)
	}
	out := make([]string, 0, len(body.Blocked))
	for _, b := range body.Blocked {
		out = append(out, b.IP)
	}
	return out, nil
}

func (c *Client) post(ctx context.Context, path string, payload map[string]string, into any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	c.auth(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := statusError(resp); err != nil {
		return err
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(into); err != nil {
		return fmt.Errorf("nftably: unreadable response: %w", err)
	}
	return nil
}

func (c *Client) auth(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("User-Agent", c.agent)
}

func statusError(resp *http.Response) error {
	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusUnauthorized:
		return ErrUnauthorized
	case http.StatusNotFound:
		return ErrAPIDisabled
	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<10))
		return fmt.Errorf("nftably returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
}

// detailOf turns nftably's note into the phrasing the ledger records.
func detailOf(note string, already bool) string {
	if already {
		return "already on the blacklist"
	}
	return orDefault(note, "added to the blacklist")
}

func orDefault(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}
