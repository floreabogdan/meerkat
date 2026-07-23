// Package eve reads Suricata's eve.json: the `tail -F` follower that survives
// rotation, truncation and Suricata being down, and the record decoder that sits
// behind a prefilter cheap enough to run on every line of a multi-gigabyte file.
//
// Lifted from the throwaway predecessor (eve-discord) with its tests, which is
// where the rotation/truncation/partial-line semantics were worked out against a
// live router.
package eve

import (
	"bytes"
	"encoding/json"
	"time"
)

// Event is the subset of a Suricata eve.json alert record meerkat stores.
// Fields Suricata omits simply stay zero; nothing here is required.
type Event struct {
	Timestamp string `json:"timestamp"`
	FlowID    int64  `json:"flow_id"`
	EventType string `json:"event_type"`
	InIface   string `json:"in_iface"`
	SrcIP     string `json:"src_ip"`
	SrcPort   int    `json:"src_port"`
	DestIP    string `json:"dest_ip"`
	DestPort  int    `json:"dest_port"`
	Proto     string `json:"proto"`
	AppProto  string `json:"app_proto"`
	Direction string `json:"direction"`

	Alert struct {
		Action      string `json:"action"`
		GID         int    `json:"gid"`
		SignatureID int    `json:"signature_id"`
		Rev         int    `json:"rev"`
		Signature   string `json:"signature"`
		Category    string `json:"category"`
		Severity    int    `json:"severity"`
	} `json:"alert"`

	Flow struct {
		PktsToServer  int64 `json:"pkts_toserver"`
		PktsToClient  int64 `json:"pkts_toclient"`
		BytesToServer int64 `json:"bytes_toserver"`
		BytesToClient int64 `json:"bytes_toclient"`
	} `json:"flow"`

	HTTP *struct {
		Hostname  string `json:"hostname"`
		URL       string `json:"url"`
		UserAgent string `json:"http_user_agent"`
		Method    string `json:"http_method"`
		Status    int    `json:"status"`
	} `json:"http,omitempty"`

	TLS *struct {
		SNI     string `json:"sni"`
		Subject string `json:"subject"`
		Version string `json:"version"`
	} `json:"tls,omitempty"`

	DNS *struct {
		RRName string `json:"rrname"`
		RRType string `json:"rrtype"`
	} `json:"dns,omitempty"`

	SSH *struct {
		Client struct {
			SoftwareVersion string `json:"software_version"`
		} `json:"client"`
	} `json:"ssh,omitempty"`
}

// Time parses the eve timestamp, falling back to now if Suricata wrote
// something unexpected. The alert is worth recording either way.
func (e *Event) Time() time.Time {
	if e.Timestamp == "" {
		return time.Now()
	}
	// Suricata emits RFC3339 with microseconds and a numeric zone offset.
	if t, err := time.Parse("2006-01-02T15:04:05.999999-0700", e.Timestamp); err == nil {
		return t
	}
	if t, err := time.Parse(time.RFC3339Nano, e.Timestamp); err == nil {
		return t
	}
	return time.Now()
}

var eventTypeKey = []byte(`"event_type"`)

// TypeOf pulls event_type out of a raw eve line without unmarshalling it.
// Nearly every line in a busy eve.json is a flow or stats record, and full JSON
// decoding of a 40 KB stats blob just to discard it dominates the whole
// program's cost. Returns "" when the key is absent or malformed.
func TypeOf(line []byte) string {
	i := bytes.Index(line, eventTypeKey)
	if i < 0 {
		return ""
	}
	p := line[i+len(eventTypeKey):]

	// skip whitespace, then ':', then whitespace, then the opening quote
	j := 0
	for j < len(p) && isJSONSpace(p[j]) {
		j++
	}
	if j >= len(p) || p[j] != ':' {
		return ""
	}
	j++
	for j < len(p) && isJSONSpace(p[j]) {
		j++
	}
	if j >= len(p) || p[j] != '"' {
		return ""
	}
	j++
	end := bytes.IndexByte(p[j:], '"')
	if end < 0 {
		return ""
	}
	// event_type values are plain lowercase identifiers, so no escape handling.
	return string(p[j : j+end])
}

func isJSONSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

// Parse decodes one eve.json line into an Event.
func Parse(line []byte) (*Event, error) {
	var e Event
	if err := json.Unmarshal(line, &e); err != nil {
		return nil, err
	}
	return &e, nil
}
