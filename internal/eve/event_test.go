package eve

import (
	"testing"

	"github.com/floreabogdan/meerkat/internal/eve/evetest"
)

func TestTypeOf(t *testing.T) {
	tests := []struct {
		name string
		line string
		want string
	}{
		{"compact", `{"timestamp":"x","event_type":"alert","src_ip":"1.1.1.1"}`, "alert"},
		{"first key", `{"event_type":"flow"}`, "flow"},
		{"spaced", `{"event_type" : "stats"}`, "stats"},
		{"absent", `{"timestamp":"x","src_ip":"1.1.1.1"}`, ""},
		{"not json", `garbage`, ""},
		{"empty", ``, ""},
		{"truncated after key", `{"event_type"`, ""},
		{"truncated in value", `{"event_type":"ale`, ""},
		{"no colon", `{"event_type" "alert"}`, ""},
		{"value not a string", `{"event_type":123}`, ""},
		// A value inside some other string must not be mistaken for the key.
		{"lookalike in payload", `{"payload":"event_type:alert","event_type":"dns"}`, "dns"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := TypeOf([]byte(tc.line)); got != tc.want {
				t.Errorf("TypeOf(%q) = %q, want %q", tc.line, got, tc.want)
			}
		})
	}
}

// TypeOf is the filter that every line in a 1 GB file passes through, so it
// must agree with a full JSON decode on real data.
func TestTypeOfMatchesFullParseOnRealAlerts(t *testing.T) {
	lines := RealAlertLines(t)
	for i, line := range lines {
		fast := TypeOf([]byte(line))
		ev, err := Parse([]byte(line))
		if err != nil {
			t.Fatalf("line %d: real eve.json line failed to parse: %v", i, err)
		}
		if fast != ev.EventType {
			t.Errorf("line %d: fast path said %q, decoder said %q", i, fast, ev.EventType)
		}
	}
	t.Logf("checked %d real alert lines", len(lines))
}

func TestParseRealAlert(t *testing.T) {
	lines := RealAlertLines(t)
	ev, err := Parse([]byte(lines[0]))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if ev.EventType != "alert" {
		t.Errorf("event_type = %q", ev.EventType)
	}
	if ev.SrcIP == "" || ev.DestIP == "" {
		t.Errorf("missing addresses: src=%q dest=%q", ev.SrcIP, ev.DestIP)
	}
	if ev.Alert.SignatureID == 0 {
		t.Error("signature_id not decoded")
	}
	if ev.Time().IsZero() {
		t.Error("timestamp not decoded")
	}
	// Suricata's timestamp format must parse, not silently fall back to now().
	if ev.Time().Year() < 2000 {
		t.Errorf("implausible timestamp: %v", ev.Time())
	}
}

func TestTimeParsing(t *testing.T) {
	// The format Suricata actually writes: microseconds, numeric zone, no colon.
	ev := &Event{Timestamp: "2026-07-20T16:58:09.531955+0300"}
	got := ev.Time()
	if got.Year() != 2026 || got.Month() != 7 || got.Day() != 20 {
		t.Errorf("wrong date: %v", got)
	}
	if got.Hour() != 16 || got.Minute() != 58 {
		t.Errorf("wrong time: %v", got)
	}
	_, offset := got.Zone()
	if offset != 3*3600 {
		t.Errorf("wrong zone offset: %d", offset)
	}
}

func TestTimeFallsBackOnGarbage(t *testing.T) {
	ev := &Event{Timestamp: "not a timestamp"}
	if ev.Time().IsZero() {
		t.Error("expected a usable fallback time, got zero")
	}
}

func RealAlertLines(t *testing.T) []string { return evetest.AlertLines(t) }
