package web

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/floreabogdan/meerkat/internal/geo"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static/*.css static/*.js static/fonts/*.woff2
var staticFS embed.FS

var funcs = template.FuncMap{
	// inc turns a 0-based range index into a 1-based position for human-facing
	// labels.
	"inc": func(i int) int { return i + 1 },
	// list builds a slice from its arguments, for ranging over a fixed set of
	// option values inline in a template.
	"list": func(items ...string) []string { return items },
	// rawURL marks an internally-constructed URL safe so html/template does not
	// re-escape its query string. Only ever used on URLs meerkat builds itself,
	// never on user input.
	"rawURL": func(s string) template.URL { return template.URL(s) },
	"fmttime": func(t time.Time) string {
		if t.IsZero() {
			return "—"
		}
		return t.Local().Format("2006-01-02 15:04:05")
	},
	// isotime feeds data-ts attributes so the client can render relative times
	// ("2m ago") that stay correct without reloads.
	"isotime": func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		return t.UTC().Format(time.RFC3339)
	},
	// duration renders a span between two timestamps compactly ("4m 12s"), for
	// how long a source has been active.
	"duration": func(from, to time.Time) string {
		if from.IsZero() || to.IsZero() {
			return "—"
		}
		return humanDuration(to.Sub(from))
	},
	// num groups thousands, because "891" and "320415" should be tellable apart
	// at a glance. It takes any integer type: the counters it renders are a mix
	// of int, int64 and uint64, and html/template will not convert between them.
	"num": humanNumber,
	// flag renders a country's flag emoji, or nothing for an unknown code.
	"flag": geo.FlagEmoji,
	// severityBadge colours a Suricata severity. Severity counts DOWN: 1 is the
	// most severe, 3 the least, and 0 means the alert carried none.
	"severityBadge": func(sev int) template.HTML {
		var class, label string
		switch sev {
		case 1:
			class, label = "badge-danger", "high"
		case 2:
			class, label = "badge-warning", "medium"
		case 3:
			class, label = "badge-info", "low"
		default:
			class, label = "badge", "—"
		}
		return template.HTML(`<span class="badge ` + class + `" title="Suricata severity ` +
			template.HTMLEscapeString(itoa(sev)) + `">` + label + `</span>`)
	},
	// stateBadge colours a source's triage state. "blocked" is the only one that
	// asserts something about the network, so it is the only one that looks like
	// an action was taken.
	"stateBadge": func(state string) template.HTML {
		class, label := "badge", state
		switch state {
		case "new":
			class, label = "badge-info", "new"
		case "acknowledged":
			class, label = "badge", "acknowledged"
		case "blocked":
			class, label = "badge-danger", "blocked"
		case "allowlisted":
			class, label = "badge-success", "allowlisted"
		}
		return template.HTML(`<span class="badge ` + class + `">` + template.HTMLEscapeString(label) + `</span>`)
	},
	// auditBadge colours a timeline entry by kind.
	"auditBadge": func(kind string) template.HTML {
		class, label := "badge", kind
		switch kind {
		case "login":
			class, label = "badge-info", "login"
		case "logout":
			class, label = "badge", "logout"
		case "settings_change":
			class, label = "badge-info", "settings"
		case "ingest_error":
			class, label = "badge-danger", "ingest"
		case "retention":
			class, label = "badge", "retention"
		case "source_change":
			class, label = "badge-warning", "triage"
		}
		return template.HTML(`<span class="badge ` + class + `">` + template.HTMLEscapeString(label) + `</span>`)
	},
	// pct is a share of a total, for the signature breakdown.
	//
	// Note there is deliberately no "render this as a bar width" helper here.
	// The obvious implementation is an inline style="width:…", and the Content
	// Security Policy this app sets (style-src 'self', no 'unsafe-inline')
	// blocks exactly that — the bar would silently render full-width in a real
	// browser while passing every server-side test. Proportional graphics use
	// <progress value=… max=…> or an SVG with geometry attributes instead;
	// both are CSP-clean and more accessible. TestNoInlineStyleInTemplates
	// guards the rule.
	"pct": func(n, total int64) string {
		if total == 0 {
			return "0%"
		}
		return fmt.Sprintf("%.1f%%", float64(n)/float64(total)*100)
	},
}

func humanNumber(v any) string {
	var s string
	switch n := v.(type) {
	case int:
		s = itoa(n)
	case int64:
		s = itoa64(n)
	case uint64:
		s = fmt.Sprintf("%d", n)
	case uint32:
		s = fmt.Sprintf("%d", n)
	default:
		s = fmt.Sprintf("%v", v)
	}
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}

func humanDuration(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
	default:
		return fmt.Sprintf("%dd %dh", int(d.Hours())/24, int(d.Hours())%24)
	}
}

func itoa(n int) string     { return fmt.Sprintf("%d", n) }
func itoa64(n int64) string { return fmt.Sprintf("%d", n) }

var tmpl = template.Must(template.New("").Funcs(funcs).ParseFS(templateFS, "templates/*.html"))

func render(w http.ResponseWriter, log *slog.Logger, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, name, data); err != nil {
		log.Error("template render failed", "template", name, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

func staticHandler() http.Handler {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err)
	}
	return http.FileServerFS(sub)
}
