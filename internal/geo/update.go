package geo

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"
)

// DB-IP publishes free Lite databases monthly under a predictable name.
// They are MaxMind-format and compatible with the GeoLite2 readers.
const dbipURLTemplate = "https://download.db-ip.com/free/dbip-%s-lite-%04d-%02d.mmdb.gz"

// Decompression guard: the country DB is ~8 MB and the city DB ~100 MB, so
// this leaves generous headroom while still bounding a hostile response.
const maxDBBytes = 512 << 20

// Kind is a DB-IP Lite database meerkat knows how to fetch.
type Kind string

const (
	KindASN     Kind = "asn"
	KindCountry Kind = "country"
	KindCity    Kind = "city"
)

// Filename is the on-disk name for a kind, matching DB-IP's own naming so a
// manually downloaded file drops straight in.
func (k Kind) Filename() string { return fmt.Sprintf("dbip-%s-lite.mmdb", k) }

// Updater keeps a local copy of the DB-IP Lite databases current.
//
// Owning the download makes meerkat self-contained: it needs no read access to
// another service's data directory, and it can fetch the city database, which
// nothing else on the router maintains. This is the only thing that ever makes
// meerkat reach the network, and it is opt-in.
type Updater struct {
	dir    string
	client *http.Client
	log    *slog.Logger
	ua     string
}

// NewUpdater manages the databases under dir. userAgent identifies meerkat to
// DB-IP (the version string, so a misbehaving build is attributable).
func NewUpdater(dir, userAgent string, log *slog.Logger) *Updater {
	return &Updater{
		dir: dir,
		log: log,
		ua:  userAgent,
		client: &http.Client{
			Timeout: 15 * time.Minute, // the city database is ~100 MB
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				// Never let a redirect downgrade us to plaintext.
				if req.URL.Scheme != "https" {
					return errors.New("refusing redirect to non-https URL")
				}
				if len(via) >= 5 {
					return errors.New("too many redirects")
				}
				return nil
			},
		},
	}
}

// Path is where a given database lives on disk.
func (u *Updater) Path(k Kind) string { return filepath.Join(u.dir, k.Filename()) }

// Ensure downloads each requested database if it is missing or older than
// maxAge. A failure to refresh an existing file is not fatal: a month-old
// database is far better than none.
func (u *Updater) Ensure(ctx context.Context, kinds []Kind, maxAge time.Duration) error {
	if err := os.MkdirAll(u.dir, 0o750); err != nil {
		return fmt.Errorf("create geoip dir: %w", err)
	}

	var firstErr error
	for _, k := range kinds {
		path := u.Path(k)
		fresh, age := isFresh(path, maxAge)
		if fresh {
			u.log.Debug("geoip database is current", "kind", k, "age", age.Round(time.Hour))
			continue
		}

		u.log.Info("downloading geoip database", "kind", k, "dest", path)
		if err := u.download(ctx, k, path); err != nil {
			if _, statErr := os.Stat(path); statErr == nil {
				// We still have the previous copy; carry on with it.
				u.log.Warn("geoip refresh failed, keeping existing copy",
					"kind", k, "age", age.Round(time.Hour), "err", err)
				continue
			}
			u.log.Error("geoip download failed and no local copy exists", "kind", k, "err", err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		u.log.Info("geoip database updated", "kind", k)
	}
	return firstErr
}

func isFresh(path string, maxAge time.Duration) (bool, time.Duration) {
	fi, err := os.Stat(path)
	if err != nil {
		return false, 0
	}
	age := time.Since(fi.ModTime())
	return age < maxAge, age
}

// download fetches this month's database, falling back to last month's because
// DB-IP publishes a few days into each month.
func (u *Updater) download(ctx context.Context, k Kind, dest string) error {
	now := time.Now().UTC()
	attempts := []time.Time{now, now.AddDate(0, -1, 0)}

	var lastErr error
	for _, t := range attempts {
		url := fmt.Sprintf(dbipURLTemplate, k, t.Year(), int(t.Month()))
		err := u.fetchTo(ctx, url, dest)
		if err == nil {
			return nil
		}
		lastErr = err
		u.log.Debug("geoip fetch attempt failed", "url", url, "err", err)
	}
	return lastErr
}

func (u *Updater) fetchTo(ctx context.Context, url, dest string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", u.ua)

	resp, err := u.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}

	zr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("gzip: %w", err)
	}
	defer zr.Close()

	// Write to a temp file beside the target so the rename is atomic and a
	// half-downloaded database is never opened.
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".dbip-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once renamed

	n, err := io.Copy(tmp, io.LimitReader(zr, maxDBBytes+1))
	if err != nil {
		tmp.Close()
		return fmt.Errorf("download: %w", err)
	}
	if n > maxDBBytes {
		tmp.Close()
		return fmt.Errorf("database exceeds %d bytes", maxDBBytes)
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	// Validate before publishing: a truncated or wrong-format file must not
	// replace a working database.
	r, err := maxminddb.Open(tmpName)
	if err != nil {
		return fmt.Errorf("downloaded file is not a valid mmdb: %w", err)
	}
	dbType := r.Metadata.DatabaseType
	r.Close()

	if err := os.Chmod(tmpName, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmpName, dest); err != nil {
		return err
	}
	u.log.Debug("geoip database installed", "path", dest, "type", dbType, "bytes", n)
	return nil
}
