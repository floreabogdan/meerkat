//go:build !unix

package eve

import "io/fs"

// fileID has no portable equivalent off unix. Reporting ok=false makes the
// tailer treat every restart as "file replaced", which is safe: it only affects
// where a restart resumes, and this build exists solely for local development —
// meerkat's deployment target is Linux.
func fileID(fs.FileInfo) (dev, ino uint64, ok bool) {
	return 0, 0, false
}
