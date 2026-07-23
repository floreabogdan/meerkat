//go:build unix

package eve

import (
	"io/fs"
	"syscall"
)

// fileID returns the device and inode numbers identifying a file. They are
// persisted across restarts to tell "same file, more data" from "rotated".
func fileID(fi fs.FileInfo) (dev, ino uint64, ok bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return uint64(st.Dev), uint64(st.Ino), true
}
