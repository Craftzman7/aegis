//go:build linux

package collector

import (
	"io/fs"
	"syscall"
)

func fileUID(st fs.FileInfo) int {
	if s, ok := st.Sys().(*syscall.Stat_t); ok {
		return int(s.Uid)
	}
	return 0
}
