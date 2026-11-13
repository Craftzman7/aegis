//go:build !linux

package collector

import "io/fs"

func fileUID(fs.FileInfo) int { return 0 }
