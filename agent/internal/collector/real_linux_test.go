//go:build linux

package collector

import (
	"os"
	"testing"
)

func TestReadProcSelfReal(t *testing.T) {
	p, ok := ReadProc("/proc", os.Getpid())
	if !ok || p.StartTime == 0 || p.PPID == 0 && os.Getppid() != 0 || p.Exe == "" || p.Cmdline == "" {
		t.Fatalf("%+v ok=%v", p, ok)
	}
	if len(ListPIDs("/proc")) == 0 {
		t.Fatal("no pids")
	}
	_ = ReadProcNet("/proc")
}
