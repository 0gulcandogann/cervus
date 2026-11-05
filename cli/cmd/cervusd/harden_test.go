//go:build unix

package main

import (
	"syscall"
	"testing"
)

func TestHardenProcessTurnsOffCoreDumps(t *testing.T) {
	if err := hardenProcess(); err != nil {
		t.Fatal(err)
	}
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &lim); err != nil {
		t.Fatal(err)
	}
	if lim.Cur != 0 || lim.Max != 0 {
		t.Fatalf("core limit is %d/%d", lim.Cur, lim.Max)
	}
	if on, err := dumpable(); err != nil || on {
		t.Fatalf("dumpable %v, %v", on, err)
	}
}
