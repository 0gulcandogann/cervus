//go:build unix

package main

import "syscall"

// hardenProcess keeps this process's memory off the disk: it holds long-term keys and passphrases while
// serving requests, and a core dump would write them in plaintext. Children inherit the limit, and the
// only child is the vault process, which sets it too.
func hardenProcess() error {
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{}); err != nil {
		return err
	}
	return denyDumps()
}
