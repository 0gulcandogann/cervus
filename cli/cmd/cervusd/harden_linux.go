//go:build linux

package main

import "syscall"

const prSetDumpable, prGetDumpable = 4, 3

// denyDumps also stops other programs of this user from attaching a debugger.
func denyDumps() error {
	_, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, prSetDumpable, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func dumpable() (bool, error) {
	v, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, prGetDumpable, 0, 0)
	if errno != 0 {
		return false, errno
	}
	return v != 0, nil
}
