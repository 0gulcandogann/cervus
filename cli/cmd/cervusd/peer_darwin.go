//go:build darwin

package main

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"unsafe"
)

// From <sys/un.h> and <sys/ucred.h>. The standard library does not expose them on macOS, and this
// one read does not justify a new dependency.
const (
	solLocal      = 0
	localPeerCred = 1
	xucredVersion = 0
)

type xucred struct {
	Version uint32
	UID     uint32
	Ngroups int16
	_       int16
	Groups  [16]uint32
}

// checkPeer rejects connections from other users (LOCAL_PEERCRED).
func checkPeer(c net.Conn) error {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("not a unix connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return err
	}
	var cred xucred
	size := uint32(unsafe.Sizeof(cred))
	var errno syscall.Errno
	if err := raw.Control(func(fd uintptr) {
		_, _, errno = syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, solLocal, localPeerCred,
			uintptr(unsafe.Pointer(&cred)), uintptr(unsafe.Pointer(&size)), 0)
	}); err != nil {
		return err
	}
	if errno != 0 {
		return errno
	}
	if cred.Version != xucredVersion {
		return fmt.Errorf("unexpected peer credential version %d", cred.Version)
	}
	if int(cred.UID) != os.Getuid() {
		return fmt.Errorf("peer uid %d is not allowed", cred.UID)
	}
	return nil
}
