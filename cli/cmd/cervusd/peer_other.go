//go:build !linux

package main

import "net"

// checkPeer is a placeholder on non-Linux platforms.
// TODO: use LOCAL_PEERCRED on macOS. Until then the 0700 socket directory and 0600 socket
// keep other users out.
func checkPeer(c net.Conn) error { return nil }
