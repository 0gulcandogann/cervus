//go:build !linux && !darwin

package main

import "net"

// checkPeer has no check on other platforms. The 0700 socket directory and 0600 socket keep other
// users out.
func checkPeer(c net.Conn) error { return nil }
