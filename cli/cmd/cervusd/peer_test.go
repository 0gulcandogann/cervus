package main

import (
	"net"
	"path/filepath"
	"testing"
)

// A connection from this same user must pass. On Linux and macOS this also proves the kernel call works.
func TestCheckPeerAcceptsTheSameUser(t *testing.T) {
	l, err := net.Listen("unix", filepath.Join(t.TempDir(), "s"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	out, err := net.Dial("unix", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	in, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	if err := checkPeer(in); err != nil {
		t.Fatalf("checkPeer: %v", err)
	}
}

func TestCheckPeerRefusesOtherConnections(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if err := checkPeer(a); err == nil && peerCheckEnforced {
		t.Fatal("a connection that is not a unix socket must be refused")
	}
}
