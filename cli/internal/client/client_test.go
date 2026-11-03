package client

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func noRuntimeDir(t *testing.T) string {
	t.Helper()
	t.Setenv("CERVUS_SOCKET", "")
	t.Setenv("XDG_RUNTIME_DIR", "")
	home := t.TempDir()
	t.Setenv("HOME", home)
	old := runUserBase
	t.Cleanup(func() { runUserBase = old })
	runUserBase = t.TempDir()
	return home
}

func TestSocketPathFallsBackToRunUser(t *testing.T) {
	noRuntimeDir(t)
	want := filepath.Join(runUserBase, fmt.Sprint(os.Getuid()), "cervus", "cervus.sock")
	if err := os.MkdirAll(filepath.Dir(want), 0o700); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", want)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if got := SocketPath(); got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestSocketPathUsesHomeWithoutRunUser(t *testing.T) {
	home := noRuntimeDir(t)
	want := filepath.Join(home, ".cervus", "cervus.sock")
	if got := SocketPath(); got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestSocketPathIgnoresARegularFile(t *testing.T) {
	home := noRuntimeDir(t)
	fake := filepath.Join(runUserBase, fmt.Sprint(os.Getuid()), "cervus", "cervus.sock")
	if err := os.MkdirAll(filepath.Dir(fake), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fake, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, want := SocketPath(), filepath.Join(home, ".cervus", "cervus.sock"); got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestSocketPathPrefersExplicitSettings(t *testing.T) {
	noRuntimeDir(t)
	t.Setenv("XDG_RUNTIME_DIR", "/run/x")
	if got := SocketPath(); got != "/run/x/cervus/cervus.sock" {
		t.Fatalf("got %s", got)
	}
	t.Setenv("CERVUS_SOCKET", "/custom.sock")
	if got := SocketPath(); got != "/custom.sock" {
		t.Fatalf("got %s", got)
	}
}

func TestSocketPathIgnoresWritableRunUserDir(t *testing.T) {
	home := noRuntimeDir(t)
	dir := filepath.Join(runUserBase, fmt.Sprint(os.Getuid()), "cervus")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", filepath.Join(dir, "cervus.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if err := os.Chmod(filepath.Dir(dir), 0o777); err != nil {
		t.Fatal(err)
	}
	if got, want := SocketPath(), filepath.Join(home, ".cervus", "cervus.sock"); got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestSocketPathIgnoresSymlink(t *testing.T) {
	home := noRuntimeDir(t)
	real := filepath.Join(t.TempDir(), "s.sock")
	ln, err := net.Listen("unix", real)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	dir := filepath.Join(runUserBase, fmt.Sprint(os.Getuid()), "cervus")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(dir, "cervus.sock")); err != nil {
		t.Fatal(err)
	}
	if got, want := SocketPath(), filepath.Join(home, ".cervus", "cervus.sock"); got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestDefaultSocketPathIgnoresCustomSocket(t *testing.T) {
	noRuntimeDir(t)
	t.Setenv("XDG_RUNTIME_DIR", "/run/x")
	t.Setenv("CERVUS_SOCKET", "/custom.sock")
	if got := DefaultSocketPath(); got != "/run/x/cervus/cervus.sock" {
		t.Fatalf("got %s", got)
	}
}
