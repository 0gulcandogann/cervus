package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeRelease makes a folder like an unpacked archive.
func fakeRelease(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range selfInstallPrograms {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(name+content), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(dir, "cervus")
}

func TestSelfInstallCopiesTheProgramsAndLinksCervus(t *testing.T) {
	home := t.TempDir()
	exe := fakeRelease(t, "-1")
	var out bytes.Buffer
	installed, copied, err := selfInstall(&out, exe, home)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(home, ".local", "share", "cervus")
	if installed != filepath.Join(dir, "cervus") || !copied {
		t.Fatalf("installed %q, copied %v", installed, copied)
	}
	for _, name := range selfInstallPrograms {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || string(data) != name+"-1" {
			t.Fatalf("%s: %q %v", name, data, err)
		}
		if st, _ := os.Stat(filepath.Join(dir, name)); st.Mode().Perm() != 0o755 {
			t.Errorf("%s has mode %v", name, st.Mode().Perm())
		}
	}
	link := filepath.Join(home, ".local", "bin", "cervus")
	if target, err := os.Readlink(link); err != nil || target != installed {
		t.Fatalf("link: %q %v", target, err)
	}
}

func TestSelfInstallUpdatesAnOlderCopy(t *testing.T) {
	home := t.TempDir()
	if _, _, err := selfInstall(&bytes.Buffer{}, fakeRelease(t, "-1"), home); err != nil {
		t.Fatal(err)
	}
	exe := fakeRelease(t, "-2")
	if selfInstallCurrent(exe, home) {
		t.Fatal("an older copy must not count as current")
	}
	if _, copied, err := selfInstall(&bytes.Buffer{}, exe, home); err != nil || !copied {
		t.Fatalf("copied %v, %v", copied, err)
	}
	data, _ := os.ReadFile(filepath.Join(home, ".local", "share", "cervus", "cervusd"))
	if string(data) != "cervusd-2" {
		t.Fatalf("not updated: %q", data)
	}
	if !selfInstallCurrent(exe, home) {
		t.Fatal("the same programs must count as current")
	}
	if _, copied, err := selfInstall(&bytes.Buffer{}, exe, home); err != nil || copied {
		t.Fatalf("nothing to copy, but copied %v, %v", copied, err)
	}
}

func TestSelfInstallNeedsAllThreePrograms(t *testing.T) {
	home := t.TempDir()
	exe := fakeRelease(t, "-1")
	if err := os.Remove(filepath.Join(filepath.Dir(exe), "cervus-vault")); err != nil {
		t.Fatal(err)
	}
	_, _, err := selfInstall(&bytes.Buffer{}, exe, home)
	if err == nil || !strings.Contains(err.Error(), "cervus-vault") {
		t.Fatalf("got %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".local", "share", "cervus", "cervus")); err == nil {
		t.Fatal("a partial install was left behind")
	}
}

func TestSelfInstallKeepsAFileAtTheLinkPath(t *testing.T) {
	home := t.TempDir()
	link := filepath.Join(home, ".local", "bin", "cervus")
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(link, []byte("mine"), 0o755); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if _, _, err := selfInstall(&out, fakeRelease(t, "-1"), home); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(link); string(data) != "mine" {
		t.Fatalf("overwrote the user's file: %q", data)
	}
	if !strings.Contains(out.String(), link) {
		t.Fatalf("no warning: %q", out.String())
	}
}

func TestSelfInstalledFromTheInstallFolder(t *testing.T) {
	home := "/home/u"
	if !runningInstalled("/home/u/.local/share/cervus/cervus", home) {
		t.Error("the installed copy is installed")
	}
	if runningInstalled("/home/u/Downloads/cervus-0.0.11-linux-amd64/cervus", home) {
		t.Error("an unpacked archive is not installed")
	}
}

func TestShellPathLineOnlyForTheInstalledCopy(t *testing.T) {
	home := "/home/u"
	if line := shellPathLine("/home/u/.local/share/cervus/cervus", home); !strings.Contains(line, `"$HOME/.local/bin:$PATH"`) {
		t.Errorf("installed: %q", line)
	}
	if line := shellPathLine("/home/u/src/cervus/bin/cervus", home); line != "" {
		t.Errorf("a build folder must not change PATH: %q", line)
	}
}
