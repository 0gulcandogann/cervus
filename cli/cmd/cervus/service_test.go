package main

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestServiceFilePath(t *testing.T) {
	cases := []struct{ goos, xdg, want string }{
		{"linux", "", "/h/.config/systemd/user/cervusd.service"},
		{"linux", "/x", "/x/systemd/user/cervusd.service"},
		{"darwin", "/x", "/h/Library/LaunchAgents/cervus.daemon.plist"},
	}
	for _, c := range cases {
		got, err := serviceFilePath(c.goos, "/h", c.xdg)
		if err != nil || got != c.want {
			t.Errorf("%s xdg=%q: got %q, %v; want %q", c.goos, c.xdg, got, err, c.want)
		}
	}
	if _, err := serviceFilePath("windows", "/h", ""); err == nil {
		t.Error("windows should not be supported")
	}
}

func TestSystemdUnitContent(t *testing.T) {
	unit := systemdUnit("/opt/c/cervusd")
	for _, want := range []string{
		`ExecStart="/opt/c/cervusd"`, "Type=exec", "Restart=on-failure", "RestartSec=2", "UMask=0077",
		"LimitCORE=0", "NoNewPrivileges=yes", "WantedBy=default.target",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("unit lacks %q:\n%s", want, unit)
		}
	}
	if strings.Contains(unit, "CERVUS_") {
		t.Error("the unit must not pin CERVUS_* values")
	}
}

func TestSystemdUnitEscapesPercent(t *testing.T) {
	unit := systemdUnit(`/a b/100%/cervusd`)
	want := `ExecStart="/a b/100%%/cervusd"`
	if !strings.Contains(unit, want) {
		t.Fatalf("want %s in:\n%s", want, unit)
	}
}

func TestSystemdAcceptsGeneratedUnit(t *testing.T) {
	if _, err := exec.LookPath("systemd-analyze"); err != nil {
		t.Skip("systemd-analyze is not available")
	}
	dir := filepath.Join(t.TempDir(), "a b", "100%")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	daemon := filepath.Join(dir, "cervusd")
	if err := os.WriteFile(daemon, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	unit := filepath.Join(t.TempDir(), "cervusd.service")
	if err := os.WriteFile(unit, []byte(systemdUnit(daemon)), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("systemd-analyze", "--user", "verify", unit).CombinedOutput(); err != nil {
		t.Fatalf("systemd rejects the unit: %v\n%s", err, out)
	}
}

func TestInstallRefusesPathsSystemdCannotRun(t *testing.T) {
	for _, bad := range []string{`qu"ote`, `apos'trophe`, `back\\slash`, "new\nline", "ta\tb", `dol$lar`} {
		t.Run(bad, func(t *testing.T) {
			e := newServiceEnv(t)
			dir := filepath.Join(e.dir, bad)
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			for _, f := range []string{"cervusd", "cervus-vault"} {
				if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			serviceExecutable = func() (string, error) { return filepath.Join(dir, "cervus"), nil }
			err := installService(io.Discard, "linux", e.home, "")
			if err == nil || !strings.Contains(err.Error(), "move the binaries") {
				t.Fatalf("got %v", err)
			}
			if _, serr := os.Stat(e.unitPath()); serr == nil {
				t.Fatal("no file should be written")
			}
		})
	}
}

func TestInstallRequiresVaultBinary(t *testing.T) {
	e := newServiceEnv(t)
	if err := os.Remove(filepath.Join(e.dir, "cervus-vault")); err != nil {
		t.Fatal(err)
	}
	err := installService(io.Discard, "linux", e.home, "")
	if err == nil || !strings.Contains(err.Error(), "cervus-vault") {
		t.Fatalf("got %v", err)
	}
	if _, serr := os.Stat(e.unitPath()); serr == nil {
		t.Fatal("no file should be written")
	}
}

func TestInstallFailsWhenServiceDoesNotComeUp(t *testing.T) {
	e := newServiceEnv(t)
	e.noStart = true
	var out bytes.Buffer
	err := installService(&out, "linux", e.home, "")
	if err == nil || !strings.Contains(err.Error(), "journalctl --user -u cervusd") {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(out.String(), "now runs at login") {
		t.Fatal("must not report success")
	}
	if _, serr := os.Stat(e.unitPath()); serr == nil {
		t.Fatal("a file this run created should be removed")
	}
	if !strings.Contains(strings.Join(e.calls, "\n"), "disable --now cervusd.service") {
		t.Fatalf("should disable again: %v", e.calls)
	}
}

func TestInstallProbesDefaultSocketDespiteCustomOne(t *testing.T) {
	e := newServiceEnv(t)
	t.Setenv("CERVUS_SOCKET", "/tmp/custom.sock")
	e.reachable = true // a daemon on the default socket, outside the service
	err := installService(io.Discard, "linux", e.home, "")
	if err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatalf("got %v", err)
	}
	for _, p := range e.probed {
		if p == "/tmp/custom.sock" {
			t.Fatal("must probe the default socket, not CERVUS_SOCKET")
		}
	}
}

func TestLaunchdPlistContent(t *testing.T) {
	plist := launchdPlist("/a&b/cervusd", "/h/.cervus/cervusd.log")
	for _, want := range []string{
		"<string>cervus.daemon</string>", "<string>/a&amp;b/cervusd</string>", "<key>RunAtLoad</key>",
		"<key>SuccessfulExit</key>", "<key>Umask</key>", "<integer>63</integer>", "<key>Core</key>",
		"<string>/h/.cervus/cervusd.log</string>",
	} {
		if !strings.Contains(plist, want) {
			t.Errorf("plist lacks %q:\n%s", want, plist)
		}
	}
	d := xml.NewDecoder(strings.NewReader(plist))
	for {
		if _, err := d.Token(); err == io.EOF {
			break
		} else if err != nil {
			t.Fatalf("plist is not valid XML: %v", err)
		}
	}
}

// serviceEnv fakes everything install and uninstall touch: HOME, the binaries and the service manager.
type serviceEnv struct {
	home, dir string
	calls     []string
	fail      map[string]bool
	active    bool
	reachable bool // a daemon answers before install does anything
	noStart   bool // the service never comes up after restart
	up        bool
	probed    []string // socket paths probed
	state     string   // overrides is-active output when set
}

func newServiceEnv(t *testing.T) *serviceEnv {
	t.Helper()
	e := &serviceEnv{home: t.TempDir(), dir: t.TempDir(), fail: map[string]bool{}}
	t.Setenv("CERVUS_SOCKET", "")
	for _, f := range []string{"cervus", "cervusd", "cervus-vault"} {
		if err := os.WriteFile(filepath.Join(e.dir, f), []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	oldRun, oldReach, oldExe := runService, daemonReachable, serviceExecutable
	t.Cleanup(func() { runService, daemonReachable, serviceExecutable = oldRun, oldReach, oldExe })
	runService = func(name string, args ...string) (string, error) {
		call := name + " " + strings.Join(args, " ")
		e.calls = append(e.calls, call)
		if strings.Contains(call, "is-active") {
			if e.state != "" {
				return e.state, errors.New("exit 1")
			}
			if !e.active && !e.up {
				return "inactive", errors.New("exit 3")
			}
			return "active", nil
		}
		for k := range e.fail {
			if strings.Contains(call, k) {
				return "boom", errors.New("exit 1")
			}
		}
		if strings.Contains(call, "restart") && !e.noStart {
			e.up = true
		}
		return "", nil
	}
	daemonReachable = func(path string) bool {
		e.probed = append(e.probed, path)
		return e.reachable || e.up
	}
	oldWait := serviceStartWait
	t.Cleanup(func() { serviceStartWait = oldWait })
	serviceStartWait = 20 * time.Millisecond
	serviceExecutable = func() (string, error) { return filepath.Join(e.dir, "cervus"), nil }
	return e
}

func (e *serviceEnv) unitPath() string {
	return filepath.Join(e.home, ".config", "systemd", "user", "cervusd.service")
}

func TestInstallWritesUnitAndEnables(t *testing.T) {
	e := newServiceEnv(t)
	var out bytes.Buffer
	if err := installService(&out, "linux", e.home, ""); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(e.unitPath())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `ExecStart="`+filepath.Join(e.dir, "cervusd")+`"`) {
		t.Fatalf("wrong unit:\n%s", b)
	}
	want := []string{
		"systemctl --user daemon-reload",
		"systemctl --user is-active cervusd.service",
		"systemctl --user daemon-reload",
		"systemctl --user enable cervusd.service",
		"systemctl --user restart cervusd.service",
		"systemctl --user is-active cervusd.service",
	}
	if strings.Join(e.calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("calls:\n%s", strings.Join(e.calls, "\n"))
	}
	if !strings.Contains(out.String(), "cervus unlock") {
		t.Fatalf("output should mention unlocking: %s", out.String())
	}
}

func TestInstallRejectsManualDaemon(t *testing.T) {
	e := newServiceEnv(t)
	e.reachable = true
	err := installService(io.Discard, "linux", e.home, "")
	if err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatalf("got %v", err)
	}
	if _, serr := os.Stat(e.unitPath()); serr == nil {
		t.Fatal("no file should be written")
	}
	if strings.Contains(strings.Join(e.calls, "\n"), "enable") {
		t.Fatal("must not enable")
	}
}

func TestInstallTwiceUpdatesPath(t *testing.T) {
	e := newServiceEnv(t)
	if err := installService(io.Discard, "linux", e.home, ""); err != nil {
		t.Fatal(err)
	}
	moved := t.TempDir()
	for _, f := range []string{"cervusd", "cervus-vault"} {
		if err := os.WriteFile(filepath.Join(moved, f), []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	serviceExecutable = func() (string, error) { return filepath.Join(moved, "cervus"), nil }
	e.active, e.reachable, e.calls = true, true, nil // our own service answers on the socket
	if err := installService(io.Discard, "linux", e.home, ""); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(e.unitPath())
	if !strings.Contains(string(b), filepath.Join(moved, "cervusd")) {
		t.Fatalf("path not updated:\n%s", b)
	}
	if !strings.Contains(strings.Join(e.calls, "\n"), "restart") {
		t.Fatal("service should restart")
	}
}

func TestInstallWithoutSystemd(t *testing.T) {
	e := newServiceEnv(t)
	e.fail["daemon-reload"] = true
	err := installService(io.Discard, "linux", e.home, "")
	if err == nil || !strings.Contains(err.Error(), "systemd") {
		t.Fatalf("got %v", err)
	}
	if _, serr := os.Stat(e.unitPath()); serr == nil {
		t.Fatal("no file should remain")
	}
}

func TestInstallRemovesNewFileWhenStartFails(t *testing.T) {
	e := newServiceEnv(t)
	e.fail["restart"] = true
	if err := installService(io.Discard, "linux", e.home, ""); err == nil {
		t.Fatal("want an error")
	}
	if _, serr := os.Stat(e.unitPath()); serr == nil {
		t.Fatal("a file this run created should be removed")
	}
}

func TestInstallWarnsAboutCustomSocket(t *testing.T) {
	e := newServiceEnv(t)
	t.Setenv("CERVUS_SOCKET", "/tmp/custom.sock")
	var out bytes.Buffer
	if err := installService(&out, "linux", e.home, ""); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "CERVUS_SOCKET") {
		t.Fatalf("no warning: %s", out.String())
	}
}

func TestUninstallRemovesOnlyServiceFile(t *testing.T) {
	e := newServiceEnv(t)
	if err := installService(io.Discard, "linux", e.home, ""); err != nil {
		t.Fatal(err)
	}
	keep := filepath.Join(filepath.Dir(e.unitPath()), "other.service")
	if err := os.WriteFile(keep, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	e.calls = nil
	if err := uninstallService(io.Discard, "linux", e.home, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(e.unitPath()); err == nil {
		t.Fatal("unit should be gone")
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatal("other files must survive")
	}
	if !strings.Contains(strings.Join(e.calls, "\n"), "systemctl --user disable --now cervusd.service") {
		t.Fatalf("calls: %v", e.calls)
	}
}

func TestUninstallWhenNotInstalled(t *testing.T) {
	e := newServiceEnv(t)
	var out bytes.Buffer
	if err := uninstallService(&out, "linux", e.home, ""); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "not installed") {
		t.Fatalf("got %q", out.String())
	}
}

func TestServiceDaemonPathMissing(t *testing.T) {
	e := newServiceEnv(t)
	if err := os.Remove(filepath.Join(e.dir, "cervusd")); err != nil {
		t.Fatal(err)
	}
	_, err := serviceDaemonPath()
	if err == nil || !strings.Contains(err.Error(), "cervusd") {
		t.Fatalf("got %v", err)
	}
}

func TestDoctorService(t *testing.T) {
	cases := []struct {
		name         string
		write        bool
		daemonExists bool
		active       bool
		fails, warns int
		want         string
	}{
		{"not installed", false, false, false, 0, 1, "cervus install-service"},
		{"program gone", true, false, true, 1, 0, "missing program"},
		{"inactive", true, true, false, 0, 1, "systemctl --user start cervusd"},
		{"running", true, true, true, 0, 0, "login service is installed and running"},
		{"cannot ask", true, true, false, 0, 1, "cannot read the login service state"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newServiceEnv(t)
			e.active = c.active
			if c.name == "cannot ask" {
				e.state = "Failed to connect to bus: No medium found"
			}
			daemon := filepath.Join(e.dir, "spaced dir", "cervusd")
			if c.daemonExists {
				if err := os.MkdirAll(filepath.Dir(daemon), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(daemon, []byte("x"), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if c.write {
				if err := os.MkdirAll(filepath.Dir(e.unitPath()), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(e.unitPath(), []byte(systemdUnit(daemon)), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			var out bytes.Buffer
			d := &doctor{out: &out}
			d.checkServiceOn("linux", e.home, "")
			if d.fails != c.fails || d.warns != c.warns {
				t.Fatalf("fails=%d warns=%d\n%s", d.fails, d.warns, out.String())
			}
			if !strings.Contains(out.String(), c.want) {
				t.Fatalf("want %q in:\n%s", c.want, out.String())
			}
		})
	}
}

func TestServiceProgramReadsBothFormats(t *testing.T) {
	path := `/a b/100%/x&z/cervusd`
	if got := serviceProgram("linux", systemdUnit(path)); got != path {
		t.Errorf("unit: got %q", got)
	}
	if got := serviceProgram("darwin", launchdPlist(path, "/log")); got != path {
		t.Errorf("plist: got %q", got)
	}
	if got := serviceProgram("linux", "garbage"); got != "" {
		t.Errorf("garbage: got %q", got)
	}
}
