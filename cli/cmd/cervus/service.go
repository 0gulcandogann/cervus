package main

import (
	"bytes"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"cervus/internal/client"
)

const (
	systemdServiceName = "cervusd.service"
	launchdLabel       = "cervus.daemon"
)

// serviceFilePath returns where the service definition lives on this platform.
func serviceFilePath(goos, home, xdgConfig string) (string, error) {
	switch goos {
	case "linux":
		if xdgConfig == "" {
			xdgConfig = filepath.Join(home, ".config")
		}
		return filepath.Join(xdgConfig, "systemd", "user", systemdServiceName), nil
	case "darwin":
		return filepath.Join(home, "Library", "LaunchAgents", launchdLabel+".plist"), nil
	}
	return "", fmt.Errorf("running at login is not supported on %s", goos)
}

// systemdUnit renders the user unit. It holds no secrets and no CERVUS_* values.
func systemdUnit(daemonPath string) string {
	exec := strings.ReplaceAll(daemonPath, `%`, `%%`) // other special characters are refused at install
	return fmt.Sprintf(`[Unit]
Description=Cervus daemon (encrypted AWS secrets and role switching)

[Service]
Type=exec
ExecStart="%s"
Restart=on-failure
RestartSec=2
UMask=0077
LimitCORE=0
NoNewPrivileges=yes

[Install]
WantedBy=default.target
`, exec)
}

func xmlEscape(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s)) // writing to a bytes.Buffer cannot fail
	return b.String()
}

// launchdPlist renders the launch agent. Its behavior on macOS has not been verified.
func launchdPlist(daemonPath, logPath string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>%s</string>
  <key>ProgramArguments</key>
  <array>
    <string>%s</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <dict>
    <key>SuccessfulExit</key>
    <false/>
  </dict>
  <key>Umask</key>
  <integer>63</integer>
  <key>SoftResourceLimits</key>
  <dict>
    <key>Core</key>
    <integer>0</integer>
  </dict>
  <key>HardResourceLimits</key>
  <dict>
    <key>Core</key>
    <integer>0</integer>
  </dict>
  <key>StandardErrorPath</key>
  <string>%s</string>
</dict>
</plist>
`, launchdLabel, xmlEscape(daemonPath), xmlEscape(logPath))
}

// These are variables so tests never run the real service manager.
var (
	runService = func(name string, args ...string) (string, error) {
		out, err := exec.Command(name, args...).CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}
	daemonReachable = func(path string) bool {
		c, err := net.DialTimeout("unix", path, time.Second)
		if err != nil {
			return false
		}
		c.Close()
		return true
	}
	serviceStartWait  = 5 * time.Second
	serviceExecutable = os.Executable
)

// serviceDaemonPath returns the absolute path of the cervusd next to this cervus binary.
func serviceDaemonPath() (string, error) {
	exe, err := serviceExecutable()
	if err != nil {
		return "", err
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	path := filepath.Join(filepath.Dir(exe), "cervusd")
	if st, err := os.Stat(path); err != nil || st.IsDir() {
		return "", fmt.Errorf("cervusd not found next to cervus (%s); build or install them together", path)
	}
	vault := filepath.Join(filepath.Dir(exe), "cervus-vault")
	if st, err := os.Stat(vault); err != nil || st.IsDir() {
		return "", fmt.Errorf("cervus-vault not found next to cervus (%s); build or install them together", vault)
	}
	return path, nil
}

// checkSystemdPath refuses paths systemd will not run. It rejects these characters in an executable
// path even when quoted, and a newline would inject lines into the unit.
func checkSystemdPath(path string) error {
	for _, r := range path {
		if r < 0x20 || r == 0x7f || strings.ContainsRune(`"'\$`, r) {
			return fmt.Errorf("the path %q contains %q, which systemd cannot run; move the binaries to a simpler path", path, r)
		}
	}
	return nil
}

// serviceManager wraps the commands that differ between systemd and launchd.
type serviceManager struct {
	name          string
	check, reload func() error
	state         func() string // "active", "inactive" or "unknown"
	start, stop   func() error
	render        func(daemon string) (string, error)
}

func newServiceManager(goos, home, file string) serviceManager {
	if goos == "darwin" {
		domain := fmt.Sprintf("gui/%d", os.Getuid())
		target := domain + "/" + launchdLabel
		return serviceManager{
			name:   "launchd",
			check:  func() error { _, err := exec.LookPath("launchctl"); return err },
			reload: func() error { return nil },
			state: func() string {
				if _, err := runService("launchctl", "print", target); err != nil {
					return "inactive"
				}
				return "active"
			},
			start: func() error {
				_, _ = runService("launchctl", "bootout", target) // fine if it was not loaded
				return commandError(runService("launchctl", "bootstrap", domain, file))
			},
			stop: func() error { return commandError(runService("launchctl", "bootout", target)) },
			render: func(daemon string) (string, error) {
				dir := filepath.Join(home, ".cervus")
				if err := os.MkdirAll(dir, 0o700); err != nil {
					return "", err
				}
				return launchdPlist(daemon, filepath.Join(dir, "cervusd.log")), nil
			},
		}
	}
	sc := func(args ...string) (string, error) {
		return runService("systemctl", append([]string{"--user"}, args...)...)
	}
	return serviceManager{
		name:   "systemd",
		check:  func() error { return commandError(sc("daemon-reload")) },
		reload: func() error { return commandError(sc("daemon-reload")) },
		state: func() string {
			out, _ := sc("is-active", systemdServiceName)
			switch out {
			case "active":
				return "active"
			case "inactive", "failed", "activating", "deactivating", "reloading", "maintenance":
				return "inactive"
			}
			return "unknown" // for example, no user bus in this shell
		},
		start: func() error {
			if err := commandError(sc("enable", systemdServiceName)); err != nil {
				return err
			}
			return commandError(sc("restart", systemdServiceName))
		},
		stop:   func() error { return commandError(sc("disable", "--now", systemdServiceName)) },
		render: func(daemon string) (string, error) { return systemdUnit(daemon), nil },
	}
}

func (m serviceManager) active() bool { return m.state() == "active" }

// waitForService confirms the service really came up: a successful restart only means systemd
// tried to start it.
func waitForService(m serviceManager) bool {
	deadline := time.Now().Add(serviceStartWait)
	for {
		if m.active() && daemonReachable(client.DefaultSocketPath()) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func commandError(out string, err error) error {
	if err == nil {
		return nil
	}
	if out != "" {
		return fmt.Errorf("%w: %s", err, out)
	}
	return err
}

func installService(w io.Writer, goos, home, xdgConfig string) error {
	file, err := serviceFilePath(goos, home, xdgConfig)
	if err != nil {
		return err
	}
	daemon, err := serviceDaemonPath()
	if err != nil {
		return err
	}
	if goos == "linux" {
		if err := checkSystemdPath(daemon); err != nil {
			return err
		}
	}
	m := newServiceManager(goos, home, file)
	if err := m.check(); err != nil {
		hint := "on systems without them, start cervusd by hand"
		if os.Getenv("XDG_RUNTIME_DIR") == "" {
			hint = "XDG_RUNTIME_DIR is not set in this shell, so try from a local login; without user services, start cervusd by hand"
		}
		return fmt.Errorf("cannot reach %s user services (%v); %s", m.name, err, hint)
	}
	customSocket := os.Getenv("CERVUS_SOCKET") != ""
	if !m.active() && daemonReachable(client.DefaultSocketPath()) {
		return errors.New("a cervusd is already running outside the service; stop it (pkill -x cervusd), then run this again")
	}
	content, err := m.render(daemon)
	if err != nil {
		return err
	}
	_, statErr := os.Stat(file)
	created := errors.Is(statErr, os.ErrNotExist)
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		return err
	}
	if err := writeFileAtomic(file, []byte(content), 0o644); err != nil {
		return err
	}
	if err := m.reload(); err != nil {
		return cleanupFailedInstall(m, file, created, err)
	}
	if err := m.start(); err != nil {
		return cleanupFailedInstall(m, file, created, err)
	}
	if !waitForService(m) {
		hint := "see `journalctl --user -u cervusd`"
		if goos == "darwin" {
			hint = "see " + filepath.Join(home, ".cervus", "cervusd.log")
		}
		return cleanupFailedInstall(m, file, created, fmt.Errorf("it did not come up; %s", hint))
	}
	fmt.Fprintf(w, "cervusd now runs at login (%s, %s).\n", m.name, file)
	fmt.Fprintln(w, "Run `cervus unlock` after each login; the vault stays locked until you do.")
	if customSocket {
		fmt.Fprintln(w, "Warning: CERVUS_SOCKET is set here, but the service uses the default socket. Unset it to reach the service.")
	}
	return nil
}

// cleanupFailedInstall removes a service file this run created, so a failure leaves nothing behind.
func cleanupFailedInstall(m serviceManager, file string, created bool, cause error) error {
	if created {
		_ = m.stop()
		_ = os.Remove(file)
		_ = m.reload()
	}
	return fmt.Errorf("could not start the service: %w", cause)
}

func uninstallService(w io.Writer, goos, home, xdgConfig string) error {
	file, err := serviceFilePath(goos, home, xdgConfig)
	if err != nil {
		return err
	}
	if _, err := os.Stat(file); errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(w, "The service is not installed.")
		return nil
	}
	m := newServiceManager(goos, home, file)
	if err := m.stop(); err != nil {
		fmt.Fprintf(w, "Warning: could not stop the service: %v\n", err)
	}
	if err := os.Remove(file); err != nil {
		return err
	}
	_ = m.reload()
	fmt.Fprintln(w, "Service removed. Your vault, config and audit log were not touched.")
	return nil
}

var (
	unitExecRe  = regexp.MustCompile(`(?m)^ExecStart="([^"]*)"$`)
	plistExecRe = regexp.MustCompile(`<key>ProgramArguments</key>\s*<array>\s*<string>([^<]*)</string>`)
)

// serviceProgram reads the daemon path back out of a service file; "" if it cannot tell.
func serviceProgram(goos, content string) string {
	if goos == "darwin" {
		if m := plistExecRe.FindStringSubmatch(content); m != nil {
			return html.UnescapeString(m[1])
		}
		return ""
	}
	if m := unitExecRe.FindStringSubmatch(content); m != nil {
		return strings.ReplaceAll(m[1], `%%`, `%`)
	}
	return ""
}

func (d *doctor) checkService() {
	home, err := os.UserHomeDir()
	if err != nil {
		d.report(lvlWarn, "cannot check the login service: no home directory", "")
		return
	}
	d.checkServiceOn(runtime.GOOS, home, os.Getenv("XDG_CONFIG_HOME"))
}

// checkServiceOn runs before the daemon check, so it still reports when the daemon is down.
func (d *doctor) checkServiceOn(goos, home, xdgConfig string) {
	file, err := serviceFilePath(goos, home, xdgConfig)
	if err != nil {
		d.report(lvlWarn, err.Error(), "")
		return
	}
	content, err := os.ReadFile(file)
	if errors.Is(err, os.ErrNotExist) {
		d.report(lvlWarn, "cervusd does not start at login", "run `cervus install-service`")
		return
	}
	if err != nil {
		d.report(lvlWarn, "cannot read the service file: "+err.Error(), "")
		return
	}
	program := serviceProgram(goos, string(content))
	if program == "" {
		d.report(lvlWarn, "cannot read the program path from "+file, "run `cervus install-service`")
		return
	}
	if _, err := os.Stat(program); err != nil {
		d.report(lvlFail, "the login service points to a missing program: "+program, "run `cervus install-service`")
		return
	}
	state := newServiceManager(goos, home, file).state()
	if state == "unknown" {
		d.report(lvlWarn, "cannot read the login service state from this shell (no user session?)", "")
		return
	}
	if state != "active" {
		fix := "run `systemctl --user start cervusd`"
		if goos == "darwin" {
			fix = "run `cervus install-service`"
		}
		d.report(lvlWarn, "the login service is installed but not running", fix)
		return
	}
	d.report(lvlOK, "login service is installed and running", "")
}

func serviceArgs(name string, args []string) (home string, err error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return "", err
	}
	if fs.NArg() != 0 {
		return "", fmt.Errorf("usage: cervus %s", name)
	}
	return os.UserHomeDir()
}

func cmdInstallService(args []string) error {
	home, err := serviceArgs("install-service", args)
	if err != nil {
		return err
	}
	return installService(os.Stdout, runtime.GOOS, home, os.Getenv("XDG_CONFIG_HOME"))
}

func cmdUninstallService(args []string) error {
	home, err := serviceArgs("uninstall-service", args)
	if err != nil {
		return err
	}
	return uninstallService(os.Stdout, runtime.GOOS, home, os.Getenv("XDG_CONFIG_HOME"))
}
