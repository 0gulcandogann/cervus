package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"cervus/internal/client"
)

// setupContinuedEnv tells a copied cervus that the first one already drew the banner and installed it.
const setupContinuedEnv = "CERVUS_SETUP_CONTINUED"

var selfInstallPrograms = []string{"cervus", "cervusd", "cervus-vault"}

func selfInstallDir(home string) string { return filepath.Join(home, ".local", "share", "cervus") }

func selfInstallLink(home string) string { return filepath.Join(home, ".local", "bin", "cervus") }

// runningInstalled compares without links: the path of the running program never contains any, but home
// can, because /home is a link on some systems and temporary folders are on macOS.
func runningInstalled(exe, home string) bool {
	return sameFolder(filepath.Dir(exe), selfInstallDir(home))
}

func sameFolder(a, b string) bool {
	if real, err := filepath.EvalSymlinks(a); err == nil {
		a = real
	}
	if real, err := filepath.EvalSymlinks(b); err == nil {
		b = real
	}
	return a == b
}

// selfInstallCurrent is true when the install folder already holds these exact programs.
func selfInstallCurrent(exe, home string) bool {
	for _, name := range selfInstallPrograms {
		have, err := os.ReadFile(filepath.Join(selfInstallDir(home), name))
		if err != nil {
			return false
		}
		want, err := os.ReadFile(filepath.Join(filepath.Dir(exe), name))
		if err != nil || !bytes.Equal(have, want) {
			return false
		}
	}
	return true
}

// selfInstall copies the three programs next to exe into the install folder and links cervus into
// ~/.local/bin, so setup no longer depends on the folder an archive was unpacked in. Each file is
// replaced atomically, so a running daemon keeps its old program until it restarts.
func selfInstall(w io.Writer, exe, home string) (installed string, copied bool, err error) {
	dir := selfInstallDir(home)
	programs := make(map[string][]byte, len(selfInstallPrograms))
	for _, name := range selfInstallPrograms {
		data, err := os.ReadFile(filepath.Join(filepath.Dir(exe), name))
		if err != nil {
			return "", false, fmt.Errorf("%s not found next to cervus; keep the three programs together: %w", name, err)
		}
		programs[name] = data
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", false, err
	}
	for _, name := range selfInstallPrograms {
		path := filepath.Join(dir, name)
		if have, err := os.ReadFile(path); err == nil && bytes.Equal(have, programs[name]) {
			continue
		}
		if err := writeFileAtomic(path, programs[name], 0o755); err != nil {
			return "", false, err
		}
		copied = true
	}
	installed = filepath.Join(dir, "cervus")
	link := selfInstallLink(home)
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		return "", false, err
	}
	if st, err := os.Lstat(link); err == nil && st.Mode()&os.ModeSymlink == 0 {
		fmt.Fprintf(w, "Leaving %s alone: it is not a link made by Cervus.\n", link)
		return installed, copied, nil
	}
	tmp := link + ".new"
	_ = os.Remove(tmp)
	if err := os.Symlink(installed, tmp); err != nil {
		return "", false, err
	}
	if err := os.Rename(tmp, link); err != nil {
		_ = os.Remove(tmp)
		return "", false, err
	}
	return installed, copied, nil
}

// execProgram replaces this process. A variable, so a failure can be tested.
var execProgram = syscall.Exec

// offerSelfInstall installs cervus when it runs from anywhere else, then continues setup from the
// installed copy, so the service, the AWS profile and the shell all point at the copy that stays.
func offerSelfInstall(confirm func(string) (bool, error), home string, yes bool) (declined bool, err error) {
	exe, err := os.Executable()
	if err != nil {
		return false, err
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	if runningInstalled(exe, home) || serviceRunsFrom(filepath.Dir(exe), home) {
		return false, nil
	}
	if !selfInstallCurrent(exe, home) {
		ok, err := confirm("Install Cervus to ~/.local/share/cervus?")
		if err != nil {
			return false, err
		}
		if !ok {
			fmt.Printf("Not installed: everything set up now keeps depending on %s.\n", filepath.Dir(exe))
			return true, nil
		}
	}
	installed, copied, err := selfInstall(os.Stdout, exe, home)
	if err != nil {
		return false, err
	}
	if copied {
		fmt.Println("Installed to ~/.local/share/cervus. You can delete the folder it came from.")
		if daemonReachable(client.SocketPath()) {
			fmt.Println("The running daemon keeps the old version until it restarts: `cervus install-service` does that, and it locks your vaults.")
		}
	}
	args := append([]string{installed, "setup"}, setupArgs(yes)...)
	env := append(os.Environ(), setupContinuedEnv+"=1")
	return false, execProgram(installed, args, env)
}

func setupArgs(yes bool) []string {
	if yes {
		return []string{"--yes"}
	}
	return nil
}

// serviceRunsFrom is true when the login service already runs the programs in this folder. Someone who
// set that up from their own build does not need to be asked about installing.
func serviceRunsFrom(dir, home string) bool {
	file, err := serviceFilePath(runtime.GOOS, home, os.Getenv("XDG_CONFIG_HOME"))
	if err != nil {
		return false
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return false
	}
	program := serviceProgram(runtime.GOOS, string(data))
	return program != "" && sameFolder(filepath.Dir(program), dir)
}

// shellPathLine puts ~/.local/bin on PATH in new shells, because many systems leave it off. It is only
// for the installed copy: a build folder must not change anyone's PATH.
func shellPathLine(exe, home string) string {
	if !runningInstalled(exe, home) {
		return ""
	}
	return strings.Join([]string{
		`case ":$PATH:" in *":$HOME/.local/bin:"*) ;; *) export PATH="$HOME/.local/bin:$PATH" ;; esac`,
		"",
	}, "\n")
}
