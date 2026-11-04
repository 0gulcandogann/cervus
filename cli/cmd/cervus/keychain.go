package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"cervus/internal/client"
)

// The keychain holds the vault passphrase through libsecret's secret-tool, an optional external
// program, so Cervus itself gains no dependency. Secrets go over stdin, never in arguments.
var runSecretTool = func(stdin string, args ...string) (string, error) {
	// A locked keyring can open a dialog nobody answers, so this must not wait forever.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "secret-tool", args...)
	cmd.Stdin = strings.NewReader(stdin)
	cmd.WaitDelay = time.Second // the timeout must hold even if a child keeps the pipe open
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	return out.String(), err
}

// Markers in the vault directory, neither secret. "Enabled" means the user opted in, so nobody else
// ever runs secret-tool. "Hold" means the user locked the vault on purpose, so only an explicit
// unlock may reopen it.
const (
	keychainEnabledFile = "keychain-enabled"
	keychainHoldFile    = "keychain-hold"
	keychainDisabledMsg = "the keychain is turned off by CERVUS_NO_KEYCHAIN"
)

func keychainTurnedOff() bool { return os.Getenv("CERVUS_NO_KEYCHAIN") != "" }

func hasKeychainMarker(dir, name string) bool {
	_, err := os.Stat(filepath.Join(dir, name))
	return err == nil
}

func setKeychainMarker(dir, name string, on bool) error {
	path := filepath.Join(dir, name)
	if on {
		return os.WriteFile(path, nil, 0o600)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func keychainAttrs(vaultDir string) []string { return []string{"service", "cervus", "vault", vaultDir} }

func keychainStore(vaultDir, passphrase string) error {
	_, err := runSecretTool(passphrase, append([]string{"store", "--label=Cervus vault passphrase"}, keychainAttrs(vaultDir)...)...)
	return err
}

func keychainLookup(vaultDir string) string {
	if keychainTurnedOff() {
		return ""
	}
	out, err := runSecretTool("", append([]string{"lookup"}, keychainAttrs(vaultDir)...)...)
	if err != nil {
		return ""
	}
	return strings.TrimRight(out, "\r\n")
}

func keychainClear(vaultDir string) error {
	_, err := runSecretTool("", append([]string{"clear"}, keychainAttrs(vaultDir)...)...)
	return err
}

// passphraseFor returns the stored passphrase of a vault that opted in. honorHold is false only for
// an explicit `cervus unlock`.
func passphraseFor(dir string, honorHold bool) string {
	if keychainTurnedOff() || !hasKeychainMarker(dir, keychainEnabledFile) {
		return ""
	}
	if honorHold && hasKeychainMarker(dir, keychainHoldFile) {
		return ""
	}
	return keychainLookup(dir)
}

func currentVaultDir() (string, error) {
	var st struct {
		Dir string `json:"dir"`
	}
	if err := client.Call("status", nil, &st); err != nil {
		return "", err
	}
	if st.Dir == "" {
		return "", errors.New("the daemon did not report a vault directory")
	}
	return st.Dir, nil
}

// storedPassphrase and keychainHoldOff are variables so tests can run withUnlock without a daemon.
var (
	storedPassphrase = func() string {
		if keychainTurnedOff() {
			return ""
		}
		dir, err := currentVaultDir()
		if err != nil {
			return ""
		}
		return passphraseFor(dir, true)
	}
	keychainHoldOff = func() {
		if dir, err := currentVaultDir(); err == nil {
			_ = setKeychainMarker(dir, keychainHoldFile, false)
		}
	}
)

func keychainOptedIn() bool {
	dir, err := currentVaultDir()
	return err == nil && hasKeychainMarker(dir, keychainEnabledFile)
}

// keychainFollow keeps a stored passphrase in step after it changed.
func keychainFollow(optedIn bool, passphrase string) {
	if !optedIn {
		return
	}
	dir, err := currentVaultDir()
	if err == nil {
		if keychainTurnedOff() {
			err = errors.New(keychainDisabledMsg)
		} else {
			err = keychainStore(dir, passphrase)
		}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not update the keychain (%v). The stored passphrase is now wrong; run `cervus keychain enable` again.\n", err)
	}
}

func isAuthFailure(err error) bool {
	var re *client.RemoteError
	return errors.As(err, &re) && re.Code == "auth_failed"
}

const keychainTradeoff = `This stores your vault passphrase in the OS keychain (Secret Service).
- The vault reopens by itself after an idle lock, for MFA-protected roles too, with nobody present.
  After "cervus lock" it stays locked until you run "cervus unlock".
- While your login keyring is open, which is often the whole session even with the screen locked,
  any program running as you can read the passphrase and open the vault.
- "cervus keychain disable" cannot undo a leak: a program that read the passphrase can open any
  copy of the vault. If that may have happened, run "cervus recover" and rotate your secrets.
- If the keyring is closed, you are asked for the passphrase as usual.`

func cmdKeychain(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: cervus keychain <enable [--yes]|disable|status>")
	}
	dir, err := currentVaultDir()
	if err != nil {
		return err
	}
	switch args[0] {
	case "enable":
		return keychainEnable(dir, args[1:])
	case "disable":
		if len(args) != 1 {
			return errors.New("usage: cervus keychain disable")
		}
		if keychainTurnedOff() {
			return errors.New(keychainDisabledMsg)
		}
		if err := keychainClear(dir); err != nil {
			return fmt.Errorf("could not remove it from the keychain, so it stays enabled: %w", err)
		}
		if err := setKeychainMarker(dir, keychainEnabledFile, false); err != nil {
			return err
		}
		_ = setKeychainMarker(dir, keychainHoldFile, false)
		_ = client.Call("keychain.event", map[string]string{"action": "disabled"}, nil)
		fmt.Println("The passphrase is no longer in the keychain.")
		return nil
	case "status":
		fmt.Println(keychainStatusLine(dir))
		return nil
	}
	return fmt.Errorf("unknown keychain command %q", args[0])
}

func keychainStatusLine(dir string) string {
	switch {
	case keychainTurnedOff():
		return "Unknown: " + keychainDisabledMsg + "."
	case !hasKeychainMarker(dir, keychainEnabledFile):
		return "The passphrase is not stored in the keychain."
	case keychainLookup(dir) == "":
		return "The keychain is enabled, but the passphrase could not be read (keyring closed?)."
	case hasKeychainMarker(dir, keychainHoldFile):
		return "The passphrase is stored in the keychain; the vault is held locked until `cervus unlock`."
	}
	return "The passphrase is stored in the keychain; the vault reopens by itself after an idle lock."
}

func keychainEnable(dir string, args []string) error {
	fs := flag.NewFlagSet("keychain enable", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "accept the trade-off without asking")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: cervus keychain enable [--yes]")
	}
	if keychainTurnedOff() {
		return errors.New(keychainDisabledMsg)
	}
	if runtime.GOOS != "linux" {
		return fmt.Errorf("the keychain is only built for Linux so far, not %s", runtime.GOOS)
	}
	if _, err := exec.LookPath("secret-tool"); err != nil {
		return errors.New("secret-tool not found; install libsecret (package libsecret or libsecret-tools)")
	}
	fmt.Println(keychainTradeoff)
	if !*yes {
		if !isTTY(os.Stdin) {
			return errors.New("re-run with --yes to accept this")
		}
		fmt.Fprint(os.Stderr, "Store it? [y/N] ")
		line, _ := stdin.ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
			return errors.New("cancelled")
		}
	}
	passphrase, err := readSecret("Passphrase: ")
	if err != nil {
		return err
	}
	if err := sendUnlock(passphrase, ""); err != nil { // only a passphrase that works gets stored
		return err
	}
	if err := keychainStore(dir, passphrase); err != nil {
		return fmt.Errorf("could not store it in the keychain (is a keyring running and open?): %w", err)
	}
	if keychainLookup(dir) != passphrase {
		_ = keychainClear(dir)
		return errors.New("the keychain did not return what was stored; nothing was kept")
	}
	if err := setKeychainMarker(dir, keychainEnabledFile, true); err != nil {
		_ = keychainClear(dir)
		return err
	}
	_ = setKeychainMarker(dir, keychainHoldFile, false)
	_ = client.Call("keychain.event", map[string]string{"action": "enabled"}, nil)
	fmt.Println("Stored. Undo with `cervus keychain disable`.")
	return nil
}
