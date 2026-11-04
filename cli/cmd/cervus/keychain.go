package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
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
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	return out.String(), err
}

func keychainAttrs(vaultDir string) []string { return []string{"service", "cervus", "vault", vaultDir} }

func keychainStore(vaultDir, passphrase string) error {
	_, err := runSecretTool(passphrase, append([]string{"store", "--label=Cervus vault passphrase"}, keychainAttrs(vaultDir)...)...)
	return err
}

func keychainLookup(vaultDir string) string {
	if os.Getenv("CERVUS_NO_KEYCHAIN") != "" {
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

// storedPassphrase is a variable so tests can run withUnlock without a keyring.
var storedPassphrase = func() string {
	if os.Getenv("CERVUS_NO_KEYCHAIN") != "" {
		return ""
	}
	dir, err := currentVaultDir()
	if err != nil {
		return ""
	}
	return keychainLookup(dir)
}

// keychainFollow keeps a stored passphrase in step after it changed.
func keychainFollow(wasStored bool, passphrase string) {
	if !wasStored {
		return
	}
	dir, err := currentVaultDir()
	if err == nil {
		err = keychainStore(dir, passphrase)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not update the keychain (%v). Run `cervus keychain enable` again.\n", err)
	}
}

const keychainTradeoff = `This stores your vault passphrase in the OS keychain (Secret Service).
- The vault then opens by itself when it is needed, so no passphrase prompts.
- While your login keyring is open, any program running as you can read the passphrase and open
  the vault, even when the vault is locked. Without the keychain it would need you to type it.
- Idle auto-lock and "cervus lock" still clear memory, but the next use reopens the vault.`

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
		if err := keychainClear(dir); err != nil {
			return fmt.Errorf("could not remove it from the keychain: %w", err)
		}
		fmt.Println("The passphrase is no longer in the keychain.")
		return nil
	case "status":
		if keychainLookup(dir) != "" {
			fmt.Println("The passphrase is stored in the keychain; the vault opens by itself when needed.")
		} else {
			fmt.Println("The passphrase is not stored in the keychain.")
		}
		return nil
	}
	return fmt.Errorf("unknown keychain command %q", args[0])
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
	if err := sendUnlock(passphrase); err != nil { // only a passphrase that works gets stored
		return err
	}
	if err := keychainStore(dir, passphrase); err != nil {
		return fmt.Errorf("could not store it in the keychain (is a keyring running and open?): %w", err)
	}
	if keychainLookup(dir) != passphrase {
		_ = keychainClear(dir)
		return errors.New("the keychain did not return what was stored; nothing was kept")
	}
	fmt.Println("Stored. Undo with `cervus keychain disable`.")
	return nil
}
