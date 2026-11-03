// cervus is the command-line client for the Cervus daemon.
package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"cervus/internal/client"
)

const version = "0.0.4"

// Must match the vault's minimum; the vault enforces it too.
const minPassphraseLen = 10

// One shared reader so piped input is not lost between prompts.
var stdin = bufio.NewReader(os.Stdin)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	args := os.Args[2:]
	var err error
	switch os.Args[1] {
	case "version":
		fmt.Println("cervus", version)
	case "help", "-h", "--help":
		usage()
	case "status":
		err = cmdStatus()
	case "init":
		err = cmdInit()
	case "unlock":
		err = cmdUnlock()
	case "lock":
		if err = client.Call("lock", nil, nil); err == nil {
			fmt.Println("vault locked")
		}
	case "secret":
		err = cmdSecret(args)
	case "identity":
		err = cmdIdentity(args)
	case "role":
		err = cmdRole(args)
	case "use":
		err = cmdUse(args)
	case "whoami":
		err = cmdWhoami()
	case "pick":
		err = cmdPick()
	case "prompt":
		err = cmdPrompt(args)
	case "session":
		err = cmdSession(args)
	case "init-shell":
		err = cmdInitShell(args)
	case "credential-process":
		err = cmdCredentialProcess()
	case "aws-profile":
		err = cmdAWSProfile(args)
	case "doctor":
		err = errors.New("\"doctor\" is not implemented yet")
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func sessionID() string {
	if s := os.Getenv("CERVUS_SESSION"); s != "" {
		return s
	}
	return "default"
}

// ---- vault lifecycle ----

func cmdStatus() error {
	var s struct {
		Initialized bool   `json:"initialized"`
		Locked      bool   `json:"locked"`
		Version     string `json:"version"`
		IdleTimeout uint64 `json:"idle_timeout_secs"`
	}
	if err := client.Call("status", nil, &s); err != nil {
		return err
	}
	state := "unlocked"
	switch {
	case !s.Initialized:
		state = "not initialized (run `cervus init`)"
	case s.Locked:
		state = "locked (run `cervus unlock`)"
	}
	fmt.Printf("vault %s: %s, auto-lock after %ds idle\n", s.Version, state, s.IdleTimeout)
	return nil
}

func cmdInit() error {
	pass, err := readSecret("New passphrase (min 10 characters): ")
	if err != nil {
		return err
	}
	if utf8.RuneCountInString(pass) < minPassphraseLen {
		return fmt.Errorf("passphrase must be at least %d characters", minPassphraseLen)
	}
	again, err := readSecret("Repeat passphrase: ")
	if err != nil {
		return err
	}
	if pass != again {
		return errors.New("passphrases do not match")
	}
	var out struct {
		RecoveryKey string `json:"recovery_key"`
	}
	if err := client.Call("init", map[string]string{"passphrase": pass}, &out); err != nil {
		return err
	}
	fmt.Println()
	fmt.Println("Vault created and unlocked.")
	fmt.Println()
	fmt.Println("RECOVERY KEY (shown once, store it somewhere safe and offline):")
	fmt.Println()
	fmt.Println("  " + out.RecoveryKey)
	fmt.Println()
	fmt.Println("If you lose your passphrase or this device, this key is the only way to")
	fmt.Println("recover synced secrets. Device-only secrets (MFA seeds) are not recoverable.")
	if isTTY(os.Stdin) {
		confirmRecoveryKey(out.RecoveryKey)
	}
	return nil
}

// confirmRecoveryKey makes the user prove they copied the key by typing its last characters.
func confirmRecoveryKey(key string) {
	tail := key[len(key)-6:]
	for attempt := 1; attempt <= 5; attempt++ {
		fmt.Printf("\nTo confirm you saved it, type the last 6 characters of the key: ")
		line, err := stdin.ReadString('\n')
		if strings.EqualFold(strings.TrimSpace(line), tail) {
			fmt.Println("Confirmed.")
			return
		}
		if err != nil {
			break
		}
		fmt.Println("That does not match. Check the key you saved.")
	}
	fmt.Println("\nNot confirmed. The key is shown only once: copy it from above before closing this window.")
}

func cmdUnlock() error {
	pass, err := readSecret("Passphrase: ")
	if err != nil {
		return err
	}
	if err := client.Call("unlock", map[string]string{"passphrase": pass}, nil); err != nil {
		return err
	}
	fmt.Println("vault unlocked")
	return nil
}

// ---- secrets ----

func cmdSecret(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: cervus secret <put|get|list|rm> ...")
	}
	switch args[0] {
	case "put":
		fs := flag.NewFlagSet("secret put", flag.ContinueOnError)
		local := fs.Bool("local", false, "device-only secret (never synced)")
		kind := fs.String("type", "generic", "secret type label")
		name, err := parseWithName(fs, args[1:], "usage: cervus secret put [--local] [--type T] <name>   (value from stdin)")
		if err != nil {
			return err
		}
		value, err := readValue()
		if err != nil {
			return err
		}
		scope := "synced"
		if *local {
			scope = "local"
		}
		return client.Call("secret.put", map[string]string{
			"name": name, "type": *kind, "scope": scope,
			"value": base64.StdEncoding.EncodeToString(value),
		}, nil)
	case "get":
		fs := flag.NewFlagSet("secret get", flag.ContinueOnError)
		nl := fs.Bool("n", false, "append a trailing newline")
		name, err := parseWithName(fs, args[1:], "usage: cervus secret get [-n] <name>")
		if err != nil {
			return err
		}
		var out struct {
			Value string `json:"value"`
		}
		if err := client.Call("secret.get", map[string]string{"name": name}, &out); err != nil {
			return err
		}
		raw, err := base64.StdEncoding.DecodeString(out.Value)
		if err != nil {
			return err
		}
		if *nl {
			raw = append(raw, '\n')
		}
		_, err = os.Stdout.Write(raw)
		return err
	case "list":
		prefix := ""
		if len(args) > 1 {
			prefix = args[1]
		}
		var out struct {
			Secrets []struct {
				Name  string `json:"name"`
				Scope string `json:"scope"`
			} `json:"secrets"`
		}
		if err := client.Call("secret.list", map[string]string{"prefix": prefix}, &out); err != nil {
			return err
		}
		for _, s := range out.Secrets {
			fmt.Printf("%-40s %s\n", s.Name, s.Scope)
		}
		return nil
	case "rm":
		if len(args) != 2 {
			return errors.New("usage: cervus secret rm <name>")
		}
		return client.Call("secret.delete", map[string]string{"name": args[1]}, nil)
	}
	return fmt.Errorf("unknown secret command %q", args[0])
}

// ---- identities ----

func cmdIdentity(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: cervus identity <add|list|remove|mfa-import> ...")
	}
	switch args[0] {
	case "add":
		fs := flag.NewFlagSet("identity add", flag.ContinueOnError)
		region := fs.String("region", "us-east-1", "default AWS region")
		serial := fs.String("mfa-serial", "", "MFA device ARN (arn:aws:iam::<acct>:mfa/<name>)")
		noVerify := fs.Bool("no-verify", false, "do not check the keys against AWS")
		id, err := parseWithName(fs, args[1:], "usage: cervus identity add <name> [--region R] [--mfa-serial ARN] [--no-verify]")
		if err != nil {
			return err
		}
		keyID, err := readLine("AWS access key ID: ")
		if err != nil {
			return err
		}
		secret, err := readSecret("AWS secret access key: ")
		if err != nil {
			return err
		}
		var out struct {
			Arn     string `json:"arn"`
			Account string `json:"account"`
		}
		err = client.Call("identity.add", map[string]any{
			"id": id, "region": *region, "mfa_serial": *serial,
			"access_key_id": keyID, "secret_access_key": secret, "verify": !*noVerify,
		}, &out)
		if err != nil {
			return err
		}
		if out.Arn != "" {
			fmt.Printf("Verified with AWS: %s (account %s)\n", out.Arn, out.Account)
		}
		fmt.Printf("Identity %q saved; the access key is stored encrypted in the vault.\n", id)
		return nil
	case "mfa-import":
		if len(args) != 2 {
			return errors.New("usage: cervus identity mfa-import <name>")
		}
		seed, err := readSecret("MFA seed (base32): ")
		if err != nil {
			return err
		}
		var out struct {
			SerialConfigured bool `json:"mfa_serial_configured"`
		}
		if err := client.Call("identity.mfa_import", map[string]string{"id": args[1], "seed": seed}, &out); err != nil {
			return err
		}
		fmt.Println("MFA seed stored on this device only (never synced).")
		if !out.SerialConfigured {
			fmt.Println("Note: this identity has no MFA serial yet, so roles cannot use MFA.")
		}
		return nil
	case "list":
		var out struct {
			Identities []struct {
				Name      string `json:"name"`
				Region    string `json:"region"`
				MFASerial string `json:"mfa_serial"`
			} `json:"identities"`
		}
		if err := client.Call("identity.list", nil, &out); err != nil {
			return err
		}
		for _, i := range out.Identities {
			mfa := "no MFA"
			if i.MFASerial != "" {
				mfa = i.MFASerial
			}
			fmt.Printf("%-20s %-14s %s\n", i.Name, i.Region, mfa)
		}
		return nil
	case "remove":
		if len(args) != 2 {
			return errors.New("usage: cervus identity remove <name>")
		}
		return client.Call("identity.remove", map[string]string{"id": args[1]}, nil)
	}
	return fmt.Errorf("unknown identity command %q", args[0])
}

// ---- roles ----

func cmdRole(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: cervus role <add|list|remove> ...")
	}
	switch args[0] {
	case "add":
		fs := flag.NewFlagSet("role add", flag.ContinueOnError)
		identity := fs.String("identity", "", "identity to authenticate as (required)")
		arn := fs.String("arn", "", "role ARN to assume (omit to use the identity itself)")
		region := fs.String("region", "", "region override")
		mfa := fs.String("mfa", "none", "none | once | always")
		confirm := fs.Bool("confirm", false, "ask for confirmation before switching to this role")
		dur := fs.Duration("duration", 0, "session duration, e.g. 1h (default 1h)")
		name, err := parseWithName(fs, args[1:], "usage: cervus role add <name> --identity I [--arn ARN] [--mfa none|once|always] [--confirm] [--duration 1h]")
		if err != nil {
			return err
		}
		return client.Call("role.add", map[string]any{
			"name": name, "identity": *identity, "arn": *arn, "region": *region,
			"mfa": *mfa, "confirm": *confirm, "duration_secs": int(dur.Seconds()),
		}, nil)
	case "list":
		var out struct {
			Roles []struct {
				Name     string `json:"name"`
				Identity string `json:"identity"`
				ARN      string `json:"arn"`
				MFA      string `json:"mfa"`
				Confirm  bool   `json:"confirm"`
			} `json:"roles"`
		}
		if err := client.Call("role.list", nil, &out); err != nil {
			return err
		}
		for _, r := range out.Roles {
			flags := "mfa=" + r.MFA
			if r.Confirm {
				flags += " confirm"
			}
			target := r.ARN
			if target == "" {
				target = "(identity session)"
			}
			fmt.Printf("%-16s %-14s %-50s %s\n", r.Name, r.Identity, target, flags)
		}
		return nil
	case "remove":
		if len(args) != 2 {
			return errors.New("usage: cervus role remove <name>")
		}
		return client.Call("role.remove", map[string]string{"name": args[1]}, nil)
	}
	return fmt.Errorf("unknown role command %q", args[0])
}

// ---- switching and credentials ----

type useResult struct {
	Role      string `json:"role"`
	ExpiresAt string `json:"expires_at"`
}

// switchRole switches this shell's session to a role. If the role is protected and yes is false,
// confirm decides whether to proceed.
func switchRole(role string, yes bool, confirm func() (bool, error)) (useResult, error) {
	call := func(confirmed bool) (useResult, error) {
		var out useResult
		err := client.Call("use", map[string]any{"session": sessionID(), "role": role, "confirmed": confirmed}, &out)
		return out, err
	}
	out, err := call(yes)
	var re *client.RemoteError
	if errors.As(err, &re) && re.Code == "confirm_required" {
		ok, cerr := confirm()
		if cerr != nil {
			return out, cerr
		}
		if !ok {
			return out, errors.New("cancelled")
		}
		return call(true)
	}
	return out, err
}

func cmdUse(args []string) error {
	if len(args) == 0 && isTTY(os.Stdin) {
		return cmdPick()
	}
	fs := flag.NewFlagSet("use", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "skip the confirmation for protected roles")
	role, err := parseWithName(fs, args, "usage: cervus use <role> [--yes]")
	if err != nil {
		return err
	}
	confirm := func() (bool, error) {
		if !isTTY(os.Stdin) {
			return false, fmt.Errorf("role %q is protected; re-run with --yes to confirm", role)
		}
		fmt.Printf("Role %q is protected. Switch to it? [y/N] ", role)
		line, _ := stdin.ReadString('\n')
		a := strings.ToLower(strings.TrimSpace(line))
		return a == "y" || a == "yes", nil
	}
	out, err := switchRole(role, *yes, confirm)
	if err != nil {
		return err
	}
	fmt.Printf("Now using role %q (credentials valid until %s)\n", out.Role, out.ExpiresAt)
	return nil
}

func cmdWhoami() error {
	var out struct {
		Role        string `json:"role"`
		ExpiresAt   string `json:"expires_at"`
		SecondsLeft int    `json:"seconds_left"`
	}
	if err := client.Call("whoami", map[string]string{"session": sessionID()}, &out); err != nil {
		return err
	}
	if out.Role == "" {
		fmt.Println("no role selected in this shell")
		return nil
	}
	fmt.Printf("role %s, %d minutes left\n", out.Role, out.SecondsLeft/60)
	return nil
}

// cmdCredentialProcess prints credentials in the format the AWS CLI expects from credential_process.
func cmdCredentialProcess() error {
	var raw json.RawMessage
	if err := client.Call("credentials", map[string]string{"session": sessionID()}, &raw); err != nil {
		return err
	}
	fmt.Println(string(raw))
	return nil
}

func cmdAWSProfile(args []string) error {
	fs := flag.NewFlagSet("aws-profile", flag.ContinueOnError)
	install := fs.Bool("install", false, "append the profile to ~/.aws/config")
	if err := fs.Parse(args); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	snippet := fmt.Sprintf("[profile cervus]\ncredential_process = %s credential-process\n", exe)
	if !*install {
		fmt.Print(snippet)
		fmt.Println("\nAdd this to ~/.aws/config (or run with --install), then: export AWS_PROFILE=cervus")
		return nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	path := filepath.Join(home, ".aws", "config")
	existing, _ := os.ReadFile(path)
	if strings.Contains(string(existing), "[profile cervus]") {
		return errors.New("[profile cervus] already exists in " + path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.WriteString("\n" + snippet); err != nil {
		return err
	}
	fmt.Println("Added [profile cervus] to", path)
	fmt.Println("Use it with: export AWS_PROFILE=cervus")
	return nil
}

// ---- input helpers ----

// parseWithName parses flags that may appear before or after one positional name.
func parseWithName(fs *flag.FlagSet, args []string, usageMsg string) (string, error) {
	var name string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		name, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return "", err
	}
	if name == "" && fs.NArg() == 1 {
		name = fs.Arg(0)
	} else if fs.NArg() != 0 {
		return "", errors.New(usageMsg)
	}
	if name == "" {
		return "", errors.New(usageMsg)
	}
	return name, nil
}

func isTTY(f *os.File) bool {
	st, err := f.Stat()
	if err != nil || st.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	if null, err := os.Stat(os.DevNull); err == nil && os.SameFile(st, null) {
		return false // /dev/null is a character device but not a terminal
	}
	return true
}

func readLine(prompt string) (string, error) {
	if isTTY(os.Stdin) {
		fmt.Fprint(os.Stderr, prompt)
	}
	line, err := stdin.ReadString('\n')
	if err != nil && (err != io.EOF || line == "") {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// readSecret reads one line without echo when attached to a terminal.
func readSecret(prompt string) (string, error) {
	if isTTY(os.Stdin) {
		fmt.Fprint(os.Stderr, prompt)
		off := exec.Command("stty", "-echo")
		off.Stdin = os.Stdin
		_ = off.Run()
		defer func() {
			on := exec.Command("stty", "echo")
			on.Stdin = os.Stdin
			_ = on.Run()
			fmt.Fprintln(os.Stderr)
		}()
	}
	line, err := stdin.ReadString('\n')
	if err != nil && (err != io.EOF || line == "") {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// readValue reads a secret value: hidden prompt on a terminal, raw stdin otherwise.
func readValue() ([]byte, error) {
	if isTTY(os.Stdin) {
		s, err := readSecret("Value: ")
		return []byte(s), err
	}
	return io.ReadAll(stdin)
}

func usage() {
	fmt.Print(`cervus - encrypted AWS secrets and role switching for your terminal

Vault:
  init                       Create the vault (passphrase + recovery key)
  unlock | lock | status     Unlock, lock or inspect the vault
  secret put [--local] <n>   Store a secret (value from stdin)
  secret get [-n] <n>        Print a secret to stdout
  secret list [prefix]       List secret names
  secret rm <n>              Delete a secret

AWS:
  identity add <n> [--region R] [--mfa-serial ARN]   Store an IAM access key (verified with AWS)
  identity mfa-import <n>    Store the MFA seed for an identity (device-only)
  identity list | remove <n>
  role add <n> --identity I [--arn ARN] [--mfa none|once|always] [--confirm] [--duration 1h]
  role list | remove <n>
  use [role] [--yes]         Switch this shell to a role (no argument opens the picker)
  pick                       Interactive role picker (bound to Alt+r by init-shell)
  init-shell <zsh|bash> [--prompt] [--install]
                             Shell integration: per-shell session, Alt+r, prompt segment
  whoami                     Show the current role and time left
  aws-profile [--install]    Print or install the AWS CLI profile (credential_process)
  credential-process         Used by the AWS CLI; prints credentials as JSON

  version                    Print version
`)
}
