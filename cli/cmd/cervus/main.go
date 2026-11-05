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
	"strconv"
	"strings"
	"unicode/utf8"

	"cervus/internal/client"
)

const version = "0.0.9"

// Must match the vault's minimum; the vault enforces it too.
const minPassphraseLen = 10

// One shared reader so piped input is not lost between prompts.
var stdin = bufio.NewReader(os.Stdin)

func main() {
	if len(os.Args) < 2 {
		if !isTTY(os.Stdin) {
			usage()
			os.Exit(2)
		}
		// Just `cervus` in a terminal: get the machine ready, or say that it already is.
		if err := cmdSetup(nil); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		return
	}
	args := os.Args[2:]
	var err error
	switch os.Args[1] {
	case "version":
		fmt.Println("cervus", version)
	case "setup":
		err = cmdSetup(args)
	case "banner":
		printBanner(os.Stdout)
	case "keybinding":
		err = cmdKeybinding(args)
	case "help", "-h", "--help":
		usage()
	case "status":
		err = cmdStatus()
	case "init":
		err = cmdInit()
	case "unlock":
		err = cmdUnlock(args)
	case "lock":
		err = cmdLock(args)
	case "recover":
		err = cmdRecover(args)
	case "passwd":
		err = cmdPasswd(args)
	case "secret":
		err = cmdSecret(args)
	case "identity":
		err = cmdIdentity(args)
	case "role":
		err = cmdRole(args)
	case "use":
		err = cmdUse(args)
	case "exec":
		err = cmdExec(args)
	case "keychain":
		err = cmdKeychain(args)
	case "vault":
		err = cmdVault(args)
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
	case "audit":
		err = cmdAudit(args)
	case "doctor":
		err = cmdDoctor()
	case "migrate":
		err = cmdMigrate(args)
	case "install-service":
		err = cmdInstallService(args)
	case "uninstall-service":
		err = cmdUninstallService(args)
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

func cmdInit() error { return createVault("") }

// vaultArg adds the vault to request parameters; no name means the default vault.
func vaultArg(params map[string]string, vault string) map[string]string {
	if vault != "" {
		params["vault"] = vault
	}
	return params
}

// createVault makes a vault and shows its own recovery key.
func createVault(vault string) error {
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
	if err := client.Call("init", vaultArg(map[string]string{"passphrase": pass}, vault), &out); err != nil {
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

func cmdRecover(args []string) error {
	fs := flag.NewFlagSet("recover", flag.ContinueOnError)
	drop := fs.Bool("drop-local", false, "delete device-only secrets that cannot be recovered")
	vault := fs.String("vault", "", "vault to recover (default: the default vault)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	key, err := readSecret("Recovery key (AGE-SECRET-KEY-...): ")
	if err != nil {
		return err
	}
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
		Reencrypted int      `json:"reencrypted"`
		LostLocal   []string `json:"lost_local"`
	}
	optedIn := keychainOptedIn(*vault)
	params := map[string]any{"recovery_key": key, "passphrase": pass, "drop_local": *drop}
	if *vault != "" {
		params["vault"] = *vault
	}
	if err := client.Call("recover", params, &out); err != nil {
		return err
	}
	keychainFollow(optedIn, pass, *vault)
	fmt.Printf("Recovered. %d secret(s) re-encrypted for this device; the vault is unlocked with the new passphrase.\n", out.Reencrypted)
	if len(out.LostLocal) > 0 {
		fmt.Println("\nThese device-only secrets could not be recovered (they were encrypted to the old device key):")
		for _, n := range out.LostLocal {
			fmt.Println("  " + n)
		}
		fmt.Println("MFA seeds: set them up again with `cervus identity mfa-import <name>`.")
		if !*drop {
			fmt.Println("Run `cervus recover --drop-local` to remove the stale files.")
		}
	}
	fmt.Println("\nYour recovery key is unchanged and still valid.")
	return nil
}

func cmdPasswd(args []string) error {
	fs := flag.NewFlagSet("passwd", flag.ContinueOnError)
	vault := fs.String("vault", "", "vault to change (default: the default vault)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	current, err := readSecret("Current passphrase: ")
	if err != nil {
		return err
	}
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
	optedIn := keychainOptedIn(*vault)
	if err := client.Call("passwd", vaultArg(map[string]string{"current": current, "new": pass}, *vault), nil); err != nil {
		return err
	}
	keychainFollow(optedIn, pass, *vault)
	fmt.Println("Passphrase changed. Your secrets and your recovery key are unchanged.")
	fmt.Println("If the old passphrase or a copy of the vault was exposed, this is not enough: an old copy still opens")
	fmt.Println("with the old passphrase. Run `cervus recover` for a new device key and rotate your secrets.")
	return nil
}

func cmdAudit(args []string) error {
	if len(args) > 0 && args[0] == "verify" {
		var out struct {
			Entries int `json:"entries"`
			BadLine int `json:"bad_line"`
		}
		if err := client.Call("audit.verify", nil, &out); err != nil {
			return err
		}
		if out.BadLine != 0 {
			return fmt.Errorf("the audit log was modified: the chain breaks at line %d of %d", out.BadLine, out.Entries)
		}
		fmt.Printf("audit log intact (%d entries)\n", out.Entries)
		return nil
	}
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	n := fs.Int("n", 20, "number of recent entries (0 = all)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var out struct {
		Lines []string `json:"lines"`
	}
	if err := client.Call("audit.tail", map[string]int{"n": *n}, &out); err != nil {
		return err
	}
	for _, l := range out.Lines {
		fmt.Println(l)
	}
	return nil
}

func cmdLock(args []string) error {
	fs := flag.NewFlagSet("lock", flag.ContinueOnError)
	vault := fs.String("vault", "", "lock only this vault (default: all of them)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := client.Call("lock", vaultArg(map[string]string{}, *vault), nil); err != nil {
		return err
	}
	if *vault != "" {
		fmt.Printf("vault %q locked\n", *vault)
	} else {
		fmt.Println("vault locked")
	}
	// A deliberate lock holds against the keychain until an explicit unlock.
	dirs := map[string]string{}
	if *vault != "" {
		if dir, err := currentVaultDir(*vault); err == nil {
			dirs[*vault] = dir
		}
	} else {
		var out vaultListing
		if client.Call("vault.list", nil, &out) == nil {
			for _, v := range out.Vaults {
				dirs[v.Name] = v.Dir
			}
		}
	}
	for _, dir := range dirs {
		if !hasKeychainMarker(dir, keychainEnabledFile) {
			continue
		}
		if err := setKeychainMarker(dir, keychainHoldFile, true); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: the keychain may reopen the vault on next use: %v\n", err)
		} else {
			fmt.Println("It stays locked until `cervus unlock`, even with the passphrase in the keychain.")
		}
	}
	return nil
}

func cmdUnlock(args []string) error {
	fs := flag.NewFlagSet("unlock", flag.ContinueOnError)
	vault := fs.String("vault", "", "vault to unlock (default: the default vault)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	dir, err := currentVaultDir(*vault)
	if err != nil {
		return err
	}
	if stored := passphraseFor(dir, false); stored != "" {
		uerr := sendUnlock(stored, "keychain", *vault)
		if uerr == nil {
			_ = setKeychainMarker(dir, keychainHoldFile, false)
			fmt.Println("vault unlocked (passphrase from the keychain)")
			return nil
		}
		if !isAuthFailure(uerr) {
			return uerr
		}
		fmt.Fprintln(os.Stderr, "The passphrase in the keychain was refused; run `cervus keychain enable` again.")
	}
	pass, err := readSecret("Passphrase: ")
	if err != nil {
		return err
	}
	if err := sendUnlock(pass, "", *vault); err != nil {
		return err
	}
	_ = setKeychainMarker(dir, keychainHoldFile, false)
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
		vault := fs.String("vault", "", vaultFlagHelp)
		name, err := parseWithName(fs, args[1:], "usage: cervus secret put [--vault V] [--local] [--type T] <name>   (value from stdin)")
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
		return client.Call("secret.put", vaultArg(map[string]string{
			"name": name, "type": *kind, "scope": scope,
			"value": base64.StdEncoding.EncodeToString(value),
		}, secretVault(*vault)), nil)
	case "get":
		fs := flag.NewFlagSet("secret get", flag.ContinueOnError)
		nl := fs.Bool("n", false, "append a trailing newline")
		vault := fs.String("vault", "", vaultFlagHelp)
		name, err := parseWithName(fs, args[1:], "usage: cervus secret get [--vault V] [-n] <name>")
		if err != nil {
			return err
		}
		var out struct {
			Value string `json:"value"`
		}
		if err := client.Call("secret.get", vaultArg(map[string]string{"name": name}, secretVault(*vault)), &out); err != nil {
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
		fs := flag.NewFlagSet("secret list", flag.ContinueOnError)
		vault := fs.String("vault", "", vaultFlagHelp)
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		prefix := fs.Arg(0)
		var out struct {
			Secrets []struct {
				Name  string `json:"name"`
				Scope string `json:"scope"`
			} `json:"secrets"`
		}
		if err := client.Call("secret.list", vaultArg(map[string]string{"prefix": prefix}, secretVault(*vault)), &out); err != nil {
			return err
		}
		for _, s := range out.Secrets {
			fmt.Printf("%-40s %s\n", s.Name, s.Scope)
		}
		return nil
	case "rm":
		fs := flag.NewFlagSet("secret rm", flag.ContinueOnError)
		vault := fs.String("vault", "", vaultFlagHelp)
		name, err := parseWithName(fs, args[1:], "usage: cervus secret rm [--vault V] <name>")
		if err != nil {
			return err
		}
		target := *vault
		if target == "" {
			target = os.Getenv("CERVUS_VAULT")
		}
		// Deleting must not depend on which role this shell happens to be on.
		if implied := activeRoleVault(); target == "" && implied != "" {
			return fmt.Errorf("this shell's role uses vault %q; say which vault: cervus secret rm --vault %s %s", implied, implied, name)
		}
		return client.Call("secret.delete", vaultArg(map[string]string{"name": name}, target), nil)
	}
	return fmt.Errorf("unknown secret command %q", args[0])
}

// ---- identities ----

func cmdIdentity(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: cervus identity <add|update|move|list|remove|mfa-import> ...")
	}
	switch args[0] {
	case "add":
		fs := flag.NewFlagSet("identity add", flag.ContinueOnError)
		region := fs.String("region", "us-east-1", "default AWS region")
		serial := fs.String("mfa-serial", "", "MFA device ARN (arn:aws:iam::<acct>:mfa/<name>)")
		noVerify := fs.Bool("no-verify", false, "do not check the keys against AWS")
		vault := fs.String("vault", "", "vault to keep this user in (default: the default vault)")
		ownVault := fs.Bool("own-vault", false, "create a new vault for this user, named after it")
		id, err := parseWithName(fs, args[1:], "usage: cervus identity add <name> [--vault V | --own-vault] [--region R] [--mfa-serial ARN] [--no-verify]")
		if err != nil {
			return err
		}
		if *ownVault && *vault != "" {
			return errors.New("use --vault or --own-vault, not both")
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
		params := map[string]any{
			"id": id, "region": *region, "mfa_serial": *serial, "vault": *vault,
			"access_key_id": keyID, "secret_access_key": secret, "verify": !*noVerify,
		}
		if *ownVault {
			// Everything that can fail comes first, so a mistake leaves no empty vault behind.
			var list vaultListing
			if err := client.Call("vault.list", nil, &list); err != nil {
				return err
			}
			for _, v := range list.Vaults {
				if v.Name == id && v.Initialized {
					return fmt.Errorf("vault %q already exists; to use it: cervus identity add %s --vault %s", id, id, id)
				}
			}
			params["vault"], params["dry_run"] = id, true
			if err := client.Call("identity.add", params, &out); err != nil {
				return err
			}
			if err := createVault(id); err != nil {
				return err
			}
			delete(params, "dry_run")
			params["verify"] = false // just checked
		}
		err = client.Call("identity.add", params, &out)
		if err != nil {
			return err
		}
		if out.Arn != "" {
			fmt.Printf("Verified with AWS: %s (account %s)\n", out.Arn, out.Account)
		}
		fmt.Printf("Identity %q saved; the access key is stored encrypted in the vault.\n", id)
		return nil
	case "move":
		fs := flag.NewFlagSet("identity move", flag.ContinueOnError)
		vault := fs.String("vault", "", "vault to move this user to")
		id, err := parseWithName(fs, args[1:], "usage: cervus identity move <name> --vault V")
		if err != nil {
			return err
		}
		if *vault == "" {
			return errors.New("usage: cervus identity move <name> --vault V")
		}
		if err := client.Call("identity.move", map[string]string{"id": id, "vault": *vault}, nil); err != nil {
			return err
		}
		fmt.Printf("Identity %q moved to vault %q. Its roles keep working.\n", id, *vault)
		return nil
	case "update":
		fs := flag.NewFlagSet("identity update", flag.ContinueOnError)
		region := fs.String("region", "", "default AWS region")
		serial := fs.String("mfa-serial", "", "MFA device ARN; empty removes it")
		rotate := fs.Bool("rotate-key", false, "replace the stored access key (asks for the new one)")
		noVerify := fs.Bool("no-verify", false, "do not check the new key against AWS")
		allowOther := fs.Bool("allow-different-principal", false, "accept a key that belongs to a different IAM principal")
		id, err := parseWithName(fs, args[1:], "usage: cervus identity update <name> [--rotate-key] [--region R] [--mfa-serial ARN] [--no-verify] [--allow-different-principal]")
		if err != nil {
			return err
		}
		if !*rotate && (*noVerify || *allowOther) {
			return errors.New("--no-verify and --allow-different-principal work only with --rotate-key")
		}
		params := map[string]any{"id": id, "rotate": *rotate, "verify": !*noVerify, "allow_different_principal": *allowOther}
		fs.Visit(func(f *flag.Flag) {
			switch f.Name {
			case "region":
				params["region"] = *region
			case "mfa-serial":
				params["mfa_serial"] = *serial
			}
		})
		if *rotate {
			keyID, err := readLine("New AWS access key ID: ")
			if err != nil {
				return err
			}
			secret, err := readSecret("New AWS secret access key: ")
			if err != nil {
				return err
			}
			params["access_key_id"], params["secret_access_key"] = keyID, secret
		}
		var out struct {
			Arn         string `json:"arn"`
			Account     string `json:"account"`
			PreviousArn string `json:"previous_arn"`
			OldKey      string `json:"old_key_unverified"`
		}
		if err := client.Call("identity.update", params, &out); err != nil {
			return err
		}
		if out.Arn != "" {
			fmt.Printf("Verified with AWS: %s (account %s)\n", out.Arn, out.Account)
		}
		if out.PreviousArn != "" {
			fmt.Printf("Warning: the old key belonged to %s and the new one to %s; check that your roles still trust it.\n", out.PreviousArn, out.Arn)
		}
		if out.OldKey != "" {
			fmt.Println("Note: the old key could not be checked (revoked?), so it was not compared with the new one.")
		}
		fmt.Printf("Identity %q updated.\n", id)
		if *rotate {
			fmt.Println("If you are done with the old key, delete it in AWS IAM; Cervus does not do that.")
		}
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
				Vault     string `json:"vault"`
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
			fmt.Printf("%-20s %-14s %-14s %s\n", i.Name, i.Region, i.Vault, mfa)
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
		return errors.New("usage: cervus role <add|edit|list|remove> ...")
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
	case "edit":
		fs := flag.NewFlagSet("role edit", flag.ContinueOnError)
		identity := fs.String("identity", "", "identity to authenticate as")
		arn := fs.String("arn", "", "role ARN to assume; empty uses the identity itself")
		region := fs.String("region", "", "region override; empty removes it")
		mfa := fs.String("mfa", "", "none | once | always")
		confirm := fs.Bool("confirm", false, "ask for confirmation before switching to this role")
		noConfirm := fs.Bool("no-confirm", false, "stop asking for confirmation")
		dur := fs.Duration("duration", 0, "session duration, e.g. 1h; 0 uses the default")
		name, err := parseWithName(fs, args[1:], "usage: cervus role edit <name> [--identity I] [--arn ARN] [--region R] [--mfa none|once|always] [--confirm|--no-confirm] [--duration 1h]")
		if err != nil {
			return err
		}
		if *confirm && *noConfirm {
			return errors.New("use --confirm or --no-confirm, not both")
		}
		params := map[string]any{"name": name}
		fs.Visit(func(f *flag.Flag) {
			switch f.Name {
			case "identity":
				params["identity"] = *identity
			case "arn":
				params["arn"] = *arn
			case "region":
				params["region"] = *region
			case "mfa":
				params["mfa"] = *mfa
			case "confirm":
				params["confirm"] = *confirm
			case "no-confirm":
				params["confirm"] = !*noConfirm
			case "duration":
				params["duration_secs"] = int(dur.Seconds())
			}
		})
		var out struct {
			ShellsRemoved int `json:"shells_removed"`
		}
		if err := client.Call("role.edit", params, &out); err != nil {
			return err
		}
		fmt.Printf("Role %q updated.\n", name)
		if out.ShellsRemoved > 0 {
			fmt.Printf("%d shell(s) must run `cervus use %s` again.\n", out.ShellsRemoved, name)
		}
		return nil
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
// sendUnlock is a variable so tests can run withUnlock without a daemon.
// source is "keychain" for an automatic unlock, so the audit log can tell it from a typed one.
var sendUnlock = func(passphrase, source, vault string) error {
	params := vaultArg(map[string]string{"passphrase": passphrase}, vault)
	if source != "" {
		params["source"] = source
	}
	return client.Call("unlock", params, nil)
}

// withUnlock runs call; if the vault is locked it tries the keychain, then asks once for the
// passphrase, unlocks and retries. A nil ask means there is no terminal to ask on, so without a
// stored passphrase the locked error stands.
func withUnlock(call func() error, ask func(vault string) (string, error)) error {
	err := call()
	var re *client.RemoteError
	if !errors.As(err, &re) || re.Code != "locked" {
		return err
	}
	vault := re.Vault // the daemon names the vault that needs opening
	if stored := storedPassphrase(vault); stored != "" {
		uerr := sendUnlock(stored, "keychain", vault)
		if uerr == nil {
			return call()
		}
		if isAuthFailure(uerr) {
			fmt.Fprintln(os.Stderr, "The passphrase in the keychain was refused; run `cervus keychain enable` again.")
		}
	}
	if ask == nil {
		return err
	}
	passphrase, err := ask(vault)
	if err != nil {
		return err
	}
	if err := sendUnlock(passphrase, "", vault); err != nil {
		return err
	}
	keychainHoldOff(vault)
	return call()
}

func switchRole(role string, yes bool, confirm func() (bool, error), ask func(vault string) (string, error)) (useResult, error) {
	call := func(confirmed bool) (useResult, error) {
		var out useResult
		err := withUnlock(func() error {
			params := map[string]any{"session": sessionID(), "role": role, "confirmed": confirmed}
			if pid, err := strconv.Atoi(os.Getenv("CERVUS_SESSION_OWNER")); err == nil && pid > 1 {
				params["pid"] = pid // re-registers a shell the daemon has forgotten
			}
			return client.Call("use", params, &out)
		}, ask)
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

func confirmOnStdin(role string) func() (bool, error) {
	return func() (bool, error) {
		if !isTTY(os.Stdin) {
			return false, fmt.Errorf("role %q is protected; re-run with --yes to confirm", role)
		}
		fmt.Fprintf(os.Stderr, "Role %q is protected. Switch to it? [y/N] ", role)
		line, _ := stdin.ReadString('\n')
		a := strings.ToLower(strings.TrimSpace(line))
		return a == "y" || a == "yes", nil
	}
}

func askOnStdin() func(string) (string, error) {
	if !isTTY(os.Stdin) {
		return nil
	}
	return func(vault string) (string, error) { return readSecret(unlockPrompt(vault)) }
}

func unlockPrompt(vault string) string {
	if vault == "" || vault == "default" {
		return "Vault is locked. Passphrase: "
	}
	return fmt.Sprintf("Vault %q is locked. Passphrase: ", vault)
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
	out, err := switchRole(role, *yes, confirmOnStdin(role), askOnStdin())
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
	err := withUnlock(func() error {
		return client.Call("credentials", map[string]string{"session": sessionID()}, &raw)
	}, nil)
	if err != nil {
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
	_, path := awsPaths()
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
  setup [--yes]              Get this machine ready (also what cervus alone does in a terminal)
  keybinding [key]           Show or change the role picker's key (default alt+r)
  init                       Create the default vault (passphrase + recovery key)
  vault create <n> | list    More vaults, each with its own passphrase and recovery key
  unlock | lock | status     Unlock, lock or inspect the vault (unlock and lock take --vault V; lock alone locks all)
  passwd [--vault V]         Change the passphrase
  keychain enable|disable|status   Keep the passphrase in the OS keychain (Linux, optional)
  recover [--drop-local] [--vault V]   Lost your passphrase? Reset it with the recovery key
  secret put [--vault V] [--local] <n>   Store a secret (value from stdin)
                             Without --vault: $CERVUS_VAULT, the active role's vault, else default
  secret get [-n] <n>        Print a secret to stdout
  secret list [prefix]       List secret names
  secret rm <n>              Delete a secret

AWS:
  identity add <n> [--vault V | --own-vault] [--region R] [--mfa-serial ARN]   Store an IAM access key (verified with AWS)
  identity move <n> --vault V  Carry a user's key and MFA seed to another vault
  identity mfa-import <n>    Store the MFA seed for an identity (device-only)
  identity update <n> [--rotate-key] [--region R] [--mfa-serial ARN] [--no-verify] [--allow-different-principal]
                             Rotate the key or change settings; roles and MFA seed stay
  identity list | remove <n>
  role add <n> --identity I [--arn ARN] [--mfa none|once|always] [--confirm] [--duration 1h]
  role edit <n> [--identity I] [--arn ARN] [--region R] [--mfa M] [--confirm|--no-confirm] [--duration 1h]
                             Change only the given settings of a role
  role list | remove <n>
  use [role|user:<n>] [--yes]  Switch this shell to a role or user (no argument opens the picker)
  exec <role> [--yes] -- <cmd>  Run one command pinned to a role, in its own session
  pick                       Interactive role picker (bound to Alt+r by init-shell)
  init-shell <zsh|bash> [--prompt] [--install] [--key K]
                             Shell integration: per-shell session, Alt+r, prompt segment
  whoami                     Show the current role and time left
  audit [-n N] | audit verify  Show recent security events; check the log was not tampered with
  migrate [--dry-run] [--yes]  Move plaintext ~/.aws/credentials keys into the vault, import role profiles
  doctor                     Check permissions, plaintext leftovers, profile and shell setup
  aws-profile [--install]    Print or install the AWS CLI profile (credential_process)
  credential-process         Used by the AWS CLI; prints credentials as JSON

  install-service            Start cervusd at login (systemd user unit or launchd agent)
  uninstall-service          Remove the service; the vault, config and audit log stay

  version                    Print version
`)
}
