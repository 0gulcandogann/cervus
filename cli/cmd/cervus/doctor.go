package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"cervus/internal/client"
)

type checkLevel int

const (
	lvlOK checkLevel = iota
	lvlWarn
	lvlFail
)

type doctor struct {
	fails, warns int
	out          io.Writer
}

func (d *doctor) report(l checkLevel, msg, fix string) {
	tag := map[checkLevel]string{lvlOK: "[ ok ]", lvlWarn: "[warn]", lvlFail: "[FAIL]"}[l]
	fmt.Fprintf(d.out, "%s %s\n", tag, msg)
	if l != lvlOK && fix != "" {
		fmt.Fprintf(d.out, "       -> %s\n", fix)
	}
	switch l {
	case lvlFail:
		d.fails++
	case lvlWarn:
		d.warns++
	}
}

func modeOf(path string) (os.FileMode, bool) {
	st, err := os.Stat(path)
	if err != nil {
		return 0, false
	}
	return st.Mode().Perm(), true
}

// checkPerm warns when a path is accessible by group or others.
func (d *doctor) checkPerm(label, path string) {
	m, ok := modeOf(path)
	if !ok {
		return
	}
	if m&0o077 != 0 {
		d.report(lvlFail, fmt.Sprintf("%s is accessible by other users (mode %o): %s", label, m, path), "chmod go-rwx "+path)
		return
	}
	d.report(lvlOK, fmt.Sprintf("%s permissions (%o)", label, m), "")
}

func cmdDoctor() error {
	d := &doctor{out: os.Stdout}
	d.checkService()

	var st struct {
		Initialized bool   `json:"initialized"`
		Locked      bool   `json:"locked"`
		Dir         string `json:"dir"`
	}
	if err := client.Call("status", nil, &st); err != nil {
		d.report(lvlFail, "the cervus daemon is not reachable", "run `cervus install-service`, or start `cervusd` by hand")
		return d.finish()
	}
	d.report(lvlOK, "daemon is running", "")
	d.checkPerm("daemon socket", client.SocketPath())
	d.checkPerm("socket directory", filepath.Dir(client.SocketPath()))

	switch {
	case !st.Initialized:
		d.report(lvlFail, "the vault is not initialized", "run `cervus init`")
	case st.Locked:
		d.report(lvlWarn, "the vault is locked", "run `cervus unlock`")
	default:
		d.report(lvlOK, "vault is initialized and unlocked", "")
	}
	if st.Dir != "" {
		if !keychainTurnedOff() && hasKeychainMarker(st.Dir, keychainEnabledFile) {
			if keychainLookup(st.Dir) == "" {
				d.report(lvlWarn, "the keychain is enabled, but the passphrase could not be read", "open your login keyring, or run `cervus keychain enable` again")
			} else {
				d.report(lvlOK, "passphrase is in the OS keychain", "")
			}
		}
		d.checkPerm("vault directory", st.Dir)
		d.checkPerm("device key", filepath.Join(st.Dir, "device.key.age"))
	}

	// identities and roles
	var ids struct {
		Identities []struct {
			Name      string `json:"name"`
			MFASerial string `json:"mfa_serial"`
			Vault     string `json:"vault"`
		} `json:"identities"`
	}
	var roles struct {
		Roles []struct {
			Name     string `json:"name"`
			Identity string `json:"identity"`
			MFA      string `json:"mfa"`
		} `json:"roles"`
	}
	_ = client.Call("identity.list", nil, &ids)
	_ = client.Call("role.list", nil, &roles)
	if len(ids.Identities) == 0 {
		d.report(lvlWarn, "no identities yet", "run `cervus identity add <name>` or `cervus migrate`")
	} else if len(roles.Roles) == 0 {
		d.report(lvlWarn, "no roles yet", "run `cervus role add <name> --identity <id> --arn <role-arn>`")
	} else {
		d.report(lvlOK, fmt.Sprintf("%d identit(ies), %d role(s) configured", len(ids.Identities), len(roles.Roles)), "")
	}
	if st.Initialized && !st.Locked {
		// Seeds live in each user's own vault; a vault that cannot be read is not reported as missing one.
		have := map[string]bool{}
		for _, ident := range ids.Identities {
			var seeds struct {
				Secrets []struct {
					Name string `json:"name"`
				} `json:"secrets"`
			}
			err := client.Call("secret.list", vaultArg(map[string]string{"prefix": "mfa-seed." + ident.Name}, ident.Vault), &seeds)
			have[ident.Name] = err != nil
			for _, sec := range seeds.Secrets {
				if strings.TrimPrefix(sec.Name, "mfa-seed.") == ident.Name {
					have[ident.Name] = true
				}
			}
		}
		needs := map[string]bool{}
		for _, r := range roles.Roles {
			if r.MFA != "none" {
				needs[r.Identity] = true
			}
		}
		for id := range needs {
			if !have[id] {
				d.report(lvlWarn, fmt.Sprintf("identity %q has MFA roles but no MFA seed on this device", id), fmt.Sprintf("run `cervus identity mfa-import %s`", id))
			}
		}
	}

	// plaintext leftovers
	credsPath, cfgPath := awsPaths()
	if data, err := os.ReadFile(credsPath); err == nil {
		n := 0
		for _, s := range parseINI(data).sections {
			if s.get("aws_access_key_id") != "" && s.get("aws_secret_access_key") != "" && s.get("aws_session_token") == "" {
				n++
			}
		}
		if n > 0 {
			d.report(lvlWarn, fmt.Sprintf("%d plaintext access key(s) in %s", n, credsPath), "run `cervus migrate`")
			d.checkPerm("AWS credentials file", credsPath)
		} else {
			d.report(lvlOK, "no plaintext access keys in "+credsPath, "")
		}
	}
	if os.Getenv("AWS_ACCESS_KEY_ID") != "" {
		d.report(lvlWarn, "AWS_ACCESS_KEY_ID is set in this shell and overrides profiles", "unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN")
	}

	// AWS CLI profile
	cfgData, _ := os.ReadFile(cfgPath)
	if p := parseINI(cfgData).find("profile cervus"); p == nil {
		d.report(lvlWarn, "no [profile cervus] in "+cfgPath, "run `cervus aws-profile --install`")
	} else if cp := p.get("credential_process"); cp == "" {
		d.report(lvlWarn, "[profile cervus] has no credential_process", "run `cervus aws-profile` and fix the profile")
	} else {
		bin := strings.Fields(cp)[0]
		if _, err := os.Stat(bin); err != nil {
			d.report(lvlFail, "credential_process points to a missing program: "+bin, "run `cervus aws-profile` and update the profile")
		} else {
			d.report(lvlOK, "AWS CLI profile [profile cervus] is set up", "")
		}
	}

	// shell integration
	if os.Getenv("CERVUS_SESSION_OWNER") != "" {
		d.report(lvlOK, "shell integration is active in this shell", "")
	} else {
		home, _ := os.UserHomeDir()
		found := false
		for _, rc := range []string{".zshrc", ".bashrc"} {
			if b, err := os.ReadFile(filepath.Join(home, rc)); err == nil && strings.Contains(string(b), "# cervus") {
				found = true
			}
		}
		if found {
			d.report(lvlWarn, "shell integration is installed but not active in this shell", "open a new terminal")
		} else {
			d.report(lvlWarn, "shell integration is not installed", "run `cervus init-shell zsh --prompt --install` (or bash)")
		}
	}
	if os.Getenv("AWS_PROFILE") != "cervus" {
		d.report(lvlWarn, "AWS_PROFILE is not 'cervus' in this shell, so the AWS CLI will not use Cervus", "export AWS_PROFILE=cervus (init-shell does this)")
	}
	return d.finish()
}

func (d *doctor) finish() error {
	fmt.Fprintf(d.out, "\n%d problem(s), %d warning(s)\n", d.fails, d.warns)
	if d.fails > 0 {
		os.Exit(1)
	}
	return nil
}
