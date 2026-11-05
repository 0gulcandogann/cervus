package main

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func fakeSecretTool(t *testing.T) *[]string {
	t.Helper()
	var calls []string
	old, oldOS := runSecretTool, keychainOS
	t.Cleanup(func() { runSecretTool, keychainOS = old, oldOS })
	keychainOS = "linux"
	runSecretTool = func(stdin string, args ...string) (string, error) {
		calls = append(calls, strings.Join(args, " ")+"|"+stdin)
		if args[0] == "lookup" {
			return "pass phrase\n", nil
		}
		return "", nil
	}
	return &calls
}

func TestKeychainCommandsNameTheVaultAndKeepSecretsOutOfArgs(t *testing.T) {
	t.Setenv("CERVUS_NO_KEYCHAIN", "")
	calls := fakeSecretTool(t)
	if err := keychainStore("/v", "pass phrase"); err != nil {
		t.Fatal(err)
	}
	if got := keychainLookup("/v"); got != "pass phrase" {
		t.Fatalf("lookup: %q", got)
	}
	if err := keychainClear("/v"); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"store --label=Cervus vault passphrase service cervus vault /v|pass phrase",
		"lookup service cervus vault /v|",
		"clear service cervus vault /v|",
	}
	if strings.Join(*calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("calls:\n%s", strings.Join(*calls, "\n"))
	}
}

func TestKeychainLookupFailureMeansNoPassphrase(t *testing.T) {
	old := runSecretTool
	t.Cleanup(func() { runSecretTool = old })
	runSecretTool = func(string, ...string) (string, error) { return "partial", errors.New("locked keyring") }
	if got := keychainLookup("/v"); got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestKeychainDisabledByEnvironment(t *testing.T) {
	calls := fakeSecretTool(t)
	t.Setenv("CERVUS_NO_KEYCHAIN", "1")
	if got := keychainLookup("/v"); got != "" {
		t.Fatalf("got %q", got)
	}
	if len(*calls) != 0 {
		t.Fatalf("secret-tool must not run: %v", *calls)
	}
}

func TestPassphraseForNeedsOptInAndRespectsAHold(t *testing.T) {
	t.Setenv("CERVUS_NO_KEYCHAIN", "")
	dir := t.TempDir()
	calls := fakeSecretTool(t)
	if got := passphraseFor(dir, true); got != "" || len(*calls) != 0 {
		t.Fatalf("no opt-in: got %q, calls %v", got, *calls)
	}
	if err := setKeychainMarker(dir, keychainEnabledFile, true); err != nil {
		t.Fatal(err)
	}
	if got := passphraseFor(dir, true); got != "pass phrase" {
		t.Fatalf("enabled: %q", got)
	}
	if err := setKeychainMarker(dir, keychainHoldFile, true); err != nil {
		t.Fatal(err)
	}
	if got := passphraseFor(dir, true); got != "" {
		t.Fatalf("held: %q", got)
	}
	if got := passphraseFor(dir, false); got != "pass phrase" {
		t.Fatalf("explicit unlock should ignore the hold: %q", got)
	}
	t.Setenv("CERVUS_NO_KEYCHAIN", "1")
	if got := passphraseFor(dir, false); got != "" {
		t.Fatalf("env: %q", got)
	}
}

func TestKeychainEnableRefusedByEnvironment(t *testing.T) {
	calls := fakeSecretTool(t)
	t.Setenv("CERVUS_NO_KEYCHAIN", "1")
	err := keychainEnable(t.TempDir(), "", true)
	if err == nil || !strings.Contains(err.Error(), "CERVUS_NO_KEYCHAIN") || len(*calls) != 0 {
		t.Fatalf("err=%v calls=%v", err, *calls)
	}
}

// fakeSecurity keeps one item, like the macOS keychain, and records every call.
func fakeSecurity(t *testing.T) (calls *[]string, item *string) {
	t.Helper()
	var c []string
	var v string
	oldRun, oldOS := runSecurity, keychainOS
	t.Cleanup(func() { runSecurity, keychainOS = oldRun, oldOS })
	keychainOS = "darwin"
	runSecurity = func(stdin string, args ...string) (string, error) {
		c = append(c, strings.Join(args, " ")+"|"+stdin)
		switch args[0] {
		case "-i":
			if !strings.HasSuffix(stdin, "\nexit\n") {
				t.Errorf("interactive mode must be told to end: %q", stdin)
			}
			f := strings.Fields(strings.TrimSuffix(stdin, "exit\n"))
			v = f[len(f)-1]
		case "find-generic-password":
			if v == "" {
				return "", errors.New("not found")
			}
			return v + "\n", nil
		case "delete-generic-password":
			v = ""
		}
		return "", nil
	}
	return &c, &v
}

func TestMacKeychainKeepsThePassphraseOutOfArguments(t *testing.T) {
	t.Setenv("CERVUS_NO_KEYCHAIN", "")
	calls, _ := fakeSecurity(t)
	secret := `pass "with" $pecial ç`
	if err := keychainStore("/v", secret); err != nil {
		t.Fatal(err)
	}
	if got := keychainLookup("/v"); got != secret {
		t.Fatalf("lookup %q", got)
	}
	for _, c := range *calls {
		args, stdin, _ := strings.Cut(c, "|")
		if strings.Contains(args, "with") || strings.Contains(args, hex.EncodeToString([]byte(secret))) {
			t.Fatalf("secret in arguments: %s", args)
		}
		if strings.Contains(stdin, `"with"`) {
			t.Fatalf("secret in plain text on stdin: %s", stdin)
		}
	}
}

func TestMacKeychainReportsAStoreThatDidNotHappen(t *testing.T) {
	t.Setenv("CERVUS_NO_KEYCHAIN", "")
	fakeSecurity(t)
	old := runSecurity
	runSecurity = func(stdin string, args ...string) (string, error) {
		if args[0] == "-i" { // the real interactive mode exits 0 on a failed command
			return "", nil
		}
		return old(stdin, args...)
	}
	if err := keychainStore("/v", "secret"); err == nil {
		t.Fatal("a store that did not keep the value must fail")
	}
}

func TestMacKeychainIgnoresAValueItDidNotWrite(t *testing.T) {
	t.Setenv("CERVUS_NO_KEYCHAIN", "")
	_, item := fakeSecurity(t)
	*item = "not hex at all"
	if got := keychainLookup("/v"); got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestMacKeychainVaultsDoNotShareAnItem(t *testing.T) {
	if securityAccount("/a") == securityAccount("/b") {
		t.Fatal("two vaults got one item")
	}
	if a := securityAccount(`/with space/"quote"`); strings.ContainsAny(a, " \"") {
		t.Fatalf("needs quoting: %s", a)
	}
}
