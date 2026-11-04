package main

import (
	"errors"
	"strings"
	"testing"
)

func fakeSecretTool(t *testing.T) *[]string {
	t.Helper()
	var calls []string
	old := runSecretTool
	t.Cleanup(func() { runSecretTool = old })
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
