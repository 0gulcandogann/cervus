package main

import (
	"path/filepath"
	"testing"

	"cervus/internal/vaultproc"
)

// testApp has a vault that can never start: a request that reaches it fails with "internal",
// so a "denied" reply proves the daemon refused it before calling the vault.
func testApp(t *testing.T) *app {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "no-such-vault")
	return newApp(vaultproc.NewSupervisor(bin, nil), filepath.Join(t.TempDir(), "config.json"), "")
}

func errCode(t *testing.T, a *app, line string) string {
	t.Helper()
	var req inRequest
	resp := handleRequest([]byte(line), a, &req)
	if resp.Error == nil {
		return ""
	}
	return resp.Error.Code
}

func TestPublicSecretOpsRefuseReservedNames(t *testing.T) {
	cases := map[string]string{
		"get access key": `{"id":1,"op":"secret.get","params":{"name":"aws-key.work"}}`,
		"get mfa seed":   `{"id":1,"op":"secret.get","params":{"name":"mfa-seed.work"}}`,
		"overwrite key":  `{"id":1,"op":"secret.put","params":{"name":"aws-key.work","value":"eA=="}}`,
		"overwrite seed": `{"id":1,"op":"secret.put","params":{"name":"mfa-seed.work","value":"eA=="}}`,
		"delete key":     `{"id":1,"op":"secret.delete","params":{"name":"aws-key.work"}}`,
		"delete seed":    `{"id":1,"op":"secret.delete","params":{"name":"mfa-seed.work"}}`,
		// macOS file systems are usually case-insensitive, so this opens the same file.
		"mixed case": `{"id":1,"op":"secret.get","params":{"name":"AWS-Key.work"}}`,
		// JSON escapes must not hide the name.
		"escaped name": `{"id":1,"op":"secret.get","params":{"name":"aws-key.work"}}`,
		// Go matches struct fields case-insensitively but the vault does not: the daemon must
		// judge the same "name" that the vault will use.
		"decoy key after": `{"id":1,"op":"secret.get","params":{"name":"aws-key.work","NAME":"harmless"}}`,
		"decoy duplicate": `{"id":1,"op":"secret.get","params":{"name":"harmless","name":"aws-key.work"}}`,
	}
	for name, line := range cases {
		t.Run(name, func(t *testing.T) {
			if got := errCode(t, testApp(t), line); got != "denied" {
				t.Fatalf("want denied, got %q", got)
			}
		})
	}
}

func TestPublicSecretOpsAllowOrdinaryNames(t *testing.T) {
	for _, name := range []string{"aws-key", "aws-keys.work", "my.aws-key.work", "mfa-seed", "note"} {
		t.Run(name, func(t *testing.T) {
			line := `{"id":1,"op":"secret.get","params":{"name":"` + name + `"}}`
			if got := errCode(t, testApp(t), line); got != "internal" {
				t.Fatalf("want the request to reach the vault (internal), got %q", got)
			}
		})
	}
}
