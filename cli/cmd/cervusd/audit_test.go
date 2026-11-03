package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuditChainDetectsTampering(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "audit.log")
	l, err := openAudit(path)
	if err != nil {
		t.Fatal(err)
	}
	l.Append("unlock", map[string]any{"result": "ok"})
	l.Append("use", map[string]any{"role": "dev", "result": "ok"})
	l.Append("use", map[string]any{"role": "prod", "result": "ok"})
	if n, bad, err := l.Verify(); err != nil || n != 3 || bad != 0 {
		t.Fatalf("fresh log should verify: n=%d bad=%d err=%v", n, bad, err)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Errorf("audit log mode %v", st.Mode().Perm())
	}

	// reopening continues the chain
	l2, _ := openAudit(path)
	l2.Append("lock", nil)
	if n, bad, _ := l2.Verify(); n != 4 || bad != 0 {
		t.Fatalf("chain must continue after reopen: n=%d bad=%d", n, bad)
	}

	orig, _ := os.ReadFile(path)
	// edit the middle entry
	edited := strings.Replace(string(orig), `"role":"dev"`, `"role":"evil"`, 1)
	os.WriteFile(path, []byte(edited), 0o600)
	if _, bad, _ := l2.Verify(); bad != 2 {
		t.Fatalf("edit of line 2 should be reported at line 2, got %d", bad)
	}
	// delete the middle entry
	lines := strings.Split(strings.TrimSpace(string(orig)), "\n")
	os.WriteFile(path, []byte(strings.Join([]string{lines[0], lines[2], lines[3]}, "\n")+"\n"), 0o600)
	if _, bad, _ := l2.Verify(); bad != 2 {
		t.Fatalf("deleting line 2 should break the chain at line 2, got %d", bad)
	}
}

func TestRecordNeverStoresSecrets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, _ := openAudit(path)
	l.record("unlock", []byte(`{"passphrase":"hunter2hunter2"}`), outResponse{OK: true})
	l.record("secret.put", []byte(`{"name":"aws-key.work","value":"U0VDUkVU","scope":"synced"}`), outResponse{OK: true})
	l.record("identity.add", []byte(`{"id":"work","secret_access_key":"TOPSECRET","access_key_id":"AKIA1"}`), outResponse{OK: true})
	l.record("ping", nil, outResponse{OK: true})
	b, _ := os.ReadFile(path)
	for _, bad := range []string{"hunter2", "U0VDUkVU", "TOPSECRET", "AKIA1", "ping"} {
		if strings.Contains(string(b), bad) {
			t.Errorf("audit log leaked %q:\n%s", bad, b)
		}
	}
	if !strings.Contains(string(b), "aws-key.work") {
		t.Error("secret names should be recorded")
	}
}

func TestNilAuditLogIsSafe(t *testing.T) {
	var l *auditLog
	l.Append("x", nil)
	l.record("use", nil, outResponse{})
}
