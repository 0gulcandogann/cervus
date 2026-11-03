package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveLoadRoundtripAndPermissions(t *testing.T) {
	p := filepath.Join(t.TempDir(), "cfg", "config.json")
	c := New()
	c.Identities["work"] = Identity{Region: "eu-west-1", MFASerial: "arn:aws:iam::123456789012:mfa/me"}
	c.Roles["prod"] = Role{Identity: "work", ARN: "arn:aws:iam::123456789012:role/Admin", MFA: "always", Confirm: true}
	if err := c.Save(p); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("config mode %v", st.Mode().Perm())
	}
	got, err := Load(p)
	if err != nil || got.Roles["prod"].ARN != c.Roles["prod"].ARN || !got.Roles["prod"].Confirm {
		t.Fatalf("roundtrip failed: %+v %v", got, err)
	}
	missing, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil || len(missing.Roles) != 0 {
		t.Fatalf("missing file should give empty config: %v", err)
	}
}

func TestValidation(t *testing.T) {
	c := New()
	c.Identities["work"] = Identity{}
	c.Identities["mfa"] = Identity{MFASerial: "arn:aws:iam::123456789012:mfa/me"}
	ok := Role{Identity: "mfa", ARN: "arn:aws:iam::123456789012:role/Admin", MFA: "once"}
	if err := ok.Validate("prod", c); err != nil {
		t.Fatal(err)
	}
	bad := []Role{
		{Identity: "ghost", MFA: "none"},
		{Identity: "work", ARN: "not-an-arn", MFA: "none"},
		{Identity: "work", MFA: "sometimes"},
		{Identity: "work", MFA: "always"}, // identity has no MFA serial
		{Identity: "work", MFA: "none", DurationSecs: 10},
	}
	for i, r := range bad {
		if err := r.Validate("x", c); err == nil {
			t.Errorf("case %d should fail: %+v", i, r)
		}
	}
	if (Identity{}).Validate("Bad Name") == nil || (Identity{MFASerial: "x"}).Validate("ok") == nil {
		t.Error("identity validation too lax")
	}
}
