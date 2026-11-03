package main

import (
	"strings"
	"testing"
)

const credsFixture = `# my keys
[default]
aws_access_key_id = AKIADEFAULT
aws_secret_access_key = secretdefault

[Work Account]
aws_access_key_id=AKIAWORK
aws_secret_access_key=secretwork
region = ap-south-1

[temp]
aws_access_key_id = ASIATEMP
aws_secret_access_key = x
aws_session_token = tok
`

const cfgFixture = `[default]
region = eu-west-1

[profile prod]
role_arn = arn:aws:iam::123456789012:role/Prod
source_profile = default
mfa_serial = arn:aws:iam::123456789012:mfa/me
duration_seconds = 7200

[profile sso]
sso_start_url = https://example.awsapps.com/start

[profile orphan]
role_arn = arn:aws:iam::123456789012:role/X
source_profile = missing

[profile cred-src]
role_arn = arn:aws:iam::123456789012:role/Y
credential_source = Ec2InstanceMetadata
`

func TestBuildPlan(t *testing.T) {
	p := buildPlan(parseINI([]byte(credsFixture)), parseINI([]byte(cfgFixture)), map[string]bool{}, map[string]bool{})
	if len(p.Identities) != 2 || p.Identities[0].Name != "default" || p.Identities[1].Name != "work-account" {
		t.Fatalf("identities: %+v", p.Identities)
	}
	if p.Identities[0].Region != "eu-west-1" || p.Identities[1].Region != "" {
		t.Errorf("regions are only taken from the matching config profile: %+v", p.Identities)
	}
	if p.Identities[0].MFASerial != "arn:aws:iam::123456789012:mfa/me" {
		t.Errorf("mfa serial should move to the identity: %+v", p.Identities[0])
	}
	if len(p.Roles) != 1 || p.Roles[0].Name != "prod" || p.Roles[0].MFA != "always" || p.Roles[0].DurationSecs != 7200 || p.Roles[0].Identity != "default" {
		t.Errorf("roles: %+v", p.Roles)
	}
	notes := strings.Join(p.Notes, "\n")
	for _, want := range []string{`"temp"`, `"orphan"`, `"cred-src"`} {
		if !strings.Contains(notes, want) {
			t.Errorf("missing note for %s in:\n%s", want, notes)
		}
	}
}

func TestExistingIdentityIsNotMigratedTwice(t *testing.T) {
	p := buildPlan(parseINI([]byte(credsFixture)), parseINI([]byte(cfgFixture)), map[string]bool{"default": true}, map[string]bool{})
	if len(p.Identities) != 1 || p.Identities[0].Name != "work-account" {
		t.Fatalf("identities: %+v", p.Identities)
	}
	if len(p.Roles) != 1 {
		t.Errorf("role should still be importable against the existing identity: %+v", p.Roles)
	}
}

func TestINIRoundTripAndKeyRemoval(t *testing.T) {
	f := parseINI([]byte(credsFixture))
	if f.String() != credsFixture {
		t.Fatalf("parse/print must be lossless:\n%q", f.String())
	}
	w := f.find("Work Account")
	w.removeKeys("aws_access_key_id", "aws_secret_access_key")
	if w.empty() {
		t.Fatal("region line must keep the section alive")
	}
	d := f.find("default")
	d.removeKeys("aws_access_key_id", "aws_secret_access_key")
	if !d.empty() {
		t.Fatal("default should be empty after removing its keys")
	}
	f.removeSection("default")
	out := f.String()
	if strings.Contains(out, "AKIADEFAULT") || strings.Contains(out, "AKIAWORK") || !strings.Contains(out, "region = ap-south-1") || !strings.Contains(out, "ASIATEMP") || !strings.Contains(out, "# my keys") {
		t.Fatalf("unexpected result:\n%s", out)
	}
}

func TestRolesAlreadyInCervusAreSkipped(t *testing.T) {
	p := buildPlan(parseINI([]byte("")), parseINI([]byte(cfgFixture)), map[string]bool{"default": true}, map[string]bool{"prod": true})
	if len(p.Roles) != 0 && p.Roles[0].Name == "prod" {
		t.Fatalf("prod already exists: %+v", p.Roles)
	}
	if !strings.Contains(strings.Join(p.Notes, "\n"), `role "prod" already exists`) {
		t.Errorf("notes: %v", p.Notes)
	}
}
