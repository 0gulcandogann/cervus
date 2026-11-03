package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestSplitExecArgs(t *testing.T) {
	cases := []struct {
		in            []string
		left, command []string
		wantErr       bool
	}{
		{[]string{"dev", "--", "aws", "s3", "ls"}, []string{"dev"}, []string{"aws", "s3", "ls"}, false},
		{[]string{"prod", "--yes", "--", "terraform", "--", "plan"}, []string{"prod", "--yes"}, []string{"terraform", "--", "plan"}, false},
		{[]string{"dev", "aws"}, nil, nil, true},
		{[]string{"dev", "--"}, nil, nil, true},
		{nil, nil, nil, true},
	}
	for _, c := range cases {
		left, command, err := splitExecArgs(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("%v: err=%v", c.in, err)
			continue
		}
		if !c.wantErr && (!reflect.DeepEqual(left, c.left) || !reflect.DeepEqual(command, c.command)) {
			t.Errorf("%v: left=%v command=%v", c.in, left, command)
		}
	}
}

func TestExecEnvironment(t *testing.T) {
	env := execEnvironment([]string{
		"PATH=/bin", "AWS_ACCESS_KEY_ID=x", "AWS_SECRET_ACCESS_KEY=y", "AWS_SESSION_TOKEN=z",
		"AWS_PROFILE=other", "AWS_DEFAULT_PROFILE=other", "AWS_REGION=eu-west-1", "CERVUS_SESSION=outer",
		"AWS_ROLE_ARN=x", "AWS_WEB_IDENTITY_TOKEN_FILE=x", "AWS_ROLE_SESSION_NAME=x", "AWS_ACCESS_KEY=x", "AWS_SECRET_KEY=x",
		"AWS_SECURITY_TOKEN=x", "AWS_CREDENTIAL_EXPIRATION=x", "AWS_CONTAINER_CREDENTIALS_FULL_URI=x",
		"AWS_CONTAINER_AUTHORIZATION_TOKEN=x", "AWS_ENDPOINT_URL=http://kept",
	})
	joined := "\n" + strings.Join(env, "\n") + "\n"
	for _, gone := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_DEFAULT_PROFILE", "AWS_PROFILE=other",
		"AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_SESSION_NAME", "AWS_ACCESS_KEY=", "AWS_SECRET_KEY=",
		"AWS_SECURITY_TOKEN", "AWS_CREDENTIAL_EXPIRATION", "AWS_CONTAINER_"} {
		if strings.Contains(joined, gone) {
			t.Errorf("%s should be removed:%s", gone, joined)
		}
	}
	for _, kept := range []string{"\nPATH=/bin\n", "\nAWS_REGION=eu-west-1\n", "\nCERVUS_SESSION=outer\n", "\nAWS_PROFILE=cervus\n", "\nAWS_ENDPOINT_URL=http://kept\n"} {
		if !strings.Contains(joined, kept) {
			t.Errorf("missing %q:%s", kept, joined)
		}
	}
}

func TestCheckCervusProfile(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "cervus")
	other := filepath.Join(dir, "other")
	for _, f := range []string{exe, other} {
		if err := os.WriteFile(f, []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(dir, "linked")
	if err := os.Symlink(exe, link); err != nil {
		t.Fatal(err)
	}
	good := "[profile cervus]\ncredential_process = " + exe + " credential-process\n"
	cases := []struct{ name, cfg, creds, want string }{
		{"good", good, "", ""},
		{"through a symlink", "[profile cervus]\ncredential_process = " + link + " credential-process\n", "", ""},
		{"no profile", "[default]\nregion = eu-west-1\n", "", "no [profile cervus]"},
		{"empty profile", "[profile cervus]\n", "", "credential_process"},
		{"missing program", "[profile cervus]\ncredential_process = /no/such/bin credential-process\n", "", "credential_process"},
		{"another program", "[profile cervus]\ncredential_process = " + other + " credential-process\n", "", "credential_process"},
		{"wrong subcommand", "[profile cervus]\ncredential_process = " + exe + " whoami\n", "", "credential_process"},
		{"static keys in the profile", good + "aws_access_key_id = x\n", "", "aws_access_key_id"},
		{"role in the profile", good + "role_arn = x\n", "", "role_arn"},
		{"keys in the credentials file", good, "[cervus]\naws_access_key_id = x\n", "credentials file"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := checkCervusProfile([]byte(c.cfg), []byte(c.creds), "config", "credentials file", exe)
			if c.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want %q, got %v", c.want, err)
			}
		})
	}
}
