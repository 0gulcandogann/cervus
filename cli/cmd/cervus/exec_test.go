package main

import (
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
	})
	joined := "\n" + strings.Join(env, "\n") + "\n"
	for _, gone := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_DEFAULT_PROFILE", "AWS_PROFILE=other"} {
		if strings.Contains(joined, gone) {
			t.Errorf("%s should be removed:%s", gone, joined)
		}
	}
	for _, kept := range []string{"\nPATH=/bin\n", "\nAWS_REGION=eu-west-1\n", "\nCERVUS_SESSION=outer\n", "\nAWS_PROFILE=cervus\n"} {
		if !strings.Contains(joined, kept) {
			t.Errorf("missing %q:%s", kept, joined)
		}
	}
}
