package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const execUsage = "usage: cervus exec <role> [--yes] -- <command> [args...]"

// splitExecArgs separates cervus's own arguments from the command after the first "--".
func splitExecArgs(args []string) (left, command []string, err error) {
	for i, a := range args {
		if a == "--" {
			if i+1 == len(args) {
				break
			}
			return args[:i], args[i+1:], nil
		}
	}
	return nil, nil, errors.New(execUsage)
}

// execEnvironment makes the command use the Cervus profile. Leftover keys and web identity settings
// would override it, and a different profile would ignore the role, so they go. Region and endpoint
// stay: they are routing choices. Credentials are never put in the environment.
func execEnvironment(environ []string) []string {
	remove := map[string]bool{
		"AWS_ACCESS_KEY_ID": true, "AWS_SECRET_ACCESS_KEY": true, "AWS_SESSION_TOKEN": true,
		"AWS_ACCESS_KEY": true, "AWS_SECRET_KEY": true, "AWS_SECURITY_TOKEN": true, "AWS_CREDENTIAL_EXPIRATION": true,
		"AWS_ROLE_ARN": true, "AWS_WEB_IDENTITY_TOKEN_FILE": true, "AWS_ROLE_SESSION_NAME": true,
		"AWS_PROFILE": true, "AWS_DEFAULT_PROFILE": true,
	}
	env := make([]string, 0, len(environ)+1)
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		if !remove[name] && !strings.HasPrefix(name, "AWS_CONTAINER_") {
			env = append(env, kv)
		}
	}
	return append(env, "AWS_PROFILE=cervus")
}

// checkCervusProfile makes sure the AWS tools will really ask this binary for credentials. Anything
// else would run the command as some other principal under a banner naming the role.
func checkCervusProfile(cfg, creds []byte, cfgPath, credsPath, exe string) error {
	fix := "run `cervus aws-profile` and correct it"
	p := parseINI(cfg).find("profile cervus")
	if p == nil {
		return fmt.Errorf("no [profile cervus] in %s; run `cervus aws-profile --install`", cfgPath)
	}
	program, ok := strings.CutSuffix(strings.TrimSpace(p.get("credential_process")), " credential-process")
	if !ok || !sameFile(strings.TrimSpace(program), exe) {
		return fmt.Errorf("[profile cervus] in %s does not set credential_process to this cervus; %s", cfgPath, fix)
	}
	for _, key := range []string{"aws_access_key_id", "aws_secret_access_key", "aws_session_token", "role_arn", "source_profile", "web_identity_token_file", "sso_start_url", "sso_session"} {
		if p.get(key) != "" {
			return fmt.Errorf("[profile cervus] in %s also sets %s, which could override Cervus; remove it", cfgPath, key)
		}
	}
	if s := parseINI(creds).find("cervus"); s != nil && !s.empty() {
		return fmt.Errorf("[cervus] in %s overrides the Cervus profile; remove it", credsPath)
	}
	return nil
}

func sameFile(a, b string) bool {
	ra, errA := filepath.EvalSymlinks(a)
	rb, errB := filepath.EvalSymlinks(b)
	return errA == nil && errB == nil && ra == rb
}

// cmdExec runs one command in its own session, pinned to one role: switching roles in the shell does
// not move it. It replaces this process, so the session owner's PID is the command's, and the daemon
// forgets the session when the command exits.
func cmdExec(args []string) error {
	left, command, err := splitExecArgs(args)
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("exec", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "skip the confirmation for protected roles")
	role, err := parseWithName(fs, left, execUsage)
	if err != nil {
		return err
	}
	path, err := exec.LookPath(command[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: command not found: %s\n", command[0])
		os.Exit(127)
	}
	credsPath, cfgPath := awsPaths()
	cfgData, _ := os.ReadFile(cfgPath)
	credsData, _ := os.ReadFile(credsPath)
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if err := checkCervusProfile(cfgData, credsData, cfgPath, credsPath, self); err != nil {
		return err
	}

	session, err := newSessionID()
	if err != nil {
		return err
	}
	os.Setenv("CERVUS_SESSION", session)
	os.Setenv("CERVUS_SESSION_OWNER", strconv.Itoa(os.Getpid()))
	out, err := switchRole(role, *yes, confirmOnStdin(role), askOnStdin())
	if err != nil {
		return err
	}
	if isTTY(os.Stderr) {
		fmt.Fprintf(os.Stderr, "Running as role %q (credentials valid until %s)\n", out.Role, out.ExpiresAt)
	}
	return syscall.Exec(path, command, execEnvironment(os.Environ()))
}
