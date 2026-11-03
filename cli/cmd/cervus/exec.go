package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
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

// execEnvironment makes the command use the Cervus profile. Leftover keys would override it, and a
// different profile would ignore the role, so both go. Credentials are never put in the environment.
func execEnvironment(environ []string) []string {
	remove := map[string]bool{
		"AWS_ACCESS_KEY_ID": true, "AWS_SECRET_ACCESS_KEY": true, "AWS_SESSION_TOKEN": true,
		"AWS_PROFILE": true, "AWS_DEFAULT_PROFILE": true,
	}
	env := make([]string, 0, len(environ)+1)
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		if !remove[name] {
			env = append(env, kv)
		}
	}
	return append(env, "AWS_PROFILE=cervus")
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
	_, cfgPath := awsPaths()
	cfgData, _ := os.ReadFile(cfgPath)
	if parseINI(cfgData).find("profile cervus") == nil {
		return fmt.Errorf("no [profile cervus] in %s; run `cervus aws-profile --install`", cfgPath)
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
