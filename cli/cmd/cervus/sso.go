package main

import (
	"errors"
	"flag"
	"fmt"
	"time"

	"cervus/internal/client"
)

func cmdIdentityAddSSO(args []string) error {
	fs := flag.NewFlagSet("identity add-sso", flag.ContinueOnError)
	startURL := fs.String("start-url", "", "IAM Identity Center start URL")
	ssoRegion := fs.String("sso-region", "", "region of IAM Identity Center")
	account := fs.String("account", "", "AWS account ID")
	roleName := fs.String("role-name", "", "permission set role name")
	region := fs.String("region", "us-east-1", "default AWS region")
	vault := fs.String("vault", "", "vault to keep the sign-in in (default: the default vault)")
	id, err := parseWithName(fs, args, "usage: cervus identity add-sso <name> --start-url U --sso-region R --account A --role-name N [--region R] [--vault V]")
	if err != nil {
		return err
	}
	if err := client.Call("identity.add_sso", map[string]string{
		"id": id, "start_url": *startURL, "sso_region": *ssoRegion, "account": *account,
		"role_name": *roleName, "region": *region, "vault": *vault,
	}, nil); err != nil {
		return err
	}
	fmt.Printf("Added %q. Sign in with: cervus sso login %s\n", id, id)
	return nil
}

func cmdSSO(args []string) error {
	if len(args) != 2 || args[0] != "login" {
		return errors.New("usage: cervus sso login <name>")
	}
	id := args[1]
	var start struct {
		URI      string `json:"verification_uri"`
		Code     string `json:"user_code"`
		Interval int    `json:"interval"`
	}
	if err := client.Call("identity.sso_start", map[string]string{"id": id}, &start); err != nil {
		return err
	}
	fmt.Printf("Open this page and approve the sign-in:\n  %s\nThe code on the page should be: %s\nWaiting...\n", start.URI, start.Code)
	wait := time.Duration(max(start.Interval, 1)) * time.Second
	for {
		time.Sleep(wait)
		var out struct {
			Status string `json:"status"`
		}
		if err := client.Call("identity.sso_poll", map[string]string{"id": id}, &out); err != nil {
			return err
		}
		switch out.Status {
		case "done":
			fmt.Printf("Signed in. Switch with Alt+r, or: cervus use user:%s\n", id)
			return nil
		case "slow_down":
			wait += 5 * time.Second
		}
	}
}
