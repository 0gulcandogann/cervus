package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"cervus/internal/client"
)

// cmdMFASetup creates and enables a virtual MFA device, with the vault as the authenticator.
func cmdMFASetup(args []string) error {
	fs := flag.NewFlagSet("identity mfa-setup", flag.ContinueOnError)
	device := fs.String("device-name", "", "name of the device in AWS (default: cervus-<name>)")
	showSeed := fs.Bool("show-seed", false, "print the seed once, to add it to a second authenticator")
	id, err := parseWithName(fs, args, "usage: cervus identity mfa-setup <name> [--device-name N] [--show-seed]")
	if err != nil {
		return err
	}
	if *showSeed && !isTTY(os.Stdout) {
		return errors.New("--show-seed prints a secret, so it only works on a terminal")
	}
	fmt.Println("Creating the device in AWS. AWS needs two codes in a row, so this takes up to 30 seconds...")
	params := map[string]any{"id": id, "device_name": *device, "show_seed": *showSeed}
	var out struct {
		Serial string `json:"mfa_serial"`
		User   string `json:"user"`
		Seed   string `json:"seed"`
	}
	if err := client.Call("identity.mfa_setup", params, &out); err != nil {
		return err
	}
	fmt.Printf("MFA is on for IAM user %s: %s\n", out.User, out.Serial)
	fmt.Println("The seed is on this device only, and a recovery key cannot restore it. If you lose this device,")
	fmt.Println("you need a second MFA device or an account admin to get back in.")
	if out.Seed != "" {
		fmt.Printf("Seed, shown once. Add it to a second authenticator: %s\n", out.Seed)
	} else {
		fmt.Println("Use a role with --mfa always or once to require it.")
	}
	return nil
}
