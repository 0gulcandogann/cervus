package main

import (
	"errors"
	"fmt"
	"os"

	"cervus/internal/client"
	"cervus/internal/config"
)

const vaultFlagHelp = "vault to use (default: $CERVUS_VAULT, then the active role's vault, then the default vault)"

type vaultListing struct {
	Vaults []struct {
		Name        string `json:"name"`
		Initialized bool   `json:"initialized"`
		Locked      bool   `json:"locked"`
		Dir         string `json:"dir"`
	} `json:"vaults"`
}

func cmdVault(args []string) error {
	const usage = "usage: cervus vault <create <name>|list>"
	if len(args) == 0 {
		return errors.New(usage)
	}
	switch args[0] {
	case "create":
		if len(args) != 2 {
			return errors.New("usage: cervus vault create <name>")
		}
		if !config.ValidName(args[1]) {
			return fmt.Errorf("vault name %q must be lowercase letters, digits, '-' or '_' (max 32)", args[1])
		}
		return createVault(args[1])
	case "list":
		var out vaultListing
		if err := client.Call("vault.list", nil, &out); err != nil {
			return err
		}
		for _, v := range out.Vaults {
			state := "unlocked"
			switch {
			case !v.Initialized:
				state = "not initialized"
			case v.Locked:
				state = "locked"
			}
			fmt.Printf("%-16s %s\n", v.Name, state)
		}
		return nil
	}
	return errors.New(usage)
}

// secretVault picks the vault for a secret command: the flag, $CERVUS_VAULT, then the vault of this
// shell's active role, so adding something to the vault in use takes no extra typing. It says so when
// it chose a vault the user did not name.
func secretVault(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if v := os.Getenv("CERVUS_VAULT"); v != "" {
		return v
	}
	var who struct {
		Vault string `json:"vault"`
	}
	if client.Call("whoami", map[string]string{"session": sessionID()}, &who) != nil || who.Vault == "" || who.Vault == "default" {
		return ""
	}
	fmt.Fprintf(os.Stderr, "(vault: %s, from the active role)\n", who.Vault)
	return who.Vault
}
