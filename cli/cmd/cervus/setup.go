package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"cervus/internal/client"
	"cervus/internal/config"
)

const defaultShellKey = "alt+r"

// shellKey is one key in the two notations the shells use.
type shellKey struct{ name, zsh, bash string }

var shellKeyRe = regexp.MustCompile(`^(alt\+[a-z0-9]|ctrl\+[a-z])$`)

// parseShellKey allows only keys that are safe in the generated script. Ctrl keys the terminal or
// the line editor relies on are refused, and ctrl+x is used by the bash integration itself.
func parseShellKey(s string) (shellKey, error) {
	if !shellKeyRe.MatchString(s) {
		return shellKey{}, fmt.Errorf("key %q must be alt+<letter or digit> or ctrl+<letter>", s)
	}
	mod, letter, _ := strings.Cut(s, "+")
	if mod == "alt" {
		return shellKey{s, "^[" + letter, `\e` + letter}, nil
	}
	if strings.Contains("cdhijmqsxz", letter) {
		return shellKey{}, fmt.Errorf("%s cannot be used: the terminal needs it", s)
	}
	return shellKey{s, "^" + strings.ToUpper(letter), `\C-` + letter}, nil
}

func (k shellKey) label() string {
	mod, letter, _ := strings.Cut(k.name, "+")
	return strings.ToUpper(mod[:1]) + mod[1:] + "+" + letter
}

func renderShellScript(script string, k shellKey) string {
	return strings.NewReplacer("@@ZSH_KEY@@", k.zsh, "@@BASH_KEY@@", k.bash).Replace(script)
}

func shellKeyPath() string { return filepath.Join(filepath.Dir(config.Path()), "keybinding") }

// currentShellKey reads the chosen key. A damaged file must not break every new shell.
func currentShellKey() shellKey {
	def, _ := parseShellKey(defaultShellKey)
	b, err := os.ReadFile(shellKeyPath())
	if err != nil {
		return def
	}
	k, err := parseShellKey(strings.TrimSpace(string(b)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "cervus: ignoring %s: %v\n", shellKeyPath(), err)
		return def
	}
	return k
}

func saveShellKey(k shellKey) error {
	path := shellKeyPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return writeFileAtomic(path, []byte(k.name+"\n"), 0o600)
}

func cmdKeybinding(args []string) error {
	switch len(args) {
	case 0:
		fmt.Println(currentShellKey().name)
		return nil
	case 1:
		k, err := parseShellKey(args[0])
		if err != nil {
			return err
		}
		if err := saveShellKey(k); err != nil {
			return err
		}
		fmt.Printf("The role picker is now on %s. It applies to new terminals; run `exec $SHELL` in this one.\n", k.label())
		return nil
	}
	return errors.New("usage: cervus keybinding [alt+<key>|ctrl+<key>]")
}

// cmdSetup takes a machine from nothing to Alt+r. Every step checks first, so running it again
// changes nothing, and each change needs a yes.
func cmdSetup(args []string) error {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "make every change without asking")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: cervus setup [--yes]")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	confirm := func(question string) (bool, error) {
		if *yes {
			return true, nil
		}
		if !isTTY(os.Stdin) {
			return false, fmt.Errorf("setup needs to change something (%s); re-run in a terminal or with --yes", question)
		}
		fmt.Printf("%s [Y/n] ", question)
		line, _ := stdin.ReadString('\n')
		a := strings.ToLower(strings.TrimSpace(line))
		return a == "" || a == "y" || a == "yes", nil
	}
	changed := false

	if !daemonReachable(client.SocketPath()) {
		ok, err := confirm("Start the Cervus daemon now and at every login?")
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("setup needs a running daemon; start it with `cervusd &` and run this again")
		}
		if err := installService(os.Stdout, runtime.GOOS, home, os.Getenv("XDG_CONFIG_HOME")); err != nil {
			return err
		}
		changed = true
	}

	var st struct {
		Initialized bool `json:"initialized"`
		Locked      bool `json:"locked"`
	}
	if err := client.Call("status", nil, &st); err != nil {
		return err
	}
	if !st.Initialized {
		ok, err := confirm("Create your vault?")
		if err != nil {
			return err
		}
		if ok {
			if err := createVault(""); err != nil {
				return err
			}
			changed = true
		}
	}

	credsPath, cfgPath := awsPaths()
	cfgData, _ := os.ReadFile(cfgPath)
	credsData, _ := os.ReadFile(credsPath)
	if parseINI(cfgData).find("profile cervus") == nil {
		ok, err := confirm("Add the Cervus profile to " + cfgPath + "?")
		if err != nil {
			return err
		}
		if ok {
			if err := cmdAWSProfile([]string{"--install"}); err != nil {
				return err
			}
			changed = true
		}
	} else if self, err := os.Executable(); err == nil {
		if err := checkCervusProfile(cfgData, credsData, cfgPath, credsPath, self); err != nil {
			fmt.Printf("Warning: %v\n", err)
		}
	}

	shell := filepath.Base(os.Getenv("SHELL"))
	reload := "open a new terminal"
	if shell == "zsh" || shell == "bash" {
		reload = "run `exec " + shell + "` here, or open a new terminal"
		rc := filepath.Join(home, "."+shell+"rc")
		existing, _ := os.ReadFile(rc)
		if !strings.Contains(string(existing), "# cervus") {
			ok, err := confirm("Add role switching to " + rc + "?")
			if err != nil {
				return err
			}
			if ok {
				if err := cmdInitShell([]string{shell, "--prompt", "--install"}); err != nil {
					return err
				}
				changed = true
			}
		}
	} else {
		fmt.Printf("Shell %q is not supported yet; only zsh and bash have role switching.\n", shell)
	}

	if !changed {
		fmt.Println("Everything is already set up.")
	}
	var users struct {
		Identities []struct {
			Name string `json:"name"`
		} `json:"identities"`
	}
	_ = client.Call("identity.list", nil, &users)
	fmt.Println()
	if st.Initialized && st.Locked {
		fmt.Println("Your vault is locked; the picker asks for the passphrase when it needs it.")
	}
	if strings.Contains(string(credsData), "aws_secret_access_key") {
		fmt.Println("Plaintext AWS keys found in " + credsPath + ". Move them into the vault: cervus migrate")
	}
	if len(users.Identities) == 0 {
		fmt.Println("Add your first AWS user: cervus identity add <name>   (--own-vault gives it its own vault)")
	}
	if os.Getenv("CERVUS_SESSION_OWNER") == "" {
		fmt.Printf("A running shell cannot pick up a new key by itself: %s.\n", reload)
	}
	fmt.Printf("Then press %s to switch between your roles, users and vaults.\n", currentShellKey().label())
	return nil
}
