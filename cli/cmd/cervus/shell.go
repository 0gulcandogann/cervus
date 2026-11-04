package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"cervus/internal/client"
)

// ---- sessions ----

func newSessionID() (string, error) {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "s-" + hex.EncodeToString(b), nil
}

func cmdSession(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: cervus session <new|register> ...")
	}
	switch args[0] {
	case "new":
		id, err := newSessionID()
		if err != nil {
			return err
		}
		fmt.Println(id)
		return nil
	case "register":
		if len(args) != 3 {
			return errors.New("usage: cervus session register <id> <pid>")
		}
		pid, err := strconv.Atoi(args[2])
		if err != nil {
			return err
		}
		client.Timeout = 2 * time.Second
		return client.Call("session.register", map[string]any{"session": args[1], "pid": pid}, nil)
	}
	return fmt.Errorf("unknown session command %q", args[0])
}

// ---- prompt segment ----

// cmdPrompt prints a short "[role 45m]" segment. It must be fast and silent on any failure.
func cmdPrompt(args []string) error {
	fs := flag.NewFlagSet("prompt", flag.ContinueOnError)
	shell := fs.String("shell", "", "zsh | bash (adds color escapes)")
	if err := fs.Parse(args); err != nil {
		return nil
	}
	client.Timeout = 300 * time.Millisecond
	var out struct {
		Role        string `json:"role"`
		SecondsLeft int    `json:"seconds_left"`
		Protected   bool   `json:"protected"`
	}
	if err := client.Call("whoami", map[string]string{"session": sessionID()}, &out); err != nil || out.Role == "" {
		return nil
	}
	text := fmt.Sprintf("[%s %dm]", out.Role, out.SecondsLeft/60)
	color, zshColor := 32, "green"
	switch {
	case out.SecondsLeft <= 0:
		text, color, zshColor = fmt.Sprintf("[%s expired]", out.Role), 33, "yellow"
	case out.Protected:
		color, zshColor = 31, "red"
	}
	switch *shell {
	case "zsh":
		fmt.Printf("%%F{%s}%s%%f", zshColor, text)
	case "bash":
		// \x01 and \x02 tell readline the enclosed bytes take no screen width.
		fmt.Printf("\x01\x1b[%dm\x02%s\x01\x1b[0m\x02 ", color, text)
	default:
		fmt.Print(text)
	}
	return nil
}

// ---- interactive picker ----

type roleItem struct {
	Name      string
	Identity  string
	Vault     string
	MFA       string
	Protected bool
}

func cmdPick() error {
	var list struct {
		Roles []struct {
			Name     string `json:"name"`
			Identity string `json:"identity"`
			MFA      string `json:"mfa"`
			Confirm  bool   `json:"confirm"`
			Vault    string `json:"vault"`
		} `json:"roles"`
	}
	if err := client.Call("role.list", nil, &list); err != nil {
		return err
	}
	var users struct {
		Identities []struct {
			Name      string `json:"name"`
			MFASerial string `json:"mfa_serial"`
			Vault     string `json:"vault"`
		} `json:"identities"`
	}
	if err := client.Call("identity.list", nil, &users); err != nil {
		return err
	}
	if len(list.Roles) == 0 && len(users.Identities) == 0 {
		return errors.New("nothing to switch to yet; add a user with `cervus identity add`")
	}
	var cur struct {
		Role string `json:"role"`
	}
	_ = client.Call("whoami", map[string]string{"session": sessionID()}, &cur)

	// Roles first, then each user on its own, so every vault is reachable from one list.
	var items []roleItem
	for _, r := range list.Roles {
		items = append(items, roleItem{r.Name, r.Identity, r.Vault, r.MFA, r.Confirm})
	}
	for _, u := range users.Identities {
		mfa := "none"
		if u.MFASerial != "" {
			mfa = "once"
		}
		items = append(items, roleItem{"user:" + u.Name, u.Name, u.Vault, mfa, false})
	}
	selected := 0
	for i, it := range items {
		if it.Name == cur.Role {
			selected = i
		}
	}

	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return errors.New("no terminal available for the picker")
	}
	defer tty.Close()

	restore, err := rawMode(tty)
	if err != nil {
		return err
	}
	restored := false
	undo := func() {
		if !restored {
			restored = true
			restore()
		}
	}
	defer undo()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() { <-sig; undo(); os.Exit(130) }()

	in := bufio.NewReader(tty)
	lines := len(items) + 1
	draw := func(first bool) {
		if first {
			fmt.Fprint(tty, "\r\n")
		} else {
			fmt.Fprintf(tty, "\x1b[%dA\x1b[J", lines)
		}
		fmt.Fprint(tty, "Switch role  (up/down or j/k, Enter, 1-9, q to cancel)\r\n")
		for i, it := range items {
			mark, flags := "  ", it.MFA
			if it.Name == cur.Role {
				mark = "* "
			}
			if it.Protected {
				flags += ", protected"
			}
			line := fmt.Sprintf("%s%-20s %-12s %-12s mfa=%s", mark, it.Name, it.Identity, it.Vault, flags)
			if i == selected {
				line = "\x1b[7m> " + line[2:] + "\x1b[0m"
			} else {
				line = "  " + line[2:]
			}
			fmt.Fprint(tty, line+"\r\n")
		}
	}
	erase := func() { fmt.Fprintf(tty, "\x1b[%dA\x1b[J", lines) }

	draw(true)
	choice := -1
loop:
	for {
		b, err := in.ReadByte()
		if err != nil {
			break
		}
		switch {
		case b == 'j' || b == 14: // j, Ctrl-N
			selected = (selected + 1) % len(items)
		case b == 'k' || b == 16: // k, Ctrl-P
			selected = (selected + len(items) - 1) % len(items)
		case b == '\r' || b == '\n':
			choice = selected
			break loop
		case b >= '1' && b <= '9' && int(b-'1') < len(items):
			choice = int(b - '1')
			break loop
		case b == 'q' || b == 3:
			break loop
		case b == 0x1b:
			if in.Buffered() == 0 {
				break loop // a lone Esc cancels
			}
			next, _ := in.ReadByte()
			if next != '[' && next != 'O' {
				continue
			}
			arrow, _ := in.ReadByte()
			if arrow == 'A' {
				selected = (selected + len(items) - 1) % len(items)
			} else if arrow == 'B' {
				selected = (selected + 1) % len(items)
			}
		}
		draw(false)
	}
	erase()
	if choice < 0 {
		fmt.Fprint(tty, "cancelled\r\n")
		return nil
	}

	confirm := func() (bool, error) {
		fmt.Fprintf(tty, "Role %q is protected. Switch to it? [y/N] ", items[choice].Name)
		b, _ := in.ReadByte()
		fmt.Fprint(tty, string(b)+"\r\n")
		return b == 'y' || b == 'Y', nil
	}
	ask := func(vault string) (string, error) {
		fmt.Fprint(tty, unlockPrompt(vault))
		passphrase, err := readHiddenLine(in)
		fmt.Fprint(tty, "\r\n")
		return passphrase, err
	}
	res, err := switchRole(items[choice].Name, false, confirm, ask)
	if err != nil {
		fmt.Fprintf(tty, "error: %v\r\n", err)
		return nil
	}
	fmt.Fprintf(tty, "Now using role %q (valid until %s)\r\n", res.Role, res.ExpiresAt)
	return nil
}

// readHiddenLine reads a line from a terminal in raw mode, where echo is already off.
func readHiddenLine(r io.ByteReader) (string, error) {
	var line []byte
	for {
		b, err := r.ReadByte()
		if err != nil {
			return "", err
		}
		switch b {
		case '\r', '\n':
			return string(line), nil
		case 3: // Ctrl-C
			return "", errors.New("cancelled")
		case 127, 8: // Backspace
			if len(line) > 0 {
				line = line[:len(line)-1]
			}
		default:
			line = append(line, b)
		}
	}
}

// rawMode puts the terminal in single-key mode using stty and returns a restore function.
func rawMode(tty *os.File) (func(), error) {
	get := exec.Command("stty", "-g")
	get.Stdin = tty
	saved, err := get.Output()
	if err != nil {
		return nil, fmt.Errorf("cannot read terminal settings: %w", err)
	}
	set := exec.Command("stty", "-icanon", "-echo", "min", "1", "time", "0")
	set.Stdin = tty
	if err := set.Run(); err != nil {
		return nil, fmt.Errorf("cannot set terminal mode: %w", err)
	}
	state := strings.TrimSpace(string(saved))
	return func() {
		r := exec.Command("stty", state)
		r.Stdin = tty
		_ = r.Run()
	}, nil
}

// ---- shell integration script ----

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

const zshScript = `# Cervus shell integration (zsh)
_cervus_bin=@@BIN@@
if [[ "${CERVUS_SESSION_OWNER:-}" != "$$" ]]; then
  export CERVUS_SESSION="$("$_cervus_bin" session new)"
  export CERVUS_SESSION_OWNER="$$"
  "$_cervus_bin" session register "$CERVUS_SESSION" "$$" >/dev/null 2>&1 &!
fi
export AWS_PROFILE=cervus
if [[ -o interactive ]]; then
  _cervus_pick_widget() {
    zle -I
    "$_cervus_bin" pick
    (( $+functions[_cervus_precmd] )) && _cervus_precmd
    zle reset-prompt
  }
  zle -N _cervus_pick_widget
  bindkey '@@ZSH_KEY@@' _cervus_pick_widget
fi
`

const zshPrompt = `if [[ -o interactive ]]; then
  _cervus_base_rprompt="${RPROMPT:-}"
  _cervus_precmd() { RPROMPT="$("$_cervus_bin" prompt --shell zsh)${_cervus_base_rprompt}"; }
  autoload -Uz add-zsh-hook
  add-zsh-hook precmd _cervus_precmd
fi
`

const bashScript = `# Cervus shell integration (bash)
_cervus_bin=@@BIN@@
if [ "${CERVUS_SESSION_OWNER:-}" != "$$" ]; then
  export CERVUS_SESSION="$("$_cervus_bin" session new)"
  export CERVUS_SESSION_OWNER="$$"
  ("$_cervus_bin" session register "$CERVUS_SESSION" "$$" >/dev/null 2>&1 &)
fi
export AWS_PROFILE=cervus
if [[ $- == *i* ]]; then
  _cervus_pick() { "$_cervus_bin" pick; }
  bind -x '"\C-x\C-p": _cervus_pick'
  bind '"\C-x\C-r": redraw-current-line'
  bind '"@@BASH_KEY@@": "\C-x\C-p\C-x\C-r"'
fi
`

const bashPrompt = `if [[ $- == *i* ]]; then
  case "$PS1" in *'cervus prompt'*|*'$_cervus_bin'*) ;; *) PS1='$("$_cervus_bin" prompt --shell bash)'"$PS1" ;; esac
fi
`

func cmdInitShell(args []string) error {
	fs := flag.NewFlagSet("init-shell", flag.ContinueOnError)
	prompt := fs.Bool("prompt", false, "also show the current role in the prompt")
	install := fs.Bool("install", false, "append the integration to your shell rc file")
	keyFlag := fs.String("key", "", "key for the role picker, e.g. alt+r (default: the one set by cervus keybinding)")
	shell, err := parseWithName(fs, args, "usage: cervus init-shell <zsh|bash> [--prompt] [--install]")
	if err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	var script, rc string
	home, _ := os.UserHomeDir()
	switch shell {
	case "zsh":
		script, rc = zshScript, filepath.Join(home, ".zshrc")
		if *prompt {
			script += zshPrompt
		}
	case "bash":
		script, rc = bashScript, filepath.Join(home, ".bashrc")
		if *prompt {
			script += bashPrompt
		}
	default:
		return fmt.Errorf("unsupported shell %q (use zsh or bash)", shell)
	}
	key := currentShellKey()
	if *keyFlag != "" {
		if key, err = parseShellKey(*keyFlag); err != nil {
			return err
		}
		if *install { // the installed line re-reads the setting in every new shell
			if err := saveShellKey(key); err != nil {
				return err
			}
		}
	}
	script = renderShellScript(strings.ReplaceAll(script, "@@BIN@@", shellQuote(exe)), key)
	if !*install {
		fmt.Print(script)
		return nil
	}

	line := fmt.Sprintf("eval \"$(%s init-shell %s", shellQuote(exe), shell)
	if *prompt {
		line += " --prompt"
	}
	line += ")\" # cervus"
	existing, _ := os.ReadFile(rc)
	if strings.Contains(string(existing), "# cervus") {
		return fmt.Errorf("%s already contains a cervus line; edit it by hand to change options", rc)
	}
	f, err := os.OpenFile(rc, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.WriteString(f, "\n"+line+"\n"); err != nil {
		return err
	}
	fmt.Printf("Added to %s. Open a new terminal; press %s to switch roles.\n", rc, key.label())
	return nil
}
