package main

import (
	"strings"
	"testing"
)

func TestParseShellKey(t *testing.T) {
	good := map[string][2]string{
		"alt+r":  {`^[r`, `\er`},
		"alt+7":  {`^[7`, `\e7`},
		"ctrl+g": {`^G`, `\C-g`},
		"ctrl+t": {`^T`, `\C-t`},
	}
	for in, want := range good {
		k, err := parseShellKey(in)
		if err != nil || k.zsh != want[0] || k.bash != want[1] {
			t.Errorf("%s: %+v %v", in, k, err)
		}
	}
	// ctrl keys the terminal or the line editor needs, and anything that could break out of the script.
	for _, in := range []string{"", "r", "alt+", "alt+rr", "alt+R", "shift+r", "ctrl+c", "ctrl+d", "ctrl+m", "ctrl+j", "ctrl+i", "ctrl+h", "ctrl+z", "ctrl+s", "ctrl+q", "alt+'", `alt+"`, "alt+;"} {
		if _, err := parseShellKey(in); err == nil {
			t.Errorf("%q should be refused", in)
		}
	}
}

func TestShellScriptsUseTheKey(t *testing.T) {
	k, _ := parseShellKey("alt+t")
	zsh, bash := renderShellScript(zshScript, k), renderShellScript(bashScript, k)
	if !strings.Contains(zsh, `bindkey '^[t' _cervus_pick_widget`) || strings.Contains(zsh, "^[r") {
		t.Errorf("zsh:\n%s", zsh)
	}
	if !strings.Contains(bash, `bind '"\et": `) || strings.Contains(bash, `\er`) {
		t.Errorf("bash:\n%s", bash)
	}
}
