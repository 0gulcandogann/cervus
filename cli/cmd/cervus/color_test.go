package main

import (
	"strings"
	"testing"
)

func TestStyleHelpKeepsTheTextAndOnlyAddsColor(t *testing.T) {
	plain := usageText()
	styled := styleHelp(plain, true)
	if ansiRe.ReplaceAllString(styled, "") != plain {
		t.Fatal("coloring changed the text")
	}
	for _, want := range []string{"Vault:", "AWS:", "identity", "migrate"} {
		i := strings.Index(styled, want)
		if i < 0 || !strings.Contains(styled[max(0, i-30):i], "\x1b[") {
			t.Errorf("%q is not colored", want)
		}
	}
	if styleHelp(plain, false) != plain {
		t.Fatal("without color the help must be untouched")
	}
}

func TestStyleLineHighlightsCommandsAndQuestions(t *testing.T) {
	for _, in := range []string{
		"Add your first AWS user: cervus identity add <name>   (--own-vault gives it its own vault)",
		"To skip that, at a security cost: cervus keychain enable",
		"The running daemon keeps the old version: `cervus install-service` does that.",
	} {
		out := styleLine(in, true)
		if ansiRe.ReplaceAllString(out, "") != in {
			t.Errorf("text changed: %q", out)
		}
		if !strings.Contains(out, "\x1b[") {
			t.Errorf("no color in %q", out)
		}
	}
	q := styleQuestion("Create your vault?", "[Y/n]", true)
	if ansiRe.ReplaceAllString(q, "") != "Create your vault? [Y/n] " {
		t.Errorf("question text: %q", q)
	}
	if styleLine("plain", false) != "plain" || styleQuestion("Q?", "[Y/n]", false) != "Q? [Y/n] " {
		t.Error("without color nothing may change")
	}
}

func TestColorChoiceFollowsTheTerminal(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	if colorFor(true) {
		t.Error("NO_COLOR must turn color off")
	}
	t.Setenv("NO_COLOR", "")
	t.Setenv("TERM", "dumb")
	if colorFor(true) {
		t.Error("a dumb terminal gets no color")
	}
	t.Setenv("TERM", "xterm-256color")
	if colorFor(false) || !colorFor(true) {
		t.Error("color only on a terminal")
	}
}
