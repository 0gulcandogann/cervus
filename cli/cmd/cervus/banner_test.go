package main

import (
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func visibleWidth(line string) int { return utf8.RuneCountInString(ansiRe.ReplaceAllString(line, "")) }

func TestBannerFillsTheWidthAndStaysABand(t *testing.T) {
	cases := []struct{ cols, lines, wantWidth, maxRows int }{
		{200, 50, 199, 20},
		{146, 40, 145, 20},
		{300, 60, 220, 20},
		{120, 30, 119, 19},
		{100, 30, 99, 16},
		{90, 24, 89, 14},
		{80, 24, 79, 12},
		{80, 12, 79, 8},
	}
	for _, c := range cases {
		out := renderBanner(c.cols, c.lines, true)
		if len(out) == 0 || len(out) > c.maxRows {
			t.Errorf("%dx%d: %d rows", c.cols, c.lines, len(out))
			continue
		}
		for i, line := range out {
			if w := visibleWidth(line); w != c.wantWidth {
				t.Errorf("%dx%d row %d: width %d, want %d", c.cols, c.lines, i, w, c.wantWidth)
				break
			}
		}
	}
}

func TestBannerKeepsTheChosenWordmarkWhenItFits(t *testing.T) {
	for _, size := range [][2]int{{200, 50}, {146, 40}, {100, 30}, {80, 24}} {
		joined := strings.Join(renderBanner(size[0], size[1], true), "\n")
		if !strings.Contains(ansiRe.ReplaceAllString(joined, ""), "█") || !strings.Contains(joined, "╗") {
			t.Errorf("%v: the large wordmark is missing", size)
		}
	}
}

func TestBannerHasNoSceneInSmallTerminals(t *testing.T) {
	for _, size := range [][2]int{{76, 30}, {60, 20}, {30, 20}, {120, 11}, {120, 8}} {
		if out := renderBanner(size[0], size[1], true); out != nil {
			t.Errorf("%v should have no scene, got %d rows", size, len(out))
		}
	}
}

func TestBannerDrawsTheDeerCloudAndWordmark(t *testing.T) {
	plain := ansiRe.ReplaceAllString(strings.Join(renderBanner(120, 30, true), "\n"), "")
	if !strings.ContainsAny(plain, "▘▝▖▗▌▐▛▜▙▟▚▞") {
		t.Error("the deer's quadrant blocks are missing")
	}
	braille := 0
	for _, r := range plain {
		if r >= 0x2801 && r <= 0x28FF {
			braille++
		}
	}
	if braille < 500 {
		t.Errorf("only %d cloud cells", braille)
	}
	for _, line := range []string{"╔════╝", "╚═════╝"} {
		if !strings.Contains(plain, line) {
			t.Errorf("the wordmark's line details are missing: %s", line)
		}
	}
}

func TestBannerIsTheSameEachTime(t *testing.T) {
	a, b := strings.Join(renderBanner(120, 30, true), "\n"), strings.Join(renderBanner(120, 30, true), "\n")
	if a != b {
		t.Fatal("the banner must not change between runs")
	}
}

func TestBannerWithoutColorHasNoEscapes(t *testing.T) {
	for _, size := range [][2]int{{120, 30}, {60, 20}, {30, 20}} {
		for _, line := range renderBanner(size[0], size[1], false) {
			if strings.Contains(line, "\x1b") {
				t.Fatalf("%v: escape in plain output: %q", size, line)
			}
		}
	}
	if out := renderBanner(120, 30, false); len(out) != 6 || !strings.Contains(out[0], "█") {
		t.Fatalf("plain output should be the wordmark: %d lines", len(out))
	}
	if out := renderBanner(30, 30, false); len(out) != 1 || strings.TrimSpace(out[0]) != "cervus" {
		t.Fatalf("very narrow plain output: %q", out)
	}
}

func TestBannerColorChoice(t *testing.T) {
	cases := []struct {
		name, noColor, term, colorterm string
		want                           bool
	}{
		{"truecolor", "", "xterm-kitty", "truecolor", true},
		{"24bit", "", "xterm", "24bit", true},
		{"NO_COLOR", "1", "xterm-kitty", "truecolor", false},
		{"dumb", "", "dumb", "truecolor", false},
		{"unknown", "", "xterm", "", false},
	}
	for _, c := range cases {
		t.Setenv("NO_COLOR", c.noColor)
		t.Setenv("TERM", c.term)
		t.Setenv("COLORTERM", c.colorterm)
		if got := bannerUsesColor(); got != c.want {
			t.Errorf("%s: got %v", c.name, got)
		}
	}
}
