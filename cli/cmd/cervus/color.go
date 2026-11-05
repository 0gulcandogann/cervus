package main

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// The CLI's colors are the banner's: white text, ice and blue accents on a dark terminal.
var (
	colorTitle   = rgb{245, 248, 255}
	colorCommand = rgb{190, 210, 255}
	colorAccent  = rgb{110, 150, 250}
	colorText    = rgb{200, 208, 228}
	colorQuiet   = rgb{140, 152, 186}
	colorWarn    = rgb{255, 200, 120}
)

// colorFor is true only for a terminal that has not refused color.
func colorFor(tty bool) bool {
	return tty && os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb"
}

func stdoutColor() bool { return colorFor(isTTY(os.Stdout)) }

// paint uses 24-bit color where the terminal says it has it, and the nearest of 256 colors elsewhere.
func paint(s string, c rgb, bold bool) string {
	if s == "" {
		return s
	}
	b := ""
	if bold {
		b = "1;"
	}
	if ct := os.Getenv("COLORTERM"); ct == "truecolor" || ct == "24bit" {
		return fmt.Sprintf("\x1b[%s38;2;%d;%d;%dm%s\x1b[0m", b, c.r, c.g, c.b, s)
	}
	q := func(v uint8) int { return (int(v)*5 + 127) / 255 }
	return fmt.Sprintf("\x1b[%s38;5;%dm%s\x1b[0m", b, 16+36*q(c.r)+6*q(c.g)+q(c.b), s)
}

var (
	helpLineRe = regexp.MustCompile(`^(  )(\S.*?)(\s{2,})(\S.*)$`)
	helpOnlyRe = regexp.MustCompile(`^(  )(\S.*)$`)
)

// styleHelp colors the usage text without changing a single character of it.
func styleHelp(text string, on bool) string {
	if !on {
		return text
	}
	lines := strings.Split(text, "\n")
	for i, l := range lines {
		switch {
		case i == 0:
			name, rest, _ := strings.Cut(l, " ")
			lines[i] = paint(name, colorTitle, true) + " " + paint(rest, colorQuiet, false)
		case l == "":
		case !strings.HasPrefix(l, " ") && strings.HasSuffix(l, ":"):
			lines[i] = paint(l, colorAccent, true)
		case strings.HasPrefix(l, strings.Repeat(" ", 20)):
			n := len(l) - len(strings.TrimLeft(l, " "))
			lines[i] = l[:n] + paint(l[n:], colorText, false)
		default:
			if m := helpLineRe.FindStringSubmatch(l); m != nil {
				lines[i] = m[1] + styleCommand(m[2]) + m[3] + paint(m[4], colorText, false)
			} else if m := helpOnlyRe.FindStringSubmatch(l); m != nil {
				lines[i] = m[1] + styleCommand(m[2])
			}
		}
	}
	return strings.Join(lines, "\n")
}

// styleCommand makes the command words stand out. Everything from the first argument or option on is
// in the accent color, so "--vault V" reads as one option.
func styleCommand(s string) string {
	words := strings.Split(s, " ")
	args := false
	for i, w := range words {
		if w == "" {
			continue
		}
		if strings.ContainsAny(w[:1], "<[-") || strings.Contains(w, "|") && i > 0 {
			args = true
		}
		if args || w == "|" {
			words[i] = paint(w, colorAccent, false)
		} else {
			words[i] = paint(w, colorCommand, true)
		}
	}
	return strings.Join(words, " ")
}

var commandInTextRe = regexp.MustCompile("`[^`]+`|cervus(?: [a-z][a-z-]*)+(?: <[^>]+>)?|(?:Alt|Ctrl)\\+[a-z0-9]")

// styleLine colors a sentence, with the commands it names in the accent color.
func styleLine(s string, on bool) string {
	if !on || s == "" {
		return s
	}
	if rest, ok := strings.CutPrefix(s, "Warning:"); ok {
		return paint("Warning:", colorWarn, true) + styleLine(rest, on)
	}
	var b strings.Builder
	last := 0
	for _, m := range commandInTextRe.FindAllStringIndex(s, -1) {
		b.WriteString(paint(s[last:m[0]], colorText, false))
		b.WriteString(paint(s[m[0]:m[1]], colorCommand, true))
		last = m[1]
	}
	b.WriteString(paint(s[last:], colorText, false))
	return b.String()
}

func styleQuestion(q, choices string, on bool) string {
	if !on {
		return q + " " + choices + " "
	}
	return paint(q, colorTitle, true) + " " + paint(choices, colorAccent, false) + " "
}

// say and sayf print a line to the terminal in the CLI's colors.
func say(s string) { fmt.Println(styleLine(s, stdoutColor())) }

func sayf(format string, args ...any) {
	fmt.Println(styleLine(strings.TrimSuffix(fmt.Sprintf(format, args...), "\n"), stdoutColor()))
}
