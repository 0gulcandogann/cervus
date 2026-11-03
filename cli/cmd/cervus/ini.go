package main

import (
	"regexp"
	"strings"
)

// A minimal INI reader/writer that preserves everything it does not touch (comments, order),
// used to read and edit ~/.aws/credentials and ~/.aws/config.

type iniSection struct {
	name   string // text between the brackets, e.g. "default" or "profile prod"
	header string
	lines  []string
}

type iniFile struct {
	preamble []string
	sections []*iniSection
}

var sectionRe = regexp.MustCompile(`^\s*\[(.+?)\]\s*$`)

func parseINI(data []byte) *iniFile {
	f := &iniFile{}
	var cur *iniSection
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	text = strings.TrimSuffix(text, "\n")
	if text == "" {
		return f
	}
	for _, line := range strings.Split(text, "\n") {
		if m := sectionRe.FindStringSubmatch(line); m != nil {
			cur = &iniSection{name: strings.TrimSpace(m[1]), header: line}
			f.sections = append(f.sections, cur)
			continue
		}
		if cur == nil {
			f.preamble = append(f.preamble, line)
		} else {
			cur.lines = append(cur.lines, line)
		}
	}
	return f
}

func splitKV(line string) (key, val string, ok bool) {
	t := strings.TrimSpace(line)
	if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, ";") {
		return "", "", false
	}
	i := strings.Index(t, "=")
	if i < 0 {
		return "", "", false
	}
	return strings.TrimSpace(t[:i]), strings.TrimSpace(t[i+1:]), true
}

func (s *iniSection) get(key string) string {
	for _, l := range s.lines {
		if k, v, ok := splitKV(l); ok && strings.EqualFold(k, key) {
			return v
		}
	}
	return ""
}

func (s *iniSection) removeKeys(keys ...string) {
	var kept []string
	for _, l := range s.lines {
		drop := false
		if k, _, ok := splitKV(l); ok {
			for _, want := range keys {
				if strings.EqualFold(k, want) {
					drop = true
				}
			}
		}
		if !drop {
			kept = append(kept, l)
		}
	}
	s.lines = kept
}

func (s *iniSection) empty() bool {
	for _, l := range s.lines {
		if t := strings.TrimSpace(l); t != "" && !strings.HasPrefix(t, "#") && !strings.HasPrefix(t, ";") {
			return false
		}
	}
	return true
}

func (f *iniFile) find(name string) *iniSection {
	for _, s := range f.sections {
		if s.name == name {
			return s
		}
	}
	return nil
}

func (f *iniFile) removeSection(name string) {
	var kept []*iniSection
	for _, s := range f.sections {
		if s.name != name {
			kept = append(kept, s)
		}
	}
	f.sections = kept
}

func (f *iniFile) String() string {
	var b strings.Builder
	for _, l := range f.preamble {
		b.WriteString(l + "\n")
	}
	for _, s := range f.sections {
		b.WriteString(s.header + "\n")
		for _, l := range s.lines {
			b.WriteString(l + "\n")
		}
	}
	return b.String()
}
