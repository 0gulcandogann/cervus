package main

import (
	"strings"
	"testing"
)

// parseINI reads ~/.aws/config and ~/.aws/credentials, and migrate rewrites what it parsed.
func FuzzParseINI(f *testing.F) {
	f.Add("[default]\naws_access_key_id = AKIA\n# note\n\n[profile dev]\nrole_arn=arn:aws:iam::1:role/x\n")
	f.Add("key without a section\n[unclosed\n=\n\r\n")
	f.Fuzz(func(t *testing.T, in string) {
		ini := parseINI([]byte(in))
		again := parseINI([]byte(ini.String()))
		// Rewriting what was read must keep every setting, or migrate could lose one from a real file.
		if a, b := iniSettings(ini), iniSettings(again); a != b {
			t.Fatalf("settings changed:\n%q\n%q", a, b)
		}
	})
}

func iniSettings(f *iniFile) string {
	var b strings.Builder
	for _, s := range f.sections {
		b.WriteString("[" + s.name + "]\n")
		for _, l := range s.lines {
			if k, v, ok := splitKV(l); ok {
				b.WriteString(k + "=" + v + "\n")
			}
		}
	}
	return b.String()
}

func FuzzParseShellKey(f *testing.F) {
	for _, s := range []string{"alt+r", "ctrl+t", "alt+", "+", "ALT+R", "alt+é", "ctrl+\x00"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		k, err := parseShellKey(in)
		if err != nil {
			return
		}
		// The accepted key is written into the shell script, so it must not be able to break out.
		if strings.ContainsAny(k.name, " '\"\\$`;\n\r\x00") {
			t.Fatalf("unsafe key accepted: %q", k.name)
		}
	})
}
