package main

import (
	"errors"
	"strings"
	"testing"

	"cervus/internal/client"
)

func TestWithUnlock(t *testing.T) {
	locked := &client.RemoteError{Code: "locked", Message: "vault is locked"}
	oldUnlock, oldStored, oldHold := sendUnlock, storedPassphrase, keychainHoldOff
	t.Cleanup(func() { sendUnlock, storedPassphrase, keychainHoldOff = oldUnlock, oldStored, oldHold })
	keychainHoldOff = func() {}
	storedPassphrase = func() string { return "" }

	t.Run("not locked never asks", func(t *testing.T) {
		asked := 0
		err := withUnlock(func() error { return nil }, func() (string, error) { asked++; return "", nil })
		if err != nil || asked != 0 {
			t.Fatalf("err=%v asked=%d", err, asked)
		}
	})
	t.Run("locked asks once and retries", func(t *testing.T) {
		calls, asked := 0, 0
		var sent string
		sendUnlock = func(p, _ string) error { sent = p; return nil }
		err := withUnlock(func() error {
			calls++
			if calls == 1 {
				return locked
			}
			return nil
		}, func() (string, error) { asked++; return "the passphrase", nil })
		if err != nil || calls != 2 || asked != 1 || sent != "the passphrase" {
			t.Fatalf("err=%v calls=%d asked=%d sent=%q", err, calls, asked, sent)
		}
	})
	t.Run("wrong passphrase does not retry", func(t *testing.T) {
		calls := 0
		sendUnlock = func(_, _ string) error { return &client.RemoteError{Code: "auth_failed", Message: "wrong passphrase"} }
		err := withUnlock(func() error { calls++; return locked }, func() (string, error) { return "x", nil })
		if err == nil || !strings.Contains(err.Error(), "wrong passphrase") || calls != 1 {
			t.Fatalf("err=%v calls=%d", err, calls)
		}
	})
	t.Run("cancelled prompt stops", func(t *testing.T) {
		cancelled := errors.New("cancelled")
		sendUnlock = func(_, _ string) error { t.Fatal("must not unlock"); return nil }
		if err := withUnlock(func() error { return locked }, func() (string, error) { return "", cancelled }); !errors.Is(err, cancelled) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("no terminal keeps the locked error", func(t *testing.T) {
		if err := withUnlock(func() error { return locked }, nil); !errors.Is(err, error(locked)) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("a stored passphrase unlocks without asking", func(t *testing.T) {
		storedPassphrase = func() string { return "from keychain" }
		defer func() { storedPassphrase = func() string { return "" } }()
		calls := 0
		var sent string
		sendUnlock = func(p, _ string) error { sent = p; return nil }
		err := withUnlock(func() error {
			calls++
			if calls == 1 {
				return locked
			}
			return nil
		}, nil)
		if err != nil || calls != 2 || sent != "from keychain" {
			t.Fatalf("err=%v calls=%d sent=%q", err, calls, sent)
		}
	})
	t.Run("a refused stored passphrase falls back to asking", func(t *testing.T) {
		storedPassphrase = func() string { return "stale" }
		defer func() { storedPassphrase = func() string { return "" } }()
		calls, asked := 0, 0
		sendUnlock = func(p, _ string) error {
			if p == "stale" {
				return &client.RemoteError{Code: "auth_failed", Message: "wrong passphrase"}
			}
			return nil
		}
		err := withUnlock(func() error {
			calls++
			if calls == 1 {
				return locked
			}
			return nil
		}, func() (string, error) { asked++; return "typed", nil })
		if err != nil || asked != 1 || calls != 2 {
			t.Fatalf("err=%v asked=%d calls=%d", err, asked, calls)
		}
	})
	t.Run("other errors pass through", func(t *testing.T) {
		other := &client.RemoteError{Code: "aws_error", Message: "denied"}
		if err := withUnlock(func() error { return other }, func() (string, error) { t.Fatal("must not ask"); return "", nil }); !errors.Is(err, error(other)) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestReadHiddenLine(t *testing.T) {
	cases := []struct {
		in, want string
		wantErr  bool
	}{
		{"secret\r", "secret", false},
		{"secret\n", "secret", false},
		{"sec\x7fcret\r", "secret", false},
		{"\x7f\x7fok\r", "ok", false},
		{"abc\x03", "", true},
		{"abc", "", true},
	}
	for _, c := range cases {
		got, err := readHiddenLine(strings.NewReader(c.in))
		if got != c.want || (err != nil) != c.wantErr {
			t.Errorf("%q: got %q, %v", c.in, got, err)
		}
	}
}
