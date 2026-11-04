// Package vaultproc runs cervus-vault as a child process and talks to it over stdio.
// The vault has no socket on disk, so only this process can reach it.
package vaultproc

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
)

// RemoteError is an application-level error reported by the vault.
type RemoteError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Vault   string `json:"vault,omitempty"` // the locked vault, when Code is "locked"
}

func (e *RemoteError) Error() string { return fmt.Sprintf("%s: %s", e.Code, e.Message) }

type request struct {
	ID     uint64          `json:"id"`
	Op     string          `json:"op"`
	Params json.RawMessage `json:"params,omitempty"`
}

type response struct {
	ID    uint64          `json:"id"`
	OK    bool            `json:"ok"`
	Data  json.RawMessage `json:"data,omitempty"`
	Error *RemoteError    `json:"error,omitempty"`
}

// ErrUnavailable means the vault process could not be reached (it was restarted if possible).
var ErrUnavailable = errors.New("vault process unavailable")

type proc struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
}

// Supervisor owns the vault child process, serializes calls and restarts it after a crash.
type Supervisor struct {
	bin string
	env []string

	mu     sync.Mutex
	p      *proc
	nextID uint64
}

func NewSupervisor(bin string, env []string) *Supervisor {
	return &Supervisor{bin: bin, env: env}
}

func (s *Supervisor) start() error {
	cmd := exec.Command(s.bin)
	cmd.Env = append(os.Environ(), s.env...)
	cmd.Stderr = os.Stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("cannot start vault %q: %w", s.bin, err)
	}
	s.p = &proc{cmd: cmd, stdin: in, stdout: bufio.NewReaderSize(out, 1<<20)}
	return nil
}

func (s *Supervisor) drop() {
	if s.p == nil {
		return
	}
	s.p.stdin.Close()
	_ = s.p.cmd.Process.Kill()
	_ = s.p.cmd.Wait()
	s.p = nil
}

// Call sends one request to the vault. A transport failure drops the process (the next call
// starts a fresh, locked one) and returns ErrUnavailable.
func (s *Supervisor) Call(op string, params json.RawMessage) (json.RawMessage, *RemoteError, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.p == nil {
		if err := s.start(); err != nil {
			return nil, nil, err
		}
	}
	s.nextID++
	b, err := json.Marshal(request{ID: s.nextID, Op: op, Params: params})
	if err != nil {
		return nil, nil, err
	}
	if _, err := s.p.stdin.Write(append(b, '\n')); err != nil {
		s.drop()
		return nil, nil, ErrUnavailable
	}
	line, err := s.p.stdout.ReadBytes('\n')
	if err != nil {
		s.drop()
		return nil, nil, ErrUnavailable
	}
	var resp response
	if err := json.Unmarshal(line, &resp); err != nil {
		s.drop()
		return nil, nil, fmt.Errorf("invalid vault response: %w", err)
	}
	if !resp.OK {
		if resp.Error == nil {
			resp.Error = &RemoteError{Code: "internal", Message: "unknown vault error"}
		}
		return nil, resp.Error, nil
	}
	return resp.Data, nil, nil
}

// Close stops the vault process.
func (s *Supervisor) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.drop()
}
