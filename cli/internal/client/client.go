// Package client talks to the cervusd daemon over its Unix socket.
package client

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

// Timeout, if non-zero, bounds connecting and the whole request (used by the fast prompt command).
var Timeout time.Duration

// RemoteError is an error reported by the daemon or the vault behind it.
type RemoteError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Vault   string `json:"vault,omitempty"` // the locked vault, when Code is "locked"
}

func (e *RemoteError) Error() string { return e.Message }

type request struct {
	ID     uint64 `json:"id"`
	Op     string `json:"op"`
	Params any    `json:"params,omitempty"`
}

type response struct {
	ID    uint64          `json:"id"`
	OK    bool            `json:"ok"`
	Data  json.RawMessage `json:"data,omitempty"`
	Error *RemoteError    `json:"error,omitempty"`
}

// runUserBase is the parent of the per-user runtime directories on Linux. Tests replace it.
var runUserBase = "/run/user"

// SocketPath returns the socket this process should talk to.
func SocketPath() string {
	if p := os.Getenv("CERVUS_SOCKET"); p != "" {
		return p
	}
	return DefaultSocketPath()
}

// DefaultSocketPath returns the socket of a daemon that was not given a custom one, such as the
// login service.
func DefaultSocketPath() string {
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		return filepath.Join(dir, "cervus", "cervus.sock")
	}
	// Some logins (SSH without a session manager) lack XDG_RUNTIME_DIR, but the login service
	// still listens in the per-user runtime directory.
	if p, ok := runUserSocket(); ok {
		return p
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".cervus", "cervus.sock")
}

// runUserSocket finds the per-user socket, but only if nobody else could have planted it: passphrases
// go through this socket, and the client has no other way to tell who is listening.
func runUserSocket() (string, bool) {
	uid := os.Getuid()
	userDir := filepath.Join(runUserBase, strconv.Itoa(uid))
	dir := filepath.Join(userDir, "cervus")
	if !privateDir(userDir, uid) || !privateDir(dir, uid) {
		return "", false
	}
	path := filepath.Join(dir, "cervus.sock")
	st, err := os.Lstat(path)
	if err != nil || st.Mode()&os.ModeSocket == 0 || !ownedBy(st, uid) {
		return "", false
	}
	return path, true
}

func privateDir(path string, uid int) bool {
	st, err := os.Lstat(path)
	return err == nil && st.IsDir() && st.Mode().Perm()&0o022 == 0 && ownedBy(st, uid)
}

func ownedBy(st os.FileInfo, uid int) bool {
	sys, ok := st.Sys().(*syscall.Stat_t)
	return ok && int(sys.Uid) == uid
}

// Call opens a connection, sends one request and decodes the reply into out (if non-nil).
func Call(op string, params any, out any) error {
	path := SocketPath()
	conn, err := net.DialTimeout("unix", path, Timeout)
	if err == nil && Timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(Timeout))
	}
	if err != nil {
		return fmt.Errorf("cannot reach the cervus daemon at %s (is cervusd running?): %w", path, err)
	}
	defer conn.Close()

	b, err := json.Marshal(request{ID: 1, Op: op, Params: params})
	if err != nil {
		return err
	}
	if _, err := conn.Write(append(b, '\n')); err != nil {
		return err
	}
	line, err := bufio.NewReaderSize(conn, 1<<20).ReadBytes('\n')
	if err != nil {
		return err
	}
	var resp response
	if err := json.Unmarshal(line, &resp); err != nil {
		return fmt.Errorf("invalid daemon response: %w", err)
	}
	if !resp.OK {
		if resp.Error != nil {
			return resp.Error
		}
		return fmt.Errorf("request failed")
	}
	if out != nil && len(resp.Data) > 0 {
		return json.Unmarshal(resp.Data, out)
	}
	return nil
}
