// cervusd is the Cervus daemon. It owns the vault child process and exposes a small,
// allowlisted API on a private Unix socket.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"cervus/internal/client"
	"cervus/internal/config"
	"cervus/internal/vaultproc"
)

// publicToVault maps public API operations to internal vault operations.
// Anything not listed here is rejected before it reaches the vault.
var publicToVault = map[string]string{
	"ping":          "ping",
	"status":        "status",
	"init":          "init",
	"unlock":        "unlock",
	"recover":       "recover",
	"lock":          "lock",
	"passwd":        "change_passphrase",
	"secret.put":    "put",
	"secret.get":    "get",
	"secret.list":   "list",
	"secret.delete": "delete",
}

type inRequest struct {
	ID     uint64          `json:"id"`
	Op     string          `json:"op"`
	Params json.RawMessage `json:"params,omitempty"`
}

type outResponse struct {
	ID    uint64                 `json:"id"`
	OK    bool                   `json:"ok"`
	Data  json.RawMessage        `json:"data,omitempty"`
	Error *vaultproc.RemoteError `json:"error,omitempty"`
}

func main() {
	socket := flag.String("socket", client.SocketPath(), "daemon socket path")
	vaultBin := flag.String("vault-bin", "", "path to cervus-vault (default: next to cervusd, then PATH)")
	vaultDir := flag.String("vault-dir", "", "vault directory (default: ~/.cervus/vault)")
	idle := flag.Int("idle-secs", 0, "auto-lock after this many idle seconds (default: 14400)")
	cfgPath := flag.String("config", config.Path(), "config file path")
	auditPath := flag.String("audit-log", "", "audit log path (default: audit.log next to the config file)")
	stsEndpoint := flag.String("sts-endpoint", "", "override the AWS STS endpoint (testing only)")
	gcEvery := flag.Duration("gc-interval", 30*time.Second, "how often to forget sessions of exited shells")
	flag.Parse()

	bin, err := resolveVaultBin(*vaultBin)
	if err != nil {
		log.Fatal(err)
	}
	var env []string
	defaultDir := *vaultDir
	if defaultDir == "" {
		defaultDir = os.Getenv("CERVUS_VAULT_DIR")
	}
	if defaultDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			log.Fatal(err)
		}
		defaultDir = filepath.Join(home, ".cervus", "vault")
	}
	if *idle > 0 {
		env = append(env, "CERVUS_IDLE_SECS="+strconv.Itoa(*idle))
	}
	vaults := newVaultSet(bin, env, defaultDir)
	defer vaults.close()
	app := newApp(vaults, *cfgPath, *stsEndpoint)
	if *auditPath == "" {
		*auditPath = filepath.Join(filepath.Dir(*cfgPath), "audit.log")
	}
	if al, err := openAudit(*auditPath); err != nil {
		log.Printf("warning: audit log disabled: %v", err)
	} else {
		app.audit = al
	}
	go func() {
		for range time.Tick(*gcEvery) {
			app.gcSessions()
		}
	}()

	ln, err := listen(*socket)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("cervusd listening on %s (vault: %s)", *socket, bin)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		ln.Close()
		vaults.close()
		os.Remove(*socket)
		os.Exit(0)
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("accept: %v", err)
			continue
		}
		go serve(conn, app)
	}
}

func resolveVaultBin(flagVal string) (string, error) {
	if flagVal != "" {
		return flagVal, nil
	}
	if exe, err := os.Executable(); err == nil {
		cand := filepath.Join(filepath.Dir(exe), "cervus-vault")
		if _, err := os.Stat(cand); err == nil {
			return cand, nil
		}
	}
	p, err := exec.LookPath("cervus-vault")
	if err != nil {
		return "", fmt.Errorf("cervus-vault not found; build it or pass --vault-bin")
	}
	return p, nil
}

func listen(path string) (net.Listener, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	if _, err := os.Stat(path); err == nil {
		if c, err := net.Dial("unix", path); err == nil {
			c.Close()
			return nil, fmt.Errorf("another cervusd is already running on %s", path)
		}
		os.Remove(path) // stale socket from a crash
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

func serve(conn net.Conn, app *app) {
	defer conn.Close()
	if err := checkPeer(conn); err != nil {
		log.Printf("rejected connection: %v", err)
		return
	}
	r := bufio.NewReaderSize(conn, 1<<20)
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			writeJSON(conn, handle(line, app))
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("read: %v", err)
			}
			return
		}
	}
}

func handle(line []byte, app *app) outResponse {
	var req inRequest
	resp := handleRequest(line, app, &req)
	app.audit.record(req.Op, req.Params, resp)
	return resp
}

func handleRequest(line []byte, app *app, reqOut *inRequest) outResponse {
	var req inRequest
	defer func() { *reqOut = req }()
	if err := json.Unmarshal(line, &req); err != nil {
		return fail(0, "bad_request", "invalid JSON")
	}
	if h, ok := apiHandlers[req.Op]; ok {
		if aerr := checkParamKeys(req.Params); aerr != nil {
			return outResponse{ID: req.ID, Error: aerr}
		}
		data, aerr := h(app, req.Params)
		if aerr != nil {
			return outResponse{ID: req.ID, Error: aerr}
		}
		b, err := json.Marshal(data)
		if err != nil {
			return fail(req.ID, "internal", err.Error())
		}
		return outResponse{ID: req.ID, OK: true, Data: b}
	}
	if req.Op == "lock" || req.Op == "recover" {
		app.clearCaches()
	}
	vop, ok := publicToVault[req.Op]
	if !ok {
		return fail(req.ID, "unknown_op", fmt.Sprintf("unknown op %q", req.Op))
	}
	params, gerr := guardSecretParams(req.Op, req.Params)
	if gerr != nil {
		return outResponse{ID: req.ID, Error: gerr}
	}
	vaultName, verr := vaultParam(params)
	if verr != nil {
		return outResponse{ID: req.ID, Error: verr}
	}
	if req.Op == "lock" && vaultName == "" { // no vault named: lock them all
		for _, sup := range app.vaults.running() {
			_, _, _ = sup.Call(vop, params)
		}
		return outResponse{ID: req.ID, OK: true, Data: json.RawMessage(`{"locked":true}`)}
	}
	sup, name, verr := app.vaults.get(vaultName)
	if verr != nil {
		return outResponse{ID: req.ID, Error: verr}
	}
	if req.Op == "init" {
		if err := app.vaults.prepare(name); err != nil {
			return fail(req.ID, "internal", err.Error())
		}
	}
	data, rerr, err := sup.Call(vop, params)
	switch {
	case errors.Is(err, vaultproc.ErrUnavailable):
		return fail(req.ID, "internal", "vault process crashed and was reset; it is locked, try again")
	case err != nil:
		return fail(req.ID, "internal", err.Error())
	case rerr != nil:
		return outResponse{ID: req.ID, Error: lockedMessage(rerr, name)}
	}
	return outResponse{ID: req.ID, OK: true, Data: data}
}

// checkParamKeys refuses keys that are not lowercase. Go matches struct fields case-insensitively but
// the audit log reads exact keys, so {"id":"decoy","ID":"work"} would change one thing and log another.
func checkParamKeys(raw json.RawMessage) *vaultproc.RemoteError {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return nil // not an object: the handler reports it
	}
	for k := range fields {
		if k != strings.ToLower(k) {
			return &vaultproc.RemoteError{Code: "bad_request", Message: fmt.Sprintf("parameter %q must be lowercase", k)}
		}
	}
	return nil
}

// reservedSecretPrefixes name secrets that only the daemon may touch: long-term access keys and
// MFA seeds. Handlers reach them through vaultCall; the public secret.* API must not.
var reservedSecretPrefixes = []string{"aws-key.", "mfa-seed."}

// guardSecretParams refuses public secret operations on reserved names. It returns the params to
// forward, re-encoded from what it checked, so the vault cannot read a different "name" than the
// one judged here (duplicate keys, or Go's case-insensitive struct field matching).
func guardSecretParams(op string, raw json.RawMessage) (json.RawMessage, *vaultproc.RemoteError) {
	switch op {
	case "secret.get", "secret.put", "secret.delete":
	default:
		return raw, nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, &vaultproc.RemoteError{Code: "bad_request", Message: "invalid parameters"}
	}
	var name string
	if v, ok := fields["name"]; ok {
		_ = json.Unmarshal(v, &name) // a non-string name is rejected by the vault
	}
	lower := strings.ToLower(name) // case-insensitive file systems open the same file
	for _, prefix := range reservedSecretPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return nil, &vaultproc.RemoteError{Code: "denied", Message: fmt.Sprintf(
				"secret %q is managed by Cervus and cannot be read or changed directly; use `cervus identity`", name)}
		}
	}
	checked, err := json.Marshal(fields)
	if err != nil {
		return nil, &vaultproc.RemoteError{Code: "internal", Message: err.Error()}
	}
	return checked, nil
}

func fail(id uint64, code, msg string) outResponse {
	return outResponse{ID: id, Error: &vaultproc.RemoteError{Code: code, Message: msg}}
}

func writeJSON(w io.Writer, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	w.Write(append(b, '\n'))
}
