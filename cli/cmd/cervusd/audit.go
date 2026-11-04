package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// auditLog is an append-only JSON-lines log. Every entry stores the hash of the previous one, so
// editing or deleting an entry in the middle is detectable. Truncating the end is not.
// Entries never contain secrets: only event names, role/identity/secret names and outcomes.
type auditLog struct {
	mu   sync.Mutex
	path string
	prev string
}

const genesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

type auditEntry struct {
	TS     string         `json:"ts"`
	Event  string         `json:"event"`
	Fields map[string]any `json:"fields,omitempty"`
	Prev   string         `json:"prev"`
	Hash   string         `json:"hash"`
}

func entryHash(prev, ts, event string, fields map[string]any) string {
	f, _ := json.Marshal(fields) // map keys are sorted, so this is canonical
	h := sha256.Sum256([]byte(prev + "|" + ts + "|" + event + "|" + string(f)))
	return hex.EncodeToString(h[:])
}

func openAudit(path string) (*auditLog, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	l := &auditLog{path: path, prev: genesisHash}
	f, err := os.Open(path)
	if err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			var e auditEntry
			if json.Unmarshal(sc.Bytes(), &e) == nil && e.Hash != "" {
				l.prev = e.Hash
			}
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return l, nil
}

// Append records an event. It is safe to call on a nil log.
func (l *auditLog) Append(event string, fields map[string]any) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	ts := time.Now().UTC().Format(time.RFC3339)
	e := auditEntry{TS: ts, Event: event, Fields: fields, Prev: l.prev}
	e.Hash = entryHash(e.Prev, e.TS, e.Event, e.Fields)
	b, err := json.Marshal(e)
	if err != nil {
		log.Printf("audit: %v", err)
		return
	}
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		log.Printf("audit: %v", err)
		return
	}
	defer f.Close()
	if _, err := f.Write(append(b, '\n')); err != nil {
		log.Printf("audit: %v", err)
		return
	}
	_ = f.Sync()
	l.prev = e.Hash
}

func readEntries(path string) ([]auditEntry, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []auditEntry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var e auditEntry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			out = append(out, auditEntry{Event: "!corrupt line"})
			continue
		}
		out = append(out, e)
	}
	return out, sc.Err()
}

// Verify walks the whole chain. It returns the number of entries and the 1-based line of the
// first broken entry (0 if the chain is intact).
func (l *auditLog) Verify() (entries, badLine int, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	list, err := readEntries(l.path)
	if err != nil {
		return 0, 0, err
	}
	prev := genesisHash
	for i, e := range list {
		if e.Prev != prev || e.Hash != entryHash(e.Prev, e.TS, e.Event, e.Fields) {
			return len(list), i + 1, nil
		}
		prev = e.Hash
	}
	return len(list), 0, nil
}

func (l *auditLog) Tail(n int) ([]auditEntry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	list, err := readEntries(l.path)
	if err != nil {
		return nil, err
	}
	if n > 0 && len(list) > n {
		list = list[len(list)-n:]
	}
	return list, nil
}

func formatEntry(e auditEntry) string {
	var keys []string
	for k := range e.Fields {
		keys = append(keys, k)
	}
	// stable order: sort keys
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%v", k, e.Fields[k]))
	}
	return strings.TrimSpace(fmt.Sprintf("%s %-20s %s", e.TS, e.Event, strings.Join(parts, " ")))
}

// auditedOps maps public operations to the parameter names that may be recorded.
var auditedOps = map[string][]string{
	"init":                nil,
	"unlock":              {"source"},
	"keychain.event":      {"action"},
	"lock":                nil,
	"passwd":              nil,
	"recover":             {"drop_local"},
	"identity.add":        {"id", "region"},
	"identity.update":     {"id", "region", "mfa_serial", "rotate", "verify", "allow_different_principal"},
	"identity.remove":     {"id"},
	"identity.verify_key": {"id"},
	"identity.mfa_import": {"id"},
	"role.add":            {"name", "identity", "arn", "mfa", "confirm"},
	"role.edit":           {"name", "identity", "arn", "mfa", "confirm"},
	"role.remove":         {"name"},
	"use":                 {"role", "session"},
	"secret.put":          {"name", "scope", "type"},
	"secret.get":          {"name"},
	"secret.delete":       {"name"},
}

// record writes an audit entry for a finished public request, if the operation is audited.
func (l *auditLog) record(op string, params json.RawMessage, resp outResponse) {
	allowed, ok := auditedOps[op]
	if !ok || l == nil {
		return
	}
	fields := map[string]any{}
	var in map[string]any
	_ = json.Unmarshal(params, &in)
	if op == "unlock" && in["source"] != "keychain" {
		delete(in, "source") // the only value worth recording; anything else could be a mistake
	}
	for _, k := range allowed {
		if v, ok := in[k]; ok {
			fields[k] = v
		}
	}
	if resp.OK {
		fields["result"] = "ok"
	} else if resp.Error != nil {
		fields["result"] = "failed"
		fields["error"] = resp.Error.Code
	}
	l.Append(op, fields)
}
