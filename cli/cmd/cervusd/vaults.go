package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"cervus/internal/config"
	"cervus/internal/vaultproc"
)

const defaultVault = "default"

// vaultSet runs one vault process per named vault, each with its own directory and passphrase. The
// default vault keeps its old location, so existing setups work unchanged; the others live in a
// "vaults" folder next to it.
type vaultSet struct {
	bin        string
	env        []string
	defaultDir string

	mu    sync.Mutex
	procs map[string]*vaultproc.Supervisor
}

func newVaultSet(bin string, env []string, defaultDir string) *vaultSet {
	return &vaultSet{bin: bin, env: env, defaultDir: defaultDir, procs: map[string]*vaultproc.Supervisor{}}
}

// normalizeVault turns a requested name into a safe one: it becomes part of a path.
func normalizeVault(name string) (string, *apiErr) {
	if name == "" {
		return defaultVault, nil
	}
	if !config.ValidName(name) {
		return "", fe("bad_request", "vault name %q must be lowercase letters, digits, '-' or '_' (max 32)", name)
	}
	return name, nil
}

func (s *vaultSet) dir(name string) string {
	if name == defaultVault {
		return s.defaultDir
	}
	return filepath.Join(filepath.Dir(s.defaultDir), "vaults", name)
}

func (s *vaultSet) get(name string) (*vaultproc.Supervisor, string, *apiErr) {
	name, e := normalizeVault(name)
	if e != nil {
		return nil, "", e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sup, ok := s.procs[name]
	if !ok {
		env := append(append([]string{}, s.env...), "CERVUS_VAULT_DIR="+s.dir(name))
		sup = vaultproc.NewSupervisor(s.bin, env)
		s.procs[name] = sup
	}
	return sup, name, nil
}

// open is get for a vault that must already exist, so a mistyped name is an error instead of a new
// process that says "not initialized". The default vault always counts: `cervus init` makes it.
func (s *vaultSet) open(name string) (*vaultproc.Supervisor, string, *apiErr) {
	normal, e := normalizeVault(name)
	if e != nil {
		return nil, "", e
	}
	if !s.exists(normal) {
		return nil, "", fe("not_found", "no vault named %q; create it with `cervus vault create %s`", normal, normal)
	}
	return s.get(normal)
}

func (s *vaultSet) exists(name string) bool {
	if name == defaultVault {
		return true
	}
	st, err := os.Stat(s.dir(name))
	return err == nil && st.IsDir()
}

// names lists the default vault and every vault folder on disk.
func (s *vaultSet) names() []string {
	out := []string{defaultVault}
	entries, err := os.ReadDir(filepath.Join(filepath.Dir(s.defaultDir), "vaults"))
	if err != nil {
		return out
	}
	var others []string
	for _, e := range entries {
		if e.IsDir() && config.ValidName(e.Name()) && e.Name() != defaultVault {
			others = append(others, e.Name())
		}
	}
	sort.Strings(others)
	return append(out, others...)
}

// prepare makes the private parent folder before a named vault is created.
func (s *vaultSet) prepare(name string) error {
	if name == defaultVault {
		return nil
	}
	parent := filepath.Dir(s.dir(name))
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	return os.Chmod(parent, 0o700)
}

// running returns the vault processes started so far: only those can be unlocked.
func (s *vaultSet) running() []*vaultproc.Supervisor {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*vaultproc.Supervisor, 0, len(s.procs))
	for _, sup := range s.procs {
		out = append(out, sup)
	}
	return out
}

func (s *vaultSet) close() {
	for _, sup := range s.running() {
		sup.Close()
	}
}

// vaultParam reads the optional "vault" parameter of a public vault operation.
func vaultParam(raw json.RawMessage) (string, *apiErr) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return "", nil
	}
	v, ok := fields["vault"]
	if !ok {
		return "", nil
	}
	var name string
	if json.Unmarshal(v, &name) != nil {
		return "", fe("bad_request", "vault name must be a string")
	}
	return name, nil
}

// lockedMessage names the vault to open, so a user with several knows which passphrase is wanted.
func lockedMessage(rerr *apiErr, name string) *apiErr {
	if rerr == nil || rerr.Code != "locked" {
		return rerr
	}
	out := *rerr
	out.Vault = name
	if name != defaultVault {
		out.Message = fmt.Sprintf("vault %q is locked; run `cervus unlock --vault %s`", name, name)
	}
	return &out
}

const userRolePrefix = "user:"

// resolveRole finds a configured role, or the implicit role of a user: "user:<identity>" uses the
// identity itself, so a user can be switched to without defining a role. Colons are not allowed in
// role names, so the two cannot collide.
//
// The implicit role takes the strictest settings of that user's roles, so it is no way around a
// confirmation or a fresh MFA code. A user with an MFA device always uses it.
func resolveRole(name string, cfg *config.Config) (config.Role, bool) {
	if id, ok := strings.CutPrefix(name, userRolePrefix); ok {
		ident, ok := cfg.Identities[id]
		if !ok {
			return config.Role{}, false
		}
		r := config.Role{Identity: id, MFA: "none"}
		if ident.MFASerial != "" {
			r.MFA = "once"
		}
		for _, other := range cfg.Roles {
			if other.Identity != id {
				continue
			}
			r.Confirm = r.Confirm || other.Confirm
			if other.MFA == "always" {
				r.MFA = "always"
			}
		}
		return r, true
	}
	r, ok := cfg.Roles[name]
	return r, ok
}

func (a *app) vaultList(params json.RawMessage) (any, *apiErr) {
	type item struct {
		Name        string `json:"name"`
		Initialized bool   `json:"initialized"`
		Locked      bool   `json:"locked"`
		Dir         string `json:"dir"`
	}
	out := []item{}
	for _, name := range a.vaults.names() {
		data, e := a.vaultCall(name, "status", map[string]string{})
		if e != nil {
			return nil, e
		}
		it := item{Name: name}
		if err := json.Unmarshal(data, &it); err != nil {
			return nil, fe("internal", "bad vault reply")
		}
		it.Name = name
		out = append(out, it)
	}
	return map[string]any{"vaults": out}, nil
}

// identityMove carries a user's key and MFA seed to another vault. It removes the old copies only
// after the new ones and the config are saved, so a failure leaves a working user.
func (a *app) identityMove(params json.RawMessage) (any, *apiErr) {
	var p struct {
		ID    string `json:"id"`
		Vault string `json:"vault"`
	}
	if e := parse(params, &p); e != nil {
		return nil, e
	}
	target, e := normalizeVault(p.Vault)
	if e != nil {
		return nil, e
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	cfg, e := a.loadCfg()
	if e != nil {
		return nil, e
	}
	ident, ok := cfg.Identities[p.ID]
	if !ok {
		return nil, fe("not_found", "unknown identity %q", p.ID)
	}
	source, e := normalizeVault(ident.Vault)
	if e != nil {
		return nil, e
	}
	if source == target {
		return nil, fe("bad_request", "identity %q is already in vault %q", p.ID, target)
	}
	for _, v := range []string{source, target} {
		locked, e := a.vaultLocked(v)
		if e != nil {
			return nil, e
		}
		if locked {
			return nil, lockedMessage(&apiErr{Code: "locked", Message: "vault is locked; run `cervus unlock`"}, v)
		}
	}
	var moved []string
	for _, name := range []string{"aws-key." + p.ID, "mfa-seed." + p.ID} {
		data, e := a.vaultCall(source, "get", map[string]string{"name": name})
		if e != nil {
			if e.Code == "not_found" {
				continue
			}
			return nil, e
		}
		var s struct {
			Type  string `json:"type"`
			Scope string `json:"scope"`
			Value string `json:"value"`
		}
		if err := json.Unmarshal(data, &s); err != nil {
			return nil, fe("internal", "bad vault reply")
		}
		if _, e := a.vaultCall(target, "put", map[string]string{"name": name, "type": s.Type, "scope": s.Scope, "value": s.Value}); e != nil {
			return nil, e
		}
		moved = append(moved, name)
	}
	ident.Vault = target
	if target == defaultVault {
		ident.Vault = ""
	}
	cfg.Identities[p.ID] = ident
	if err := cfg.Save(a.cfgPath); err != nil {
		return nil, fe("internal", "%v", err)
	}
	a.forgetIdentity(p.ID, cfg)
	for _, name := range moved {
		if _, e := a.vaultCall(source, "delete", map[string]string{"name": name}); e != nil {
			return nil, fe(e.Code, "the user moved, but a copy of %s stays in vault %q: %s", name, source, e.Message)
		}
	}
	return map[string]any{"vault": target}, nil
}

// clearVaultCaches drops the cached credentials of one vault's users; the others are not affected.
func (a *app) clearVaultCaches(vault string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	cfg, e := a.loadCfg()
	if e != nil {
		a.clearCachesLocked()
		return
	}
	for id, ident := range cfg.Identities {
		if vaultDisplay(ident.Vault) == vault {
			a.forgetIdentity(id, cfg)
		}
	}
}

// takeSessionsOffUser ends shells on a user's implicit role when one of its roles gains a confirmation.
// Caller holds a.mu. It returns how many shells it affected.
func (a *app) takeSessionsOffUser(id string) int {
	delete(a.roleCache, userRolePrefix+id)
	removed := 0
	for s, r := range a.sessions {
		if r == userRolePrefix+id {
			delete(a.sessions, s)
			removed++
		}
	}
	return removed
}

// forgetIdentity drops everything cached for a user. Caller holds a.mu.
func (a *app) forgetIdentity(id string, cfg *config.Config) {
	delete(a.identTok, id)
	delete(a.roleCache, userRolePrefix+id)
	for n, r := range cfg.Roles {
		if r.Identity == id {
			delete(a.roleCache, n)
		}
	}
}
