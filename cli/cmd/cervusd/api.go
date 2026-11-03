package main

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"cervus/internal/awsapi"
	"cervus/internal/config"
	"cervus/internal/vaultproc"
)

type apiErr = vaultproc.RemoteError

func fe(code, format string, args ...any) *apiErr {
	return &apiErr{Code: code, Message: fmt.Sprintf(format, args...)}
}

const (
	refreshMargin     = 5 * time.Minute
	defaultDuration   = time.Hour
	identityTokenSpan = 12 * time.Hour
)

var sessionRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
var seedRe = regexp.MustCompile(`^[A-Za-z2-7]{16,128}$`)

// app holds daemon state: sessions (shell -> role) and in-memory credential caches.
// Credentials are never written to disk.
type app struct {
	vault       *vaultproc.Supervisor
	cfgPath     string
	stsEndpoint string
	now         func() time.Time
	audit       *auditLog

	mu        sync.Mutex
	sessions  map[string]string
	pids      map[string]int // session -> shell PID, for cleanup
	roleCache map[string]awsapi.Credentials
	identTok  map[string]awsapi.Credentials
	lastCode  map[string]string
}

func newApp(v *vaultproc.Supervisor, cfgPath, stsEndpoint string) *app {
	return &app{
		vault: v, cfgPath: cfgPath, stsEndpoint: stsEndpoint, now: time.Now,
		sessions:  map[string]string{},
		pids:      map[string]int{},
		roleCache: map[string]awsapi.Credentials{},
		identTok:  map[string]awsapi.Credentials{},
		lastCode:  map[string]string{},
	}
}

// clearCaches drops all cached credentials (called when the vault is locked on request).
func (a *app) clearCaches() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.roleCache = map[string]awsapi.Credentials{}
	a.identTok = map[string]awsapi.Credentials{}
	a.lastCode = map[string]string{}
}

type handler func(a *app, params json.RawMessage) (any, *apiErr)

var apiHandlers = map[string]handler{
	"identity.add":        (*app).identityAdd,
	"identity.list":       (*app).identityList,
	"identity.update":     (*app).identityUpdate,
	"identity.remove":     (*app).identityRemove,
	"identity.verify_key": (*app).identityVerifyKey,
	"identity.mfa_import": (*app).identityMFAImport,
	"role.add":            (*app).roleAdd,
	"role.list":           (*app).roleList,
	"role.edit":           (*app).roleEdit,
	"role.remove":         (*app).roleRemove,
	"use":                 (*app).use,
	"credentials":         (*app).credentials,
	"whoami":              (*app).whoami,
	"session.register":    (*app).sessionRegister,
	"audit.tail":          (*app).auditTail,
	"audit.verify":        (*app).auditVerify,
}

func (a *app) auditTail(params json.RawMessage) (any, *apiErr) {
	var p struct {
		N int `json:"n"`
	}
	if e := parse(params, &p); e != nil {
		return nil, e
	}
	if a.audit == nil {
		return map[string]any{"lines": []string{}}, nil
	}
	list, err := a.audit.Tail(p.N)
	if err != nil {
		return nil, fe("internal", "%v", err)
	}
	lines := make([]string, 0, len(list))
	for _, e := range list {
		lines = append(lines, formatEntry(e))
	}
	return map[string]any{"lines": lines}, nil
}

func (a *app) auditVerify(params json.RawMessage) (any, *apiErr) {
	if a.audit == nil {
		return map[string]any{"entries": 0, "bad_line": 0}, nil
	}
	n, bad, err := a.audit.Verify()
	if err != nil {
		return nil, fe("internal", "%v", err)
	}
	return map[string]any{"entries": n, "bad_line": bad}, nil
}

func pidAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

// gcSessions forgets shells whose process has exited.
func (a *app) gcSessions() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for s, pid := range a.pids {
		if !pidAlive(pid) {
			delete(a.pids, s)
			delete(a.sessions, s)
		}
	}
}

func (a *app) sessionRegister(params json.RawMessage) (any, *apiErr) {
	var p struct {
		Session string `json:"session"`
		PID     int    `json:"pid"`
	}
	if e := parse(params, &p); e != nil {
		return nil, e
	}
	if !sessionRe.MatchString(p.Session) || p.PID <= 1 {
		return nil, fe("bad_request", "invalid session or pid")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pids[p.Session] = p.PID
	return map[string]any{}, nil
}

// ---- vault helpers ----

func (a *app) vaultCall(op string, params any) (json.RawMessage, *apiErr) {
	raw, err := json.Marshal(params)
	if err != nil {
		return nil, fe("internal", "%v", err)
	}
	data, rerr, err := a.vault.Call(op, raw)
	switch {
	case errors.Is(err, vaultproc.ErrUnavailable):
		return nil, fe("internal", "vault process crashed and was reset; it is locked, try again")
	case err != nil:
		return nil, fe("internal", "%v", err)
	case rerr != nil:
		return nil, rerr
	}
	return data, nil
}

func (a *app) vaultPut(name, typ, scope string, value []byte) *apiErr {
	_, e := a.vaultCall("put", map[string]string{
		"name": name, "type": typ, "scope": scope,
		"value": base64.StdEncoding.EncodeToString(value),
	})
	return e
}

func (a *app) vaultGet(name string) ([]byte, *apiErr) {
	data, e := a.vaultCall("get", map[string]string{"name": name})
	if e != nil {
		return nil, e
	}
	var r struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fe("internal", "bad vault reply")
	}
	b, err := base64.StdEncoding.DecodeString(r.Value)
	if err != nil {
		return nil, fe("internal", "bad vault reply")
	}
	return b, nil
}

type accessKey struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
}

func (a *app) longTermCreds(identity string) (awsapi.Credentials, *apiErr) {
	raw, e := a.vaultGet("aws-key." + identity)
	if e != nil {
		if e.Code == "not_found" {
			return awsapi.Credentials{}, fe("not_found", "no access key stored for identity %q", identity)
		}
		return awsapi.Credentials{}, e
	}
	var k accessKey
	if err := json.Unmarshal(raw, &k); err != nil || k.AccessKeyID == "" {
		return awsapi.Credentials{}, fe("internal", "stored access key for %q is corrupt", identity)
	}
	return awsapi.Credentials{AccessKeyID: k.AccessKeyID, SecretAccessKey: k.SecretAccessKey}, nil
}

// totpCode returns a fresh MFA code, refusing to reuse a code AWS has probably already seen.
func (a *app) totpCode(identity string) (string, *apiErr) {
	data, e := a.vaultCall("totp", map[string]string{"name": "mfa-seed." + identity})
	if e != nil {
		if e.Code == "not_found" {
			return "", fe("mfa_not_configured", "no MFA seed for identity %q; run `cervus identity mfa-import %s`", identity, identity)
		}
		return "", e
	}
	var r struct {
		Code     string `json:"code"`
		ValidFor int    `json:"valid_for_secs"`
	}
	if err := json.Unmarshal(data, &r); err != nil || r.Code == "" {
		return "", fe("internal", "bad vault reply")
	}
	if a.lastCode[identity] == r.Code {
		return "", fe("mfa_code_reused", "the current MFA code was already used; wait %d seconds and retry", r.ValidFor)
	}
	a.lastCode[identity] = r.Code
	return r.Code, nil
}

func awsErr(err error) *apiErr {
	var ae *awsapi.APIError
	if errors.As(err, &ae) {
		return fe("aws_error", "%s", ae.Error())
	}
	return fe("network", "%v", err)
}

func (a *app) stsFor(region string) *awsapi.STS {
	if region == "" {
		region = "us-east-1"
	}
	return &awsapi.STS{Region: region, Endpoint: a.stsEndpoint, Now: a.now}
}

func fresh(c awsapi.Credentials, now time.Time) bool {
	return !c.Expiration.IsZero() && c.Expiration.Sub(now) > refreshMargin
}

// ---- credential resolution ----

// identitySession returns an MFA-backed session token for an identity (cached, used by mfa=once).
func (a *app) identitySession(name string, ident config.Identity, base awsapi.Credentials) (awsapi.Credentials, *apiErr) {
	if c, ok := a.identTok[name]; ok && fresh(c, a.now()) {
		return c, nil
	}
	if ident.MFASerial == "" {
		return awsapi.Credentials{}, fe("mfa_not_configured", "identity %q has no MFA serial", name)
	}
	code, e := a.totpCode(name)
	if e != nil {
		return awsapi.Credentials{}, e
	}
	c, err := a.stsFor(ident.Region).GetSessionToken(base, identityTokenSpan, ident.MFASerial, code)
	if err != nil {
		return awsapi.Credentials{}, awsErr(err)
	}
	a.identTok[name] = c
	return c, nil
}

// getCreds returns valid credentials for a role, refreshing them if needed. Caller holds a.mu.
func (a *app) getCreds(roleName string, cfg *config.Config) (awsapi.Credentials, *apiErr) {
	role, ok := cfg.Roles[roleName]
	if !ok {
		return awsapi.Credentials{}, fe("not_found", "unknown role %q", roleName)
	}
	if c, ok := a.roleCache[roleName]; ok && fresh(c, a.now()) {
		return c, nil
	}
	ident := cfg.Identities[role.Identity]
	region := role.Region
	if region == "" {
		region = ident.Region
	}
	sts := a.stsFor(region)
	dur := time.Duration(role.DurationSecs) * time.Second
	if dur == 0 {
		dur = defaultDuration
	}

	base, e := a.longTermCreds(role.Identity)
	if e != nil {
		return awsapi.Credentials{}, e
	}

	var creds awsapi.Credentials
	var err error
	switch {
	case role.ARN == "" && role.MFA == "once":
		c, e := a.identitySession(role.Identity, ident, base)
		if e != nil {
			return awsapi.Credentials{}, e
		}
		creds = c
	case role.ARN == "":
		serial, code := "", ""
		if role.MFA == "always" {
			if code, e = a.totpCode(role.Identity); e != nil {
				return awsapi.Credentials{}, e
			}
			serial = ident.MFASerial
		}
		creds, err = sts.GetSessionToken(base, dur, serial, code)
	default:
		src, serial, code := base, "", ""
		switch role.MFA {
		case "once":
			if src, e = a.identitySession(role.Identity, ident, base); e != nil {
				return awsapi.Credentials{}, e
			}
		case "always":
			if code, e = a.totpCode(role.Identity); e != nil {
				return awsapi.Credentials{}, e
			}
			serial = ident.MFASerial
		}
		creds, err = sts.AssumeRole(src, role.ARN, "cervus-"+roleName, dur, serial, code)
	}
	if err != nil {
		return awsapi.Credentials{}, awsErr(err)
	}
	a.roleCache[roleName] = creds
	a.audit.Append("credentials.issued", map[string]any{
		"role": roleName, "identity": role.Identity, "mfa": role.MFA,
		"expires_at": creds.Expiration.UTC().Format(time.RFC3339),
	})
	return creds, nil
}

// ---- handlers ----

func (a *app) loadCfg() (*config.Config, *apiErr) {
	c, err := config.Load(a.cfgPath)
	if err != nil {
		return nil, fe("internal", "%v", err)
	}
	return c, nil
}

func parse(params json.RawMessage, v any) *apiErr {
	if len(params) == 0 {
		params = []byte("{}")
	}
	if err := json.Unmarshal(params, v); err != nil {
		return fe("bad_request", "invalid parameters: %v", err)
	}
	return nil
}

func (a *app) identityAdd(params json.RawMessage) (any, *apiErr) {
	var p struct {
		ID              string `json:"id"`
		Region          string `json:"region"`
		MFASerial       string `json:"mfa_serial"`
		AccessKeyID     string `json:"access_key_id"`
		SecretAccessKey string `json:"secret_access_key"`
		Verify          *bool  `json:"verify"`
	}
	if e := parse(params, &p); e != nil {
		return nil, e
	}
	ident := config.Identity{Region: p.Region, MFASerial: p.MFASerial}
	if err := ident.Validate(p.ID); err != nil {
		return nil, fe("bad_request", "%v", err)
	}
	if p.AccessKeyID == "" || p.SecretAccessKey == "" {
		return nil, fe("bad_request", "access key id and secret are required")
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	cfg, e := a.loadCfg()
	if e != nil {
		return nil, e
	}
	if _, exists := cfg.Identities[p.ID]; exists {
		return nil, fe("bad_request", "identity %q already exists", p.ID)
	}

	creds := awsapi.Credentials{AccessKeyID: p.AccessKeyID, SecretAccessKey: p.SecretAccessKey}
	res := map[string]string{}
	if p.Verify == nil || *p.Verify {
		arn, account, err := a.stsFor(p.Region).GetCallerIdentity(creds)
		if err != nil {
			return nil, awsErr(err)
		}
		res["arn"], res["account"] = arn, account
	}
	blob, _ := json.Marshal(accessKey{AccessKeyID: p.AccessKeyID, SecretAccessKey: p.SecretAccessKey})
	if e := a.vaultPut("aws-key."+p.ID, "aws_access_key", "synced", blob); e != nil {
		return nil, e
	}
	cfg.Identities[p.ID] = ident
	if err := cfg.Save(a.cfgPath); err != nil {
		return nil, fe("internal", "%v", err)
	}
	return res, nil
}

func (a *app) identityList(params json.RawMessage) (any, *apiErr) {
	cfg, e := a.loadCfg()
	if e != nil {
		return nil, e
	}
	type item struct {
		Name      string `json:"name"`
		Region    string `json:"region,omitempty"`
		MFASerial string `json:"mfa_serial,omitempty"`
	}
	var out []item
	for n, i := range cfg.Identities {
		out = append(out, item{n, i.Region, i.MFASerial})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return map[string]any{"identities": out}, nil
}

// identityUpdate changes an identity in place, so rotating a key does not mean deleting its roles
// and MFA seed. A new key is checked with AWS before it replaces the old one.
func (a *app) identityUpdate(params json.RawMessage) (any, *apiErr) {
	var p struct {
		ID              string  `json:"id"`
		Region          *string `json:"region"`
		MFASerial       *string `json:"mfa_serial"`
		Rotate          bool    `json:"rotate"`
		AccessKeyID     string  `json:"access_key_id"`
		SecretAccessKey string  `json:"secret_access_key"`
		Verify          *bool   `json:"verify"`

		AllowDifferentPrincipal bool `json:"allow_different_principal"`
	}
	if e := parse(params, &p); e != nil {
		return nil, e
	}
	if !p.Rotate && p.Region == nil && p.MFASerial == nil {
		return nil, fe("bad_request", "nothing to change; use --rotate-key, --region or --mfa-serial")
	}
	if p.Rotate != (p.AccessKeyID != "" && p.SecretAccessKey != "") {
		return nil, fe("bad_request", "rotating a key needs both the access key id and the secret")
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
	if p.Region != nil {
		ident.Region = *p.Region
	}
	if p.MFASerial != nil {
		ident.MFASerial = *p.MFASerial
	}
	if err := ident.Validate(p.ID); err != nil {
		return nil, fe("bad_request", "%v", err)
	}
	if ident.MFASerial == "" {
		for n, r := range cfg.Roles {
			if r.Identity == p.ID && r.MFA != "none" {
				return nil, fe("bad_request", "role %q needs MFA; change it first with `cervus role edit`", n)
			}
		}
	}

	res := map[string]string{}
	verified := p.Rotate && (p.Verify == nil || *p.Verify)
	if p.Rotate {
		locked, e := a.vaultLocked()
		if e != nil {
			return nil, e
		}
		if locked {
			return nil, fe("locked", "vault is locked; run `cervus unlock`")
		}
	}
	if verified {
		creds := awsapi.Credentials{AccessKeyID: p.AccessKeyID, SecretAccessKey: p.SecretAccessKey}
		arn, account, err := a.stsFor(ident.Region).GetCallerIdentity(creds)
		if err != nil {
			return nil, awsErr(err)
		}
		res["arn"], res["account"] = arn, account
		old, e := a.longTermCreds(p.ID)
		if e != nil && e.Code != "not_found" {
			return nil, e
		}
		if e == nil {
			oldArn, _, err := a.stsFor(ident.Region).GetCallerIdentity(old)
			switch {
			case err != nil:
				res["old_key_unverified"] = "true" // usually a key that is already revoked
			case oldArn != arn && !p.AllowDifferentPrincipal:
				return nil, fe("principal_changed", "the new key belongs to %s but the old one to %s; to accept that, re-run with --allow-different-principal", arn, oldArn)
			case oldArn != arn:
				res["previous_arn"] = oldArn
			}
		}
	}
	// Settings go first: if they cannot be saved the old key is still there, and a saved region
	// without a new key does no harm.
	cfg.Identities[p.ID] = ident
	if err := cfg.Save(a.cfgPath); err != nil {
		return nil, fe("internal", "%v", err)
	}
	delete(a.identTok, p.ID)
	for n, r := range cfg.Roles {
		if r.Identity == p.ID {
			delete(a.roleCache, n)
		}
	}
	if p.Rotate {
		blob, _ := json.Marshal(accessKey{AccessKeyID: p.AccessKeyID, SecretAccessKey: p.SecretAccessKey})
		if e := a.vaultPut("aws-key."+p.ID, "aws_access_key", "synced", blob); e != nil {
			return nil, fe(e.Code, "the settings were saved but the key was not replaced: %s", e.Message)
		}
		event := map[string]any{"id": p.ID, "verified": verified}
		if arn, ok := res["arn"]; ok {
			event["arn"] = arn
		}
		if prev, ok := res["previous_arn"]; ok {
			event["previous_arn"] = prev
		}
		a.audit.Append("identity.key_replaced", event)
	}
	return res, nil
}

func (a *app) vaultLocked() (bool, *apiErr) {
	data, e := a.vaultCall("status", map[string]string{})
	if e != nil {
		return false, e
	}
	var st struct {
		Locked bool `json:"locked"`
	}
	if err := json.Unmarshal(data, &st); err != nil {
		return false, fe("internal", "bad vault reply")
	}
	return st.Locked, nil
}

// identityVerifyKey tells a caller that already holds a key whether the vault stored the same one,
// so `cervus migrate` can safely delete the plaintext. It only ever answers yes or no.
func (a *app) identityVerifyKey(params json.RawMessage) (any, *apiErr) {
	var p struct {
		ID              string `json:"id"`
		AccessKeyID     string `json:"access_key_id"`
		SecretAccessKey string `json:"secret_access_key"`
	}
	if e := parse(params, &p); e != nil {
		return nil, e
	}
	stored, e := a.longTermCreds(p.ID)
	if e != nil {
		return nil, e
	}
	idOK := subtle.ConstantTimeCompare([]byte(stored.AccessKeyID), []byte(p.AccessKeyID))
	secretOK := subtle.ConstantTimeCompare([]byte(stored.SecretAccessKey), []byte(p.SecretAccessKey))
	return map[string]any{"match": idOK&secretOK == 1}, nil
}

func (a *app) identityMFAImport(params json.RawMessage) (any, *apiErr) {
	var p struct {
		ID   string `json:"id"`
		Seed string `json:"seed"`
	}
	if e := parse(params, &p); e != nil {
		return nil, e
	}
	seed := strings.ToUpper(strings.NewReplacer(" ", "", "=", "").Replace(p.Seed))
	if !seedRe.MatchString(seed) {
		return nil, fe("bad_request", "MFA seed must be a base32 string (letters A-Z and digits 2-7)")
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
	if e := a.vaultPut("mfa-seed."+p.ID, "mfa_seed", "local", []byte(seed)); e != nil {
		return nil, e
	}
	delete(a.identTok, p.ID)
	delete(a.lastCode, p.ID)
	return map[string]any{"mfa_serial_configured": ident.MFASerial != ""}, nil
}

func (a *app) identityRemove(params json.RawMessage) (any, *apiErr) {
	var p struct {
		ID string `json:"id"`
	}
	if e := parse(params, &p); e != nil {
		return nil, e
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	cfg, e := a.loadCfg()
	if e != nil {
		return nil, e
	}
	if _, ok := cfg.Identities[p.ID]; !ok {
		return nil, fe("not_found", "unknown identity %q", p.ID)
	}
	for n, r := range cfg.Roles {
		if r.Identity == p.ID {
			return nil, fe("bad_request", "role %q still uses identity %q; remove it first", n, p.ID)
		}
	}
	for _, name := range []string{"aws-key." + p.ID, "mfa-seed." + p.ID} {
		if _, e := a.vaultCall("delete", map[string]string{"name": name}); e != nil && e.Code != "not_found" {
			return nil, e
		}
	}
	delete(cfg.Identities, p.ID)
	delete(a.identTok, p.ID)
	delete(a.lastCode, p.ID)
	if err := cfg.Save(a.cfgPath); err != nil {
		return nil, fe("internal", "%v", err)
	}
	return map[string]any{}, nil
}

func (a *app) roleAdd(params json.RawMessage) (any, *apiErr) {
	var p struct {
		Name         string `json:"name"`
		Identity     string `json:"identity"`
		ARN          string `json:"arn"`
		Region       string `json:"region"`
		MFA          string `json:"mfa"`
		Confirm      bool   `json:"confirm"`
		DurationSecs int    `json:"duration_secs"`
	}
	if e := parse(params, &p); e != nil {
		return nil, e
	}
	if p.MFA == "" {
		p.MFA = "none"
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	cfg, e := a.loadCfg()
	if e != nil {
		return nil, e
	}
	if _, exists := cfg.Roles[p.Name]; exists {
		return nil, fe("bad_request", "role %q already exists", p.Name)
	}
	r := config.Role{Identity: p.Identity, ARN: p.ARN, Region: p.Region, MFA: p.MFA, Confirm: p.Confirm, DurationSecs: p.DurationSecs}
	if err := r.Validate(p.Name, cfg); err != nil {
		return nil, fe("bad_request", "%v", err)
	}
	cfg.Roles[p.Name] = r
	if err := cfg.Save(a.cfgPath); err != nil {
		return nil, fe("internal", "%v", err)
	}
	return map[string]any{}, nil
}

// roleEdit changes only the fields it is given. A change of target or a new confirmation takes
// active shells off the role, so a terminal labelled with this role cannot silently start acting
// on another one or skip the confirmation. Other changes keep them on it with fresh credentials.
func (a *app) roleEdit(params json.RawMessage) (any, *apiErr) {
	var p struct {
		Name         string  `json:"name"`
		Identity     *string `json:"identity"`
		ARN          *string `json:"arn"`
		Region       *string `json:"region"`
		MFA          *string `json:"mfa"`
		Confirm      *bool   `json:"confirm"`
		DurationSecs *int    `json:"duration_secs"`
	}
	if e := parse(params, &p); e != nil {
		return nil, e
	}
	if p.Identity == nil && p.ARN == nil && p.Region == nil && p.MFA == nil && p.Confirm == nil && p.DurationSecs == nil {
		return nil, fe("bad_request", "nothing to change; see `cervus help`")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	cfg, e := a.loadCfg()
	if e != nil {
		return nil, e
	}
	r, ok := cfg.Roles[p.Name]
	if !ok {
		return nil, fe("not_found", "unknown role %q", p.Name)
	}
	old := r
	if p.Identity != nil {
		r.Identity = *p.Identity
	}
	if p.ARN != nil {
		r.ARN = *p.ARN
	}
	if p.Region != nil {
		r.Region = *p.Region
	}
	if p.MFA != nil {
		r.MFA = *p.MFA
	}
	if p.Confirm != nil {
		r.Confirm = *p.Confirm
	}
	if p.DurationSecs != nil {
		r.DurationSecs = *p.DurationSecs
	}
	if err := r.Validate(p.Name, cfg); err != nil {
		return nil, fe("bad_request", "%v", err)
	}
	cfg.Roles[p.Name] = r
	if err := cfg.Save(a.cfgPath); err != nil {
		return nil, fe("internal", "%v", err)
	}
	delete(a.roleCache, p.Name)
	removed := 0
	if r.Identity != old.Identity || r.ARN != old.ARN || (r.Confirm && !old.Confirm) {
		for s, role := range a.sessions {
			if role == p.Name {
				delete(a.sessions, s)
				removed++
			}
		}
	}
	return map[string]any{"shells_removed": removed}, nil
}

func (a *app) roleList(params json.RawMessage) (any, *apiErr) {
	cfg, e := a.loadCfg()
	if e != nil {
		return nil, e
	}
	type item struct {
		Name string `json:"name"`
		config.Role
	}
	var out []item
	for n, r := range cfg.Roles {
		out = append(out, item{n, r})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return map[string]any{"roles": out}, nil
}

func (a *app) roleRemove(params json.RawMessage) (any, *apiErr) {
	var p struct {
		Name string `json:"name"`
	}
	if e := parse(params, &p); e != nil {
		return nil, e
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	cfg, e := a.loadCfg()
	if e != nil {
		return nil, e
	}
	if _, ok := cfg.Roles[p.Name]; !ok {
		return nil, fe("not_found", "unknown role %q", p.Name)
	}
	delete(cfg.Roles, p.Name)
	delete(a.roleCache, p.Name)
	for s, r := range a.sessions {
		if r == p.Name {
			delete(a.sessions, s)
		}
	}
	if err := cfg.Save(a.cfgPath); err != nil {
		return nil, fe("internal", "%v", err)
	}
	return map[string]any{}, nil
}

func (a *app) use(params json.RawMessage) (any, *apiErr) {
	var p struct {
		Session   string `json:"session"`
		Role      string `json:"role"`
		Confirmed bool   `json:"confirmed"`
		PID       int    `json:"pid"` // optional: the shell, in case it never registered
	}
	if e := parse(params, &p); e != nil {
		return nil, e
	}
	if !sessionRe.MatchString(p.Session) {
		return nil, fe("bad_request", "invalid session id")
	}
	if p.PID != 0 && p.PID <= 1 {
		return nil, fe("bad_request", "invalid pid")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	cfg, e := a.loadCfg()
	if e != nil {
		return nil, e
	}
	role, ok := cfg.Roles[p.Role]
	if !ok {
		return nil, fe("not_found", "unknown role %q (see `cervus role list`)", p.Role)
	}
	if role.Confirm && !p.Confirmed {
		return nil, fe("confirm_required", "role %q requires confirmation", p.Role)
	}
	creds, e := a.getCreds(p.Role, cfg)
	if e != nil {
		return nil, e
	}
	a.sessions[p.Session] = p.Role
	if p.PID != 0 {
		a.pids[p.Session] = p.PID
	}
	return map[string]any{"role": p.Role, "expires_at": creds.Expiration.UTC().Format(time.RFC3339)}, nil
}

func (a *app) credentials(params json.RawMessage) (any, *apiErr) {
	var p struct {
		Session string `json:"session"`
	}
	if e := parse(params, &p); e != nil {
		return nil, e
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	role := a.sessions[p.Session]
	if role == "" {
		return nil, fe("no_role", "no role selected in this shell; run `cervus use <role>`")
	}
	cfg, e := a.loadCfg()
	if e != nil {
		return nil, e
	}
	c, e := a.getCreds(role, cfg)
	if e != nil {
		return nil, e
	}
	// Shape expected by the AWS CLI's credential_process.
	return map[string]any{
		"Version":         1,
		"AccessKeyId":     c.AccessKeyID,
		"SecretAccessKey": c.SecretAccessKey,
		"SessionToken":    c.SessionToken,
		"Expiration":      c.Expiration.UTC().Format("2006-01-02T15:04:05Z"),
	}, nil
}

func (a *app) whoami(params json.RawMessage) (any, *apiErr) {
	var p struct {
		Session string `json:"session"`
	}
	if e := parse(params, &p); e != nil {
		return nil, e
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	role := a.sessions[p.Session]
	out := map[string]any{"role": role}
	if cfg, e := a.loadCfg(); e == nil {
		out["protected"] = cfg.Roles[role].Confirm
	}
	if c, ok := a.roleCache[role]; ok {
		out["expires_at"] = c.Expiration.UTC().Format(time.RFC3339)
		out["seconds_left"] = int(c.Expiration.Sub(a.now()).Seconds())
	}
	return out, nil
}
