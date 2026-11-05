package main

import (
	"encoding/json"
	"errors"
	"time"

	"cervus/internal/awsapi"
	"cervus/internal/config"
)

// A sign-in token stays on this device, like an MFA seed: it is short-lived and easy to get again.
const ssoTokenPrefix = "sso-token."

type ssoToken struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

type ssoPending struct {
	client    awsapi.SSOClient
	device    string
	expiresAt time.Time
}

func (a *app) ssoFor(region string) *awsapi.SSO {
	return &awsapi.SSO{Region: region, Endpoint: a.stsEndpoint}
}

func ssoLoginNeeded(id string) *apiErr {
	return fe("sso_login_needed", "the SSO sign-in of %q has ended; run `cervus sso login %s`", id, id)
}

func notForSSO(ident config.Identity, id, what string) *apiErr {
	if ident.SSO != nil {
		return fe("bad_request", "%q signs in through SSO, so it has no %s", id, what)
	}
	return nil
}

func (a *app) identityAddSSO(params json.RawMessage) (any, *apiErr) {
	var p struct {
		ID        string `json:"id"`
		StartURL  string `json:"start_url"`
		SSORegion string `json:"sso_region"`
		Account   string `json:"account"`
		RoleName  string `json:"role_name"`
		Region    string `json:"region"`
		Vault     string `json:"vault"`
	}
	if e := parse(params, &p); e != nil {
		return nil, e
	}
	vault, e := normalizeVault(p.Vault)
	if e != nil {
		return nil, e
	}
	if !a.vaults.exists(vault) {
		return nil, fe("not_found", "no vault named %q; create it with `cervus vault create %s`", vault, vault)
	}
	ident := config.Identity{Region: p.Region, SSO: &config.SSO{
		StartURL: p.StartURL, Region: p.SSORegion, Account: p.Account, RoleName: p.RoleName,
	}}
	if vault != defaultVault {
		ident.Vault = vault
	}
	if err := ident.Validate(p.ID); err != nil {
		return nil, fe("bad_request", "%v", err)
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
	cfg.Identities[p.ID] = ident
	if err := cfg.Save(a.cfgPath); err != nil {
		return nil, fe("internal", "%v", err)
	}
	return map[string]any{}, nil
}

func (a *app) ssoIdentity(id string) (config.Identity, *apiErr) {
	a.mu.Lock()
	defer a.mu.Unlock()
	cfg, e := a.loadCfg()
	if e != nil {
		return config.Identity{}, e
	}
	ident, ok := cfg.Identities[id]
	if !ok {
		return config.Identity{}, fe("not_found", "unknown identity %q", id)
	}
	if ident.SSO == nil {
		return config.Identity{}, fe("bad_request", "%q is not an SSO identity", id)
	}
	return ident, nil
}

// identitySSOStart begins a sign-in. Everything needed to finish it stays in the daemon.
func (a *app) identitySSOStart(params json.RawMessage) (any, *apiErr) {
	var p struct {
		ID string `json:"id"`
	}
	if e := parse(params, &p); e != nil {
		return nil, e
	}
	ident, e := a.ssoIdentity(p.ID)
	if e != nil {
		return nil, e
	}
	if locked, e := a.vaultLocked(ident.Vault); e != nil {
		return nil, e
	} else if locked {
		return nil, lockedMessage(fe("locked", "the vault is locked; run `cervus unlock`"), vaultDisplay(ident.Vault))
	}
	sso := a.ssoFor(ident.SSO.Region)
	client, err := sso.RegisterClient()
	if err != nil {
		return nil, awsErr(err)
	}
	device, err := sso.StartDeviceAuthorization(client, ident.SSO.StartURL)
	if err != nil {
		return nil, awsErr(err)
	}
	a.mu.Lock()
	a.ssoLogins[p.ID] = ssoPending{client, device.DeviceCode, a.now().Add(time.Duration(device.ExpiresIn) * time.Second)}
	a.mu.Unlock()
	return map[string]any{
		"verification_uri": device.VerificationURI, "user_code": device.UserCode,
		"interval": device.Interval, "expires_in": device.ExpiresIn,
	}, nil
}

// identitySSOPoll asks whether the person has approved the sign-in, and stores the token when they have.
func (a *app) identitySSOPoll(params json.RawMessage) (any, *apiErr) {
	var p struct {
		ID string `json:"id"`
	}
	if e := parse(params, &p); e != nil {
		return nil, e
	}
	ident, e := a.ssoIdentity(p.ID)
	if e != nil {
		return nil, e
	}
	a.mu.Lock()
	login, ok := a.ssoLogins[p.ID]
	a.mu.Unlock()
	if !ok {
		return nil, fe("bad_request", "no sign-in is waiting for %q", p.ID)
	}
	if a.now().After(login.expiresAt) {
		a.endSSOLogin(p.ID)
		return nil, fe("sso_login_expired", "the sign-in was not approved in time; run `cervus sso login %s` again", p.ID)
	}
	token, expiresIn, err := a.ssoFor(ident.SSO.Region).CreateToken(login.client, login.device)
	switch {
	case errors.Is(err, awsapi.ErrSSOPending):
		return map[string]any{"status": "pending"}, nil
	case errors.Is(err, awsapi.ErrSSOSlowDown):
		return map[string]any{"status": "slow_down"}, nil
	case err != nil:
		a.endSSOLogin(p.ID)
		return nil, awsErr(err)
	}
	blob, _ := json.Marshal(ssoToken{token, a.now().Add(time.Duration(expiresIn) * time.Second)})
	if e := a.vaultPut(ident.Vault, ssoTokenPrefix+p.ID, "sso_token", "local", blob); e != nil {
		return nil, e
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.ssoLogins, p.ID)
	cfg, e := a.loadCfg()
	if e != nil {
		return nil, e
	}
	a.forgetIdentity(p.ID, cfg)
	a.audit.Append("identity.sso_login", map[string]any{"id": p.ID})
	return map[string]any{"status": "done", "expires_in": expiresIn}, nil
}

func (a *app) endSSOLogin(id string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.ssoLogins, id)
}

// ssoBase returns short-lived credentials of an SSO identity's own account and role, cached until they
// are nearly expired. Caller holds a.mu.
func (a *app) ssoBase(id string, ident config.Identity) (awsapi.Credentials, *apiErr) {
	if c, ok := a.ssoCreds[id]; ok && fresh(c, a.now()) {
		return c, nil
	}
	raw, e := a.vaultGet(ident.Vault, ssoTokenPrefix+id)
	if e != nil {
		if e.Code == "not_found" {
			return awsapi.Credentials{}, ssoLoginNeeded(id)
		}
		return awsapi.Credentials{}, e
	}
	var t ssoToken
	if err := json.Unmarshal(raw, &t); err != nil || t.Token == "" {
		return awsapi.Credentials{}, fe("internal", "stored SSO token of %q is corrupt", id)
	}
	if !t.ExpiresAt.After(a.now()) {
		return awsapi.Credentials{}, ssoLoginNeeded(id)
	}
	c, err := a.ssoFor(ident.SSO.Region).RoleCredentials(t.Token, ident.SSO.Account, ident.SSO.RoleName)
	if errors.Is(err, awsapi.ErrSSOLoginNeeded) {
		return awsapi.Credentials{}, ssoLoginNeeded(id)
	}
	if err != nil {
		return awsapi.Credentials{}, awsErr(err)
	}
	a.ssoCreds[id] = c
	return c, nil
}
