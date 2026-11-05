package main

import (
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"cervus/internal/awsapi"
)

var mfaDeviceNameRe = regexp.MustCompile(`^[\w+=,.@-]{1,128}$`)

func (a *app) iam() *awsapi.IAM { return &awsapi.IAM{Endpoint: a.stsEndpoint, Now: a.now} }

// vaultTOTP returns the current code of a seed, without the reuse guard: enrolling needs the code of
// a new device, which nothing can have used.
func (a *app) vaultTOTP(vault, identity string) (code string, validFor int, e *apiErr) {
	data, e := a.vaultCall(vault, "totp", map[string]string{"name": "mfa-seed." + identity})
	if e != nil {
		return "", 0, e
	}
	var r struct {
		Code     string `json:"code"`
		ValidFor int    `json:"valid_for_secs"`
	}
	if err := json.Unmarshal(data, &r); err != nil || r.Code == "" {
		return "", 0, fe("internal", "bad vault reply")
	}
	return r.Code, r.ValidFor, nil
}

// identityMFASetup creates a virtual MFA device in AWS with the vault as its authenticator. The lock
// is not held across the wait for the second code, which takes up to 30 seconds. On any failure the
// device and the seed are removed again, so a failed attempt leaves nothing behind.
func (a *app) identityMFASetup(params json.RawMessage) (any, *apiErr) {
	var p struct {
		ID         string `json:"id"`
		DeviceName string `json:"device_name"`
		ShowSeed   bool   `json:"show_seed"`
	}
	if e := parse(params, &p); e != nil {
		return nil, e
	}
	device := p.DeviceName
	if device == "" {
		device = "cervus-" + p.ID
	}
	if !mfaDeviceNameRe.MatchString(device) {
		return nil, fe("bad_request", "invalid MFA device name %q", device)
	}
	a.mu.Lock()
	cfg, e := a.loadCfg()
	if e != nil {
		a.mu.Unlock()
		return nil, e
	}
	ident, ok := cfg.Identities[p.ID]
	a.mu.Unlock()
	if !ok {
		return nil, fe("not_found", "unknown identity %q", p.ID)
	}
	if e := notForSSO(ident, p.ID, "MFA device of its own"); e != nil {
		return nil, e
	}
	if ident.MFASerial != "" {
		return nil, fe("mfa_exists", "identity %q already has an MFA device: %s", p.ID, ident.MFASerial)
	}
	switch _, _, e := a.vaultTOTP(ident.Vault, p.ID); {
	case e == nil:
		return nil, fe("mfa_exists", "identity %q already has an MFA seed; set its serial with `cervus identity update %s --mfa-serial <arn>`", p.ID, p.ID)
	case e.Code != "not_found":
		return nil, e
	}
	base, e := a.longTermCreds(ident.Vault, p.ID)
	if e != nil {
		return nil, e
	}
	arn, _, err := a.stsFor(ident.Region).GetCallerIdentity(base)
	if err != nil {
		return nil, awsErr(err)
	}
	user := awsapi.UserNameFromARN(arn)
	if user == "" {
		return nil, fe("bad_request", "this works for IAM users only, not %s; set up MFA for it in the AWS console", arn)
	}
	iam := a.iam()
	serial, seed, err := iam.CreateVirtualMFADevice(base, device)
	if err != nil {
		return nil, mfaSetupErr(err)
	}
	undo := func() {
		_, _ = a.vaultCall(ident.Vault, "delete", map[string]string{"name": "mfa-seed." + p.ID})
		_ = iam.DeleteVirtualMFADevice(base, serial)
	}
	if e := a.vaultPut(ident.Vault, "mfa-seed."+p.ID, "mfa_seed", "local", []byte(seed)); e != nil {
		_ = iam.DeleteVirtualMFADevice(base, serial)
		return nil, e
	}
	code1, validFor, e := a.vaultTOTP(ident.Vault, p.ID)
	if e != nil {
		undo()
		return nil, e
	}
	code2 := code1
	for tries := 0; code2 == code1; tries++ {
		if tries > 40 {
			undo()
			return nil, fe("internal", "the MFA code did not change; is the system clock running?")
		}
		time.Sleep(mfaWait(validFor, tries))
		if code2, validFor, e = a.vaultTOTP(ident.Vault, p.ID); e != nil {
			undo()
			return nil, e
		}
	}
	if err := iam.EnableMFADevice(base, user, serial, code1, code2); err != nil {
		undo()
		return nil, mfaSetupErr(err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	cfg, e = a.loadCfg()
	if e != nil {
		return nil, fe("internal", "MFA is on in AWS as %s, but saving it failed: %s; set it with `cervus identity update %s --mfa-serial`", serial, e.Message, p.ID)
	}
	ident, ok = cfg.Identities[p.ID]
	if !ok {
		return nil, fe("not_found", "identity %q was removed while MFA was being set up; device %s stays in AWS", p.ID, serial)
	}
	ident.MFASerial = serial
	cfg.Identities[p.ID] = ident
	if err := cfg.Save(a.cfgPath); err != nil {
		return nil, fe("internal", "MFA is on in AWS as %s, but saving it failed: %v; set it with `cervus identity update %s --mfa-serial`", serial, err, p.ID)
	}
	delete(a.identTok, p.ID)
	a.lastCode[p.ID] = code2 // AWS has just seen it, and refuses a code twice
	out := map[string]any{"mfa_serial": serial, "user": user}
	if p.ShowSeed {
		out["seed"] = seed
	}
	return out, nil
}

// mfaWait waits for the code to change: the time left the first time, then short steps in case the
// clock moved.
func mfaWait(validFor, tries int) time.Duration {
	if tries == 0 && validFor > 0 {
		return time.Duration(validFor) * time.Second
	}
	return time.Second
}

func mfaSetupErr(err error) *apiErr {
	var ae *awsapi.APIError
	if errors.As(err, &ae) && ae.Code == "AccessDenied" {
		return fe("aws_error", "%s. This user needs iam:CreateVirtualMFADevice, iam:EnableMFADevice and iam:DeleteVirtualMFADevice", ae.Error())
	}
	return awsErr(err)
}
