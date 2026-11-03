// Package config stores non-secret Cervus settings: identities and roles.
// Secrets (access keys, MFA seeds) live only in the vault.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

type Identity struct {
	Region    string `json:"region,omitempty"`
	MFASerial string `json:"mfa_serial,omitempty"`
}

type Role struct {
	Identity     string `json:"identity"`
	ARN          string `json:"arn,omitempty"` // empty: use the identity itself (session token)
	Region       string `json:"region,omitempty"`
	MFA          string `json:"mfa"` // none | once | always
	Confirm      bool   `json:"confirm,omitempty"`
	DurationSecs int    `json:"duration_secs,omitempty"`
}

type Config struct {
	Version    int                 `json:"version"`
	Identities map[string]Identity `json:"identities"`
	Roles      map[string]Role     `json:"roles"`
}

var (
	nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
	arnRe  = regexp.MustCompile(`^arn:aws[a-z-]*:iam::\d{12}:role/.+$`)
	mfaRe  = regexp.MustCompile(`^arn:aws[a-z-]*:iam::\d{12}:mfa/.+$`)
)

func ValidName(s string) bool { return nameRe.MatchString(s) }

// Path returns the config file location.
func Path() string {
	if p := os.Getenv("CERVUS_CONFIG"); p != "" {
		return p
	}
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "cervus", "config.json")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "cervus", "config.json")
}

func New() *Config {
	return &Config{Version: 1, Identities: map[string]Identity{}, Roles: map[string]Role{}}
}

// Load reads the config; a missing file yields an empty config.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return New(), nil
	}
	if err != nil {
		return nil, err
	}
	c := New()
	if err := json.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("%s is not valid: %w", path, err)
	}
	if c.Identities == nil {
		c.Identities = map[string]Identity{}
	}
	if c.Roles == nil {
		c.Roles = map[string]Role{}
	}
	return c, nil
}

// Save writes the config atomically with mode 0600.
func (c *Config) Save(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".config-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func (i Identity) Validate(name string) error {
	if !ValidName(name) {
		return fmt.Errorf("identity name %q must be lowercase letters, digits, '-' or '_' (max 32)", name)
	}
	if i.MFASerial != "" && !mfaRe.MatchString(i.MFASerial) {
		return fmt.Errorf("mfa serial must look like arn:aws:iam::<account>:mfa/<name>")
	}
	return nil
}

func (r Role) Validate(name string, c *Config) error {
	if !ValidName(name) {
		return fmt.Errorf("role name %q must be lowercase letters, digits, '-' or '_' (max 32)", name)
	}
	if _, ok := c.Identities[r.Identity]; !ok {
		return fmt.Errorf("unknown identity %q", r.Identity)
	}
	if r.ARN != "" && !arnRe.MatchString(r.ARN) {
		return fmt.Errorf("role arn must look like arn:aws:iam::<account>:role/<name>")
	}
	switch r.MFA {
	case "none", "once", "always":
	default:
		return fmt.Errorf("mfa must be none, once or always")
	}
	if r.MFA != "none" && c.Identities[r.Identity].MFASerial == "" {
		return fmt.Errorf("identity %q has no MFA serial; add one with `cervus identity add --mfa-serial`", r.Identity)
	}
	if r.DurationSecs != 0 && (r.DurationSecs < 900 || r.DurationSecs > 43200) {
		return fmt.Errorf("duration must be between 15 minutes and 12 hours")
	}
	return nil
}
