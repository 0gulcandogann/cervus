package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"cervus/internal/client"
)

type planIdentity struct {
	Name, Profile, AccessKeyID, Secret, Region, MFASerial string
}

type planRole struct {
	Name, Identity, ARN, Region, MFA string
	DurationSecs                     int
}

type migrationPlan struct {
	Identities []planIdentity
	Roles      []planRole
	Notes      []string
}

var badNameChars = regexp.MustCompile(`[^a-z0-9_-]+`)

func sanitizeName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = badNameChars.ReplaceAllString(s, "-")
	s = strings.TrimLeft(s, "-_")
	if len(s) > 32 {
		s = s[:32]
	}
	return s
}

func awsPaths() (creds, cfg string) {
	home, _ := os.UserHomeDir()
	creds = os.Getenv("AWS_SHARED_CREDENTIALS_FILE")
	if creds == "" {
		creds = filepath.Join(home, ".aws", "credentials")
	}
	cfg = os.Getenv("AWS_CONFIG_FILE")
	if cfg == "" {
		cfg = filepath.Join(home, ".aws", "config")
	}
	return
}

// configProfile returns the section of ~/.aws/config for a profile name.
func configProfile(cfg *iniFile, profile string) *iniSection {
	if profile == "default" {
		if s := cfg.find("default"); s != nil {
			return s
		}
	}
	return cfg.find("profile " + profile)
}

// buildPlan decides what can be migrated. existing lists identity names already in Cervus.
func buildPlan(creds, cfg *iniFile, existing, existingRoles map[string]bool) migrationPlan {
	var p migrationPlan
	byProfile := map[string]string{} // aws profile -> identity name
	for _, s := range creds.sections {
		id, secret := s.get("aws_access_key_id"), s.get("aws_secret_access_key")
		if id == "" || secret == "" {
			continue
		}
		if s.get("aws_session_token") != "" {
			p.Notes = append(p.Notes, fmt.Sprintf("skipped profile %q: temporary credentials (session token), nothing permanent to migrate", s.name))
			continue
		}
		name := sanitizeName(s.name)
		if name == "" {
			p.Notes = append(p.Notes, fmt.Sprintf("skipped profile %q: name cannot be used as an identity name", s.name))
			continue
		}
		if existing[name] {
			p.Notes = append(p.Notes, fmt.Sprintf("skipped profile %q: identity %q already exists in Cervus", s.name, name))
			byProfile[s.name] = name
			continue
		}
		ident := planIdentity{Name: name, Profile: s.name, AccessKeyID: id, Secret: secret}
		if cp := configProfile(cfg, s.name); cp != nil {
			ident.Region = cp.get("region")
		}
		p.Identities = append(p.Identities, ident)
		byProfile[s.name] = name
	}

	for _, s := range cfg.sections {
		profile := strings.TrimPrefix(s.name, "profile ")
		arn, src := s.get("role_arn"), s.get("source_profile")
		if arn == "" {
			continue
		}
		if src == "" {
			p.Notes = append(p.Notes, fmt.Sprintf("skipped role profile %q: it has no source_profile (SSO and credential_source are not supported yet)", profile))
			continue
		}
		ident, ok := byProfile[src]
		if !ok && existing[sanitizeName(src)] {
			ident, ok = sanitizeName(src), true
		}
		if !ok {
			p.Notes = append(p.Notes, fmt.Sprintf("skipped role profile %q: its source profile %q is not migrated", profile, src))
			continue
		}
		name := sanitizeName(profile)
		if name == "" {
			continue
		}
		if existingRoles[name] {
			p.Notes = append(p.Notes, fmt.Sprintf("skipped role profile %q: role %q already exists in Cervus", profile, name))
			continue
		}
		r := planRole{Name: name, Identity: ident, ARN: arn, Region: s.get("region"), MFA: "none"}
		if serial := s.get("mfa_serial"); serial != "" {
			r.MFA = "always"
			for i := range p.Identities {
				if p.Identities[i].Name == ident && p.Identities[i].MFASerial == "" {
					p.Identities[i].MFASerial = serial
				}
			}
		}
		if d := s.get("duration_seconds"); d != "" {
			fmt.Sscanf(d, "%d", &r.DurationSecs)
		}
		p.Roles = append(p.Roles, r)
	}
	return p
}

func askYesNo(prompt string, yes bool) bool {
	if yes {
		return true
	}
	if !isTTY(os.Stdin) {
		fmt.Println(prompt + " [skipped: not a terminal, use --yes]")
		return false
	}
	fmt.Print(prompt + " [y/N] ")
	line, _ := stdin.ReadString('\n')
	a := strings.ToLower(strings.TrimSpace(line))
	return a == "y" || a == "yes"
}

func cmdMigrate(args []string) error {
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	dry := fs.Bool("dry-run", false, "only show what would happen")
	if err := fs.Parse(args); err != nil {
		return err
	}
	credsPath, cfgPath := awsPaths()
	credData, err := os.ReadFile(credsPath)
	if err != nil {
		return fmt.Errorf("cannot read %s: %w", credsPath, err)
	}
	cfgData, _ := os.ReadFile(cfgPath)
	credsINI, cfgINI := parseINI(credData), parseINI(cfgData)

	var ids struct {
		Identities []struct {
			Name string `json:"name"`
		} `json:"identities"`
	}
	if err := client.Call("identity.list", nil, &ids); err != nil {
		return err
	}
	existing := map[string]bool{}
	for _, i := range ids.Identities {
		existing[i.Name] = true
	}

	var rl struct {
		Roles []struct {
			Name string `json:"name"`
		} `json:"roles"`
	}
	_ = client.Call("role.list", nil, &rl)
	existingRoles := map[string]bool{}
	for _, r := range rl.Roles {
		existingRoles[r.Name] = true
	}

	plan := buildPlan(credsINI, cfgINI, existing, existingRoles)
	for _, n := range plan.Notes {
		fmt.Println("note:", n)
	}
	if len(plan.Identities) == 0 && len(plan.Roles) == 0 {
		fmt.Println("Nothing to migrate.")
		return nil
	}
	fmt.Println("\nPlan:")
	for _, i := range plan.Identities {
		fmt.Printf("  identity %-16s from profile %q (key %s)\n", i.Name, i.Profile, i.AccessKeyID)
	}
	for _, r := range plan.Roles {
		fmt.Printf("  role     %-16s %s (identity %s, mfa=%s)\n", r.Name, r.ARN, r.Identity, r.MFA)
	}
	if *dry {
		return nil
	}
	if !askYesNo("\nMigrate these into Cervus? Keys are verified with AWS and stored encrypted.", *yes) {
		return errors.New("cancelled")
	}

	var migrated []planIdentity
	for _, i := range plan.Identities {
		err := client.Call("identity.add", map[string]any{
			"id": i.Name, "region": firstNonEmpty(i.Region, "us-east-1"), "mfa_serial": i.MFASerial,
			"access_key_id": i.AccessKeyID, "secret_access_key": i.Secret, "verify": true,
		}, nil)
		if err != nil {
			var re *client.RemoteError
			if errors.As(err, &re) && strings.Contains(re.Message, "locked") {
				return err
			}
			fmt.Printf("  FAILED identity %s: %v (plaintext key left in place)\n", i.Name, err)
			continue
		}
		if !storedKeyMatches(i) {
			fmt.Printf("  FAILED identity %s: could not read the stored key back (plaintext key left in place)\n", i.Name)
			continue
		}
		fmt.Printf("  ok identity %s\n", i.Name)
		migrated = append(migrated, i)
	}
	migratedNames := map[string]bool{}
	for _, i := range migrated {
		migratedNames[i.Name] = true
	}
	for _, r := range plan.Roles {
		if !migratedNames[r.Identity] && !existing[r.Identity] {
			fmt.Printf("  skipped role %s: identity %s was not migrated\n", r.Name, r.Identity)
			continue
		}
		err := client.Call("role.add", map[string]any{
			"name": r.Name, "identity": r.Identity, "arn": r.ARN, "region": r.Region,
			"mfa": r.MFA, "duration_secs": r.DurationSecs,
		}, nil)
		if err != nil {
			fmt.Printf("  FAILED role %s: %v\n", r.Name, err)
			continue
		}
		fmt.Printf("  ok role %s\n", r.Name)
		if r.MFA != "none" {
			fmt.Printf("     MFA is required: run `cervus identity mfa-import %s` (or mfa-setup) before using it\n", r.Identity)
		}
	}

	if len(migrated) == 0 {
		return nil
	}
	fmt.Println()
	if !askYesNo(fmt.Sprintf("Remove the %d migrated plaintext key(s) from %s?", len(migrated), credsPath), *yes) {
		fmt.Println("Plaintext keys kept. Run `cervus doctor` later to be reminded.")
		return nil
	}
	for _, i := range migrated {
		if s := credsINI.find(i.Profile); s != nil {
			s.removeKeys("aws_access_key_id", "aws_secret_access_key")
			if s.empty() {
				credsINI.removeSection(i.Profile)
			}
		}
	}
	if err := writeFileAtomic(credsPath, []byte(credsINI.String()), 0o600); err != nil {
		return err
	}
	fmt.Printf("Removed plaintext keys from %s. They now live only in the encrypted vault;\n", credsPath)
	fmt.Println("your recovery key can restore them. Use `cervus use <role>` or `cervus doctor` next.")
	return nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func storedKeyMatches(i planIdentity) bool {
	var out struct {
		Match bool `json:"match"`
	}
	err := client.Call("identity.verify_key", map[string]string{
		"id": i.Name, "access_key_id": i.AccessKeyID, "secret_access_key": i.Secret,
	}, &out)
	return err == nil && out.Match
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".cervus-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(mode); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
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
