# Handoff — where we stopped (2026-11-03)

Version: cervus 0.0.5, cervus-vault 0.0.4. Pre-release. Not reviewed. Core role flows passed one real-AWS test pass (see below).

## Done and tested (Linux, fake STS)

| Area | What exists | Test |
|---|---|---|
| Vault | age encryption, passphrase-wrapped device key, recovery key, synced vs device-only secrets, idle auto-lock, crash restart (locked) | Rust unit (15) + `e2e.sh` |
| Recovery | `cervus recover [--drop-local]` | Rust unit + `e2e.sh` |
| TOTP | RFC 6238 in the vault, seed never leaves it | RFC vectors + cross-check in `e2e_aws.sh` |
| AWS | own SigV4 (official AWS vector passes), AssumeRole, GetSessionToken, GetCallerIdentity | Go unit + `e2e_aws.sh` |
| Identities / roles | add/list/remove, `mfa none|once|always`, `--confirm`, durations, MFA code reuse guard, credential cache + refresh | `e2e_aws.sh` |
| Sessions | per-shell `CERVUS_SESSION`, dead-shell cleanup, `credential_process`, `aws-profile --install` | `e2e_aws.sh`, `e2e_shell.sh` |
| Shell | `init-shell zsh|bash [--prompt] [--install]`, Alt+r picker, prompt segment | `e2e_shell.sh` (pty) |
| Migration | `cervus migrate` (plaintext keys -> vault, role profiles import, verify before delete) | `e2e_migrate.sh` |
| One-command roles | `cervus exec <role> [--yes] -- <cmd>` | Go unit, `e2e_aws.sh` (fake STS only), `pty_test.py` |
| Key lifecycle | `identity update [--rotate-key]`, `role edit`, `passwd` | Rust unit, `e2e.sh`, `e2e_aws.sh` (fake STS only) |
| Doctor | `cervus doctor`, including the login service | `e2e_migrate.sh` |
| Login service | `cervus install-service`, `uninstall-service` (systemd user unit; launchd plist content only) | Go unit, `e2e_migrate.sh` with a fake `systemctl` |
| Audit | hash-chained log, `cervus audit [verify]`, no secrets logged | Go unit + `e2e_aws.sh` |

Last verification (2026-11-03, Linux): Rust 12/12, Go unit tests ok, `e2e.sh`, `e2e_aws.sh`, `e2e_migrate.sh` all passed. `e2e_shell.sh` passed for **bash only** in that run (zsh was not installed there; zsh passed in an earlier session). **First task: run `make test` on a machine with zsh and read the result.**

## Real-AWS test pass (2026-11-03, Linux, one sandbox account, us-east-1)

Passed: own SigV4 accepted; `mfa none|always|once` against real roles; a trust policy requiring MFA rejects a call without it and accepts vault TOTP codes; two sessions hold two roles; `credential_process` through a real `[profile cervus]` in the AWS CLI.

Reused TOTP code: real AWS accepted the first `GetSessionToken` and rejected a second call with the same code (`AccessDenied`). One sample, `GetSessionToken` only.

Not covered yet: credential refresh on expiry, `cervus migrate` and the shell picker against real AWS, the actual billing result.

## Never verified

- macOS (see below) and any real-AWS behavior not listed above.
- macOS (Keychain, `LOCAL_PEERCRED`, `PT_DENY_ATTACH`, Terminal/iTerm2 Alt key).
- oh-my-zsh themes with the prompt segment.
- WSL: only the vault suite of `make test` has been run there.

## Known gaps (small)

1. Vault idle auto-lock does not clear the daemon's credential caches (`cervus lock` does). Fix: daemon polls vault `status`, or the vault reports lock events; clear caches when locked.
2. Audit log: truncation of the tail is undetectable. Option: periodically store the head hash in the vault.
3. Sessions are keyed only by PID liveness (PID reuse is possible but unlikely within 30s).
4. `cervus init` unlock UX: passphrase is required for every unlock (keychain not built).
5. Keep the `lastCode` reuse guard: real AWS rejected a reused code (one sample, see the test pass above).

## Small issues from the install-service review (deferred)

- A failed reinstall does not restore the previous unit; uninstall leaves the enable symlink if `disable` fails.
- `CERVUS_CONFIG`, `CERVUS_VAULT_DIR` and `CERVUS_IDLE_SECS` get no warning at install, and the service ignores them.
- Ctrl-C at the `readSecret` passphrase prompt leaves terminal echo off.
- `readHiddenLine`: Ctrl-D and arrow-key bytes enter the passphrase; Backspace removes one byte of a multibyte character.
- `CERVUS_SESSION=x cervus use r` in an integrated shell ties session `x` to that shell.
- `reserved_test.go` "escaped name" case contains no escape; `e2e_migrate.sh` unsets `XDG_CONFIG_HOME` late; the `switchRole` doc comment sits above `sendUnlock`.

## Small issues from the key lifecycle review (deferred)

- A bad name or `--mfa-serial` still prompts for the key before failing; `cervus passwd` ignores extra arguments and accepts new == current.
- `--confirm=false --no-confirm=false` is accepted; the access key ID echoes on a terminal and the secret is not trimmed (same as `identity add`).
- `.tmp-<pid>` writes use no `O_EXCL`/`O_NOFOLLOW` and leave the file on error; passphrases parsed into `req.params` are not wiped in the vault.
- A vault crash right after the `passwd` rename says "try again", though the change took effect; `whoami` shows `0 minutes left` and the prompt `[role expired]` after an edit, until the next use.
- `role edit --mfa` does not warn when the identity has no seed; `mfa=always` edits can hit the code reuse guard within one window; `a.mu` is held across STS calls in `identityUpdate`.
- The fake STS checks key IDs, not signatures, so "verified" in tests means "known key ID".

## Small issues from the `cervus exec` review (deferred)

- A non-executable file, a directory or `PATH=.` says "command not found" with 127; a script without a shebang gives a bare "exec format error".
- A child that strips `CERVUS_SESSION` but keeps `AWS_PROFILE=cervus` falls back to the `default` session and its role.
- The audit log cannot tell a pinned run from a shell; removed variables are not named on the terminal.
- Prompts read stdin, not `/dev/tty`, so `cat x | cervus exec prod -- cmd` cannot confirm or unlock; `use prod 2>/dev/null` waits with no visible prompt.
- `e2e_aws.sh` uses `sleep` around the pinned run; daemon restart, role removal during a run and outliving children have no automated test.
- Only aws-cli v1 was used to check credential provider order; the Go SDK and Terraform were not.

## Task list (in priority order)

Agreed next order (2026-11-03): real-AWS test (task 10), then `install-service` (task 2), then ARN encryption (task 12).

Each task: use `superpowers:brainstorming` -> `writing-plans` -> TDD. Acceptance = a new test in the relevant e2e suite.

1. **Run the full suite** (`make test`), fix anything red. Commit baseline (`git init`, add `.gitignore` already present).
2. **Done: run at login.** `cervus install-service`, `uninstall-service`, `doctor` check. Real systemd checked on Linux (2026-11-03): enable, start, restart after `kill -9`, status, uninstall. Not tested: an actual log out and log in. launchd behavior is unverified. The new unlock prompt has not run in zsh (zsh was not installed).
3. **Known gap 1** (cache clear on idle lock).
4. **MFA enrollment with QR** (`cervus identity mfa-setup <id>`): IAM client in `awsapi` (`CreateVirtualMFADevice`, `EnableMFADevice`, SigV4 service `iam`, global endpoint, region us-east-1); render `otpauth://` QR in the terminal (prefer a small, audited QR dependency or a small own encoder with tests against known vectors); ask for two consecutive codes; store seed device-only; set the identity's `mfa_serial`. Fake IAM in `mock_sts.py`. Also show the base32 text as fallback. Explain missing IAM permissions clearly.
5. **Git sync** (`cervus vault git init|sync`, `vault recipient add|remove`): `.gitignore` excluding `local/`, pre-push hook blocking non-`.age` files under `secrets/`, re-encrypt on recipient change, print "rotate these secrets" on removal. Needs a vault op to list/replace recipients.
6. **OS keychain** (macOS Keychain, Linux Secret Service), optional, passphrase stays as fallback. Needs a macOS machine to test; mark untested parts honestly.
7. **macOS peer check** (`LOCAL_PEERCRED`) in `peer_other.go`.
8. **SSO identity kind** (IAM Identity Center device flow). Design doc section 7.
9. **Hardening**: mlock in vault, fuzz tests for both parsers, CI (`go vet`, `govulncheck`, `cargo audit`, `cargo deny`), signed release builds, Homebrew tap.
10. **Finish the real-AWS test pass**: credential refresh, `cervus migrate`, the shell picker, and compare the bill before credits 24-48 hours after the test.
11. Independent security review before calling anything 1.0.
12. **Encrypt role ARNs and MFA serials** (agreed, not urgent; do after the real-AWS test and `install-service`). Today they are plaintext in `config.json`, and role ARNs also go into the audit log. Move them into the vault, drop the ARN from `auditedOps`, and make `cervus migrate` offer to clean role ARNs from `~/.aws/config`. Trade-off: `role list` cannot show ARNs while locked; role and identity names stay plaintext.

## Design reference

The full design document (threat model, milestones) is not in the repo yet; export it to `docs/DESIGN.md` when convenient. Differences from that doc: the vault is a stdio child process (not a socketpair); the device key is passphrase-wrapped (keychain not built); config is JSON (not TOML).

## Open decisions

- License (MIT vs Apache-2.0).
- Name availability: check GitHub, crates.io, Go module path, Homebrew, trademark databases for `cervus`.
- Opaque secret names vs readable file names.
- Idle timeout default (currently 4 h).
