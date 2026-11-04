# Cervus protocols (v0)

Two separate contracts. Both use newline-delimited JSON (one UTF-8 object per line, one response per request, in order).

```json
{"id": 1, "op": "status"}
{"id": 1, "ok": true, "data": {"locked": true}}
{"id": 2, "ok": false, "error": {"code": "locked", "message": "vault is locked; run `cervus unlock`"}}
```

Binary values (secrets) are base64 strings.

## 1. Public API: `cervus` CLI to `cervusd`

- Unix socket. Lookup: `$CERVUS_SOCKET`, `$XDG_RUNTIME_DIR/cervus/cervus.sock`, `/run/user/<uid>/cervus/cervus.sock` if that socket exists, `~/.cervus/cervus.sock`.
- Directory `0700`, socket `0600`. Linux: peer UID is checked with `SO_PEERCRED`. macOS: TODO (`LOCAL_PEERCRED`).
- The daemon maps public ops to vault ops through an allowlist. Anything else returns `unknown_op` and never reaches the vault.

| Public op | Params | Vault op |
|---|---|---|
| `ping` | none | `ping` |
| `status` | none | `status` |
| `init` | `{passphrase}` | `init` |
| `unlock` | `{passphrase, source?}` (`source: "keychain"` is client-claimed and goes to the audit log) | `unlock` |
| `recover` | `{recovery_key, passphrase, drop_local?}` | `recover` |
| `lock` | none | `lock` |
| `passwd` | `{current, new}` | `change_passphrase` |
| `secret.put` | `{name, value, type?, scope?}` | `put` |
| `secret.get` | `{name}` | `get` |
| `secret.list` | `{prefix?}` | `list` |
| `secret.delete` | `{name}` | `delete` |

`secret.get`, `secret.put` and `secret.delete` refuse names starting with `aws-key.` or `mfa-seed.` (any letter case) with `denied`. Only the daemon's own handlers use those secrets.

Handlers of the operations below refuse parameter keys that are not lowercase, because the audit log reads exact keys.

AWS operations are handled by the daemon itself (they use the vault internally and talk to AWS STS):

| Public op | Params | Reply data |
|---|---|---|
| `identity.add` | `{id, region?, mfa_serial?, access_key_id, secret_access_key, verify?}` | `{arn?, account?}` |
| `identity.list` | none | `{identities: [{name, region, mfa_serial}]}` |
| `identity.update` | `{id, region?, mfa_serial?, rotate?, access_key_id?, secret_access_key?, verify?, allow_different_principal?}` | `{arn?, account?, previous_arn?, old_key_unverified?}` |
| `identity.remove` | `{id}` | `{}` |
| `identity.verify_key` | `{id, access_key_id, secret_access_key}` (compares with the stored key) | `{match}` |
| `identity.mfa_import` | `{id, seed}` (base32; stored device-only) | `{mfa_serial_configured}` |
| `role.add` | `{name, identity, arn?, region?, mfa?: "none"\|"once"\|"always", confirm?, duration_secs?}` | `{}` |
| `role.edit` | `{name, identity?, arn?, region?, mfa?, confirm?, duration_secs?}` (only the given fields change; a new target or new confirmation takes shells off the role) | `{shells_removed}` |
| `role.list` / `role.remove` | none / `{name}` | `{roles}` / `{}` |
| `use` | `{session, role, confirmed?, pid?}` (`pid` also registers the shell, for one the daemon has forgotten) | `{role, expires_at}` |
| `credentials` | `{session}` | AWS `credential_process` JSON (Version 1) |
| `whoami` | `{session}` | `{role, expires_at, seconds_left, protected}` |
| `keychain.event` | `{action}` (`enabled` or `disabled`; audit log only) | `{}` |
| `session.register` | `{session, pid}` (daemon forgets the session when the PID exits) | `{}` |

| `audit.tail` | `{n}` | `{lines: [string]}` |
| `audit.verify` | none | `{entries, bad_line}` (0 = intact) |

Extra error codes: `confirm_required`, `no_role`, `aws_error`, `network`, `mfa_not_configured`, `mfa_code_reused`.

Planned: audit, session listing.

## 2. Internal API: `cervusd` to `cervus-vault`

- The daemon starts `cervus-vault` as a child process and talks over its stdin/stdout. There is no socket path on disk, so only the parent can reach the vault. Vault logs go to stderr.
- If the pipe breaks, the daemon drops the process; the next call starts a fresh vault, which is locked.

| Op | Params | Reply data |
|---|---|---|
| `ping` | none | `{pong}` |
| `status` | none | `{initialized, locked, version, idle_timeout_secs, dir}` |
| `init` | `{passphrase}` (min 10 chars) | `{recovery_key}` (shown once) |
| `unlock` | `{passphrase}` | `{locked: false}` |
| `change_passphrase` | `{current, new}` | `{}` |
| `lock` | none | `{locked: true}` |
| `put` | `{name, value, type?: "generic", scope?: "synced"\|"local"}` | `{}` |
| `get` | `{name}` | `{type, scope, value}` |
| `list` | `{prefix?}` | `{secrets: [{name, scope}]}` |
| `delete` | `{name}` | `{}` |
| `totp` | `{name}` (a secret of type `mfa_seed`) | `{code, valid_for_secs}` |
| `recover` | `{recovery_key, passphrase, drop_local?}` | `{reencrypted, lost_local: [name]}` |

Names: letters, digits, `.`, `_`, `-`; max 64; no leading dot.

## Error codes

`bad_request`, `unknown_op`, `locked`, `not_initialized`, `already_initialized`, `auth_failed`, `not_found`, `internal`.
