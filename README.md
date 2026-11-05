# Cervus

![A glowing white deer leaping through a dark forest, trailing light that spells Cervus](docs/assets/banner.jpg)

**Encrypted AWS credentials and instant role switching for your terminal.** Set it up once, then press `Alt+r` to move between your AWS roles, users and vaults.

> **Pre-release.** Cervus has not had an independent security review, and only part of it has been tried on real AWS. Do not use it with production credentials yet.

## Why

- **No plaintext keys.** Access keys and MFA seeds live in encrypted [age](https://age-encryption.org) files, not in `~/.aws/credentials`.
- **Each shell has its own role.** One terminal can be on `dev` and another on `prod`, and the prompt shows which is which.
- **No keys in your environment.** The AWS CLI asks Cervus through `credential_process`, and short-lived credentials stay in the daemon's memory.
- **Separate vaults when you want them.** A user can have its own vault, passphrase and recovery key.
- **Local only.** No account, no cloud service and no telemetry. It only talks to AWS.

## Quick start

Get a [release](#install) or [build from source](#build-and-test), then run:

```sh
cervus                       # sets up the daemon, a vault, the AWS profile and your shell; asks before each change
exec $SHELL                  # a running shell cannot gain a shortcut by itself; new terminals work right away
cervus identity add work     # asks for an access key and checks it with AWS
cervus role add dev --identity work --arn arn:aws:iam::123456789012:role/Dev
```

`cervus` and `cervus setup` open with a banner that fits your terminal's width: run `cervus banner` to see it. In a pipe it prints nothing, and with `NO_COLOR` or without 24-bit color it is plain text. Everyday commands never show it.

Press `Alt+r`, pick a role, and use AWS as usual:

```sh
aws sts get-caller-identity
```

It keeps working after a restart: the daemon starts at login and new terminals have `Alt+r`. The vault stays locked until the picker first needs it, then asks for its passphrase once. To skip that, see [fewer passphrase prompts](#optional-fewer-passphrase-prompts).

Already have keys in `~/.aws/credentials`? `cervus migrate` moves them into the vault. It checks each key before removing the plaintext.

## Everyday use

| You want to | Run |
|---|---|
| Switch role, user or vault | `Alt+r`, or `cervus use dev` |
| Use a user directly, without a role | `cervus use user:work` |
| Pin one command to a role | `cervus exec prod -- terraform plan` |
| See where you are | `cervus whoami` |
| Check your setup | `cervus doctor` |
| Lock everything now | `cervus lock` |
| Use another key for the picker | `cervus keybinding alt+s` |

In the picker, use `j`/`k` or the arrows, `Enter` or a number to choose, and `q` to cancel. The prompt shows `[dev 45m]`: the role and the minutes left, in red for protected roles.

Prefer `cervus exec` for anything long-running. A plain command follows its shell's role, so `Alt+r` can move it at its next credential refresh.

### Roles and MFA

```sh
cervus identity add work --region eu-west-1 --mfa-serial arn:aws:iam::123456789012:mfa/me
cervus identity mfa-import work     # paste the base32 seed; it stays on this device
cervus role add prod --identity work --arn arn:aws:iam::123456789012:role/Prod --mfa always --confirm
```

| `--mfa` | Behavior |
|---|---|
| `none` | No MFA code |
| `once` | One MFA-backed session token, reused for this user's roles |
| `always` | A fresh code each time credentials are issued |

`--confirm` asks before switching to the role. The vault computes MFA codes itself, so this protects against mistakes, not against malware running as you.

### Several vaults

Everything starts in a default vault. Give a user its own vault only when you want one:

```sh
cervus identity add client --own-vault     # new vault named "client", with its own passphrase and recovery key
cervus vault create personal               # or make one first
cervus identity add me --vault personal
cervus identity move me --vault client     # carries the key and MFA seed across
cervus vault list
```

The picker shows each entry's vault. If that vault is locked, it asks for that vault's passphrase only. `cervus lock` locks all vaults; `cervus lock --vault client` locks one.

Roles of the same user share a vault, because they share its access key and MFA seed. To isolate a sensitive role, give it a different IAM user in its own vault.

### Other secrets

```sh
cervus secret put api-token                # goes to your active role's vault; it tells you which
cervus secret put --vault personal note
cervus secret get api-token
cervus secret list
cervus secret rm --vault personal note
```

Without `--vault`, `get`, `put` and `list` use `$CERVUS_VAULT`, then the active role's vault, then the default one. `rm` asks you to name the vault rather than follow the active role. Access keys and MFA seeds cannot be read or changed this way.

### Changing things later

| Change | Run |
|---|---|
| Replace an access key; roles and MFA seed stay | `cervus identity update work --rotate-key` |
| Change a role's settings | `cervus role edit dev --mfa always` |
| Change a passphrase | `cervus passwd [--vault V]` |
| Lost a passphrase | `cervus recover [--vault V]` |
| Read or check the audit log | `cervus audit`, `cervus audit verify` |

Run `cervus help` for every command. After upgrading, restart `cervusd`: an older daemon ignores `--vault`.

### Optional: fewer passphrase prompts

`cervus keychain enable` keeps a vault's passphrase in the Linux Secret Service, using libsecret's `secret-tool`. It is off by default, so read this first:

- While your login keyring is open, often the whole session, any program running as you can read the passphrase and open the vault, MFA-protected roles included.
- The vault reopens by itself after an idle lock. After `cervus lock` it stays locked until `cervus unlock`.
- `cervus keychain disable` cannot undo a leak. If the passphrase may have been read, run `cervus recover` and rotate your secrets.

## Install

Release archives are available for `linux-amd64`, `linux-arm64`, `darwin-arm64` and `darwin-amd64`. Keep the three programs in one folder:

```sh
V=0.0.8 P=linux-amd64
curl -LO "https://github.com/0gulcandogann/cervus/releases/download/v$V/cervus-$V-$P.tar.gz"
gh attestation verify "cervus-$V-$P.tar.gz" --repo 0gulcandogann/cervus   # optional: proves GitHub Actions built it from this repo
tar -xzf "cervus-$V-$P.tar.gz"
export PATH="$PWD/cervus-$V-$P:$PATH"
```

Linux builds need glibc 2.34 or newer. Only the Linux amd64 build has been run. The macOS builds have never been run and are not notarized.

## Security model

Cervus protects against a stolen disk or backup, plaintext keys left lying around, and other users on the machine. Your secrets are encrypted at rest, and the daemon's socket only accepts your own user.

It does **not** protect against a program running as you:

- While a vault is unlocked, such a program can use the daemon to get credentials.
- It can edit `config.json` or replace vault files, because those files are not authenticated.
- Blocking `secret get` and `put` for keys stops direct reads and accidents. It does not make the vault tamper-proof.

Also worth knowing:

- Role and user names, ARNs and each user's vault are readable in `config.json`. Secret names are visible as file names.
- Go cannot wipe memory, so secrets passing through the daemon are not erased.
- The audit log never contains secrets. It detects edits in the middle but not a cut-off end, and it can be rewritten by a program running as you.
- `passwd` does not undo a leak: an old copy of a vault still opens with the old passphrase. After a leak, run `cervus recover` and rotate your secrets.
- MFA seeds are device-only. A recovery key cannot restore them, so import them again after `cervus recover`.

## How it works

```
cervus (CLI) --> cervusd (Go daemon) --stdio pipe--> cervus-vault (Rust, one process per vault)
 aws CLI --credential_process--^   |                  age encryption, TOTP, idle auto-lock
                                   +--> AWS STS (own SigV4 client, no SDK)
```

| Program | Language | Role |
|---|---|---|
| `cervus` | Go | Command line, shell integration, `credential_process` helper |
| `cervusd` | Go | Daemon: sessions, credential cache and refresh, STS calls, allowlisted API |
| `cervus-vault` | Rust | Encryption, key handling, TOTP, idle auto-lock |

A vault has no socket on disk, so only the daemon can reach it. Idle lock defaults to 4 hours and also drops that vault's cached credentials. `cervus install-service` runs the daemon at login as a systemd user unit. See [docs/PROTOCOL.md](docs/PROTOCOL.md).

`cervus exec` pins a command only while it runs. Background children left behind lose the role, so keep the command in the foreground (`nohup cervus exec ...`). A daemon restart, or removing or retargeting the role, also ends it: the command gets an error at its next refresh and must be restarted.

## Build and test

Needs Go 1.22+, Rust 1.74+ and Python 3. The shell tests also use zsh if it is installed.

```sh
make build && export PATH="$PWD/bin:$PATH"
make test        # unit tests and 5 end-to-end suites against a fake STS, a few minutes
make test-dist   # builds and checks a release archive
```

The AWS signer is checked against the official AWS SigV4 example, and TOTP against the RFC 6238 vectors.

## Roadmap

- Finish real-AWS testing
- Encrypt role ARNs and MFA serials
- MFA enrollment from the CLI
- macOS: Keychain and peer check
- IAM Identity Center (SSO)
- Hardening and fuzz tests
- Independent security review

## License

[MIT](LICENSE)
