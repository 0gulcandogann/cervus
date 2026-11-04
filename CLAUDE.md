# CLAUDE.md — Cervus project memory

Read this first. Then read `docs/HANDOFF.md` (status + task list), `README.md`, `docs/PROTOCOL.md`.

## What this is

Cervus: encrypted AWS secrets and per-shell role/identity switching for the terminal.
Go daemon + CLI (`cli/`), Rust vault (`vault/`), talk over stdio. See README for the architecture diagram.

## Language

Code, comments, docs, CLI output and commit messages are in **English**.

## Skills and workflow (Superpowers plugin)

Use the `superpowers:*` skills. Minimum for this project:

| When | Skill |
|---|---|
| Before starting any new feature | `superpowers:brainstorming`, then `superpowers:writing-plans` |
| Any feature or bugfix | `superpowers:test-driven-development` (write the failing test first) |
| Any test failure or odd behavior | `superpowers:systematic-debugging` |
| Before saying "done / passes / fixed" | `superpowers:verification-before-completion` (run the command, read the output, then claim) |
| After a feature is finished | `superpowers:requesting-code-review` |
| Independent subtasks (e.g. keychain + git sync) | `superpowers:dispatching-parallel-agents` |

Other useful skills if installed: `dataviz` not needed; `anthropic-skills:docs` only if asked for a doc.

## Hard rules (security product)

- Never print, log, commit or paste secrets: access keys, passphrases, recovery keys, MFA seeds, session tokens. This includes test output and audit-log fields.
- Never add a dependency without saying why. The AWS client is deliberately dependency-free (own SigV4). Keep the Rust crate list small.
- Secrets in Go cannot be zeroized; keep their lifetime short and never copy them into long-lived structs.
- New daemon operations must be added to the allowlist/handlers deliberately, and to `auditedOps` in `cli/cmd/cervusd/audit.go` with an explicit list of loggable params.
- Do not claim macOS behavior is verified, or real-AWS behavior beyond the test pass recorded in `docs/HANDOFF.md`. Automated tests use only the fake STS (`scripts/mock_sts.py`).
- Do not use real AWS accounts in tests. Real-AWS testing is manual, by a maintainer, in a sandbox account.

## Commands

```sh
make build          # vault (cargo) + cli (go) into ./bin
make test           # unit tests + 4 e2e suites, ~3 min
make dist           # release archive for this machine into ./dist
make test-dist      # checks that archive
BIN=./bin bash scripts/e2e.sh          # vault + recovery
BIN=./bin bash scripts/e2e_aws.sh      # identities, roles, MFA, audit (fake STS; waits for a TOTP window)
BIN=./bin bash scripts/e2e_migrate.sh  # migrate + doctor
BIN=./bin ZSH=$(command -v zsh) bash scripts/e2e_shell.sh   # real bash/zsh in a pty
```

Requirements: Go 1.22+, Rust 1.74+, Python 3, zsh (for the shell suite).

## Gotchas

- On WSL under `/mnt/c/...`, file modes are not enforced and scripts lose the exec bit, so the Makefile runs scripts with `bash`. Keep the repo on the Linux side for real use.
- Tests use temp dirs and `CERVUS_SOCKET` / `--vault-dir` / `--config` flags. Never touch the real `~/.cervus`, `~/.aws` in tests (migrate test sets `HOME` and `AWS_*_FILE`).
- The `cervus-vault` process ignores nothing on stdin: one JSON request per line, one reply per line.
- zsh integration adds to `RPROMPT`; oh-my-zsh themes that reset `RPROMPT` may hide the segment (unverified).
- `go build` / `cargo` output dirs: use `GOCACHE` and `CARGO_TARGET_DIR` outside the repo if the filesystem is slow.

## Layout

```
cli/cmd/cervus/     CLI (main.go, shell.go, migrate.go, doctor.go, ini.go)
cli/cmd/cervusd/    daemon (main.go allowlist+serve, api.go handlers, audit.go)
cli/internal/       awsapi (SigV4, STS), client, config, vaultproc
vault/src/          store.rs (age, recovery), totp.rs, main.rs (stdio ops)
scripts/            e2e suites + mock_sts.py + pty_test.py
docs/PROTOCOL.md    both protocols
docs/HANDOFF.md     status and task list
```
