# Run at Login (`install-service`) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `cervus install-service` makes `cervusd` start at login; `uninstall-service` undoes it; `doctor` reports its state.

**Architecture:** One new file, `cli/cmd/cervus/service.go`, holds pure generators for the systemd unit and launchd plist, plus install and uninstall flows that call the service manager through a replaceable runner, so tests never touch the real one.

**Tech Stack:** Go standard library only.

**Spec:** the design approved in chat on 2026-11-03, summarized under Global Constraints. Task 2 in `docs/HANDOFF.md` is its origin.

## Global Constraints

- No new dependencies. CLI output, comments and docs are in English.
- Linux path: `~/.config/systemd/user/cervusd.service`, or under `$XDG_CONFIG_HOME` when set. macOS path: `~/Library/LaunchAgents/cervus.daemon.plist`, label `cervus.daemon`.
- `ExecStart` / `ProgramArguments` use the absolute path of the `cervusd` next to the running `cervus` (symlinks resolved). If it is missing, install fails and writes nothing.
- Systemd unit: `Restart=on-failure`, `RestartSec=2`, `UMask=0077`, `LimitCORE=0`, `NoNewPrivileges=yes`, `WantedBy=default.target`.
- Launchd plist: `RunAtLoad` true, `KeepAlive` with `SuccessfulExit` false, `Umask` 63, core limit 0.
- The service file holds no secrets and no `CERVUS_*` values.
- Uninstall never touches the vault, config or audit log.
- A manually started daemon is never killed: install stops with a clear error and the fix.
- Out of scope: automatic unlock, shell or AWS profile setup, merging into `cervus init`.
- Never run the real service manager, or use the real `$HOME`, in tests.
- Do not claim macOS behavior is verified: only plist content is tested.

## Review Focus

- A path with spaces or `%` still starts the right file; systemd refuses `"`, `'`, `\\` and control characters even when quoted, so install refuses those (and `$`) with a clear error. The plist must be XML-escaped. Tested in Task 1 and in the final fix pass.
- Running install twice, or after moving the binaries: the file is rewritten with the new path and the service is restarted. Tested in Task 2.
- No `systemctl`, or no user systemd (some WSL): clear error naming the next step, with no file left behind. Tested in Task 2.
- `CERVUS_SOCKET` is set: the service uses the default socket, so the shell would miss it; install warns. Tested in Task 2.
- Daemon unreachable: `doctor` must still report the service state before its early exit. Tested in Task 3.

---

### Task 1: Service file generators

**Files:**
- Create: `cli/cmd/cervus/service.go`, `cli/cmd/cervus/service_test.go`

**Interfaces:**
- Produces: `serviceFilePath(goos, home, xdgConfig string) (string, error)`, `systemdUnit(daemonPath string) string`, `launchdPlist(daemonPath, logPath string) string`

- [ ] **Step 1: Write failing tests**
  - `TestServiceFilePath`: linux with and without `xdgConfig`, darwin, and an error for `windows`.
  - `TestSystemdUnitContent`: contains every value under Global Constraints, and `ExecStart="/opt/c/cervusd"`.
  - `TestSystemdUnitEscapesPath`: `/a b/100%/x"y/cervusd` gives `ExecStart="/a b/100%%/x\"y/cervusd"`.
  - `TestLaunchdPlistContent`: label, program path, `RunAtLoad`, `SuccessfulExit`, `<integer>63</integer>`; `/a&b/cervusd` appears as `/a&amp;b/cervusd`; the result parses with `encoding/xml`.
- [ ] **Step 2: Run** `cd cli && go test ./cmd/cervus/ -run 'ServiceFilePath|SystemdUnit|LaunchdPlist'`. Expected: FAIL, undefined functions.
- [ ] **Step 3: Implement the three functions.** Escape for systemd: `\` then `"`, then `%` to `%%`. Use `xml.EscapeText` for the plist.
- [ ] **Step 4: Run the same command.** Expected: PASS.
- [ ] **Step 5: Commit** `Add systemd unit and launchd plist generators`.

### Task 2: Install and uninstall

**Files:**
- Modify: `cli/cmd/cervus/service.go`, `cli/cmd/cervus/service_test.go`, `cli/cmd/cervus/main.go` (dispatch and usage)

**Interfaces:**
- Consumes: Task 1 functions.
- Produces: `var runService = func(name string, args ...string) (string, error)`, `var daemonReachable = func() bool`, `cmdInstallService(args []string) error`, `cmdUninstallService(args []string) error`, `serviceDaemonPath() (string, error)`

Linux commands: `systemctl --user daemon-reload`, `systemctl --user is-active cervusd.service`, `systemctl --user enable cervusd.service`, `systemctl --user restart cervusd.service`; uninstall `systemctl --user disable --now cervusd.service`. macOS: `launchctl bootstrap gui/<uid> <plist>`, `launchctl bootout gui/<uid>/cervus.daemon`.

- [ ] **Step 1: Write failing tests**, using a temp `HOME` and a fake `runService` that records calls:
  - `TestInstallWritesUnitAndEnables`: file exists with the unit content; calls happen in the order above.
  - `TestInstallRejectsManualDaemon`: `daemonReachable` true and service not active gives an error containing `already running`; no file; no `enable`.
  - `TestInstallTwiceUpdatesPath`: a second install with a new daemon path rewrites `ExecStart` and restarts.
  - `TestInstallWithoutSystemd`: the runner fails on `daemon-reload`; the error contains `systemd`; no file remains.
  - `TestInstallWarnsAboutCustomSocket`: with `CERVUS_SOCKET` set, output contains `CERVUS_SOCKET`.
  - `TestUninstallRemovesOnlyServiceFile`: a sibling file in `HOME` survives; the `disable --now` call is recorded.
  - `TestUninstallWhenNotInstalled`: returns nil and prints `not installed`.
  - `TestServiceDaemonPathMissing`: error naming `cervusd`.
- [ ] **Step 2: Run** `cd cli && go test ./cmd/cervus/ -run 'Install|Uninstall|ServiceDaemonPath'`. Expected: FAIL.
- [ ] **Step 3: Implement.** Write the file only after `daemon-reload` is known to work, then reload again so systemd sees it. On failure after writing, remove a file this run created. On success print: what started, then `Run \`cervus unlock\` after each login; the vault stays locked until you do.`
- [ ] **Step 4: Run the same command.** Expected: PASS.
- [ ] **Step 5: Commit** `Add cervus install-service and uninstall-service`.

### Task 3: Doctor check, e2e and docs

**Files:**
- Modify: `cli/cmd/cervus/doctor.go`, `cli/cmd/cervus/service.go`, `cli/cmd/cervus/service_test.go`, `scripts/e2e_migrate.sh`, `README.md`, `docs/HANDOFF.md`, `docs/superpowers/plans/2026-11-03-install-service.md`

**Interfaces:**
- Consumes: `serviceFilePath`, `runService`.
- Produces: `func (d *doctor) checkService()`, called first in `cmdDoctor`, before the daemon check and its early exit.

Outcomes: no file gives `[warn]` with the fix `cervus install-service`; a file whose `ExecStart` program is missing gives `[FAIL]` with the fix `cervus install-service`; not active gives `[warn]` with the fix `systemctl --user start cervusd`; active gives `[ ok ]`. On macOS, use `launchctl print gui/<uid>/cervus.daemon` for the active check. If the state cannot be read, `[warn]`, never a crash.

- [ ] **Step 1: Write failing tests**: `TestDoctorService` with one case per outcome above, asserting `fails` and `warns`. In `e2e_migrate.sh`, put a fake `systemctl` first on `PATH` that logs its arguments to `$T`. Add checks: install writes `$HOME/.config/systemd/user/cervusd.service` containing the `bin` path, `doctor` mentions the service, uninstall removes the file, and the vault directory still exists.
- [ ] **Step 2: Run** `cd cli && go test ./cmd/cervus/ -run DoctorService`, then `make build && BIN=$PWD/bin bash scripts/e2e_migrate.sh`. Expected: FAIL on the new checks.
- [ ] **Step 3: Implement `checkService`** and change the `cervusd` fix in `doctor.go` to point at `cervus install-service`. Update README ("Try it", replacing `cervusd &` with `install-service` as the normal path) and `docs/HANDOFF.md` (status table, task 2 done, manual and macOS notes).
- [ ] **Step 4: Run `make test`.** Expected: exit 0, no `FAIL:` lines.
- [ ] **Step 5: Manual check on this Linux machine, with the user.** Install, `systemctl --user status cervusd`, `cervus status`, `cervus doctor`, uninstall. Do this with `CERVUS_SOCKET` unset in a fresh terminal. It uses the real `~/.cervus`, which holds an empty state unless the user initializes it. Record the result in HANDOFF.
- [ ] **Step 6: Commit** `Report the service in doctor; document install-service`, including this plan.

### Task 4: Unlock from `use` and the picker

The user approved this addition in chat on 2026-11-03: after login the vault is locked, and Alt+r must not be a dead end.

**Files:**
- Modify: `cli/cmd/cervus/main.go`, `cli/cmd/cervus/shell.go`, `scripts/pty_test.py`

**Interfaces:**
- Produces: `withUnlock(call func() error, ask func() (string, error)) error`, which runs `call`; on a remote `locked` error it asks once for the passphrase, sends `unlock` and retries. A failed unlock returns that error. `ask` is nil when there is no terminal, which keeps today's error.

- [ ] **Step 1: Write failing tests**: `TestWithUnlock` (not locked calls `ask` zero times; locked asks once and retries; a wrong passphrase returns `wrong passphrase` without a retry; nil `ask` returns the `locked` error). A `pty_test.py` case for each shell: lock, Alt+r, Enter on a role, type the passphrase, expect `Now using role`, and the passphrase is not visible in the terminal output.
- [ ] **Step 2: Run** `cd cli && go test ./cmd/cervus/ -run WithUnlock` and `make build && BIN=$PWD/bin bash scripts/e2e_shell.sh`. Expected: FAIL.
- [ ] **Step 3: Implement.** `cmdUse` uses `readSecret`. `cmdPick` reads bytes from its raw-mode tty reader until Enter, with Ctrl-C cancelling and echo staying off.
- [ ] **Step 4: Run the same commands.** Expected: PASS.
- [ ] **Step 5: Commit** `Offer to unlock the vault when switching roles`.

### Task 5: Sessions survive a missed registration

The user approved this addition in chat on 2026-11-03. A daemon restart forgets sessions and roles, and shells registered only at startup are then never cleaned up. Roles are deliberately not restored after a restart: the user picks again.

**Files:**
- Modify: `cli/cmd/cervusd/api.go`, `cli/cmd/cervus/main.go`, `scripts/e2e_aws.sh`, `docs/PROTOCOL.md`

**Interfaces:**
- Produces: the `use` op takes an optional `pid`; the CLI sends it from `CERVUS_SESSION_OWNER` when that is a valid number. A `pid` of 1 or less is `bad_request`.

- [ ] **Step 1: Write failing test** in `e2e_aws.sh`: start the daemon with `--gc-interval 1s`; run `use dev` with `CERVUS_SESSION_OWNER` set to the PID of a background `sleep`; kill it; wait 3 seconds; `credential-process` for that session reports `no role selected`.
- [ ] **Step 2: Run** `make build && BIN=$PWD/bin bash scripts/e2e_aws.sh`. Expected: FAIL on the new check only.
- [ ] **Step 3: Implement** in `use`: record the PID in `a.pids` when the switch succeeds.
- [ ] **Step 4: Run the same command.** Expected: PASS.
- [ ] **Step 5: Commit** `Register the shell PID when switching roles`.

### Task 6: One socket path with and without XDG_RUNTIME_DIR

A shell without `XDG_RUNTIME_DIR` (some SSH logins) looks in `~/.cervus` while the service listens under `/run/user/<uid>`.

**Files:**
- Modify: `cli/internal/client/client.go`
- Create: `cli/internal/client/client_test.go`

**Interfaces:**
- Produces: `var runUserBase = "/run/user"`. `SocketPath()` order: `CERVUS_SOCKET`, `XDG_RUNTIME_DIR`, then `<runUserBase>/<uid>/cervus/cervus.sock` if that socket exists, then `~/.cervus/cervus.sock`.

- [ ] **Step 1: Write failing tests**: `TestSocketPathFallsBackToRunUser` (socket file present) and `TestSocketPathUsesHomeWithoutRunUser` (absent).
- [ ] **Step 2: Run** `cd cli && go test ./internal/client/`. Expected: FAIL on the first test.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the same command, then `make test`.** Expected: exit 0.
- [ ] **Step 5: Commit** `Find the service socket when XDG_RUNTIME_DIR is unset`.
