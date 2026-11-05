#!/usr/bin/env bash
# Shell integration test: real bash (and zsh if $ZSH is set) in a pseudo-terminal.
# Usage: BIN=./bin [ZSH=/path/to/zsh] scripts/e2e_shell.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
export BIN="${BIN:-$HERE/../bin}"
export CERVUS_NO_KEYCHAIN=1 # tests never touch a real keyring
T="$(mktemp -d)"; mkdir -p "$T/run"
export CERVUS_SOCKET="$T/run/cervus.sock"
PASS="correct horse battery"
cleanup() { kill "$(cat "$T/d.pid" 2>/dev/null)" "${M:-}" 2>/dev/null; rm -rf "$T"; }
trap cleanup EXIT

python3 "$HERE/mock_sts.py" "$T/port" "$T/sts.log" & M=$!
for _ in $(seq 50); do [ -s "$T/port" ] && break; sleep 0.1; done
# Stopping and starting the daemon stands in for a reboot: sessions and unlocked vaults are gone.
cat > "$T/restart.sh" <<RESTART
#!/usr/bin/env bash
[ -e "$T/d.pid" ] && kill "\$(cat "$T/d.pid")" 2>/dev/null && sleep 0.5
"$BIN/cervusd" --vault-bin "$BIN/cervus-vault" --vault-dir "$T/vault" --config "$T/config.json" \\
  --sts-endpoint "http://127.0.0.1:$(cat "$T/port")/" --gc-interval 1s 2>>"$T/d.log" </dev/null >/dev/null &
echo \$! > "$T/d.pid"
sleep 1
RESTART
bash "$T/restart.sh"
cv() { "$BIN/cervus" "$@"; }
printf "$PASS\n$PASS\n" | cv init >/dev/null 2>&1
printf 'AKIATESTKEY\nSUPERSECRET\n' | cv identity add work >/dev/null 2>&1
for r in alpha beta; do cv role add $r --identity work --arn arn:aws:iam::123456789012:role/$r >/dev/null; done
cv role add gamma --identity work --arn arn:aws:iam::123456789012:role/gamma --confirm >/dev/null
printf 'other vault passphrase\nother vault passphrase\n' | cv vault create other >/dev/null 2>&1
printf 'AKIATESTKEY\nSUPERSECRET\n' | cv identity add outside --vault other >/dev/null 2>&1
cv role add zeta --identity outside --arn arn:aws:iam::123456789012:role/zeta >/dev/null
CERVUS_TEST_PASS="$PASS" CERVUS_TEST_RESTART="$T/restart.sh" python3 "$HERE/pty_test.py"
