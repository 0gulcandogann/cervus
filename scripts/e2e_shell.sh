#!/usr/bin/env bash
# Shell integration test: real bash (and zsh if $ZSH is set) in a pseudo-terminal.
# Usage: BIN=./bin [ZSH=/path/to/zsh] scripts/e2e_shell.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
export BIN="${BIN:-$HERE/../bin}"
T="$(mktemp -d)"; mkdir -p "$T/run"
export CERVUS_SOCKET="$T/run/cervus.sock"
PASS="correct horse battery"
cleanup() { kill "${D:-}" "${M:-}" 2>/dev/null; rm -rf "$T"; }
trap cleanup EXIT

python3 "$HERE/mock_sts.py" "$T/port" "$T/sts.log" & M=$!
for _ in $(seq 50); do [ -s "$T/port" ] && break; sleep 0.1; done
"$BIN/cervusd" --vault-bin "$BIN/cervus-vault" --vault-dir "$T/vault" --config "$T/config.json" \
  --sts-endpoint "http://127.0.0.1:$(cat "$T/port")/" --gc-interval 1s 2>"$T/d.log" & D=$!
sleep 1
cv() { "$BIN/cervus" "$@"; }
printf "$PASS\n$PASS\n" | cv init >/dev/null 2>&1
printf 'AKIATESTKEY\nSUPERSECRET\n' | cv identity add work >/dev/null 2>&1
for r in alpha beta; do cv role add $r --identity work --arn arn:aws:iam::123456789012:role/$r >/dev/null; done
cv role add gamma --identity work --arn arn:aws:iam::123456789012:role/gamma --confirm >/dev/null
CERVUS_TEST_PASS="$PASS" python3 "$HERE/pty_test.py"
