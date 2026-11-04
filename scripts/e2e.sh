#!/usr/bin/env bash
# End-to-end test: cervusd + cervus-vault + cervus CLI in a temp directory.
# Usage: BIN=./bin scripts/e2e.sh
set -u
B="${BIN:-$(cd "$(dirname "$0")/.." && pwd)/bin}"
export CERVUS_NO_KEYCHAIN=1 # tests never touch a real keyring; the keychain block uses a fake
T="$(mktemp -d)"; mkdir -p "$T/run"
export CERVUS_SOCKET="$T/run/cervus.sock"
PASS="correct horse battery"
FAILS=0
ok()  { echo "PASS: $1"; }
bad() { echo "FAIL: $1"; FAILS=$((FAILS+1)); }
cleanup() { kill "${D:-}" 2>/dev/null; rm -rf "$T"; }
trap cleanup EXIT

start() { "$B/cervusd" --vault-bin "$B/cervus-vault" --vault-dir "$T/vault" --config "$T/config.json" --idle-secs "$1" 2>>"$T/d.log" & D=$!; sleep 1; }

start 3600
"$B/cervus" status | grep -q "not initialized" && ok "status before init" || bad "status before init"
printf "$PASS\n$PASS\n" | "$B/cervus" init >"$T/init.out" 2>&1 && grep -q "RECOVERY KEY" "$T/init.out" && ok "init prints recovery key" || bad init
printf 'AKIA-TOP-SECRET-VALUE' | "$B/cervus" secret put aws-work && ok "put" || bad put
printf 'seed-123' | "$B/cervus" secret put --local --type mfa_seed mfa-work && ok "put local" || bad "put local"
[ "$("$B/cervus" secret get aws-work)" = "AKIA-TOP-SECRET-VALUE" ] && ok "get roundtrip" || bad "get roundtrip"
grep -rq "AKIA-TOP-SECRET" "$T/vault" && bad "plaintext secret on disk" || ok "no plaintext secret on disk"
grep -rq "$PASS" "$T/vault" && bad "passphrase on disk" || ok "no passphrase on disk"
perm() { stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1"; }
[ "$(perm "$CERVUS_SOCKET")" = 600 ] && [ "$(perm "$T/run")" = 700 ] && [ "$(perm "$T/vault")" = 700 ] \
  && [ "$(perm "$T/vault/device.key.age")" = 600 ] && ok "file and socket permissions" || bad "permissions"
"$B/cervus" lock >/dev/null
"$B/cervus" secret get aws-work 2>&1 | grep -qi locked && ok "locked vault refuses reads" || bad "locked refuses reads"
echo "wrong passphrase!" | "$B/cervus" unlock 2>&1 | grep -qi "wrong passphrase" && ok "wrong passphrase rejected" || bad "wrong passphrase"
echo "$PASS" | "$B/cervus" unlock >/dev/null && ok unlock || bad unlock

RAW=$(python3 - "$CERVUS_SOCKET" <<'PY'
import socket, sys
s = socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])
s.sendall(b'{"id":7,"op":"put_raw_internal"}\n'); print(s.makefile().readline())
PY
)
echo "$RAW" | grep -q unknown_op && ok "non-allowlisted op rejected" || bad "allowlist"

pkill -P "$D" -x cervus-vault; sleep 0.5
"$B/cervus" secret get aws-work 2>&1 | grep -q "crashed" && ok "vault crash reported cleanly" || bad "crash report"
"$B/cervus" status | grep -q locked && ok "restarted vault is locked" || bad "restart locked"
echo "$PASS" | "$B/cervus" unlock >/dev/null
[ "$("$B/cervus" secret get aws-work)" = "AKIA-TOP-SECRET-VALUE" ] && ok "data survives crash" || bad "data after crash"

kill "$D"; sleep 0.5
[ -e "$CERVUS_SOCKET" ] && bad "socket left behind" || ok "socket removed on shutdown"

start 2
echo "$PASS" | "$B/cervus" unlock >/dev/null; sleep 3
"$B/cervus" secret get aws-work 2>&1 | grep -qi locked && ok "idle timeout auto-locks" || bad "idle timeout"

kill "$D" 2>/dev/null; sleep 0.5

# --- recovery with the recovery key (fresh vault)
"$B/cervusd" --vault-bin "$B/cervus-vault" --vault-dir "$T/vault2" --config "$T/config.json" 2>>"$T/d.log" & D3=$!
sleep 1
printf "$PASS\n$PASS\n" | "$B/cervus" init >"$T/init2.out" 2>&1
RK=$(grep -o 'AGE-SECRET-KEY-[A-Z0-9]*' "$T/init2.out")
printf 'shared-value' | "$B/cervus" secret put shared-one >/dev/null
printf 'seed-value' | "$B/cervus" secret put --local seed-one >/dev/null
"$B/cervus" lock >/dev/null
NEW="a completely new passphrase"
printf "WRONG-KEY\n$NEW\n$NEW\n" | "$B/cervus" recover 2>&1 | grep -qi "not a valid recovery key" && ok "invalid recovery key rejected" || bad "invalid recovery key"
printf "$RK\n$NEW\n$NEW\n" | "$B/cervus" recover >"$T/rec.out" 2>&1 && grep -q "1 secret(s) re-encrypted" "$T/rec.out" && ok "recover re-encrypts synced secrets" || bad "recover"
grep -q "seed-one" "$T/rec.out" && ok "recover reports the device-only secret it could not restore" || bad "recover lost-local report"
"$B/cervus" secret get shared-one 2>&1 | grep -q shared-value && ok "synced secret readable after recovery" || bad "secret after recovery"
"$B/cervus" lock >/dev/null
echo "$PASS" | "$B/cervus" unlock 2>&1 | grep -qi "wrong passphrase" && ok "old passphrase no longer works" || bad "old passphrase"
echo "$NEW" | "$B/cervus" unlock >/dev/null && ok "new passphrase works" || bad "new passphrase"
printf "$RK\n$NEW\n$NEW\n" | "$B/cervus" recover --drop-local >/dev/null 2>&1
"$B/cervus" secret list | grep -q seed-one && bad "stale local secret not dropped" || ok "--drop-local removes the stale device-only secret"
# --- changing the passphrase
NEW2="yet another long passphrase"
printf 'WRONG-CURRENT-PASS\n%s\n%s\n' "$NEW2" "$NEW2" | "$B/cervus" passwd 2>&1 | grep -qi "wrong passphrase" && ok "passwd refuses a wrong current passphrase" || bad "passwd wrong current"
printf '%s\nshort\nshort\n' "$NEW" | "$B/cervus" passwd 2>&1 | grep -q "at least 10" && ok "passwd refuses a short passphrase" || bad "passwd short"
printf '%s\n%s\nno match here\n' "$NEW" "$NEW2" | "$B/cervus" passwd 2>&1 | grep -q "do not match" && ok "passwd refuses mismatched passphrases" || bad "passwd mismatch"
printf '%s\n%s\n%s\n' "$NEW" "$NEW2" "$NEW2" | "$B/cervus" passwd >/dev/null 2>&1 && ok "passwd succeeds" || bad "passwd"
"$B/cervus" secret get shared-one 2>&1 | grep -q shared-value && ok "the vault stays usable after passwd" || bad "secret after passwd"
"$B/cervus" lock >/dev/null
echo "$NEW" | "$B/cervus" unlock 2>&1 | grep -qi "wrong passphrase" && ok "the old passphrase stops working" || bad "old passphrase after passwd"
echo "$NEW2" | "$B/cervus" unlock >/dev/null && ok "the new passphrase unlocks" || bad "new passphrase after passwd"
printf "$RK\n$NEW\n$NEW\n" | "$B/cervus" recover >/dev/null 2>&1 && ok "the recovery key survives passwd" || bad "recovery after passwd"
grep -q "cervus recover" <(printf '%s\n%s\n%s\n' "$NEW" "$NEW2" "$NEW2" | "$B/cervus" passwd 2>&1) && ok "passwd explains what to do after a leak" || bad "passwd leak note"
! grep -rqE "$NEW2|$NEW|WRONG-CURRENT-PASS" "$T/config.json" "$T/d.log" "$T"/audit.log "$T/vault2" 2>/dev/null && ok "no passphrase in the logs" || bad "passphrase in logs"
# --- keychain, against a fake secret-tool
mkdir -p "$T/fakebin"; cp "$(dirname "$0")/fake_secret_tool.sh" "$T/fakebin/secret-tool"; chmod +x "$T/fakebin/secret-tool"
(
  export PATH="$T/fakebin:$PATH" FAKE_KEYRING="$T/fake-keyring"
  [ "$(command -v secret-tool)" = "$T/fakebin/secret-tool" ] || { echo "FAIL: the fake secret-tool is not in use"; exit 1; }
  echo "$NEW2" | "$B/cervus" keychain enable --yes 2>&1 | grep -q "CERVUS_NO_KEYCHAIN" && [ ! -e "$FAKE_KEYRING" ] && ok "CERVUS_NO_KEYCHAIN blocks enable" || bad "enable under CERVUS_NO_KEYCHAIN"
  "$B/cervus" keychain status | grep -q "CERVUS_NO_KEYCHAIN" && ok "status names CERVUS_NO_KEYCHAIN" || bad "status under CERVUS_NO_KEYCHAIN"
  unset CERVUS_NO_KEYCHAIN
  "$B/cervus" keychain status | grep -q "not stored" && ok "keychain starts empty" || bad "keychain status empty"
  "$B/cervus" lock >/dev/null; echo "$NEW2" | "$B/cervus" unlock >/dev/null; "$B/cervus" doctor >/dev/null 2>&1
  [ ! -e "$FAKE_KEYRING.args" ] && ok "without opting in, nothing calls secret-tool" || bad "secret-tool called without opt-in: $(cat "$FAKE_KEYRING.args")"
  echo "$NEW2" | "$B/cervus" keychain enable 2>&1 | grep -q -- "--yes" && [ ! -e "$FAKE_KEYRING" ] && ok "keychain enable needs --yes without a terminal" || bad "keychain needs --yes"
  echo "not the passphrase" | "$B/cervus" keychain enable --yes 2>&1 | grep -qi "wrong passphrase" && [ ! -e "$FAKE_KEYRING" ] && ok "keychain enable refuses a wrong passphrase" || bad "keychain wrong passphrase"
  echo "$NEW2" | "$B/cervus" keychain enable --yes > "$T/kc.txt" 2>&1 && ok "keychain enable succeeds" || bad "keychain enable: $(cat "$T/kc.txt")"
  grep -q "any program running as you" "$T/kc.txt" && grep -q "MFA" "$T/kc.txt" && grep -q "cervus recover" "$T/kc.txt" && ok "keychain enable states the trade-offs" || bad "keychain warning"
  [ "$(cat "$FAKE_KEYRING")" = "$NEW2" ] && ok "the passphrase is stored" || bad "keychain stored value"
  "$B/cervus" keychain status | grep -q "is stored" && ok "keychain status reports it" || bad "keychain status stored"
  "$B/cervus" audit -n 0 | grep -q 'keychain.event .*action=enabled' && ok "the audit log records enabling" || bad "audit enable"
  : > "$FAKE_KEYRING.args"
  "$B/cervus" lock | grep -q "cervus unlock" && ok "lock says it holds until cervus unlock" || bad "lock note"
  ! grep -q lookup "$FAKE_KEYRING.args" && ok "lock does not read the passphrase" || bad "lock read the passphrase"
  "$B/cervus" unlock </dev/null 2>&1 | grep -q "unlocked" && ok "unlock uses the keychain without asking" || bad "keychain unlock"
  "$B/cervus" audit -n 3 | grep -q 'unlock .*source=keychain' && ok "the audit log marks a keychain unlock" || bad "audit unlock source"
  "$B/cervus" secret get shared-one 2>&1 | grep -q shared-value && ok "the vault is open after a keychain unlock" || bad "secret after keychain unlock"
  printf '%s\n%s\n%s\n' "$NEW2" "$NEW" "$NEW" | "$B/cervus" passwd >/dev/null 2>&1
  [ "$(cat "$FAKE_KEYRING")" = "$NEW" ] && ok "passwd updates the stored passphrase" || bad "keychain after passwd"
  printf "$RK\n$NEW2\n$NEW2\n" | "$B/cervus" recover >/dev/null 2>&1
  [ "$(cat "$FAKE_KEYRING")" = "$NEW2" ] && ok "recover updates the stored passphrase" || bad "keychain after recover"
  touch "$FAKE_KEYRING.closed"
  "$B/cervus" keychain status | grep -q "could not be read" && ok "a closed keyring is not reported as empty" || bad "status closed keyring"
  "$B/cervus" doctor 2>&1 | grep -q "could not be read" && ok "doctor reports a closed keyring" || bad "doctor closed keyring"
  printf '%s\n%s\n%s\n' "$NEW2" "$NEW" "$NEW" | "$B/cervus" passwd 2>&1 | grep -q "could not update the keychain" && ok "passwd warns when it cannot update a closed keyring" || bad "passwd closed keyring"
  rm -f "$FAKE_KEYRING.closed"
  "$B/cervus" lock >/dev/null
  echo "$NEW" | "$B/cervus" unlock > "$T/kc2.txt" 2>&1; grep -q "refused" "$T/kc2.txt" && grep -q "unlocked" "$T/kc2.txt" && ok "a stale stored passphrase falls back to asking" || bad "keychain stale"
  ! grep -qE "$NEW|$NEW2" "$FAKE_KEYRING.args" && ok "no passphrase in secret-tool arguments" || bad "passphrase in arguments"
  ! grep -qE "$NEW|$NEW2" "$T/d.log" "$T/audit.log" 2>/dev/null && ok "no passphrase in the logs after keychain use" || bad "keychain passphrase in logs"
  "$B/cervus" keychain disable >/dev/null && [ ! -e "$FAKE_KEYRING" ] && ok "keychain disable removes it" || bad "keychain disable"
  "$B/cervus" audit -n 3 | grep -q 'keychain.event .*action=disabled' && ok "the audit log records disabling" || bad "audit disable"
  "$B/cervus" lock >/dev/null; "$B/cervus" unlock </dev/null >/dev/null 2>&1 && bad "unlock succeeded with nothing stored" || ok "after disable, unlock needs the passphrase again"
  exit $((FAILS > 0))
)
[ $? = 0 ] || FAILS=$((FAILS+1))
kill "$D3" 2>/dev/null

echo; [ "$FAILS" = 0 ] && echo "all checks passed" || { echo "$FAILS check(s) failed"; exit 1; }
