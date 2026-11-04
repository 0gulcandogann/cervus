#!/usr/bin/env bash
# Several vaults: one per user if wanted, each with its own passphrase. Uses a fake STS.
# Usage: BIN=./bin scripts/e2e_vaults.sh
set -u
export CERVUS_NO_KEYCHAIN=1 # tests never touch a real keyring
HERE="$(cd "$(dirname "$0")" && pwd)"
B="$(cd "${BIN:-$HERE/../bin}" && pwd)"
T="$(mktemp -d)"; mkdir -p "$T/run"
export CERVUS_SOCKET="$T/run/c.sock"
unset CERVUS_SESSION CERVUS_SESSION_OWNER CERVUS_VAULT
P0="default vault passphrase"; PA="first other passphrase"; PB="second other passphrase"
LOG="$T/sts.log"; : > "$LOG"
FAILS=0
ok()  { echo "PASS: $1"; }
bad() { echo "FAIL: $1"; FAILS=$((FAILS+1)); }
cleanup() { kill "${D:-}" "${M:-}" 2>/dev/null; rm -rf "$T"; }
trap cleanup EXIT
cv() { "$B/cervus" "$@"; }
ROLE=arn:aws:iam::123456789012:role

python3 "$HERE/mock_sts.py" "$T/port" "$LOG" & M=$!
for _ in $(seq 50); do [ -s "$T/port" ] && break; sleep 0.1; done
"$B/cervusd" --vault-bin "$B/cervus-vault" --vault-dir "$T/vault" --config "$T/config.json" \
  --sts-endpoint "http://127.0.0.1:$(cat "$T/port")/" --idle-secs 3600 --gc-interval 1s 2>"$T/d.log" & D=$!
sleep 1
printf "$P0\n$P0\n" | cv init >/dev/null 2>&1

# --- creating vaults
cv vault list | grep -q '^default ' && ok "the default vault is listed" || bad "vault list default"
printf "$PA\n$PA\n" | cv vault create kisisel >"$T/create.txt" 2>&1 && ok "vault create" || bad "vault create"
grep -q "RECOVERY KEY" "$T/create.txt" && ok "a new vault gets its own recovery key" || bad "vault recovery key"
RK=$(grep -o 'AGE-SECRET-KEY-[A-Z0-9]*' "$T/create.txt")
cv vault list | grep '^kisisel ' | grep -q unlocked && ok "a new vault is listed, unlocked" || bad "vault list new"
[ "$(stat -c %a "$T/vaults")" = 700 ] && ok "the vaults folder is private" || bad "vaults folder mode"
printf "$PA\n$PA\n" | cv vault create kisisel 2>&1 | grep -qi "already" && ok "an existing vault is not overwritten" || bad "vault create twice"
for name in ../evil 'a/b' .hidden UPPER; do
  printf "$PA\n$PA\n" | cv vault create "$name" 2>&1 | grep -qi "vault name" && ok "vault name '$name' is refused" || bad "vault name '$name'"
done
[ ! -e "$T/evil" ] && ok "a path in a vault name goes nowhere" || bad "vault path traversal"
printf 'x' | cv secret put --vault ../evil s 2>&1 | grep -qi "vault name" && ok "secret put refuses a bad vault name" || bad "secret bad vault name"

# --- a user in its own vault
printf 'AKIATESTKEY\nSUPERSECRETKEYVALUE\n' | cv identity add ben --vault kisisel --mfa-serial arn:aws:iam::123456789012:mfa/tester >/dev/null 2>&1 && ok "identity add --vault" || bad "identity add --vault"
ls "$T/vaults/kisisel/secrets" | grep -q aws-key.ben && [ ! -e "$T/vault/secrets/aws-key.ben.age" ] && ok "the key is in that vault only" || bad "key location"
printf 'AKIATESTKEY\nSUPERSECRETKEYVALUE\n' | cv identity add orphan --vault nosuch 2>&1 | grep -q "vault create nosuch" && ok "identity add refuses a vault that does not exist" || bad "identity add missing vault"
cv identity list | grep -q '^orphan' && bad "a failed identity was saved" || ok "a failed identity is not saved"
cv identity list | grep '^ben ' | grep -q kisisel && ok "identity list shows the vault" || bad "identity list vault"
printf "AKIABADKEY\nBADSECRET\n" | cv identity add rejected --own-vault 2>&1 | grep -q InvalidClientTokenId && ok "--own-vault refuses a key AWS rejects" || bad "own vault bad key"
cv vault list | grep -q '^rejected ' && bad "a rejected key left a vault behind" || ok "a rejected key leaves no vault behind"
printf "AKIATESTKEY\nSUPERSECRETKEYVALUE\n" | cv identity add ben --own-vault 2>&1 | grep -q "already exists" && ok "--own-vault refuses an existing user" || bad "own vault existing user"
cv vault list | grep -q '^ben ' && bad "an existing user left a vault behind" || ok "an existing user leaves no vault behind"
printf "AKIATESTKEY\nSUPERSECRETKEYVALUE\n" | cv identity add kisisel --own-vault 2>&1 | grep -q -- "--vault kisisel" && ok "--own-vault points to an existing vault of that name" || bad "own vault existing vault"
printf "AKIATESTKEY\nSUPERSECRETKEYVALUE\n$PB\n$PB\n" | cv identity add musteri --own-vault >"$T/own.txt" 2>&1 && ok "identity add --own-vault" || bad "own vault"
grep -q "RECOVERY KEY" "$T/own.txt" && ok "--own-vault shows its recovery key" || bad "own vault recovery"
cv vault list | grep -q '^musteri ' && ls "$T/vaults/musteri/secrets" | grep -q aws-key.musteri && ok "--own-vault creates a vault named after the user" || bad "own vault created"
printf 'AKIATESTKEY\nSUPERSECRETKEYVALUE\n' | cv identity add evde >/dev/null 2>&1 && ls "$T/vault/secrets" | grep -q aws-key.evde && ok "without --vault a user goes to the default vault" || bad "default vault identity"
cv role add dev --identity ben --arn "$ROLE/Dev" >/dev/null
cv role add prod --identity musteri --arn "$ROLE/Prod" >/dev/null
cv role add home --identity evde --arn "$ROLE/Home" >/dev/null
cv role list | grep '^prod ' | grep -q musteri && ok "role list still works across vaults" || bad "role list"

# --- secrets belong to one vault
printf 'value-a' | cv secret put --vault kisisel token >/dev/null 2>&1
[ "$(cv secret get --vault kisisel token 2>/dev/null)" = value-a ] && ok "secret put and get in a named vault" || bad "secret in vault"
cv secret get --vault musteri token 2>&1 | grep -qi "no such secret" && ok "another vault does not see it" || bad "secret isolation"
cv secret get token 2>&1 | grep -qi "no such secret" && ok "the default vault does not see it" || bad "secret isolation default"
cv secret list --vault kisisel | grep -q token && ok "secret list --vault" || bad "secret list vault"
cv secret get --vault kisisel aws-key.ben 2>&1 | grep -q "managed by Cervus" && ok "keys stay blocked in every vault" || bad "reserved in vault"
export CERVUS_SESSION=shell-1
cv use dev >/dev/null 2>&1
printf 'value-b' | cv secret put here >"$T/here.txt" 2>&1
ls "$T/vaults/kisisel/secrets" | grep -q '^here.age' && ok "without --vault, a secret goes to the active role's vault" || bad "active vault secret"
grep -q kisisel "$T/here.txt" && ok "it says which vault it used" || bad "active vault note"
CERVUS_VAULT=musteri cv secret list | grep -q aws-key.musteri && ok "CERVUS_VAULT picks a vault" || bad "CERVUS_VAULT"
unset CERVUS_SESSION

# --- each vault locks and opens alone
export CERVUS_SESSION=shell-2
cv use prod >/dev/null 2>&1 && cv use home >/dev/null 2>&1 && ok "roles work across unlocked vaults" || bad "use across vaults"
cv lock --vault musteri >/dev/null
cv vault list | grep -E '^musteri +locked$' >/dev/null && cv vault list | grep -E '^kisisel +unlocked$' >/dev/null && ok "lock --vault locks only that vault" || bad "lock one vault"
cv use prod </dev/null 2>&1 | grep -q musteri && ok "a locked role names the vault to open" || bad "locked vault name"
cv use home </dev/null >/dev/null 2>&1 && cv credential-process | grep -q ASIAROLEHome && ok "other vaults keep working" || bad "other vault after lock"
echo "$PA" | cv unlock --vault musteri 2>&1 | grep -qi "wrong passphrase" && ok "another vault's passphrase does not open it" || bad "passphrase isolation"
echo "$PB" | cv unlock --vault musteri >/dev/null 2>&1 && cv use prod </dev/null >/dev/null 2>&1 && ok "its own passphrase opens it" || bad "unlock own passphrase"
cv lock --vault prdo 2>&1 | grep -q "vault create prdo" && ok "locking a mistyped vault is an error" || bad "lock typo"
cv lock >/dev/null
L=$(cv vault list); [ -n "$L" ] && ! echo "$L" | grep -q ' unlocked' && ok "lock with no vault locks all of them" || bad "lock all"
cv credential-process </dev/null 2>&1 | grep -qi locked && ok "lock all drops cached credentials" || bad "lock all caches"
echo "$P0" | cv unlock >/dev/null; echo "$PA" | cv unlock --vault kisisel >/dev/null; echo "$PB" | cv unlock --vault musteri >/dev/null
unset CERVUS_SESSION

# --- moving a user between vaults
printf 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\n' | cv identity mfa-import ben >/dev/null 2>&1
ls "$T/vaults/kisisel/local" | grep -q mfa-seed.ben && ok "the MFA seed goes to the user's vault" || bad "seed location"
CERVUS_SESSION=shell-mv cv use dev >/dev/null 2>&1; N=$(grep -c 'role/Dev"' "$LOG")
cv lock --vault musteri >/dev/null
cv identity move ben --vault musteri 2>&1 | grep -q 'vault "musteri" is locked' && ls "$T/vaults/kisisel/secrets" | grep -q aws-key.ben && ok "move refuses a locked target and keeps the key" || bad "move locked"
echo "$PB" | cv unlock --vault musteri >/dev/null
cv identity move ben --vault musteri >/dev/null 2>&1 && ok "identity move" || bad "identity move"
ls "$T/vaults/musteri/secrets" | grep -q aws-key.ben && ls "$T/vaults/musteri/local" | grep -q mfa-seed.ben && ok "key and seed arrive" || bad "move target"
! ls "$T/vaults/kisisel/secrets" "$T/vaults/kisisel/local" | grep -qE 'aws-key.ben|mfa-seed.ben' && ok "key and seed leave the old vault" || bad "move source"
CERVUS_SESSION=shell-3 cv use dev >/dev/null 2>&1 && ok "its roles keep working after the move" || bad "role after move"
[ "$(grep -c 'role/Dev"' "$LOG")" -gt "$N" ] && ok "a move drops the user's cached credentials" || bad "cache after move"
cv identity list | grep '^ben ' | grep -q musteri && ok "identity list shows the new vault" || bad "list after move"
cv identity move ben --vault musteri 2>&1 | grep -qi "already" && ok "moving to the same vault says so" || bad "move same vault"

# --- users without a role
export CERVUS_SESSION=shell-4
cv use user:evde >/dev/null 2>&1 && ok "use user:<name> works without a role" || bad "use user"
cv credential-process | grep -q ASIASESSION && ok "it gets that user's session credentials" || bad "user credentials"
cv whoami | grep -q 'user:evde' && ok "whoami reports the user" || bad "whoami user"
cv use user:ghost 2>&1 | grep -qi unknown && ok "an unknown user is refused" || bad "unknown user"
cv role add 'user:x' --identity evde 2>&1 | grep -qi "role name" && ok "a role cannot be named like a user" || bad "role name user:"
printf 'AKIATESTKEY\nSUPERSECRETKEYVALUE\n' | cv identity add guard >/dev/null 2>&1
cv role add guarded --identity guard --arn "$ROLE/Guarded" --confirm >/dev/null
cv use user:guard </dev/null 2>&1 | grep -q -- "--yes" && ok "a user with a protected role needs confirmation too" || bad "user skips confirm"
cv use user:guard --yes >/dev/null 2>&1 && ok "--yes confirms the user" || bad "user --yes"
cv role add plain --identity evde --arn "$ROLE/Plain" >/dev/null
cv use user:evde >/dev/null 2>&1; cv role edit plain --confirm >/dev/null
cv credential-process 2>&1 | grep -q "no role selected" && ok "protecting a role takes shells off its user" || bad "user session after role edit"
cv role edit plain --no-confirm >/dev/null; cv use user:evde >/dev/null 2>&1
printf 'AKIATESTKEY\nSUPERSECRETKEYVALUE\n' | cv identity add gone >/dev/null 2>&1; cv use user:gone >/dev/null 2>&1
cv identity remove gone >/dev/null; cv credential-process 2>&1 | grep -q "no role selected" && ok "removing a user ends its sessions" || bad "user session after remove"
S=arn:aws:iam::123456789012:mfa/tester
printf 'AKIATESTKEY\nSUPERSECRETKEYVALUE\n' | cv identity add mfauser --mfa-serial "$S" >/dev/null 2>&1
cv use user:mfauser 2>&1 | grep -q "mfa-import" && ok "a user with an MFA device keeps needing MFA" || bad "user drops MFA"
cv use user:evde >/dev/null 2>&1
unset CERVUS_SESSION

# --- other vault-aware commands
printf '%s\n%s\n%s\n' "$PA" "$PA second" "$PA second" | cv passwd --vault kisisel >/dev/null 2>&1 && ok "passwd --vault" || bad "passwd vault"
cv lock --vault kisisel >/dev/null
echo "$PA second" | cv unlock --vault kisisel >/dev/null 2>&1 && ok "the new passphrase opens that vault" || bad "unlock after passwd"
echo "$P0" | cv unlock >/dev/null 2>&1 && ok "the default vault's passphrase did not change" || bad "default after passwd"
cv lock --vault kisisel >/dev/null
printf "$RK\n$PA\n$PA\n" | cv recover --vault kisisel >/dev/null 2>&1 && ok "recover --vault" || bad "recover vault"
cv audit -n 0 | grep -qE 'Z lock +.*vault=musteri' && cv audit -n 0 | grep -q 'identity.move .*vault=musteri' && cv audit -n 0 | grep -q 'unlock .*vault=kisisel' && ok "the audit log names the vault" || bad "audit vault"
! grep -qE "$P0|$PA|$PB|SUPERSECRETKEYVALUE|value-a" "$T/audit.log" "$T/d.log" "$T/config.json" && ok "no secrets in logs or config" || bad "secrets in logs"
cv doctor 2>&1 | grep -q "daemon is running" && ok "doctor runs" || bad "doctor"
cv status >/dev/null && ok "status runs" || bad "status"

# --- locking one vault leaves the others alone
export CERVUS_SESSION=shell-5
cv use home >/dev/null 2>&1; N=$(grep -c 'role/Home"' "$LOG")
cv lock --vault musteri >/dev/null
cv credential-process | grep -q ASIAROLEHome && [ "$(grep -c 'role/Home"' "$LOG")" = "$N" ] && ok "locking another vault keeps this one's cached credentials" || bad "lock clears others"
printf "not a key\n$PB\n$PB\n" | cv recover --vault ../bad >/dev/null 2>&1
printf "not a key\n$PB\n$PB\n" | cv recover --vault kisisel >/dev/null 2>&1
cv credential-process >/dev/null && [ "$(grep -c 'role/Home"' "$LOG")" = "$N" ] && ok "a failed recover clears nothing" || bad "recover clears"
unset CERVUS_SESSION
echo "$PB" | cv unlock --vault musteri >/dev/null

# --- secret rm never guesses
export CERVUS_SESSION=shell-6
cv use prod >/dev/null 2>&1
printf 'x' | cv secret put --vault musteri pick >/dev/null 2>&1
cv secret rm pick 2>&1 | grep -q -- "--vault" && cv secret list --vault musteri | grep -q '^pick' && ok "secret rm needs a named vault when one is only implied" || bad "secret rm implied"
cv secret rm --vault musteri pick >/dev/null 2>&1 && ! cv secret list --vault musteri | grep -q '^pick' && ok "secret rm --vault works" || bad "secret rm named"
unset CERVUS_SESSION

# --- a bad vault in a hand-edited config goes nowhere
cp "$T/config.json" "$T/config.bak"
python3 -I -c 'import json,sys; p=sys.argv[1]; c=json.load(open(p)); c["identities"]["evde"]["vault"]="../../evil"; json.dump(c,open(p,"w"))' "$T/config.json"
CERVUS_SESSION=shell-7 cv use home 2>&1 | grep -q "vault name" && ok "a bad vault in the config is refused" || bad "bad vault in config"
[ ! -e "$T/../evil" ] && ok "it creates nothing" || bad "bad vault created something"
cp "$T/config.bak" "$T/config.json"

# --- the keychain hold works per vault, against a fake secret-tool
mkdir -p "$T/fakebin"; cp "$HERE/fake_secret_tool.sh" "$T/fakebin/secret-tool"; chmod +x "$T/fakebin/secret-tool"
(
  unset CERVUS_NO_KEYCHAIN
  export PATH="$T/fakebin:$PATH" FAKE_KEYRING="$T/fake-keyring" CERVUS_SESSION=shell-8
  [ "$(command -v secret-tool)" = "$T/fakebin/secret-tool" ] || { echo "FAIL: the fake secret-tool is not in use"; exit 1; }
  echo "$PB" | cv keychain enable --yes --vault musteri >/dev/null 2>&1
  cv use prod >/dev/null 2>&1
  cv lock --vault musteri >/dev/null
  cv credential-process </dev/null 2>&1 | grep -q musteri && ok "a hold keeps that vault locked" || bad "hold named vault"
  cv lock >/dev/null
  [ -e "$T/vaults/musteri/keychain-hold" ] && ok "lock all sets the hold there too" || bad "hold on lock all"
  cv unlock --vault musteri </dev/null >/dev/null 2>&1 && cv credential-process </dev/null | grep -q ASIAROLEProd && ok "unlock --vault ends the hold" || bad "unlock hold"
  cv keychain disable --vault musteri >/dev/null
  exit $((FAILS > 0))
)
[ $? = 0 ] || FAILS=$((FAILS+1))
echo "$P0" | cv unlock >/dev/null; echo "$PA" | cv unlock --vault kisisel >/dev/null 2>&1

# --- a named vault locks by itself when idle
(
  export CERVUS_SOCKET="$T/run/idle.sock" CERVUS_SESSION=idle
  mkdir -p "$T/idle"
  "$B/cervusd" --socket "$CERVUS_SOCKET" --vault-bin "$B/cervus-vault" --vault-dir "$T/idle/vault" --config "$T/idle/config.json" \
    --sts-endpoint "http://127.0.0.1:$(cat "$T/port")/" --idle-secs 3 --gc-interval 1h 2>/dev/null & I=$!
  sleep 1
  printf "$P0\n$P0\n" | cv vault create idlev >/dev/null 2>&1
  printf 'AKIATESTKEY\nSUPERSECRETKEYVALUE\n' | cv identity add idleuser --vault idlev >/dev/null 2>&1
  cv role add idlerole --identity idleuser --arn "$ROLE/IdleRole" >/dev/null
  cv use idlerole >/dev/null 2>&1
  sleep 4
  cv credential-process </dev/null 2>&1 | grep -q idlev && ok "idle lock of a named vault stops its cached credentials" || bad "idle named vault"
  kill "$I" 2>/dev/null
  exit $((FAILS > 0))
)
[ $? = 0 ] || FAILS=$((FAILS+1))

echo; [ "$FAILS" = 0 ] && echo "all vault checks passed" || { echo "$FAILS check(s) failed"; exit 1; }
