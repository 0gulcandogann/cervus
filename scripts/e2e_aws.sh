#!/usr/bin/env bash
# End-to-end test of identities, roles, MFA and credential_process against a fake STS.
# Usage: BIN=./bin scripts/e2e_aws.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
B="${BIN:-$HERE/../bin}"
T="$(mktemp -d)"; mkdir -p "$T/run"
export CERVUS_SOCKET="$T/run/cervus.sock"
PASS="correct horse battery"
SEED="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
SERIAL="arn:aws:iam::123456789012:mfa/tester"
LOG="$T/sts.log"; : > "$LOG"
FAILS=0
ok()  { echo "PASS: $1"; }
bad() { echo "FAIL: $1"; FAILS=$((FAILS+1)); }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }
cleanup() { kill "${D:-}" "${M:-}" 2>/dev/null; rm -rf "$T"; }
trap cleanup EXIT
cnt() { grep -c "\"action\": \"$1\"" "$LOG" || true; }
cv() { "$B/cervus" "$@"; }

python3 "$HERE/mock_sts.py" "$T/port" "$LOG" & M=$!
for _ in $(seq 50); do [ -s "$T/port" ] && break; sleep 0.1; done
PORT=$(cat "$T/port")
"$B/cervusd" --vault-bin "$B/cervus-vault" --vault-dir "$T/vault" --config "$T/config.json" \
  --sts-endpoint "http://127.0.0.1:$PORT/" --idle-secs 3600 2>"$T/d.log" & D=$!
sleep 1

printf "$PASS\n$PASS\n" | cv init >/dev/null 2>&1
# --- identities
printf 'AKIABADKEY\nBADSECRET\n' | cv identity add bad 2>&1 | grep -q "InvalidClientTokenId" \
  && ok "bad access key rejected by AWS check" || bad "bad access key"
cv identity list | grep -q '^bad ' && bad "rejected identity was saved" || ok "rejected identity not saved"
printf 'AKIATESTKEY\nSUPERSECRETKEYVALUE\n' | cv identity add work --region eu-west-1 --mfa-serial "$SERIAL" 2>&1 | grep -q "tester" \
  && ok "identity add verified with GetCallerIdentity" || bad "identity add"
cv identity list | grep -q "work" && ok "identity listed" || bad "identity list"
check "request was SigV4-signed" "grep -q '\"signed\": true' $LOG && ! grep -q '\"signed\": false' $LOG"
check "access key not in plaintext on disk" "! grep -rq SUPERSECRETKEYVALUE $T/vault $T/config.json"
check "config.json is mode 600" "[ \"\$(stat -c %a $T/config.json)\" = 600 ]"
printf "$SEED\n" | cv identity mfa-import work 2>&1 | grep -q "device only" && ok "mfa seed imported (device-only)" || bad "mfa import"
check "mfa seed stored in local/ only" "ls $T/vault/local | grep -q mfa-seed.work && ! ls $T/vault/secrets | grep -q mfa-seed"

# --- roles
cv role add dev --identity work --arn arn:aws:iam::123456789012:role/Dev && ok "role add dev (no MFA)" || bad "role add dev"
cv role add prod --identity work --arn arn:aws:iam::123456789012:role/Prod --mfa always --confirm && ok "role add prod (MFA always, confirm)" || bad "role add prod"
cv role add stage --identity work --arn arn:aws:iam::123456789012:role/Stage --mfa once && ok "role add stage (MFA once)" || bad "role add stage"
cv role add prodb --identity work --arn arn:aws:iam::123456789012:role/ProdB --mfa always && ok "role add prodb" || bad "role add prodb"
cv role add stage2 --identity work --arn arn:aws:iam::123456789012:role/Stage2 --mfa once && ok "role add stage2" || bad "role add stage2"
cv role add short --identity work --arn arn:aws:iam::123456789012:role/Short && ok "role add short" || bad "role add short"
cv role add nope --identity work --arn arn:aws:iam::123456789012:role/Denied && ok "role add denied" || bad "role add denied"
cv role add bad --identity ghost 2>&1 | grep -q "unknown identity" && ok "role with unknown identity rejected" || bad "role validation"

# --- use + credential_process
export CERVUS_SESSION=shell-a
cv use dev | grep -q "Now using role" && ok "use dev" || bad "use dev"
OUT=$(cv credential-process)
echo "$OUT" | python3 -c 'import sys,json,datetime;d=json.load(sys.stdin);assert d["Version"]==1 and d["AccessKeyId"]=="ASIAROLEDev" and d["SessionToken"]=="TOK-Dev";datetime.datetime.strptime(d["Expiration"],"%Y-%m-%dT%H:%M:%SZ")' \
  && ok "credential-process emits valid Version 1 JSON" || bad "credential-process JSON: $OUT"
N=$(cnt AssumeRole); cv credential-process >/dev/null
check "credentials are cached (no second AssumeRole)" "[ \"\$(grep -c '\"action\": \"AssumeRole\"' $LOG)\" = \"$N\" ]"
cv whoami | grep -q "role dev" && ok "whoami" || bad "whoami"

export CERVUS_SESSION=shell-b
cv use short >/dev/null
cv credential-process >/dev/null
check "short-lived credentials are refreshed on demand" "[ \"\$(grep -c 'role/Short' $LOG)\" -ge 2 ]"
cv use dev >/dev/null
check "two shells hold two different roles" "[ \"\$(CERVUS_SESSION=shell-a $B/cervus credential-process | python3 -c 'import sys,json;print(json.load(sys.stdin)[\"AccessKeyId\"])')\" = ASIAROLEDev ] && CERVUS_SESSION=shell-b $B/cervus use dev >/dev/null"
cv use short >/dev/null
check "switching one shell does not change the other" "CERVUS_SESSION=shell-a $B/cervus credential-process | grep -q ASIAROLEDev"
CERVUS_SESSION=never-used cv credential-process 2>&1 | grep -q "no role selected" && ok "shell without a role is refused" || bad "no-role handling"

# --- confirmation, MFA, errors
cv use prod 2>&1 </dev/null | grep -q -- "--yes" && ok "protected role needs confirmation" || bad "confirm gating"
cv use nope 2>&1 | grep -q "not authorized" && ok "AWS AccessDenied surfaced clearly" || bad "denied error"
cv use prod --yes | grep -q "Now using role" && ok "use prod --yes (fresh TOTP accepted by independent TOTP check)" || bad "use prod"
check "AssumeRole carried serial and 6-digit code" "grep '\"role\": \"arn:aws:iam::123456789012:role/Prod\"' $LOG | grep -q '\"serial\": \"$SERIAL\"' && grep '\"role\": \"arn:aws:iam::123456789012:role/Prod\"' $LOG | grep -Eq '\"code\": \"[0-9]{6}\"'"
cv use prod --yes 2>&1 | grep -q "Now using" && ok "cached MFA-protected role needs no new code" || bad "cached prod reuse"
cv use prodb --yes 2>&1 | grep -q "already used" && ok "reused MFA code is refused with a wait hint" || bad "MFA reuse guard"
echo "(waiting for the next 30s TOTP window...)"; sleep $((31 - $(date +%s) % 30))
cv use stage >/dev/null 2>&1 && ok "use stage (MFA once)" || bad "use stage"
check "mfa=once: session token fetched with MFA, role assumed from it" "grep -q '\"action\": \"GetSessionToken\", \"key\": \"AKIATESTKEY\", \"serial\": \"$SERIAL\"' $LOG && grep '\"role\": \"arn:aws:iam::123456789012:role/Stage\"' $LOG | grep -q '\"key\": \"ASIASESSION\", \"serial\": null'"
cv use stage2 >/dev/null 2>&1 && ok "use stage2 (MFA once, second role)" || bad "use stage2"
check "mfa=once: session token reused, no new MFA code" "[ \"\$(grep -c '\"action\": \"GetSessionToken\", \"key\": \"AKIATESTKEY\"' $LOG)\" = 1 ]"

# --- lock behaviour
cv lock >/dev/null
CERVUS_SESSION=shell-a cv credential-process 2>&1 | grep -q "locked" && ok "lock drops cached credentials (refresh needs unlock)" || bad "lock clears cache"
echo "$PASS" | cv unlock >/dev/null
CERVUS_SESSION=shell-a cv credential-process | grep -q ASIAROLEDev && ok "after unlock the shell keeps its role" || bad "role after unlock"
cv role remove stage && ok "role remove" || bad "role remove"
cv identity remove work 2>&1 | grep -q "still uses" && ok "identity in use cannot be removed" || bad "identity remove guard"
cv aws-profile | grep -q "credential_process = .*cervus credential-process" && ok "aws-profile snippet" || bad "aws-profile"

echo; [ "$FAILS" = 0 ] && echo "all AWS checks passed" || { echo "$FAILS check(s) failed"; echo "--- daemon log"; tail -5 "$T/d.log"; exit 1; }
