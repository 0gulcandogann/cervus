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
  --sts-endpoint "http://127.0.0.1:$PORT/" --idle-secs 3600 --gc-interval 1s 2>"$T/d.log" & D=$!
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

# --- reserved names: key material never leaves through the public secret API
for name in aws-key.work mfa-seed.work; do
  OUT=$(cv secret get "$name" 2>&1); RC=$?
  if [ "$RC" -ne 0 ] && echo "$OUT" | grep -q "managed by Cervus" && ! echo "$OUT" | grep -qE "SUPERSECRETKEYVALUE|AKIATESTKEY|$SEED"; then
    ok "secret get refuses $name"
  else
    bad "secret get refuses $name" # the output is not printed: it may contain the secret
  fi
  printf 'evil' | cv secret put "$name" 2>&1 | grep -q "managed by Cervus" && ok "secret put refuses $name" || bad "secret put refuses $name"
  cv secret rm "$name" 2>&1 | grep -q "managed by Cervus" && ok "secret rm refuses $name" || bad "secret rm refuses $name"
done
check "reserved secrets are still stored" "cv secret list | grep -q aws-key.work && cv secret list | grep -q mfa-seed.work"
printf 'plain-value' | cv secret put note.one
[ "$(cv secret get note.one)" = "plain-value" ] && ok "ordinary secrets still work" || bad "ordinary secrets"

# --- identity.verify_key answers only yes or no, for a caller that already holds the key
api() { python3 -I -c 'import socket,sys; s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); s.sendall(sys.argv[2].encode()+b"\n"); print(s.makefile().readline())' "$CERVUS_SOCKET" "$1"; }
vk() { api "{\"id\":1,\"op\":\"identity.verify_key\",\"params\":{\"id\":\"$1\",\"access_key_id\":\"$2\",\"secret_access_key\":\"$3\"}}"; }
vk work AKIATESTKEY SUPERSECRETKEYVALUE | grep -q '"match":true' && ok "verify_key matches the stored key" || bad "verify_key match"
vk work AKIATESTKEY WRONGVALUE | grep -q '"match":false' && ok "verify_key rejects a wrong secret" || bad "verify_key wrong secret"
vk work AKIAOTHER SUPERSECRETKEYVALUE | grep -q '"match":false' && ok "verify_key rejects a wrong key id" || bad "verify_key wrong id"
vk ghost AKIATESTKEY SUPERSECRETKEYVALUE | grep -q '"code":"not_found"' && ok "verify_key reports an unknown identity" || bad "verify_key unknown identity"
check "verify_key reply does not contain the stored secret" "! vk work AKIATESTKEY WRONGVALUE | grep -q SUPERSECRETKEYVALUE"

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

# --- a shell that never registered (for example, opened before a daemon restart)
sleep 60 & OWNER=$!
CERVUS_SESSION=gc-test CERVUS_SESSION_OWNER=$OWNER cv use dev >/dev/null 2>&1
CERVUS_SESSION=gc-test cv credential-process 2>&1 | grep -q AccessKeyId && ok "use works before the owner exits" || bad "use with an owner pid"
kill "$OWNER"; wait "$OWNER" 2>/dev/null; sleep 3
CERVUS_SESSION=gc-test cv credential-process 2>&1 | grep -q "no role selected" && ok "use registers the shell, so its session is cleaned up" || bad "session cleanup after use"
CERVUS_SESSION=gc-odd CERVUS_SESSION_OWNER=not-a-number cv use dev >/dev/null 2>&1 && ok "an invalid owner value is ignored" || bad "invalid owner"
api '{"id":1,"op":"use","params":{"session":"gc-bad","role":"dev","pid":1}}' | grep -q '"code":"bad_request"' && ok "use refuses pid 1" || bad "use pid 1"

# --- lock behaviour
cv lock >/dev/null
CERVUS_SESSION=shell-a cv credential-process 2>&1 | grep -q "locked" && ok "lock drops cached credentials (refresh needs unlock)" || bad "lock clears cache"
echo "$PASS" | cv unlock >/dev/null
CERVUS_SESSION=shell-a cv credential-process | grep -q ASIAROLEDev && ok "after unlock the shell keeps its role" || bad "role after unlock"
cv role remove stage && ok "role remove" || bad "role remove"
cv identity remove work 2>&1 | grep -q "still uses" && ok "identity in use cannot be removed" || bad "identity remove guard"
cv aws-profile | grep -q "credential_process = .*cervus credential-process" && ok "aws-profile snippet" || bad "aws-profile"

# --- rotating a key and editing roles keep everything else in place
cv identity update work 2>&1 | grep -q "nothing to change" && ok "identity update with no flags explains itself" || bad "identity update no flags"
cv identity update ghost --region eu-west-1 2>&1 | grep -q "unknown identity" && ok "identity update refuses an unknown identity" || bad "identity update unknown"
printf 'AKIABADKEY\nBADSECRET\n' | cv identity update work --rotate-key 2>&1 | grep -q "InvalidClientTokenId" && ok "a rejected new key is refused" || bad "rotate bad key"
vk work AKIATESTKEY SUPERSECRETKEYVALUE | grep -q '"match":true' && ok "a rejected new key keeps the old one" || bad "old key after rejection"
printf 'AKIAOTHERUSER\nOTHERSECRETVALUE\n' | cv identity update work --rotate-key 2>&1 | grep -q "Warning: .*user/tester.*user/other" && ok "a key of another user gets a warning" || bad "rotate other user warning"
printf 'AKIANEWKEY\nNEWSECRETVALUE\n' | cv identity update work --rotate-key >/dev/null 2>&1 && ok "identity update --rotate-key" || bad "rotate key"
vk work AKIANEWKEY NEWSECRETVALUE | grep -q '"match":true' && ok "the vault holds the new key" || bad "new key stored"
cv secret list | grep -q mfa-seed.work && ok "rotating the key keeps the MFA seed" || bad "seed after rotate"
cv role list | grep -q "^dev " && ok "rotating the key keeps the roles" || bad "roles after rotate"
export CERVUS_SESSION=shell-rot
cv use dev >/dev/null 2>&1
check "the next AssumeRole uses the new key, not a stale cache" "grep -q '\"action\": \"AssumeRole\", \"key\": \"AKIANEWKEY\"' $LOG"
check "the new secret is not in plaintext on disk" "! grep -rq NEWSECRETVALUE $T/vault $T/config.json"
cv identity update work --mfa-serial "" 2>&1 | grep -q 'needs MFA' && ok "the MFA serial cannot be cleared while a role needs it" || bad "clear serial guard"
cv identity update work --region us-west-2 >/dev/null && cv identity list | grep -q "us-west-2" && ok "identity update --region" || bad "update region"
cv identity list | grep -q "$SERIAL" && ok "updating the region keeps the MFA serial" || bad "serial after region"

cv role edit dev 2>&1 | grep -q "nothing to change" && ok "role edit with no flags explains itself" || bad "role edit no flags"
cv role edit ghost --mfa none 2>&1 | grep -q "unknown role" && ok "role edit refuses an unknown role" || bad "role edit unknown"
cv role edit dev --mfa nonsense 2>&1 | grep -q "mfa must be" && ok "role edit validates the result" || bad "role edit validation"
cv role edit dev --confirm --no-confirm 2>&1 | grep -q "not both" && ok "role edit refuses --confirm with --no-confirm" || bad "confirm conflict"
cv use dev >/dev/null 2>&1
cv role edit dev --arn arn:aws:iam::123456789012:role/DevTwo && ok "role edit --arn" || bad "role edit arn"
cv credential-process | grep -q ASIAROLEDevTwo && ok "role edit drops the cached credentials; the shell keeps its role" || bad "role cache after edit"
cv role edit dev --confirm >/dev/null; cv use dev 2>&1 </dev/null | grep -q -- "--yes" && ok "role edit --confirm protects the role" || bad "role edit confirm"
cv role edit dev --no-confirm >/dev/null; cv use dev >/dev/null 2>&1 && ok "role edit --no-confirm removes the protection" || bad "role edit no-confirm"
cv role list | grep "^dev " | grep -q "DevTwo" && ok "role edit keeps the other fields" || bad "role edit other fields"

# --- audit log
echo "$PASS" | cv unlock >/dev/null 2>&1
AUD=$(cv audit -n 0)
check "audit log records identity add, role switches and credential issuance" "echo \"\$AUD\" | grep -q 'identity.add.*id=work' && echo \"\$AUD\" | grep -q 'use .*role=prod' && echo \"\$AUD\" | grep -q 'credentials.issued.*role=dev'"
check "audit log records failures with an error code" "echo \"\$AUD\" | grep -q 'result=failed' && echo \"\$AUD\" | grep -q 'error=mfa_code_reused'"
check "audit log records refused access to reserved secrets" "echo \"\$AUD\" | grep -q 'secret.get .*error=denied name=aws-key.work'"
check "audit log records verify_key by identity" "echo \"\$AUD\" | grep -q 'identity.verify_key .*id=work'"
check "audit log records key rotation and role edits" "echo \"\$AUD\" | grep -q 'identity.update .*id=work.*rotate=true' && echo \"\$AUD\" | grep -q 'role.edit .*name=dev'"
check "audit log never contains secrets, TOTP codes or the passphrase" "! grep -qE 'SUPERSECRETKEYVALUE|NEWSECRETVALUE|OTHERSECRETVALUE|AKIANEWKEY|correct horse|$SEED|SECRET-ASIA' $T/audit.log"
check "audit log is mode 600" "[ \"\$(stat -c %a $T/audit.log)\" = 600 ]"
cv audit verify | grep -q intact && ok "audit chain verifies" || bad "audit verify"
cp "$T/audit.log" "$T/audit.bak"
sed -i '0,/"role":"dev"/s//"role":"evil"/' "$T/audit.log"
cv audit verify 2>&1 | grep -q "chain breaks at line" && ok "tampering with an entry is detected" || bad "tamper detection"
cp "$T/audit.bak" "$T/audit.log"

echo; [ "$FAILS" = 0 ] && echo "all AWS checks passed" || { echo "$FAILS check(s) failed"; echo "--- daemon log"; tail -5 "$T/d.log"; exit 1; }
