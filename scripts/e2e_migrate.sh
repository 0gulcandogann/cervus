#!/usr/bin/env bash
# Tests `cervus migrate` and `cervus doctor` with throwaway AWS files and a fake STS.
# Usage: BIN=./bin scripts/e2e_migrate.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
B="${BIN:-$HERE/../bin}"
export CERVUS_NO_KEYCHAIN=1 # tests never touch a real keyring
T="$(mktemp -d)"; mkdir -p "$T/run" "$T/aws"
export CERVUS_SOCKET="$T/run/cervus.sock" HOME="$T/home"; mkdir -p "$HOME"
export AWS_SHARED_CREDENTIALS_FILE="$T/aws/credentials" AWS_CONFIG_FILE="$T/aws/config"
unset AWS_ACCESS_KEY_ID AWS_PROFILE CERVUS_SESSION CERVUS_SESSION_OWNER
PASS="correct horse battery"; SERIAL="arn:aws:iam::123456789012:mfa/me"
FAILS=0
ok()  { echo "PASS: $1"; }
bad() { echo "FAIL: $1"; FAILS=$((FAILS+1)); }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }
cleanup() { kill "${D:-}" "${M:-}" "$(cat "$T/svc.pid" 2>/dev/null)" 2>/dev/null; rm -rf "$T"; }
trap cleanup EXIT
cv() { "$B/cervus" "$@"; }

python3 "$HERE/mock_sts.py" "$T/port" "$T/sts.log" & M=$!
for _ in $(seq 50); do [ -s "$T/port" ] && break; sleep 0.1; done
"$B/cervusd" --vault-bin "$B/cervus-vault" --vault-dir "$T/vault" --config "$T/config.json" \
  --sts-endpoint "http://127.0.0.1:$(cat "$T/port")/" 2>"$T/d.log" & D=$!
sleep 1
printf "$PASS\n$PASS\n" | cv init >/dev/null 2>&1

cat > "$AWS_SHARED_CREDENTIALS_FILE" <<CRED
# keys of mine
[default]
aws_access_key_id = AKIATESTKEY
aws_secret_access_key = PLAINTEXTSECRETVALUE

[broken]
aws_access_key_id = AKIABADKEY
aws_secret_access_key = whatever

[temp]
aws_access_key_id = ASIATEMP
aws_secret_access_key = x
aws_session_token = tok
CRED
chmod 644 "$AWS_SHARED_CREDENTIALS_FILE"
cat > "$AWS_CONFIG_FILE" <<CFG
[default]
region = eu-west-1

[profile dev]
role_arn = arn:aws:iam::123456789012:role/Dev
source_profile = default

[profile prod]
role_arn = arn:aws:iam::123456789012:role/Prod
source_profile = default
mfa_serial = $SERIAL

[profile sso]
sso_start_url = https://example.awsapps.com/start
CFG

# --- doctor before
cv doctor > "$T/doc1.txt" 2>&1; RC=$?
check "doctor finds plaintext keys and a world-readable credentials file" "grep -q '2 plaintext access key' $T/doc1.txt && grep -q 'FAIL.*credentials file' $T/doc1.txt"
check "doctor suggests the aws profile and shell setup" "grep -q 'aws-profile --install' $T/doc1.txt && grep -q 'init-shell' $T/doc1.txt"
check "doctor exits non-zero when something is wrong" "[ $RC -ne 0 ]"

# --- migrate
HASH=$(sha256sum "$AWS_SHARED_CREDENTIALS_FILE" | cut -d' ' -f1)
cv migrate --dry-run > "$T/dry.txt" 2>&1
check "dry-run shows the plan" "grep -q 'identity default' $T/dry.txt && grep -q 'role     prod' $T/dry.txt && grep -q 'skipped profile \"temp\"' $T/dry.txt"
check "dry-run changes nothing" "[ \"\$(sha256sum $AWS_SHARED_CREDENTIALS_FILE | cut -d' ' -f1)\" = $HASH ]"

cv migrate --yes > "$T/mig.txt" 2>&1
check "good key migrated" "grep -q 'ok identity default' $T/mig.txt"
check "bad key rejected by AWS and left alone" "grep -q 'FAILED identity broken' $T/mig.txt && grep -q AKIABADKEY $AWS_SHARED_CREDENTIALS_FILE"
check "roles imported" "grep -q 'ok role dev' $T/mig.txt && grep -q 'ok role prod' $T/mig.txt"
check "plaintext secret removed from the credentials file" "! grep -q PLAINTEXTSECRETVALUE $AWS_SHARED_CREDENTIALS_FILE && ! grep -q AKIATESTKEY $AWS_SHARED_CREDENTIALS_FILE"
check "unrelated content kept (comment, temp creds, bad key)" "grep -q '# keys of mine' $AWS_SHARED_CREDENTIALS_FILE && grep -q ASIATEMP $AWS_SHARED_CREDENTIALS_FILE && grep -q '\\[broken\\]' $AWS_SHARED_CREDENTIALS_FILE"
check "credentials file is mode 600 afterwards" "[ \"\$(stat -c %a $AWS_SHARED_CREDENTIALS_FILE)\" = 600 ]"
check "secret is not in plaintext in the vault dir" "! grep -rq PLAINTEXTSECRETVALUE $T/vault"
check "identity carries the region and MFA serial" "cv identity list | grep -q 'default.*eu-west-1.*mfa/me'"
check "prod role is mfa=always, dev is mfa=none" "cv role list | grep -E '^prod ' | grep -q 'mfa=always' && cv role list | grep -E '^dev ' | grep -q 'mfa=none'"
export CERVUS_SESSION=mig1
check "migrated key works: use dev reaches AWS" "cv use dev 2>&1 | grep -q 'Now using role'"
cv use prod 2>&1 | grep -q "no MFA seed" && ok "prod explains that the MFA seed is missing" || bad "prod MFA message"

cv migrate --yes > "$T/mig2.txt" 2>&1
check "second run does not migrate the same identity again" "grep -q 'already exists in Cervus' $T/mig2.txt"

# --- doctor after
cv doctor > "$T/doc2.txt" 2>&1
check "doctor now sees 1 remaining plaintext key" "grep -q '1 plaintext access key' $T/doc2.txt"
check "doctor warns about the missing MFA seed" "grep -q 'MFA roles but no MFA seed' $T/doc2.txt"
printf 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\n' | cv identity mfa-import default >/dev/null 2>&1
cv doctor > "$T/doc3.txt" 2>&1
check "after mfa-import the MFA warning is gone" "! grep -q 'MFA roles but no MFA seed' $T/doc3.txt"
check "doctor reports permissions as fine" "grep -q 'ok.*vault directory permissions' $T/doc3.txt && grep -q 'ok.*device key permissions' $T/doc3.txt"

cv aws-profile --install >/dev/null 2>&1; export HOME
cv doctor > "$T/doc4.txt" 2>&1
check "doctor accepts the installed AWS profile" "grep -q 'ok.*AWS CLI profile' $T/doc4.txt"

kill "$D"; sleep 0.5
cv doctor > "$T/doc5.txt" 2>&1; RC=$?
check "doctor with the daemon down fails clearly" "grep -q 'FAIL.*daemon is not reachable' $T/doc5.txt && [ $RC -eq 1 ]"

# --- install-service, with a fake systemctl: the real service manager is never called
unset XDG_CONFIG_HOME
mkdir -p "$T/fakebin" "$T/xdg"; chmod 700 "$T/xdg"
SAVED_XDG=${XDG_RUNTIME_DIR:-}; export XDG_RUNTIME_DIR="$T/xdg"
BIN_ABS="$(cd "$B" && pwd)"
cat > "$T/fakebin/systemctl" <<FAKE
#!/usr/bin/env bash
echo "\$*" >> "$T/systemctl.log"
case "\$*" in
  *is-active*) if [ -e "$T/svc.pid" ]; then echo active; else echo inactive; exit 3; fi ;;
  *restart*) "$BIN_ABS/cervusd" --socket "$T/xdg/cervus/cervus.sock" --vault-bin "$BIN_ABS/cervus-vault" --vault-dir "$T/svc-vault" --config "$T/svc.json" >/dev/null 2>&1 & echo \$! > "$T/svc.pid" ;;
  *disable*) [ -e "$T/svc.pid" ] && kill "\$(cat "$T/svc.pid")"; rm -f "$T/svc.pid" ;;
esac
exit 0
FAKE
chmod +x "$T/fakebin/systemctl"
UNIT="$HOME/.config/systemd/user/cervusd.service"
SAVED_PATH=$PATH; export PATH="$T/fakebin:$PATH"
cv doctor 2>&1 | grep -q "cervus install-service" && ok "doctor suggests install-service" || bad "doctor suggests install-service"
cv install-service > "$T/inst.txt" 2>&1 && ok "install-service succeeds" || bad "install-service: $(cat "$T/inst.txt")"
grep -qF "ExecStart=\"$BIN_ABS/cervusd\"" "$UNIT" && ok "unit points at this cervusd" || bad "unit path"
grep -q 'enable cervusd.service' "$T/systemctl.log" && ok "service is enabled" || bad "service enable"
cv doctor 2>&1 | grep -q "login service is installed and running" && ok "doctor reports the running service" || bad "doctor service state"
cv uninstall-service >/dev/null 2>&1; [ ! -e "$UNIT" ] && ok "uninstall-service removes the unit" || bad "uninstall unit"
[ -d "$T/vault" ] && ok "uninstall-service keeps the vault" || bad "uninstall vault"
export PATH=$SAVED_PATH
export XDG_RUNTIME_DIR=$SAVED_XDG

echo; [ "$FAILS" = 0 ] && echo "all migrate/doctor checks passed" || { echo "$FAILS check(s) failed"; exit 1; }
