#!/usr/bin/env bash
# The real macOS Keychain, in a throwaway keychain on a CI machine. Never run this on your own Mac: it
# changes the default keychain. Usage: BIN=./bin CI=true scripts/mac_keychain_test.sh
set -u
[ "$(uname)" = Darwin ] || { echo "macOS only"; exit 0; }
[ "${CI:-}" = true ] || { echo "CI only: this changes the default keychain"; exit 1; }
B="$(cd "${BIN:-$(dirname "$0")/../bin}" && pwd)"
T="$(mktemp -d)"; mkdir -p "$T/run" "$T/home"
export HOME="$T/home" CERVUS_SOCKET="$T/run/c.sock"
unset CERVUS_NO_KEYCHAIN
FAILS=0
ok() { echo "PASS: $1"; }
bad() { echo "FAIL: $1"; FAILS=$((FAILS+1)); }
KC="$T/test.keychain-db"
security create-keychain -p testkc "$KC" || exit 1
security set-keychain-settings "$KC"
security unlock-keychain -p testkc "$KC"
security list-keychains -d user -s "$KC"
security default-keychain -d user -s "$KC"
security default-keychain -s "$KC"
echo "probe default: $(security default-keychain 2>&1) list: $(security list-keychains 2>&1 | tr -d '\n ')"
cleanup() { [ -n "${D:-}" ] && kill "$D" 2>/dev/null; security delete-keychain "$KC" 2>/dev/null; rm -rf "$T"; }
trap cleanup EXIT
# How security behaves here, printed for whoever reads the CI log. Dummy values only.
lim() { perl -e 'alarm shift; exec @ARGV' "$@"; }
probe() { local start=$SECONDS; "$@" >/dev/null 2>&1; echo "probe rc=$? $((SECONDS-start))s: ${*: -1}"; }
probe lim 15 bash -c "printf 'add-generic-password -U -a p1 -s cervus-probe -w 6869\\n' | security -i"
probe lim 15 bash -c "printf 'add-generic-password -U -a p2 -s cervus-probe -w 6869\\nexit\\n' | security -i"
probe lim 15 bash -c "printf 'add-generic-password -U -a p3 -s cervus-probe -w 6869\\nquit\\n' | security -i"
probe lim 15 bash -c "printf 'add-generic-password -U -a p4 -s cervus-probe -w 6869\\n' | security -i -q"
probe lim 15 bash -c "security add-generic-password -U -a p5 -s cervus-probe -w 6869 </dev/null"
probe lim 15 bash -c "security add-generic-password -U -a p6 -s cervus-probe -w 6869 '$KC' </dev/null"
probe lim 15 bash -c "security add-generic-password -U -A -a p7 -s cervus-probe -w 6869 </dev/null"
for a in p1 p2 p3 p4 p5 p6 p7; do echo "probe stored $a: $(lim 10 security find-generic-password -a $a -s cervus-probe -w 2>&1 | head -1)"; done
"$B/cervusd" --vault-bin "$B/cervus-vault" --vault-dir "$T/vault" --config "$T/config.json" 2>"$T/d.log" </dev/null >/dev/null & D=$!
sleep 1
P='pass "with" $pecial chars ç 1'
printf '%s\n%s\n' "$P" "$P" | "$B/cervus" init >/dev/null 2>&1 && ok "vault created" || bad "init"
printf '%s\n' "$P" | "$B/cervus" keychain enable --yes > "$T/en.txt" 2>&1 && ok "keychain enable stores in the real Keychain" || bad "enable: $(cat "$T/en.txt")"
"$B/cervus" keychain status | grep -q "reopens by itself" && ok "status reads it back" || bad "status: $("$B/cervus" keychain status)"
ACCOUNT=$(security dump-keychain "$KC" 2>/dev/null | grep -c '"svce"<blob>="cervus"')
[ "$ACCOUNT" = 1 ] && ok "one item is in the Keychain" || bad "item count $ACCOUNT"
security dump-keychain -d "$KC" 2>/dev/null | grep -q 'with' && bad "the passphrase is readable as plain text in a dump" || ok "the stored value is not the plain passphrase"
kill "$D"; sleep 0.5
"$B/cervusd" --vault-bin "$B/cervus-vault" --vault-dir "$T/vault" --config "$T/config.json" 2>"$T/d.log" </dev/null >/dev/null & D=$!
sleep 1
"$B/cervus" status | grep -q locked && ok "after a restart the vault is locked" || bad "not locked"
"$B/cervus" unlock </dev/null 2>&1 | grep -q "from the keychain" && ok "the real Keychain opens the vault" || bad "keychain unlock"
"$B/cervus" status | grep -q unlocked && ok "it is open" || bad "still locked"
"$B/cervus" keychain disable >/dev/null 2>&1 && ok "disable succeeds" || bad "disable"
"$B/cervus" keychain disable 2>&1 | grep -q "no longer" && ok "disable twice is fine" || bad "disable twice"
[ "$(security dump-keychain "$KC" 2>/dev/null | grep -c '"svce"<blob>="cervus"')" = 0 ] && ok "the item is gone" || bad "item left"
security lock-keychain "$KC"
printf '%s\n' "$P" | "$B/cervus" keychain enable --yes > "$T/en.txt" 2>&1 && bad "enable claimed success with a locked Keychain: $(tail -1 "$T/en.txt")" || ok "a locked Keychain is reported"
[ -e "$T/vault/keychain-enabled" ] && bad "marked enabled after a failure" || ok "a failed enable leaves it off"
echo; [ "$FAILS" = 0 ] && echo "all macOS Keychain checks passed" || { echo "$FAILS check(s) failed"; exit 1; }
