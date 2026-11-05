#!/usr/bin/env bash
# Test stand-in for the macOS security program, same idea as fake_secret_tool.sh: one entry in the file
# $FAKE_KEYRING, in plain text so tests can compare it. Arguments are logged, because a secret must
# never reach them.
echo "$*" >> "$FAKE_KEYRING.args"
[ -e "$FAKE_KEYRING.closed" ] && exit 1 # a locked keychain answers nothing
case "$1" in
  -i) # the real interactive mode says nothing about a failure, and neither does this
    line=$(head -1); value=${line##* -w }; value=${value%%[[:space:]]*}
    python3 -c 'import sys; open(sys.argv[1],"wb").write(bytes.fromhex(sys.argv[2]))' "$FAKE_KEYRING" "$value" ;;
  find-generic-password)
    [ -s "$FAKE_KEYRING" ] || exit 44
    python3 -c 'import sys; print(open(sys.argv[1],"rb").read().hex())' "$FAKE_KEYRING" ;;
  delete-generic-password)
    [ -e "$FAKE_KEYRING" ] || exit 44
    rm -f "$FAKE_KEYRING" ;;
  *) exit 2 ;;
esac
