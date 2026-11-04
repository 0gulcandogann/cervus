#!/usr/bin/env bash
# Test stand-in for libsecret's secret-tool: one entry in the file $FAKE_KEYRING, so tests never touch
# a real keyring. Arguments are logged, because a secret must never reach them.
echo "$*" >> "$FAKE_KEYRING.args"
[ -e "$FAKE_KEYRING.closed" ] && exit 1 # a closed keyring answers nothing
case "$1" in
  store)  cat > "$FAKE_KEYRING" ;;
  lookup) [ -s "$FAKE_KEYRING" ] || exit 1; cat "$FAKE_KEYRING" ;;
  clear)  rm -f "$FAKE_KEYRING" ;;
  *)      exit 2 ;;
esac
