#!/usr/bin/env bash
# Checks the release archive built by `make dist`: its contents, modes and that it runs from anywhere.
# Usage: bash scripts/test_dist.sh
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
T="$(mktemp -d)"
FAILS=0
ok()  { echo "PASS: $1"; }
bad() { echo "FAIL: $1"; FAILS=$((FAILS+1)); }
trap 'rm -rf "$T"' EXIT

VERSION="$(make -s -C "$ROOT" version)"
[ "$VERSION" = "$(sed -n 's/^const version = "\(.*\)"/\1/p' "$ROOT/cli/cmd/cervus/main.go")" ] && [ -n "$VERSION" ] && ok "make version prints the CLI version" || bad "make version: '$VERSION'"

make -s -C "$ROOT" dist DIST="$T/out" >"$T/build.log" 2>&1 && ok "make dist succeeds" || { bad "make dist"; tail -5 "$T/build.log"; exit 1; }
ARCHIVE="$(ls "$T/out"/cervus-"$VERSION"-*.tar.gz 2>/dev/null)"
case "$(basename "$ARCHIVE")" in
  cervus-"$VERSION"-"$(go env GOOS)"-"$(go env GOARCH)".tar.gz) ok "the archive name has the version, OS and architecture" ;;
  *) bad "archive name: '$ARCHIVE'"; exit 1 ;;
esac

NAME="cervus-$VERSION-$(go env GOOS)-$(go env GOARCH)"
LISTED="$(tar -tzf "$ARCHIVE" | LC_ALL=C sort | tr '\n' ' ')"
[ "$LISTED" = "$NAME/ $NAME/LICENSE $NAME/README.md $NAME/cervus $NAME/cervus-vault $NAME/cervusd " ] && ok "the archive holds exactly the expected files" || bad "archive contents: $LISTED"

mkdir "$T/x"; tar -xzf "$ARCHIVE" -C "$T/x"
for b in cervus cervusd cervus-vault; do
  [ -x "$T/x/$NAME/$b" ] && ok "$b is executable" || bad "$b not executable"
done
[ "$("$T/x/$NAME/cervus" version)" = "cervus $VERSION" ] && ok "the packaged cervus runs" || bad "packaged cervus"
for b in cervus cervusd; do
  grep -qF "$ROOT" "$T/x/$NAME/$b" && bad "$b contains the build path" || ok "$b does not contain the build path"
done

# The packaged daemon must find its vault next to it.
S="$T/run/c.sock"; mkdir -m 700 "$T/run"
"$T/x/$NAME/cervusd" --socket "$S" --vault-dir "$T/vault" --config "$T/c.json" 2>/dev/null & D=$!
sleep 1
CERVUS_SOCKET="$S" "$T/x/$NAME/cervus" status 2>&1 | grep -q "not initialized" && ok "the packaged daemon starts its vault" || bad "packaged daemon"
kill "$D" 2>/dev/null

echo; [ "$FAILS" = 0 ] && echo "all dist checks passed" || { echo "$FAILS check(s) failed"; exit 1; }
