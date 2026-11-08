#!/usr/bin/env bash
# Smoke test for pinned app exes (docs/release-plan.md §5): an `exe` with
# `sha256` or `hashes` gives the identity only to files with one of those
# hashes, also to ones that appear later at a glob that matched nothing,
# and a hash list a user could replace is refused.
#
# Runs explsmd against a throwaway sandbox in /var/tmp. Must run as root;
# the accessing processes run as `nobody`.
#
#   cargo build --release
#   sudo tests/guard-smoke.sh [target/release]

set -u

BIN=$(realpath "${1:-target/release}")
EXPLSMD=$BIN/explsmd
CTL=$BIN/explsmctl
DIR=/var/tmp/explsm-guard
[[ $EUID -eq 0 ]] || { echo "must run as root" >&2; exit 2; }
. "$(dirname "$0")/common.sh"
fresh "$EXPLSMD" "$CTL"
step "setting up $DIR"

rm -rf "$DIR"
B=$DIR/bin         # user-writable, like ~/.local/bin
E=$DIR/secret      # owned by `pinned`
L=$DIR/lists       # root-owned hash lists
mkdir -p "$B" "$E" "$L"
echo s3cret > "$E/file"
cp "$(type -P cat)" "$B/good"
GOOD=$(sha256sum "$B/good" | cut -d' ' -f1)
sha256sum "$B/good" > "$L/good.sha256"
chmod -R a+rwX "$B" "$E"
chmod 0755 "$DIR"
chown root:root "$L" "$L/good.sha256"
chmod 0755 "$L"
chmod 0644 "$L/good.sha256"
chmod 0644 "$E/file"

POLICY=$DIR/policy.explsm
cat > "$POLICY" <<EOF
app pinned {
    exe "$B/good" sha256 "$GOOD", "$B/tool-*" hashes "$L/good.sha256"
    owns "$E"
    mode enforce
}
EOF

OUT=$DIR/events.log
ERR=$DIR/explsmd.log
fails=0
check() { # name, condition result (0 = pass), detail
    if [[ $2 -eq 0 ]]; then echo "PASS  $1"; else echo "FAIL  $1: $3"; fails=$((fails + 1)); fi
}
nobody() { setpriv --reuid=65534 --regid=65534 --clear-groups -- "$@"; }
wait_err() {
    for _ in $(seq $((50 * ${SMOKE_SLOW:-1}))); do grep -qE "$1" "$ERR" && return 0; sleep 0.1; done
    return 1
}

# --- the policy -------------------------------------------------------------------
"$CTL" check "$POLICY" --resolve > /dev/null 2>&1
check "the policy checks" $? "$("$CTL" check "$POLICY" --resolve 2>&1 | tail -3)"
sha256sum "$B/good" > "$B/list.sha256"
sed "s|$L/good.sha256|$B/list.sha256|" "$POLICY" > "$DIR/bad.explsm"
out=$("$CTL" check "$DIR/bad.explsm" --resolve 2>&1)
rc=$?
check "a hash list a user could replace is refused" \
    "$([[ $rc -ne 0 && $out == *"could replace"* ]]; echo $?)" "rc=$rc $out"
out=$("$CTL" check /dev/stdin <<< 'app a { exe "/a" sha256 "12ab" }' 2>&1)
check "a bad hash is an error" "$([[ $out == *"not a SHA-256"* ]]; echo $?)" "$out"

"$EXPLSMD" --policy "$POLICY" --no-dbus --no-pin --no-self-protect > "$OUT" 2> "$ERR" &
daemon=$!
trap 'kill $daemon 2> /dev/null' EXIT
for _ in $(seq $((100 * ${SMOKE_SLOW:-1}))); do grep -q attached "$ERR" && break; sleep 0.1; done
grep -q attached "$ERR" || { echo "explsmd did not start:"; cat "$ERR"; exit 1; }

# --- pins ---------------------------------------------------------------------------
out=$(nobody "$B/good" "$E/file" 2>&1)
check "an exe with its pinned hash is the app" "$([[ $out == s3cret ]]; echo $?)" "$out"

# Appears at the glob, which matched nothing: not the pinned binary.
cp "$(type -P head)" "$B/tool-evil"
chmod a+rx "$B/tool-evil"
wait_err "exe $B/tool-evil of pinned has none of its pinned hashes"
f=$?
out=$(nobody "$B/tool-evil" "$E/file" 2>&1)
check "a new exe at the glob without a pinned hash is no app" \
    "$([[ $f -eq 0 && $out != s3cret ]]; echo $?)" "f=$f $out $(tail -5 "$ERR")"

cp "$B/good" "$B/tool-1"
chmod a+rx "$B/tool-1"
wait_err "\+ exe +$B/tool-1 "
f=$?
out=$(nobody "$B/tool-1" "$E/file" 2>&1)
check "a new exe at the glob with a listed hash is the app" \
    "$([[ $f -eq 0 && $out == s3cret ]]; echo $?)" "f=$f $out $(tail -5 "$ERR")"

# The pinned exe is user-writable, so it is guarded like the app's data.
nobody sh -c "cat '$(type -P head)' > '$B/good'" 2> /dev/null
cmp -s "$B/good" "$B/tool-1"
check "nobody else can replace a pinned exe" $? "$(tail -3 "$OUT")"

kill -INT "$daemon"; wait "$daemon"
echo
[[ $fails -eq 0 ]] && echo "all checks passed" || echo "$fails checks FAILED"
exit $((fails > 0))
