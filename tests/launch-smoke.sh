#!/usr/bin/env bash
# Smoke test for "who started the app" (docs/release-plan.md §9):
# `started_by` gives an app its identity only when a subject it names
# started it (an app, `@terminal`: a chain of shells from a terminal,
# `@desktop`), `deny_args` drops it for listed arguments, and `code trusted`
# (the default) keeps an app from mapping code the user could change.
#
# Runs explsmd against a throwaway sandbox in /var/tmp. Must run as root;
# the accessing processes run as `nobody`. Needs python3 and a C compiler
# (cc) for the code tests, which are skipped without one.
#
#   cargo build --release
#   sudo tests/launch-smoke.sh [target/release]

set -u

BIN=$(realpath "${1:-target/release}")
EXPLSMD=$BIN/explsmd
DIR=/var/tmp/explsm-launch
[[ $EUID -eq 0 ]] || { echo "must run as root" >&2; exit 2; }
. "$(dirname "$0")/common.sh"
fresh "$EXPLSMD"
step "setting up $DIR"
command -v python3 > /dev/null || { echo "python3 is needed" >&2; exit 2; }

rm -rf "$DIR"
B=$DIR/bin
E=$DIR/secret      # owned by `keyed`, started_by @terminal, @desktop, helper
A=$DIR/audited     # owned by `watched`, the same in audit mode
G=$DIR/args        # owned by `argy`, with deny_args
C=$DIR/code        # owned by `coder`, code trusted (the default)
mkdir -p "$B" "$E" "$A" "$G" "$C"
echo s3cret > "$E/file"
echo s3cret > "$A/file"
echo s3cret > "$G/file"
echo s3cret > "$C/file"
# Private copies of bash, so their inodes are the exes below.
for b in term sh desk interp helper keyed watched argy; do cp "$(type -P bash)" "$B/$b"; done
cp "$(type -P cat)" "$B/cat"
cp "$(readlink -f "$(type -P python3)")" "$B/coder"
cp "$(readlink -f "$(type -P python3)")" "$B/anycoder"
chmod -R a+rwX "$DIR"

POLICY=$DIR/policy.explsm
cat > "$POLICY" <<EOF
terminal "$B/term"
shell "$B/sh"
desktop "$B/desk"

app helper { exe "$B/helper" }

app keyed {
    exe "$B/keyed"
    owns "$E"
    started_by @terminal, @desktop, helper
    mode enforce
}

app watched {
    exe "$B/watched"
    owns "$A"
    started_by @terminal
}

app argy {
    exe "$B/argy"
    owns "$G"
    deny_args "-O", "--debug*"
    mode enforce
}

app coder {
    exe "$B/coder"
    owns "$C"
    mode enforce
}

app anycoder {
    exe "$B/anycoder"
    code any
    mode enforce
}
EOF

OUT=$DIR/events.log
ERR=$DIR/explsmd.log
fails=0
check() { # name, condition result (0 = pass), detail
    if [[ $2 -eq 0 ]]; then echo "PASS  $1"; else echo "FAIL  $1: $3"; fails=$((fails + 1)); fi
}
skip() { echo "SKIP  $1: $2"; }
mark() { wc -l < "$OUT"; }
since() { sleep "0.$((3 * ${SMOKE_SLOW:-1}))"; tail -n +"$(($1 + 1))" "$OUT"; }
nobody() { setpriv --reuid=65534 --regid=65534 --clear-groups -- "$@"; }
run() { m=$(mark); out=$("$@" 2>&1); rc=$?; ev=$(since "$m"); }
has() { grep -qE "$1" <<< "$ev"; }

daemon=
"$EXPLSMD" --policy "$POLICY" --no-dbus --no-pin --no-self-protect > "$OUT" 2> "$ERR" &
daemon=$!
trap 'kill $daemon 2> /dev/null' EXIT
for _ in $(seq $((100 * ${SMOKE_SLOW:-1}))); do grep -q attached "$ERR" && break; sleep 0.1; done
grep -q attached "$ERR" || { echo "explsmd did not start:"; cat "$ERR"; exit 1; }
grep -E 'warning' "$ERR"

# The app reads its own data with a builtin, so the reading process is the
# app exe itself. Scripts, so the commands survive any nesting of -c.
for d in "$E" "$A" "$G"; do
    printf 'read -r l < %q && echo "$l"\n' "$d/file" > "$d.sh"
    chmod a+r "$d.sh"
done

# --- started_by -----------------------------------------------------------------
step "started_by"
run nobody "$B/term" -c "$B/sh -c '$B/keyed $E.sh'"
[[ $rc -eq 0 && $out == s3cret ]]
check "typed in a shell below a terminal: the app" $? "rc=$rc out=$out $ev"

run nobody "$B/term" -c "$B/interp -c '$B/keyed $E.sh'"
[[ $rc -ne 0 ]] && has "deny .* app=keyed exe=$B/keyed dropped=started_by spawner=unconfined$"
check "started by a non-shell below a terminal: no app" $? "rc=$rc out=$out $ev"

run nobody "$B/keyed" "$E.sh"
[[ $rc -ne 0 ]] && has "dropped=started_by spawner=unconfined$"
check "started by an unconfined process: no app" $? "rc=$rc out=$out $ev"

# Forked twice, so its parent is gone when it execs: the spawner still is
# what forked it, not what it was re-parented to.
m=$(mark)
nobody "$B/interp" -c "( ( sleep 0.5; $B/keyed $E.sh > $DIR/orphan.out 2>&1 ) & ) ; exit 0"
sleep $((2 * ${SMOKE_SLOW:-1}))
ev=$(since "$m")
! grep -q s3cret "$DIR/orphan.out" && has "dropped=started_by"
check "an orphan of an untrusted process: no app" $? "$(cat "$DIR/orphan.out") $ev"

run nobody "$B/desk" -c "$B/keyed $E.sh"
[[ $rc -eq 0 && $out == s3cret ]]
check "started by the desktop: the app" $? "rc=$rc out=$out $ev"

run nobody "$B/desk" -c "$B/interp -c '$B/keyed $E.sh'"
[[ $rc -ne 0 ]] && has "dropped=started_by"
check "started by what the desktop started: no app" $? "rc=$rc out=$out $ev"

run nobody "$B/helper" -c "$B/keyed $E.sh"
[[ $rc -eq 0 && $out == s3cret ]]
check "started by an app it names: the app" $? "rc=$rc out=$out $ev"

run nobody "$B/watched" "$A.sh"
[[ $rc -eq 0 && $out == s3cret ]] && has "audit .* app=watched exe=$B/watched dropped=started_by"
check "audit mode: reported, the identity kept" $? "rc=$rc out=$out $ev"

# --- deny_args ------------------------------------------------------------------
step "deny_args"
run nobody "$B/argy" "$G.sh"
[[ $rc -eq 0 && $out == s3cret ]]
check "without a denied argument: the app" $? "rc=$rc out=$out $ev"

run nobody "$B/argy" -O extglob "$G.sh"
[[ $rc -ne 0 ]] && has "deny .* app=argy exe=$B/argy dropped=deny_args"
check "an exact denied argument: no app" $? "rc=$rc out=$out $ev"

run nobody "$B/argy" --debugger "$G.sh"
[[ $rc -ne 0 ]] && has "dropped=deny_args"
check "an argument with a denied prefix: no app" $? "rc=$rc out=$out $ev"

run nobody "$B/argy" "$G.sh" "x -O"
[[ $rc -eq 0 && $out == s3cret ]]
check "a denied argument inside another one: the app" $? "rc=$rc out=$out $ev"

# --- code trusted ---------------------------------------------------------------
step "code"
if command -v cc > /dev/null; then
    echo 'int explsm_test_symbol = 1;' > "$DIR/lib.c"
    cc -shared -fPIC -o "$DIR/user.so" "$DIR/lib.c"
    cp "$DIR/user.so" "$DIR/root.so"
    chown 65534:65534 "$DIR/user.so"
    chown root:root "$DIR/root.so"
    chmod 0644 "$DIR/root.so" "$DIR/user.so"
    load() { echo "import ctypes; ctypes.CDLL('$1'); print('loaded')"; }
    # A copied python looks for its library next to itself.
    export PYTHONHOME
    PYTHONHOME=$(python3 -c 'import sys; print(sys.prefix)')

    run nobody "$B/coder" -c "$(load "$DIR/root.so")"
    [[ $rc -eq 0 && $out == loaded ]]
    check "an app maps code that only root can change" $? "rc=$rc out=$out $ev"

    run nobody "$B/coder" -c "$(load "$DIR/user.so")"
    [[ $rc -ne 0 ]] && has "deny .* subject=coder owner=unconfined mmap need=code .*user\.so"
    check "an app can't map code the user could change" $? "rc=$rc out=$out $ev"

    cp "$DIR/user.so" "$C/own.so"
    chown 65534:65534 "$C/own.so"
    run nobody "$B/coder" -c "$(load "$C/own.so")"
    [[ $rc -eq 0 && $out == loaded ]]
    check "an app maps code from its own data" $? "rc=$rc out=$out $ev"

    run nobody "$B/anycoder" -c "$(load "$DIR/user.so")"
    [[ $rc -eq 0 && $out == loaded ]]
    check "code any: an app maps any code" $? "rc=$rc out=$out $ev"

    run nobody env -u PYTHONHOME python3 -c "$(load "$DIR/user.so")"
    [[ $rc -eq 0 && $out == loaded ]]
    check "an unconfined process maps any code" $? "rc=$rc out=$out $ev"
else
    skip "code" "no C compiler (cc)"
fi

kill -INT "$daemon"; wait "$daemon"
echo
[[ $fails -eq 0 ]] && echo "all checks passed" || echo "$fails checks FAILED"
exit $((fails > 0))
