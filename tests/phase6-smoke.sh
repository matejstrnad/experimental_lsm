#!/usr/bin/env bash
# Hardening added with the packaging: an app exe exec'd in a user namespace
# gets no identity, core-dumping signals and rlimit changes from other
# subjects are refused, repeated read-only ptrace reports are merged, and
# `exec` lines are only logged with --log-execs.
#
# Runs explsmd against a throwaway sandbox in /var/tmp, not pinned. Must run
# as root; accessing processes run as `nobody`. Stop an installed explsmd
# first (`sudo explsmctl unload`).
#
#   cargo build --release
#   sudo tests/phase6-smoke.sh [target/release]

set -u

BIN=$(realpath "${1:-target/release}")
DIR=/var/tmp/explsm-phase6
[[ $EUID -eq 0 ]] || { echo "must run as root" >&2; exit 2; }
[[ -x $BIN/explsmd ]] || { echo "explsmd not in $BIN; build first" >&2; exit 2; }
command -v unshare > /dev/null || { echo "unshare is needed" >&2; exit 2; }
command -v prlimit > /dev/null || { echo "prlimit is needed" >&2; exit 2; }

rm -rf "$DIR"
E=$DIR/enforced     # owned by `owner`, enforce mode
A=$DIR/audited      # owned by `aud`, audit mode
OB=$DIR/owner-bin   # exes of `owner`: cat, bash, sleep
AB=$DIR/aud-bin     # exe of `aud`: sleep
mkdir -p "$E" "$A" "$OB" "$AB" "$DIR/state" "$DIR/claims.d"
echo s3cret > "$E/secret"
cp "$(type -P cat)" "$OB/cat"
cp "$(type -P bash)" "$OB/bash"
cp "$(type -P sleep)" "$OB/sleep"
cp "$(type -P sleep)" "$AB/sleep"
chmod -R a+rX "$DIR"
chmod a+rwx "$E" "$E/secret"
EXPLSMD=$BIN/explsmd

cat > "$DIR/policy.explsm" <<EOF
# written by phase6-smoke.sh
users root
app owner {
    exe "$OB/cat", "$OB/bash", "$OB/sleep"
    owns "$E"
    mode enforce
}
app aud {
    exe "$AB/sleep"
    owns "$A"
    mode audit
}
EOF

OUT=$DIR/events.log
ERR=$DIR/explsmd.log

fails=0
check() { # name, condition result (0 = pass), detail
    if [[ $2 -eq 0 ]]; then echo "PASS  $1"; else echo "FAIL  $1: $3"; fails=$((fails + 1)); fi
}
skip() { echo "SKIP  $1: $2"; }
nobody() { setpriv --reuid=65534 --regid=65534 --clear-groups -- "$@"; }
emark() { om=$(wc -l < "$OUT"); }
olog() { tail -n +"$(( om + 1 ))" "$OUT"; }
wait_out() { # pattern: wait up to 5 s for it in the event log since `emark`
    for _ in $(seq 50); do olog | grep -qE "$1" && return 0; sleep 0.1; done
    return 1
}
wait_err() {
    for _ in $(seq 50); do grep -qE "$1" "$ERR" && return 0; sleep 0.1; done
    return 1
}

daemon=
start() { # extra args
    : > "$ERR"
    "$EXPLSMD" --policy "$DIR/policy.explsm" --claims "$DIR/claims.d" --agent "$DIR/no-agent" \
        --state-dir "$DIR/state" --no-dbus --no-pin --no-self-protect --quiet-window 2 \
        "$@" >> "$OUT" 2> "$ERR" &
    daemon=$!
    wait_err attached || { echo "explsmd did not start:"; cat "$ERR"; exit 1; }
}
stop() {
    [[ -n $daemon ]] || return 0
    kill -TERM "$daemon" 2> /dev/null; wait "$daemon" 2> /dev/null; daemon=
}
targets=()
cleanup() {
    stop
    for t in "${targets[@]}"; do kill -KILL "$t" 2> /dev/null; done
}
trap cleanup EXIT
: > "$OUT"; om=0

# An app process started in a user namespace before explsmd: never seeded.
userns=1
nobody unshare -U true 2> /dev/null || userns=0
if [[ $userns -eq 1 ]]; then
    mkfifo "$DIR/go"; chmod a+rw "$DIR/go"
    setpriv --reuid=65534 --regid=65534 --clear-groups -- \
        unshare -U "$OB/bash" -c "read -t 30 _ < '$DIR/go'; read -r _ < '$E/secret'" &
    early=$!
    targets+=("$early")
fi

start

# --- user namespaces ---------------------------------------------------------
if [[ $userns -eq 0 ]]; then
    skip "user namespaces" "nobody can't create one here"
else
    emark
    nobody "$OB/cat" "$E/secret" > /dev/null 2>&1
    check "the app reads its data" $? ""
    nobody unshare -U "$OB/cat" "$E/secret" > /dev/null 2>&1
    rc=$?
    check "in a user namespace the app is unconfined and denied" "$([[ $rc -ne 0 ]]; echo $?)" "rc=$rc"
    wait_out "app=owner exe=.*dropped=userns"
    check "the dropped exec is logged" $? "$(olog | tail -3)"
    echo go > "$DIR/go"; wait "$early"
    rc=$?
    check "an app process started in a user namespace is not seeded" "$([[ $rc -ne 0 ]]; echo $?)" "rc=$rc"
    grep -q "left unconfined.*user namespace" "$ERR"
    check "… and that is reported" $? "$(grep -i unconfined "$ERR")"
fi

# --- core-dumping signals and rlimits ----------------------------------------
# setpriv execs the app, so $! is its pid. No core dumps from the test.
setpriv --reuid=65534 --regid=65534 --clear-groups -- \
    bash -c "ulimit -c 0; exec '$OB/sleep' 60" &
t=$!
targets+=("$t")
sleep 0.3
emark
nobody kill -SEGV "$t" 2> /dev/null
rc=$?
check "an unconfined process can't send the app SIGSEGV" "$([[ $rc -ne 0 ]] && kill -0 "$t"; echo $?)" "rc=$rc"
wait_out "subject=unconfined owner=owner signal\\(SIGSEGV\\) need=tamper target=$t"
check "the denial is logged" $? "$(olog | tail -3)"
nobody kill -ABRT "$t" 2> /dev/null
rc=$?
check "… nor SIGABRT" "$([[ $rc -ne 0 ]] && kill -0 "$t"; echo $?)" "rc=$rc"
nobody prlimit --cpu=1 --pid "$t" 2> /dev/null
rc=$?
check "… nor change its RLIMIT_CPU" "$([[ $rc -ne 0 ]]; echo $?)" "rc=$rc"
wait_out "subject=unconfined owner=owner rlimit\\(RLIMIT_CPU\\) need=tamper target=$t"
check "the rlimit denial is logged" $? "$(olog | tail -3)"
nobody "$OB/bash" -c 'ulimit -t 100' 2> /dev/null
check "the app may change its own limits" $? ""
nobody "$OB/bash" -c "kill -QUIT $t" 2> /dev/null
rc=$?
wait "$t" 2> /dev/null
check "the same app may send it SIGQUIT" "$([[ $rc -eq 0 ]] && ! kill -0 "$t" 2> /dev/null; echo $?)" "rc=$rc"

setpriv --reuid=65534 --regid=65534 --clear-groups -- \
    bash -c "ulimit -c 0; exec '$OB/sleep' 60" &
t=$!
targets+=("$t")
sleep 0.3
nobody kill -TERM "$t" 2> /dev/null
rc=$?
wait "$t" 2> /dev/null
check "an unconfined process may still send SIGTERM" "$([[ $rc -eq 0 ]]; echo $?)" "rc=$rc"

setpriv --reuid=65534 --regid=65534 --clear-groups -- \
    bash -c "ulimit -c 0; exec '$AB/sleep' 60" &
t=$!
targets+=("$t")
sleep 0.3
emark
nobody kill -QUIT "$t" 2> /dev/null
rc=$?
wait "$t" 2> /dev/null
check "audit mode: SIGQUIT goes through" "$([[ $rc -eq 0 ]]; echo $?)" "rc=$rc"
wait_out "^audit .*owner=aud signal\\(SIGQUIT\\) need=tamper target=$t"
check "… and is logged" $? "$(olog | tail -3)"

# --- repeated ptrace reports ----------------------------------------------------
setpriv --reuid=65534 --regid=65534 --clear-groups -- \
    bash -c "ulimit -c 0; exec '$OB/sleep' 60" &
t=$!
targets+=("$t")
sleep 0.3
emark
for _ in 1 2 3 4 5; do nobody cat "/proc/$t/environ" > /dev/null 2>&1; done
for _ in 1 2; do nobody bash -c "exec 3< /proc/$t/mem" 2> /dev/null; done
sleep 0.5
n=$(olog | grep -cE "ptrace\(read\) need=tamper target=$t\$")
check "five environ reads by one program are logged once" "$([[ $n -eq 1 ]]; echo $?)" "n=$n $(olog | tail -5)"
n=$(olog | grep -cE "ptrace\(attach\) need=tamper target=$t\$")
check "attach attempts are each logged" "$([[ $n -eq 2 ]]; echo $?)" "n=$n"
wait_out "ptrace\(read\) need=tamper target=$t repeated=4\$"
check "the window ends with the number of repeats" $? "$(olog | tail -3)"
kill -KILL "$t" 2> /dev/null

# --- exec lines --------------------------------------------------------------
emark
nobody "$OB/cat" "$E/secret" > /dev/null 2>&1
sleep 0.3
! olog | grep -q "^exec "
check "no exec lines by default" $? "$(olog | grep '^exec ' | head -3)"
stop
start --log-execs
emark
nobody "$OB/cat" "$E/secret" > /dev/null 2>&1
wait_out "^exec .*app=owner exe=$OB/cat"
check "exec lines with --log-execs" $? "$(olog | tail -3)"

echo
if [[ $fails -eq 0 ]]; then echo "all passed"; else echo "$fails failed; logs in $DIR"; fi
[[ $fails -eq 0 ]]
