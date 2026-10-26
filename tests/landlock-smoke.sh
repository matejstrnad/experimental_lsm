#!/usr/bin/env bash
# The daemon's Landlock sandbox: explsmd restricts itself once attached, its
# /proc helper keeps only the capabilities it needs, processes of exes added
# by a reload are still seeded (through the helper), and the pins are still
# removed on exit.
#
# Runs explsmd against a throwaway sandbox in /var/tmp, not pinned. Must run
# as root; app processes run as `nobody`. Stop an installed explsmd first
# (`sudo explsmctl unload`).
#
#   cargo build --release
#   sudo tests/landlock-smoke.sh [target/release]

set -u

BIN=$(realpath "${1:-target/release}")
DIR=/var/tmp/explsm-landlock
[[ $EUID -eq 0 ]] || { echo "must run as root" >&2; exit 2; }
[[ -x $BIN/explsmd ]] || { echo "explsmd not in $BIN; build first" >&2; exit 2; }
# Another explsmd's hooks would see this one as an unconfined process.
if pgrep -x explsmd > /dev/null || [[ -e /sys/fs/bpf/explsm ]]; then
    echo "an explsmd is loaded; \`sudo explsmctl unload\` first" >&2
    exit 2
fi

rm -rf "$DIR"
L=$DIR/late         # owned by `late`, added by a reload
LB=$DIR/late-bin    # exe of `late`: sleep
mkdir -p "$L" "$LB" "$DIR/state" "$DIR/claims.d"
cp "$(type -P sleep)" "$LB/sleep"
chmod -R a+rX "$DIR"
EXPLSMD=$BIN/explsmd

cat > "$DIR/policy.explsm" <<EOF
# written by landlock-smoke.sh
users root
EOF

OUT=$DIR/events.log
ERR=$DIR/explsmd.log

fails=0
check() { # name, condition result (0 = pass), detail
    if [[ $2 -eq 0 ]]; then echo "PASS  $1"; else echo "FAIL  $1: $3"; fails=$((fails + 1)); fi
}
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
status_of() { # pid, field
    awk -v f="$2:" '$1 == f { print $2 }' "/proc/$1/status"
}

daemon=
targets=()
cleanup() {
    [[ -n $daemon ]] && { kill -TERM "$daemon" 2> /dev/null; wait "$daemon" 2> /dev/null; }
    for t in "${targets[@]}"; do kill -KILL "$t" 2> /dev/null; done
}
trap cleanup EXIT
: > "$OUT"; : > "$ERR"; om=0

"$EXPLSMD" --policy "$DIR/policy.explsm" --claims "$DIR/claims.d" --agent "$DIR/no-agent" \
    --state-dir "$DIR/state" --no-dbus --no-pin --no-self-protect \
    >> "$OUT" 2> "$ERR" &
daemon=$!
wait_err attached || { echo "explsmd did not start:"; cat "$ERR"; exit 1; }
pins=/sys/fs/bpf/explsm-run$daemon

# --- the sandbox and the helper ----------------------------------------------
wait_err "sandboxed \(Landlock\)"
check "explsmd is sandboxed" $? "$(grep -i sandbox "$ERR")"
check "… with no_new_privs" "$([[ $(status_of "$daemon" NoNewPrivs) == 1 ]]; echo $?)" \
    "$(status_of "$daemon" NoNewPrivs)"
helper=$(pgrep -P "$daemon" -x explsmd-proc)
check "the /proc helper runs" "$([[ -n $helper ]]; echo $?)" "$(ps --ppid "$daemon" -o pid,comm)"
if [[ -n $helper ]]; then
    caps=$(status_of "$helper" CapEff)
    # CAP_DAC_READ_SEARCH (2) and CAP_SYS_PTRACE (19).
    check "the helper keeps only DAC_READ_SEARCH and SYS_PTRACE" \
        "$([[ $caps == 0000000000080004 ]]; echo $?)" "CapEff=$caps"
    check "… in its bounding set too" "$([[ $(status_of "$helper" CapBnd) == 0000000000080004 ]]; echo $?)" \
        "CapBnd=$(status_of "$helper" CapBnd)"
    fds=$(ls "/proc/$helper/fd" | wc -l)
    check "… and holds just its socket and stdio" "$([[ $fds -le 4 ]]; echo $?)" \
        "$(ls -l "/proc/$helper/fd")"
fi

# --- seeding after a reload, through the helper ------------------------------
setpriv --reuid=65534 --regid=65534 --clear-groups -- "$LB/sleep" 60 &
t=$!
targets+=("$t")
setpriv --reuid=65534 --regid=65534 --clear-groups -- \
    env LD_LIBRARY_PATH=/nonexistent "$LB/sleep" 60 &
tainted=$!
targets+=("$tainted")
sleep 0.3
cat >> "$DIR/policy.explsm" <<EOF
app late {
    exe "$LB/sleep"
    owns "$L"
    mode enforce
}
EOF
kill -HUP "$daemon"
wait_err "policy reloaded"
check "the policy reloads" $? "$(tail -5 "$ERR")"
wait_err "seeded 1 running processes"
check "a running process of the new exe is seeded" $? "$(grep -iE "seed|helper|warning" "$ERR")"
grep -qE "left unconfined.*pids \[$tainted\]" "$ERR"
check "… one with a loader variable is not" $? "$(grep -i unconfined "$ERR")"
emark
nobody cat "/proc/$t/environ" > /dev/null 2>&1
rc=$?
check "the seeded process is protected" "$([[ $rc -ne 0 ]]; echo $?)" "rc=$rc"
wait_out "owner=late ptrace\(read\) need=tamper target=$t"
check "… as the new app" $? "$(olog | tail -3)"

# --- exit --------------------------------------------------------------------
kill -TERM "$daemon"; wait "$daemon" 2> /dev/null; daemon=
check "the pins are removed on exit" "$([[ ! -e $pins ]]; echo $?)" "$(ls "$pins" 2>&1)"
sleep 0.2
check "the helper exits with the daemon" "$([[ -z $helper ]] || ! kill -0 "$helper" 2> /dev/null; echo $?)" \
    "pid $helper"
! grep -q "warning" "$ERR"
check "no warnings" $? "$(grep warning "$ERR")"

echo
[[ $fails -eq 0 ]] && echo "all passed" || echo "$fails failed"
exit $(( fails > 0 ))
