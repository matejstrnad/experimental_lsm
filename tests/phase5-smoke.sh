#!/usr/bin/env bash
# Phase 5 smoke test: hardening. Loader variables at exec, ptrace and
# /proc/<pid>/{mem,environ} of app processes, user-writable app exes and
# the directories above them, atomic saves of an owned file, forced truncates,
# pinning (explsm stays loaded when the daemon exits, the next one takes
# over, unload removes it), the bpf() restrictions and explsm's own files.
#
# Runs explsmd from a copy in a throwaway sandbox in /var/tmp, pinned in
# /sys/fs/bpf/explsm-smoke5 (not the real pin directory). Must run as root;
# accessing processes run as `nobody`. Needs bpftool, and the Phase 4
# packaging/org.explsm.Daemon1.conf installed for the D-Bus unload check.
# If something goes wrong half-way, `$DIR/sbin/explsmd --unload --pin-dir
# /sys/fs/bpf/explsm-smoke5` cleans up (or reboot).
#
#   cargo build --release
#   sudo tests/phase5-smoke.sh [target/release]

set -u

BIN=$(realpath "${1:-target/release}")
DIR=/var/tmp/explsm-phase5
PIN=/sys/fs/bpf/explsm-smoke5
[[ $EUID -eq 0 ]] || { echo "must run as root" >&2; exit 2; }
for b in explsmd explsmctl; do
    [[ -x $BIN/$b ]] || { echo "$b not in $BIN; build first" >&2; exit 2; }
done
command -v bpftool > /dev/null || { echo "bpftool is needed" >&2; exit 2; }
command -v python3 > /dev/null || { echo "python3 is needed" >&2; exit 2; }
if busctl status org.explsm.Daemon1 > /dev/null 2>&1; then
    echo "another explsmd owns org.explsm.Daemon1; stop it first" >&2
    exit 2
fi
if [[ -e $PIN ]]; then
    echo "$PIN exists from an earlier run; unload it first:" >&2
    echo "  $DIR/sbin/explsmd --unload --pin-dir $PIN --policy $DIR/policy.explsm" >&2
    exit 2
fi

rm -rf "$DIR"
E=$DIR/enforced     # owned by `owner`, enforce mode
OB=$DIR/owner-bin   # exes of `owner`: cat and bash
W=$DIR/home/upd/versions # user-writable exes of `upd` (owned by nobody)
SB=$DIR/sbin        # the explsmd under test, root-owned
mkdir -p "$E" "$OB" "$W" "$SB" "$DIR/state" "$DIR/claims.d"
echo s3cret > "$E/secret"
# setgid with group exec: truncate(2) forces the size change to clear it.
echo s3cret > "$E/sgid"
cp "$(type -P cat)" "$OB/cat"
cp "$(type -P bash)" "$OB/bash"
cp "$(type -P mv)" "$OB/mv"
cp "$(type -P bash)" "$W/app-1"
cp "$BIN/explsmd" "$SB/explsmd"
cp "$BIN/explsmctl" "$SB/explsmctl"
chmod -R a+rX "$DIR"
chmod a+rwx "$E" "$E/secret" "$DIR/home" "$DIR/state"
chmod 2777 "$E/sgid"
echo s3cret > "$DIR/home/owner.json" # a file root, saved by rename
chown -R 65534:65534 "$DIR/home"
EXPLSMD=$SB/explsmd
CTL=$SB/explsmctl

cat > "$DIR/policy.explsm" <<EOF
# written by phase5-smoke.sh
users root
app owner {
    exe "$OB/cat", "$OB/bash", "$OB/mv"
    owns "$E", "$DIR/home/owner.json"
    mode enforce
}
app upd {
    exe "$W/app-*"
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
        --state-dir "$DIR/state" --pin-dir "$PIN" --daemon "$EXPLSMD" "$@" >> "$OUT" 2> "$ERR" &
    daemon=$!
    wait_err attached || { echo "explsmd did not start:"; cat "$ERR"; exit 1; }
}
stop() { # signal
    [[ -n $daemon ]] || return 0
    kill "-$1" "$daemon" 2> /dev/null; wait "$daemon" 2> /dev/null; daemon=
}
cleanup() {
    stop TERM
    [[ -e $PIN ]] && "$EXPLSMD" --unload --pin-dir "$PIN" --policy "$DIR/policy.explsm" 2> /dev/null
    kill "$target" 2> /dev/null
}
target=
trap cleanup EXIT
: > "$OUT"; om=0

# Baseline before anything is loaded.
nobody "$OB/cat" "$E/secret" > /dev/null 2>&1
check "baseline: nobody reads the secret with the owner's cat" $? ""

start
check "the pin directory exists" "$([[ -e $PIN/link-file_open && -e $PIN/ROOTS ]]; echo $?)" "$(ls "$PIN" 2>&1)"

# --- loader variables ----------------------------------------------------------
emark
nobody "$OB/cat" "$E/secret" > /dev/null 2>&1
check "the app reads its data" $? ""
nobody env LD_PRELOAD=/nonexistent.so "$OB/cat" "$E/secret" > /dev/null 2>&1
rc=$?
check "LD_PRELOAD: the app runs unconfined and is denied" "$([[ $rc -ne 0 ]]; echo $?)" "rc=$rc"
wait_out "app=owner exe=.*dropped=LD_PRELOAD"
check "the dropped exec is logged" $? "$(olog | tail -3)"
nobody env LD_LIBRARY_PATH= "$OB/cat" "$E/secret" > /dev/null 2>&1
check "an empty LD_LIBRARY_PATH does not taint" $? ""
# One string may be at most 128 KiB (MAX_ARG_STRLEN), so three of 100 KB.
big=$(head -c 100000 /dev/zero | tr '\0' x)
nobody env B1="$big" B2="$big" B3="$big" "$OB/cat" "$E/secret" > /dev/null 2>&1
check "a 300 KB environment without loader variables is fine" $? ""
nobody env B1="$big" B2="$big" B3="$big" LD_AUDIT=/x.so "$OB/cat" "$E/secret" > /dev/null 2>&1
rc=$?
check "LD_AUDIT after 300 KB of variables is found" "$([[ $rc -ne 0 ]]; echo $?)" "rc=$rc"
# argv is not the environment: the secret is read, the second "file" does
# not exist.
out=$(nobody "$OB/cat" "$E/secret" LD_PRELOAD=/x.so 2> /dev/null)
check "LD_PRELOAD=… as an argument does not taint" "$([[ $out == s3cret ]]; echo $?)" "out=$out"

# --- tamper -------------------------------------------------------------------
# Not through the `nobody` function: that would background a subshell, and
# $! would be the subshell's pid. setpriv execs the app.
setpriv --reuid=65534 --regid=65534 --clear-groups -- "$OB/bash" -c 'read -t 60 _' < <(sleep 60) &
target=$!
tpid=$target
sleep 0.5
emark
nobody cat "/proc/$tpid/environ" > /dev/null 2>&1
rc=$?
check "an unconfined process can't read an app's /proc/<pid>/environ" "$([[ $rc -ne 0 ]]; echo $?)" "rc=$rc"
wait_out "owner=owner ptrace\\(read\\) need=tamper target=$tpid"
check "the denial is logged" $? "$(olog | tail -3)"
nobody "$OB/bash" -c "x=\$(< /proc/$tpid/environ)" 2> /dev/null
check "the same app can" $? ""
nobody bash -c "$OB/bash -c 'read -t 3 _' < <(sleep 3) & sleep 0.3; exec 3< /proc/\$!/mem" 2> /dev/null
rc=$?
check "an unconfined parent can't open its app child's /proc/<pid>/mem" "$([[ $rc -ne 0 ]]; echo $?)" "rc=$rc"
cat "/proc/$tpid/environ" > /dev/null 2>&1
check "root can (bypass on)" $? ""

# --- user-writable exes -------------------------------------------------------
grep -q "exe $W/app-1 of upd is user-writable" "$ERR"
check "the user-writable exe is noticed" $? "$(grep -i writable "$ERR")"
nobody "$W/app-1" -c 'exit 0'
check "anyone may run it" $? ""
nobody bash -c "echo x >> $W/app-1" 2> /dev/null
rc=$?
check "an unconfined process can't write it" "$([[ $rc -ne 0 ]]; echo $?)" "rc=$rc"
nobody mv "$W/app-1" "$W/../moved" 2> /dev/null
rc=$?
check "… nor move it" "$([[ $rc -ne 0 ]]; echo $?)" "rc=$rc"
nobody rm -f "$W/app-1" 2> /dev/null
check "… nor remove it" "$([[ -e $W/app-1 ]]; echo $?)" ""
emark
nobody touch "$W/app-2" 2> /dev/null
check "… nor plant a new version next to it" "$([[ ! -e $W/app-2 ]]; echo $?)" ""
wait_out "subject=unconfined owner=upd exe_dir need=tamper"
check "the planting is logged" $? "$(olog | tail -3)"
nobody "$W/app-1" -c ": > $W/app-3"
check "the app itself may add a version" "$([[ -e $W/app-3 ]]; echo $?)" ""
# Moving the exe's directory aside and creating it anew would put another
# exe at the path the policy names.
emark
nobody mv "$W" "$DIR/home/upd/aside" 2> /dev/null
check "… nor move its directory aside" "$([[ -d $W && ! -e $DIR/home/upd/aside ]]; echo $?)" ""
wait_out "subject=unconfined owner=upd exe_dir need=tamper"
check "the move is logged" $? "$(olog | tail -3)"
nobody mv "$DIR/home/upd" "$DIR/home/aside" 2> /dev/null
check "… nor a directory above it that a user may move" "$([[ -d $DIR/home/upd && ! -e $DIR/home/aside ]]; echo $?)" ""

# --- forced truncate ----------------------------------------------------------
# truncate(2) by path, not open + ftruncate (coreutils), which the open
# check would stop anyway.
nobody python3 -c 'import os, sys; os.truncate(sys.argv[1], 0)' "$E/sgid" 2> /dev/null
rc=$?
check "truncate(2) of a setgid owned file is checked" "$([[ $rc -ne 0 && -s $E/sgid ]]; echo $?)" "rc=$rc"

# --- atomic save of a file root -----------------------------------------------
J=$DIR/home/owner.json
nobody cat "$J" > /dev/null 2>&1
rc=$?
check "the file root is protected" "$([[ $rc -ne 0 ]]; echo $?)" "rc=$rc"
nobody "$OB/bash" -c "echo n3w > $J.tmp" && nobody "$OB/mv" "$J.tmp" "$J"
check "the app saves it by rename" $? ""
# Right away, before the daemon has resolved the path again.
nobody cat "$J" > /dev/null 2>&1
rc=$?
check "the new file is protected at once" "$([[ $rc -ne 0 ]]; echo $?)" "rc=$rc"
# The first `+ root` line is from the start, the second from the rescan.
for _ in $(seq 50); do [[ $(grep -c "+ root $J " "$ERR") -ge 2 ]] && break; sleep 0.1; done
[[ $(grep -c "+ root $J " "$ERR") -ge 2 ]]
check "the daemon takes the new file as the root" $? "$(grep owner.json "$ERR")"
nobody cat "$J" > /dev/null 2>&1
rc=$?
out=$(nobody "$OB/cat" "$J" 2> /dev/null)
check "… still protected, and the app reads it" "$([[ $rc -ne 0 && $out == n3w ]]; echo $?)" "rc=$rc out=$out"

# --- self-protection, bypass on ----------------------------------------------
bpftool map dump pinned "$PIN/ROOTS" > /dev/null 2>&1
rc=$?
check "root can't open a pinned map with bpftool" "$([[ $rc -ne 0 ]]; echo $?)" "rc=$rc"
# Link pins can still be opened (BPF_OBJ_GET of a link has no LSM hook);
# docs/threat-model.md lists that.
rm -f "$PIN/link-file_open" 2> /dev/null
check "root can't remove a pin" "$([[ -e $PIN/link-file_open ]]; echo $?)" ""
nobody touch "$DIR/state/planted" 2> /dev/null
check "nobody can't write explsm's state" "$([[ ! -e $DIR/state/planted ]]; echo $?)" ""
echo "# root was here" >> "$DIR/policy.explsm"
check "root can edit the policy (bypass on)" $? ""

# --- pinning ------------------------------------------------------------------
stop TERM
grep -q "explsm stays loaded" "$ERR"
check "the daemon exits and says explsm stays loaded" $? "$(tail -3 "$ERR")"
nobody env LD_PRELOAD=/x.so "$OB/cat" "$E/secret" > /dev/null 2>&1
rc=$?
check "with no daemon, enforcement goes on" "$([[ $rc -ne 0 ]]; echo $?)" "rc=$rc"
nobody "$OB/cat" "$E/secret" > /dev/null 2>&1
check "… and apps started meanwhile keep their identity" $? ""

start
grep -q "took over the pinned state" "$ERR"
check "a new daemon takes over the pins" $? "$(head -5 "$ERR")"
nobody cat "/proc/$tpid/environ" > /dev/null 2>&1
rc=$?
check "the app process from before still has its identity" "$([[ $rc -ne 0 ]]; echo $?)" "rc=$rc"

if busctl status org.explsm.Daemon1 > /dev/null 2>&1; then
    "$CTL" unload > /dev/null 2>&1
    rc=$?
    wait "$daemon" 2> /dev/null; daemon=
    check "explsmctl unload asks the daemon" "$([[ $rc -eq 0 && ! -e $PIN ]]; echo $?)" "rc=$rc $(tail -3 "$ERR")"
else
    echo "SKIP  explsmctl unload over D-Bus (bus policy not installed)"
    stop TERM
    "$EXPLSMD" --unload --pin-dir "$PIN" --policy "$DIR/policy.explsm" 2> /dev/null
fi
nobody env LD_PRELOAD=/x.so "$OB/cat" "$E/secret" > /dev/null 2>&1
check "after unload, nothing is enforced" $? ""

# --- self-protection, bypass off ----------------------------------------------
start --no-root-bypass
echo "# root was here" >> "$DIR/policy.explsm" 2> /dev/null
rc=$?
check "root can't edit the policy (bypass off)" "$([[ $rc -ne 0 ]]; echo $?)" "rc=$rc"
mv "$EXPLSMD" "$SB/moved" 2> /dev/null
check "root can't move explsmd away (bypass off)" "$([[ -e $EXPLSMD ]]; echo $?)" ""
# Not environ: the kernel lets CAP_PERFMON/CAP_SYS_ADMIN read it whatever
# the LSM says (mm_access). /proc/<pid>/mem is attach mode, with no override.
bash -c "exec 3< /proc/$tpid/mem" 2> /dev/null
rc=$?
check "root can't open an app's /proc/<pid>/mem (bypass off)" "$([[ $rc -ne 0 ]]; echo $?)" "rc=$rc"
stop KILL
"$EXPLSMD" --unload --pin-dir "$PIN" --policy "$DIR/policy.explsm" 2> "$DIR/unload.log"
rc=$?
check "explsmd --unload works with the daemon killed" "$([[ $rc -eq 0 && ! -e $PIN ]]; echo $?)" "rc=$rc $(cat "$DIR/unload.log")"

echo
if [[ $fails -eq 0 ]]; then echo "all passed"; else echo "$fails failed; logs in $DIR"; fi
[[ $fails -eq 0 ]]
