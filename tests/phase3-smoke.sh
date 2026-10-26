#!/usr/bin/env bash
# Phase 3 smoke test: the policy language, reloads without a restart,
# re-resolution of exes and roots, explsmctl, and the journal fields. Runs
# explsmd against a throwaway sandbox in /var/tmp; enforcement only applies
# there. Must run as root; accessing processes drop to `nobody` so the
# @root bypass does not hide them.
#
# The D-Bus checks run if packaging/org.explsm.Daemon1.conf is installed and
# no other explsmd owns the name; the journal checks need systemd-run.
#
#   cargo build --release
#   sudo tests/phase3-smoke.sh [target/release]

set -u

BIN=$(realpath "${1:-target/release}")
EXPLSMD=$BIN/explsmd
CTL=$BIN/explsmctl
DIR=/var/tmp/explsm-phase3
[[ $EUID -eq 0 ]] || { echo "must run as root" >&2; exit 2; }
[[ -x $EXPLSMD && -x $CTL ]] || { echo "explsmd/explsmctl not in $BIN; build first" >&2; exit 2; }
command -v python3 > /dev/null || { echo "python3 is needed" >&2; exit 2; }

rm -rf "$DIR"
E=$DIR/enforced    # owned by `owner`, enforce mode
L=$DIR/later       # owned by `owner`, created after the daemon started
A=$DIR/audited     # owned by `auditee`, audit mode (journal checks)
OB=$DIR/owner-bin  # exes of `owner`
RB=$DIR/reader-bin # exes of `reader`
PD=$DIR/policy.d
mkdir -p "$E" "$A" "$OB" "$RB" "$PD" "$DIR/audit.d"
echo s3cret > "$E/secret"
echo audit > "$A/file"
cp "$(type -P cat)" "$OB/cat"
cp "$(type -P bash)" "$RB/bash"
cp "$(type -P true)" "$DIR/auditee-true" # never runs
chmod -R a+rwX "$DIR"

policy() { # roots of owner, extra lines
    cat > "$PD/main.explsm" <<EOF
# written by phase3-smoke.sh
app owner {
    exe "$OB/cat"
    owns $1
    mode enforce
}

app reader {
    exe "$RB/bash"
}
$2
EOF
}

OUT=$DIR/events.log
ERR=$DIR/explsmd.log

fails=0
check() { # name, condition result (0 = pass), detail
    if [[ $2 -eq 0 ]]; then echo "PASS  $1"; else echo "FAIL  $1: $3"; fails=$((fails + 1)); fi
}
skip() { echo "SKIP  $1: $2"; }
mark() { wc -l < "$OUT"; }
since() { sleep 0.3; tail -n +"$(( $1 + 1 ))" "$OUT"; }
nobody() { setpriv --reuid=65534 --regid=65534 --clear-groups -- "$@"; }
getlabel() { python3 -c "import os,sys; print(os.getxattr(sys.argv[1], 'security.bpf.explsm').decode())" "$1" 2>/dev/null; }

# Daemon log lines after the last `emark`.
emark() { em=$(wc -l < "$ERR"); }
elog() { tail -n +"$(( em + 1 ))" "$ERR"; }
wait_log() { # pattern: wait up to 5 s for it in the daemon log since `emark`
    for _ in $(seq 50); do elog | grep -qE "$1" && return 0; sleep 0.1; done
    return 1
}

# run CMD...: record its status, output and the events it caused.
run() { m=$(mark); out=$("$@" 2>&1); rc=$?; ev=$(since "$m"); }
denied() { [[ $rc -ne 0 ]]; }
has() { grep -qE "$1" <<< "$ev"; }
quiet() { ! grep -qE "^(deny|audit) " <<< "$ev"; }
hup() { emark; kill -HUP "$daemon"; }

# --- explsmctl check (no daemon) -------------------------------------------
cat > "$DIR/bad.explsm" <<EOF
app a { exe "/usr/bin/true" }
grant nosuch read to a
EOF
out=$("$CTL" check "$DIR/bad.explsm" 2>&1); rc=$?
[[ $rc -ne 0 ]] && grep -q 'unknown app `nosuch`' <<< "$out" && grep -q "bad.explsm:2:7" <<< "$out"
check "check rejects a bad policy with a located diagnostic" $? "rc=$rc $out"

policy "\"$E\", \"$L\"" ""
out=$(nobody "$CTL" check "$PD" 2>&1); rc=$?
[[ $rc -eq 0 ]] && grep -q "policy ok: 1 files, 2 apps, 0 grants" <<< "$out"
check "check accepts a good policy, without root" $? "rc=$rc $out"

# --- start -----------------------------------------------------------------
dbus=0
conf=org.explsm.Daemon1.conf
if [[ -e /etc/dbus-1/system.d/$conf || -e /usr/share/dbus-1/system.d/$conf ]]; then
    if busctl status org.explsm.Daemon1 > /dev/null 2>&1; then
        skip "D-Bus" "another explsmd owns org.explsm.Daemon1"
    else
        dbus=1
    fi
else
    skip "D-Bus" "$conf is not installed"
fi
dbus_args=()
[[ $dbus -eq 1 ]] || dbus_args=(--no-dbus)

: > "$OUT"; : > "$ERR"; em=0
"$EXPLSMD" --policy "$PD" --no-pin --no-self-protect "${dbus_args[@]}" > "$OUT" 2> "$ERR" &
daemon=$!
trap 'kill $daemon 2>/dev/null' EXIT
wait_log attached || { echo "explsmd did not start:"; cat "$ERR"; exit 1; }

grep -q "root $L of owner does not exist" "$ERR"
check "a missing root is reported, not an error" $? "$(cat "$ERR")"

# --- reload ----------------------------------------------------------------
run nobody "$RB/bash" -c "read -r l < '$E/secret'"
denied && has "subject=reader owner=owner open\(r\) need=read $E/secret\$"
check "reader is denied before the grant" $? "rc=$rc $ev"

policy "\"$E\", \"$L\"" "grant reader read to owner"
hup
wait_log "policy reloaded"
run nobody "$RB/bash" -c "read -r l < '$E/secret'; echo \$l"
[[ $rc -eq 0 && $out == s3cret ]] && quiet
check "SIGHUP reload adds a grant without a restart" $? "rc=$rc $out $ev $(elog)"

policy "\"$E\", \"$L\"" "grant reader frobnicate to owner"
hup
wait_log "reload failed" && elog | grep -q 'unknown permission `frobnicate`'
f=$?
run nobody "$RB/bash" -c "read -r l < '$E/secret'"
[[ $f -eq 0 && $rc -eq 0 ]] && quiet
check "a bad reload keeps the old policy" $? "f=$f rc=$rc $ev $(elog)"

policy "\"$E\", \"$L\"" "grant reader read to owner"
hup
wait_log "policy reloaded"

# --- re-resolution ---------------------------------------------------------
emark
cp "$OB/cat" "$OB/cat.new"
mv -f "$OB/cat.new" "$OB/cat"
wait_log "\+ exe +$OB/cat " && elog | grep -qE "\- exe +$OB/cat "
f=$?
run nobody "$OB/cat" "$E/secret"
[[ $f -eq 0 && $rc -eq 0 ]] && quiet
check "an exe replaced by rename is identified again" $? "f=$f rc=$rc $out $ev $(elog)"

emark
mkdir "$L"
echo later > "$L/file"  # opened, so its owner is cached as unprotected
chmod -R a+rwX "$L"
wait_log "\+ root $L "
f=$?
run nobody /usr/bin/cat "$L/file"
[[ $f -eq 0 ]] && denied && has "need=read $L/file\$"
check "a root created after the start is protected" $? "f=$f rc=$rc $ev $(elog)"

label=$(getlabel "$L")
[[ $label == "app=owner mode=enforce" ]]
check "the late root is labelled" $? "label=$label"

emark
mv "$E" "$DIR/elsewhere"
wait_log "moved to $DIR/elsewhere"
f=$?
run nobody /usr/bin/cat "$DIR/elsewhere/secret"
[[ $f -eq 0 ]] && denied && has "need=read"
check "a root moved away from its path stays protected" $? "f=$f rc=$rc $ev $(elog)"
emark
mv "$DIR/elsewhere" "$E"
wait_log "root $E is back at its path"
check "the moved root is found at its path again" $? "$(elog)"

policy "\"$E\"" "grant reader read to owner"
hup
wait_log "policy reloaded" && elog | grep -q "\- root $L "
f=$?
label=$(getlabel "$L")
run nobody /usr/bin/cat "$L/file"
[[ $f -eq 0 && -z $label && $rc -eq 0 ]] && quiet
check "a root removed from the policy is unlabelled and unprotected" $? "f=$f label=$label rc=$rc $ev $(elog)"

# --- D-Bus -----------------------------------------------------------------
if [[ $dbus -eq 1 ]]; then
    out=$("$CTL" status 2>&1); rc=$?
    [[ $rc -eq 0 ]] && grep -q "app owner (enforce" <<< "$out" && grep -qE "root +$E " <<< "$out" \
        && grep -qE "reader -> owner: read" <<< "$out" && grep -q "counters    checks=" <<< "$out"
    check "explsmctl status shows the policy and counters" $? "rc=$rc $out"

    emark
    out=$("$CTL" load 2>&1); rc=$?
    [[ $rc -eq 0 ]] && grep -q "policy loaded: 2 apps" <<< "$out"
    check "explsmctl load reloads over D-Bus" $? "rc=$rc $out"

    out=$(nobody "$CTL" status 2>&1); rc=$?
    [[ $rc -ne 0 ]]
    check "the D-Bus API refuses non-root callers" $? "rc=$rc $out"
fi

kill -INT "$daemon"; wait "$daemon"
grep -E "stopping|warning" "$ERR"

# --- journal: log and learn ------------------------------------------------
if command -v systemd-run > /dev/null; then
    cat > "$DIR/audit.d/audit.explsm" <<EOF
app auditee {
    exe "$DIR/auditee-true"
    owns "$A"
}
EOF
    unit=explsm-smoke-$$
    systemd-run --quiet --collect --unit "$unit" "$EXPLSMD" --policy "$DIR/audit.d" --no-dbus --no-seed --no-pin --no-self-protect
    for _ in $(seq 50); do
        journalctl -q -u "$unit" -o cat | grep -q attached && break
        sleep 0.1
    done
    nobody /usr/bin/cat "$A/file" > /dev/null
    sleep 1
    systemctl stop "$unit"
    out=$("$CTL" log --app auditee --since "5 min ago" 2>&1)
    grep -qE "audit .*subject=unconfined owner=auditee open\(r\) need=read $A/file" <<< "$out"
    check "explsmctl log finds the audited access in the journal" $? "$out"
    out=$("$CTL" learn auditee --since "5 min ago" 2>&1)
    grep -q "# grant @unconfined read to auditee" <<< "$out" && grep -q "from cat" <<< "$out"
    check "explsmctl learn suggests the grant" $? "$out"
else
    skip "journal" "systemd-run is not available"
fi

echo
echo "logs: $OUT $ERR"
if [[ $fails -eq 0 ]]; then echo "all checks passed"; else echo "$fails check(s) failed"; exit 1; fi
