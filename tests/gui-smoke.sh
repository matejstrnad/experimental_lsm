#!/usr/bin/env bash
# GUI smoke test: explsmd's methods for explsm-gui on
# org.explsm.AgentManager1 (UserStatus, RevokeTemp, RevokeSaved, SetSecret):
# only the GUI and agent exes may call them, only about their own user,
# and they do what they say. Runs explsmd against a throwaway sandbox in
# /var/tmp. Must run as root; the user is `nobody`. No display is needed:
# the GUI's `test` command calls the methods without a window.
#
# Needs packaging/org.explsm.Daemon1.conf installed and no other explsmd
# running. The agent must be built with `test-answer` and the GUI with
# `test-cli`, which installed ones must never have:
#
#   cargo build --release --features explsm-agent/test-answer,explsm-gui/test-cli
#   sudo install -m644 packaging/org.explsm.Daemon1.conf /etc/dbus-1/system.d/
#   sudo tests/gui-smoke.sh [target/release]

set -u

BIN=$(realpath "${1:-target/release}")
EXPLSMD=$BIN/explsmd
DIR=/var/tmp/explsm-gui-smoke
[[ $EUID -eq 0 ]] || { echo "must run as root" >&2; exit 2; }
. "$(dirname "$0")/common.sh"
fresh "$BIN/explsmd" "$BIN/explsm-agent" "$BIN/explsm-gui"
step "setting up $DIR"
"$BIN/explsm-agent" --help | grep -q -- --answer ||
    { echo "build the agent with --features explsm-agent/test-answer" >&2; exit 2; }
"$BIN/explsm-gui" test 2>&1 | grep -q "usage: explsm-gui test" ||
    { echo "build the GUI with --features explsm-gui/test-cli" >&2; exit 2; }
command -v python3 > /dev/null || { echo "python3 is needed" >&2; exit 2; }
conf=org.explsm.Daemon1.conf
if ! grep -qs AgentManager1 "/etc/dbus-1/system.d/$conf" "/usr/share/dbus-1/system.d/$conf"; then
    echo "install packaging/$conf into /etc/dbus-1/system.d/ first" >&2
    exit 2
fi
if busctl status org.explsm.Daemon1 > /dev/null 2>&1; then
    echo "another explsmd owns org.explsm.Daemon1; stop it first" >&2
    exit 2
fi

rm -rf "$DIR"
E=$DIR/enforced     # owned by `owner`, enforce mode
OB=$DIR/owner-bin   # exe of `owner`
UB=$DIR/bin         # unconfined copies of cat, one per scenario
AB=$DIR/agent-bin   # the agent and GUI exes explsmd trusts
FB=$DIR/fake-bin    # a copy of the GUI at a path explsmd does not trust
CD=$DIR/claims.d
mkdir -p "$E" "$OB" "$UB" "$AB" "$FB" "$CD" "$DIR/state"
echo s3cret > "$E/secret"
cp "$(type -P cat)" "$OB/cat"
# Each cat keeps its name: uutils coreutils picks the tool by file name.
for i in 1 2; do mkdir -p "$UB/$i"; cp "$(type -P cat)" "$UB/$i/cat"; done
cp "$BIN/explsm-agent" "$AB/explsm-agent"
cp "$BIN/explsm-gui" "$AB/explsm-gui"
cp "$BIN/explsm-gui" "$FB/explsm-gui"
chmod -R a+rwX "$DIR"
chmod 755 "$AB" "$AB/explsm-agent" "$AB/explsm-gui" # not writable by the user

cat > "$DIR/policy.explsm" <<EOF
# written by gui-smoke.sh
users root
app owner {
    exe "$OB/cat"
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
gui() { nobody "$AB/explsm-gui" test "$@"; }
emark() { em=$(wc -l < "$ERR"); }
elog() { tail -n +"$(( em + 1 ))" "$ERR"; }
wait_log() { # pattern: wait up to 5 s for it in the daemon log since `emark`
    for _ in $(seq $((50 * ${SMOKE_SLOW:-1}))); do elog | grep -qE "$1" && return 0; sleep 0.1; done
    return 1
}
# json EXPR: evaluate a Python expression on the JSON on stdin (`s`).
json() { python3 -c "import json,sys; s=json.load(sys.stdin); print($1)"; }
# cat that stays a moment after a denial, so the daemon finds its exe in
# /proc (it is not in a bin directory, where it would be found anyway).
read_secret() { sleep 0.5 | "$@" "$E/secret" - > /dev/null 2>&1; }

agent=
agent_pid=
start_agent() { # answer (as nobody)
    stop_agent
    agent=$DIR/agent-$1.log
    setpriv --reuid=65534 --regid=65534 --clear-groups -- \
        "$AB/explsm-agent" --answer "$1" > "$agent" 2>&1 &
    agent_pid=$!
    for _ in $(seq $((50 * ${SMOKE_SLOW:-1}))); do grep -q "registered with explsmd" "$agent" && return 0; sleep 0.1; done
    echo "agent did not register:"; cat "$agent"; return 1
}
stop_agent() {
    [[ -n $agent_pid ]] || return 0
    kill "$agent_pid" 2> /dev/null; wait "$agent_pid" 2> /dev/null; agent_pid=
}

: > "$OUT"; : > "$ERR"; em=0
"$EXPLSMD" --policy "$DIR/policy.explsm" --claims "$CD" --agent "$AB/explsm-agent" \
    --gui "$AB/explsm-gui" --no-pin --no-self-protect \
    --state-dir "$DIR/state" > "$OUT" 2> "$ERR" &
daemon=$!
trap 'stop_agent; kill $daemon 2>/dev/null' EXIT
wait_log attached || { echo "explsmd did not start:"; cat "$ERR"; exit 1; }

# --- who may call ---------------------------------------------------------------
out=$(nobody busctl call org.explsm.Daemon1 /org/explsm/Daemon1 \
    org.explsm.AgentManager1 UserStatus 2>&1); rc=$?
# busctl shows an AccessDenied error by its name, not its message.
[[ $rc -ne 0 ]] && grep -qiE "access denied|only explsm-agent and explsm-gui" <<< "$out"
check "a process that is not the GUI can't read the user status" $? "rc=$rc $out"

out=$(nobody "$FB/explsm-gui" test status 2>&1); rc=$?
[[ $rc -ne 0 ]] && grep -q "only explsm-agent and explsm-gui" <<< "$out"
check "a copy of the GUI at another path can't either" $? "rc=$rc $out"

out=$(nobody busctl call org.explsm.Daemon1 /org/explsm/Daemon1 \
    org.explsm.AgentManager1 SetSecret '(ss)' starred-symbolic fake 2>&1); rc=$?
check "a process that is not the GUI can't set the picture" "$([[ $rc -ne 0 ]]; echo $?)" "rc=$rc $out"

out=$(gui status 2>&1); rc=$?
apps=$(json '",".join(a["name"] for a in s["apps"])' <<< "$out" 2>&1)
[[ $rc -eq 0 && $apps == owner ]]
check "the GUI reads the user status" $? "rc=$rc apps=$apps $out"

# --- the security picture -------------------------------------------------------
out=$(gui status | json 's["secret"]["icon"] == ""' 2>&1)
check "no picture at first" "$([[ $out == True ]]; echo $?)" "$out"

out=$(gui set-secret weather-clear-night-symbolic "blue horse" 2>&1); rc=$?
pic=$(gui status | json 's["secret"]["icon"] + "/" + s["secret"]["phrase"]' 2>&1)
[[ $rc -eq 0 && $pic == "weather-clear-night-symbolic/blue horse" ]]
check "the GUI sets the picture and reads it back" $? "rc=$rc $out pic=$pic"

f=$DIR/state/secret-65534
mode=$(stat -c '%a %U' "$f" 2>&1)
nobody cat "$f" > /dev/null 2>&1; rc=$?
[[ $mode == "600 root" && $rc -ne 0 ]]
check "the picture is kept where the user can't read it" $? "mode=$mode rc=$rc"

out=$(gui set-secret evil-icon x 2>&1); rc=$?
pic=$(gui status | json 's["secret"]["icon"]' 2>&1)
[[ $rc -ne 0 && $pic == weather-clear-night-symbolic ]]
check "an unknown picture is refused" $? "rc=$rc $out pic=$pic"

out=$("$AB/explsm-gui" test status | json 's["secret"]["icon"] == ""' 2>&1)
check "each user has their own picture" "$([[ $out == True ]]; echo $?)" "$out"

# --- grants until logout ----------------------------------------------------------
start_agent allow-session
emark
read_secret nobody "$UB/1/cat"
wait_log "answered allow-session for $UB/1/cat on owner"
read_secret nobody "$UB/1/cat"
check "allow-session gives a grant" $? "$(elog)"

st=$(gui status 2>&1)
t=$(json '[(g["subject"], g["owner"], g["lifetime"]) for g in s["temp_grants"]]' <<< "$st" 2>&1)
h=$(json '[(e["answer"], e["subject"], e["owner"]) for e in s["history"]]' <<< "$st" 2>&1)
a=$(json 's["agent"]' <<< "$st" 2>&1)
[[ $t == "[('$UB/1/cat', 'owner', 'session')]" && $h == "[('allow-session', '$UB/1/cat', 'owner')]" && $a == True ]]
check "the status lists the grant, the answer and the agent" $? "t=$t h=$h a=$a"

out=$("$AB/explsm-gui" test revoke-temp "$UB/1/cat" owner 2>&1)
read_secret nobody "$UB/1/cat"; rc=$?
[[ $out == 0 && $rc -eq 0 ]]
check "another user can't revoke the grant" $? "out=$out rc=$rc"

emark
out=$(gui revoke-temp "$UB/1/cat" owner 2>&1)
wait_log "uid 65534 revoked 1 temporary grants of $UB/1/cat on owner"
f=$?
# The agent re-allows the denial that follows; the read itself fails.
read_secret nobody "$UB/1/cat"; rc=$?
[[ $out == 1 && $f -eq 0 && $rc -ne 0 ]]
check "the user revokes the grant until logout" $? "out=$out f=$f rc=$rc $(elog)"

# --- saved grants -------------------------------------------------------------------
start_agent allow-always
emark
read_secret nobody "$UB/2/cat"
wait_log "policy reloaded"
read_secret nobody "$UB/2/cat"; rc=$?
s=$(gui status | json '[(g["subject"], g["exe"], g["owner"]) for g in s["saved_grants"]]' 2>&1)
[[ $rc -eq 0 && $s == "[('cat', '$UB/2/cat', 'owner')]" ]]
check "the status lists the saved grant with its exe" $? "rc=$rc s=$s $(elog)"

start_agent deny
emark
out=$(gui revoke-saved cat owner 2>&1); rc=$?
wait_log "uid 65534 revoked the grant of cat on owner; policy reloaded"
f=$?
read_secret nobody "$UB/2/cat"; r=$?
left=$(grep -c "cat" "$CD/nobody.explsm")
[[ $rc -eq 0 && $f -eq 0 && $r -ne 0 && $left -eq 0 ]]
check "the user revokes a saved grant: the app and grant are taken out" $? \
    "rc=$rc $out f=$f r=$r left=$left $(cat "$CD/nobody.explsm") $(elog)"

out=$(gui revoke-saved cat owner 2>&1); rc=$?
check "revoking a grant that is not there fails" "$([[ $rc -ne 0 ]]; echo $?)" "rc=$rc $out"

out=$(gui status | json 'len(s["saved_grants"])' 2>&1)
check "the status no longer lists it" "$([[ $out == 0 ]]; echo $?)" "$out"
stop_agent

kill -INT "$daemon"; wait "$daemon"
grep -E "stopping|warning" "$ERR"

echo
echo "logs: $OUT $ERR $DIR/agent-*.log"
if [[ $fails -eq 0 ]]; then echo "all checks passed"; else echo "$fails check(s) failed"; exit 1; fi
