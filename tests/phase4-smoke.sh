#!/usr/bin/env bash
# Phase 4 smoke test: prompts answered by explsm-agent (process, session and
# permanent grants, deny), agent registration, auto-claim, and @terminal.
# Runs explsmd against a throwaway sandbox in /var/tmp. Must run as root;
# accessing processes and their agent run as `nobody`. The auto-claim checks
# create two folders in /root (an app's folder must be right in a home) and
# remove them again.
#
# Needs the Phase 4 packaging/org.explsm.Daemon1.conf installed (agents call
# org.explsm.AgentManager1) and no other explsmd running. `script` (util-linux)
# gives the @terminal checks a tty.
#
# The agent must be built with the `test-answer` feature (`--answer`), which
# an installed agent must never have.
#
#   cargo build --release --features explsm-agent/test-answer
#   sudo install -m644 packaging/org.explsm.Daemon1.conf /etc/dbus-1/system.d/
#   sudo tests/phase4-smoke.sh [target/release]

set -u

BIN=$(realpath "${1:-target/release}")
EXPLSMD=$BIN/explsmd
CTL=$BIN/explsmctl
DIR=/var/tmp/explsm-phase4
[[ $EUID -eq 0 ]] || { echo "must run as root" >&2; exit 2; }
for b in explsmd explsmctl explsm-agent; do
    [[ -x $BIN/$b ]] || { echo "$b not in $BIN; build first" >&2; exit 2; }
done
"$BIN/explsm-agent" --help | grep -q -- --answer ||
    { echo "build the agent with --features explsm-agent/test-answer" >&2; exit 2; }
command -v script > /dev/null || { echo "script (util-linux) is needed" >&2; exit 2; }
conf=org.explsm.Daemon1.conf
if ! grep -qs AgentManager1 "/etc/dbus-1/system.d/$conf" "/usr/share/dbus-1/system.d/$conf"; then
    echo "install the Phase 4 packaging/$conf into /etc/dbus-1/system.d/ first" >&2
    exit 2
fi
if busctl status org.explsm.Daemon1 > /dev/null 2>&1; then
    echo "another explsmd owns org.explsm.Daemon1; stop it first" >&2
    exit 2
fi

rm -rf "$DIR"
E=$DIR/enforced     # owned by `owner`, enforce mode
OB=$DIR/owner-bin   # exe of `owner`
RB=$DIR/reader-bin  # exe of `reader`, an app with no grants
MB=$DIR/maker-bin   # exe of `maker`, which creates folders in /root
TB=$DIR/term-bin    # a terminal "emulator" (a copy of bash)
UB=$DIR/bin         # unconfined copies of cat (UB/N/cat) and bash, one per scenario
AB=$DIR/agent-bin   # the agent exe explsmd trusts
CD=$DIR/claims.d
mkdir -p "$E" "$OB" "$RB" "$MB" "$TB" "$UB" "$AB" "$CD" "$DIR/state"
echo s3cret > "$E/secret"
cp "$(type -P cat)" "$OB/cat"
cp "$(type -P bash)" "$RB/bash"
cp "$(type -P mkdir)" "$MB/mkdir"
cp "$(type -P bash)" "$TB/term"
# Each cat keeps its name: uutils coreutils picks the tool by file name.
for i in 1 2 3 4 5; do mkdir -p "$UB/$i"; cp "$(type -P cat)" "$UB/$i/cat"; done
# 5/cat is also 6/cat: a hard-linked exe is never offered "always".
mkdir -p "$UB/6"; ln "$UB/5/cat" "$UB/6/cat"
cp "$(type -P bash)" "$UB/bash1"
cp "$BIN/explsm-agent" "$AB/explsm-agent"
chmod -R a+rwX "$DIR"
chmod 755 "$AB" "$AB/explsm-agent" # not writable by the agent's user
CLAIM_A=/root/.explsm-smoke-a-$$
CLAIM_B=/root/.explsm-smoke-b-$$

cat > "$DIR/policy.explsm" <<EOF
# written by phase4-smoke.sh
users root
app owner {
    exe "$OB/cat"
    owns "$E"
    mode enforce
}
app reader { exe "$RB/bash" }
app maker { exe "$MB/mkdir" }
terminal "$TB/term"
grant @terminal read to owner
EOF

OUT=$DIR/events.log
ERR=$DIR/explsmd.log

fails=0
check() { # name, condition result (0 = pass), detail
    if [[ $2 -eq 0 ]]; then echo "PASS  $1"; else echo "FAIL  $1: $3"; fails=$((fails + 1)); fi
}
nobody() { setpriv --reuid=65534 --regid=65534 --clear-groups -- "$@"; }
emark() { em=$(wc -l < "$ERR"); }
elog() { tail -n +"$(( em + 1 ))" "$ERR"; }
wait_log() { # pattern: wait up to 5 s for it in the daemon log since `emark`
    for _ in $(seq 50); do elog | grep -qE "$1" && return 0; sleep 0.1; done
    return 1
}
# cat that stays a moment after a denial, so the daemon finds its exe in
# /proc (it is not in a bin directory, where it would be found anyway).
read_secret() { sleep 0.5 | "$@" "$E/secret" - > /dev/null 2>&1; }

agent=
agent_pid=
start_agent() { # user answer
    stop_agent
    agent=$DIR/agent-$1-$2.log
    # Not through the `nobody` function: that would background a subshell,
    # and killing it would leave the agent running.
    if [[ $1 == nobody ]]; then
        setpriv --reuid=65534 --regid=65534 --clear-groups -- \
            "$AB/explsm-agent" --answer "$2" > "$agent" 2>&1 &
    else
        "$AB/explsm-agent" --answer "$2" > "$agent" 2>&1 &
    fi
    agent_pid=$!
    for _ in $(seq 50); do grep -q "registered with explsmd" "$agent" && return 0; sleep 0.1; done
    echo "agent did not register:"; cat "$agent"; return 1
}
stop_agent() {
    [[ -n $agent_pid ]] || return 0
    kill "$agent_pid" 2> /dev/null; wait "$agent_pid" 2> /dev/null; agent_pid=
}

: > "$OUT"; : > "$ERR"; em=0
"$EXPLSMD" --policy "$DIR/policy.explsm" --claims "$CD" --agent "$AB/explsm-agent" --no-pin --no-self-protect \
    --state-dir "$DIR/state" > "$OUT" 2> "$ERR" &
daemon=$!
trap 'stop_agent; kill $daemon 2>/dev/null; rmdir $CLAIM_A $CLAIM_B 2>/dev/null' EXIT
wait_log attached || { echo "explsmd did not start:"; cat "$ERR"; exit 1; }

# --- registration -----------------------------------------------------------
emark
out=$(nobody busctl call org.explsm.Daemon1 /org/explsm/Daemon1 \
    org.explsm.AgentManager1 Register 2>&1); rc=$?
[[ $rc -ne 0 ]] && wait_log "refused agent registration .*uid 65534"
check "a process that is not the agent can't register" $? "rc=$rc $out $(elog)"

emark
start_agent nobody allow-session
wait_log "agent of uid 65534 registered"
check "the agent registers" $? "$(elog) $(cat "$agent")"
nobody cat "/proc/$agent_pid/environ" > /dev/null 2>&1
rc=$?
check "an unconfined process of the user can't read the agent's memory" "$([[ $rc -ne 0 ]]; echo $?)" "rc=$rc"

# --- allow for the session --------------------------------------------------
emark
read_secret nobody "$UB/1/cat"; first=$?
wait_log "answered allow-session for $UB/1/cat on owner"
f=$?
read_secret nobody "$UB/1/cat"; second=$?
[[ $first -ne 0 && $f -eq 0 && $second -eq 0 ]]
check "allow-session: denied, prompted, then allowed" $? "first=$first f=$f second=$second $(elog)"

out=$("$CTL" status 2>&1)
grep -q "agent       uid 65534" <<< "$out" && grep -qE "prompted +uid 65534: $UB/1/cat -> owner: read \(until logout\)" <<< "$out"
check "explsmctl status shows the agent and the session grant" $? "$out"

emark
stop_agent
wait_log "agent of uid 65534 left; 1 session grants ended"
f=$?
read_secret nobody "$UB/1/cat"
[[ $f -eq 0 && $? -ne 0 ]]
check "session grants end when the agent leaves" $? "f=$f $(elog)"

# --- allow for the process --------------------------------------------------
start_agent nobody allow-process
emark
out=$(nobody "$UB/bash1" -c "read -r l < '$E/secret' 2>/dev/null || echo denied; sleep 1.5; read -r l < '$E/secret' && echo \$l")
[[ $out == $'denied\ns3cret' ]]
check "allow-process: the same process may retry" $? "out=$out $(elog)"
sleep 0.5
out=$("$CTL" status 2>&1)
! grep -q "until it exits" <<< "$out"
check "the process grant ends when the process exits" $? "$out"

# --- allow always -----------------------------------------------------------
start_agent nobody allow-always
emark
read_secret nobody "$UB/3/cat"
wait_log "policy reloaded"
f=$?
read_secret nobody "$UB/3/cat"; rc=$?
grep -q "app cat { exe \"$UB/3/cat\" }" "$CD/nobody.explsm" && grep -q "grant cat read to owner" "$CD/nobody.explsm"
w=$?
[[ $f -eq 0 && $w -eq 0 && $rc -eq 0 ]]
check "allow-always for an unconfined exe writes an app and a grant" $? "f=$f w=$w rc=$rc $(cat "$CD"/*.explsm 2>&1) $(elog)"

emark
nobody "$RB/bash" -c "read -r l < '$E/secret'" 2> /dev/null
wait_log "policy reloaded"
grep -q "grant reader read to owner" "$CD/nobody.explsm"
w=$?
nobody "$RB/bash" -c "read -r l < '$E/secret'" 2> /dev/null; rc=$?
[[ $w -eq 0 && $rc -eq 0 ]]
check "allow-always for an app writes a grant" $? "w=$w rc=$rc $(elog)"

emark
kill -HUP "$daemon"
wait_log "policy reloaded"
read_secret nobody "$UB/3/cat"
check "the written grants survive a reload" $? "$(elog)"

# --- only offered answers ---------------------------------------------------
start_agent nobody force:allow-always
emark
read_secret nobody "$UB/5/cat"
for _ in $(seq 50); do grep -q "is not an answer to this prompt" "$agent" && break; sleep 0.1; done
grep -q "is not an answer to this prompt" "$agent"
r=$?
! grep -qs "$UB/[56]/cat" "$CD/nobody.explsm"
w=$?
read_secret nobody "$UB/5/cat"; rc=$?
[[ $r -eq 0 && $w -eq 0 && $rc -ne 0 ]]
check "an answer that was not offered is refused" $? "r=$r w=$w rc=$rc $(cat "$agent") $(elog)"

# --- deny -------------------------------------------------------------------
start_agent nobody deny
emark
read_secret nobody "$UB/4/cat"
wait_log "answered deny for $UB/4/cat"
f=$?
read_secret nobody "$UB/4/cat"; rc=$?
sleep 0.5
prompts=$(grep -c "prompt .*$UB/4/cat" "$agent")
[[ $f -eq 0 && $rc -ne 0 && $prompts -eq 1 ]]
check "deny keeps denying and is not asked again" $? "f=$f rc=$rc prompts=$prompts"
stop_agent

# --- auto-claim -------------------------------------------------------------
start_agent root claim
emark
"$MB/mkdir" "$CLAIM_A"
wait_log "\+ root $CLAIM_A "
f=$?
grep -q "claim maker \"$CLAIM_A\"" "$CD/root.explsm" && grep -qE "^claim .* app=maker path=$CLAIM_A$" "$OUT"
[[ $f -eq 0 && $? -eq 0 ]]
check "claim: a new folder of an app becomes its root" $? "f=$f $(cat "$CD/root.explsm" 2>&1) $(elog)"

start_agent root decline
emark
"$MB/mkdir" "$CLAIM_B"
wait_log "answered decline for $CLAIM_B of maker"
f=$?
rmdir "$CLAIM_B"; "$MB/mkdir" "$CLAIM_B"
sleep 1.5 # new folders are asked about a second after they appear
prompts=$(grep -c "prompt .*$CLAIM_B" "$agent")
grep -q "maker	$CLAIM_B" "$DIR/state/declined-claims"
[[ $f -eq 0 && $? -eq 0 && $prompts -eq 1 ]]
check "decline: remembered and not asked again" $? "f=$f prompts=$prompts $(elog)"
stop_agent

# --- @terminal ----------------------------------------------------------------
out=$(nobody "$TB/term" -c "script -qec 'cat $E/secret' /dev/null" 2>&1)
grep -q s3cret <<< "$out"
check "@terminal: below a terminal, with a tty, allowed" $? "$out"

nobody "$TB/term" -c "setsid cat '$E/secret' < /dev/null > /dev/null 2>&1"
check "@terminal: without a controlling tty, denied" $(( $? == 0 )) ""

out=$(nobody "$TB/term" -c "script -qec \"$RB/bash -c 'cat $E/secret'\" /dev/null" 2>&1)
! grep -q s3cret <<< "$out"
check "@terminal: an app in between ends the trust" $? "$out"

out=$(nobody bash -c "script -qec 'cat $E/secret' /dev/null" 2>&1)
! grep -q s3cret <<< "$out"
check "@terminal: not below a terminal, denied" $? "$out"

grep -qE "subject=unconfined\(terminal\)" "$OUT"
check "terminal processes are marked in the log" $? ""

kill -INT "$daemon"; wait "$daemon"
grep -E "stopping|warning" "$ERR"
rmdir "$CLAIM_A" "$CLAIM_B" 2> /dev/null

echo
echo "logs: $OUT $ERR $DIR/agent-*.log"
if [[ $fails -eq 0 ]]; then echo "all checks passed"; else echo "$fails check(s) failed"; exit 1; fi
