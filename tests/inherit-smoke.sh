#!/usr/bin/env bash
# Smoke test for `inherit` and `env`: an inheriting app keeps its identity
# across execs of exes that are no app, and chooses its own environment;
# allowed loader variables don't drop the identity, others still do; an
# `env` path a user could replace is refused.
#
# Runs explsmd from a copy in a throwaway sandbox in /var/tmp, pinned in
# /sys/fs/bpf/explsm-smoke-inherit (not the real pin directory). Must run
# as root; accessing processes run as `nobody`. If something goes wrong
# half-way, `$DIR/sbin/explsmd --unload --pin-dir
# /sys/fs/bpf/explsm-smoke-inherit` cleans up (or reboot).
#
#   cargo build --release
#   sudo tests/inherit-smoke.sh [target/release]

set -u

BIN=$(realpath "${1:-target/release}")
DIR=/var/tmp/explsm-inherit
PIN=/sys/fs/bpf/explsm-smoke-inherit
[[ $EUID -eq 0 ]] || { echo "must run as root" >&2; exit 2; }
for b in explsmd explsmctl; do
    [[ -x $BIN/$b ]] || { echo "$b not in $BIN; build first" >&2; exit 2; }
done
if busctl status org.explsm.Daemon1 > /dev/null 2>&1; then
    echo "another explsmd owns org.explsm.Daemon1; stop it first" >&2
    exit 2
fi
if [[ -e $PIN ]]; then
    echo "$PIN exists from an earlier run; unload it first:" >&2
    echo "  $DIR/sbin/explsmd --unload --pin-dir $PIN --policy $DIR/policy.explsm" >&2
    exit 2
fi
# A real, root-owned library, harmless to preload.
LIBC=$(ldd "$(type -P cat)" | awk '/libc\.so/ { print $3 }')
[[ -f $LIBC ]] || { echo "libc not found" >&2; exit 2; }

rm -rf "$DIR"
I=$DIR/inherited   # owned by `inh`, which inherits
P=$DIR/plain       # owned by `plain`, which does not
IB=$DIR/inh-bin
PB=$DIR/plain-bin
XB=$DIR/other-bin  # exe of `other`, a third app
SB=$DIR/sbin
mkdir -p "$I" "$P" "$IB" "$PB" "$XB" "$SB" "$DIR/state" "$DIR/claims.d" "$DIR/home"
echo s3cret > "$I/secret"
echo s3cret > "$P/secret"
cp "$(type -P bash)" "$IB/bash"
cp "$(type -P bash)" "$PB/bash"
cp "$(type -P cat)" "$XB/cat"
cp "$BIN/explsmd" "$SB/explsmd"
cp "$BIN/explsmctl" "$SB/explsmctl"
chmod -R a+rX "$DIR"
chmod a+rw "$I/secret" "$P/secret"
chmod a+rwx "$DIR/state"
touch "$DIR/home/lib.so"
chown -R 65534:65534 "$DIR/home"
EXPLSMD=$SB/explsmd
CTL=$SB/explsmctl

cat > "$DIR/policy.explsm" <<EOF
# written by inherit-smoke.sh
users root
app inh {
    exe "$IB/bash"
    owns "$I"
    inherit
    env "LD_PRELOAD=$LIBC"
    mode enforce
}
app plain {
    exe "$PB/bash"
    owns "$P"
    mode enforce
}
app other {
    exe "$XB/cat"
    mode enforce
}
EOF

OUT=$DIR/events.log
ERR=$DIR/explsmd.log

fails=0
check() { # name, condition result (0 = pass), detail
    if [[ $2 -eq 0 ]]; then echo "PASS  $1"; else echo "FAIL  $1: $3"; fails=$((fails + 1)); fi
}
denied() { [[ $1 -ne 0 ]]; echo $?; }
nobody() { setpriv --reuid=65534 --regid=65534 --clear-groups -- "$@"; }
wait_err() {
    for _ in $(seq 50); do grep -qE "$1" "$ERR" && return 0; sleep 0.1; done
    return 1
}

daemon=
start() {
    : > "$ERR"
    "$EXPLSMD" --policy "$DIR/policy.explsm" --claims "$DIR/claims.d" --agent "$DIR/no-agent" \
        --state-dir "$DIR/state" --pin-dir "$PIN" --daemon "$EXPLSMD" >> "$OUT" 2> "$ERR" &
    daemon=$!
    wait_err attached || { echo "explsmd did not start:"; cat "$ERR"; exit 1; }
}
cleanup() {
    [[ -n $daemon ]] && { kill -TERM "$daemon" 2> /dev/null; wait "$daemon" 2> /dev/null; }
    [[ -e $PIN ]] && "$EXPLSMD" --unload --pin-dir "$PIN" --policy "$DIR/policy.explsm" 2> /dev/null
}
trap cleanup EXIT
: > "$OUT"

# --- the policy ---------------------------------------------------------------
"$CTL" check "$DIR/policy.explsm" --resolve > /dev/null 2>&1
check "the policy checks" $? "$("$CTL" check "$DIR/policy.explsm" --resolve 2>&1 | tail -3)"
sed "s|env \"LD_PRELOAD=$LIBC\"|env \"LD_PRELOAD=$DIR/home/lib.so\"|" "$DIR/policy.explsm" \
    > "$DIR/bad.explsm"
out=$("$CTL" check "$DIR/bad.explsm" --resolve 2>&1)
rc=$?
check "an env path a user could replace is refused" \
    "$([[ $rc -ne 0 && $out == *"could replace"* ]]; echo $?)" "rc=$rc $out"

start

# --- inherit ------------------------------------------------------------------
nobody "$IB/bash" -c "cat $I/secret" > /dev/null 2>&1
check "an inheriting app's child (cat) reads its data" $? ""
nobody "$PB/bash" -c "cat $P/secret" > /dev/null 2>&1
check "without inherit, the child is unconfined and denied" "$(denied $?)" ""
nobody "$IB/bash" -c "sh -c 'cat $I/secret'" > /dev/null 2>&1
check "… through several execs" $? ""
nobody "$IB/bash" -c "$XB/cat $I/secret" > /dev/null 2>&1
check "another app's exe takes that app's identity" "$(denied $?)" ""
nobody "$IB/bash" -c "LD_LIBRARY_PATH=/tmp cat $I/secret" > /dev/null 2>&1
check "the app may set loader variables for its children" $? ""
nobody "$IB/bash" -c "LD_PRELOAD=/nonexistent.so $IB/bash -c 'cat $I/secret'" > /dev/null 2>&1
check "… and for its own exe" $? ""
nobody cat "$I/secret" > /dev/null 2>&1
check "an unconfined process is denied" "$(denied $?)" ""

# --- env ----------------------------------------------------------------------
nobody env LD_PRELOAD="$LIBC" "$IB/bash" -c "cat $I/secret" > /dev/null 2>&1
check "an allowed LD_PRELOAD keeps the identity" $? ""
nobody env LD_PRELOAD=/nonexistent.so "$IB/bash" -c "cat $I/secret" > /dev/null 2>&1
check "another LD_PRELOAD drops it" "$(denied $?)" ""
nobody env LD_PRELOAD="$LIBC" LD_LIBRARY_PATH=/tmp "$IB/bash" -c "cat $I/secret" > /dev/null 2>&1
check "an allowed one next to another one drops it" "$(denied $?)" ""
nobody env LD_PRELOAD=/nonexistent.so "$IB/bash" -c "$IB/bash -c 'cat $I/secret'" > /dev/null 2>&1
check "a tainted process does not get the identity back" "$(denied $?)" ""
nobody env LD_PRELOAD="$LIBC" "$PB/bash" -c "cat $P/secret" > /dev/null 2>&1
check "the allowed string is only for its app" "$(denied $?)" ""

echo
if [[ $fails -eq 0 ]]; then echo "all passed"; else echo "$fails failed; logs in $DIR"; fi
[[ $fails -eq 0 ]]
