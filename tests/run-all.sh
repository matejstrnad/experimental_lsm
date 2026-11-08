#!/usr/bin/env bash
# Run the smoke tests one after another and print one summary table. Meant
# for a throwaway VM (tests/vm-smoke.sh boots one): it starts a private
# system D-Bus with explsm's bus policy when none is running, which writes
# to /etc, so on anything else it refuses unless given --not-a-vm.
#
#   sudo tests/run-all.sh [options] [TEST...]
#
# TEST is a name like phase2, phase4-smoke or tests/phase4-smoke.sh; the
# default is every test. Options:
#   --bin DIR        explsmd, explsmctl and explsm-agent (default target/release)
#   --agent-bin DIR  the same, with the agent built with the `test-answer`
#                    feature, for phase4 (default target/smoke/release)
#   --any-build      SMOKE_ANY_BUILD=1: don't refuse builds older than the sources
#   --timeout SECS   per test (default 1200)
#   --not-a-vm       run on a machine that is not a VM anyway
#   --list           print the test names and exit
#
# Exits 0 if every test passed, 1 if any failed, 2 on a usage or setup error.

set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
ALL=(phase2 phase3 phase4 phase5 phase6 inherit landlock)
BIN=$ROOT/target/release
AGENT_BIN=$ROOT/target/smoke/release
TIMEOUT=1200
NOT_A_VM=0
LOGS=/var/tmp/explsm-run-all

usage() { sed -n '2,/^$/s/^# \{0,1\}//p' "$0"; exit "${1:-2}"; }

tests=()
while (($#)); do
    case $1 in
        --bin) BIN=${2:?--bin needs a directory}; shift ;;
        --agent-bin) AGENT_BIN=${2:?--agent-bin needs a directory}; shift ;;
        --any-build) export SMOKE_ANY_BUILD=1 ;;
        --timeout) TIMEOUT=${2:?--timeout needs seconds}; shift ;;
        --not-a-vm) NOT_A_VM=1 ;;
        --list) printf '%s\n' "${ALL[@]}"; exit 0 ;;
        -h | --help) usage 0 ;;
        -*) echo "unknown option $1" >&2; usage ;;
        *)
            t=${1##*/}; t=${t%.sh}; t=${t%-smoke}
            [[ -f $ROOT/tests/$t-smoke.sh ]] || { echo "no test $1 (try --list)" >&2; exit 2; }
            tests+=("$t") ;;
    esac
    shift
done
((${#tests[@]})) || tests=("${ALL[@]}")

[[ $EUID -eq 0 ]] || { echo "must run as root" >&2; exit 2; }
in_vm() {
    grep -q virtme /proc/cmdline 2> /dev/null && return 0
    command -v systemd-detect-virt > /dev/null && systemd-detect-virt --vm --quiet
}
if [[ $NOT_A_VM -ne 1 ]] && ! in_vm; then
    echo "this is not a VM; run tests/vm-smoke.sh instead, or pass --not-a-vm" >&2
    exit 2
fi
BIN=$(realpath "$BIN")
AGENT_BIN=$(realpath -m "$AGENT_BIN")
cd "$ROOT" || exit 2

# --- what the tests need ------------------------------------------------------
missing=()
for c in busctl setpriv unshare prlimit script python3 bpftool dbus-daemon timeout; do
    command -v "$c" > /dev/null || missing+=("$c")
done
((${#missing[@]})) && { echo "missing commands: ${missing[*]}" >&2; exit 2; }
getent passwd 65534 > /dev/null || { echo "no user 65534 (nobody)" >&2; exit 2; }
grep -qw bpf /sys/kernel/security/lsm ||
    { echo "bpf is not in the active LSMs ($(cat /sys/kernel/security/lsm)); boot with lsm=...,bpf" >&2; exit 2; }
[[ -e /sys/kernel/btf/vmlinux ]] || { echo "the kernel has no BTF (/sys/kernel/btf/vmlinux)" >&2; exit 2; }
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf ||
    { echo "can't mount bpffs on /sys/fs/bpf" >&2; exit 2; }
probe=$(mktemp /var/tmp/.run-all-XXXXXX) || { echo "/var/tmp is not writable" >&2; exit 2; }
rm -f "$probe"
mkdir -p "$LOGS"

# A system bus with explsm's policy, unless one is running already.
CONF=org.explsm.Daemon1.conf
bus_pid=
if busctl status > /dev/null 2>&1; then
    grep -qs AgentManager1 "/etc/dbus-1/system.d/$CONF" "/usr/share/dbus-1/system.d/$CONF" ||
        echo "warning: the running system bus has no $CONF; phase4 will fail" >&2
else
    echo "== starting a private system bus with packaging/$CONF"
    install -D -m644 "$ROOT/packaging/$CONF" "/etc/dbus-1/system.d/$CONF" || exit 2
    mkdir -p /run/dbus
    rm -f /run/dbus/system_bus_socket /run/dbus/pid
    # The distribution's system.conf (it includes system.d) drops to
    # messagebus when that user exists; --nofork keeps $! the daemon.
    dbus-daemon --system --nofork --nopidfile > "$LOGS/dbus-daemon.log" 2>&1 &
    bus_pid=$!
    for _ in $(seq 50); do busctl status > /dev/null 2>&1 && break; sleep 0.1; done
    busctl status > /dev/null 2>&1 ||
        { echo "dbus-daemon did not start:"; cat "$LOGS/dbus-daemon.log"; exit 2; } >&2
fi
cleanup() { [[ -n $bus_pid ]] && kill "$bus_pid" 2> /dev/null; }
trap cleanup EXIT

echo "kernel $(uname -r), LSMs $(cat /sys/kernel/security/lsm)"

# --- the tests ------------------------------------------------------------------
declare -A pass fail skip status
for t in "${tests[@]}"; do
    case $t in
        phase2) args=("$BIN/explsmd") ;;
        phase4) args=("$AGENT_BIN") ;;
        *) args=("$BIN") ;;
    esac
    log=$LOGS/$t.log
    echo
    echo "######## $t-smoke.sh ${args[*]}"
    # Its own process group, so a timeout takes the daemons it started too.
    timeout --kill-after=30 "$TIMEOUT" setsid --wait \
        bash "$ROOT/tests/$t-smoke.sh" "${args[@]}" < /dev/null 2>&1 | tee "$log"
    rc=${PIPESTATUS[0]}
    [[ $rc -eq 124 ]] && echo "TIMEOUT after ${TIMEOUT}s" | tee -a "$log"
    pass[$t]=$(grep -c '^PASS ' "$log")
    fail[$t]=$(grep -c '^FAIL ' "$log")
    skip[$t]=$(grep -c '^SKIP ' "$log")
    status[$t]=$rc
    # Whatever a failed test left behind would disturb the next one.
    pkill -x explsmd 2> /dev/null && sleep 1
    pkill -x explsm-agent 2> /dev/null
done

# --- summary --------------------------------------------------------------------
echo
printf '%-10s %5s %5s %5s  %s\n' test PASS FAIL SKIP exit
failed=0
for t in "${tests[@]}"; do
    s=${status[$t]}
    if [[ $s -eq 0 && ${fail[$t]} -eq 0 ]]; then r=ok; else r=FAILED; failed=1; fi
    [[ $s -eq 124 ]] && r="FAILED (timeout)"
    printf '%-10s %5d %5d %5d  %-3d %s\n' "$t" "${pass[$t]}" "${fail[$t]}" "${skip[$t]}" "$s" "$r"
done
echo "logs: $LOGS"
exit "$failed"
