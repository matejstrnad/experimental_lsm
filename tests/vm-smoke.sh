#!/usr/bin/env bash
# Build explsm and run every smoke test (tests/run-all.sh) as root in a
# throwaway virtme-ng VM: a copy-on-write snapshot of this machine's root
# filesystem, so the tests change nothing here. Run as a normal user.
#
#   tests/vm-smoke.sh [options] [TEST...]
#
# Options:
#   --kernel K     the kernel to boot: a bzImage/vmlinuz path, a directory
#                  with one, or an upstream version like v6.9, which vng
#                  downloads from kernel.ubuntu.com's mainline builds
#                  (default: the running kernel)
#   --cpus N       guest CPUs (default 2)
#   --memory SIZE  guest memory (default 2G)
#   --no-build     test the builds in target/ as they are
#   --any-build    don't refuse builds older than the sources (SMOKE_ANY_BUILD)
#   --timeout SECS per test, passed to run-all.sh (default 1200)
#   --dry-run      print the vng command instead of running it
#
# The logs of each test end up in target/vm-smoke-logs/.
#
# TEST names are passed to tests/run-all.sh (see `tests/run-all.sh --list`).
# Exits with run-all.sh's status: 0 if every test passed.

set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
KERNEL=
CPUS=2
MEMORY=2G
BUILD=1
DRY=0
run_args=()

usage() { sed -n '2,/^$/s/^# \{0,1\}//p' "$0"; exit "${1:-2}"; }

while (($#)); do
    case $1 in
        --kernel) KERNEL=${2:?--kernel needs a path or version}; shift ;;
        --cpus) CPUS=${2:?--cpus needs a number}; shift ;;
        --memory) MEMORY=${2:?--memory needs a size}; shift ;;
        --no-build) BUILD=0 ;;
        --any-build) run_args+=(--any-build) ;;
        --timeout) run_args+=(--timeout "${2:?--timeout needs seconds}"); shift ;;
        --dry-run) DRY=1 ;;
        -h | --help) usage 0 ;;
        -*) echo "unknown option $1" >&2; usage ;;
        *) run_args+=("$1") ;;
    esac
    shift
done

[[ $EUID -ne 0 || ${VM_SMOKE_AS_ROOT:-0} -eq 1 ]] || { echo "run this as a normal user; the tests run as root in the VM" >&2; exit 2; }
command -v vng > /dev/null || {
    echo "virtme-ng (vng) is not installed: sudo apt install virtme-ng" >&2
    echo "(or pip install virtme-ng; it also needs qemu-system-x86 and virtiofsd)" >&2
    exit 2
}

# --- the kernel -------------------------------------------------------------------
vng_kernel=()
if [[ -z $KERNEL ]]; then
    img=/boot/vmlinuz-$(uname -r)
    up=$(uname -r | cut -d- -f1); up=v${up%.0} # mainline names x.y.0 vx.y
    if [[ -e $img && ! -r $img ]]; then
        echo "$img is not readable by you (Ubuntu installs kernels 0600). Either:" >&2
        echo "  sudo chmod 0644 $img" >&2
        echo "  or test an upstream build instead: $0 --kernel $up" >&2
        exit 2
    fi
elif [[ $KERNEL =~ ^v[0-9]+\.[0-9]+ ]]; then
    vng_kernel=("$KERNEL")
else
    [[ -r $KERNEL ]] || { echo "$KERNEL: no such kernel (or not readable)" >&2; exit 2; }
    vng_kernel=("$(realpath "$KERNEL")")
fi

# The host's LSM order, with bpf added (at the end) when it isn't in it. An
# LSM that the guest kernel lacks is skipped by the kernel.
lsm=$(cat /sys/kernel/security/lsm 2> /dev/null) || lsm=
[[ -n $lsm ]] || lsm=lockdown,capability,landlock,yama,apparmor
[[ ,$lsm, == *,bpf,* ]] || lsm=$lsm,bpf

vng_opts=()
if [[ -r /dev/kvm && -w /dev/kvm ]]; then
    :
else
    echo "warning: no access to /dev/kvm; emulating the CPU (TCG), which is SLOW:" >&2
    echo "  expect the tests to take many times longer. To use KVM, enable SVM/VT-x" >&2
    echo "  in the firmware and add yourself to the kvm group." >&2
    vng_opts+=(--disable-kvm)
fi

# --- build --------------------------------------------------------------------------
if [[ $BUILD -eq 1 ]]; then
    cd "$ROOT" || exit 2
    echo "== cargo build --release"
    cargo build --release || exit 2
    # phase4's agent answers prompts by itself (`test-answer`): kept in a
    # target dir of its own so target/release never holds one.
    echo "== cargo build --release --features explsm-agent/test-answer (target/smoke)"
    cargo build --release --target-dir "$ROOT/target/smoke" --features explsm-agent/test-answer || exit 2
fi

# --- run ------------------------------------------------------------------------------
# vng (1.41) shares the host root read-only and overlays /etc, /home, /var,
# /tmp and friends with writable copies in guest memory; /var/tmp and /root
# are tmpfs. So the tests can write where they need to, and none of it
# reaches the host.
logs=$ROOT/target/vm-smoke-logs
rm -rf "$logs" && mkdir -p "$logs" || exit 2
inner=$(printf '%q ' "$ROOT/tests/run-all.sh" --logs "$logs" "${run_args[@]}")
cmd=(vng --run "${vng_kernel[@]}" --user root --cwd "$ROOT" --rwdir "$logs"
    --cpus "$CPUS" --memory "$MEMORY" --append "lsm=$lsm"
    "${vng_opts[@]}" --exec "$inner")
echo "== ${cmd[*]}"
[[ $DRY -eq 1 ]] && exit 0
"${cmd[@]}"
