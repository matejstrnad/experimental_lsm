# Shared by the smoke tests (sourced): refuse binaries older than the
# sources, and say that the quiet setup is running.

SMOKE_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

# fresh BINARY…: exit unless each one exists and is newer than every source
# file. SMOKE_ANY_BUILD=1 skips the age check (a build from elsewhere).
fresh() {
    local b newer
    for b in "$@"; do
        [[ -x $b ]] || { echo "$b not found; run: cargo build --release" >&2; exit 2; }
        [[ ${SMOKE_ANY_BUILD:-0} == 1 ]] && continue
        newer=$(find "$SMOKE_ROOT"/explsm* "$SMOKE_ROOT"/Cargo.lock \
            \( -name '*.rs' -o -name '*.c' -o -name '*.h' -o -name Cargo.toml -o -name Cargo.lock \) \
            -newer "$b" -print -quit)
        if [[ -n $newer ]]; then
            echo "$b is older than ${newer#"$SMOKE_ROOT"/}; run: cargo build --release" >&2
            echo "(or SMOKE_ANY_BUILD=1 to test it anyway)" >&2
            exit 2
        fi
    done
    echo "testing $(dirname "$1") ($(date -r "$1" '+%F %T'))"
}

# step MESSAGE: a progress line.
step() { echo "== $*"; }
