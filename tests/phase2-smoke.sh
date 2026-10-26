#!/usr/bin/env bash
# Phase 2 smoke test: runs explsmd against a throwaway sandbox in /var/tmp
# and checks what is denied, audited and allowed. Enforcement only applies to
# the sandbox. Must run as root; the accessing processes drop to `nobody` so
# the @root bypass does not hide them.
#
#   cargo build --release -p explsmd
#   sudo tests/phase2-smoke.sh [path/to/explsmd]

set -u

EXPLSMD=$(realpath "${1:-target/release/explsmd}")
DIR=/var/tmp/explsm-phase2
[[ $EUID -eq 0 ]] || { echo "must run as root" >&2; exit 2; }
[[ -x $EXPLSMD ]] || { echo "$EXPLSMD not found; build it first" >&2; exit 2; }
command -v python3 > /dev/null || { echo "python3 is needed" >&2; exit 2; }

rm -rf "$DIR"
E=$DIR/enforced    # owned by `owner`, enforce mode
A=$DIR/audited     # owned by `auditee`, audit mode
O=$DIR/outside     # unprotected
OB=$DIR/owner-bin  # exes of `owner`
RB=$DIR/reader-bin # exes of `reader`, which may read and list owner's data
mkdir -p "$E/sub" "$E/empty" "$A" "$O" "$OB" "$RB"
echo s3cret > "$E/secret"
echo s3cret > "$E/linked"
ln "$E/linked" "$O/alias"           # hard link that predates the daemon
echo audit > "$A/file"
echo audit > "$A/victim"
echo audit > "$A/moving"
echo outside > "$O/file"
DEEP=$E/deep$(printf '/d%.0s' $(seq 60)) # MAX_WALK is 64
mkdir -p "$DEEP"
echo deep > "$DEEP/file"
# Private copies, so their inodes identify the apps without also matching
# every system binary. Named like the originals for multi-call coreutils.
for b in cat mv ln bash; do cp "$(type -P $b)" "$OB/$b"; done
cp "$(type -P bash)" "$RB/bash"
cp "$(type -P true)" "$DIR/auditee-true" # never runs
mkfifo "$DIR/go"
chmod -R a+rwX "$DIR"

POLICY=$DIR/policy.explsm
cat > "$POLICY" <<EOF
app owner {
    exe "$OB/cat", "$OB/mv", "$OB/ln", "$OB/bash"
    owns "$E"
    mode enforce
}

app auditee {
    exe "$DIR/auditee-true"
    owns "$A"
}

app reader {
    exe "$RB/bash"
}

grant reader read, list to owner
EOF

OUT=$DIR/events.log
ERR=$DIR/explsmd.log

fails=0
check() { # name, condition result (0 = pass), detail
    if [[ $2 -eq 0 ]]; then echo "PASS  $1"; else echo "FAIL  $1: $3"; fails=$((fails + 1)); fi
}
mark() { wc -l < "$OUT"; }
since() { sleep 0.3; tail -n +"$(( $1 + 1 ))" "$OUT"; }
nobody() { setpriv --reuid=65534 --regid=65534 --clear-groups -- "$@"; }

daemon=
start() { # extra explsmd args
    : > "$OUT"; : > "$ERR"
    "$EXPLSMD" --policy "$POLICY" --no-dbus --no-pin --no-self-protect "$@" > "$OUT" 2> "$ERR" &
    daemon=$!
    for _ in $(seq 100); do grep -q attached "$ERR" && return; sleep 0.1; done
    echo "explsmd did not start:"; cat "$ERR"; kill "$daemon" 2>/dev/null; exit 1
}
stop() {
    kill -INT "$daemon"; wait "$daemon"
    grep -E "seeded|stopping|warning|hard-linked" "$ERR"
}

# run CMD...: record its status, output and the events it caused.
run() { m=$(mark); out=$("$@" 2>&1); rc=$?; ev=$(since "$m"); }
denied() { [[ $rc -ne 0 ]]; }
has() { grep -qE "$1" <<< "$ev"; }
quiet() { ! grep -qE "^(deny|audit) " <<< "$ev"; }

# Started before explsmd: only seeding can give it the app identity.
# setpriv directly, not the `nobody` function: $! must be the reader itself.
setpriv --reuid=65534 --regid=65534 --clear-groups -- \
    "$OB/bash" -c "read -r _ < '$DIR/go'; read -r _ < '$E/secret'" &
early=$!
# Don't leave it (or the daemon) behind if the test bails out early.
trap 'kill $early $daemon 2>/dev/null' EXIT

start

# --- identity --------------------------------------------------------------
run nobody "$OB/cat" "$E/secret"
[[ $rc -eq 0 ]] && quiet
check "owner reads its own data" $? "rc=$rc $out $ev"

echo go > "$DIR/go"; wait "$early"
check "already running owner process was seeded" $? "early reader failed"

run nobody "$OB/bash" -c "( read -r _ < '$E/secret' )"
[[ $rc -eq 0 ]]
check "fork keeps identity" $? "rc=$rc $out"

run nobody "$OB/bash" -c "/usr/bin/cat '$E/secret'"
denied && has "^deny .*proc=cat .*subject=unconfined owner=owner open\(r\) need=read $E/secret\$"
check "exec of unknown exe drops identity" $? "rc=$rc $ev"

# --- enforce: each operation by a foreign subject --------------------------
run nobody /usr/bin/cat "$E/secret"
denied && has "^deny .*subject=unconfined owner=owner open\(r\) need=read $E/secret\$"
check "foreign read is denied" $? "rc=$rc $out $ev"

run nobody bash -c "echo x >> '$E/secret'"
denied && has "open\(w\) need=write $E/secret\$"
check "foreign write is denied" $? "rc=$rc $ev"

run nobody ls "$E"
denied && has "open\(r\) need=list $E\$"
check "foreign readdir is denied" $? "rc=$rc $ev"

run nobody touch "$E/new"
denied && [[ ! -e $E/new ]] && has "create need=create $E/new\$"
check "foreign create is denied" $? "rc=$rc $ev"

run nobody mkdir "$E/newdir"
denied && [[ ! -e $E/newdir ]] && has "mkdir need=create $E/newdir\$"
check "foreign mkdir is denied" $? "rc=$rc $ev"

run nobody ln -s /etc/passwd "$E/sym"
denied && [[ ! -L $E/sym ]] && has "symlink need=create $E/sym\$"
check "foreign symlink is denied" $? "rc=$rc $ev"

run nobody rm -f "$E/secret"
denied && [[ -e $E/secret ]] && has "unlink need=delete $E/secret\$"
check "foreign unlink is denied" $? "rc=$rc $ev"

run nobody rmdir "$E/empty"
denied && [[ -d $E/empty ]] && has "rmdir need=delete $E/empty\$"
check "foreign rmdir is denied" $? "rc=$rc $ev"

run nobody mv "$E/secret" "$E/sub/secret"
denied && [[ -e $E/secret ]] && has "rename need=rename $E/secret -> $E/sub/secret\$"
check "foreign rename inside the tree is denied" $? "rc=$rc $ev"

run nobody chmod 600 "$E/secret"
denied && has "setattr need=setattr $E/secret\$"
check "foreign chmod is denied" $? "rc=$rc $ev"

# touch may open the file for writing before it sets the times.
run nobody touch -d 2000-01-01 "$E/secret"
denied && has "need=(setattr|write) $E/secret\$"
check "foreign utimes is denied" $? "rc=$rc $ev"

run nobody truncate -s 0 "$E/secret"
denied && [[ -s $E/secret ]] && has "need=write $E/secret\$"
check "foreign truncate is denied" $? "rc=$rc $ev"

run nobody python3 -c "import os; os.setxattr('$E/secret', 'user.x', b'1')"
denied && has "setxattr need=setattr $E/secret\$"
check "foreign setxattr is denied" $? "rc=$rc $ev"

# --- moving data across owners ---------------------------------------------
run nobody ln "$E/secret" "$O/hard"
denied && [[ ! -e $O/hard ]] && has "^deny .*owner=owner->unconfined link need=xdev $E/secret -> $O/hard\$"
check "foreign hard link out of the tree is refused" $? "rc=$rc $ev"

run nobody "$OB/ln" "$E/secret" "$O/hard"
denied && [[ ! -e $O/hard ]] && has "subject=owner owner=owner->unconfined link need=xdev"
check "owner hard link out of the tree is refused too" $? "rc=$rc $ev"

run nobody mv "$O/file" "$E/file"
denied && [[ -e $O/file && ! -e $E/file ]] && has "owner=unconfined->owner rename need=xdev" \
    && has "create need=create $E/file\$"
check "foreign move into the tree falls back to copy, which is denied" $? "rc=$rc $out $ev"

echo moving > "$E/moving"; chmod a+rw "$E/moving"
run nobody "$OB/mv" "$E/moving" "$O/moved"
[[ $rc -eq 0 && -e $O/moved && ! -e $E/moving ]] && has "^deny .*owner=owner->unconfined rename need=xdev $E/moving -> $O/moved\$"
check "owner move out of the tree is copied, not renamed" $? "rc=$rc $out $ev"

run nobody /usr/bin/cat "$O/alias"
denied && has "need=read $O/alias\$"
check "hard link made before the daemon started is protected" $? "rc=$rc $ev"

# --- grants ----------------------------------------------------------------
run nobody "$RB/bash" -c "read -r l < '$E/secret'; echo \$l"
[[ $rc -eq 0 && $out == s3cret ]] && quiet
check "granted read is allowed" $? "rc=$rc $out $ev"

run nobody "$RB/bash" -c "echo x >> '$E/secret'"
denied && has "subject=reader owner=owner open\(w\) need=write"
check "write beyond the grant is denied" $? "rc=$rc $ev"

# --- label -----------------------------------------------------------------
label=$(python3 -c "import os; print(os.getxattr('$E', 'security.bpf.explsm').decode())")
[[ $label == "app=owner mode=enforce" ]]
check "root is labelled" $? "label=$label"

run python3 -c "import os; os.removexattr('$E', 'security.bpf.explsm')"
denied && has "^deny .*removexattr need=label $E\$"
check "root cannot remove the label" $? "rc=$rc $ev"

run python3 -c "import os; os.setxattr('$O/file', 'security.bpf.explsm', b'app=x')"
denied && has "setxattr need=label $O/file\$"
check "root cannot set a label anywhere" $? "rc=$rc $ev"

# --- deep trees ------------------------------------------------------------
run nobody /usr/bin/cat "$DEEP/file"
denied && has "need=read $DEEP/file\$"
check "foreign read 60 levels below the root is denied" $? "rc=$rc $ev"

# --- audit mode ------------------------------------------------------------
run nobody /usr/bin/cat "$A/file"
[[ $rc -eq 0 ]] && has "^audit .*subject=unconfined owner=auditee open\(r\) need=read $A/file\$"
check "audit mode allows and reports reads" $? "rc=$rc $ev"

run nobody rm "$A/victim"
[[ $rc -eq 0 && ! -e $A/victim ]] && has "^audit .*unlink need=delete $A/victim\$"
check "audit mode allows and reports unlink" $? "rc=$rc $ev"

run nobody mv "$A/moving" "$O/from-audit"
[[ $rc -eq 0 && -e $O/from-audit ]] && has "^audit .*owner=auditee->unconfined rename need=xdev"
check "audit mode allows and reports cross-owner rename" $? "rc=$rc $out $ev"

run nobody /usr/bin/cat "$O/from-audit"
[[ $rc -eq 0 ]] && quiet
check "data renamed out in audit mode is no longer owned (cache flushed)" $? "rc=$rc $ev"

# --- root bypass -----------------------------------------------------------
run /usr/bin/cat "$E/secret"
[[ $rc -eq 0 ]] && quiet
check "root bypass lets root read" $? "rc=$rc $ev"

run nobody /usr/bin/cat "$O/file"
[[ $rc -eq 0 ]] && quiet
check "unprotected files are not reported" $? "rc=$rc $ev"

stop
start --no-root-bypass --no-seed
run /usr/bin/cat "$E/secret"
denied && has "^deny .*uid=0 .*need=read $E/secret\$"
check "--no-root-bypass denies root" $? "rc=$rc $ev"
stop

echo
echo "logs: $OUT $ERR"
if [[ $fails -eq 0 ]]; then echo "all checks passed"; else echo "$fails check(s) failed"; exit 1; fi
