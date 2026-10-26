#!/usr/bin/env bash
# Build target/deb/explsm_<version>_<arch>.deb with dpkg-deb: explsmd as a
# boot-time system service, explsmctl, and explsm-agent as a user service
# for every graphical session. The policy directory is shipped empty; see
# /usr/share/doc/explsm/examples for a start.
#
#   packaging/build-deb.sh            # from the repository root or anywhere
set -euo pipefail
umask 022

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

cargo build --release --locked --workspace
REL=target/release

# The test agent answers prompts without asking; it must never ship.
if "$REL/explsm-agent" --help | grep -q -- '--answer'; then
    echo "build-deb: target/release/explsm-agent was built with test-answer; rebuild without it" >&2
    exit 1
fi

VERSION=$(cargo metadata --format-version 1 --no-deps |
    python3 -c 'import json, sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"] == "explsmd"))')
ARCH=$(dpkg --print-architecture)
OUT=target/deb
PKG=$OUT/root
rm -rf "$PKG"
mkdir -p "$PKG/DEBIAN"

install -Dm755 "$REL/explsmd" "$PKG/usr/sbin/explsmd"
install -Dm755 "$REL/explsmctl" "$PKG/usr/bin/explsmctl"
install -Dm755 "$REL/explsm-agent" "$PKG/usr/libexec/explsm-agent"
install -Dm644 packaging/explsmd.service "$PKG/usr/lib/systemd/system/explsmd.service"
install -Dm644 packaging/explsm-agent.service "$PKG/usr/lib/systemd/user/explsm-agent.service"
install -Dm644 packaging/org.explsm.Daemon1.conf "$PKG/usr/share/dbus-1/system.d/org.explsm.Daemon1.conf"
install -dm755 "$PKG/etc/explsm/policy.d"
DOC=$PKG/usr/share/doc/explsm
install -Dm644 README.md "$DOC/README.md"
install -Dm644 docs/dsl.md "$DOC/dsl.md"
install -Dm644 docs/threat-model.md "$DOC/threat-model.md"
install -Dm644 docs/production-review.md "$DOC/production-review.md"
install -Dm644 packaging/example.explsm "$DOC/examples/ssh.explsm"
install -Dm644 packaging/deb/copyright "$DOC/copyright"

for script in postinst prerm postrm; do
    install -m755 "packaging/deb/$script" "$PKG/DEBIAN/$script"
done

SIZE=$(du -sk --exclude=DEBIAN "$PKG" | cut -f1)
cat > "$PKG/DEBIAN/control" <<CONTROL
Package: explsm
Version: $VERSION
Architecture: $ARCH
Maintainer: Matej Strnad <contact@matejstrnad.cz>
Section: admin
Priority: optional
Installed-Size: $SIZE
Depends: systemd, dbus, libc6
Description: data-centric BPF LSM: an app's folder belongs to the app
 explsm protects application data (~/.ssh, ~/.claude, ...) from other
 processes of the same user. explsmd loads BPF LSM programs at boot and
 enforces the policy in /etc/explsm/policy.d; explsmctl checks, loads and
 inspects it; explsm-agent asks the user about denials in each graphical
 session. Needs a kernel with "bpf" in its active LSM list.
CONTROL

DEB=$OUT/explsm_${VERSION}_${ARCH}.deb
dpkg-deb --root-owner-group -Zxz --build "$PKG" "$DEB"
echo "$DEB"
