#!/usr/bin/env bash
# Build two packages into target/deb with dpkg-deb:
#   explsm_<version>_<arch>.deb          explsmd as a boot-time system
#       service and explsmctl. The policy directory is shipped empty; see
#       /usr/share/doc/explsm/examples for a start. Enough for a server.
#   explsm-desktop_<version>_<arch>.deb  explsm-agent as a user service for
#       every graphical session and the explsm-gui settings app; depends on
#       explsm. Maintainer scripts are in packaging/deb-desktop.
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
# The test GUI hands the user's security picture to any caller.
if "$REL/explsm-gui" test 2>&1 | grep -q 'usage: explsm-gui test'; then
    echo "build-deb: target/release/explsm-gui was built with test-cli; rebuild without it" >&2
    exit 1
fi

VERSION=$(cargo metadata --format-version 1 --no-deps |
    python3 -c 'import json, sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"] == "explsmd"))')
ARCH=$(dpkg --print-architecture)
OUT=target/deb
PKG=$OUT/root
DPKG=$OUT/root-desktop
rm -rf "$PKG" "$DPKG"
mkdir -p "$PKG/DEBIAN" "$DPKG/DEBIAN"

install -Dm755 "$REL/explsmd" "$PKG/usr/sbin/explsmd"
install -Dm755 "$REL/explsmctl" "$PKG/usr/bin/explsmctl"
install -Dm644 packaging/explsmd.service "$PKG/usr/lib/systemd/system/explsmd.service"
install -Dm644 packaging/explsm-gate.service "$PKG/usr/lib/systemd/system/explsm-gate.service"
install -Dm644 packaging/systemd-user-sessions.service.d/explsm-gate.conf \
    "$PKG/usr/lib/systemd/system/systemd-user-sessions.service.d/explsm-gate.conf"
install -Dm644 packaging/org.explsm.Daemon1.conf "$PKG/usr/share/dbus-1/system.d/org.explsm.Daemon1.conf"
install -dm755 "$PKG/etc/explsm/policy.d"
DOC=$PKG/usr/share/doc/explsm
install -Dm644 README.md "$DOC/README.md"
install -Dm644 docs/dsl.md "$DOC/dsl.md"
install -Dm644 docs/threat-model.md "$DOC/threat-model.md"
install -Dm644 docs/production-review.md "$DOC/production-review.md"
install -Dm644 packaging/example.explsm "$DOC/examples/ssh.explsm"
install -Dm644 packaging/dpkg.explsm "$DOC/examples/dpkg.explsm"
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
 inspects it. Install explsm-desktop for prompts in graphical sessions.
 Needs a kernel with "bpf" in its active LSM list.
CONTROL

DEB=$OUT/explsm_${VERSION}_${ARCH}.deb
dpkg-deb --root-owner-group -Zxz --build "$PKG" "$DEB"

# explsm-desktop: the agent and the GUI.
install -Dm755 "$REL/explsm-agent" "$DPKG/usr/libexec/explsm-agent"
install -Dm755 "$REL/explsm-gui" "$DPKG/usr/libexec/explsm-gui"
install -Dm644 packaging/explsm-agent.service "$DPKG/usr/lib/systemd/user/explsm-agent.service"
install -Dm644 packaging/org.explsm.Settings.desktop \
    "$DPKG/usr/share/applications/org.explsm.Settings.desktop"
install -Dm644 packaging/deb/copyright "$DPKG/usr/share/doc/explsm-desktop/copyright"

for script in postinst prerm postrm; do
    install -m755 "packaging/deb-desktop/$script" "$DPKG/DEBIAN/$script"
done

DSIZE=$(du -sk --exclude=DEBIAN "$DPKG" | cut -f1)
cat > "$DPKG/DEBIAN/control" <<CONTROL
Package: explsm-desktop
Version: $VERSION
Architecture: $ARCH
Maintainer: Matej Strnad <contact@matejstrnad.cz>
Section: admin
Priority: optional
Installed-Size: $DSIZE
Depends: explsm (= $VERSION), libgtk-4-1 (>= 4.14), libadwaita-1-0 (>= 1.5), libc6
Description: data-centric BPF LSM: desktop prompts and settings
 explsm-agent asks the user about explsm denials in each graphical session;
 explsm Settings shows the security picture, grants and prompt history.
CONTROL

DDEB=$OUT/explsm-desktop_${VERSION}_${ARCH}.deb
dpkg-deb --root-owner-group -Zxz --build "$DPKG" "$DDEB"
echo "$DEB"
echo "$DDEB"
