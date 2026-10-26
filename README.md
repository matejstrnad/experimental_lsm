# explsm

A data-centric eBPF LSM in Rust: an application's folder (`~/.claude`,
`~/.ssh`, …) belongs to that application, and other processes are denied
(or, in audit mode, reported). See [docs/dsl.md](docs/dsl.md) for the
policy language and [docs/threat-model.md](docs/threat-model.md) for what it
does and does not protect against.

> [!WARNING]
> explsm is an experimental research project. It has not been audited, its
> policy language and on-disk formats may change without notice, and a
> mistake in it can deny access to your own data. Don't use it in
> production or on a machine you can't afford to break.

**Status: Phase 5, hardening.** Each app is in audit or enforce mode on its
own; start in audit mode. Denials and folders apps create can be put to the
user as desktop notifications by `explsm-agent`. Apps are protected against
tampering by other processes of the same user (ptrace, `/proc/<pid>/mem`,
`LD_PRELOAD`, user namespaces, forced core dumps, replacing their exe), and
explsm protects itself: it stays loaded when the daemon exits, and only
`explsmctl unload` removes it. It is packaged as a `.deb` that starts explsmd
at boot. If you run it on a machine you depend on anyway, read
[docs/production-review.md](docs/production-review.md) first.

## Requirements

- Linux with `bpf` in the active LSM list (`cat /sys/kernel/security/lsm`).
- Linux 6.9 or newer with BTF (`/sys/kernel/btf/vmlinux`).
- Stable Rust and clang. The LSM programs (`explsmd/bpf/`) are C compiled
  with CO-RE: kernel struct offsets are fixed up at load time, so one build
  runs on any of those kernels without a rebuild.

## Policy

```
# /etc/explsm/policy.d/ssh.explsm
app ssh {
    exe  "/usr/bin/ssh", "/usr/bin/scp", "/usr/bin/ssh-add"
    owns "~/.ssh"                  # for every regular user
    mode audit                     # or enforce
}

app backup {
    exe "/usr/bin/restic"
}

grant backup read, list to ssh     # read write create delete rename list setattr, or all
grant @unconfined list to ssh      # every process that is no app

terminal "/usr/bin/ptyxis", "/usr/sbin/sshd"
grant @terminal read to ssh        # shells in a terminal (a heuristic, see the docs)
```

See [docs/dsl.md](docs/dsl.md) for the details. Check a policy without
loading it (no root needed):

```bash
explsmctl check /etc/explsm/policy.d --resolve
```

## Installing

Build the package (needs Rust, clang and `dpkg-deb`) and install it:

```bash
packaging/build-deb.sh                 # prints target/deb/explsm_<version>_<arch>.deb
sudo apt install ./target/deb/explsm_*.deb
systemctl --user start explsm-agent    # in sessions that were open already
```

It installs:

| | |
|---|---|
| `/usr/sbin/explsmd` | the daemon, `explsmd.service`, enabled at boot |
| `/usr/bin/explsmctl` | the CLI |
| `/usr/libexec/explsm-agent` | the prompt agent, a user service in every graphical session |
| `/etc/explsm/policy.d/` | the policy, **empty**: put your `*.explsm` files here |
| `/usr/share/doc/explsm/` | these docs and `examples/ssh.explsm` |

explsmd starts before anyone can log in (`Before=systemd-user-sessions.service`),
with a nice level of -10, the highest best-effort I/O priority and an OOM
score of -1000. It does not run realtime: the decisions are made by the BPF
programs in the kernel, the daemon only reads their events, asks the agents
and follows package updates.

Upgrading or removing the package turns explsm off first (`explsmctl
unload` in `prerm`), so it is off for the few seconds dpkg takes. `apt purge`
also removes `/var/lib/explsm` and `/etc/explsm/claims.d`; your policy files
stay.

To start with a policy:

```bash
sudo cp /usr/share/doc/explsm/examples/ssh.explsm /etc/explsm/policy.d/
sudo explsmctl load
```

## Using it

```bash
sudo explsmctl status                 # apps, resolved exes and roots, grants, counters
sudo explsmctl load                   # apply edits to /etc/explsm/policy.d (or: systemctl reload explsmd)
explsmctl log --app ssh --since today # denied (`deny`) and allowed-in-audit-mode (`audit`) accesses
explsmctl log --deny -f               # follow denials
explsmctl learn ssh --since "1 week ago"  # suggested grants from the log
```

`status` and `load` talk to explsmd over D-Bus and need root. `log` and
`learn` read the journal (`EXPLSM_*` fields), so they need journal access
(root, or the `systemd-journal`/`adm` group). Log lines look like this:

```
deny   pid=4242 tid=4242 uid=1000 proc=cat comm=cat subject=unconfined owner=ssh open(r) need=read /home/me/.ssh/id_ed25519
audit  pid=4243 tid=4243 uid=1000 proc=rm comm=rm subject=unconfined owner=ssh unlink need=delete /home/me/.ssh/known_hosts
deny   pid=4244 tid=4244 uid=1000 proc=mv comm=mv subject=ssh owner=ssh->unconfined rename need=xdev /home/me/.ssh/a -> /tmp/a
```

`deny` lines were refused (`EACCES`), `audit` lines would have been refused
in enforce mode.

## Prompts

With `explsm-agent` running in your session, a denial in enforce mode shows a
notification. The access has already failed (BPF can't wait for an answer),
so retry after answering:

- **Allow this process**: until the process that was denied exits.
- **Allow until logout**: for the app (or, for a process that is no app, every
  process of that exe) until the agent stops, i.e. until you log out.
- **Always allow**: writes a grant to `/etc/explsm/claims.d/<you>.explsm`
  and reloads. For a process that is no app it adds an app for its exe. The
  notification warns when the exe is one you can change, or one that runs
  other programs (shells, interpreters). It is not offered for an exe with
  several hard links: Ubuntu's coreutils are one file under 116 names, so
  allowing `cat` would allow `rm` too.
- **Deny**: and don't ask about that program and data again for 10 minutes.

When an app creates a folder right in `~`, `~/.config`, `~/.local/share` or
`~/.cache` that the policy does not mention, and it still exists a second
later, the agent asks whether the app
should own it. "Protect" adds a `claim` to the claims file. "Leave
unprotected" is remembered in `/var/lib/explsm/declined-claims`.

Only a process running the installed agent exe (`explsmd --agent`, by
default `/usr/libexec/explsm-agent`) is accepted as an agent, and only
your own agent may answer your prompts. `explsmctl status` shows the
registered agents and the grants given through prompts.

A typical rollout: an app in audit mode for a while, `explsmctl learn` to
find the accesses that should be granted, add the grants, `mode enforce`,
`explsmctl load`.

## Turning it off

The programs and maps are pinned in `/sys/fs/bpf/explsm`, so stopping or
killing explsmd does **not** turn explsm off: enforcement goes on (without
prompts or reloads), and the next explsmd takes over.

- `sudo explsmctl unload`: removes the labels and the pins, which detaches
  everything, and stops the daemon. With no daemon running it runs
  `/usr/sbin/explsmd --unload`. Nothing else may remove the pins, root
  included.
- Reboot with `explsm=off` on the kernel command line: pins don't survive a
  reboot, and the unit does not start (`ConditionKernelCommandLine`). Use this
  if a policy locks you out. Ubuntu hides the GRUB menu: hold Shift (BIOS) or
  press Esc (UEFI) while booting, press `e` on the entry and add `explsm=off`
  to the `linux` line. Recovery mode works too: `rescue.target` doesn't start
  explsmd.
- `sudo systemctl disable explsmd` to keep it off after the next boot.

**Upgrading explsmd:** the package unloads explsm before an upgrade and
starts the new version after it. By hand: install the new binary at the same
path. A running daemon notices it and lets it in; a new binary at another
path is refused the pinned state, so `explsmctl unload` first (or reboot).

## What explsm protects of itself

- Its files: the policy and claims directories, `/var/lib/explsm`, the
  explsmd, explsm-agent and explsmctl binaries, its unit files and bus policy.
  Anyone may read them; only explsmd may change them, and root while the
  `@root` bypass is on (so package upgrades work). **With `root_bypass off`,
  root can't edit the policy either**: `explsmctl unload` (or reboot with
  `explsm=off`), edit, start again.
- Its pins: only explsmd may remove them, whatever the bypass says.
- Its BPF maps, programs and links: only explsmd may get a file descriptor
  for them, so `bpftool map dump` and the like are refused.
- Its processes and the agent's: like an app's, see below.
- Everything else, from its own bugs: once attached, explsmd puts itself in
  a Landlock sandbox. It may still list directories and set labels anywhere,
  read its policy, claims, state, `/etc/passwd` and `/proc`, write claims and
  state and remove its pins; it can't read your files, write anywhere else,
  run programs, mount or open network connections. Other processes' `/proc`
  entries are read by a small helper, `explsmd-proc`, that stays outside the
  sandbox with only `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH`. The daemon
  keeps `CAP_BPF` and `CAP_SYS_ADMIN`, so this contains bugs, not code
  running in it.

## Behaviour worth knowing

- **Tampering.** Only the same app, explsmd, and root with the bypass on may
  ptrace a process of an app, or use what the kernel guards the same way:
  `/proc/<pid>/mem`, `environ`, `fd/`, `maps`, `process_vm_readv/writev`,
  `pidfd_getfd`. So `gdb -p`, `strace -p` and `ls /proc/<pid>/fd` fail on app
  processes; `ps` still works. In audit mode it is only logged. (The kernel
  still lets root read `environ` and `maps`, whatever explsm says.)
  Process monitors (`ps`, Resources) open every process's `environ` each
  time they look; such read-only probes by one program on one app's
  processes are logged once per 10 minutes, then once more with
  `repeated=N`. Attach attempts are logged each time.
- **Core dumps.** A dump holds the process's memory, and apport or
  systemd-coredump keep it readable by its user. So only the same app,
  explsmd and root with the bypass on may send an app's process a signal
  that dumps core (`SIGSEGV`, `SIGABRT`, `SIGQUIT`, …) or change its resource
  limits (`prlimit`; a low `RLIMIT_CPU` ends in `SIGXCPU`). `SIGTERM`,
  `SIGKILL` and `Ctrl-\` in its own terminal still work.
- **Loader variables.** An app exe run with `LD_PRELOAD`, `LD_LIBRARY_PATH`
  or `LD_AUDIT` set (non-empty) runs, but unconfined: it has no access to the
  app's data. It is logged as `dropped=LD_PRELOAD`.
- **User namespaces.** An app exe run in a user namespace other than the
  initial one (`unshare -U`, Flatpak's bwrap, rootless containers) runs
  unconfined too: there its user can mount its own libraries or
  `/etc/ld.so.preload` over the real ones. It is logged as `dropped=userns`.
  Snaps run in the initial one and are not affected.

- Mediated: open (read/write, and `list` for directories), create, mkdir,
  mknod, symlink, link, unlink, rmdir, rename, setattr (chmod, chown,
  utimes; truncation counts as `write`), xattrs and ACLs (`setattr`).
- **Renames and hard links never move data between owners.** They fail with
  `EXDEV`, as across filesystems, so `mv` copies and unlinks instead, and
  each step is checked. This applies to the owner too. Roots themselves can
  be renamed: their identity is their inode.
- Files inside a tree with more than one hard link are found when the root
  is added and protected under every name.
- Each root gets the xattr `security.bpf.explsm` (`app=… mode=…`). Only the
  daemon may set or remove it, root included. Roots dropped from the policy
  are unlabelled.
- The app is identified by the inode of its executable. Interpreted apps
  (`node script.js`) are not supported yet.
- Grants given through prompts for a process or a session are lost when
  explsmd restarts; "always" grants are in the policy.
- Exes replaced by package updates and roots created after the start are
  picked up automatically (see [docs/dsl.md](docs/dsl.md#resolution-and-updates)).
- Processes of the apps that were already running are given their identity
  at startup and when exes are added (`--no-seed` turns this off).

## Running explsmd by hand

```bash
sudo ./target/release/explsmd --policy my-policy.d   # or a single .explsm file
```

Without systemd, log lines go to stdout and diagnostics to stderr. Ctrl-C or
SIGTERM stops it, SIGHUP reloads the policy. `--no-dbus` skips the D-Bus API,
`--no-root-bypass` overrides `root_bypass on`, `--log-execs` also logs every
exec that gives a process an app identity (`exec` lines; off by default,
there are many).

## Tests

```bash
cargo test --workspace                # parser, compiler, resolution, events, learn
sudo tests/phase2-smoke.sh            # enforcement against a sandbox in /var/tmp
sudo tests/phase3-smoke.sh            # reloads, re-resolution, explsmctl, journal
sudo tests/phase4-smoke.sh            # prompts and their answers, auto-claim, @terminal
sudo tests/phase5-smoke.sh            # tamper protection, self-protection, pinning
sudo tests/phase6-smoke.sh            # user namespaces, core-dump signals, rlimits
sudo tests/landlock-smoke.sh          # the daemon's Landlock sandbox and /proc helper
```

The smoke tests need the D-Bus name to themselves: stop an installed
explsmd first (`sudo explsmctl unload`).

`phase4-smoke.sh` needs an agent built with
`cargo build --release --features explsm-agent/test-answer`: its `--answer`
answers prompts without asking. Don't install that build.

## License

The Rust code is licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. The BPF programs in `explsmd/bpf/` are licensed under the MIT
license ([LICENSE-MIT](LICENSE-MIT)) or the GNU General Public License,
version 2 ([LICENSE-GPL-2.0](LICENSE-GPL-2.0)), at your option: the kernel
only lets GPL-compatible programs call some of the BPF helpers they use.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in explsm by you shall be licensed as above, without
any additional terms or conditions.
