# Running explsm on a machine you depend on

A review of explsm as packaged (`packaging/build-deb.sh`), written for
running it on a desktop that has to keep working. Short version: **safe to
run in audit mode right away; move single apps to enforce mode after a week
of audit logs; don't treat it as a boundary against root.**

## What can go wrong, and how bad it is

| Risk | How likely | What happens | Way out |
|---|---|---|---|
| Kernel crash or hang from the BPF programs | Very low | The verifier proves every program terminates and only touches memory it may; a bug shows up as wrong decisions, not a crash. | — |
| A policy in enforce mode denies something needed (a shell its config, an app its own data after an update) | Real, per app | The access fails with `EACCES`/`EPERM`/`EXDEV`. | `sudo explsmctl unload`; or boot with `explsm=off` (Ubuntu hides the GRUB menu: hold Shift or press Esc at boot); recovery mode doesn't start explsmd. |
| explsmd fails to start at boot (policy error, kernel without the bpf LSM) | Low | Nothing is protected (fail-open), nothing is blocked. | `journalctl -b -u explsmd`. |
| explsmd crashes while running | Low | Enforcement goes on (the programs are pinned), but no prompts and no re-resolution: an app updated meanwhile may be denied its own data. systemd restarts it within 2 s (`Restart=on-failure`, at most 5 times a minute). | `systemctl status explsmd`. |
| Log noise from process monitors | Certain | `ps` and Resources read every process's `environ`; explsm refuses that for apps and the agent. One line per program and app every 10 minutes, then a `repeated=N` line. | — |
| The Landlock sandbox refuses something explsmd needs at runtime | Low | That one operation fails with `EACCES` and a warning in the journal (e.g. a claim not written); enforcement goes on. | `systemctl edit explsmd` and add `--no-landlock` to `ExecStart`; report it. |
| The `/proc` helper (`explsmd-proc`) dies | Very low | A warning; running processes of exes added later are not seeded (their app is denied its data until restarted), and prompts may show a process name instead of its exe path. | `systemctl restart explsmd`. |
| The ring buffer fills (a denial storm) | Low | Events are dropped and counted (`dropped` in `explsmctl status`); decisions are not affected. | — |
| Slower file system access | Unmeasured | Every `open` and inode operation runs a hook; owners are cached per inode, misses walk up to 64 parent dentries. | Measure (`find ~`, a large build) before and after; planned for Phase 7. |
| Package upgrade | Certain, briefly | `prerm` unloads explsm; it is off for the seconds dpkg takes. | — |

With the shipped (empty) policy, explsmd only guards its own files and
objects: nothing of yours can be denied.

## What it protects, and what it doesn't

Protected, for apps in enforce mode: the app's folders against other
processes of the same user, the app's processes against ptrace,
`/proc/<pid>/mem` and the like, against loader variables, mounts in a user
namespace and forced core dumps, and user-writable app exes against
replacement. See [threat-model.md](threat-model.md) for the details.

Not protected:

- **Against root.** `root_bypass on` is the default, so anything that gets
  sudo gets everything. With `root_bypass off` the casual routes fail, but
  root can still bind-mount another binary over `/usr/sbin/explsmd` in a
  mount namespace and be the daemon, or load a kernel module. Root is out of
  scope.
- **Interpreted apps** (`node cli.js`, `python3 app.py`) can't be apps yet.
- **`@terminal`** is a heuristic: malware can start a terminal emulator.
- **What an app sends out itself**, plugins running inside it, and data
  copied out before enforcement started.
- **Flatpak apps and rootless containers** can't be apps (user namespaces).
- **Prompts on X11** can be clicked by any client of the user. This machine
  runs Wayland.

## Findings of the review

Fixed in the same change as this document:

- **High: identity inside a user namespace.** A process of the user could
  `unshare -Urm`, mount a tmpfs over `/etc` or the library directories with
  its own `ld.so.preload` or libc, and exec the real app exe, which kept its
  identity (the inode matched) and so its data. Ubuntu's
  `kernel.apparmor_restrict_unprivileged_userns=1` makes this harder, but
  bypasses of that restriction have been published, and other distributions
  don't have it. Now an exec in a non-initial user namespace gets no
  identity (`dropped=userns`), and seeding skips such processes.
- **High: forced core dumps.** A process of the user could `kill -SEGV` an
  app, or `prlimit` it a tiny `RLIMIT_CPU`, and read its memory from the
  crash report apport writes to `/var/crash` (owned by the user). Now
  core-dumping signals and rlimit changes from other subjects are refused
  (`task_kill`, `task_setrlimit` hooks).
- **Low: stale daemon tgid.** After explsmd exited (explsm staying loaded),
  a new process with its pid could change the label xattr. The label is only
  informational (`ROOTS` decides), and the tgid is now cleared on exit.

Checked and fine:

- **Forged prompt answers on the session bus.** The agent takes the
  notification's `ActionInvoked` signal through a zbus proxy, which accepts
  signals only from the unique name that owns `org.freedesktop.Notifications`
  (`SignalStream::filter` in zbus 6.1). A unicast signal from another client
  is dropped. Keep this in mind when changing the agent's D-Bus code.
- **The test agent** (`--answer`) only exists with the `test-answer` feature;
  `build-deb.sh` refuses to package a build that has it.
- **Package upgrades with `root_bypass off`** work, because `prerm` unloads
  first.

Left as known limitations (in [threat-model.md](threat-model.md)): crashes
an app has on its own still leave a dump its user can read; setuid sandbox
tools that let users mount in the initial user namespace (firejail) are
trusted like root's mounts.

## Recommended rollout

1. Install the package; check `systemctl status explsmd` and
   `sudo explsmctl status`.
2. Copy `/usr/share/doc/explsm/examples/ssh.explsm` to
   `/etc/explsm/policy.d/`, `sudo explsmctl load`. It is in audit mode.
3. Use the machine for a week; read `explsmctl log --app ssh` and
   `explsmctl learn ssh --since "1 week ago"`, add the grants that are
   needed.
4. `mode enforce`, `sudo explsmctl load`. Keep a second way in (an SSH
   session from another machine, or knowing the GRUB route) for the first
   days.
5. Turn off core dumps for the apps you protect, or system-wide, if their
   memory holds secrets (see above).
6. Add more apps one at a time, each through audit mode first.
