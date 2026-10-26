# explsm threat model

explsm protects **application data at rest** on a multi-app Linux system: a
folder owned by one application (e.g. `~/.claude`, `~/.ssh`,
`~/.mozilla`) should only be readable and writable by that application, plus
whatever the policy explicitly grants.

## Assets

- Contents and metadata of owned folders: credentials, tokens, history,
  browser profiles, keys.
- The integrity of the owner application itself (its executable and the
  libraries it loads), because identity is derived from it.
- explsm's own state: policy files, BPF programs and maps, labels.

## Adversaries

| Adversary | In scope? | Notes |
|---|---|---|
| Another application running as the **same user** (compromised npm package, malicious VS Code extension, rogue script) | **Yes — primary target** | This is the gap classic DAC (UID-based) permissions leave open. |
| Same-user code that **tampers with the owner app** (ptrace, `/proc/<pid>/mem`, `LD_PRELOAD`, mounts in a user namespace, forced core dumps, replacing the exe) | **Yes** | Covered in enforce mode since Phase 5; see the limitations for what is left. |
| A user at an interactive terminal | Policy decision | `@terminal` grants are a heuristic convenience, not a security boundary. |
| Other local users | Already covered by DAC | explsm adds nothing, but also must not weaken it. |
| **root** / `CAP_SYS_ADMIN` / `CAP_MAC_ADMIN` | **No** | Root can edit policy (with the bypass on), read raw block devices, load kernel modules, or open a pinned link and detach it. explsm makes the casual routes fail (pins, `bpftool` on its maps, its files with the bypass off) but is no boundary against root. |
| Kernel compromise | No | |
| Offline attacks (booting another OS, stolen disk) | No | Use disk encryption. |

## Trust assumptions

1. The kernel, the BPF LSM and the explsm daemon are trusted. Once set up,
   the daemon confines itself with Landlock (`explsmd/src/sandbox.rs`), so a
   bug in handling events, D-Bus calls or directory changes can't read
   users' files, write outside explsm's own places, exec, mount or use TCP.
   It keeps `CAP_BPF` and `CAP_SYS_ADMIN`, so this does not hold against
   code running in the daemon. Its `/proc` helper (`explsmd-proc`) stays
   outside the sandbox and answers only three questions about a pid (exe,
   loader variables, user namespace), with only `CAP_SYS_PTRACE` and
   `CAP_DAC_READ_SEARCH`.
2. Executables named in policy are trusted to be the application they claim
   to be **as long as nobody else can modify them**. Exes in user-writable
   locations (`~/.local/share/claude/versions/*`) are therefore treated as
   owned data, and only the app may add files next to them. They are trusted
   only as long as the app itself is: an app that downloads its own updates
   decides what its next version is.
3. Interpreters (`node`, `python3`) are *not* an identity on their own; the
   script path narrows it. A script in a user-writable path has the same
   caveat as (2).
4. Policy is written by the administrator (root). Auto-claims need an
   explicit user confirmation and are written to a root-owned file.

## Known limitations (by design or until a later phase)

- **Identity is per exec image, not per code origin.** Plugins or `eval`
  inside an owner app run with the app's identity.
- **Prompts are not blocking.** The first denied access fails with `EACCES`;
  approval takes effect on retry. fanotify permission events could hold an
  open while the user is asked, but BPF would have to allow those opens
  first (so a hung or killed explsmd fails open), and a mark on the home
  filesystem slows down every open on it.
- **The agent is trusted by its exe.** explsmd takes answers only from a
  process whose task storage says it runs the agent exe, and only from the
  agent of the prompt's user. Like an app in enforce mode (always, whatever
  the policy), the agent can't be ptraced, started with `LD_PRELOAD` as the
  agent, or replaced. Malware can run the real agent, but that only shows the
  user real prompts. The agent's `--answer` (answer every prompt without
  asking) only exists in builds with the `test-answer` feature, which must
  never be installed.
- **Tamper protection covers the loader and ptrace, not every way of
  injecting code.** Only `LD_PRELOAD`, `LD_LIBRARY_PATH` and `LD_AUDIT` drop
  the identity. Variables that make a program load code by its own means
  (`NODE_OPTIONS`, `PYTHONPATH`, `GTK_MODULES`, `GIO_EXTRA_MODULES`, …) and
  config files the app reads from a user-writable place are not looked at.
  Policy for such apps should own those config folders. Processes started
  before explsm was first loaded are checked through `/proc/<pid>/environ`,
  which a process can overwrite in its own memory.
- **User namespaces end the identity.** An app exe exec'd in a user
  namespace other than the initial one runs unconfined, because there its
  user can mount over the libraries or `/etc/ld.so.preload` the loader reads.
  So apps run by Flatpak (bwrap) or in rootless containers can't be explsm
  apps. Mount namespaces that root sets up in the initial user namespace
  (snaps) are trusted; so is whatever a setuid sandbox tool (firejail) lets
  its user mount there.
- **Core dumps.** Signals that dump core and resource limit changes are
  refused to other subjects, but an app that crashes by itself (on data it
  was fed, say) still leaves a dump its user can read, with apport or
  systemd-coredump. Turn dumps off for sensitive apps (`ulimit -c 0` in their
  unit or wrapper, or `kernel.core_pattern`).
- **Audit mode does not stop tampering**, like it does not stop anything; it
  only logs.
- **ptrace protection makes debugging apps harder**: `gdb -p`, `strace -p`
  and `/proc/<pid>/fd` of an app process need root (with the bypass on) or the
  app itself. With the bypass off, root loses them too, and journald no longer
  records an app's exe path.
- **Read-only views of an app's memory map stay open to `CAP_PERFMON` and
  `CAP_SYS_ADMIN`.** The kernel's `mm_access` lets a caller with either read
  `/proc/<pid>/environ`, `maps` and `auxv` even when explsm refuses (the
  refusal is still logged). Root has both; ordinary users don't. Memory
  contents (`/proc/<pid>/mem`, `process_vm_readv`) need attach mode, which has
  no such override.
- **A new version of explsmd at another path can't take over the pinned
  state**; unload first, or reboot.
- **Prompt answers are only as good as the user's reading of them.** The
  notification names the program by its exe path and process name, both of
  which the program chooses. The agent takes a button press only from the
  owner of `org.freedesktop.Notifications` (zbus filters signals by sender),
  but on X11 any client of the user can synthesize the click; Wayland
  sessions don't allow that.
- **"Always allow" grants are not per user.** A grant written for one user's
  prompt applies to the same app's data of every user.
- **`@terminal` can be spoofed** by same-user malware that spawns a terminal
  emulator. Prefer prompts or explicit grants for sensitive data.
- **Mounts inside a protected tree** and filesystems without stable inode
  numbers (some FUSE, NFS) are not covered by the `d_parent` walk.
- **Data already copied out** before enforcement started is not protected.
- **User-writable exes are trusted on first use.** Once an exe in a
  user-writable place resolves, nothing but the app may add files next to it
  or move its directory (or the ones above it a user could move) aside. A
  path or glob that matches nothing yet is not guarded: whatever appears
  there first becomes the app.
- **Atomic saves of an owned file.** A file root replaced by a rename keeps
  its owner (the new file takes over), but the temporary file the app wrote
  first is only protected if it was in an owned folder.
- **Audit mode protects nothing**; it only logs.

## Failure modes we must avoid

- Locking the user out of their own session (e.g. denying a shell its
  config). Mitigations: per-app audit mode first, `@root` bypass by default,
  and a documented unload / boot-time disable path.
- Denying the owner app its own data because identity resolution broke (app
  update changed the exe inode). Mitigation: path-based re-resolution in the
  daemon, audit events on unknown exes that touch owned data.
