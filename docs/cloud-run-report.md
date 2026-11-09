# Cloud run report

An unattended run on branch `release-hardening` (2026-11-08/09). What was
done, what CI says, what was skipped and why, and what is still open.

## 1. CI

Done:

- `tests/run-all.sh` (in the VM, as root): starts a private system bus with
  `packaging/org.explsm.Daemon1.conf` when none runs, runs each smoke test
  in its own process group with a timeout, prints one table, exits 1 on any
  failure, takes test names (`--list`), `--logs DIR`, `--slow N`.
- `tests/vm-smoke.sh` (host, normal user): builds the release and the
  `test-answer` agent in `target/smoke`, boots `vng` with `bpf` added to
  `lsm=`, shares `target/vm-smoke-logs` writable, runs run-all.sh as root
  and returns its status. `--kernel PATH|vX.Y`, TCG without `/dev/kvm`.
- `.github/workflows/ci.yml`: job `check` (fmt, clippy `-D warnings`, test,
  release build, `--locked`) and job `vm-smoke` on Ubuntu mainline kernels
  6.9, 6.15 and 7.3.3 (KVM through a udev rule, kernels cached, actions
  pinned to SHAs, logs uploaded as artifacts).
- A "Testing" section in the README.

Commits: `917561b`, `44a8ded`, `031407e` (runner and CI), fixes below,
`9eb31f1` (README).

Bugs found by running the smoke tests in a VM (`f1ae0ce`, `a9cafef`,
`d002368`, `2d2ad6a`, `5aa64b2`, `0e2fa12`):

- **Kernel oops on 6.9.** A denied create in a protected folder crashed the
  kernel (NULL dereference in the `inode_create` program). 6.9's verifier
  takes `dentry->d_inode` of a trusted dentry for non-NULL, drops the NULL
  check as dead code and emits a plain load. Every `d_inode` read now goes
  through `bpf_probe_read_kernel`.
- The sandbox unit test failed on kernels without securityfs or Landlock
  ABI 9.
- The smoke tests gave explsmd 5 s to attach, too little under emulation,
  and refused an agent binary cargo had not relinked as stale.
- **explsmd did not start on 6.15 and later.** Clang compiled
  `deny ? -EPERM : 0` into `-(deny & 1)`, and 6.15's verifier, which checks
  the return range of LSM programs, refused `ptrace_access_check`. Every
  error return now goes through `ERR()`, which hides the constant from the
  optimiser (`d002368`).
- Test bugs, on every kernel: phase5 cleared the daemon's log while the
  daemon wrote to it without `O_APPEND` (lost lines, NUL bytes); the
  unload check did not wait for the RCU grace period of sleepable
  programs; Yama (before `bpf` in the VM's `lsm=`) refused a ptrace
  before explsm saw it; phase3's journal checks need a running journald;
  6.9's Landlock has only some of the rights (`partly sandboxed`).

## 2. §9 Who started the app

Commits: `1a7446e` (BPF), `1b23973` (policy), `fc816df` (daemon, ctl),
`537f194` (smoke test), `ccaec47` (6.9/7.3 verifier fixes), `993dc6f`
(9.3), `9eb31f1` (docs, example).

- 9.1 `code trusted|any`: new `mmap_file` and `file_mprotect` programs
  (registered in `hooks.rs`); a process of an app maps a file as code only
  if root alone can change it (uid 0, not group/other writable, not FUSE)
  or the app owns it.
- 9.2 `started_by APP, @terminal, @desktop, @unconfined`, judged by the
  task's identity before the exec (copied at fork, so re-parenting does not
  matter). `shell` and `desktop` lines; `@terminal` is a chain of shells
  from a terminal exe (`TF_SHELL`). Warnings for launchers that start
  programs for anyone, and for `@terminal`/`@desktop` without their exes.
  Drops are logged with the spawner.
- 9.3 `launch_files off|audit|enforce` (audit by default): `~/.bashrc` and
  the other shell startup files, `~/.config/autostart`,
  `~/.config/systemd/user`, `~/.local/share/applications` belong to
  `@launch`; readable by all, changed only with `grant APP … to @launch`.
- 9.5 `deny_args` (exact, or a prefix ending in `*`), a hash map plus
  per-app prefix lengths because the sleepable exec hook can't use an LPM
  trie on 6.9.
- 9.6 `packaging/examples/ssh-agent.explsm`; the threat model's "anyone who
  can start an owner app can use it" with the three cases.
- `tests/launch-smoke.sh`: shell chain, non-shell interpreter, orphan,
  desktop, named app, audit mode, both kinds of `deny_args`, root-, user-
  and app-owned libraries, `code any`, and (in a VM) `launch_files`.

## 3. §5 Guarded binaries

Commits: `8716f5b`, `7408164`.

- `exe "PATH" sha256 "HEX"` and `hashes "FILE"` (a root-owned `sha256sum`
  list; one a user could replace is refused like an `env` path). A file the
  path or glob matches with none of the hashes is refused, logged, and
  shown by `explsmctl check --resolve`; this closes trust on first use for
  pinned paths.
- `explsmctl status` notes each exe as `protected (user-writable)` or
  `trusted: only root can change it`, and `, hash pinned`; the threat model
  and `docs/dsl.md` say why root-owned exes are trusted.
- `tests/guard-smoke.sh`: a pinned exe, a glob that later matches a bad and
  then a good file, a replaceable hash list, a bad hash, and that nobody
  else can replace a pinned user-writable exe.

## CI status

Green on `e533672`:
https://github.com/matejstrnad/experimental_lsm/actions/runs/42539835524

- `check` (fmt, clippy `-D warnings`, test, release build): passed.
- `vm-smoke` on 6.9, 6.15 and 7.3.3: every test passed on each (phase2 45,
  phase3 16, phase4 20, phase5 57, phase6 20, inherit 18, landlock 18,
  launch 22, guard 7 checks). Skipped: phase3's journal checks, as the VM
  runs no journald.

Later commits only change this report. The runs before it are the history
of the fixes above; the last fix CI found was that the sandboxed daemon
could not read pinned exes to hash them (`76e7195`).

## Skipped, and why

- **GitHub writes were refused** for the first hour of the run (403 for
  `git push` and the API); the work stayed local until access was fixed,
  then went up in order.
- **§9.4 ask at launch (fanotify `FAN_OPEN_EXEC_PERM`)**: needs a new
  prompt type in the agent and the D-Bus API, a way to hand the answer to
  the exec hook for that one exec, and decisions on the prompt and its
  timeout. A design choice, not a mechanical step.
- **§5 ask on first match**: the same prompt machinery.
- **§5 signature check for self-updating apps**: which scheme (fs-verity
  with the kernel keyring, minisign, a vendor's signed hash list) is a
  design choice; only root-owned hash lists are supported.
- Root resistance stage 2, §4, §6, §7 and release engineering beyond CI:
  out of scope for this run.

## Open concerns

- The `code` check looks at the file only, not the directories above it,
  and trusts every root-owned file: a root-owned library in a
  user-writable directory can be swapped for another root-owned one.
- An exe hash is taken when the daemon resolves the path, before the file
  is guarded: a short race for a user-writable exe.
- `started_by` judges the identity before the exec: wrappers (`env`,
  `sudo`, `nice`, `time`) end the chain of shells unless listed as `shell`,
  and listing one lets anything typed after it through. Processes that ran
  before explsmd started get no `TF_SHELL` (only `TF_TERMINAL` is seeded).
- `launch_files` is audit by default and only protects the files, not the
  folders above them; renaming `~/.config` aside and recreating it gets
  around it until the daemon resolves the paths again.
- `*` grants cover `@launch`.
- Capping app names at 250 (one id went to `@launch`) changes the id space;
  a saved id table with 251 names would be cut.
- The 6.9 verifier treats `d_inode` of a trusted dentry as non-NULL; any
  new code that reads `d_inode` directly would oops there. The comment at
  `positive_key` says so; a lint for it would be better.
