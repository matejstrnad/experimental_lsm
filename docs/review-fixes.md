# Fix brief: findings of the 2026-11-10 review

This is a work order for an agent fixing what a code review of explsm found.
It is written to be read cold: you do not need the review conversation.

The review read the docs, `explsmd/bpf/explsm.bpf.c`, and the daemon's
policy, prompt, claims and D-Bus code at commit `42b9eee` on `main`. Line
numbers below are from that commit; if the code has moved, find the function
by name.

**None of the findings was reproduced on a running system.** They come from
reading the code. For each one, reproduce it first (a failing test), then
fix it. If one turns out not to be real, say so and write down why instead
of "fixing" it.

## Ground rules

- Part 1 is the job: four security bugs, in the order given. Part 2 is
  smaller follow-up work. Part 3 lists things that need the owner's
  decision: do not implement them, only what Part 3 says.
- One commit per finding, on a branch, not on `main`. Commit subjects in
  this repository are plain sentences saying what changed
  (`Fail deny_args closed and hold the agent to code trusted`). Do not push.
- Every fix comes with a test that fails before it and passes after.
- Before each commit, all of these pass:

  ```bash
  cargo fmt --all --check
  cargo clippy --locked --all-targets -- -D warnings
  cargo test --locked
  ```

- Anything that touches the BPF program or what the daemon writes into the
  maps also needs the smoke tests, which run as root in a throwaway VM
  (`tests/vm-smoke.sh`, see "Testing" in `README.md`). Never run the
  `tests/*-smoke.sh` scripts directly on this machine: they change the
  system. If you cannot run the VM, say so in your report; do not claim the
  smoke tests passed.
- Update the docs in the same commit as the behaviour:
  `docs/threat-model.md`, `docs/dsl.md`, `docs/gui.md`, `README.md`.

Things that are easy to break here:

- **Map layout.** The pinned maps carry a layout version derived from
  `explsmd/bpf/explsm.h` and the map definitions in `explsm.bpf.c`
  (`explsm-common/layout.rs`). Changing a struct, a constant in `explsm.h`
  or a map definition changes it, and an upgrade then unloads explsm instead
  of taking the maps over. That is allowed, but avoid it when a fix does not
  need it, and mention it in the commit when it happens. If only the meaning
  of entries changes, bump `LAYOUT_EPOCH`.
- **`explsm.h` and `explsm-common/src/lib.rs` mirror each other**, with size
  and offset assertions on both sides.
- **The BPF verifier, on three kernels.** CI loads the programs on 6.9, 6.15
  and 7.3.3. Read the comments in `explsm.bpf.c` before changing code near
  them: several odd-looking constructs (`ERR()`, `positive_key`, reads
  through `bpf_probe_read_kernel`) work around verifier behaviour of one of
  those kernels.
- **The daemon is sandboxed** (Landlock, `explsmd/src/sandbox.rs`): it can
  list directories and stat anywhere, but read only its own files and
  `/proc`. New code in the daemon that reads other files will fail at
  runtime, not in unit tests.
- **Fail closed.** When in doubt a check denies, drops the identity or does
  not offer the answer.

---

## Part 1: security bugs

### 1. A prompt grants more permissions than it shows

**Severity: high.** A program can get write and delete access approved by a
user who was shown "read".

**What happens.** Denials of one subject on one owner's data, for one user,
are a single prompt. While it is open and younger than `STALE`,
`Prompts::access` ORs the permissions of later denials into it and returns
`Outcome::Merged` (`explsmd/src/prompts.rs:146-151`). `Desk::event` returns
early on anything but `Outcome::Ask` (`explsmd/src/desk.rs:417-422`), so the
`PromptInfo` stored on the prompt, and sent to the agent, keeps the
permissions of the first denial. The dialog shows that stored info
(`explsm-gui/src/prompt.rs:132`, fetched by id through `Desk::prompt_info`);
the notification fallback shows the same (`explsm-agent/src/main.rs:499`).
`Desk::answer` then grants `perms` from `prompt.kind`, the merged set
(`desk.rs:554-617`), for all three allow answers, including the grant line
written into the claims file.

**Attack.** As any program: open a file of the owner read-only (prompt:
"Needs read"), then at once try to write, unlink and chmod it. The user
answers "Allow"; the grant is `read, write, delete, setattr`.

**Fix.** What is granted must be exactly what was shown. Do the simple
thing:

- Do not add permissions to an open prompt. A later denial of the same key
  while a prompt is open stays `Merged` (no second prompt), but leaves the
  prompt alone.
- In `Desk::answer`, take the permissions from one place that is also what
  was displayed. Either drop `perms` from `Kind::Access` and use the stored
  `PromptInfo`, or keep the field and never change it after the prompt is
  sent; the first is harder to get wrong later.
- A program that needs more than was approved is denied again and asks
  again, with a prompt that names the new permissions. After "Deny" the
  quiet period already silences it.

Do not re-send or update an open dialog instead: the user may be clicking
while the text changes, which is the problem the 1.2 s button delay exists
to prevent.

**Tests.**

- `prompts.rs`, `merges_and_quiets` currently asserts the bug
  (`(perms, pid) == (READ | WRITE, 42)`). Change it to assert that the open
  prompt still has `READ`.
- A test that the permissions granted by an answer equal the permissions in
  the prompt's `PromptInfo`. `Desk::answer` needs a `State` with a loaded
  BPF object, so either extract the "which perms does this answer grant"
  step into a pure function and test that, or add the case to
  `tests/phase4-smoke.sh` (deny read, then deny write before answering,
  answer allow, expect the write to be denied again).

**Done when** no code path grants a permission that is not in the
`PromptInfo` the user saw, and `docs/gui.md` says a prompt covers the
permissions it shows and nothing more.

### 2. Paths written into the claims file are read back as globs

**Severity: high for "Protect", medium for "Always allow".**

**What happens.** Answers are written into `/etc/explsm/claims.d/<user>.explsm`
as policy text. `claims::quote` escapes `\` and `"` and `claims::writable_path`
refuses relative paths and control characters
(`explsmd/src/claims.rs:35-43`). But the policy language treats `*`, `?` and
`[` in the last path component as a glob (`PathPat::parse`,
`explsm-policy/src/compile.rs:225-236`), and has no way to write them
literally. The name of a new folder (`Kind::Claim`, from the `inode_mkdir`
event) and the path of an exe (`ALLOW_ALWAYS` for `Subject::Exe`) are chosen
by the program being asked about.

**Attack.** An app creates `~/.config/*` (a folder literally named `*`). The
user is asked whether the app should own `/home/me/.config/*` and answers
"Protect". The file gets `claim app "/home/me/.config/*"`, and the app now
owns every entry in `~/.config`. Likewise an exe named `x*` in a directory
with other programs: "Always allow" makes every file matching `x*` there
the app.

**Fix.**

- Make `writable_path` refuse a path with `*`, `?` or `[` in any component.
  Its three callers then do the right thing already: the new folder is not
  asked about (`desk.rs:388`), and "Always allow" is not offered
  (`desk.rs:450`) and refused if sent anyway (`desk.rs:608`).
- Do not rely on the reload failing: a glob in a directory component is a
  parse error and the append is undone, but a glob in the last component
  loads fine. That is the bug.
- Share the definition of "glob character" with the policy crate (export a
  function from `explsm-policy` next to `PathPat`), so the two cannot drift.

While in this file, fix the neighbouring mistake: `code()` cuts a line at
the first `#` (`claims.rs:203-205`), and its comment says the lines explsmd
writes never contain one. An exe path can. For an exe such as
`/opt/a#b/tool`, `exe_app_line` then fails, so the saved grant is listed
without its exe and `remove_grant` leaves the `app` line behind. Parse the
quoted string first and look for a comment only after it, and add the case
to `reads_and_removes_saved_grants`.

Optional, and only if it stays small: an escape for glob characters in the
policy language, so such paths can be claimed. If you do it, it needs
`docs/dsl.md`, lexer tests and a round-trip test through `claims.rs`. If it
does not stay small, leave it and say so.

**Tests.**

- `claims.rs`: `writable_path` refuses `/home/me/.config/*`, `/a/b?`,
  `/a/[x]`, `/a/*/b`.
- A round-trip property: for a set of awkward but accepted paths (spaces,
  `#`, `"`, `\`, `~` in the middle, non-ASCII), the text `claim()` and
  `exe_grant()` write compiles to exactly one non-glob `PathPat` whose path
  is the input. Extend `the_text_compiles`.

**Done when** no path that reaches `claims::claim` or `claims::exe_grant`
can compile to a pattern matching anything but that path.

### 3. Data can be moved out of protection by renaming a directory above it

**Severity: high for roots below `~/.config`, `~/.local/share` and similar;
roots directly in the home directory (`~/.ssh`) are not affected.**

**What happens.** A root is identified by its inode. The rename hook checks
the object being renamed (`inode_rename`, `explsm.bpf.c:1556-1614`), so a
root itself can only be renamed with `rename` permission on its owner. The
directories above a root are not checked at all, unless they are on the way
to a user-writable app exe: `exe_path()` looks only in `EXE_PATHS`
(`explsm.bpf.c:891-899`), and the daemon fills `EXE_PATHS` only for exes
(`State::plan`, `explsmd/src/state.rs:905-929`).

**Attack.** Policy has `owns "~/.config/gh"`. As any program of the user:

```bash
mv ~/.config ~/.config.old
mkdir -p ~/.config/gh        # a decoy, with a config of the attacker's
```

1. The daemon's watch resolves `~/.config/gh` again and makes the decoy a
   root of the app. The app now reads a config the attacker wrote, and for
   many apps a config can make them run commands or send data somewhere.
2. The real folder, now `~/.config.old/gh`, stays protected only because the
   running daemon holds it open and marks it "moved"
   (`State::update_roots`, `state.rs:798-823`). Nothing of that survives a
   reboot or `explsmctl unload`: the pins and the fds are gone, the policy
   names a path the real folder is no longer at, and it is unprotected.
   Check whether a plain daemon restart also loses it (the new daemon reads
   back the pinned `ROOTS`, then syncs it to its own plan).

**Fix.** Guard the directories above data roots the way `EXE_PATHS` guards
those above exes: a directory on the way to a root that a user could rename
or remove may only be renamed, replaced or removed by the root's app, the
daemon, or root with the bypass.

- Read `renameable()` and `user_writable()` in `state.rs` first; they decide
  which ancestors count for exes. Use the same rule for roots, including
  roots found through a symlinked path (see how `canonicalize` is used for
  exes).
- Cover every kind of root that comes from a path of the policy: `owns`,
  `claim`, and the `launch_files` roots (owner `OWNER_LAUNCH`).
- Reuse the `EXE_PATHS` map if you can, so the map layout stays the same;
  update its comments in `explsm.bpf.c`, `explsm.h`, `state.rs` and the
  capacity message in `State::write` to say it now holds both. Check that
  4096 entries are still enough (several users, many roots) and that the
  capacity check reports it clearly when they are not.
- **Mode.** `exe_guard()` denies only if the app in the map value is
  enforced. `State::plan` inserts with `entry(k).or_insert(app)`, "the first
  keeps it". With data roots, `~/.config` will be above the roots of many
  apps, some in audit mode. The guard must enforce as soon as one app whose
  root is below the directory is enforced. Pick the value accordingly
  (prefer an enforced app), make the choice deterministic, and test it.
- **Who may rename.** Today only the app in the value may. For a directory
  above the roots of several apps, none of them alone should be able to move
  the others' data: decide whether such a directory may be renamed by none
  of them (simplest: use a value no subject equals when more than one app is
  below, keeping the enforced/audit question above in mind) and document it.
- **Logging.** The denial is reported as `OP_EXE_DIR` with reason tamper.
  Make sure the log line and `explsmctl log` read sensibly for a data root
  ("directory above protected data"), without changing `enum op` values that
  existing journal entries and `explsmctl learn` rely on. A new op at the
  end of the enum is fine.
- This makes `mv ~/.config elsewhere` fail for the user in enforce mode.
  That is intended; say so in `docs/dsl.md` and in the README's "Behaviour
  worth knowing", with the way out (`explsmctl unload`, or audit mode).

Not part of this fix: a path of the policy that does not exist yet can still
be created first by anyone (documented in the threat model as trust on first
use), and mounts over a root.

**Tests.** A smoke test (new file, or in `tests/guard-smoke.sh`), in the VM:

- app in enforce mode owning `~/.config/x`: `mv ~/.config ~/c2` by an
  unconfined process fails and is logged; `rmdir`/rename of an unrelated
  sibling still works; the app itself is handled as you decided above.
- the same with the app in audit mode: allowed and logged.
- two apps below `~/.config`, one audit and one enforce: denied.
- `mv` of a directory that is above no root is unaffected, and so is a
  rename inside `~/.config` of entries that are no ancestors.

**Done when** the two-line attack above fails in enforce mode, and
`docs/threat-model.md` describes what is guarded and what is left (audit
mode, missing paths).

### 4. On btrfs, and probably overlayfs, nothing matches and nothing is protected

**Severity: high where it applies (btrfs is the default on Fedora and
openSUSE), and silent. Not verified: reproduce first.**

**What happens.** Everything is keyed by `(device, inode)`. Userspace takes
the device from `stat` (`key_of`, `explsm-policy/src/resolve.rs:47-55`); the
BPF side takes `inode->i_sb->s_dev` (`file_key`, `explsm.bpf.c:350-353`, and
`positive_key`, `deep_step`). On most filesystems these are the same number.
On btrfs `stat` reports an anonymous device per subvolume that is not the
superblock's, so the keys the daemon writes into `EXES` and `ROOTS` should
never equal what the hooks compute: no exe gets an identity, no root is
found, and explsm reports a loaded policy while enforcing nothing.
overlayfs can report a `st_dev` different from its superblock's too, when
its layers are on different filesystems.

Making userspace compute `s_dev` would not fix it: btrfs inode numbers are
only unique within a subvolume, and an unprivileged user can create a
subvolume and create files in it until one has the inode number of
`/usr/bin/ssh`. That file would have the app's key.

**Fix, in this order.**

1. **Reproduce.** In the VM, make a btrfs filesystem on a loop device (if
   `mkfs.btrfs` is not in the VM image, find out how `tests/vm-smoke.sh`
   provides tools before adding a dependency), put a root and an exe on it,
   load a policy and show that the root is not protected. Record what
   `stat -c %d`, `/proc/self/mountinfo` and the daemon's `show_key` say for
   the same file. If explsm does protect it, stop: write down what you saw
   and report it.
2. **Detect it, generally.** Do not match on filesystem names. For a path
   being resolved, compare the device `stat` reports with the device of the
   mount it is on: `statx` gives the mount id (`STATX_MNT_ID`), and
   `/proc/self/mountinfo` gives that mount's `major:minor`, which is the
   superblock's (`events.rs:55-70` already parses mountinfo). Where they
   differ, the kernel side cannot match this path. Check that the sandbox
   lets the daemon do this (it reads `/proc`), and that `explsmctl check
   --resolve`, which runs without root, does the same.
3. **Say so, loudly.** Such a path is not put into the maps. It is reported
   as its own kind of problem, not as "missing": a warning on load and
   reload, in `explsmctl status` next to the exe or root, and in `explsmctl
   check --resolve`. Wording along the lines of: the filesystem of PATH
   (btrfs) is not supported, PATH is NOT protected.
4. **Do not let enforce mode pretend.** An app in `mode enforce` with an exe
   or root on such a filesystem is a policy that does not do what it says.
   Make that an error that keeps the old policy in force, unless the owner
   decides otherwise (ask in your report; a policy option to downgrade it to
   a warning is an acceptable way to leave the choice open).
5. **Document it** under Requirements in `README.md` and in the limitations
   of `docs/threat-model.md`. Also correct the threat model's remark about
   "filesystems without stable inode numbers": this is a different problem.

Real btrfs support (the subvolume in the key) is out of scope: it changes
`struct file_key`, every map keyed by it, and needs the subvolume id read in
BPF from a filesystem that is usually a module. Describe what it would take
in a short section of `docs/release-plan.md` and leave it there.

**Tests.** Unit tests for the comparison with a fake mountinfo. The
reproduction from step 1 as a smoke test that expects the warning and the
refusal, skipped with a clear message when btrfs is not available in the VM.

**Done when** explsm cannot be loaded with a policy that silently protects
nothing on such a filesystem.

---

## Part 2: smaller work, after Part 1

### 5. `launch_files` misses files the shell and desktop run things from

`LAUNCH_FILES` (`explsm-policy/src/compile.rs:29-39`) is what backs
`started_by @terminal` and `@desktop`. Add at least:

- `~/.bash_aliases` (Ubuntu's default `~/.bashrc` sources it),
  `~/.bash_logout`, `~/.inputrc` (key bindings can run shell commands)
- `~/.zshenv`, `~/.zprofile`, `~/.zlogin`
- `~/.config/environment.d` (environment of every user service and session)
- `~/.bash_completion`, `~/.local/share/bash-completion` (loaded when the
  user presses Tab)
- `~/.local/share/gnome-shell/extensions` (code loaded into the `desktop`
  exe)

For each, check on a real system that it is what the comment claims before
adding it, and that owning it in `enforce` mode does not break something
ordinary (GNOME's extension manager must be grantable `@launch`, for
example). Update the array length, `docs/dsl.md`, `docs/threat-model.md`,
and the tests that list the files (`tests/launch-smoke.sh`).

### 6. Docs that contradict the code

- `docs/release-plan.md:234` says `root_bypass on` is the default. It is
  `audit` (see the README's release note).
- `docs/release-plan.md` section 1 lists "correctness blockers" (atomic
  load, hook arguments by BTF, atomic policy commit, telling the user when
  explsm is not running) and section 2 "should-fix" items. Several appear to
  be implemented (`state.rs` commit and undo, `hooks.rs`, `fail_closed`,
  the agent's notice). Check each against the code and mark it done with
  the date, as sections 3 to 9 do, or leave it open with what is missing.
  Do not mark anything done that you have not found in the code.
- `docs/threat-model.md`: add that reading metadata is not mediated. Without
  `list` a process cannot open a protected directory, but it can still
  `stat` files in it, read symlink targets and read extended attributes,
  because there are no hooks on lookup, `getattr`, `readlink` or `getxattr`.

### 7. Release engineering

- Pin the toolchain: `rust-toolchain.toml` says `stable`, so a new Rust
  release can fail CI (clippy with `-D warnings`) on an unchanged tree. Pin
  the version installed now (`cargo --version`), with `rustfmt` and `clippy`
  as components.
- Add a dependency audit job to `.github/workflows/ci.yml` (`cargo audit` or
  `cargo deny`), with the action pinned by commit hash like the others.
- Add `SECURITY.md`: how to report a vulnerability and what is in scope
  (point at `docs/threat-model.md`). **Leave the contact address as a
  clearly marked placeholder for the owner to fill in; do not invent one and
  do not copy an address from git history.**

---

## Part 3: needs the owner's decision, do not implement

Write a short note for each in your report (what you would do, what it
costs), nothing more.

- **Tamper protection for the trusted launchers.** Shells, terminals and the
  desktop shell carry `TF_SHELL` or `TF_DESKTOP`, which `started_by`
  trusts, but they are unconfined tasks, and `may_tamper()` lets anyone
  ptrace an unconfined task. Where Yama's `ptrace_scope` is 0, a program can
  inject into the user's shell and start an app from there. Guarding tasks
  with those flags would close it, and would stop `gdb -p` and `strace -p`
  on every shell. Since a program can also start a terminal with a command
  of its choice (documented), the gain is limited to `@desktop`.
- **"Allow until logout" for an exe the user can change.** The grant is
  keyed by the exe's inode (`TK_EXE`); a user-writable exe can be rewritten
  in place and keeps it. The prompt warns, but still offers the answer.
  Options: do not offer it for such exes, or offer only "this process".
- **Overhead numbers.** The cost per `open` is unmeasured
  (`docs/production-review.md` says so). Needs a benchmark plan, not code.

---

## What to hand back

A report with, for each numbered item: whether you reproduced it, what you
changed (files), the test that covers it, and anything you decided that the
brief left open. Then the output of the three `cargo` commands, and for the
smoke tests either the result per kernel or a plain statement that they were
not run and why. List the questions for the owner (item 4 step 4, Part 3)
at the top, not at the end.
