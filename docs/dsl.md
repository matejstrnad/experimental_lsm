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

App names are words of letters, digits, `_`, `-` and `.`. `unconfined`,
`all`, `terminal`, `explsm-agent`, `explsmd` and `explsm-pins` are reserved.
At most 252 different app names can be used until explsm is unloaded: ids are
not reused, because running processes keep theirs, and they are kept across
daemon restarts in `/var/lib/explsm/ids`.

An exe that a user other than root could replace (owned by a user, writable
by group or others, or in such a directory) is protected like the app's data:
anyone may run it, only the app may change, move or remove it, and only the
app may add files to its directory, so nothing can be planted for a glob such
as `~/.local/share/claude/versions/*`.

`exe "…" script "…"` (interpreter identity, e.g. `node …/cli.js`) is
reserved and reported as not supported yet.

### `grant SUBJECT PERMS to OWNER`

Lets `SUBJECT` access the data of `OWNER`. Grants for the same pair add up.

- **SUBJECT**: an app, `@unconfined` (every process that is no app), or
  `@terminal` (see [`terminal`](#terminal-path-)). `@root` can't be granted
  to: root bypasses every check unless `root_bypass off`.
- **PERMS**: comma-separated, from `read`, `write`, `create`, `delete`,
  `rename`, `list` (read a directory), `setattr` (mode, owner, times,
  xattrs, ACLs), or `all`. Truncation counts as `write`.
- **OWNER**: an app, or `*` for every app's data.

An app always has full access to its own data; granting it to itself is an
error.

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

List the process that starts the shells: for GNOME Terminal that is
`/usr/libexec/gnome-terminal-server`, not the `gnome-terminal` command. A
`@terminal` grant without any `terminal` exe is a warning.

**This is a heuristic, not a boundary.** Any program of the user can start a
terminal emulator with a command of its choice (`konsole -e cat …`). Prefer
prompts or app grants for sensitive data. Processes that were running below a
terminal when the daemon started get the flag too. A terminal removed from
the policy keeps its running processes trusted until they exit.

### `claim APP "PATH", …`

More roots of an app defined elsewhere. The daemon writes these for
auto-claims; they can be written by hand too.

### `root_bypass on|off`

`on` (the default): processes with fsuid 0 bypass every check except label
changes and `EXDEV`. `explsmd --no-root-bypass` turns it off regardless.

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
