# The GUI

explsm's desktop parts are in the `explsm-desktop` package: `explsm-agent`,
a user service in each graphical session, and `explsm-gui`, a GTK4 /
libadwaita program with two windows. Servers install `explsm` only and pull
in nothing graphical.

**The windows need Wayland.** On X11 any client of the user can read the
screen, and so the security picture, and send clicks and key presses to any
window; no dialog can defend against that. In an X11 session the windows
don't open (the prompt dialog exits with code 3), and the agent keeps
showing prompts as notifications. `explsm-gui` holds GTK to its Wayland
backend (`GDK_BACKEND=wayland`), so it can't end up on X11 through Xwayland
either.

## The prompt dialog

For each prompt of explsmd, the agent starts `explsm-gui prompt`, writes the
prompt to its stdin as JSON and reads the answer from its stdout. One dialog
is shown at a time; later prompts wait. The dialog shows:

- your **security picture** (below),
- what is asked: the program, whose data, the file and the permissions, or
  the new folder,
- the warning explsmd attached (an exe you can change, an interpreter),
- your earlier answers about the same program and data,
- one button per answer explsmd offers.

Closing the window or pressing Escape answers nothing: the access stays
denied. If the dialog crashes, nothing is answered either; the agent keeps
the logic and the D-Bus link to explsmd, so a broken UI can't answer for
you. The dialog exits with code 3 when it can't open a window at all (not a
Wayland session, GTK fails); the agent then shows the prompt as a
notification, as it does when `explsm-gui` is not installed or there is no
`WAYLAND_DISPLAY`. `explsm-agent --no-gui` uses notifications only.

## Against fake and hijacked prompts

A prompt that can be faked or clicked by another program is worse than
none. What the dialog does about it:

- **Security picture.** In explsm Settings you pick a picture and a phrase.
  Every dialog shows them. explsmd keeps them in
  `/var/lib/explsm/secret-<uid>` (root only) and hands them only to
  processes running the agent or GUI exe, which get the agent's identity
  (`explsmd --gui`, default `/usr/libexec/explsm-gui`), so another program
  of yours can't ask explsmd for them, ptrace the dialog or read its memory
  (but see the compositor below). The agent's identity is held to `code
  trusted`, so a library planted in your folders isn't loaded into them. A window
  without your picture is not explsm's: answer nothing.
- **Only explsmd's words next to the picture.** Any program can start
  `explsm-gui prompt`, so the dialog takes nothing but the prompt's id from
  its caller and shows what explsmd has under that id (`PromptInfo`). A
  program that starts it gets a real, open prompt of yours or no window.
- **Delayed buttons.** The buttons work only once the window has been
  active (focused) for 1.2 seconds, and stop working when it loses focus. A
  click or key press meant for another window can't land on a dialog that
  just popped up, and no button is the default for Enter.
- **A clean environment.** `explsm-gui` drops every environment variable
  but those that name the Wayland display, the session bus and the language before
  GTK starts: GLib, GTK and Mesa load code named by variables such as
  `GIO_EXTRA_MODULES`, `GDK_PIXBUF_MODULE_FILE` or `LIBGL_DRIVERS_PATH`,
  which would run with the agent's identity. `DBUS_SYSTEM_BUS_ADDRESS` goes
  too, so it always talks to the real system bus.
- **No single instance.** The windows don't register as unique GApplications
  on the session bus: any program could own that name first and get the
  activation instead.

What it does not do (yet):

- A program can still draw a window that looks like the dialog;
  the picture is what tells them apart, so it only helps if you look at it.
- It does not check that the denied program is the one in the foreground.
- It does not check which Wayland compositor it draws on. A program of
  yours can start the dialog or the settings window (or the agent, which
  starts the dialog) with `WAYLAND_DISPLAY` naming a compositor it runs
  itself, and read your picture from what the window draws. Against such
  a program the picture does not tell explsm's windows from fakes.
- GTK still reads your theme and `~/.config/gtk-4.0/gtk.css`, which other
  programs of yours can write: they can restyle the dialog, though not read
  your picture.

## explsm Settings

`explsm-gui settings` (the "explsm Settings" entry in your app list) has
four pages:

- **Picture**: choose the security picture and phrase.
- **Grants**: the grants you gave through prompts. Grants until the process
  exits or until logout can be revoked at once; "Always" grants are taken
  out of `/etc/explsm/claims.d/<you>.explsm` and the policy is reloaded (if
  it does not load without them, the file is put back). Folders you chose
  to protect are listed, but only an administrator can take them back:
  doing that unprotects data.
- **History**: your answers since explsmd started (the last 200; not kept
  across restarts).
- **Apps**: the apps of the policy, their mode, exes and data.

## D-Bus

The GUI uses these methods of `org.explsm.AgentManager1` (see
`explsm-ipc`). explsmd answers them only for processes running the agent or
GUI exe, and only about the caller's own user:

| Method | |
|---|---|
| `PromptInfo(id) → PromptInfo` | your open prompt `id`, as explsmd sent it to the agent |
| `UserStatus() → UserStatus` | apps, your temporary and saved grants, your claims, history, picture |
| `RevokeTemp(subject, owner) → u` | end your grants until exit or logout of `subject` to `owner` |
| `RevokeSaved(subject, owner)` | remove your saved grant of `subject` to `owner`, and reload |
| `SetSecret(Secret)` | set your picture and phrase |

Revoking only ever takes access away. Removing a `claim` is not offered.

## Trying it out

`--preview FILE` reads the user status from a JSON file instead of asking
explsmd, e.g.:

```bash
cargo run -p explsm-gui -- settings --preview explsm-gui/examples/preview.json
echo '{"id":1,"kind":"access","subject":"/usr/bin/rg","process":"rg (pid 7)","owner":"ssh",
  "perms":["read"],"path":"/home/me/.ssh/id_ed25519","warning":"",
  "choices":["allow-session","deny"]}' |
  cargo run -p explsm-gui -- prompt --preview explsm-gui/examples/preview.json
```

Building needs the GTK 4 (≥ 4.14) and libadwaita (≥ 1.5) development files
(`libgtk-4-dev libadwaita-1-dev`).

## Tests

`tests/gui-smoke.sh` (in `tests/run-all.sh`, so in CI's VM) checks the four
methods against a real explsmd: that only the GUI exe at the path explsmd
was given may call them (not `busctl`, not a copy of the GUI elsewhere),
that the picture is stored root-only and each user has their own, that
the status lists grants, saved grants and answers, and that revoking works
and only on the caller's own grants. It calls them through `explsm-gui
test …`, which only exists with the `test-cli` feature;
`packaging/build-deb.sh` refuses to package such a build.
