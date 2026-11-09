//! The prompt dialog.
//!
//! Made so that another program has a hard time answering it or faking it:
//!
//! - It shows the user's security picture, which only explsm's own
//!   processes can read; a window without it is not explsm's.
//! - Its buttons work only once the window has been active (focused) for
//!   [`ARM_DELAY`], and stop working whenever it loses focus, so a click or
//!   key press meant for another window can't land on them when the dialog
//!   pops up, and no button is the default for Enter.
//! - Escape or closing the window answers nothing; the access stays denied.

use std::{cell::Cell, cell::RefCell, rc::Rc, time::Duration};

use adw::prelude::*;
use explsm_ipc::{HistoryEntry, PROMPT_CLAIM, PromptInfo, UserStatus, choice};

use crate::{Source, secret};

/// How long the window must have been active before its buttons work.
pub const ARM_DELAY: Duration = Duration::from_millis(1200);
/// How many earlier answers are shown.
const HISTORY_SHOWN: usize = 5;

fn row(title: &str, value: &str) -> adw::ActionRow {
    let r = adw::ActionRow::new();
    r.set_use_markup(false);
    r.set_title(title);
    r.set_subtitle(value);
    r.set_subtitle_selectable(true);
    r.add_css_class("property");
    r
}

/// The earlier answers about the same program and data.
fn related<'a>(info: &PromptInfo, status: &'a UserStatus) -> Vec<&'a HistoryEntry> {
    status
        .history
        .iter()
        .filter(|h| h.kind == info.kind && h.subject == info.subject && h.owner == info.owner)
        .take(HISTORY_SHOWN)
        .collect()
}

/// "3 hours ago" and so on, from a Unix time.
pub fn ago(time: u64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let s = now.saturating_sub(time);
    match s {
        0..60 => "just now".into(),
        60..3600 => format!("{} min ago", s / 60),
        3600..86400 => format!("{} h ago", s / 3600),
        _ => format!("{} days ago", s / 86400),
    }
}

/// Show the dialog for `info`; the answer, if the user gave one.
pub fn run(info: PromptInfo, source: Source) -> Option<String> {
    // Read before the window opens: it is local and quick, and the window
    // should not appear without the picture.
    let status = source.user_status();
    let answer: Rc<RefCell<Option<String>>> = Rc::default();
    let app = adw::Application::builder()
        .application_id("org.explsm.Prompt")
        // Unique applications forward to whoever owns the name on the
        // session bus first, which any program can.
        .flags(gtk::gio::ApplicationFlags::NON_UNIQUE)
        .build();
    let answer2 = answer.clone();
    app.connect_activate(move |app| build(app, &info, &status, answer2.clone()));
    app.run_with_args::<&str>(&[]);
    answer.take()
}

fn build(
    app: &adw::Application,
    info: &PromptInfo,
    status: &Result<UserStatus, String>,
    answer: Rc<RefCell<Option<String>>>,
) {
    let window = adw::ApplicationWindow::builder()
        .application(app)
        .title("explsm")
        .default_width(520)
        .resizable(false)
        .build();
    let body = gtk::Box::new(gtk::Orientation::Vertical, 12);
    body.set_margin_top(12);
    body.set_margin_bottom(18);
    body.set_margin_start(18);
    body.set_margin_end(18);

    body.append(&secret::widget(
        &status
            .as_ref()
            .map(|s| s.secret.clone())
            .map_err(Clone::clone),
    ));

    let title = gtk::Label::new(Some(&info.summary()));
    title.set_wrap(true);
    title.set_xalign(0.0);
    title.add_css_class("title-2");
    body.append(&title);

    let details = adw::PreferencesGroup::new();
    if info.kind == PROMPT_CLAIM {
        let explain = gtk::Label::new(Some(&format!(
            "{} created this folder. Protect it, so that only {} may use it?",
            info.subject, info.subject
        )));
        explain.set_wrap(true);
        explain.set_xalign(0.0);
        body.append(&explain);
        details.add(&row("Folder", &info.path));
        if !info.process.is_empty() {
            details.add(&row("Created by", &info.process));
        }
    } else {
        let explain = gtk::Label::new(Some(
            "The access was denied. If you allow it, the program has to try again.",
        ));
        explain.set_wrap(true);
        explain.set_xalign(0.0);
        explain.add_css_class("dim-label");
        body.append(&explain);
        details.add(&row("Program", &info.process));
        details.add(&row("Data of", &info.owner));
        details.add(&row("File", &info.path));
        details.add(&row("Needs", &info.perms.join(", ")));
    }
    body.append(&details);

    if !info.warning.is_empty() {
        let warning = gtk::Label::new(Some(&info.warning));
        warning.set_wrap(true);
        warning.set_xalign(0.0);
        warning.add_css_class("warning");
        body.append(&warning);
    }

    if let Ok(status) = status {
        let earlier = related(info, status);
        if !earlier.is_empty() {
            let group = adw::PreferencesGroup::new();
            group.set_title("Earlier answers");
            for h in earlier {
                let r = adw::ActionRow::new();
                r.set_use_markup(false);
                r.set_title(&choice::label(&h.answer, &h.subject));
                r.set_subtitle(&format!(
                    "{} · {} · {}",
                    ago(h.time),
                    h.perms.join(", "),
                    h.path
                ));
                group.add(&r);
            }
            body.append(&group);
        }
    }

    let buttons = gtk::Box::new(gtk::Orientation::Vertical, 6);
    buttons.set_margin_top(6);
    let mut all = Vec::new();
    for c in &info.choices {
        let b = gtk::Button::with_label(&choice::label(c, &info.subject));
        b.add_css_class("pill");
        match c.as_str() {
            choice::DENY | choice::DECLINE => b.add_css_class("suggested-action"),
            choice::ALLOW_ALWAYS => b.add_css_class("destructive-action"),
            _ => {}
        }
        b.set_sensitive(false);
        let (c, answer, window) = (c.clone(), answer.clone(), window.clone());
        b.connect_clicked(move |_| {
            *answer.borrow_mut() = Some(c.clone());
            window.close();
        });
        buttons.append(&b);
        all.push(b);
    }
    body.append(&buttons);
    let hint = gtk::Label::new(Some(
        "The buttons work once this window has been in front for a moment.",
    ));
    hint.set_wrap(true);
    hint.add_css_class("caption");
    hint.add_css_class("dim-label");
    body.append(&hint);

    // Arm the buttons ARM_DELAY after the window became active; disarm
    // when it is not. A counter drops timers of earlier activations.
    let generation = Rc::new(Cell::new(0u64));
    let arm = {
        let all = all.clone();
        let generation = generation.clone();
        move |active: bool| {
            let g = generation.get() + 1;
            generation.set(g);
            for b in &all {
                b.set_sensitive(false);
            }
            if active {
                let all = all.clone();
                let generation = generation.clone();
                gtk::glib::timeout_add_local_once(ARM_DELAY, move || {
                    if generation.get() == g {
                        for b in &all {
                            b.set_sensitive(true);
                        }
                    }
                });
            }
        }
    };
    window.connect_is_active_notify(move |w| arm(w.is_active()));

    // Escape closes without an answer.
    let keys = gtk::EventControllerKey::new();
    let w = window.clone();
    keys.connect_key_pressed(move |_, key, _, _| {
        if key == gtk::gdk::Key::Escape {
            w.close();
            gtk::glib::Propagation::Stop
        } else {
            gtk::glib::Propagation::Proceed
        }
    });
    window.add_controller(keys);

    let view = adw::ToolbarView::new();
    view.add_top_bar(&adw::HeaderBar::new());
    let scroll = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .propagate_natural_height(true)
        .max_content_height(720)
        .child(&body)
        .build();
    view.set_content(Some(&scroll));
    window.set_content(Some(&view));
    window.present();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_earlier_answers() {
        let info = PromptInfo {
            kind: "access".into(),
            subject: "rg".into(),
            owner: "ssh".into(),
            ..PromptInfo::default()
        };
        let h = |subject: &str, owner: &str| HistoryEntry {
            kind: "access".into(),
            subject: subject.into(),
            owner: owner.into(),
            ..HistoryEntry::default()
        };
        let status = UserStatus {
            history: vec![
                h("rg", "ssh"),
                h("rg", "claude"),
                h("fd", "ssh"),
                h("rg", "ssh"),
            ],
            ..UserStatus::default()
        };
        assert_eq!(related(&info, &status).len(), 2);
        assert!(ago(0).ends_with("days ago"));
    }
}
