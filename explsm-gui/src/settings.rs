//! `explsm-gui settings`: the explsm Settings window.
//!
//! Four pages in a view stack: the security picture (and choosing it), the
//! grants given through prompts (and revoking them), the history of answers,
//! and the apps of the policy. Everything is read from explsmd (or the
//! preview file) off the main thread, and rebuilt from scratch on each load.

use std::{cell::RefCell, rc::Rc};

use adw::prelude::*;
use explsm_ipc::{
    HistoryEntry, SECRET_ICONS, SECRET_PHRASE_MAX, SavedClaim, SavedGrant, Secret, TempGrantStatus,
    UserApp, UserStatus, choice,
};

use crate::{Source, daemon, prompt::ago, secret};

/// The window's parts that loading and the actions need.
struct Ui {
    source: Source,
    window: adw::ApplicationWindow,
    toasts: adw::ToastOverlay,
    /// `loading`, `error` or `content`.
    outer: gtk::Stack,
    error: adw::StatusPage,
    stack: adw::ViewStack,
    /// The pages currently in `stack`, to remove on reload.
    pages: RefCell<Vec<gtk::Widget>>,
}

type UiRef = Rc<Ui>;

pub fn run(source: Source) {
    let app = adw::Application::builder()
        .application_id("org.explsm.Settings")
        // Unique applications forward to whoever owns the name on the
        // session bus first, which any program can.
        .flags(gtk::gio::ApplicationFlags::NON_UNIQUE)
        .build();
    app.connect_activate(move |app| build(app, source.clone()));
    app.run_with_args::<&str>(&[]);
}

fn build(app: &adw::Application, source: Source) {
    let window = adw::ApplicationWindow::builder()
        .application(app)
        .title("explsm Settings")
        .default_width(720)
        .default_height(640)
        .width_request(360)
        .height_request(300)
        .build();

    let stack = adw::ViewStack::new();
    let switcher = adw::ViewSwitcher::builder()
        .stack(&stack)
        .policy(adw::ViewSwitcherPolicy::Wide)
        .build();
    let header = adw::HeaderBar::new();
    header.set_title_widget(Some(&switcher));
    let refresh = gtk::Button::from_icon_name("view-refresh-symbolic");
    refresh.set_tooltip_text(Some("Reload"));
    header.pack_start(&refresh);

    let bar = adw::ViewSwitcherBar::builder().stack(&stack).build();

    let loading = adw::StatusPage::builder().title("Loading…").build();
    let spinner = gtk::Spinner::new();
    spinner.set_spinning(true);
    spinner.set_size_request(32, 32);
    loading.set_child(Some(&spinner));
    let error = adw::StatusPage::builder()
        .icon_name("dialog-error-symbolic")
        .title("Can't reach explsm")
        .build();

    let outer = gtk::Stack::new();
    outer.add_named(&loading, Some("loading"));
    outer.add_named(&error, Some("error"));
    outer.add_named(&stack, Some("content"));

    let toasts = adw::ToastOverlay::new();
    toasts.set_child(Some(&outer));

    let view = adw::ToolbarView::new();
    view.add_top_bar(&header);
    view.set_content(Some(&toasts));
    view.add_bottom_bar(&bar);
    window.set_content(Some(&view));

    // Show the bottom switcher bar instead of the header one when narrow.
    let bp = adw::Breakpoint::new(adw::BreakpointCondition::new_length(
        adw::BreakpointConditionLengthType::MaxWidth,
        550.0,
        adw::LengthUnit::Sp,
    ));
    bp.add_setter(&bar, "reveal", Some(&true.to_value()));
    bp.add_setter(&header, "show-title", Some(&false.to_value()));
    window.add_breakpoint(bp);

    let ui = Rc::new(Ui {
        source,
        window: window.clone(),
        toasts,
        outer,
        error,
        stack,
        pages: RefCell::default(),
    });
    let ui2 = ui.clone();
    refresh.connect_clicked(move |_| reload(&ui2));
    reload(&ui);
    window.present();
}

/// Reads the status again and rebuilds every page.
fn reload(ui: &UiRef) {
    ui.outer.set_visible_child_name("loading");
    let ui = ui.clone();
    gtk::glib::spawn_future_local(async move {
        let source = ui.source.clone();
        let result = gtk::gio::spawn_blocking(move || source.user_status())
            .await
            .unwrap_or_else(|_| Err("reading the status failed".into()));
        match result {
            Ok(status) => {
                fill(&ui, &status);
                ui.outer.set_visible_child_name("content");
            }
            Err(e) => {
                ui.error
                    .set_description(Some(&gtk::glib::markup_escape_text(&e)));
                ui.outer.set_visible_child_name("error");
            }
        }
    });
}

fn fill(ui: &UiRef, status: &UserStatus) {
    let visible = ui.stack.visible_child_name();
    for page in ui.pages.take() {
        ui.stack.remove(&page);
    }
    let pages = [
        (
            "picture",
            "Picture",
            "security-high-symbolic",
            picture_page(ui, status),
        ),
        (
            "grants",
            "Grants",
            "channel-secure-symbolic",
            grants_page(ui, status),
        ),
        (
            "history",
            "History",
            "document-open-recent-symbolic",
            history_page(&status.history),
        ),
        (
            "apps",
            "Apps",
            "application-x-executable-symbolic",
            apps_page(status),
        ),
    ];
    let mut kept = Vec::new();
    for (name, title, icon, page) in pages {
        ui.stack
            .add_titled_with_icon(&page, Some(name), title, icon);
        kept.push(page.upcast());
    }
    *ui.pages.borrow_mut() = kept;
    if let Some(name) = visible {
        ui.stack.set_visible_child_name(&name);
    }
}

fn toast(ui: &UiRef, text: &str) {
    ui.toasts.add_toast(adw::Toast::new(text));
}

/// Runs `call` off the main thread, toasts `done` or the error, and reloads.
fn act<T: Send + 'static>(
    ui: &UiRef,
    done: &'static str,
    call: impl FnOnce() -> Result<T, String> + Send + 'static,
) {
    if matches!(ui.source, Source::Preview(_)) {
        toast(ui, "Preview: nothing changed");
        return;
    }
    let ui = ui.clone();
    gtk::glib::spawn_future_local(async move {
        let result = gtk::gio::spawn_blocking(call)
            .await
            .unwrap_or_else(|_| Err("the call failed".into()));
        match result {
            Ok(_) => toast(&ui, done),
            Err(e) => toast(&ui, &e),
        }
        reload(&ui);
    });
}

/// An action row that shows its text as is.
fn row(title: &str, subtitle: &str) -> adw::ActionRow {
    let row = adw::ActionRow::new();
    row.set_use_markup(false);
    row.set_title(title);
    if !subtitle.is_empty() {
        row.set_subtitle(subtitle);
    }
    row
}

/// A row whose subtitle holds paths, which the user may want to copy.
fn path_row(title: &str, subtitle: &str) -> adw::ActionRow {
    let r = row(title, subtitle);
    r.set_subtitle_selectable(true);
    r
}

fn none_row(text: &str) -> adw::ActionRow {
    let r = row(text, "");
    r.add_css_class("dim-label");
    r
}

fn group(title: &str, description: &str) -> adw::PreferencesGroup {
    let g = adw::PreferencesGroup::new();
    if !title.is_empty() {
        g.set_title(title);
    }
    if !description.is_empty() {
        // Descriptions are markup.
        g.set_description(Some(&gtk::glib::markup_escape_text(description)));
    }
    g
}

fn revoke_button() -> gtk::Button {
    let b = gtk::Button::with_label("Revoke");
    b.add_css_class("flat");
    b.set_valign(gtk::Align::Center);
    b
}

// ---- Security picture ----

fn picture_page(ui: &UiRef, status: &UserStatus) -> adw::PreferencesPage {
    let page = adw::PreferencesPage::new();
    let current = group("", "");
    current.add(&secret::widget(&Ok(status.secret.clone())));
    page.add(&current);

    let choose = group(
        "Choose a picture",
        "explsm shows this picture and phrase in every prompt. Other programs can't \
         read it, so a prompt without it is fake: answer nothing and close it. \
         Choose something you will recognise.",
    );
    let flow = gtk::FlowBox::builder()
        .selection_mode(gtk::SelectionMode::Single)
        .max_children_per_line(8)
        .min_children_per_line(4)
        .homogeneous(true)
        .row_spacing(6)
        .column_spacing(6)
        .margin_bottom(12)
        .build();
    for icon in SECRET_ICONS {
        let image = gtk::Image::from_icon_name(icon);
        image.set_pixel_size(48);
        let child = gtk::FlowBoxChild::new();
        child.set_child(Some(&image));
        child.set_tooltip_text(Some(icon));
        flow.append(&child);
        if *icon == status.secret.icon {
            flow.select_child(&child);
        }
    }
    choose.add(&flow);

    let list = gtk::ListBox::new();
    list.add_css_class("boxed-list");
    list.set_selection_mode(gtk::SelectionMode::None);
    let phrase = adw::EntryRow::builder().title("Phrase").build();
    phrase.set_text(&status.secret.phrase);
    if let Some(text) = phrase.delegate().and_downcast::<gtk::Text>() {
        text.set_max_length(SECRET_PHRASE_MAX as i32);
    }
    list.append(&phrase);
    choose.add(&list);

    let save = gtk::Button::with_label("Save");
    save.add_css_class("suggested-action");
    save.add_css_class("pill");
    save.set_halign(gtk::Align::Center);
    save.set_margin_top(12);
    choose.add(&save);
    page.add(&choose);

    let ui = ui.clone();
    save.connect_clicked(move |_| {
        let icon = flow
            .selected_children()
            .first()
            .and_then(|c| SECRET_ICONS.get(c.index() as usize))
            .map(|s| s.to_string());
        let Some(icon) = icon else {
            toast(&ui, "Choose a picture first");
            return;
        };
        let secret = Secret {
            icon,
            phrase: phrase.text().to_string(),
        };
        if let Err(e) = secret.check() {
            toast(&ui, &e);
            return;
        }
        if matches!(ui.source, Source::Preview(_)) {
            toast(&ui, "Preview: not saved");
            return;
        }
        act(&ui, "Picture saved", move || daemon::set_secret(secret));
    });
    page
}

// ---- Grants ----

fn grants_page(ui: &UiRef, status: &UserStatus) -> adw::PreferencesPage {
    let page = adw::PreferencesPage::new();
    page.add(&temp_group(ui, &status.temp_grants));
    page.add(&saved_group(ui, &status.saved_grants));
    page.add(&claims_group(&status.saved_claims));
    page
}

fn temp_group(ui: &UiRef, grants: &[TempGrantStatus]) -> adw::PreferencesGroup {
    let g = group("Until the program exits or you log out", "");
    if grants.is_empty() {
        g.add(&none_row("None"));
    }
    for t in grants {
        let until = if t.lifetime == "process" {
            "the process exits"
        } else {
            "logout"
        };
        let r = row(
            &format!("{} → {}", t.subject, t.owner),
            &format!("{} · until {until}", t.perms.join(", ")),
        );
        let b = revoke_button();
        let (ui, subject, owner) = (ui.clone(), t.subject.clone(), t.owner.clone());
        b.connect_clicked(move |_| {
            let (s, o) = (subject.clone(), owner.clone());
            act(&ui, "Grant revoked", move || daemon::revoke_temp(s, o));
        });
        r.add_suffix(&b);
        g.add(&r);
    }
    g
}

fn saved_group(ui: &UiRef, grants: &[SavedGrant]) -> adw::PreferencesGroup {
    let g = group("Always", "");
    if grants.is_empty() {
        g.add(&none_row("None"));
    }
    for s in grants {
        let mut sub = s.perms.join(", ");
        if !s.exe.is_empty() {
            sub = format!("{sub} · {}", s.exe);
        }
        let r = path_row(&format!("{} → {}", s.subject, s.owner), &sub);
        let b = revoke_button();
        let (ui, subject, owner) = (ui.clone(), s.subject.clone(), s.owner.clone());
        b.connect_clicked(move |_| confirm_revoke(&ui, subject.clone(), owner.clone()));
        r.add_suffix(&b);
        g.add(&r);
    }
    g
}

#[allow(deprecated)]
fn confirm_revoke(ui: &UiRef, subject: String, owner: String) {
    let dialog = adw::MessageDialog::new(
        Some(&ui.window),
        Some("Revoke this grant?"),
        Some(&format!(
            "{subject} will no longer be able to use the data of {owner} without asking."
        )),
    );
    dialog.add_responses(&[("cancel", "Cancel"), ("revoke", "Revoke")]);
    dialog.set_response_appearance("revoke", adw::ResponseAppearance::Destructive);
    dialog.set_default_response(Some("cancel"));
    dialog.set_close_response("cancel");
    let ui = ui.clone();
    dialog.connect_response(Some("revoke"), move |_, _| {
        let (s, o) = (subject.clone(), owner.clone());
        act(&ui, "Grant revoked", move || daemon::revoke_saved(s, o));
    });
    dialog.present();
}

fn claims_group(claims: &[SavedClaim]) -> adw::PreferencesGroup {
    let g = group(
        "Protected folders you added",
        "Only an administrator can take these back, by editing /etc/explsm/claims.d.",
    );
    if claims.is_empty() {
        g.add(&none_row("None"));
    }
    for c in claims {
        g.add(&path_row(&c.app, &c.path));
    }
    g
}

// ---- History ----

fn history_page(history: &[HistoryEntry]) -> adw::PreferencesPage {
    let page = adw::PreferencesPage::new();
    let g = group("", "Answers since explsmd started (newest first).");
    if history.is_empty() {
        g.add(&none_row("No answers yet"));
    }
    for h in history {
        g.add(&history_row(h));
    }
    page.add(&g);
    page
}

fn history_row(h: &HistoryEntry) -> adw::ActionRow {
    let what = if h.kind == explsm_ipc::PROMPT_CLAIM {
        format!("folder {}", h.path)
    } else {
        format!("{} → {}", h.subject, h.owner)
    };
    let title = format!("{} — {what}", choice::label(&h.answer, &h.subject));
    let perms = h.perms.join(", ");
    let parts = [ago(h.time), h.process.clone(), perms, h.path.clone()];
    let subtitle = parts
        .iter()
        .filter(|p| !p.is_empty())
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(" · ");
    path_row(&title, &subtitle)
}

// ---- Apps ----

fn apps_page(status: &UserStatus) -> adw::PreferencesPage {
    let page = adw::PreferencesPage::new();
    let mut description = format!(
        "Policy generation {}, loaded {}.",
        status.generation,
        ago(status.loaded_at)
    );
    if !status.agent {
        description.push_str(
            "\nexplsm-agent is not running in your session: you will not be asked about denials.",
        );
    }
    let g = group("Apps", &description);
    if status.apps.is_empty() {
        g.add(&none_row("None"));
    }
    for a in &status.apps {
        g.add(&app_row(a));
    }
    page.add(&g);
    page
}

fn app_row(a: &UserApp) -> adw::ExpanderRow {
    let r = adw::ExpanderRow::new();
    r.set_use_markup(false);
    r.set_title(&a.name);
    r.set_subtitle(&a.mode);
    for exe in &a.exes {
        r.add_row(&path_row("Program", exe));
    }
    for root in &a.roots {
        r.add_row(&path_row("Data", root));
    }
    r
}
