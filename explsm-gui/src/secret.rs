//! The user's security picture, as every explsm window shows it.

use adw::prelude::*;
use explsm_ipc::Secret;

/// A box with the picture and phrase; or, when there is none or it could
/// not be read, a warning saying so.
pub fn widget(secret: &Result<Secret, String>) -> gtk::Widget {
    let row = gtk::Box::new(gtk::Orientation::Horizontal, 12);
    row.add_css_class("card");
    row.set_margin_bottom(6);
    let inner = gtk::Box::new(gtk::Orientation::Horizontal, 12);
    inner.set_margin_top(12);
    inner.set_margin_bottom(12);
    inner.set_margin_start(12);
    inner.set_margin_end(12);
    row.append(&inner);
    let text = gtk::Box::new(gtk::Orientation::Vertical, 2);
    text.set_valign(gtk::Align::Center);
    let caption = gtk::Label::new(None);
    caption.set_xalign(0.0);
    caption.set_wrap(true);
    caption.add_css_class("caption");
    let phrase = gtk::Label::new(None);
    phrase.set_xalign(0.0);
    phrase.set_wrap(true);
    phrase.add_css_class("title-3");
    match secret {
        Ok(s) if s.is_set() => {
            let image = gtk::Image::from_icon_name(&s.icon);
            image.set_pixel_size(48);
            inner.append(&image);
            caption.set_text("Your explsm picture. If it is missing or wrong, this window is not from explsm: answer nothing.");
            phrase.set_text(&s.phrase);
        }
        Ok(_) => {
            let image = gtk::Image::from_icon_name("dialog-warning-symbolic");
            image.set_pixel_size(48);
            inner.append(&image);
            phrase.set_text("No security picture yet");
            caption.set_text(
                "Choose one in explsm Settings, so you can tell explsm's windows from fakes.",
            );
            row.add_css_class("warning");
        }
        Err(e) => {
            let image = gtk::Image::from_icon_name("dialog-warning-symbolic");
            image.set_pixel_size(48);
            inner.append(&image);
            phrase.set_text("Your security picture could not be loaded");
            caption.set_text(&format!("{e}. Treat this window with suspicion."));
            row.add_css_class("error");
        }
    }
    text.append(&phrase);
    text.append(&caption);
    inner.append(&text);
    row.upcast()
}
