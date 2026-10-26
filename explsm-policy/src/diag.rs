//! Diagnostics with source spans, rendered by ariadne.

use std::fmt;

use ariadne::{Color, Config, Label, Report, ReportKind};

use crate::{Sources, Span};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
}

#[derive(Clone, Debug)]
pub struct Diagnostic {
    pub severity: Severity,
    pub span: Span,
    pub message: String,
    /// Text at the primary span; the message is used when there is none.
    pub label: Option<String>,
    /// More spans, e.g. an earlier definition.
    pub secondary: Vec<(Span, String)>,
    pub note: Option<String>,
}

impl Diagnostic {
    pub fn error(span: Span, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Error,
            span,
            message: message.into(),
            label: None,
            secondary: Vec::new(),
            note: None,
        }
    }

    pub fn warning(span: Span, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warning,
            ..Self::error(span, message)
        }
    }

    pub fn label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    pub fn also(mut self, span: Span, label: impl Into<String>) -> Self {
        self.secondary.push((span, label.into()));
        self
    }

    pub fn note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }
}

/// Render diagnostics against their sources, as ariadne reports.
pub fn render(diags: &[Diagnostic], sources: &Sources, color: bool) -> String {
    let mut cache = ariadne::sources(
        sources
            .0
            .iter()
            .map(|s| (s.name.clone(), s.text.clone()))
            .collect::<Vec<_>>(),
    );
    let name = |span: Span| {
        sources
            .0
            .get(span.file)
            .map_or_else(|| "<policy>".to_string(), |s| s.name.clone())
    };
    let mut out = Vec::new();
    for d in diags {
        let (kind, colour) = match d.severity {
            Severity::Error => (ReportKind::Error, Color::Red),
            Severity::Warning => (ReportKind::Warning, Color::Yellow),
        };
        let primary = (name(d.span), d.span.start..d.span.end);
        let mut report = Report::build(kind, primary.clone())
            .with_config(Config::default().with_color(color))
            .with_message(&d.message)
            .with_label(
                Label::new(primary)
                    .with_message(d.label.as_deref().unwrap_or(&d.message))
                    .with_color(colour),
            );
        for (span, label) in &d.secondary {
            report = report.with_label(
                Label::new((name(*span), span.start..span.end))
                    .with_message(label)
                    .with_color(Color::Blue),
            );
        }
        if let Some(note) = &d.note {
            report = report.with_note(note);
        }
        // Writing into a Vec only fails if a span is out of range, which
        // would be a bug; fall back to the plain message.
        if report.finish().write(&mut cache, &mut out).is_err() {
            out.extend(format!("{d}\n").bytes());
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
        };
        write!(f, "{kind}: {}", self.message)
    }
}
