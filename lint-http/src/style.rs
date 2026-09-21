// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! How a byte of report gets its colour — and how a citation becomes clickable.
//!
//! A module of the binary, not of the library: nothing here is about HTTP, and
//! nothing that lints wants to know whether stderr is a terminal. It answers
//! one question, which is the shelving rule the rule helpers follow — *what
//! does this run of text look like on the way out*.
//!
//! # The discipline
//!
//! **Severity is the only thing allowed a hue.** Everything else that needs to
//! stand out is bold, and everything that needs to recede is dim. A report
//! where the method, the status, the rule id and the citation each had their
//! own colour would be a paint chart, and the one `error` in it would be no
//! easier to find than it is today in plain text — which is the whole reason
//! for adding colour.
//!
//! Status codes are the single exception, and only because their first digit
//! *is* a severity: a reader already treats `5xx` as red without being told.
//!
//! # Why the 16-colour palette
//!
//! Every style here names an [`AnsiColor`], never an RGB triple. Those sixteen
//! slots are what the user's terminal theme actually remaps, so a report drawn
//! from them lands in whatever palette they chose; a truecolor report imposes
//! ours over theirs and reads as wrong in exactly the themes that were
//! configured most deliberately.

use anstyle::{AnsiColor, Color, Style};
use lint_http::lint::Severity;

/// When to colour.
///
/// The same three words `ls`, `grep`, `cargo` and `git` use, because a person
/// typing `--color=always` into this tool has typed it into those and means the
/// same thing. `Auto` is the default and asks the stream.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum ColorChoice {
    /// Colour when the report's stream is a terminal and no environment
    /// variable says otherwise.
    #[default]
    Auto,
    /// Colour regardless — for `less -R`, and for capturing a report *with* its
    /// escapes.
    Always,
    /// Never colour, whatever the stream is.
    Never,
}

impl ColorChoice {
    /// Resolve against a stream that has already been asked whether it is a
    /// terminal.
    ///
    /// `is_tty` is passed in rather than probed here so the decision is
    /// testable without a terminal, and so the caller names *which* stream it
    /// meant — the text report goes to stderr on a session and to stdout on
    /// `lint-captures`, and asking the wrong one is how escapes end up in a
    /// redirect.
    ///
    /// # The environment
    ///
    /// Two conventions, checked in the order the `NO_COLOR` and `CLICOLOR`
    /// specifications give them, and only under `Auto` — an explicit
    /// `--color=always` on the command line is a person overriding their own
    /// environment, and losing to it would make the flag useless in exactly
    /// the shell that set the variable.
    ///
    /// - `NO_COLOR` set to anything non-empty: no colour.
    /// - `CLICOLOR_FORCE` set to anything non-empty and not `0`: colour, even
    ///   into a pipe.
    ///
    /// `TERM=dumb` is also refused: it is what an editor's embedded shell and
    /// several CI runners report, and those *are* terminals by
    /// [`std::io::IsTerminal`] while rendering escapes as literal garbage.
    pub fn resolve(self, is_tty: bool) -> bool {
        match self {
            ColorChoice::Always => true,
            ColorChoice::Never => false,
            ColorChoice::Auto => {
                if env_set("NO_COLOR") {
                    return false;
                }
                if env_set_and_not_zero("CLICOLOR_FORCE") {
                    return true;
                }
                is_tty && std::env::var_os("TERM").is_none_or(|term| term != "dumb")
            }
        }
    }
}

fn env_set(name: &str) -> bool {
    std::env::var_os(name).is_some_and(|v| !v.is_empty())
}

fn env_set_and_not_zero(name: &str) -> bool {
    std::env::var_os(name).is_some_and(|v| !v.is_empty() && v != "0")
}

/// The palette, and whether it is switched on.
///
/// A `Copy` flag rather than a writer wrapper, because every renderer in the
/// report returns a `String` that a test asserts on. Making the decision a
/// property of the stream would put the styling somewhere no test can read it,
/// and would style the diagnostics and the JSON document too.
#[derive(Clone, Copy, Debug, Default)]
pub struct Styles {
    enabled: bool,
}

impl Styles {
    /// The palette a resolved [`ColorChoice`] selects. `Styles::default()` is
    /// the one that emits nothing, which is what a pipe and every test get.
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    /// Whether anything at all will be emitted. Read by the citation renderer,
    /// which shows a URL when it cannot make a link out of one.
    pub fn is_enabled(self) -> bool {
        self.enabled
    }

    /// The severity's own colour: bold red, yellow, blue.
    ///
    /// Bold on `error` alone. Three colours at one weight read as three peers,
    /// and the point of the column is that one of them is not.
    pub fn severity(self, severity: Severity) -> Style {
        match severity {
            Severity::Error => Style::new()
                .fg_color(Some(Color::Ansi(AnsiColor::Red)))
                .bold(),
            Severity::Warn => Style::new().fg_color(Some(Color::Ansi(AnsiColor::Yellow))),
            Severity::Info => Style::new().fg_color(Some(Color::Ansi(AnsiColor::Blue))),
        }
    }

    /// The name a finding is grepped for, and the method it happened on:
    /// weight, not hue.
    pub fn name(self) -> Style {
        Style::new().bold()
    }

    /// Counts, hosts, hints, and everything present for when you look rather
    /// than for when you don't.
    pub fn dim(self) -> Style {
        Style::new().dimmed()
    }

    /// A citation, which reads as a link because under a capable terminal it
    /// *is* one. Underlined so it still reads as one where it is not.
    ///
    /// Named for the whole word deliberately: the short spelling is the marker
    /// `apycite` scans this tree for, and a method called that would be read as
    /// an unchecked quotation on every line that calls it.
    pub fn citation(self) -> Style {
        Style::new()
            .fg_color(Some(Color::Ansi(AnsiColor::Cyan)))
            .underline()
    }

    /// A response status, coloured by its class — the one place structure gets
    /// a hue, because the first digit already carries the meaning the hue would
    /// add. A transaction that never got a response is dim.
    pub fn status(self, status: Option<u16>) -> Style {
        match status {
            None => self.dim(),
            Some(code) => match code / 100 {
                2 => Style::new().fg_color(Some(Color::Ansi(AnsiColor::Green))),
                3 => Style::new().fg_color(Some(Color::Ansi(AnsiColor::Cyan))),
                4 => Style::new().fg_color(Some(Color::Ansi(AnsiColor::Yellow))),
                5 => Style::new()
                    .fg_color(Some(Color::Ansi(AnsiColor::Red)))
                    .bold(),
                _ => Style::new(),
            },
        }
    }

    /// Wrap `text` in `style`, or hand it back untouched when colour is off.
    ///
    /// The untouched path is not an optimisation: it is what keeps a piped
    /// report byte-identical to the report this tool has always printed, so a
    /// script reading it does not have to learn about escapes.
    pub fn paint(self, style: Style, text: &str) -> String {
        if !self.enabled || text.is_empty() {
            return text.to_string();
        }
        format!("{style}{text}{style:#}")
    }

    /// `text` as a terminal hyperlink to `url` — OSC 8.
    ///
    /// This is what lets a citation print as `RFC 9110 §12.5.3` and still be
    /// clickable, which is the whole of the 58 characters it recovers from
    /// every cited finding. A terminal that does not understand the sequence
    /// ignores it and prints the label, which is why it is safe to emit by
    /// default; one that does understand it opens the section.
    ///
    /// Only under colour, and for the same reason: the escapes must not reach
    /// a file. A caller that has colour switched off shows the URL instead —
    /// see `render_cite`, which is where that choice is made, because it is a
    /// choice about the *report* and not about this sequence.
    ///
    /// `ESC \` terminates rather than `BEL`: both are accepted, the string
    /// terminator is the one the specification gives, and `BEL` is the spelling
    /// that rings a bell in the terminals that do not implement OSC 8.
    pub fn link(self, url: &str, text: &str) -> String {
        if !self.enabled {
            return text.to_string();
        }
        format!("\x1b]8;;{url}\x1b\\{text}\x1b]8;;\x1b\\")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The plain palette is a pass-through, byte for byte. Every existing test
    /// that asserts on report text depends on this, and so does every script.
    #[test]
    fn a_plain_palette_emits_no_escapes() {
        let styles = Styles::default();
        assert_eq!(
            styles.paint(styles.severity(Severity::Error), "error"),
            "error"
        );
        assert_eq!(styles.link("https://example.com/", "RFC 9110"), "RFC 9110");
    }

    /// And an enabled one wraps, then resets.
    #[test]
    fn an_enabled_palette_wraps_and_resets() {
        let styles = Styles::new(true);
        let painted = styles.paint(styles.name(), "host_header");
        assert!(painted.starts_with('\x1b'), "{painted:?}");
        assert!(painted.contains("host_header"), "{painted:?}");
        assert!(painted.ends_with("\x1b[0m"), "{painted:?}");
    }

    /// Empty text stays empty: a zero-width run of escapes is invisible on
    /// screen and still costs a column to anything measuring the line.
    #[test]
    fn empty_text_is_never_painted() {
        assert_eq!(Styles::new(true).paint(Style::new().bold(), ""), "");
    }

    /// The hyperlink carries the URL and shows only the label.
    #[test]
    fn a_link_hides_its_url_behind_the_label() {
        let out = Styles::new(true).link("https://www.rfc-editor.org/rfc/rfc9110.html", "RFC 9110");
        assert_eq!(
            out,
            "\x1b]8;;https://www.rfc-editor.org/rfc/rfc9110.html\x1b\\RFC 9110\x1b]8;;\x1b\\"
        );
    }

    /// `always` and `never` ignore the stream; `auto` asks it.
    #[test]
    fn an_explicit_choice_ignores_the_stream() {
        assert!(ColorChoice::Always.resolve(false));
        assert!(!ColorChoice::Never.resolve(true));
    }

    /// Status classes get the colours their first digit already implies, and
    /// nothing else does.
    #[test]
    fn status_colour_follows_the_class() {
        let styles = Styles::new(true);
        for (status, colour) in [
            (Some(200), AnsiColor::Green),
            (Some(301), AnsiColor::Cyan),
            (Some(404), AnsiColor::Yellow),
            (Some(503), AnsiColor::Red),
        ] {
            assert_eq!(
                styles.status(status).get_fg_color(),
                Some(Color::Ansi(colour)),
                "{status:?}"
            );
        }
        // A transaction with no response is dim, not coloured.
        assert_eq!(styles.status(None).get_fg_color(), None);
    }
}
