// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Quoted-string defects — the ways the production between two DQUOTEs is not
//! one.
//!
//! One grammar, everywhere. `quoted-string` is RFC 9110 § 5.6.4's, and this
//! crate reads one out of a `WWW-Authenticate` `auth-param`, a
//! `Cache-Control` directive argument, a `Content-Disposition` `filename`, a
//! `Warning` text, a `TE` parameter and a `Strict-Transport-Security` value —
//! seven rules and three helpers so far, all through
//! [`crate::helpers::quoted_string`]. So the defect belongs here rather than to
//! whichever field noticed it, and an operator who does not care about an
//! unescaped DQUOTE says so once.
//!
//! The interior is where the reading happens, and the messages are written
//! against the whole value: a caller embeds them after naming the parameter or
//! the directive the value belonged to.

use crate::helpers::quoted_string::QuotedStringDefect;
use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::quoted_pair::QUOTED_PAIR_MALFORMED;
use crate::violations::{defects, ViolationDef};

/// The production, its interior class and its escape — one section behind all
/// four entries, because § 5.6.4 is where the whole of `quoted-string` is
/// written.
pub const RFC_9110_5_6_4: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("5.6.4"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.4",
    note: "`quoted-string = DQUOTE *( qdtext / quoted-pair ) DQUOTE` — the two delimiters, the class between them, and the backslash escape",
};

defects! {
    /// No opening DQUOTE, or nothing closing it. The production *is* its two
    /// delimiters and what they enclose, so a value missing one of them has no
    /// interior to examine rather than a bad one — which is why this is the one
    /// defect answered before the walk starts.
    ///
    // cite(RFC 9110 § 5.6.4): "quoted-string  = DQUOTE *( qdtext / quoted-pair ) DQUOTE"
    QUOTED_STRING_DELIMITER_MISSING = {
        id: "quoted_string_delimiter_missing",
        title: "Quoted-string is missing one of its DQUOTEs",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_5_6_4],
    }

    /// A DQUOTE inside the interior that no backslash introduced. The interior
    /// runs between the production's two delimiters, so a third one closes the
    /// value early and everything after it derives from nothing — which is why
    /// this is the defect most likely to change what a recipient reads rather
    /// than merely to be refused.
    ///
    // cite(RFC 9110 § 5.6.4): "qdtext         = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text"
    QUOTED_STRING_QUOTE_ESCAPE_MISSING = {
        id: "quoted_string_quote_escape_missing",
        title: "Quoted-string holds an unescaped DQUOTE",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_5_6_4],
    }

    /// A control octet `qdtext` excludes — HTAB is not one of them, since it is
    /// in the class by name. `error` by default, for the reason every other
    /// subject's invisible defect is: `qdtext` runs from %x20 up, so a control
    /// octet in a quoted value is something that happened to it rather than
    /// something a sender chose, and it is in the class a field value is split
    /// with.
    ///
    // cite(RFC 9110 § 5.6.4): "qdtext         = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text"
    QUOTED_STRING_CONTROL_CHARACTER_FORBIDDEN = {
        id: "quoted_string_control_character_forbidden",
        title: "Quoted-string holds a control character",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_5_6_4],
    }
}

/// The defect a parsed [`QuotedStringDefect`] reports as.
pub fn quoted_string_defect(defect: QuotedStringDefect) -> &'static ViolationDef {
    match defect {
        QuotedStringDefect::NotQuoted => &QUOTED_STRING_DELIMITER_MISSING,
        QuotedStringDefect::BadQuotedPair | QuotedStringDefect::TrailingEscape => {
            &QUOTED_PAIR_MALFORMED
        }
        QuotedStringDefect::UnescapedQuote => &QUOTED_STRING_QUOTE_ESCAPE_MISSING,
        QuotedStringDefect::ControlCharacter => &QUOTED_STRING_CONTROL_CHARACTER_FORBIDDEN,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The mapping, spelled out — including the place two variants answer with
    /// one def, which is a decision and not an oversight.
    #[test]
    fn each_quoted_string_defect_maps_to_its_own_id() {
        for (defect, id) in [
            (
                QuotedStringDefect::NotQuoted,
                "quoted_string_delimiter_missing",
            ),
            (QuotedStringDefect::BadQuotedPair, "quoted_pair_malformed"),
            (QuotedStringDefect::TrailingEscape, "quoted_pair_malformed"),
            (
                QuotedStringDefect::UnescapedQuote,
                "quoted_string_quote_escape_missing",
            ),
            (
                QuotedStringDefect::ControlCharacter,
                "quoted_string_control_character_forbidden",
            ),
        ] {
            assert_eq!(quoted_string_defect(defect).id, id);
        }
    }
}
