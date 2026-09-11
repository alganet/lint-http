// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `comment` defects — the parenthesised text three fields admit.
//!
//! `Server`, `User-Agent` and `Via` all reach § 5.6.5's construct by naming it
//! in their own grammar and none of them restates it, so a comment that never
//! closes is the same defect wherever it was written. Two entries here and a
//! third borrowed: the escape inside a comment is `quoted-pair`'s, which is a
//! subject of its own precisely because this construct and `quoted-string`
//! share it.
//!
//! The nesting is the production's own: `comment = "(" *( ctext / quoted-pair
//! / comment ) ")"`, a rule that appears inside its own definition. That is why
//! an unterminated comment is one finding however many parentheses were opened
//! — the depth is not a count of delimiters to report, it is the reader
//! following the recursion.

use crate::helpers::comment::CommentDefect;
use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::quoted_pair::QUOTED_PAIR_MALFORMED;
use crate::violations::{defects, ViolationDef};

/// The construct, its character class and its self-reference — one section for
/// both entries, because § 5.6.5 is the whole of `comment`.
pub const RFC_9110_5_6_5: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("5.6.5"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.5",
    note: "Comments — `comment = \"(\" *( ctext / quoted-pair / comment ) \")\"`, the `ctext` class, and the self-reference that makes a comment nestable",
};

defects! {
    /// A comment that never closes: the value ended with a parenthesis still
    /// open.
    ///
    /// The construct *is* its two parentheses and what they enclose, so a
    /// value missing the closing one has no comment in it rather than a bad
    /// one — the same shape `quoted_string_delimiter_missing` and
    /// `etag_delimiter_missing` have, at the third construct in this catalogue
    /// defined by what wraps it.
    ///
    // cite(RFC 9110 § 5.6.5): "comment        = "(" *( ctext / quoted-pair / comment ) ")""
    COMMENT_DELIMITER_MISSING = {
        id: "comment_delimiter_missing",
        title: "Comment is never closed",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_5_6_5],
    }

    /// An octet `ctext` does not admit — a control character, DEL — where the
    /// parentheses and the backslash are the construct's own and are read
    /// before this.
    ///
    /// `ctext` is wide: HTAB, SP, most of the visible range and every octet at
    /// or above %x80, since a comment is where a product name in someone's
    /// language ends up. What it refuses is what a field value cannot carry
    /// anyway, which is why this entry is `warn` and not the `error` its
    /// namesakes in the `token` and `quoted_string` subjects default to: those
    /// two report an octet that changes how a *recipient* cuts the value up,
    /// and inside a comment nothing is cut on.
    ///
    // cite(RFC 9110 § 5.6.5): "ctext          = HTAB / SP / %x21-27 / %x2A-5B / %x5D-7E / obs-text"
    COMMENT_CHARACTER_FORBIDDEN = {
        id: "comment_character_forbidden",
        title: "Comment holds a character ctext does not admit",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_5_6_5],
    }
}

/// The defect a parsed [`CommentDefect`] reports as.
///
/// Two of the four arms leave this subject: an escape inside a comment is
/// § 5.6.4's `quoted-pair`, which `quoted-string` reads too and which is why
/// that entry is a subject of its own rather than either construct's.
pub fn comment_defect(defect: CommentDefect) -> &'static ViolationDef {
    match defect {
        CommentDefect::TrailingEscape | CommentDefect::BadQuotedPair(_) => &QUOTED_PAIR_MALFORMED,
        CommentDefect::BadCharacter(_) => &COMMENT_CHARACTER_FORBIDDEN,
        CommentDefect::Unterminated => &COMMENT_DELIMITER_MISSING,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The mapping, spelled out — including the two arms that answer with
    /// another subject's entry, which is a decision and not an oversight.
    #[test]
    fn each_comment_defect_maps_to_its_own_id() {
        for (defect, id) in [
            (CommentDefect::Unterminated, "comment_delimiter_missing"),
            (
                CommentDefect::BadCharacter(0x00),
                "comment_character_forbidden",
            ),
            (CommentDefect::TrailingEscape, "quoted_pair_malformed"),
            (CommentDefect::BadQuotedPair(0x01), "quoted_pair_malformed"),
        ] {
            assert_eq!(comment_defect(defect).id, id, "{defect:?}");
        }
    }
}
