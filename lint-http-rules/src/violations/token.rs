// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `token` defects — the character set HTTP is written in.
//!
//! `token = 1*tchar` is the most-read production in this tree: seventy-nine
//! sites ask [`crate::helpers::token::find_invalid_token_char`] whether a value
//! is one, across field names, parameter names, directive names, media type
//! subtypes, transfer codings, method names and every `auth-param` label. One
//! sentence answers all of them, so one pair of ids does — and an operator who
//! does not care about a `_` where a `-` belongs says so once rather than in
//! seventy-nine places.
//!
//! **Two entries, split the way `docs/development.md` mandates.** `tchar` is
//! fifteen punctuation marks, the digits and the letters; everything else fails,
//! and *which* thing failed is the whole of the difference between a sender who
//! typed the wrong character and a value that something did to. A space or a
//! control octet in a name is the second — most often a value that was split,
//! joined or padded on the way — and it defaults a level above.
//!
//! Not here: `token68`, which is a different alphabet under a similar name and
//! lives in [`crate::violations::token68`]. The two share no character class —
//! `token68` admits `/` and `=` and no `!#$%&'*^\`|~` — and a value that is one
//! is not measured against the other anywhere in this crate.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::{defects, ViolationDef};

/// The production and its character set, in the one section that writes both.
/// Every field name, parameter name and directive name in HTTP reaches it.
pub const RFC_9110_5_6_2: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("5.6.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.2",
    note: "Tokens — `token = 1*tchar`, and the fifteen punctuation marks besides the digits and letters that `tchar` admits",
};

defects! {
    /// Whitespace or a control octet where a `token` was written. `error` by
    /// default, the convention every subject with this pair follows: `tchar` is
    /// letters, digits and fifteen visible marks, so neither a space nor an
    /// invisible octet is a character a sender chose to put in a name — it is a
    /// value that was split, joined or padded by something between them.
    ///
    /// It is also the octet that changes what a recipient parses. Field lines,
    /// list members and parameters are all cut apart on whitespace or on a
    /// delimiter beside it, so a space inside a name is read as the end of one
    /// construct and the start of another.
    ///
    // cite(RFC 9110 § 5.6.2): "token = 1*tchar tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA"
    TOKEN_WHITESPACE_OR_CONTROL_FORBIDDEN = {
        id: "token_whitespace_or_control_forbidden",
        title: "Token holds whitespace or a control character",
        message: "",
        default_severity: Severity::Error,
        spec: Some(RFC_9110_5_6_2),
    }

    /// A visible octet outside `tchar` — one of the delimiters § 5.6.2 names,
    /// most often, or an octet at or above %x80 in a name that was written in
    /// something other than US-ASCII. The sender chose the character; what is
    /// wrong is that the production does not admit it.
    ///
    // cite(RFC 9110 § 5.6.2): "Delimiters are chosen from the set of US-ASCII visual characters not allowed in a token (DQUOTE and "(),/:;<=>?@[\]{}")."
    TOKEN_CHARACTER_FORBIDDEN = {
        id: "token_character_forbidden",
        title: "Token holds a character outside tchar",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_9110_5_6_2),
    }
}

/// The defect a character outside `tchar` reports as.
///
/// The reader that found it — [`crate::helpers::token::find_invalid_token_char`]
/// — answers with one `char` and no verdict, because the production draws no
/// distinction inside "not a `tchar`". The catalogue does, so the sort happens
/// here: this is the shape 2.10's bearer token settled, and the reason a coarse
/// helper can feed a catalogue finer than itself.
pub fn token_character(c: char) -> &'static ViolationDef {
    match c.is_whitespace() || c.is_control() {
        true => &TOKEN_WHITESPACE_OR_CONTROL_FORBIDDEN,
        false => &TOKEN_CHARACTER_FORBIDDEN,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The split is by what the character *is*, not by where it was found.
    #[test]
    fn the_invisible_octet_and_the_chosen_one_are_two_ids() {
        for c in [' ', '\t', '\u{1}', '\u{7f}', '\r'] {
            assert_eq!(
                token_character(c).id,
                "token_whitespace_or_control_forbidden",
                "{c:?}",
            );
        }
        // Every one of these is a delimiter § 5.6.2 names, plus an `obs-text`
        // octet that no `tchar` admits either.
        for c in [
            '(', ')', ',', '/', ':', ';', '<', '=', '>', '?', '@', '"', '\u{e9}',
        ] {
            assert_eq!(token_character(c).id, "token_character_forbidden", "{c:?}");
        }
    }

    /// The pair defaults a level apart, which is the convention
    /// `docs/development.md` states and the only reason to have two entries.
    #[test]
    fn the_invisible_octet_outranks_the_chosen_one() {
        assert!(
            TOKEN_WHITESPACE_OR_CONTROL_FORBIDDEN.default_severity
                > TOKEN_CHARACTER_FORBIDDEN.default_severity
        );
    }
}
