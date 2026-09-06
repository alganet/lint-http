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

use crate::helpers::media_type::MediaTypeDefect;
use crate::helpers::word::WordDefect;
use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::parameter::{PARAMETER_EQUALS_MISSING, PARAMETER_VALUE_EMPTY};
use crate::violations::quoted_string::quoted_string_defect;
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

    /// A token with no characters in it: the `=` of a parameter with nothing
    /// before it, a directive that is only its argument, a media type with an
    /// empty subtype. `token = 1*tchar` has a one-character floor, so this is
    /// arithmetic on the production and not a per-field tolerance.
    ///
    /// Not to be confused with the *value* half of `word = token /
    /// quoted-string` being empty, which is a verdict each field makes for
    /// itself — [`word_defect`] answers `None` there, and this def is not its
    /// substitute.
    ///
    // cite(RFC 9110 § 5.6.2): "token = 1*tchar tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA"
    TOKEN_EMPTY = {
        id: "token_empty",
        title: "Token is written with no characters in it",
        message: "",
        default_severity: Severity::Warn,
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

/// The defect a [`WordDefect`] reports as — `None` when the answer is the
/// caller's rather than the catalogue's.
///
/// `( token / quoted-string )` is an alternation and owns no defect of its
/// own: a value that failed did so at one of the two halves, and each half has
/// a subject. This lives here rather than in a `word` file because a value that
/// does not open with a DQUOTE is a `token` by elimination, which is the same
/// reasoning [`crate::helpers::word::token_or_quoted_string`] uses to pick the
/// alternative — and the quoted half delegates, the way every nested mapping in
/// this catalogue does.
///
/// [`WordDefect::Empty`] is the `None`, and deliberately so. Neither
/// alternative derives the empty string, which is arithmetic — but what a
/// *field* does about a value that is empty is a per-field verdict, and
/// `helpers::word` records that six callers had answered it in four different
/// ways. Two of them tolerate it outright. A def here would be this catalogue
/// deciding a question its callers have not agreed on.
pub fn word_defect(defect: WordDefect) -> Option<&'static ViolationDef> {
    match defect {
        WordDefect::Empty => None,
        WordDefect::NotToken(c) => Some(token_character(c)),
        WordDefect::NotQuotedString(defect) => Some(quoted_string_defect(defect)),
    }
}

/// The defect a [`MediaTypeDefect`] reports as.
///
/// `media-type` owns none of these. A type and a subtype are `token`s, a
/// parameter name is a `token`, a parameter value is `( token / quoted-string
/// )`, and the `=` between a parameter's halves is § 5.6.6's — so a rule
/// reading a media type reports the same ids as a rule reading any other field
/// written out of the same three productions, which is the whole of why the
/// reader was typed.
///
/// It lives here, beside the subject of the first thing the reader measures,
/// for the reason `read_member`'s mapping lives beside the list's: a mapping fn
/// whose every answer belongs to another subject has no file of its own, and a
/// `violations/media_type.rs` holding nothing but this function would carry no
/// `// cite` for the citation ratchet to find. The next reader will look for a
/// file named after the helper, which is why this paragraph is here.
///
/// The empty parameter value is the one answer that is neither production's.
/// [`word_defect`] returns `None` there, because what a *field* does about a
/// value that is empty is the field's own verdict — and for a `parameter` the
/// fields agreed before this catalogue existed, which is what
/// [`PARAMETER_VALUE_EMPTY`] records.
pub fn media_type_defect(defect: MediaTypeDefect<'_>) -> &'static ViolationDef {
    match defect {
        MediaTypeDefect::TypeCharacter(c) | MediaTypeDefect::SubtypeCharacter(c) => {
            token_character(c)
        }
        MediaTypeDefect::ParameterMissingEquals(_) => &PARAMETER_EQUALS_MISSING,
        MediaTypeDefect::ParameterNameEmpty => &TOKEN_EMPTY,
        MediaTypeDefect::ParameterNameCharacter { character, .. } => token_character(character),
        MediaTypeDefect::ParameterValue { defect, .. } => {
            word_defect(defect).unwrap_or(&PARAMETER_VALUE_EMPTY)
        }
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

    /// The alternation answers with the half that failed, and with nothing at
    /// all for the empty value — which is the one verdict this catalogue leaves
    /// to the field.
    #[test]
    fn a_word_answers_with_the_half_that_failed() {
        use crate::helpers::quoted_string::QuotedStringDefect;

        assert_eq!(word_defect(WordDefect::Empty).map(|d| d.id), None);
        assert_eq!(
            word_defect(WordDefect::NotToken('@')).map(|d| d.id),
            Some("token_character_forbidden"),
        );
        assert_eq!(
            word_defect(WordDefect::NotToken(' ')).map(|d| d.id),
            Some("token_whitespace_or_control_forbidden"),
        );
        assert_eq!(
            word_defect(WordDefect::NotQuotedString(QuotedStringDefect::NotQuoted)).map(|d| d.id),
            Some("quoted_string_delimiter_missing"),
        );
    }

    /// A media type's parts answer with three subjects' ids and none of its
    /// own, which is the claim the typed reader was written to make. The rows
    /// are the whole of `media_type_parts_defect`'s fan-out.
    #[test]
    fn a_media_types_parts_report_the_productions_they_are_written_in() {
        use crate::helpers::quoted_string::QuotedStringDefect;

        let value = |defect| MediaTypeDefect::ParameterValue {
            name: "charset",
            value: "",
            defect,
        };
        for (defect, id) in [
            (
                MediaTypeDefect::TypeCharacter('@'),
                "token_character_forbidden",
            ),
            (
                MediaTypeDefect::SubtypeCharacter(' '),
                "token_whitespace_or_control_forbidden",
            ),
            (
                MediaTypeDefect::ParameterMissingEquals("badparam"),
                "parameter_equals_missing",
            ),
            (MediaTypeDefect::ParameterNameEmpty, "token_empty"),
            (
                MediaTypeDefect::ParameterNameCharacter {
                    name: "ba@d",
                    character: '@',
                },
                "token_character_forbidden",
            ),
            (value(WordDefect::Empty), "parameter_value_empty"),
            (
                value(WordDefect::NotToken(' ')),
                "token_whitespace_or_control_forbidden",
            ),
            (
                value(WordDefect::NotQuotedString(QuotedStringDefect::NotQuoted)),
                "quoted_string_delimiter_missing",
            ),
        ] {
            assert_eq!(media_type_defect(defect).id, id, "{defect:?}");
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
