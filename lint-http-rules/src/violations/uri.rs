// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! URI defects — the escapes and the scheme name, wherever a field carries a
//! reference.
//!
//! A `%` obliges two hexadecimal digits wherever it is written, and this crate
//! reads escapes in a request target, a `Location`, a cookie `Path`, an
//! `Alt-Svc` parameter and a dozen other places. The sentence answering all of
//! them is the same one, so the defect is too: naming it after the field that
//! happened to carry it would give an operator one name per field for one
//! mistake.
//!
//! That is a correction to this campaign's first subject, made while the
//! catalogue was small enough for corrections to be free. `cookie_path` shipped
//! a `cookie_path_percent_encoding_malformed` of its own, which was the same
//! reasoning error the rule-shaped catalogue is being split to fix.

use crate::helpers::uri::{PercentEncodingDefect, SchemeNameDefect};
use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::{defects, ViolationDef};

/// The scheme name: one production, and the three ways a value is not it.
/// Read out of a `Referer`, a `Forwarded` `proto`, a `Link` target, an
/// `Alt-Svc` and an absolute-form request target, all through one helper.
pub const RFC_3986_3_1: SpecRef = SpecRef {
    spec: "RFC 3986",
    section: Some("3.1"),
    url: "https://www.rfc-editor.org/rfc/rfc3986.html#section-3.1",
    note: "Scheme — `scheme = ALPHA *( ALPHA / DIGIT / \"+\" / \"-\" / \".\" )`, the name before the first colon",
};

/// The triplet a `%` obliges, and the only sentence either percent defect here
/// needs.
pub const RFC_3986_2_1: SpecRef = SpecRef {
    spec: "RFC 3986",
    section: Some("2.1"),
    url: "https://www.rfc-editor.org/rfc/rfc3986.html#section-2.1",
    note: "Percent-Encoding — `pct-encoded = \"%\" HEXDIG HEXDIG`, the two digits every `%` still owes",
};

defects! {
    /// A `%` with fewer than two characters after it, because the value ended.
    /// Kept apart from the malformed triplet because the fix differs: this one
    /// is a value that was cut, most often by something that truncated it.
    ///
    // cite(RFC 3986 § 2.1): "pct-encoded = "%" HEXDIG HEXDIG"
    PERCENT_ENCODING_DIGITS_MISSING = {
        id: "percent_encoding_digits_missing",
        title: "Percent-encoding stops before its two hexadecimal digits",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_3986_2_1),
    }

    /// Two characters after the `%` that are not both `HEXDIG` — a literal
    /// percent that was never escaped, most often.
    ///
    // cite(RFC 3986 § 2.1): "pct-encoded = "%" HEXDIG HEXDIG"
    PERCENT_ENCODING_MALFORMED = {
        id: "percent_encoding_malformed",
        title: "Percent-encoding is not two hexadecimal digits",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_3986_2_1),
    }
    /// A value whose scheme candidate is empty — the colon with nothing before
    /// it. `ALPHA *( … )` generates nothing empty, so this derives from no
    /// alternative of the production.
    ///
    // cite(RFC 3986 § 3.1): "scheme      = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )"
    URI_SCHEME_EMPTY = {
        id: "uri_scheme_empty",
        title: "URI scheme is empty",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_3986_3_1),
    }

    /// A scheme opening on something that is not a letter — a digit, most
    /// often, in a value whose first path segment happens to hold a colon.
    ///
    // cite(RFC 3986 § 3.1): "scheme      = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )"
    URI_SCHEME_LEADING_LETTER_MISSING = {
        id: "uri_scheme_leading_letter_missing",
        title: "URI scheme does not begin with a letter",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_3986_3_1),
    }

    /// A character after the first that the production does not admit: only
    /// letters, digits, `+`, `-` and `.` follow the opening letter.
    ///
    // cite(RFC 3986 § 3.1): "scheme      = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )"
    URI_SCHEME_CHARACTER_FORBIDDEN = {
        id: "uri_scheme_character_forbidden",
        title: "URI scheme holds a character outside letters, digits, '+', '-' and '.'",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_3986_3_1),
    }
}

/// The defect a parsed [`SchemeNameDefect`] reports as.
pub fn scheme_name(defect: SchemeNameDefect<'_>) -> &'static ViolationDef {
    match defect {
        SchemeNameDefect::Empty => &URI_SCHEME_EMPTY,
        SchemeNameDefect::DoesNotBeginWithLetter(_) => &URI_SCHEME_LEADING_LETTER_MISSING,
        SchemeNameDefect::BadCharacter { .. } => &URI_SCHEME_CHARACTER_FORBIDDEN,
    }
}

/// The defect a parsed [`PercentEncodingDefect`] reports as.
pub fn percent_encoding(defect: PercentEncodingDefect<'_>) -> &'static ViolationDef {
    match defect {
        PercentEncodingDefect::Incomplete => &PERCENT_ENCODING_DIGITS_MISSING,
        PercentEncodingDefect::NotHexDigits(_) => &PERCENT_ENCODING_MALFORMED,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Three variants, three ids: a scheme that is not one fails in exactly
    /// the places the production has — nothing there, the wrong first
    /// character, or the wrong later one.
    #[test]
    fn each_scheme_name_defect_maps_to_its_own_id() {
        for (defect, id) in [
            (SchemeNameDefect::Empty, "uri_scheme_empty"),
            (
                SchemeNameDefect::DoesNotBeginWithLetter("1http"),
                "uri_scheme_leading_letter_missing",
            ),
            (
                SchemeNameDefect::BadCharacter {
                    character: '_',
                    scheme: "ht_tp",
                },
                "uri_scheme_character_forbidden",
            ),
        ] {
            assert_eq!(scheme_name(defect).id, id);
        }
    }

    #[test]
    fn each_percent_encoding_defect_maps_to_its_own_id() {
        assert_eq!(
            percent_encoding(PercentEncodingDefect::Incomplete).id,
            "percent_encoding_digits_missing",
        );
        assert_eq!(
            percent_encoding(PercentEncodingDefect::NotHexDigits("%ZZ")).id,
            "percent_encoding_malformed",
        );
    }
}
