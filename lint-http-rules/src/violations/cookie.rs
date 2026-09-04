// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Cookie defects — today, the seven ways a `Set-Cookie` `Path` attribute is
//! wrong.
//!
//! The subject is the attribute, not the rule that reads it: `cookie_path_*`
//! names what a server wrote, so a second rule that parses `Set-Cookie` reports
//! the same defect under the same name and an operator tunes it once.
//!
//! Three of these are not syntax errors at all. RFC 6265 § 5.2.4 has the user
//! agent replace an empty or unrooted `Path` with the default-path, so the
//! cookie still works and the server has merely written something that does
//! nothing; the remaining four are the § 4.1.1 grammar and the percent-encoding
//! it admits. That difference is why the defaults below are not one severity
//! repeated: a control character is an `error`, the whitespace this crate
//! refuses past the grammar is `info`, and the rest sit between them. It is the
//! whole reason a defect carries its own severity — the rule reporting these
//! could only ever have said one thing about all seven.

use crate::helpers::cookie::CookiePathDefect;
use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::{ViolationDef, REGISTERED_VIOLATIONS};
use linkme::distributed_slice;

/// The `Set-Cookie` grammar, which is what the character defects below are
/// answered by. Declared here rather than in the rule file because the
/// sentence belongs to the defect: it is the same sentence whichever rule
/// happens to notice the character.
pub const RFC_6265_4_1_1: SpecRef = SpecRef {
    spec: "RFC 6265",
    section: Some("4.1.1"),
    url: "https://www.rfc-editor.org/rfc/rfc6265.html#section-4.1.1",
    note: "Set-Cookie syntax — servers SHOULD NOT send a non-conforming Set-Cookie; `path-value` excludes control characters and `;`",
};

/// What a user agent does with a `Path` it cannot use — the sentence behind
/// the three defects that are about a value being discarded rather than about
/// a value being ungrammatical.
pub const RFC_6265_5_2_4: SpecRef = SpecRef {
    spec: "RFC 6265",
    section: Some("5.2.4"),
    url: "https://www.rfc-editor.org/rfc/rfc6265.html#section-5.2.4",
    note: "Path attribute — the user agent replaces an empty or non-`/` Path with the default-path (why those forms are flagged)",
};

/// The triplet a `%` obliges. `path-value` admits `%` as an ordinary
/// character, so a broken escape is answered by the document that defines the
/// escape and not by RFC 6265.
pub const RFC_3986_2_1: SpecRef = SpecRef {
    spec: "RFC 3986",
    section: Some("2.1"),
    url: "https://www.rfc-editor.org/rfc/rfc3986.html#section-2.1",
    note: "Percent-Encoding — `pct-encoded = \"%\" HEXDIG HEXDIG`, the two digits a `%` in a cookie path still owes",
};

/// `Path` written as a bare attribute, with no `=` and nothing after it.
///
/// Separate from [`COOKIE_PATH_EMPTY`] because the senders differ: this one
/// never wrote a value, that one wrote an empty one. The user agent treats
/// them alike — both take the default-path — but the operator's fix does not,
/// and neither does the message.
///
// cite(RFC 6265 § 5.2.4): "If the attribute-value is empty or if the first character of the attribute-value is not %x2F ("/"):"
pub static COOKIE_PATH_MISSING: ViolationDef = ViolationDef {
    id: "cookie_path_missing",
    title: "Set-Cookie Path attribute carries no value",
    message: "Set-Cookie attribute 'Path' requires a value",
    default_severity: Severity::Warn,
    spec: Some(RFC_6265_5_2_4),
};

/// `Path=` with nothing after the `=`.
///
// cite(RFC 6265 § 5.2.4): "If the attribute-value is empty or if the first character of the attribute-value is not %x2F ("/"):"
pub static COOKIE_PATH_EMPTY: ViolationDef = ViolationDef {
    id: "cookie_path_empty",
    title: "Set-Cookie Path attribute is empty",
    message: "",
    default_severity: Severity::Warn,
    spec: Some(RFC_6265_5_2_4),
};

/// A `Path` that does not start with `/`, which the user agent discards in
/// favour of the default-path — so the scope the server asked for is not the
/// scope the cookie gets.
///
// cite(RFC 6265 § 5.2.4): "If the attribute-value is empty or if the first character of the attribute-value is not %x2F ("/"):"
pub static COOKIE_PATH_LEADING_SLASH_MISSING: ViolationDef = ViolationDef {
    id: "cookie_path_leading_slash_missing",
    title: "Set-Cookie Path attribute is not rooted at `/`",
    message: "",
    default_severity: Severity::Warn,
    spec: Some(RFC_6265_5_2_4),
};

/// A `%` in the path that no two hex digits follow.
///
// cite(RFC 3986 § 2.1): "pct-encoded = "%" HEXDIG HEXDIG"
pub static COOKIE_PATH_PERCENT_ENCODING_MALFORMED: ViolationDef = ViolationDef {
    id: "cookie_path_percent_encoding_malformed",
    title: "Set-Cookie Path attribute has a broken percent-encoding",
    message: "",
    default_severity: Severity::Warn,
    spec: Some(RFC_3986_2_1),
};

/// A byte at or above %x80. `path-value` is built on `CHAR` = %x01-7F, so
/// non-ASCII derives from nothing in the grammar and has to be percent-encoded.
///
// cite(RFC 6265 § 4.1.1): "Servers SHOULD NOT send Set-Cookie headers that fail to conform to the following grammar:"
pub static COOKIE_PATH_NON_ASCII_CHARACTER_FORBIDDEN: ViolationDef = ViolationDef {
    id: "cookie_path_non_ascii_character_forbidden",
    title: "Set-Cookie Path attribute holds a raw non-ASCII character",
    message: "",
    default_severity: Severity::Warn,
    spec: Some(RFC_6265_4_1_1),
};

/// A `CTL`, which `path-value` excludes by name. The most serious of the seven
/// by default: the class it belongs to is the one a header value is split
/// with, and nothing legitimate puts one in a path.
///
// cite(RFC 6265 § 4.1.1): "Servers SHOULD NOT send Set-Cookie headers that fail to conform to the following grammar:"
pub static COOKIE_PATH_CONTROL_CHARACTER_FORBIDDEN: ViolationDef = ViolationDef {
    id: "cookie_path_control_character_forbidden",
    title: "Set-Cookie Path attribute holds a control character",
    message: "",
    default_severity: Severity::Error,
    spec: Some(RFC_6265_4_1_1),
};

/// A space, which `CHAR` admits and this crate refuses anyway — the one defect
/// here that no sentence requires, which is why it carries no `spec` and
/// defaults to `info`. An operator who wants the grammar and nothing else
/// leaves it there and never sees it; one who wants unambiguous cookie scopes
/// raises it. Neither was expressible while a rule had one severity.
pub static COOKIE_PATH_WHITESPACE_INVALID: ViolationDef = ViolationDef {
    id: "cookie_path_whitespace_invalid",
    title: "Set-Cookie Path attribute holds unencoded whitespace",
    message: "",
    default_severity: Severity::Info,
    spec: None,
};

/// The defect a parsed [`CookiePathDefect`] reports as.
///
/// The helper answers *what is wrong* and this answers *what it is called*, so
/// the two vocabularies are matched in one place instead of at every rule that
/// validates a cookie path. The match is exhaustive on purpose: a new variant
/// there does not compile until it is named here, which is the only way a
/// defect can fail to reach the catalogue.
pub fn path_defect(defect: &CookiePathDefect<'_>) -> &'static ViolationDef {
    match defect {
        CookiePathDefect::Empty => &COOKIE_PATH_EMPTY,
        CookiePathDefect::NotAbsolute(_) => &COOKIE_PATH_LEADING_SLASH_MISSING,
        CookiePathDefect::PercentEncoding(_) => &COOKIE_PATH_PERCENT_ENCODING_MALFORMED,
        CookiePathDefect::NonAscii(_) => &COOKIE_PATH_NON_ASCII_CHARACTER_FORBIDDEN,
        CookiePathDefect::ControlCharacter(_) => &COOKIE_PATH_CONTROL_CHARACTER_FORBIDDEN,
        CookiePathDefect::Whitespace(_) => &COOKIE_PATH_WHITESPACE_INVALID,
    }
}

/// Registers this subject's defects into the catalogue. One entry per def,
/// each a `static` reference the linker collects — the same shape a rule file
/// ends with.
#[distributed_slice(REGISTERED_VIOLATIONS)]
static R_COOKIE_PATH_MISSING: &ViolationDef = &COOKIE_PATH_MISSING;
#[distributed_slice(REGISTERED_VIOLATIONS)]
static R_COOKIE_PATH_EMPTY: &ViolationDef = &COOKIE_PATH_EMPTY;
#[distributed_slice(REGISTERED_VIOLATIONS)]
static R_COOKIE_PATH_LEADING_SLASH_MISSING: &ViolationDef = &COOKIE_PATH_LEADING_SLASH_MISSING;
#[distributed_slice(REGISTERED_VIOLATIONS)]
static R_COOKIE_PATH_PERCENT_ENCODING_MALFORMED: &ViolationDef =
    &COOKIE_PATH_PERCENT_ENCODING_MALFORMED;
#[distributed_slice(REGISTERED_VIOLATIONS)]
static R_COOKIE_PATH_NON_ASCII_CHARACTER_FORBIDDEN: &ViolationDef =
    &COOKIE_PATH_NON_ASCII_CHARACTER_FORBIDDEN;
#[distributed_slice(REGISTERED_VIOLATIONS)]
static R_COOKIE_PATH_CONTROL_CHARACTER_FORBIDDEN: &ViolationDef =
    &COOKIE_PATH_CONTROL_CHARACTER_FORBIDDEN;
#[distributed_slice(REGISTERED_VIOLATIONS)]
static R_COOKIE_PATH_WHITESPACE_INVALID: &ViolationDef = &COOKIE_PATH_WHITESPACE_INVALID;

#[cfg(test)]
mod tests {
    use super::*;

    /// Every variant maps to a def, and no two share one: a mapping that
    /// collapsed two variants would silence one defect under the other's
    /// severity, which nothing downstream could notice.
    #[test]
    fn each_path_defect_names_a_defect_of_its_own() {
        let defects = [
            CookiePathDefect::Empty,
            CookiePathDefect::NotAbsolute("login"),
            CookiePathDefect::PercentEncoding("%ZZ".to_string()),
            CookiePathDefect::NonAscii(3),
            CookiePathDefect::ControlCharacter(3),
            CookiePathDefect::Whitespace(3),
        ];
        let mut ids: Vec<&str> = defects.iter().map(|d| path_defect(d).id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), defects.len(), "two variants share one def");
    }

    /// The six mapped defects format their message at the site, and
    /// `COOKIE_PATH_MISSING` holds its own — the invariant `report` and
    /// `report_with` each assert one half of.
    #[test]
    fn only_the_unparameterised_defect_holds_a_message() {
        assert!(!COOKIE_PATH_MISSING.message.is_empty());
        for defect in [
            CookiePathDefect::Empty,
            CookiePathDefect::NotAbsolute("login"),
            CookiePathDefect::PercentEncoding("%ZZ".to_string()),
            CookiePathDefect::NonAscii(3),
            CookiePathDefect::ControlCharacter(3),
            CookiePathDefect::Whitespace(3),
        ] {
            let def = path_defect(&defect);
            assert!(def.message.is_empty(), "{} holds a message", def.id);
        }
    }
}
