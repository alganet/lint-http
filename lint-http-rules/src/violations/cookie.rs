// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Cookie defects — the ways a `Set-Cookie` attribute is wrong, `Path` and
//! `Domain` so far.
//!
//! The subject is the attribute, not the rule that reads it: `cookie_path_*`
//! names what a server wrote, so a second rule that parses `Set-Cookie` reports
//! the same defect under the same name and an operator tunes it once. What is
//! *not* here is the domain syntax underneath `Domain`: a name is a name in
//! every field that carries one, and those defects live in
//! [`crate::violations::domain`] where a rule reading a `From` mailbox can
//! report the same ones.
//!
//! Three of the `Path` defects are not syntax errors at all. RFC 6265 § 5.2.4 has the user
//! agent replace an empty or unrooted `Path` with the default-path, so the
//! cookie still works and the server has merely written something that does
//! nothing; the remaining four are the § 4.1.1 grammar and the percent-encoding
//! it admits. That difference is why the defaults below are not one severity
//! repeated: a control character is an `error`, the whitespace this crate
//! refuses past the grammar is `info`, and the rest sit between them. It is the
//! whole reason a defect carries its own severity — the rule reporting these
//! could only ever have said one thing about all seven.

use crate::helpers::cookie::CookiePathDefect;
use crate::helpers::domain::CookieDomainDefect;
use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::domain::preferred_name_defect;
use crate::violations::uri::percent_encoding;
use crate::violations::{defects, ViolationDef};

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

/// What a user agent does with a `Domain` it is given: an empty value leaves
/// the behaviour undefined, and a leading dot is dropped before anything else
/// happens to it.
pub const RFC_6265_5_2_3: SpecRef = SpecRef {
    spec: "RFC 6265",
    section: Some("5.2.3"),
    url: "https://www.rfc-editor.org/rfc/rfc6265.html#section-5.2.3",
    note: "`Domain` attribute processing — an empty value is undefined (the user agent ignores it) and a leading dot is stripped; the value's *format* is § 4.1.1 and RFC 1035",
};

/// Domain matching, which is where an IP address stops being a cookie domain:
/// the algorithm only reaches its host-name arm for a string that is not one.
pub const RFC_6265_5_1_3: SpecRef = SpecRef {
    spec: "RFC 6265",
    section: Some("5.1.3"),
    url: "https://www.rfc-editor.org/rfc/rfc6265.html#section-5.1.3",
    note: "Domain matching — a cookie-domain that is not a host name matches only the identical string, so an IP address scopes the cookie to nothing it can be sent for",
};

defects! {
    /// `Path` written as a bare attribute, with no `=` and nothing after it.
    ///
    /// Separate from [`COOKIE_PATH_EMPTY`] because the senders differ: this one
    /// never wrote a value, that one wrote an empty one. The user agent treats
    /// them alike — both take the default-path — but the operator's fix does not,
    /// and neither does the message.
    ///
    // cite(RFC 6265 § 5.2.4): "If the attribute-value is empty or if the first character of the attribute-value is not %x2F ("/"):"
    COOKIE_PATH_MISSING = {
        id: "cookie_path_missing",
        title: "Set-Cookie Path attribute carries no value",
        message: "Set-Cookie attribute 'Path' requires a value",
        default_severity: Severity::Warn,
        spec: Some(RFC_6265_5_2_4),
    }

    /// `Path=` with nothing after the `=`.
    ///
    // cite(RFC 6265 § 5.2.4): "If the attribute-value is empty or if the first character of the attribute-value is not %x2F ("/"):"
    COOKIE_PATH_EMPTY = {
        id: "cookie_path_empty",
        title: "Set-Cookie Path attribute is empty",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_6265_5_2_4),
    }

    /// A `Path` that does not start with `/`, which the user agent discards in
    /// favour of the default-path — so the scope the server asked for is not the
    /// scope the cookie gets.
    ///
    // cite(RFC 6265 § 5.2.4): "If the attribute-value is empty or if the first character of the attribute-value is not %x2F ("/"):"
    COOKIE_PATH_LEADING_SLASH_MISSING = {
        id: "cookie_path_leading_slash_missing",
        title: "Set-Cookie Path attribute is not rooted at `/`",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_6265_5_2_4),
    }

    /// A byte at or above %x80. `path-value` is built on `CHAR` = %x01-7F, so
    /// non-ASCII derives from nothing in the grammar and has to be percent-encoded.
    ///
    // cite(RFC 6265 § 4.1.1): "Servers SHOULD NOT send Set-Cookie headers that fail to conform to the following grammar:"
    COOKIE_PATH_NON_ASCII_CHARACTER_FORBIDDEN = {
        id: "cookie_path_non_ascii_character_forbidden",
        title: "Set-Cookie Path attribute holds a raw non-ASCII character",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_6265_4_1_1),
    }

    /// A `CTL`, which `path-value` excludes by name. The most serious of the seven
    /// by default: the class it belongs to is the one a header value is split
    /// with, and nothing legitimate puts one in a path.
    ///
    // cite(RFC 6265 § 4.1.1): "Servers SHOULD NOT send Set-Cookie headers that fail to conform to the following grammar:"
    COOKIE_PATH_CONTROL_CHARACTER_FORBIDDEN = {
        id: "cookie_path_control_character_forbidden",
        title: "Set-Cookie Path attribute holds a control character",
        message: "",
        default_severity: Severity::Error,
        spec: Some(RFC_6265_4_1_1),
    }

    /// A space, which `CHAR` admits and this crate refuses anyway — the one defect
    /// here that no sentence requires, which is why it carries no `spec` and
    /// defaults to `info`. An operator who wants the grammar and nothing else
    /// leaves it there and never sees it; one who wants unambiguous cookie scopes
    /// raises it. Neither was expressible while a rule had one severity.
    COOKIE_PATH_WHITESPACE_INVALID = {
        id: "cookie_path_whitespace_invalid",
        title: "Set-Cookie Path attribute holds unencoded whitespace",
        message: "",
        default_severity: Severity::Info,
        spec: None,
    }

    /// `Domain` written with no value, or with one that is empty before
    /// anything reads it. The user agent is left with nothing to scope the
    /// cookie by, and the specification does not say what it should do.
    ///
    // cite(RFC 6265 § 5.2.3): "If the attribute-value is empty, the behavior is undefined."
    COOKIE_DOMAIN_MISSING = {
        id: "cookie_domain_missing",
        title: "Set-Cookie Domain attribute carries no value",
        message: "Set-Cookie attribute 'Domain' requires a value",
        default_severity: Severity::Warn,
        spec: Some(RFC_6265_5_2_3),
    }

    /// A `Domain` that is empty once the tolerated leading dot comes off —
    /// `Domain=.` and nothing more. Reached through the domain reader rather
    /// than at the attribute, which is why it is not
    /// [`COOKIE_DOMAIN_MISSING`]: the server wrote something, and it came to
    /// nothing.
    ///
    // cite(RFC 6265 § 5.2.3): "Let cookie-domain be the attribute-value without the leading %x2E (".") character."
    COOKIE_DOMAIN_EMPTY = {
        id: "cookie_domain_empty",
        title: "Set-Cookie Domain attribute is empty",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_6265_5_2_3),
    }

    /// A leading `.`, which is not a syntax error: the user agent strips it,
    /// so `.example.com` and `example.com` are the same cookie-domain. That is
    /// exactly why it is reported — RFC 2965 gave the dot a meaning and RFC
    /// 6265 does not, so it is a form that survives without saying anything.
    /// `info` by default, because nothing about the cookie is wrong.
    ///
    // cite(RFC 6265 § 5.2.3): "Let cookie-domain be the attribute-value without the leading %x2E (".") character."
    COOKIE_DOMAIN_LEADING_DOT_OBSOLETE = {
        id: "cookie_domain_leading_dot_obsolete",
        title: "Set-Cookie Domain attribute keeps the obsolete leading dot",
        message: "Set-Cookie 'Domain' attribute uses a leading '.' which is deprecated; prefer the registry form without leading dot",
        default_severity: Severity::Info,
        spec: Some(RFC_6265_5_2_3),
    }

    /// A dotted-quad where a host name goes. The cookie is not thereby
    /// dangerous, it is inert: domain matching reaches its host-name arm only
    /// for a string that is not an address, so nothing but an identical
    /// request host can ever be sent it.
    ///
    // cite(RFC 6265 § 5.1.3): "The string is a host name (i.e., not an IP address)."
    COOKIE_DOMAIN_IPV4_ADDRESS_FORBIDDEN = {
        id: "cookie_domain_ipv4_address_forbidden",
        title: "Set-Cookie Domain attribute is an IPv4 address",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_6265_5_1_3),
    }

    /// A bracketed IPv6 literal, for the same reason as the IPv4 form — kept
    /// apart from it because the two are written differently and an operator
    /// looking at a report is looking for one of them.
    ///
    // cite(RFC 6265 § 5.1.3): "The string is a host name (i.e., not an IP address)."
    COOKIE_DOMAIN_IPV6_LITERAL_FORBIDDEN = {
        id: "cookie_domain_ipv6_literal_forbidden",
        title: "Set-Cookie Domain attribute is an IPv6 literal",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_6265_5_1_3),
    }
}

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
        CookiePathDefect::PercentEncoding(defect) => percent_encoding(*defect),
        CookiePathDefect::NonAscii(_) => &COOKIE_PATH_NON_ASCII_CHARACTER_FORBIDDEN,
        CookiePathDefect::ControlCharacter(_) => &COOKIE_PATH_CONTROL_CHARACTER_FORBIDDEN,
        CookiePathDefect::Whitespace(_) => &COOKIE_PATH_WHITESPACE_INVALID,
    }
}

/// The defect a parsed [`CookieDomainDefect`] reports as.
///
/// Both empty forms answer with [`COOKIE_DOMAIN_EMPTY`]: the reader trims
/// before it strips the dot, so `Domain=` and `Domain=.` arrive here as two
/// variants of one thing an operator fixes one way. The last arm hands the
/// question to [`crate::violations::domain`], which is the point of that
/// module — the name syntax under a `Domain` is the same syntax as under any
/// other field, and reports under the same names.
pub fn domain_defect(defect: CookieDomainDefect) -> &'static ViolationDef {
    match defect {
        CookieDomainDefect::Empty | CookieDomainDefect::EmptyAfterLeadingDot => {
            &COOKIE_DOMAIN_EMPTY
        }
        CookieDomainDefect::WhitespaceOrControl => {
            &crate::violations::domain::DOMAIN_NAME_WHITESPACE_OR_CONTROL_FORBIDDEN
        }
        CookieDomainDefect::Ipv6Literal => &COOKIE_DOMAIN_IPV6_LITERAL_FORBIDDEN,
        CookieDomainDefect::Ipv4Address => &COOKIE_DOMAIN_IPV4_ADDRESS_FORBIDDEN,
        CookieDomainDefect::PreferredName(defect) => preferred_name_defect(defect),
    }
}

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
            CookiePathDefect::PercentEncoding(
                crate::helpers::uri::PercentEncodingDefect::NotHexDigits("%ZZ"),
            ),
            CookiePathDefect::NonAscii(3),
            CookiePathDefect::ControlCharacter(3),
            CookiePathDefect::Whitespace(3),
        ];
        let mut ids: Vec<&str> = defects.iter().map(|d| path_defect(d).id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), defects.len(), "two variants share one def");
    }

    /// The `Domain` mapping, spelled out — including the one place two
    /// variants answer with one def, which is a decision and not an oversight.
    #[test]
    fn each_domain_defect_maps_to_its_own_id() {
        for (defect, id) in [
            (CookieDomainDefect::Empty, "cookie_domain_empty"),
            (
                CookieDomainDefect::EmptyAfterLeadingDot,
                "cookie_domain_empty",
            ),
            (
                CookieDomainDefect::WhitespaceOrControl,
                "domain_name_whitespace_or_control_forbidden",
            ),
            (
                CookieDomainDefect::Ipv6Literal,
                "cookie_domain_ipv6_literal_forbidden",
            ),
            (
                CookieDomainDefect::Ipv4Address,
                "cookie_domain_ipv4_address_forbidden",
            ),
            (
                CookieDomainDefect::PreferredName(
                    crate::helpers::domain::PreferredNameDefect::EmptyLabel,
                ),
                "domain_label_empty",
            ),
        ] {
            assert_eq!(domain_defect(defect).id, id);
        }
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
            CookiePathDefect::PercentEncoding(
                crate::helpers::uri::PercentEncodingDefect::NotHexDigits("%ZZ"),
            ),
            CookiePathDefect::NonAscii(3),
            CookiePathDefect::ControlCharacter(3),
            CookiePathDefect::Whitespace(3),
        ] {
            let def = path_defect(&defect);
            assert!(def.message.is_empty(), "{} holds a message", def.id);
        }
    }
}
