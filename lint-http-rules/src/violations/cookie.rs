// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Cookie defects — the ways a `Set-Cookie` attribute is wrong.
//!
//! The subject is the attribute, not the rule that reads it: `cookie_path_*`
//! names what a server wrote, so a second rule that parses `Set-Cookie` reports
//! the same defect under the same name and an operator tunes it once. What is
//! *not* here is the domain syntax underneath `Domain`: a name is a name in
//! every field that carries one, and those defects live in
//! [`crate::violations::domain`] where a rule reading a `From` mailbox can
//! report the same ones.
//!
//! **Two entries are ranked above the rest, and one line separates them from
//! it: whether the *cookie* is lost or an attribute is.** A `Set-Cookie` with
//! no cookie-pair sets nothing, and a `SameSite=None` without `Secure` is
//! thrown away entirely by the user agent — in both cases the server believes
//! it stored state and did not. Everything else here costs an attribute: a
//! discarded `Max-Age`, a `Path` replaced by the default-path, a `SameSite`
//! that falls back. That is the difference between `error` and `warn` in this
//! subject, and it is a property of the processing algorithm rather than a
//! judgment about how much any of it matters.
//!
//! **The `SameSite`, `Max-Age` and `Expires` entries are a third kind, and
//! they are why this subject cannot be filed under "syntax".** Each of those
//! attributes has a processing algorithm that *discards* what it cannot read: a
//! `Max-Age` with a stray character is ignored and the cookie silently becomes
//! a session cookie, an unknown `SameSite` falls back to the default policy,
//! an `Expires` naming no instant expires nothing. The server asked for
//! something and got something else, with no error anywhere in the exchange —
//! which is the whole argument for reporting them at all.
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
    note: "Set-Cookie syntax — servers SHOULD NOT send a non-conforming Set-Cookie; the `cookie-av` list, where each attribute is written with or without a value, and the `path-value` that excludes control characters and `;`",
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
        spec: &[RFC_6265_5_2_4],
    }

    /// `Path=` with nothing after the `=`.
    ///
    // cite(RFC 6265 § 5.2.4): "If the attribute-value is empty or if the first character of the attribute-value is not %x2F ("/"):"
    COOKIE_PATH_EMPTY = {
        id: "cookie_path_empty",
        title: "Set-Cookie Path attribute is empty",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_6265_5_2_4],
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
        spec: &[RFC_6265_5_2_4],
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
        spec: &[RFC_6265_4_1_1],
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
        spec: &[RFC_6265_4_1_1],
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
        spec: &[],
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
        spec: &[RFC_6265_5_2_3],
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
        spec: &[RFC_6265_5_2_3],
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
        spec: &[RFC_6265_5_2_3],
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
        spec: &[RFC_6265_5_1_3],
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
        spec: &[RFC_6265_5_1_3],
    }

    /// `SameSite` written as a bare attribute. The attribute is the whole of
    /// its policy — there is no default it selects by being present — so a
    /// server that wrote it with no value asked for nothing and got the
    /// behaviour it would have had without the attribute at all.
    ///
    // cite(draft-ietf-httpbis-rfc6265bis § 4.1.1): "samesite-value = "Strict" / "Lax" / "None""
    COOKIE_SAME_SITE_MISSING = {
        id: "cookie_same_site_missing",
        title: "Set-Cookie SameSite attribute carries no value",
        message: "Set-Cookie attribute 'SameSite' requires a value",
        default_severity: Severity::Warn,
        spec: &[DRAFT_IETF_HTTPBIS_RFC6265BIS],
    }

    /// A `SameSite` value that is none of the three the grammar lists. It is
    /// `_invalid` rather than `_malformed` because the value is a perfectly
    /// good token and what it is not is a *member of a closed list* — and the
    /// consequence is the one that makes this worth reporting: an unknown value
    /// does not fail loudly, it falls back to the user agent's default policy,
    /// so a server asking for one thing quietly receives another.
    ///
    /// The comparison folds case, which is the grammar's doing: the three
    /// alternatives are ABNF string literals.
    ///
    // cite(draft-ietf-httpbis-rfc6265bis § 4.1.1): "samesite-value = "Strict" / "Lax" / "None""
    COOKIE_SAME_SITE_INVALID = {
        id: "cookie_same_site_invalid",
        title: "Set-Cookie SameSite names no policy the grammar defines",
        message: "",
        default_severity: Severity::Warn,
        spec: &[DRAFT_IETF_HTTPBIS_RFC6265BIS],
    }

    /// `Max-Age` written as a bare attribute, with no number after it.
    ///
    // cite(RFC 6265 § 4.1.1, label: cookie-av alternatives): "max-age-av        = "Max-Age=" non-zero-digit *DIGIT"
    COOKIE_MAX_AGE_MISSING = {
        id: "cookie_max_age_missing",
        title: "Set-Cookie Max-Age attribute carries no value",
        message: "Set-Cookie attribute 'Max-Age' requires a numeric value",
        default_severity: Severity::Warn,
        spec: &[RFC_6265_4_1_1],
    }

    /// A `Max-Age` a user agent will not read a number out of. § 5.2.2 states
    /// the two gates — a first character that is a DIGIT or `-`, and a
    /// remainder that is all DIGITs — and tells the user agent to ignore the
    /// attribute when either fails, which is why this matters more than a
    /// mistyped number usually would: the cookie does not get a bad lifetime,
    /// it gets *no* lifetime and becomes a session cookie.
    ///
    /// A leading `-` is not this defect. The ABNF summary writes
    /// `non-zero-digit *DIGIT` and the processing algorithm admits the sign,
    /// and a negative `Max-Age` is how a cookie is deleted — the algorithm is
    /// what a user agent runs, so it is what the entry measures.
    ///
    // cite(RFC 6265 § 5.2.2): "If the remainder of attribute-value contains a non-DIGIT character, ignore the cookie-av."
    COOKIE_MAX_AGE_MALFORMED = {
        id: "cookie_max_age_malformed",
        title: "Set-Cookie Max-Age is not a number a user agent will read",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_6265_5_2_2],
    }

    /// A `Set-Cookie` field line with no cookie-pair on it: nothing before the
    /// first `;`, or a line that is attributes from the start. The line sets no
    /// cookie — the pair is the cookie, and the attributes only describe one —
    /// so a server that wrote this believes it stored state and stored none.
    ///
    /// `error`, with the pairing entry below and for the same reason: what is
    /// lost is the whole cookie rather than one of its attributes.
    ///
    // cite(RFC 6265 § 4.1.1, label: set-cookie-string): "set-cookie-header = "Set-Cookie:" SP set-cookie-string set-cookie-string = cookie-pair *( ";" SP cookie-av )"
    COOKIE_PAIR_MISSING = {
        id: "cookie_pair_missing",
        title: "Set-Cookie carries no cookie-pair",
        message: "Set-Cookie header missing cookie-pair",
        default_severity: Severity::Error,
        spec: &[RFC_6265_4_1_1],
    }

    /// A value written on `Secure` or `HttpOnly`. Both attributes are their own
    /// presence — the grammar is the bare word, with no `=` in it — so
    /// `Secure=true` and `Secure=false` are the same attribute, and a server
    /// writing the second has switched nothing off.
    ///
    /// `warn`: a user agent reads the attribute by name and the cookie keeps
    /// the protection either way, so what is wrong is the sender's belief about
    /// what it wrote rather than the state it stored.
    ///
    // cite(RFC 6265 § 4.1.1, label: the flag attributes): "secure-av         = "Secure" httponly-av       = "HttpOnly""
    COOKIE_FLAG_VALUE_FORBIDDEN = {
        id: "cookie_flag_value_forbidden",
        title: "Set-Cookie writes a value on a flag attribute",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_6265_4_1_1],
    }

    /// `SameSite=None` on a cookie that is not `Secure`. The two attributes are
    /// each unremarkable and the pairing is what fails: a user agent asked to
    /// send a cookie cross-site over an insecure connection ignores the cookie
    /// entirely.
    ///
    /// **The id names the missing attribute rather than the pair**, because
    /// that is what a server fixes: `Secure` is what is absent, and
    /// `SameSite=None` is the condition that makes its absence fatal. An id
    /// spelled for the pairing would have to be read backwards to act on.
    ///
    /// `error`, with the entry above: the cookie is discarded, not weakened.
    ///
    // cite(draft-ietf-httpbis-rfc6265bis § 5.7): "If the cookie's "same-site-flag" is "None", abort this algorithm and ignore the cookie entirely unless the cookie's secure-only-flag is true."
    COOKIE_SECURE_MISSING = {
        id: "cookie_secure_missing",
        title: "A SameSite=None cookie is not Secure",
        message: "Set-Cookie with 'SameSite=None' must also set 'Secure'",
        default_severity: Severity::Error,
        spec: &[DRAFT_IETF_HTTPBIS_RFC6265BIS],
    }

    /// `Expires` written as a bare attribute. The timestamp itself is
    /// [`http_date`](crate::violations::http_date)'s — `sane-cookie-date` is
    /// RFC 6265's name for the same production — so what is left here is the
    /// attribute having no value for that production to read.
    ///
    // cite(RFC 6265 § 4.1.1, label: expires-av): "expires-av        = "Expires=" sane-cookie-date"
    COOKIE_EXPIRES_MISSING = {
        id: "cookie_expires_missing",
        title: "Set-Cookie Expires attribute carries no value",
        message: "Set-Cookie attribute 'Expires' requires a HTTP-date value",
        default_severity: Severity::Warn,
        spec: &[RFC_6265_4_1_1],
    }
}

/// The `Max-Age` processing algorithm: the two gates a value passes before a
/// user agent reads a number out of it, and the instruction to drop the
/// attribute when it does not.
pub const RFC_6265_5_2_2: SpecRef = SpecRef {
    spec: "RFC 6265",
    section: Some("5.2.2"),
    url: "https://www.rfc-editor.org/rfc/rfc6265.html#section-5.2.2",
    note: "The Max-Age attribute — ignored unless it is a `-`-or-DIGIT first character with an all-DIGIT remainder",
};

/// The `SameSite` attribute, in the draft that defines it. No section: a draft
/// renumbers between revisions, and the value list has moved once already.
pub const DRAFT_IETF_HTTPBIS_RFC6265BIS: SpecRef = SpecRef {
    spec: "draft-ietf-httpbis-rfc6265bis",
    section: None,
    url: "https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis",
    note: "`SameSite` value grammar and the `SameSite=None` requires `Secure` rule. No section: a draft renumbers between revisions",
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
