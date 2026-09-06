// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! URI defects — the escapes, the scheme name and the host, wherever a field
//! carries a reference.
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
//!
//! The `uri_host_*` and `uri_port_*` entries are the same argument at the scale
//! it matters most. Seven rules in this tree measure a host and an optional
//! port through one helper — a `Host` field, an HTTP/2 `:authority`, a
//! `Forwarded` `host`, a `Warning` `warn-agent`, a `Referer` authority, a
//! request target and `X-Forwarded-Host` — and the fix an operator makes
//! for `user@host` is the same fix whichever of them reported it. The port owns
//! exactly one entry, because `port = *DIGIT` has exactly one way to fail; a
//! number too large for a socket is a different sentence and belongs to the
//! rule that can name the transport.

use crate::helpers::uri::{
    HostAndPortDefect, PercentEncodingDefect, SchemeNameDefect, UriHostDefect,
};
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

/// The host, whose three alternatives are told apart by their brackets: an IP
/// literal wears them, and nothing else in the URI syntax does. Read out of a
/// `Host` field, a `:authority`, a `Forwarded` `host`, a `Via` `received-by`
/// and every authority this crate parses, all through one helper.
pub const RFC_3986_3_2_2: SpecRef = SpecRef {
    spec: "RFC 3986",
    section: Some("3.2.2"),
    url: "https://www.rfc-editor.org/rfc/rfc3986.html#section-3.2.2",
    note: "Host — `host = IP-literal / IPv4address / reg-name`, where the square brackets of the IP literal are the only ones the URI syntax admits anywhere",
};

/// The port, and the whole of what its production says: digits, any number of
/// them, none of them required.
pub const RFC_3986_3_2_3: SpecRef = SpecRef {
    spec: "RFC 3986",
    section: Some("3.2.3"),
    url: "https://www.rfc-editor.org/rfc/rfc3986.html#section-3.2.3",
    note: "Port — `port = *DIGIT`, which has no lower bound, no upper bound, and admits the empty string",
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
    /// A host that opens an IP literal and never closes it. The `[` is what
    /// chooses that alternative, so there is no reading of the value in which
    /// the bracket was meant as something else.
    ///
    // cite(RFC 3986 § 3.2.2): "IP-literal = "[" ( IPv6address / IPvFuture  ) "]""
    URI_HOST_CLOSING_BRACKET_MISSING = {
        id: "uri_host_closing_bracket_missing",
        title: "Host opens an IP literal and never closes it",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_3986_3_2_2),
    }

    /// Brackets around something that is neither an `IPv6address` nor an
    /// `IPvFuture`. Both alternatives are read, unlikely as the second is: the
    /// production generates it, and a finding against what a grammar admits is
    /// wrong however rare the value.
    ///
    // cite(RFC 3986 § 3.2.2): "IP-literal = "[" ( IPv6address / IPvFuture  ) "]""
    URI_HOST_IP_LITERAL_MALFORMED = {
        id: "uri_host_ip_literal_malformed",
        title: "Host brackets something that is not an IP literal",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_3986_3_2_2),
    }

    /// A bracket somewhere other than around an IP literal — a closing one with
    /// nothing that opened it, most often, in a value assembled from an address
    /// and a port by string concatenation. Told apart from the two above
    /// because this value is not trying to be a literal at all.
    ///
    // cite(RFC 3986 § 3.2.2): "This is the only place where square bracket characters are allowed in the URI syntax."
    URI_HOST_BRACKET_FORBIDDEN = {
        id: "uri_host_bracket_forbidden",
        title: "Host holds a square bracket outside an IP literal",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_3986_3_2_2),
    }

    /// A character no `reg-name` admits: not `unreserved`, not the `%` that
    /// opens a triplet, not `sub-delims`. The alphabet is wide — every one of
    /// the delimiters a URI reserves for a *later* component is in it — so what
    /// reaches this defect is usually a component that was never split off: an
    /// `@` left with its userinfo, a `/` left with its path.
    ///
    // cite(RFC 3986 § 3.2.2): "reg-name    = *( unreserved / pct-encoded / sub-delims )"
    URI_HOST_CHARACTER_FORBIDDEN = {
        id: "uri_host_character_forbidden",
        title: "Host holds a character outside the registered-name alphabet",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_3986_3_2_2),
    }

    /// A character in the port that is not a digit. There is no companion
    /// defect for a port outside a transport's range: `port = *DIGIT` bounds
    /// nothing, so a number too large for any socket is this production's and
    /// a finding about it needs a sentence naming the transport.
    ///
    // cite(RFC 3986 § 3.2.3): "The port subcomponent of authority is designated by an optional port number in decimal following the host and delimited from it by a single colon (":") character."
    URI_PORT_CHARACTER_FORBIDDEN = {
        id: "uri_port_character_forbidden",
        title: "Port holds a character that is not a digit",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_3986_3_2_3),
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

/// The defect a parsed [`UriHostDefect`] reports as.
///
/// The percent arm delegates rather than naming a host-shaped id of its own: a
/// malformed triplet is the same defect wherever it is read, which is what the
/// helper's own nesting already says.
pub fn uri_host(defect: UriHostDefect<'_>) -> &'static ViolationDef {
    match defect {
        UriHostDefect::UnclosedBracket(_) => &URI_HOST_CLOSING_BRACKET_MISSING,
        UriHostDefect::NotAnIpLiteral(_) => &URI_HOST_IP_LITERAL_MALFORMED,
        UriHostDefect::Bracket(_) => &URI_HOST_BRACKET_FORBIDDEN,
        UriHostDefect::PercentEncoding(defect) => percent_encoding(defect),
        UriHostDefect::BadCharacter { .. } => &URI_HOST_CHARACTER_FORBIDDEN,
    }
}

/// The defect a parsed [`HostAndPortDefect`] reports as.
///
/// The composition owns exactly one id — the port's — and hands the rest to
/// the host's own mapping, which is the same split the helper makes.
pub fn host_and_port(defect: HostAndPortDefect<'_>) -> &'static ViolationDef {
    match defect {
        HostAndPortDefect::Host(defect) => uri_host(defect),
        HostAndPortDefect::PortCharacter { .. } => &URI_PORT_CHARACTER_FORBIDDEN,
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

    /// Five variants, four ids of this subject's own and one borrowed: the
    /// malformed triplet inside a host is the percent-encoding's defect and
    /// says so, which is the pair of ids `cookie_path` had to be corrected to.
    #[test]
    fn each_uri_host_defect_maps_to_its_own_id() {
        for (defect, id) in [
            (
                UriHostDefect::UnclosedBracket("[::1"),
                "uri_host_closing_bracket_missing",
            ),
            (
                UriHostDefect::NotAnIpLiteral("nope"),
                "uri_host_ip_literal_malformed",
            ),
            (
                UriHostDefect::Bracket("2001:db8::1]"),
                "uri_host_bracket_forbidden",
            ),
            (
                UriHostDefect::PercentEncoding(PercentEncodingDefect::NotHexDigits("%zz")),
                "percent_encoding_malformed",
            ),
            (
                UriHostDefect::BadCharacter {
                    character: '@',
                    host: "user@host",
                },
                "uri_host_character_forbidden",
            ),
        ] {
            assert_eq!(uri_host(defect).id, id);
        }
    }

    /// The port is the one thing the composition adds, and the host half
    /// answers with exactly what it answers with on its own.
    #[test]
    fn the_composition_owns_only_the_port() {
        assert_eq!(
            host_and_port(HostAndPortDefect::PortCharacter {
                character: 'n',
                port: "notnum",
            })
            .id,
            "uri_port_character_forbidden",
        );
        assert_eq!(
            host_and_port(HostAndPortDefect::Host(UriHostDefect::BadCharacter {
                character: '@',
                host: "user@host",
            }))
            .id,
            "uri_host_character_forbidden",
        );
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
