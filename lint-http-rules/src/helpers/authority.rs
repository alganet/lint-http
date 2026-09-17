// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! An authority: who is being addressed. Where the component begins and ends,
//! the `userinfo` in front of it, and the `host [ ":" port ]` that is the rest.
//!
//! **`authority = [ userinfo "@" ] host [ ":" port ]` is one production and the
//! four readings here are its four parts**, which is why they share a module and
//! not merely a file: [`authority_component`] answers where § 3.2's component
//! stops, [`split_userinfo`] where the credential half ends,
//! [`split_host_and_port`] where the colon that delimits a port is — and it is
//! the only colon that does, since an `IP-literal` carries its own —, and
//! [`validate_uri_host`] what the host may be made of.
//!
//! **The brackets are what separate the three host alternatives, and nothing
//! else does.** `IPv4address` generates nothing `reg-name` does not also
//! generate, so a dotted quad out of range is a perfectly good registered name;
//! `IP-literal` is the one place in the whole URI syntax where a square bracket
//! appears. Every defect this module reports about a host is therefore either a
//! bracket in the wrong place or a character no `reg-name` admits.
//!
//! **Two questions that look like this one are deliberately elsewhere.** What a
//! *serialized origin* is — an authority with a scheme in front and nothing
//! after it — is the origin grammar's question, because the sentence that
//! forbids the path is that grammar's and not § 3.2's. And whether a run of digits lands in
//! the sixteen-bit namespace a transport registers ports in is [`port_number`]'s
//! rather than [`validate_host_and_optional_port`]'s: `port = *DIGIT` bounds
//! nothing at either end, so the range needs a sentence naming a transport, and
//! that sentence is always the caller's.

use crate::helpers::percent_encoding::{percent_encoding_defect, PercentEncodingDefect};
use crate::helpers::scheme::scheme_prefix;
use crate::helpers::uri::{is_sub_delim, is_unreserved};
/// Split an authority into its `userinfo` subcomponent and the `host [ ":" port ]`
/// that follows the `@`, with the delimiter itself discarded.
///
/// The split is at the **last** `@`, and that is not a tolerance: neither
/// `userinfo` nor `reg-name` admits an at-sign, so an authority the grammar
/// generates holds at most one. Taking the last leaves the host half — the one
/// a caller goes on to measure — as short as the value allows, so a second
/// at-sign is reported as part of the userinfo rather than as a host character.
// cite(RFC 3986 § 3.2, label: authority grammar): "authority   = [ userinfo "@" ] host [ ":" port ]"
// cite(RFC 3986 § 3.2.1): "userinfo    = *( unreserved / pct-encoded / sub-delims / ":" )"
// cite(RFC 3986 § 3.2.1): "The user information, if present, is followed by a commercial at-sign ("@") that delimits it from the host."
pub fn split_userinfo(authority: &str) -> (Option<&str>, &str) {
    match authority.rfind('@') {
        Some(at) => (Some(&authority[..at]), &authority[at + 1..]),
        None => (None, authority),
    }
}

/// `Some(authority with the password elided)`, or `None` when there is nothing
/// to elide.
///
/// The point of a userinfo finding is that credentials arrived somewhere a
/// server logs, and a lint report is one more place they would be written down
/// in clear. The sentence asking for this names the *first* colon and exempts
/// an empty tail, so `user:@host` has nothing to elide and `user:s3cret@host`
/// becomes `user:...@host`.
///
/// Shared on its second caller: `referer_uri_valid` wrote this for the
/// field whose MUST NOT names the component, and the two pseudo-header rules
/// print an authority rather than a whole reference — the elision is the same
/// decision in both shapes, so the authority form lives here and the
/// whole-value caller substitutes the result back into its value.
// cite(RFC 3986 § 3.2.1): "Applications should not render as clear text any data after the first colon (":") character found within a userinfo subcomponent unless the data after the colon is the empty string (indicating no password)."
pub fn userinfo_password_withheld(authority: &str) -> Option<String> {
    let (Some(userinfo), host_and_port) = split_userinfo(authority) else {
        return None;
    };
    let (user, secret) = userinfo.split_once(':')?;
    if secret.is_empty() {
        return None;
    }
    Some(format!("{user}:...@{host_and_port}"))
}

/// The `authority` a URI reference carries, or `None` when it carries none.
///
/// § 3.2's sentence is the whole of this function, in both directions: the
/// component is *preceded* by a double slash and *terminated* by the next "/",
/// "?" or "#" character, or by the end of the value. The two slashes are what
/// the search is for, and a scheme in front of them is optional — both
/// alternatives of the generic syntax that reach an authority open with them
/// and only with them, `hier-part` and `relative-part` each writing
/// `"//" authority path-abempty`.
///
/// **`Some("")` is an authority; `None` is the absence of one.** `host` may be
/// a `reg-name`, which is `*( ... )`, so `http://` carries an empty authority
/// where `http:/path` carries none — and RFC 9110 § 4.2.1's and § 4.2.2's MUST
/// NOTs are about exactly the first of those, which is why the empty one is
/// returned rather than folded away here. A caller that compares one authority
/// against another has nothing to compare in that case and folds it itself;
/// [`super::uri::reference_authority`] is that caller, and says so at its own site.
///
/// The `//` must follow the scheme's colon immediately, which is why the scheme
/// is taken with [`scheme_prefix`] rather than by looking for a `://`: in
/// `a:b://c` the scheme is `a` and `b://c` is a `path-rootless`, so the value
/// carries no authority at all.
// cite(RFC 3986 § 4.3, label: absolute-URI): "absolute-URI  = scheme ":" hier-part [ "?" query ]"
// cite(RFC 3986 § 3): "hier-part   = "//" authority path-abempty / path-absolute / path-rootless / path-empty"
// cite(RFC 3986 § 4.2, label: relative-part): "relative-part = "//" authority path-abempty / path-absolute / path-noscheme / path-empty"
// cite(RFC 3986 § 3.2): "The authority component is preceded by a double slash ("//") and is terminated by the next slash ("/"), question mark ("?"), or number sign ("#") character, or by the end of the URI."
// cite(RFC 3986 § 3.2.2): "reg-name    = *( unreserved / pct-encoded / sub-delims )"
pub fn authority_component(value: &str) -> Option<&str> {
    let after_slashes = match scheme_prefix(value) {
        Some(scheme) => value[scheme.len() + 1..].strip_prefix("//")?,
        None => value.strip_prefix("//")?,
    };
    let end = after_slashes
        .find(['/', '?', '#'])
        .unwrap_or(after_slashes.len());
    Some(&after_slashes[..end])
}

/// The scheme of a reference that identifies an origin server and names no
/// host, if the value is one.
///
/// **Not a grammar question, which is why it is a reader of its own.** The
/// generic syntax admits an empty host — `reg-name` is `*( ... )` and
/// `authority` is one alternative of a `hier-part` — so `file:///etc/hosts` is a
/// URI in daily use and nothing in RFC 3986 objects to `https:///p` either. What
/// objects is each of the two scheme definitions HTTP mints identifiers in: an
/// `http` or `https` URI names the origin server in its authority, and a sender
/// may not leave that identifier empty.
///
/// So the scheme is the condition. It is matched without regard to case,
/// because a scheme is compared that way, and it is returned rather than
/// discarded: the two sentences are written once per scheme, so a caller naming
/// the one that governs its value needs to know which scheme it read.
///
/// A userinfo is stepped over rather than reported — `https://user@/p` names no
/// host either, and the credential is a separate finding the callers make
/// first.
// cite(RFC 9110 § 4.2.1): "A sender MUST NOT generate an "http" URI with an empty host identifier."
// cite(RFC 9110 § 4.2.2): "A sender MUST NOT generate an "https" URI with an empty host identifier."
// cite(RFC 9110 § 4.2.3): "The scheme and host are case-insensitive and normally provided in lowercase; all other components are compared in a case-sensitive manner."
pub fn empty_host_scheme(value: &str) -> Option<&str> {
    let scheme = scheme_prefix(value)?;
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return None;
    }
    let (_, host_and_port) = split_userinfo(authority_component(value)?);
    let (host, _) = split_host_and_port(host_and_port);
    host.is_empty().then_some(scheme)
}

/// Validate a `uri-host`: an IP literal in brackets, or a registered name.
///
/// The three alternatives are not three checks. `IPv4address` generates nothing
/// `reg-name` does not also generate — every `dec-octet` is DIGIT and `.` is
/// `unreserved` — so a dotted quad that is out of range is a perfectly good
/// registered name and is not a syntax finding here. What separates the
/// alternatives is the brackets, which appear in no other host form.
///
/// The two sets `reg-name` is written out of are [`is_unreserved`] and
/// [`is_sub_delim`], and their productions are quoted there rather than here:
/// this function composes them, it does not transcribe them.
// cite(RFC 3986 § 3.2.2): "host        = IP-literal / IPv4address / reg-name"
// cite(RFC 3986 § 3.2.2): "reg-name    = *( unreserved / pct-encoded / sub-delims )"
pub fn validate_uri_host(host: &str) -> Result<(), UriHostDefect<'_>> {
    if let Some(rest) = host.strip_prefix('[') {
        // cite(RFC 3986 § 3.2.2): "IP-literal = "[" ( IPv6address / IPvFuture  ) "]""
        let Some(inner) = rest.strip_suffix(']') else {
            return Err(UriHostDefect::UnclosedBracket(host));
        };
        if inner.parse::<std::net::Ipv6Addr>().is_ok() || is_ipvfuture(inner) {
            return Ok(());
        }
        return Err(UriHostDefect::NotAnIpLiteral(inner));
    }

    if host.contains([']', '[']) {
        return Err(UriHostDefect::Bracket(host));
    }

    // The triplet is the whole of `pct-encoded`, and it is read by the module
    // that owns that production rather than here. Its two hex digits are DIGIT
    // and ALPHA, so the character walk below has nothing left to say about them.
    if let Some(defect) = percent_encoding_defect(host) {
        return Err(UriHostDefect::PercentEncoding(defect));
    }
    // The production read left to right: `unreserved`, the `%` that opens a
    // `pct-encoded`, `sub-delims`, and nothing else — no `:` and no `@`, which
    // is the whole of the difference between this alphabet and `pchar`'s.
    for c in host.chars() {
        if !(is_unreserved(c) || c == '%' || is_sub_delim(c)) {
            return Err(UriHostDefect::BadCharacter { character: c, host });
        }
    }
    Ok(())
}

/// What a `uri-host` fails to be.
///
/// The first three are all about brackets, which is the module doc's point made
/// as a type: the brackets are what separate the three alternatives, so a
/// bracket problem is the only kind of "wrong alternative" this production has.
/// [`Bracket`](Self::Bracket) is the value that has one somewhere no host form
/// puts one, which is different from an IP literal that opened correctly and
/// then failed.
///
/// [`PercentEncoding`](Self::PercentEncoding) nests
/// [`super::percent_encoding::PercentEncodingDefect`] rather than flattening
/// its two cases in, because a malformed triplet is the same defect wherever it
/// is read — which is the sentence that gave it a module of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UriHostDefect<'a> {
    /// A `[`-led host with no closing `]`, carrying the whole host.
    UnclosedBracket(&'a str),
    /// Brackets around something that is neither an `IPv6address` nor an
    /// `IPvFuture`, carrying what was inside them.
    NotAnIpLiteral(&'a str),
    /// A bracket somewhere other than around an IP literal. § 3.2.2 calls the
    /// literal the only place in the URI syntax where one appears.
    Bracket(&'a str),
    /// A malformed `pct-encoded` triplet in what would otherwise be a
    /// `reg-name`.
    PercentEncoding(PercentEncodingDefect<'a>),
    /// A character no `reg-name` admits: not `unreserved`, not the `%` that
    /// opens a triplet, not `sub-delims`.
    BadCharacter {
        /// The character.
        character: char,
        /// The host it was found in.
        host: &'a str,
    },
}

impl UriHostDefect<'_> {
    /// The finding fragment.
    pub fn message(self) -> String {
        match self {
            Self::UnclosedBracket(host) => format!("IP literal '{}' is missing its ']'", host),
            Self::NotAnIpLiteral(inner) => format!("'{}' is not an IPv6 address", inner),
            Self::Bracket(host) => format!(
                "'{}' holds a bracket, which appears in no host form but an IP literal",
                host
            ),
            Self::PercentEncoding(defect) => defect.message(),
            Self::BadCharacter { character, host } => {
                format!("invalid character '{}' in host '{}'", character, host)
            }
        }
    }
}

/// `IPvFuture = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )`
///
/// Nothing has ever been registered under it, which is the reason to read it
/// rather than to leave a bracketed literal that is not an IPv6 address as a
/// finding: the production exists, and a rule that reports what a grammar
/// generates is wrong however unlikely the value.
// cite(RFC 3986 § 3.2.2): "IPvFuture  = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )"
fn is_ipvfuture(s: &str) -> bool {
    let Some(rest) = s.strip_prefix(['v', 'V']) else {
        return false;
    };
    let Some(dot) = rest.find('.') else {
        return false;
    };
    let (version, tail) = (&rest[..dot], &rest[dot + 1..]);
    if version.is_empty() || !version.chars().all(|c| c.is_ascii_hexdigit()) {
        return false;
    }
    !tail.is_empty()
        && tail
            .chars()
            .all(|c| is_unreserved(c) || is_sub_delim(c) || c == ':')
}

/// Where the `uri-host` ends and `":" port` begins, with neither half examined.
///
/// Only a colon after the closing bracket separates a port: every colon inside an
/// IP literal belongs to the address, and the brackets are the only thing marking
/// where it stopped.
///
/// The port half is `Some("")` for a value ending in its delimiter, because that
/// is a real distinction: `port` is `*DIGIT`, so `example.com:` carries a port of
/// no digits and `example.com` carries no port at all. Two productions one bracket
/// apart tell those cases apart -- `Host = uri-host [ ":" port ]` generates both,
/// `authority-form = uri-host ":" port` only the first -- so a caller reading the
/// stricter one asks for the `Some` and a caller reading `Host` does not care.
// cite(RFC 3986 § 3.2.2): "A host identified by an Internet Protocol literal address, version 6 [RFC3513] or later, is distinguished by enclosing the IP literal within square brackets ("[" and "]")."
// cite(RFC 3986 § 3.2.2): "This is the only place where square bracket characters are allowed in the URI syntax."
// cite(RFC 3986 § 3.2.3): "The port subcomponent of authority is designated by an optional port number in decimal following the host and delimited from it by a single colon (":") character."
pub fn split_host_and_port(value: &str) -> (&str, Option<&str>) {
    let colon = match value.starts_with('[') {
        true => value.find(']').and_then(|close| {
            value[close + 1..]
                .find(':')
                .map(|offset| close + 1 + offset)
        }),
        false => value.find(':'),
    };

    match colon {
        Some(i) => (&value[..i], Some(&value[i + 1..])),
        None => (value, None),
    }
}

/// The port a run of digits designates, or `None` when it designates none.
///
/// **This is not `port`'s grammar and must never be confused for it.**
/// `port = *DIGIT` bounds nothing at either end, which is why
/// [`validate_host_and_optional_port`] declines the range and why
/// `host_header` reports no port for being out of range. What this
/// answers is the *other* question — whether the number lands in the sixteen-bit
/// namespace a transport registers its ports in — and **the licence to ask it is
/// the caller's**, because it takes a sentence naming the transport or the type.
/// Its three callers each carry their own: RFC 9113 § 8.5's TCP connection for a
/// CONNECT `:authority`, RFC 7838 § 2's ALPN-name-includes-TLS for an
/// `alt-authority`, and the URL Standard's *16-bit unsigned integer* for a
/// serialized origin, which is the only one of the three where the width is
/// stated of the value itself rather than reached through the transport.
///
/// **`0` is a port.** It is inside the namespace — a reserved value at the edge
/// of a range, held back for extending the ranges later — and reserved is not
/// invalid. Two of the three callers already read it that way after their own
/// audits; the third rejected it, so `Origin: https://example.com:0` was not a
/// serialized origin.
///
/// Empty and non-digit inputs are `None` too, which is the same answer for a
/// different reason: they derive from no `port` at all. A caller wanting to tell
/// the two apart measures the characters first, and all three do.
// cite(RFC 3986 § 3.2.3): "The port subcomponent of authority is designated by an optional port number in decimal following the host and delimited from it by a single colon (":") character."
// cite(RFC 6335 § 6): "TCP, UDP, UDP-Lite, SCTP, and DCCP use 16-bit namespaces for their port number registries."
// cite(RFC 6335 § 6): "Reserved port numbers include values at the edges of each range, e.g., 0, 1023, 1024, etc., which may be used to extend these ranges or the overall port number space in the future."
pub fn port_number(digits: &str) -> Option<u16> {
    if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    // Sixteen bits, written as sixteen bits rather than as the literal 65535:
    // the width is the whole of what the cited sentence says, and a type cannot
    // be spelled wrong. A `*DIGIT` of any length either fits or overflows, and
    // both mean the same thing here — a number outside the namespace — so the
    // overflow is the answer rather than an early return.
    //
    // The digit scan above is what makes this parser safe to reach for: on its
    // own, `u16::from_str` accepts a leading '+', which no `*DIGIT` writes.
    digits.parse::<u16>().ok()
}

/// Validate a `Host` field value: a `uri-host` and, optionally, a port.
///
/// The port is `*DIGIT` — no upper bound and no lower one. A number no
/// transport could carry is a syntax question for nobody, and a colon with
/// nothing after it is a port of no digits, which is what the second sentence
/// below is addressing when it asks a URI producer to leave the delimiter off
/// as well. A rule wanting the TCP range wants a different sentence than these.
// cite(RFC 9110 § 7.2, label: Host grammar): "Host = uri-host [ ":" port ]"
// cite(RFC 3986 § 3.2.3): "The port subcomponent of authority is designated by an optional port number in decimal following the host and delimited from it by a single colon (":") character."
// cite(RFC 3986 § 3.2.3): "URI producers and normalizers should omit the port component and its ":" delimiter if port is empty or if its value would be the same as that of the scheme's default."
pub fn validate_host_and_optional_port(value: &str) -> Result<(), HostAndPortDefect<'_>> {
    let (host, port) = split_host_and_port(value);

    validate_uri_host(host).map_err(HostAndPortDefect::Host)?;

    if let Some(port) = port {
        if let Some(c) = port.chars().find(|c| !c.is_ascii_digit()) {
            return Err(HostAndPortDefect::PortCharacter { character: c, port });
        }
    }
    Ok(())
}

/// What a `uri-host [ ":" port ]` fails to be.
///
/// Two halves and therefore two variants: everything the host can be wrong
/// about is [`UriHostDefect`]'s and is nested rather than flattened, because a
/// host is the same production wherever it is read and this composition adds
/// nothing to it. What the composition does add is the second half — a `port`
/// of `*DIGIT` — and that is the only defect spelled out here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostAndPortDefect<'a> {
    /// The `uri-host` half.
    Host(UriHostDefect<'a>),
    /// A character in the port that is not a `DIGIT`. There is no out-of-range
    /// variant beside it: `port = *DIGIT` bounds nothing at either end, and a
    /// rule wanting the transport's namespace wants [`port_number`] and a
    /// sentence of its own.
    PortCharacter {
        /// The character.
        character: char,
        /// The port it was found in.
        port: &'a str,
    },
}

impl HostAndPortDefect<'_> {
    /// The finding fragment.
    pub fn message(self) -> String {
        match self {
            Self::Host(defect) => defect.message(),
            Self::PortCharacter { character, port } => {
                format!("invalid character '{}' in port '{}'", character, port)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::scheme::scheme_authority_marker;

    /// § 3.2.1's sentence names the *first* colon and exempts an empty tail:
    /// only a nonempty secret is elided, and everything else comes back `None`
    /// so the caller shows the value as written.
    #[test]
    fn userinfo_password_withheld_elides_only_a_nonempty_secret() {
        use super::userinfo_password_withheld;
        assert_eq!(
            userinfo_password_withheld("user:s3cret@h:1"),
            Some("user:...@h:1".into())
        );
        // The first colon decides; later ones are part of the secret and go
        // with it.
        assert_eq!(
            userinfo_password_withheld("user:a:b@h"),
            Some("user:...@h".into())
        );
        assert_eq!(userinfo_password_withheld("user:@h"), None);
        assert_eq!(userinfo_password_withheld("user@h"), None);
        assert_eq!(userinfo_password_withheld("h:1"), None);
    }

    /// What `helpers::ipv6::parse_bracketed_ipv6` used to assert, asked of the
    /// pair that replaced it — and the case it could not answer, which is why it
    /// went: it handed the bracketed content back unexamined, so `[foo]` was a
    /// host to every caller that did not re-examine it, and no caller did.
    #[test]
    fn a_bracketed_host_is_split_and_then_measured() {
        assert_eq!(split_host_and_port("[::1]"), ("[::1]", None));
        assert_eq!(split_host_and_port("[::1]:443"), ("[::1]", Some("443")));
        assert_eq!(
            split_host_and_port("[fe80::1]:80"),
            ("[fe80::1]", Some("80"))
        );
        // The colon belongs to the address, not to a port, and the bracket is
        // what says so.
        assert_eq!(split_host_and_port("[::1]:"), ("[::1]", Some("")));

        assert!(validate_uri_host("[::1]").is_ok());
        assert!(validate_uri_host("[fe80::1]").is_ok());
        // `IPvFuture` is the other alternative of `IP-literal`, and it used to
        // pass here by accident rather than by the production.
        assert!(validate_uri_host("[v7.abc]").is_ok());

        // Four bracket defects that `is_err()` reported as one. The last is not
        // an IP literal that went wrong — it never opened one, and the bracket
        // it carries appears in no host form.
        assert_eq!(
            validate_uri_host("[foo]"),
            Err(UriHostDefect::NotAnIpLiteral("foo"))
        );
        assert_eq!(
            validate_uri_host("[]"),
            Err(UriHostDefect::NotAnIpLiteral(""))
        );
        assert_eq!(
            validate_uri_host("[::1"),
            Err(UriHostDefect::UnclosedBracket("[::1"))
        );
        assert_eq!(
            validate_uri_host("[::1]extra"),
            Err(UriHostDefect::UnclosedBracket("[::1]extra"))
        );
        assert_eq!(
            validate_uri_host("2001:db8::1]"),
            Err(UriHostDefect::Bracket("2001:db8::1]"))
        );
    }

    #[test]
    fn uri_host_accepts_what_reg_name_generates() {
        for host in [
            "example.com",
            "EXAMPLE.com",
            "a(b)c",
            "a,b;c=d",
            "%41%42",
            "192.0.2.1",
            // A dotted quad out of range is still a registered name.
            "999.999.999.999",
            "",
            "[2001:db8::1]",
            "[::ffff:192.0.2.1]",
            "[v7.host:name]",
        ] {
            assert!(validate_uri_host(host).is_ok(), "{host}");
        }
        // The rejections, each as the thing it is: an alphabet defect, a
        // malformed triplet, or one of the three bracket answers.
        for (host, want) in [
            (
                "exa mple",
                UriHostDefect::BadCharacter {
                    character: ' ',
                    host: "exa mple",
                },
            ),
            (
                "user@host",
                UriHostDefect::BadCharacter {
                    character: '@',
                    host: "user@host",
                },
            ),
            (
                "a^b",
                UriHostDefect::BadCharacter {
                    character: '^',
                    host: "a^b",
                },
            ),
            (
                "a|b",
                UriHostDefect::BadCharacter {
                    character: '|',
                    host: "a|b",
                },
            ),
            (
                "a\"b",
                UriHostDefect::BadCharacter {
                    character: '"',
                    host: "a\"b",
                },
            ),
            (
                "%4",
                UriHostDefect::PercentEncoding(PercentEncodingDefect::Incomplete),
            ),
            (
                "%zz",
                UriHostDefect::PercentEncoding(PercentEncodingDefect::NotHexDigits("%zz")),
            ),
            (
                "[2001:db8::1",
                UriHostDefect::UnclosedBracket("[2001:db8::1"),
            ),
            (
                "[not-an-address]",
                UriHostDefect::NotAnIpLiteral("not-an-address"),
            ),
            ("2001:db8::1]", UriHostDefect::Bracket("2001:db8::1]")),
        ] {
            assert_eq!(validate_uri_host(host), Err(want), "{host}");
        }
    }

    #[test]
    fn a_delimiter_with_nothing_after_it_is_not_the_same_as_no_delimiter() {
        // The distinction `validate_host_and_optional_port` discards, and the
        // reason this split is its own function: `Host = uri-host [ ":" port ]`
        // generates both, `authority-form = uri-host ":" port` only the first.
        assert_eq!(
            split_host_and_port("example.com:"),
            ("example.com", Some(""))
        );
        assert_eq!(split_host_and_port("example.com"), ("example.com", None));
        assert_eq!(split_host_and_port(":80"), ("", Some("80")));
        assert_eq!(split_host_and_port(":"), ("", Some("")));
        assert_eq!(split_host_and_port(""), ("", None));
        // Every colon inside the brackets belongs to the address; only one after
        // the closing bracket separates a port.
        assert_eq!(split_host_and_port("[::1]:443"), ("[::1]", Some("443")));
        assert_eq!(split_host_and_port("[::1]"), ("[::1]", None));
        assert_eq!(split_host_and_port("2001:db8::1"), ("2001", Some("db8::1")));
    }

    #[test]
    fn host_port_is_star_digit() {
        // `port = *DIGIT` bounds nothing: no minimum, so a colon with nothing
        // after it is a port, and no maximum, so a number no transport could
        // carry is not a syntax question.
        for value in [
            "example.com",
            "example.com:80",
            "example.com:",
            "example.com:0",
            "example.com:99999",
            "[2001:db8::1]:8080",
            "[2001:db8::1]",
        ] {
            assert!(validate_host_and_optional_port(value).is_ok(), "{value}");
        }
        for value in ["example.com:8o8", "exa mple:80", "2001:db8::1", "[::1]x:80"] {
            assert!(validate_host_and_optional_port(value).is_err(), "{value}");
        }
    }

    /// The three axes the four readers of this question used to disagree on:
    /// which characters terminate the component, whether an empty authority is
    /// an authority, and how close the `//` has to sit to the scheme's colon.
    #[test]
    fn authority_component_reads_section_3_2s_sentence_and_nothing_else() {
        // All three terminators, and the end of the value.
        assert_eq!(
            authority_component("http://example.com/p"),
            Some("example.com")
        );
        assert_eq!(
            authority_component("http://example.com?x=1"),
            Some("example.com")
        );
        assert_eq!(
            authority_component("http://example.com#f"),
            Some("example.com")
        );
        assert_eq!(
            authority_component("http://example.com"),
            Some("example.com")
        );
        // The `//` is what the search is for; a scheme in front of it is
        // optional, and a network-path reference carries one without any.
        assert_eq!(authority_component("//example.com/p"), Some("example.com"));
        // Every subcomponent stays in: this function answers where the
        // component ends and nothing about what is inside it.
        assert_eq!(
            authority_component("http://user:pass@[::1]:8080/p"),
            Some("user:pass@[::1]:8080")
        );
        // `Some("")` and `None` are different answers — `reg-name` is
        // `*( ... )`, so the first value carries an empty authority and the
        // second carries none.
        assert_eq!(authority_component("http://"), Some(""));
        assert_eq!(authority_component("http:///p"), Some(""));
        assert_eq!(authority_component("http:/p"), None);
        // No `//` at all, in each of the forms that reach this.
        for none in ["/p", "p", "", "mailto:a@b", "example.com:443", "*", "?x"] {
            assert_eq!(authority_component(none), None, "{none}");
        }
        // The `//` must follow the scheme's colon immediately. Here the scheme
        // is `a` and `b://c` is a `path-rootless`, so the value carries no
        // authority — which a bare search for `://` reads the other way.
        assert_eq!(authority_component("a:b://c"), None);
        assert!(scheme_authority_marker("a:b://c").is_some());
    }

    /// The axis the three copies of this predicate disagreed on was `0`, and
    /// the ones either side of the namespace are what it is not.
    #[test]
    fn port_number_holds_the_sixteen_bit_namespace_including_its_reserved_edge() {
        assert_eq!(port_number("0"), Some(0));
        assert_eq!(port_number("1"), Some(1));
        assert_eq!(port_number("443"), Some(443));
        assert_eq!(port_number("65535"), Some(65535));
        assert_eq!(port_number("65536"), None);
        // A `*DIGIT` has no length bound, so an overflow is an answer rather
        // than an early return.
        assert_eq!(port_number("999999999999999999999999"), None);
        // Leading zeros are digits: `port = *DIGIT` writes no canonical form,
        // and the number is what it is.
        assert_eq!(port_number("080"), Some(80));
        assert_eq!(port_number("00000"), Some(0));
        // Not a run of digits at all, which is a different reason for the same
        // answer — `u16::from_str` would have taken the sign.
        assert_eq!(port_number(""), None);
        assert_eq!(port_number("+80"), None);
        assert_eq!(port_number("-1"), None);
        assert_eq!(port_number("8o8"), None);
        assert_eq!(port_number(" 80"), None);
    }

    #[test]
    fn userinfo_is_split_at_the_last_at_sign() {
        assert_eq!(split_userinfo("example.com"), (None, "example.com"));
        assert_eq!(
            split_userinfo("user@example.com"),
            (Some("user"), "example.com")
        );
        assert_eq!(
            split_userinfo("user:pass@example.com:8080"),
            (Some("user:pass"), "example.com:8080")
        );
        // No `userinfo` and no `reg-name` holds an at-sign, so a second one
        // derives from nothing; the host half stays the short one.
        assert_eq!(
            split_userinfo("a@b@example.com"),
            (Some("a@b"), "example.com")
        );
        // The delimiter with nothing before it is a present-but-empty userinfo,
        // which `*( ... )` generates.
        assert_eq!(split_userinfo("@example.com"), (Some(""), "example.com"));
        assert_eq!(split_userinfo(""), (None, ""));
    }
}
