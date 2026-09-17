// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! An origin: a scheme, the `://` after it, and an authority — with nothing at
//! all following.
//!
//! **The absence is the production**, and it is why this is not a corner of the
//! authority module. `serialized-origin = scheme "://" host [ ":" port ]` writes
//! no path, no query and no fragment, which is the whole point of the field that
//! carries one: an origin says where a request came from without saying what it
//! was reading. So a value RFC 3986 generates happily — `https://example.com/p`
//! — derives from nothing here, and the finding is not that a production broke
//! but that a different one was used.
//!
//! **Two documents write the grammar and both are quoted**, because the two
//! callers that read a field value take theirs from Fetch, whose production
//! supplants RFC 6454's. They agree on the shape checked here; where they differ
//! Fetch is the stricter, and this module is deliberately permissive in that
//! direction — it accepts host shapes (IDNA, label syntax) Fetch's serialization
//! would reject, because a `reg-name` is a character set and no more.
//!
//! **None of the three parts is transcribed here.** The scheme is
//! [`super::scheme::validate_scheme_name`]'s, the host
//! [`super::authority::validate_uri_host`]'s, the port
//! [`super::authority::port_number`]'s, and where an authority ends is
//! [`super::authority::authority_component`]'s § 3.2 sentence. What is left is
//! the composition, which is the only thing this module can get wrong — and it
//! did, twice, in the same way both times: by enumerating one of the three
//! characters that terminate an authority instead of asking the reader that
//! knows all three, so `?` and `#` stayed acceptable for as long as `/` did not.
//!
//! **The predicate lived in the module named for the header map until it was
//! shelved by its question**, and that is where the third copy of the scheme
//! production hid — a copy the two extractions that preceded it did not count,
//! because nobody looks for a URI grammar under a field name.

use crate::helpers::authority::{
    authority_component, port_number, split_host_and_port, validate_uri_host,
};
use crate::helpers::headers::trim_ows;
use crate::helpers::scheme::{
    scheme_authority_marker, scheme_if_present, scheme_prefix, validate_scheme_name,
    SchemeNameDefect,
};
use crate::helpers::uri::find_non_uri_char;
/// If `s` is an absolute-form request-target or full URI, return the origin
/// component as `scheme://host[:port]`. Returns `None` if input is not absolute
/// or if it does not contain a valid origin.
pub fn extract_origin_if_absolute(s: &str) -> Option<String> {
    // An origin is a scheme, the `://` between them, and an authority — so it is
    // rebuilt from its two parts rather than sliced out of the value by
    // arithmetic over their lengths. Where the authority ends is
    // [`authority_component`]'s question and § 3.2's sentence: `path-abempty`
    // may be empty, so `http://example.com?x=1` is a legal absolute-form target
    // whose authority ends before the query.
    //
    // Requiring a scheme is what makes this *absolute*-form only. A network-path
    // reference carries an authority and no scheme, and it has no origin.
    let scheme = scheme_prefix(s)?;
    let authority = authority_component(s)?;
    if authority.is_empty() {
        return None;
    }
    let origin = format!("{scheme}://{authority}");

    // Basic validation: the scheme is a scheme, and every character is one a URI
    // may be written with. The second was `contains_whitespace`, which asked one
    // sixth of that question — SP, HTAB, CR, LF and FF, and not `<`, `>`, `"`,
    // `{`, `}`, `|`, `\`, `^`, `` ` `` or any octet at or above %x80. A value
    // holding one of those is not a URI, so it carries no origin, which is what
    // this function's `None` says. The narrower `reg-name` alphabet is a
    // different question and not this function's: what an authority may hold is
    // asked where an authority is *validated*, and this one is reconstructing.
    if scheme_if_present(&origin).is_some() {
        return None;
    }
    if find_non_uri_char(&origin).is_some() {
        return None;
    }
    Some(origin)
}

/// Why an `Origin` field value derives from neither alternative of
/// `origin-list-or-null`.
///
/// The rendered `Option<String>` this replaced carried four sentences, and one
/// of them — *"Invalid scheme in Origin"* — was a [`SchemeNameDefect`] that had
/// already been typed and was then thrown away at the door. That is 2.5's
/// correction in miniature: a `String` between a typed reader and its two
/// callers hides which production was broken, and the catalogue cannot name
/// what it cannot see.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginDefect<'a> {
    /// A `/` after the authority. `serialized-origin = scheme "://" host [ ":"
    /// port ]` has no path component at all, which is the whole point of the
    /// field: an origin says where a request came from without saying what it
    /// was reading. No production is broken by the slash — the value simply
    /// derives from a different rule of RFC 3986 — so this stays the field's own
    /// finding.
    PathPresent,
    /// The characters before the `://` are not a scheme name.
    Scheme(SchemeNameDefect<'a>),
    /// A character no part of a URI is composed from.
    Character(char),
    /// Neither `null` nor anything a `serialized-origin` generates: no `://`
    /// at all, or an authority the shared predicate refuses. **Deriving from
    /// none of my alternatives is what the catalogue cannot name**, which is why
    /// this variant carries no id and the two callers word it themselves.
    NotSerialized,
}

impl OriginDefect<'_> {
    /// The finding fragment.
    pub fn message(self) -> String {
        match self {
            Self::PathPresent => "Origin must not include a path".to_string(),
            Self::Scheme(defect) => format!("Invalid scheme in Origin: {}", defect.message()),
            Self::Character(c) => format!(
                "Origin holds {}, which no part of a URI is composed from",
                crate::helpers::shown::describe_char(c)
            ),
            Self::NotSerialized => "Origin is not a valid serialized origin".to_string(),
        }
    }
}

/// Validate an `Origin` header value. Accepts `null` or a serialized origin
/// of the form `scheme://host[:port]`, and answers with the typed defect
/// otherwise.
pub fn validate_origin_value(s: &str) -> Result<(), OriginDefect<'_>> {
    let s_trim = trim_ows(s);
    // The `%x6E %x75 %x6C %x6C` hex literals spell lowercase `null` byte-for-byte,
    // so the comparison is case-sensitive.
    // cite(RFC 6454 § 7.1): "origin-list-or-null = %x6E %x75 %x6C %x6C / origin-list"
    if s_trim == "null" {
        return Ok(());
    }
    // Must be an origin (absolute with no path). The grammar has no path component,
    // which is the whole point of the header: an origin reveals where a request came
    // from without revealing what it was reading.
    // cite(RFC 6454 § 7.1): "serialized-origin = scheme "://" host [ ":" port ]"
    if let Some(colon_pos) = scheme_authority_marker(s_trim) {
        // no path allowed
        if s_trim[colon_pos + 3..].contains('/') {
            return Err(OriginDefect::PathPresent);
        }
        if let Some(defect) = scheme_if_present(s_trim) {
            return Err(OriginDefect::Scheme(defect));
        }
        // The alphabet, before the authority question below it. This was
        // `contains_whitespace`, one sixth of the same set, so an `Origin` value
        // holding `<`, `` ` `` or an octet at or above %x80 reached the
        // serialized-origin predicate — which asks where the authority ends and
        // not what it may hold — and was returned valid.
        //
        // A floor rather than a ceiling: `reg-name` is narrower than the
        // URI-wide alphabet, so a character passing here has only been found
        // somewhere in the generic syntax.
        //
        // cite(RFC 3986 § 2): "A URI is composed from a limited set of characters consisting of digits, letters, and a few graphic symbols."
        if let Some(c) = find_non_uri_char(s_trim) {
            return Err(OriginDefect::Character(c));
        }
        // The authority itself — host present, bracketed IPv6 well formed, port
        // numeric and in range, no userinfo — is checked by the shared
        // serialized-origin predicate rather than a second hand-written copy, so
        // the two validators cannot drift apart on what an origin is. A lack of
        // host reports the same generic reason, so callers that inspect the
        // string do not need to handle multiple error forms.
        if !is_valid_serialized_origin(s_trim) {
            return Err(OriginDefect::NotSerialized);
        }
        return Ok(());
    }

    Err(OriginDefect::NotSerialized)
}

/// Validate a serialized-origin as defined by RFC 6454: scheme "://" host [":" port]
/// The grammar has no path component, so nothing may follow the authority — not
/// even a bare trailing slash, which a byte-for-byte origin comparison rejects.
///
/// **Each of the three parts is read by the function that owns its production**,
/// and none of them is transcribed here: [`validate_scheme_name`]
/// for `scheme`, [`validate_uri_host`] for `host`, and
/// [`port_number`] for `port`. What is left is the
/// composition — the `://` between the first two, and that the authority is the
/// whole of what follows it.
///
/// **It measured where the authority ended and nothing about what it held.** The
/// host was checked for emptiness, a space, a tab and an at-sign, so
/// `https://exa|mple.com`, `https://a<b>c` and `https://a^b` were serialized
/// origins — none of `|`, `<`, `>`, `^`, `` ` ``, `\`, `"`, `{`, `}` or any octet
/// at or above %x80 is in `unreserved`, `sub-delims` or a `pct-encoded`, so none
/// is in any `reg-name`. Two more went with it: `%zz` and `%4` passed because
/// nothing asked `check_percent_encoding`, and `https://[foo]` passed because
/// `helpers::ipv6::parse_bracketed_ipv6` handed its bracketed content back
/// unexamined — which its own doc comment said in as many words, and which was
/// what condemned it: this was its last caller and the function is gone.
///
/// **The conservatism that remains is about IDNA and label syntax**, which is a
/// different question from the alphabet: a `reg-name` is a character set and no
/// more, so `a..b` and a 300-character label are registered names here and are
/// not domains anywhere.
///
/// **"Nothing may follow the authority" is § 3.2's sentence, and it names three
/// characters.** This function used to enumerate one of them — a
/// `rest.contains('/')` — so `https://example.com?x=1` and
/// `https://example.com#f` were serialized origins to every caller. The
/// terminators are not re-enumerated here now:
/// [`authority_component`] is where that sentence is read
/// and cited, and what this function adds is the *grammar's* half — a
/// serialized-origin ends where its authority does, so any character that
/// function stopped at is a character the production does not generate.
// Both callers (Timing-Allow-Origin, Access-Control-Allow-Origin) take their value
// grammar from Fetch, whose production supplants RFC 6454's. The two agree on the
// shape checked here — an authority and nothing after it — so both are quoted.
// cite(Fetch § 3.2): "serialized-origin = serialized-scheme "://" serialized-host [ ":" serialized-port ]"
// cite(Fetch § 3.2): "This supplants the definition in The Web Origin Concept"
// cite(RFC 6454 § 7.1): "serialized-origin = scheme "://" host [ ":" port ]"
// Where they differ, Fetch is the stricter of the two, which is the direction this
// validator is deliberately permissive in: it accepts host shapes (IDNA, label
// syntax) that Fetch's serialization would reject.
// cite(Fetch § 3.2): "The origin serialization defined here is more constrained than [RFC3986]’s grammar in two substantial ways."
pub fn is_valid_serialized_origin(val: &str) -> bool {
    let s = trim_ows(val);
    if s.is_empty() {
        return false;
    }

    // The `://` is located rather than split on, because a `://` further along
    // is data rather than a delimiter: `scheme_authority_marker` is that
    // question's one answer and argues at its own site why `find("://")` is not.
    let Some(marker) = scheme_authority_marker(s) else {
        return false;
    };
    let scheme = &s[..marker];

    // `scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )` was written out here
    // a third time, and `validate_scheme_name`'s own doc comment already counts
    // the two copies it was extracted from. This one was missed because it sits
    // in `helpers::headers`, on the shelf keyed by the field rather than by the
    // question — the same reason the sixteen-bit port predicate was missed.
    if validate_scheme_name(scheme).is_err() {
        return false;
    }

    // Where the authority ends is § 3.2's sentence and not this function's; the
    // grammar above is what makes stopping short of the value's end a defect,
    // since a serialized-origin is a scheme, a `://` and an authority and
    // nothing else. Enumerating the terminators here instead is how `?` and `#`
    // stayed acceptable for as long as `/` did not.
    let Some(rest) = authority_component(s) else {
        return false;
    };
    if rest != &s[marker + "://".len()..] {
        return false;
    }

    // `authority = [ userinfo "@" ] host [ ":" port ]` is the production this
    // one is *not*: the origin grammars above write `host [ ":" port ]` and no
    // userinfo, so the at-sign that would delimit one is a character no
    // `reg-name` holds and `validate_uri_host` refuses it as such. The split is
    // at the first colon and bracket-aware, which is why an `IP-literal`'s own
    // colons do not become a port.
    // cite(RFC 3986 § 3.2, label: authority grammar): "authority   = [ userinfo "@" ] host [ ":" port ]"
    let (host, port) = split_host_and_port(rest);

    // `reg-name = *( unreserved / pct-encoded / sub-delims )` derives the empty
    // string, so this is not the grammar's line. An origin naming no host names
    // nothing to compare against, and every caller here is comparing origins.
    if host.is_empty() {
        return false;
    }
    if validate_uri_host(host).is_err() {
        return false;
    }

    // Sixteen bits, and the licence to ask that of *this* value is the URL
    // Standard's rather than a transport's: an origin's port is not a run of
    // digits that happens to reach a TCP port, it is declared to be an integer
    // of that width. `0` is one of them, so an origin naming it is a serialized
    // origin; the shared reader rejected it until this was read.
    // cite(URL § 4.1): "A URL’s port is either null or a 16-bit unsigned integer that identifies a networking port."
    match port {
        Some(port) => port_number(port).is_some(),
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_origin_if_absolute_cases() {
        assert_eq!(extract_origin_if_absolute("/relative"), None);
        assert_eq!(
            extract_origin_if_absolute("http://example.com/path"),
            Some("http://example.com".into())
        );
        assert_eq!(
            extract_origin_if_absolute("https://example.com:8080"),
            Some("https://example.com:8080".into())
        );
        assert_eq!(extract_origin_if_absolute("not-a-scheme//no"), None);
    }

    /// The trim is `OWS`, so an `obs-text` octet at the edge of a value stays
    /// in it — where `str::trim` took U+00A0 off and pronounced the rest valid.
    #[test]
    fn an_obs_text_octet_at_the_edge_is_part_of_the_value() {
        let padded: String = std::iter::once('\u{a0}')
            .chain("https://example.com".chars())
            .collect();
        assert!(validate_origin_value(&padded).is_err());
        assert!(!is_valid_serialized_origin(&padded));
        // The `OWS` a field value may carry beside its content is still taken.
        assert!(validate_origin_value(" https://example.com\t").is_ok());
    }

    #[test]
    fn validate_origin_value_cases() {
        assert!(validate_origin_value("null").is_ok());
        assert!(validate_origin_value("NULL").is_err());
        assert!(validate_origin_value("https://example.com").is_ok());
        assert!(validate_origin_value("http:///bad").is_err());
        assert!(validate_origin_value("https://exa mple").is_err());
        assert!(validate_origin_value("invalid-origin").is_err());
        // The authority is validated too, not merely required to be non-empty.
        assert!(validate_origin_value("http://host:notaport").is_err());
        assert!(validate_origin_value("https://user@example.com").is_err());
        // A port outside the sixteen-bit namespace is the finding; `0` is
        // inside it, reserved rather than invalid.
        assert!(validate_origin_value("http://example.com:65536").is_err());
        assert!(validate_origin_value("http://example.com:0").is_ok());
    }

    /// The four variants, each named and each rendered — the split between them
    /// is a decision rather than a coincidence, which is why the messages are
    /// pinned beside the variants.
    #[test]
    fn each_origin_defect_names_the_production_it_broke() {
        // The scheme half was already typed and the rendered `String` this
        // enum replaced threw the type away at the door.
        let m = validate_origin_value("1http://example.com")
            .expect_err("a leading digit is no scheme name");
        assert!(matches!(m, OriginDefect::Scheme(_)), "{m:?}");
        assert!(m.message().contains("Invalid scheme"), "{}", m.message());

        // This function names the path itself, because § 3.2's *first*
        // terminator is the one an `Origin` sender most plausibly wrote by
        // accident. The other two are the shared predicate's answer and get its
        // generic reason — which is what the comment at the delegation says
        // callers may rely on, and the two messages are asserted here so the
        // split between them is a decision and not a coincidence.
        // The alphabet, at the two callers `contains_whitespace` was left
        // running at. Neither could see a character outside the URI set that was
        // not whitespace, so `<` reached the serialized-origin predicate — which
        // asks where the authority *ends*, not what it may hold — and passed.
        let angle = validate_origin_value("https://exa<mple.com").expect_err("no URI holds '<'");
        assert_eq!(angle, OriginDefect::Character('<'));
        assert_eq!(
            angle.message(),
            "Origin holds '<', which no part of a URI is composed from"
        );
        assert_eq!(extract_origin_if_absolute("http://exa<mple.com/p"), None);
        assert_eq!(
            extract_origin_if_absolute("http://exa\u{ff}mple.com/p"),
            None
        );

        let path = validate_origin_value("https://example.com/p")
            .expect_err("a serialized origin has no path component");
        assert_eq!(path, OriginDefect::PathPresent);
        assert_eq!(path.message(), "Origin must not include a path");
        for after in ["https://example.com?x=1", "https://example.com#frag"] {
            assert_eq!(
                validate_origin_value(after).expect_err("neither alternative"),
                OriginDefect::NotSerialized,
                "for {after}"
            );
        }
    }

    #[test]
    fn extract_origin_invalid_scheme_whitespace_and_missing_authority() {
        // invalid scheme (does not start with alphabetic)
        assert_eq!(extract_origin_if_absolute("1http://example.com"), None);
        // whitespace in authority
        assert_eq!(extract_origin_if_absolute("http://exa mple"), None);
        // missing authority (empty after scheme)
        assert_eq!(extract_origin_if_absolute("http://"), None);
    }

    #[test]
    fn validate_origin_missing_host_reports_missing() {
        // An authority the shared predicate refuses is the same verdict as no
        // `://` at all: the value derives from neither alternative, and that is
        // one variant rather than a specialized sentence per way of failing.
        let m = validate_origin_value("http://").expect_err("an origin needs a host");
        assert_eq!(m, OriginDefect::NotSerialized);
        assert!(m.message().contains("not a valid serialized origin"));
    }

    #[test]
    fn test_is_valid_serialized_origin() {
        const CASES: &[(&str, bool)] = &[
            ("https://example.com", true),
            ("http://example.com:8080", true),
            ("https://localhost", true),
            ("https://[::1]:8080", true),
            ("https://[::1]", true),
            // Port range & formatting.
            ("http://example.com:1", true),
            ("http://example.com:65535", true),
            ("http://example.com:080", true), // leading zero allowed -> 80
            // `0` is a 16-bit unsigned integer and RFC 6335 §6 calls it a value
            // *inside* the namespace, reserved rather than invalid. This asserted
            // the opposite until the port reading was shared with the two rules
            // that had already audited the bound.
            ("http://example.com:0", true),
            ("http://example.com:65536", false), // out of range
            ("http://example.com:999999999999", false), // too large
            // The grammar has no path component, and a browser compares the value
            // byte-for-byte against a serialized origin, which never carries one.
            ("https://example.com/", false),
            ("https://example.com/path", false),
            ("https://example.com:8080/", false),
            ("https://[::1]/path", false),
            // § 3.2 ends the authority at three characters and the slash is one of
            // them. The other two were accepted here until the terminator sentence
            // stopped being enumerated by hand — and only in the shape below,
            // because a port or a bracketed literal put the trailing junk in front
            // of a reader that was already strict about it.
            ("https://example.com?x=1", false),
            ("https://example.com#frag", false),
            ("https://example.com?", false),
            ("https://example.com#", false),
            ("https://example.com:8080?x=1", false),
            ("https://[::1]#frag", false),
            ("example.com", false),
            ("https:///foo", false),
            ("https://", false),
            ("http://host:notaport", false),
            ("https://user@example.com", false),
            ("https://[::1", false),
            ("", false),
        ];

        for (value, is_origin) in CASES {
            assert_eq!(
                is_valid_serialized_origin(value),
                *is_origin,
                "for {value:?}"
            );
        }
    }

    #[test]
    fn an_origins_host_is_measured_against_its_own_production() {
        // **The host's own alphabet, which nothing here used to ask.** None of
        // these is in `unreserved`, `sub-delims` or a `pct-encoded`, so none is
        // in any `reg-name` — and each was a serialized origin to all three
        // callers while the host was checked for emptiness, a space, a tab and
        // an at-sign and for nothing else.
        for c in [
            '|', '<', '>', '"', '{', '}', '\\', '^', '`', '\u{80}', '\u{ff}',
        ] {
            assert!(
                !is_valid_serialized_origin(&format!("https://exa{c}mple.com")),
                "for {c:?}"
            );
            assert!(
                !is_valid_serialized_origin(&format!("https://exa{c}mple.com:8080")),
                "for {c:?} with a port"
            );
        }

        // A `pct-encoded` is three characters and the last two are `HEXDIG`. The
        // alphabet walk alone would admit these, which is why `validate_uri_host`
        // asks `check_percent_encoding` before it.
        assert!(!is_valid_serialized_origin("https://a%zzb.example"));
        assert!(!is_valid_serialized_origin("https://a%4"));
        assert!(is_valid_serialized_origin("https://a%41b.example"));

        // `IP-literal = "[" ( IPv6address / IPvFuture ) "]"`, and the inner text
        // used to be handed back unexamined — so a bracketed anything was a
        // host. `[v7.abc]` passed then for no reason and passes now for the
        // production's.
        assert!(!is_valid_serialized_origin("https://[foo]"));
        assert!(!is_valid_serialized_origin("https://[]"));
        assert!(is_valid_serialized_origin("https://[v7.abc]"));

        // A `reg-name` holds no colon, so the second one is not a port
        // delimiter; the split is at the first colon and this used to be read
        // right to left, which made `a:b` a host and `80` its port.
        assert!(!is_valid_serialized_origin("https://a:b:80"));

        // The explicit space and tab checks went with the host's own production,
        // which admits neither -- and `port_number` refuses a non-digit, so the
        // other half of the authority is covered by the reader that owns it.
        assert!(!is_valid_serialized_origin("https://exa mple.com"));
        assert!(!is_valid_serialized_origin("https://exa\tmple.com"));
        assert!(!is_valid_serialized_origin("https://example.com: 80"));
        assert!(!is_valid_serialized_origin("https://example.com:8 0"));
    }

    /// Each row is a value that is not a serialized origin. A table rather
    /// than thirty `assert!` lines, so a failure names the value that failed.
    ///
    /// **The authority's contents, which this predicate measures nothing of.**
    /// It asks the host for emptiness, a space, a tab and an at-sign; the host
    /// has a production, and each of these values fails it.
    #[rstest::rstest]
    #[case("ht$tp://example.com")]
    #[case("http://example.com:")]
    #[case("http://:80")]
    fn invalid_serialized_origin_cases(#[case] input: &str) {
        assert!(!is_valid_serialized_origin(input));
    }

    #[test]
    fn scheme_first_char_not_alpha_is_invalid() {
        assert!(!is_valid_serialized_origin("1http://example.com"));
    }
}
