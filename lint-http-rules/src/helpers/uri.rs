// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! The characters a URI is composed from — the alphabet question, asked of a
//! whole value rather than of any one component.
//!
//! **§ 2.2 is why this is a module of its own and not a clause inside each
//! component's validator.** A component rule never names `reserved` or
//! `gen-delims` directly: it lists the characters it admits, one at a time, so
//! `pchar` takes `:` and `@` and `IPvFuture` takes `:` and no production but a
//! question asked of the *whole* URI takes all seven. The two sets those
//! component alphabets are built from — [`is_unreserved`] and [`is_sub_delim`]
//! — live here for the same reason and are read by five sites between them,
//! each adding its own line to the pair. Count what a caller shares, not what
//! it wraps: these two were written out character for character at four sites
//! while the function one of them was wrapped in had a single caller.
//!
//! **Nothing here trims, and the modules that do never use `str::trim`.** A
//! value reaching a URI reader carries one `char` per octet, so `%xA0` is in
//! hand where a UTF-8 decode would have had U+00A0 — and `str::trim` removes
//! the second. A `Location`, an `Origin` or a request-target with an `obs-text`
//! octet at its edge would then arrive *shorter than the sender wrote it* and
//! be pronounced valid, when the octet is exactly what no character in this
//! alphabet admits. `SP` and `HTAB` are the only whitespace a field value may
//! carry beside its content, and `headers::trim_ows` is exactly them.
//!
//! The productions built on this alphabet each have their own module:
//! [`super::scheme`], [`super::authority`], [`super::origin`],
//! [`super::request_target`], [`super::reference`] and
//! [`super::percent_encoding`].

/// The first character of `s` that no `URI-reference` admits, or `None` when
/// every character is one a URI may be written with.
///
/// The set is the union of `unreserved`, `gen-delims` and `sub-delims` plus the
/// `"%"` that opens a `pct-encoded` triplet — every terminal reachable from
/// `URI-reference`, since each component rule of the generic syntax lists a
/// subset of those characters and nothing outside them. So this answers only the
/// *alphabet* question; whether a character sits where its component allows it,
/// and whether a `%` is followed by two `HEXDIG`, are
/// [`super::percent_encoding::check_percent_encoding`]'s and the component rules' questions.
///
/// Deliberately narrower than "is this visible US-ASCII": `<`, `>`, `"`, `{`,
/// `}`, `|`, `\`, `^`, `` ` `` and SP are all VCHAR or SP and none of them is a
/// URI character. Every octet outside the set has to be percent-encoded before
/// the URI is formed, which is what makes the finding actionable.
// cite(RFC 3986 § 2): "A URI is composed from a limited set of characters consisting of digits, letters, and a few graphic symbols."
// cite(RFC 3986 § 2.1): "A percent-encoding mechanism is used to represent a data octet in a component when that octet's corresponding character is outside the allowed set or is being used as a delimiter of, or within, the component."
// cite(RFC 3986 § 2.2): "A component's ABNF syntax rule will not use the reserved or gen-delims rule names directly; instead, each syntax rule lists the characters allowed within that component (i.e., not delimiting it), and any of those characters that are also in the reserved set are "reserved" for use as subcomponent delimiters within the component."
pub fn find_non_uri_char(s: &str) -> Option<char> {
    s.chars().find(|&c| !is_uri_char(c))
}

/// Whether `c` is in RFC 3986's `unreserved` set.
///
/// One of the two character sets RFC 3986 builds its general component
/// alphabets out of. Five of its productions name the pair and then add
/// something different beside it — `userinfo`, `IPvFuture`, `reg-name`,
/// `segment-nz-nc`, `pchar` — which is why this is a predicate and not a
/// transcription per site: the set is the shared answer and the divergence is
/// each caller's own line. Five sites in this crate read it (`reg-name`,
/// `pchar`, `IPvFuture`, the URI-wide alphabet, and [`super::percent_encoding::decode_unreserved`], which
/// asks it of a decoded octet rather than of a written character).
// cite(RFC 3986 § 2.3): "unreserved  = ALPHA / DIGIT / "-" / "." / "_" / "~""
pub fn is_unreserved(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~')
}

/// Whether `c` is in RFC 3986's `sub-delims` set.
///
/// The other of the two, and it never travels alone: every component rule of
/// the generic syntax that names this set names [`is_unreserved`]'s beside it.
/// The one place `sub-delims` appears without it is `reserved = gen-delims /
/// sub-delims`, which is a set definition rather than a component's alphabet —
/// and §2.2 says a component rule never names *that* one at all. Four sites in
/// this crate read it, one fewer than its partner, because a decoder asks which
/// octets it may write out and no `sub-delims` octet is one of them.
// cite(RFC 3986 § 2.2): "sub-delims  = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "=""
pub fn is_sub_delim(c: char) -> bool {
    matches!(
        c,
        '!' | '$' | '&' | '\'' | '(' | ')' | '*' | '+' | ',' | ';' | '='
    )
}

/// Whether `c` is one of the characters a URI is composed from.
///
/// `gen-delims` stays written out here because this is the only reading in the
/// tree that wants it: §2.2 says a component rule never names the set directly,
/// so a *component* alphabet borrows characters from it one at a time — `pchar`
/// takes `:` and `@`, `IPvFuture` takes `:` — and only a question asked of the
/// whole URI takes all seven.
// cite(RFC 3986 § 2.2): "gen-delims  = ":" / "/" / "?" / "#" / "[" / "]" / "@""
// cite(RFC 3986 § 2.2): "A component's ABNF syntax rule will not use the reserved or gen-delims rule names directly; instead, each syntax rule lists the characters allowed within that component (i.e., not delimiting it), and any of those characters that are also in the reserved set are "reserved" for use as subcomponent delimiters within the component."
// cite(RFC 3986 § 2.1): "pct-encoded = "%" HEXDIG HEXDIG"
fn is_uri_char(c: char) -> bool {
    is_unreserved(c)
        || is_sub_delim(c)
        || matches!(c, ':' | '/' | '?' | '#' | '[' | ']' | '@')
        || c == '%'
}

/// Parse a query string (the portion after `?`) into a vector of
/// `(name,value)` pairs.  Percent-encoding is **not** decoded; callers can
/// compare values verbatim.  Empty names are permitted (they may appear in
/// malformed URIs) and missing values are treated as empty strings.
///
/// This simple helper is useful when rules need to examine specific
/// parameters without importing a full URI parser dependency.
pub fn parse_query_string(s: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for pair in s.split('&') {
        if pair.is_empty() {
            continue;
        }
        let mut kv = pair.splitn(2, '=');
        let name = kv.next().unwrap_or("").to_string();
        let value = kv.next().unwrap_or("").to_string();
        out.push((name, value));
    }
    out
}

#[cfg(test)]
mod tests {
    use crate::helpers::authority::validate_uri_host;

    /// Both sets, spelled out from the productions rather than composed from the
    /// predicates, and asserted over the whole US-ASCII range — four component
    /// alphabets and one decoder now rest on these two functions, so a character
    /// added or dropped here is added or dropped in all five.
    #[test]
    fn the_two_character_sets_are_what_their_productions_print() {
        // unreserved  = ALPHA / DIGIT / "-" / "." / "_" / "~"
        let unreserved: Vec<char> = ('a'..='z')
            .chain('A'..='Z')
            .chain('0'..='9')
            .chain("-._~".chars())
            .collect();
        // sub-delims  = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="
        let sub_delims: Vec<char> = "!$&'()*+,;=".chars().collect();
        assert_eq!(sub_delims.len(), 11);

        for c in (0u8..=0x7F).map(char::from) {
            assert_eq!(
                is_unreserved(c),
                unreserved.contains(&c),
                "unreserved disagrees about {c:?}"
            );
            assert_eq!(
                is_sub_delim(c),
                sub_delims.contains(&c),
                "sub-delims disagrees about {c:?}"
            );
        }

        // Neither set reaches past US-ASCII: every octet at or above %x80 has to
        // be percent-encoded before the URI is formed.
        for c in (0x80u8..=0xFF).map(char::from) {
            assert!(!is_unreserved(c) && !is_sub_delim(c), "{c:?}");
        }
    }

    /// The four alphabets built on those sets differ exactly where their
    /// productions differ, and nowhere else. This is the property the extraction
    /// was for: the divergence is one line per caller, and it is this one.
    #[test]
    fn the_component_alphabets_differ_only_by_what_their_productions_add() {
        for c in (0u8..=0x7F).map(char::from) {
            let shared = is_unreserved(c) || is_sub_delim(c);

            // reg-name = *( unreserved / pct-encoded / sub-delims ). Asked of a
            // character standing between two others, and with `%` left out of
            // the sweep: a lone `%` is not the alphabet's answer but
            // `pct-encoded`'s, which `validate_uri_host` asks separately and
            // first. The two assertions below the loop are that half.
            let reg_name = c == '%' || validate_uri_host(&format!("a{c}b")).is_ok();
            assert_eq!(reg_name, shared || c == '%', "reg-name: {c:?}");

            // pchar = unreserved / pct-encoded / sub-delims / ":" / "@"
            let pchar = is_unreserved(c) || is_sub_delim(c) || matches!(c, ':' | '@' | '%');
            assert_eq!(pchar, reg_name || matches!(c, ':' | '@'), "pchar: {c:?}");

            // IPvFuture's tail = 1*( unreserved / sub-delims / ":" ) — the one
            // of the four that admits no `pct-encoded`, so no `%`. Asked through
            // the bracketed literal, which is the only way a host reader reaches
            // that production and the only door this module has to it.
            assert_eq!(
                validate_uri_host(&format!("[v1.{c}]")).is_ok(),
                shared || c == ':',
                "IPvFuture: {c:?}"
            );

            // The URI-wide alphabet adds all seven `gen-delims` at once, which
            // §2.2 says no component rule does.
            assert_eq!(
                is_uri_char(c),
                shared || c == '%' || matches!(c, ':' | '/' | '?' | '#' | '[' | ']' | '@'),
                "URI alphabet: {c:?}"
            );
        }

        // `pct-encoded` is the triplet and not the `%`, and it is a separate
        // question from the alphabet at every one of the four sites.
        assert!(validate_uri_host("a%41b").is_ok());
        assert!(validate_uri_host("a%zzb").is_err());
        assert!(validate_uri_host("a%4").is_err());
    }

    use super::*;

    /// What `contains_whitespace` used to assert, asked of the function that
    /// replaced it — and the five characters beside the space, which that
    /// predicate answered `false` for at every one of its three callers.
    #[test]
    fn whitespace_detection() {
        assert!(find_non_uri_char("hello world").is_some());
        assert!(find_non_uri_char("/path/no-space").is_none());
        for c in [
            '<', '>', '"', '{', '}', '|', '\\', '^', '`', '\u{80}', '\u{ff}',
        ] {
            assert_eq!(
                find_non_uri_char(&format!("/p{c}ath")),
                Some(c),
                "for {c:?}"
            );
        }
    }

    #[test]
    fn parse_query_string_basic() {
        let v = parse_query_string("");
        assert!(v.is_empty());
        let v = parse_query_string("a=1&b=2");
        assert_eq!(
            v,
            vec![
                ("a".to_string(), "1".to_string()),
                ("b".to_string(), "2".to_string())
            ]
        );
        let v = parse_query_string("foo");
        assert_eq!(v, vec![("foo".to_string(), "".to_string())]);
        let v = parse_query_string("x=&=y&z=3");
        assert_eq!(
            v,
            vec![
                ("x".to_string(), "".to_string()),
                ("".to_string(), "y".to_string()),
                ("z".to_string(), "3".to_string()),
            ]
        );
    }
}
