// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! A `pct-encoded` triplet: whether the two characters after a `%` are the ones
//! the production obliges, and which octet the pair stands for.
//!
//! **The percent sign is the one character the generic syntax gives the same
//! job in every component**, which is what makes this its own question rather
//! than a clause inside each component's answer. A `reg-name`, a segment, a
//! query and a `userinfo` each admit the triplet, and not one of them says what
//! it is; the four of them name `pct-encoded` and stop. So the reading lives
//! once and every component's validator borrows it: the `uri-host` reader reads
//! the triplet through this module and reports what it finds as the host defect
//! it is.
//!
//! **What may be decoded is a narrower question than what is well formed, and
//! § 2.4 draws the line.** A triplet standing for a `gen-delims` or a
//! `sub-delims` octet may not be turned back into that character before the
//! components have been separated, because the character is where a component
//! *ends* — so [`decode_unreserved`] decodes exactly the set § 2.4 exempts and
//! leaves every other triplet standing. That is the whole of what a normalizer
//! may do to a component it has not parsed, and it is why this module answers
//! about a *component* and never about a whole URI.
//!
//! The alphabet the triplet sits in — which characters need one in the first
//! place — is [`super::uri`]'s question.

use crate::helpers::uri::is_unreserved;

/// The two ways a `pct-encoded` triplet fails to be one.
///
/// The triplet is the whole production: a `%` obliges exactly two hex digits,
/// which is why a short run at the end of the string and a run with a non-hex
/// digit are two answers rather than one "malformed" verdict.
// cite(RFC 3986 § 2.1): "pct-encoded = "%" HEXDIG HEXDIG"
// cite(RFC 3986 § 2.1): "A percent-encoded octet is encoded as a character triplet, consisting of the percent character "%" followed by the two hexadecimal digits representing that octet's numeric value."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PercentEncodingDefect<'a> {
    /// Fewer than two characters after the `%`, because the value ended.
    Incomplete,
    /// Two characters that are not both `HEXDIG`, carrying the triplet as
    /// written — which is up to three *characters* and not three bytes, since
    /// what follows a `%` is exactly where a multi-byte character may begin.
    NotHexDigits(&'a str),
}

impl PercentEncodingDefect<'_> {
    /// The finding fragment.
    pub fn message(self) -> String {
        match self {
            Self::Incomplete => {
                "Percent-encoding incomplete: '%' must be followed by two hex digits".to_string()
            }
            Self::NotHexDigits(seq) => format!("Invalid percent-encoding '{}'", seq),
        }
    }
}

/// Check percent-encoding runs inside a string. Returns `Some(msg)` describing the
/// first problem found, or `None` if all percent-encodings look well-formed.
///
/// This is [`percent_encoding_defect`] rendered, and the twenty-odd callers that
/// embed the sentence in one of their own keep asking it. A caller that needs
/// the failure inside a finding of its own — [`super::authority::validate_uri_host`] names the
/// host the triplet was in — asks the typed one.
pub fn check_percent_encoding(s: &str) -> Option<String> {
    percent_encoding_defect(s).map(PercentEncodingDefect::message)
}

/// The first malformed `pct-encoded` triplet in `s`, as a
/// [`PercentEncodingDefect`], or `None` when every `%` opens a well-formed one.
pub fn percent_encoding_defect(s: &str) -> Option<PercentEncodingDefect<'_>> {
    let bytes = s.as_bytes();
    let len = bytes.len();
    let mut i = 0usize;

    while i < len {
        if bytes[i] == b'%' {
            if i + 2 >= len {
                return Some(PercentEncodingDefect::Incomplete);
            }
            let hi = bytes[i + 1];
            let lo = bytes[i + 2];
            // Both cases of the six letter digits derive from `HEXDIG`, whose
            // alternatives are quoted strings and so case-insensitive, and § 2.1
            // says the same of these digits directly -- two URIs differing only
            // in that case are one URI. The recommendation beside it, to prefer
            // uppercase, is a consistency one and is declined where a caller
            // publishes its findings.
            // cite(RFC 5234 § 2.3): "ABNF strings are case insensitive and the character set for these strings is US-ASCII."
            // cite(RFC 3986 § 2.1): "The uppercase hexadecimal digits 'A' through 'F' are equivalent to the lowercase digits 'a' through 'f', respectively."
            // cite(RFC 3986 § 2.1): "If two URIs differ only in the case of hexadecimal digits used in percent-encoded octets, they are equivalent."
            if !hi.is_ascii_hexdigit() || !lo.is_ascii_hexdigit() {
                // Take three *characters*, not three bytes. The bytes after '%'
                // are non-hex precisely here, which is when they may be the lead
                // or continuation bytes of a multi-byte character — slicing to
                // `i + 3` would cut one in half and panic. `i` is always at a '%'
                // and so always on a character boundary.
                let end = s[i..]
                    .char_indices()
                    .nth(3)
                    .map_or(len, |(offset, _)| i + offset);
                return Some(PercentEncodingDefect::NotHexDigits(&s[i..end]));
            }
            i += 3;
        } else {
            i += 1;
        }
    }

    None
}

/// One URI component with § 6.2.2's two percent-encoding normalizations applied:
/// every triplet standing for an `unreserved` character written as that
/// character, and the hexadecimal of every triplet that stays encoded in upper
/// case.
///
/// **Only `unreserved`, and § 2.4 is why.** Decoding a `gen-delims` or a
/// `sub-delims` octet moves where the component boundaries are — `%2F` inside a
/// segment is data, and `/` between two segments is not the same thing — so a
/// caller handing a whole path to a decoder that took every triplet would get
/// back a string whose structure the sender never wrote. That is the exact
/// inverse of the decision at
/// `alt_svc_protocol_registered::alpn_protocol_name`, which decodes
/// **every** triplet because RFC 7301 § 3.1 makes an ALPN protocol name an
/// opaque octet sequence with no components for a delimiter to bound. One
/// question, two answers, both cited; the two functions must not be folded.
///
/// **The second normalization is free here and required at one caller.** A
/// triplet this leaves encoded is still put in one form, which is what lets two
/// authorities that differ only in `%2f` versus `%2F` compare equal. The other
/// caller compares against a literal made of `unreserved` characters, where a
/// surviving triplet can never match whatever its case — so applying § 6.2.2.1
/// cannot change its verdict, and having one function is worth more than having
/// two that differ by a `format!`.
///
/// The walk is over `char`s and not over `str::as_bytes`, because callers hand
/// this a value carrying one `char` per octet: an octet at or above %x80 is a
/// single `char` here and two UTF-8 bytes, and a byte walk would take it apart
/// into two octets that were never on the wire. The two characters after a `%`
/// are tested for being hexadecimal before they are read as a number, because
/// `from_str_radix` accepts a leading `+` and no `pct-encoded` does.
///
/// **[`super::reference::normalize_path_and_query`] runs this before its other two steps**, and
/// § 2.4's exception is why it may: an `unreserved` octet needs no component
/// boundary established before it can be decoded, so nothing waits on it. What
/// that ordering buys is written at that function. Callers that want one
/// component decoded and nothing else — a segment, a host — call this directly.
// cite(RFC 3986 § 2.3): "unreserved  = ALPHA / DIGIT / "-" / "." / "_" / "~""
// cite(RFC 3986 § 2.3): "URIs that differ in the replacement of an unreserved character with its corresponding percent-encoded US-ASCII octet are equivalent"
// cite(RFC 3986 § 6.2.2.2): "These URIs should be normalized by decoding any percent-encoded octet that corresponds to an unreserved character, as described in Section 2.3."
// cite(RFC 3986 § 6.2.2.1): "For all URIs, the hexadecimal digits within a percent-encoding triplet (e.g., "%3a" versus "%3A") are case-insensitive and therefore should be normalized to use uppercase letters for the digits A-F."
// cite(RFC 3986 § 2.4): "When a URI is dereferenced, the components and subcomponents significant to the scheme-specific dereferencing process (if any) must be parsed and separated before the percent-encoded octets within those components can be safely decoded, as otherwise the data may be mistaken for component delimiters."
pub fn decode_unreserved(component: &str) -> String {
    let chars: Vec<char> = component.chars().collect();
    let mut out = String::with_capacity(component.len());
    let mut i = 0;

    while i < chars.len() {
        let octet = (chars[i] == '%' && i + 2 < chars.len())
            .then(|| {
                let hex: String = chars[i + 1..i + 3].iter().collect();
                hex.chars()
                    .all(|c| c.is_ascii_hexdigit())
                    .then(|| u8::from_str_radix(&hex, 16).ok())
                    .flatten()
            })
            .flatten();

        match octet {
            // The set is ASCII-only and `u8 as char` is the identity there, so
            // asking [`is_unreserved`] of the decoded octet answers exactly what
            // a byte-wise copy of it would — this is the same set as the other
            // four sites, read at the one place it arrives as an octet.
            Some(octet) if is_unreserved(octet as char) => {
                out.push(octet as char);
                i += 3;
            }
            Some(octet) => {
                out.push('%');
                out.push_str(&format!("{:02X}", octet));
                i += 3;
            }
            None => {
                out.push(chars[i]);
                i += 1;
            }
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two normalizations § 6.2.2 asks for on percent-encoding, and the one
    /// § 2.4 forbids.
    #[test]
    fn decode_unreserved_leaves_delimiters_encoded() {
        // `%2F` is a `gen-delims` octet: decoding it would move a component
        // boundary, which is the mistake RFC 3986 § 2.4 names.
        assert_eq!(decode_unreserved("a%2Fb"), "a%2Fb");
        assert_eq!(decode_unreserved("a%2Cb"), "a%2Cb");
        // An `unreserved` octet is decoded, in either hexadecimal case.
        assert_eq!(decode_unreserved("%2Ewell%2dknown"), ".well-known");
        // A triplet that stays encoded is still put in one form, which is what
        // lets two authorities differing only in the case of their hexadecimal
        // compare equal (§ 6.2.2.1).
        assert_eq!(decode_unreserved("a%2fb"), "a%2Fb");
        // A truncated or non-hexadecimal run is left exactly as written; whether
        // it is well formed is another rule's finding.
        assert_eq!(decode_unreserved("%2"), "%2");
        assert_eq!(decode_unreserved("%zz"), "%zz");
        assert_eq!(decode_unreserved("%%41"), "%A");
        // `from_str_radix` would read this as %x0A; no `pct-encoded` writes a
        // sign, so the two characters are measured against `HEXDIG` first.
        assert_eq!(decode_unreserved("%+A"), "%+A");
        // A captured target read back through `lint-captures` is an arbitrary string:
        // the two positions after a `%` can be inside a multi-byte code point,
        // and slicing them would panic.
        assert_eq!(decode_unreserved("%é4"), "%é4");
        assert_eq!(decode_unreserved("café"), "café");
    }

    #[test]
    fn percent_encoding_good_and_bad() {
        assert!(check_percent_encoding("/path%20ok").is_none());
        assert_eq!(
            check_percent_encoding("/incomplete%2"),
            Some("Percent-encoding incomplete: '%' must be followed by two hex digits".into())
        );
        let m = check_percent_encoding("/bad%2G").unwrap();
        assert!(m.contains("Invalid percent-encoding") && m.contains("%2G"));
    }

    /// The typed answer and the rendered one, over the same values. The
    /// triplet is carried as written, which is what lets a caller quote it
    /// inside a sentence of its own rather than splice a whole message in.
    #[test]
    fn percent_encoding_defect_is_what_the_sentence_is_rendered_from() {
        assert_eq!(percent_encoding_defect("/path%20ok"), None);
        assert_eq!(
            percent_encoding_defect("/incomplete%2"),
            Some(PercentEncodingDefect::Incomplete)
        );
        assert_eq!(
            percent_encoding_defect("/bad%2G"),
            Some(PercentEncodingDefect::NotHexDigits("%2G"))
        );
        // Three *characters*, not three bytes: what follows a '%' is exactly
        // where a multi-byte character may begin.
        assert_eq!(
            percent_encoding_defect("/p%\u{20AC}x"),
            Some(PercentEncodingDefect::NotHexDigits("%\u{20AC}x"))
        );
        assert_eq!(
            check_percent_encoding("/bad%2G"),
            percent_encoding_defect("/bad%2G").map(PercentEncodingDefect::message)
        );
    }

    #[test]
    fn percent_followed_by_a_multibyte_character_does_not_panic() {
        // A '%' whose next bytes are the lead/continuation bytes of a multi-byte
        // character used to be reported by slicing three *bytes*, splitting the
        // character and panicking. Request targets are not guaranteed ASCII.
        let m = check_percent_encoding("/p%\u{20AC}x").expect("must be reported, not panic");
        assert!(m.contains("Invalid percent-encoding"), "{m}");
        assert!(check_percent_encoding("%\u{20AC}").is_some());
        assert!(check_percent_encoding("\u{20AC}%2G").is_some());
        assert!(check_percent_encoding("/caf\u{e9}/ok%20").is_none());
    }
}
