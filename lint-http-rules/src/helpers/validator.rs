// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Validators: the `ETag` and `Last-Modified` a response offers, and how a
//! request's `If-None-Match` is compared against one.
//!
//! **Strong and weak are two questions, and the module keeps them apart.**
//! [`extract_validators_from_response`] answers "what did this response offer",
//! [`extract_strong_validators_from_response`] answers the narrower "what may a
//! `Range` or `If-Range` turn on" — a weak validator is a validator, and is
//! still not one of those. [`normalize_etag`] strips the `W/` and is therefore
//! only ever the *weak* comparison; the prefix it discards is exactly what a
//! strong comparison turns on, which is why it must not be used to prepare one.
//!
//! [`check_entity_tag`] is the grammar underneath all of it.

use crate::helpers::headers::{field_lines_as_written, trim_ows};
use crate::helpers::list::split_commas_respecting_quotes;
use hyper::HeaderMap;

/// Weak-compare an `If-None-Match` header value against a known ETag.
///
/// Returns `true` if the ETag is present in the comma-separated list of
/// values.  The comparison ignores leading `W/` prefixes to emulate HTTP's
/// weak comparison rules.  A lone `"*"` value is treated as **not** matching;
/// it represents an existence condition rather than a specific validator.
pub fn inm_matches_known(inm: &str, known: &str) -> bool {
    fn normalize(s: &str) -> &str {
        let s = trim_ows(s);
        // cite(RFC 9110 § 13.1.2, label: If-None-Match weak comparison): "A recipient MUST use the weak comparison function when comparing entity tags for If-None-Match"
        if let Some(rest) = s.strip_prefix("W/") {
            trim_ows(rest)
        } else {
            s
        }
    }

    let known_norm = normalize(known);
    for member in split_commas_respecting_quotes(inm) {
        let t = trim_ows(member);
        if t == "*" {
            return false;
        }
        if normalize(t) == known_norm {
            return true;
        }
    }
    false
}

/// Extract validator values from a response's headers, **including weak
/// ETags**.
///
/// This variant is appropriate for semantics that allow weak comparison
/// (e.g. `If-None-Match` handling).  The tuple is `(etag, last_modified)` and
/// each component is the trimmed string value if present.  No filtering of
/// weak tags is performed; callers should apply the appropriate comparison
/// rules themselves.
///
/// For rules that require *strong-only* validators (such as those dealing with
/// `If-Range` or range revalidation), use
/// [`extract_strong_validators_from_response`] instead.
///
/// See the `cache_validation_chain` rule for an example consumer.
pub fn extract_validators_from_response(headers: &HeaderMap) -> (Option<String>, Option<String>) {
    (
        validator(headers, "etag"),
        validator(headers, "last-modified"),
    )
}

/// One validator field, trimmed, if the response carries a readable one.
fn validator(headers: &HeaderMap, name: &str) -> Option<String> {
    // As written, because `etagc = %x21 / %x23-7E / obs-text`: an octet at or
    // above %x80 is a character an entity tag *generates*, so a decode that
    // refuses it drops a legal validator and every question asked of the pair
    // is then answered about a response that did offer one.
    field_lines_as_written(headers, name)
        .into_iter()
        .next()
        .map(|line| trim_ows(&line).to_string())
}

/// Extract **strong** validators from a response's headers.
///
/// This is the original implementation of [`extract_validators_from_response`];
/// it filters out weak ETags (`W/` prefix) because they are not suitable for
/// certain cache validation scenarios.  Rules that do not accept weak ETags
/// (for example, `range_request_and_caching`) should call this
/// helper instead of `extract_validators_from_response`.
pub fn extract_strong_validators_from_response(
    headers: &HeaderMap,
) -> (Option<String>, Option<String>) {
    // Exactly the pair above with the weak ETags dropped, which is what the
    // paragraphs on both functions say the difference is. `Last-Modified` is
    // not filtered here: whether a timestamp is a strong validator depends on
    // the origin's clock resolution, not on anything visible in the field.
    let (etag, last_modified) = extract_validators_from_response(headers);
    (etag.filter(|etag| !etag.starts_with("W/")), last_modified)
}

/// Strip an optional weak (`W/`) prefix from an ETag value, leaving the
/// quoted-string intact.
///
/// Reducing both sides to their opaque-tag and comparing those character by
/// character *is* weak comparison -- that is the sentence below, and it is the
/// only thing this function is good for. It must not be used to prepare a strong
/// comparison: the `W/` it discards is exactly what strong comparison turns on.
///
/// The pointer that stood here read "RFC 9111 §5.3.2". RFC 9111 § 5.3 is
/// Expires and has no § 5.3.2 -- the section numbering goes straight to § 5.4,
/// Pragma. So it was not merely the wrong document, it named nothing at all.
///
/// The resulting string is trimmed but otherwise returned verbatim.
///
// cite(RFC 9110 § 8.8.3.2): "two entity tags are equivalent if their opaque-tags match character-by-character, regardless of either or both being tagged as "weak"."
pub fn normalize_etag(s: &str) -> String {
    let trimmed = trim_ows(s);
    if trimmed.len() >= 2 && (trimmed.starts_with("W/") || trimmed.starts_with("w/")) {
        trim_ows(&trimmed[2..]).to_string()
    } else {
        trimmed.to_string()
    }
}

/// Validate an entity-tag, which may be weak (prefix `W/`). Returns `Ok(())` on
/// success or `Err(msg)` describing the problem.
///
/// **`*` is not one, and this function used to say it was.** The production has
/// two parts and neither generates it; the `*` belongs to `If-Match` and
/// `If-None-Match`, whose own grammars are `"*" / #entity-tag` — an alternation,
/// so there the `*` is the **whole field value** and never a member of the list.
/// Accepting it here put it in both places at once, and every caller answered
/// that the same way: three of the five excluded `*` on the line before calling
/// (`etag_syntax` with a finding of its own, `range_request_and_caching`
/// with a `return`), and the two that did not were the two the `*` was
/// ostensibly for — where it made `If-None-Match: "abc", *` a conforming list.
/// **A tolerance that every honest caller has to undo is not a tolerance.**
// cite(RFC 9110 § 8.8.3): "An entity tag consists of an opaque quoted string, possibly prefixed by a weakness indicator."
pub fn check_entity_tag(val: &str) -> Result<(), EntityTagDefect> {
    // cite(RFC 9110 § 8.8.3, label: entity-tag grammar): "entity-tag = [ weak ] opaque-tag weak = %s"W/" opaque-tag = DQUOTE *etagc DQUOTE"
    let s = trim_ows(val);

    let rest = if let Some(stripped) = s.strip_prefix("W/") {
        stripped
    } else if s.get(..2).is_some_and(|p| p.eq_ignore_ascii_case("w/")) {
        // `%s"W/"` — the `%s` prefix is what makes the case part of the
        // production, and RFC 5234 § 2.3 says an unprefixed string would have
        // been case-insensitive. A `w/` is therefore a weakness indicator the
        // sender meant and the grammar does not generate, which is a different
        // finding from a tag that never opened its quotes.
        // cite(RFC 5234 § 2.3): "ABNF strings are case insensitive and the character set for these strings is US-ASCII."
        return Err(EntityTagDefect::WeakIndicatorInvalid);
    } else {
        s
    };

    // `opaque-tag = DQUOTE *etagc DQUOTE`, and the interior is **not** a
    // `quoted-string`: `etagc` holds the backslash as an ordinary character
    // and holds no DQUOTE at all, so nothing inside an opaque-tag is an
    // escape. Reading one with the quoted-string reader — which this did —
    // reported `"a\"` for a trailing escape the production generates, and
    // accepted `"a\"b"` as an escaped DQUOTE the production cannot hold.
    let Some(inner) = rest
        .strip_prefix('"')
        .and_then(|open| open.strip_suffix('"'))
    else {
        return Err(EntityTagDefect::DelimiterMissing);
    };

    match inner.chars().find(|&c| !is_etagc(c)) {
        Some(c) => Err(EntityTagDefect::BadCharacter(c)),
        None => Ok(()),
    }
}

/// `etagc`, over a single character.
///
/// The class is the visible US-ASCII minus the DQUOTE that delimits the tag,
/// plus `obs-text`. It is written as the ranges the production writes rather
/// than as "visible, except the quote", because the exclusion at %x22 is the
/// whole reason the tag can be scanned at all.
fn is_etagc(c: char) -> bool {
    // cite(RFC 9110 § 8.8.3): "etagc      = %x21 / %x23-7E / obs-text ; VCHAR except double quotes, plus obs-text"
    c == '\u{21}' || ('\u{23}'..='\u{7e}').contains(&c) || c >= '\u{80}'
}

/// Why a value is not an `entity-tag`.
///
/// Three defects and no fourth: the production is a two-character prefix, two
/// delimiters and a character class, and there is nothing else in it to fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntityTagDefect {
    /// A weakness indicator in any spelling but `W/`.
    WeakIndicatorInvalid,
    /// No opening DQUOTE, or nothing closing it.
    DelimiterMissing,
    /// A character `etagc` does not admit — a DQUOTE inside the tag, a control
    /// octet, DEL.
    BadCharacter(char),
}

impl EntityTagDefect {
    /// The finding fragment. Callers name the field the tag came from and put
    /// this after it.
    pub fn message(self) -> String {
        match self {
            Self::WeakIndicatorInvalid => {
                "weakness indicator must be written \"W/\", which is case-sensitive".to_string()
            }
            Self::DelimiterMissing => {
                "entity-tag must be an opaque tag between two double quotes".to_string()
            }
            Self::BadCharacter(c) => format!(
                "entity-tag holds {}, which no etagc admits",
                crate::helpers::shown::describe_char(c)
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;
    use rstest::rstest;

    #[test]
    fn strong_etag_and_last_modified_are_returned() {
        let mut headers = HeaderMap::new();
        headers.insert("etag", HeaderValue::from_static("\"abc\""));
        headers.insert(
            "last-modified",
            HeaderValue::from_static("Wed, 21 Oct 2015 07:28:00 GMT"),
        );
        let (etag, lm) = extract_validators_from_response(&headers);
        assert_eq!(etag.as_deref(), Some("\"abc\""));
        assert_eq!(lm.as_deref(), Some("Wed, 21 Oct 2015 07:28:00 GMT"));
    }

    #[test]
    fn weak_etag_is_returned() {
        let mut headers = HeaderMap::new();
        headers.insert("etag", HeaderValue::from_static("W/\"weak\""));
        let (etag, lm) = extract_validators_from_response(&headers);
        assert_eq!(etag.as_deref(), Some("W/\"weak\""));
        assert!(lm.is_none());
    }

    #[test]
    fn strong_helper_filters_weak_etag() {
        let mut headers = HeaderMap::new();
        headers.insert("etag", HeaderValue::from_static("W/\"weak\""));
        let (etag, lm): (Option<String>, Option<String>) =
            extract_strong_validators_from_response(&headers);
        assert!(etag.is_none(), "strong helper should ignore weak etag");
        assert!(lm.is_none());
    }

    #[test]
    fn missing_headers_return_none() {
        let headers = HeaderMap::new();
        let (etag, lm) = extract_validators_from_response(&headers);
        assert!(etag.is_none());
        assert!(lm.is_none());
    }

    #[test]
    fn an_obs_text_octet_is_part_of_the_tag_not_a_reason_to_drop_it() {
        let mut headers = HeaderMap::new();
        // `etagc` generates this octet, so the response did offer a validator
        // and the old decode answered that it had offered none.
        let bad = HeaderValue::from_bytes(b"\"caf\xe9\"").expect("a field line");
        headers.insert("etag", bad);
        let (etag, _lm) = extract_validators_from_response(&headers);
        assert_eq!(
            etag.expect("a validator"),
            ['"', 'c', 'a', 'f', '\u{e9}', '"']
                .iter()
                .collect::<String>()
        );
    }

    #[test]
    fn a_tag_whose_second_octet_is_obs_text_is_measured_not_sliced() {
        // One `char` per octet is not one *byte* per octet: `a%xFF"` puts byte
        // index 2 inside a code point, which a `[..2]` would have split.
        let val: String = [0x61u8, 0xff, 0x22].into_iter().map(char::from).collect();
        assert!(check_entity_tag(&val).is_err());
    }

    #[test]
    fn inm_matches_known_behaviour() {
        assert!(inm_matches_known("\"a\"", "\"a\""));
        assert!(inm_matches_known("W/\"a\"", "\"a\""));
        assert!(!inm_matches_known("\"b\"", "\"a\""));
        assert!(!inm_matches_known("*", "\"a\""));
    }

    // Entity-tag helper tests
    #[test]
    fn check_entity_tag_cases() {
        // The production is `[ weak ] opaque-tag` and neither part generates a
        // `*`. This asserted the opposite, which is how `If-None-Match: "abc", *`
        // passed as a conforming list; the `*` is the *other* alternative of the
        // two conditional fields' own grammars, and each of them decides it on
        // the whole field value now.
        assert!(check_entity_tag("*").is_err());
        assert!(check_entity_tag("\"abc\"").is_ok());
        // `etagc` admits the comma, so this is one tag and not two.
        assert!(check_entity_tag("\"a,b\"").is_ok());
        assert!(check_entity_tag("W/\"abc\"").is_ok());
        assert!(check_entity_tag(" W/\"abc\" ").is_ok()); // leading/trailing whitespace tolerated
        assert!(check_entity_tag("abc").is_err()); // missing quotes
        assert!(check_entity_tag("W/abc").is_err()); // weak prefix without an opaque-tag
    }

    /// The interior is `*etagc` and not a `quoted-string`, which is the whole
    /// of what separates this reader from the one it replaced. A backslash is
    /// an ordinary `etagc`, so a tag may end in one; a DQUOTE is not, so an
    /// "escaped" one closed the tag early and left content behind.
    #[rstest]
    #[case("\"a\\\"", Ok(()))]
    #[case("\"a\\\"b\"", Err(EntityTagDefect::BadCharacter('"')))]
    #[case("w/\"abc\"", Err(EntityTagDefect::WeakIndicatorInvalid))]
    #[case("W\"abc\"", Err(EntityTagDefect::DelimiterMissing))]
    #[case("\"\"", Ok(()))]
    #[case("\"", Err(EntityTagDefect::DelimiterMissing))]
    fn an_opaque_tag_is_not_a_quoted_string(
        #[case] value: &str,
        #[case] expected: Result<(), EntityTagDefect>,
    ) {
        assert_eq!(check_entity_tag(value), expected, "{value}");
    }
}
