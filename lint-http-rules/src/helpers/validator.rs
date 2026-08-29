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
//! [`validate_entity_tag`] is the grammar underneath all of it.

use crate::helpers::headers::get_header_str;
use crate::helpers::list::split_commas_respecting_quotes;
use crate::helpers::quoted_string::validate_quoted_string;
use hyper::HeaderMap;

/// Weak-compare an `If-None-Match` header value against a known ETag.
///
/// Returns `true` if the ETag is present in the comma-separated list of
/// values.  The comparison ignores leading `W/` prefixes to emulate HTTP's
/// weak comparison rules.  A lone `"*"` value is treated as **not** matching;
/// it represents an existence condition rather than a specific validator.
pub fn inm_matches_known(inm: &str, known: &str) -> bool {
    fn normalize(s: &str) -> &str {
        let s = s.trim();
        // cite(RFC 9110 § 13.1.2, label: If-None-Match weak comparison): "A recipient MUST use the weak comparison function when comparing entity tags for If-None-Match"
        if let Some(rest) = s.strip_prefix("W/") {
            rest.trim()
        } else {
            s
        }
    }

    let known_norm = normalize(known);
    for member in split_commas_respecting_quotes(inm) {
        let t = member.trim();
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
    get_header_str(headers, name).map(|value| value.trim().to_string())
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
    let trimmed = s.trim();
    if trimmed.len() >= 2 && (trimmed.starts_with("W/") || trimmed.starts_with("w/")) {
        trimmed[2..].trim().to_string()
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
pub fn validate_entity_tag(val: &str) -> Result<(), String> {
    // cite(RFC 9110 § 8.8.3, label: entity-tag grammar): "entity-tag = [ weak ] opaque-tag weak = %s"W/" opaque-tag = DQUOTE *etagc DQUOTE"
    let s = val.trim();

    let rest = if let Some(stripped) = s.strip_prefix("W/") {
        stripped
    } else {
        s
    };
    // rest must be a quoted-string
    validate_quoted_string(rest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;

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
    fn non_utf8_headers_are_skipped() {
        let mut headers = HeaderMap::new();
        // create invalid bytes
        let bad = HeaderValue::from_bytes(&[0xff]).unwrap();
        headers.insert("etag", bad);
        let (etag, _lm) = extract_validators_from_response(&headers);
        assert!(
            etag.is_none(),
            "invalid etag should not panic or return value"
        );
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
    fn validate_entity_tag_cases() {
        // The production is `[ weak ] opaque-tag` and neither part generates a
        // `*`. This asserted the opposite, which is how `If-None-Match: "abc", *`
        // passed as a conforming list; the `*` is the *other* alternative of the
        // two conditional fields' own grammars, and each of them decides it on
        // the whole field value now.
        assert!(validate_entity_tag("*").is_err());
        assert!(validate_entity_tag("\"abc\"").is_ok());
        // `etagc` admits the comma, so this is one tag and not two.
        assert!(validate_entity_tag("\"a,b\"").is_ok());
        assert!(validate_entity_tag("W/\"abc\"").is_ok());
        assert!(validate_entity_tag(" W/\"abc\" ").is_ok()); // leading/trailing whitespace tolerated
        assert!(validate_entity_tag("abc").is_err()); // missing quotes
        assert!(validate_entity_tag("W/abc").is_err()); // weak prefix without quoted-string
    }
}
