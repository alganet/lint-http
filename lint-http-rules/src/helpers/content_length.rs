// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! How long the body is, and what in the message says so.
//!
//! Two questions that look like one. [`validate_content_length`] asks whether
//! the field derives from its production and agrees with itself across every
//! line that carries it — repeated `Content-Length: 5` lines and a single
//! `Content-Length: 5, 5` are the same message, and used to get opposite
//! answers. [`content_evidence`] asks the different question of *which*
//! mechanism frames this body at all, since `Transfer-Encoding` outranks the
//! field and a body may be framed by connection close.
//!
//! [`ContentLengthError`] is one of the typed defect enums in this tree: the
//! three ways the field fails are three different findings, and a caller that
//! got a `String` could not tell them apart to word them differently.

use crate::helpers::list::list_members;
use hyper::HeaderMap;

/// Errors returned by `validate_content_length`.
#[derive(Debug, PartialEq, Eq)]
pub enum ContentLengthError {
    InvalidCharacter(String),
    TooLarge(String),
    MultipleValuesDiffer(String, String),
    NonUtf8,
}

/// Validate `Content-Length` headers in a `HeaderMap`.
///
/// Checks:
/// 1. Values must be valid UTF-8 digits.
/// 2. Values must be parseable as u128.
/// 3. If multiple values are present, they must be identical.
///
/// Returns `Ok(None)` if no Content-Length header is present,
/// `Ok(Some(n))` if valid, or `Err(ContentLengthError)`.
pub fn validate_content_length(headers: &HeaderMap) -> Result<Option<u128>, ContentLengthError> {
    let entries: Vec<_> = headers
        .get_all(hyper::header::CONTENT_LENGTH)
        .iter()
        .collect();

    if entries.is_empty() {
        return Ok(None);
    }

    let mut first_val: Option<u128> = None;
    let mut first_raw: String = String::new();

    for hv in entries.iter() {
        let s = hv.to_str().map_err(|_| ContentLengthError::NonUtf8)?;

        // A single field line may itself carry a comma-separated list, and that is
        // not automatically a violation. The sentence below makes `5, 5` valid and
        // says what it means: one value, 5. Splitting here is what keeps this
        // function's answer the same for a message however its field lines were
        // merged -- two `Content-Length: 5` lines and one `Content-Length: 5, 5`
        // line are the same message by § 5.3, and used to get opposite answers.
        //
        // cite(RFC 9112 § 6.3): "If a message is received without Transfer-Encoding and with an invalid Content-Length header field, then the message framing is invalid and the recipient MUST treat it as an unrecoverable error, unless the field value can be successfully parsed as a comma-separated list (Section 5.6.1 of [HTTP]), all values in the list are valid, and all values in the list are the same (in which case, the message is processed with that single value used as the Content-Length field value)."
        let mut saw_value = false;
        for t in list_members(s) {
            saw_value = true;

            // cite(RFC 9110 § 8.6, label: Content-Length grammar): "Content-Length = 1*DIGIT"
            if !t.chars().all(|c| c.is_ascii_digit()) {
                return Err(ContentLengthError::InvalidCharacter(s.to_string()));
            }

            // A digit run too long for `u128` is still valid `1*DIGIT` — the grammar
            // sets no ceiling and, unlike `delta-seconds`, nothing here tells a
            // recipient to clamp an unrepresentable value. So this rejection is a
            // tolerance rather than a quoted requirement, and it is left in place on
            // the reasoning that a length no recipient can represent cannot frame a
            // message either: §6.3 makes an unusable Content-Length a framing error.
            // It takes a 39-digit value to reach.
            let n = t
                .parse::<u128>()
                .map_err(|_| ContentLengthError::TooLarge(s.to_string()))?;

            match first_val {
                None => {
                    first_val = Some(n);
                    first_raw = s.to_string();
                }
                Some(f) if f != n => {
                    return Err(ContentLengthError::MultipleValuesDiffer(
                        first_raw,
                        s.to_string(),
                    ));
                }
                _ => {}
            }
        }

        // An empty field line has no values to be "all the same", and one is not a
        // list of none: `Content-Length:` is simply not `1*DIGIT`.
        if !saw_value {
            return Err(ContentLengthError::InvalidCharacter(s.to_string()));
        }
    }

    Ok(first_val)
}

/// What a captured message shows of its own content, for the rules whose
/// sentence is about content rather than about framing.
#[derive(Debug, PartialEq, Eq)]
pub enum ContentEvidence {
    /// Octets that streamed through, counted after framing was removed.
    Captured(u64),
    /// No body was captured, so the sender's own declaration is what is left.
    Declared(u128),
}

impl std::fmt::Display for ContentEvidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContentEvidence::Captured(n) => write!(f, "{n} octets captured"),
            ContentEvidence::Declared(n) => write!(f, "Content-Length: {n}"),
        }
    }
}

/// Whether a message carries content, and on what evidence.
///
/// Content is the octet stream left once framing has been taken off, so a
/// framing field is not itself an answer: a chunked message whose only chunk is
/// the terminator carries none, and over HTTP/2 and HTTP/3 content arrives with
/// no framing field at all.
// cite(RFC 9110 § 6.4): "HTTP messages often transfer a complete or partial representation as the message "content": a stream of octets sent after the header section, as delineated by the message framing."
// cite(RFC 9110 § 6.4): "For example, an HTTP/1.1 message body (Section 6 of [HTTP/1.1]) might consist of a stream of data encoded with the chunked transfer coding -- a sequence of data chunks, one zero-length chunk, and a trailer section -- whereas the content of that same message includes only the data stream after the transfer coding has been decoded; it does not include the chunk lengths, chunked framing syntax, nor the trailer fields (Section 6.5)."
//
// The captured count is that stream measured directly, so it answers first; a
// coded representation of nothing is still nothing, which is why a
// `Content-Encoding` does not disturb the comparison against zero.
pub fn content_evidence(headers: &HeaderMap, body_length: Option<u64>) -> Option<ContentEvidence> {
    match body_length {
        Some(n) => (n > 0).then_some(ContentEvidence::Captured(n)),
        None => declared_content_length(headers)
            .filter(|n| *n > 0)
            .map(ContentEvidence::Declared),
    }
}

/// The sender's own claim about how much content it enclosed, where that claim
/// parses.
///
/// A value that does not parse leaves no number and `content_length_valid`
/// reports it; a declared length that disagrees with the captured octets is
/// `request_body_length_accuracy`'s finding.
// cite(RFC 9110 § 8.6): "When transferring a representation as content, Content-Length refers specifically to the amount of data enclosed so that it can be used to delimit framing"
pub fn declared_content_length(headers: &HeaderMap) -> Option<u128> {
    validate_content_length(headers).ok().flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Quoted-string helper tests
    /// Two `Content-Length: 5` field lines and one `Content-Length: 5, 5` line are
    /// the same message -- § 5.3 lets a recipient combine the former into the
    /// latter -- so they must get the same answer. They used to get opposite ones.
    #[test]
    fn content_length_comma_list_matches_repeated_field_lines() {
        fn one(raw: &str) -> Result<Option<u128>, ContentLengthError> {
            let mut h = HeaderMap::new();
            h.append(
                "content-length",
                raw.parse::<hyper::header::HeaderValue>().unwrap(),
            );
            validate_content_length(&h)
        }
        fn many(raws: &[&str]) -> Result<Option<u128>, ContentLengthError> {
            let mut h = HeaderMap::new();
            for r in raws {
                h.append(
                    "content-length",
                    r.parse::<hyper::header::HeaderValue>().unwrap(),
                );
            }
            validate_content_length(&h)
        }

        assert_eq!(one("5, 5"), Ok(Some(5)));
        assert_eq!(one("5,5"), Ok(Some(5)));
        assert_eq!(one("5, 5"), many(&["5", "5"]));

        // Differing values are an unrecoverable error either way round.
        assert!(matches!(
            one("5, 6"),
            Err(ContentLengthError::MultipleValuesDiffer(_, _))
        ));
        assert!(matches!(
            many(&["5", "6"]),
            Err(ContentLengthError::MultipleValuesDiffer(_, _))
        ));

        // Still not a list of digits.
        assert!(one("").is_err());
        assert!(one("5, x").is_err());
        assert!(one("abc").is_err());
    }
}
