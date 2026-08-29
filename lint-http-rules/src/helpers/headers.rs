// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::helpers::list::{list_members, split_commas_respecting_quotes};
use crate::helpers::quoted_string::{unescape_quoted_string, validate_quoted_string};
use crate::helpers::shown::describe_char;
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

/// Retrieve a header value as a string, if it exists and contains only visible ASCII.
///
/// Returns `None` if the header is missing or contains non-visible ASCII characters
/// (control characters) or non-ASCII bytes.
pub fn get_header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// The field lines for `name` that are readable as text, in order.
///
/// **The three-line ladder this replaces was written at over a hundred call
/// sites** — `for hv in headers.get_all(name).iter()`, then `if let Ok(s) =
/// hv.to_str()`, then the work — and the two outer lines cost every one of them
/// a level of nesting before the question being asked could be stated. What
/// they mean is uniform: a field line that is not text is not a value this
/// caller can compare, and naming *that* as a defect belongs to the rule owning
/// the field.
///
/// Composition is the point: `.flat_map(list_members)` for a `#rule` field,
/// `.map(str::trim)` for a singleton, `.next()` for the first line. Callers
/// that must measure what a sender actually wrote — including the octets
/// `to_str` refuses — want [`combined_field_value_octets`] instead, and the
/// distinction is the same one drawn at [`get_all_header_values`].
pub fn field_lines<'a>(headers: &'a HeaderMap, name: &str) -> impl Iterator<Item = &'a str> {
    headers
        .get_all(name)
        .iter()
        .filter_map(|hv| hv.to_str().ok())
}

/// Whether any field line for `name` carries octets that are not text.
///
/// The companion to [`field_lines`], and the reason that one can be silent: it
/// skips such a line, so a rule whose *finding* is that the sender wrote one
/// has to ask separately. Keeping the two beside each other is what stops the
/// silent skip from quietly deleting a rule's finding when it adopts the
/// reader.
pub fn has_unreadable_line(headers: &HeaderMap, name: &str) -> bool {
    headers.get_all(name).iter().any(|hv| hv.to_str().is_err())
}

/// Collect all header values for the given name and concatenate them using
/// ", " as a separator, trimming each entry.
///
/// Returns `None` if the header is absent or if any of its values are not
/// valid UTF-8 (i.e. `HeaderValue::to_str()` fails for any of them). This
/// avoids comparing partial header values.
///
/// This is handy when rules need to compare the *effective* string value of a
/// possibly-multiple header field (e.g. Upgrade, Vary dimensions, etc.).
///
/// The `", "` is not a house style. § 5.3 permits the combining, names the comma
/// as the separator, and then says which of comma and comma-SP to use, so all
/// three of the decisions in this function are in one sentence. The in-order
/// append is the same sentence: order is significant, so `get_all`'s order is
/// preserved rather than sorted or deduplicated.
///
/// **This is not valid for every field, and the RFC names the exception.** The
/// doc comment here used to offer "cookies" as an example, which is precisely
/// backwards: `Set-Cookie` does not use list syntax and cannot be combined into
/// one field value at all. No caller passes it today. Do not add one -- for that
/// field, iterate the lines.
///
// cite(RFC 9110 § 5.3): "A recipient MAY combine multiple field lines within a field section that have the same field name into one field line, without changing the semantics of the message, by appending each subsequent field line value to the initial field line value in order, separated by a comma (",") and optional whitespace (OWS, defined in Section 5.6.3).  For consistency, use comma SP."
// cite(RFC 9110 § 5.3): "Since it cannot be combined into a single field value, recipients ought to handle "Set-Cookie" as a special case while processing fields."
pub fn get_all_header_values(headers: &HeaderMap, name: &str) -> Option<String> {
    let mut iter = headers.get_all(name).iter();
    // Return None if header is absent.
    let first = iter.next()?;
    let first_str = first.to_str().ok()?;
    let mut parts = vec![first_str.trim().to_string()];
    for hv in iter {
        let s = hv.to_str().ok()?;
        parts.push(s.trim().to_string());
    }
    Some(parts.join(", "))
}

/// The combined field value for `name` in one field section, one `char` per octet.
///
/// Two decisions, and the same sentence is behind both. A list-based field is one
/// list however many lines carry it, so the lines are joined before the members are
/// counted — an empty element written at a line boundary is an empty element. And
/// the join is over the raw octets: a value outside US-ASCII is not a value most
/// fields may carry, but it is the *member* that is wrong, so every octet is decoded
/// to the `char` of the same value and reaches the check that owns it. `to_str`
/// would fold the whole message into "no such field here", and
/// [`get_all_header_values`] folds it into `None` for the same reason — right for a
/// caller asking what a message advertised, wrong for one reporting what it wrote.
///
/// Use that one to read a value; use this one to measure the sender that wrote it.
/// Neither is valid for `Set-Cookie`, which does not use list syntax; iterate the
/// lines for that field.
///
/// cite(RFC 9110 § 5.2): "When a field name is repeated within a section, its combined field value consists of the list of corresponding field line values within that section, concatenated in order, with each field line value separated by a comma."
/// cite(RFC 9110 § 5.5): "A recipient SHOULD treat other allowed octets in field content (i.e., obs-text) as opaque data."
pub fn combined_field_value_as_written(headers: &HeaderMap, name: &str) -> Option<String> {
    Some(
        combined_field_value_octets(headers, name)?
            .into_iter()
            .map(char::from)
            .collect(),
    )
}

/// One field line's value, one `char` per octet.
///
/// [`combined_field_value_as_written`]'s per-line sibling, and the one the tree
/// was missing. A field whose grammar is *not* a list — `Content-Type` is the
/// example, and a second field line of one is another rule's finding — is read
/// line by line, and joining the lines first would answer a question § 5.2 only
/// asks of a list. So the loop is `get_all(name)` and what it needs is this: the
/// same octet-for-`char` decode, applied to the line in hand.
///
/// **`String::from_utf8_lossy(hv.as_bytes())` is not this function**, which is
/// what eleven rules reached for while it did not exist. That decoder reads the
/// octets as UTF-8 and hands back the text they spell: a sender's %xC3 %xA9 —
/// two `obs-text` octets — arrives as the single `char` U+00E9, and an octet that
/// begins no valid sequence arrives as U+FFFD, which is a character no sender can
/// write and no `field-content` admits. Every verdict of the shape *"is this
/// US-ASCII"* survives either decode, because both put the result at or above
/// %x80. What does not survive is anything that **counts** the octets, every
/// finding that **names** one — `boundary contains invalid character '<U+FFFD>'`
/// reports a character the message did not carry — and, the one that actually
/// moved verdicts when the callers were converted, **anything that trims Unicode
/// whitespace**. U+FFFD is not whitespace and U+00A0 is, so a `str::trim` that
/// left a lossy value alone removes an as-written one; three sites had that trim
/// and are `trim_ows` now. Converting a caller means sweeping it for `str::trim`,
/// not only for `len` and `format!`.
///
/// cite(RFC 9110 § 5.5): "A recipient SHOULD treat other allowed octets in field content (i.e., obs-text) as opaque data."
/// cite(RFC 9110 § 5.5): "field-content  = field-vchar [ 1*( SP / HTAB / field-vchar ) field-vchar ]"
pub fn field_line_as_written(hv: &hyper::header::HeaderValue) -> String {
    hv.as_bytes().iter().copied().map(char::from).collect()
}

/// The octets an as-written value stands for, or `None` if it is not one.
///
/// The inverse of [`field_line_as_written`] and of
/// [`combined_field_value_as_written`], and the answer for the one caller shape
/// that needs it: a rule comparing a *value* against the *body*, where the body
/// is octets and no amount of care with `char`s will make the two meet.
/// `str::as_bytes` is the trap — on a string holding one `char` per octet it
/// re-encodes, so U+00A0 comes back out as %xC2 %xA0 and a boundary the sender
/// wrote as three octets is hunted for as four.
///
/// `None` rather than a truncation when a `char` will not fit in an octet, so a
/// caller that hands this a string from somewhere else finds out. Every `char` in
/// an as-written value is below U+0100 by construction — and that is also the
/// limit of what the guard can notice: U+00E9 *is* what the octet %xE9 reads as,
/// so a genuine `"é"` and an as-written %xE9 are one string and no function can
/// separate them. What `None` catches is a string that was never an as-written
/// value at all, which is the mistake that produces octets nobody wrote.
pub fn as_written_octets(s: &str) -> Option<Vec<u8>> {
    s.chars().map(|c| u8::try_from(c as u32).ok()).collect()
}

/// The field sections a response can carry, in the order they arrive on the
/// wire, each with the name a finding calls it by.
///
/// There are two, and which of them a reader opens is not a detail any caller
/// should be deciding for itself: a rule that reads the header section alone
/// reports a response for saying nothing when it said it after the content.
/// This walk was written in `helpers::accept_ranges` first, for the one field
/// whose own section grants it a trailer; the second field to need it made the
/// walk the shared thing and the *permission* the caller's, which is the right
/// split -- whether a given field may sit in a trailer section is that field's
/// definition's answer and RFC 9110 § 6.5.1's question, and it differs per
/// caller. What does not differ is that there are exactly two sections, in this
/// order, and that they are never joined to each other: appending a field line
/// to the one before it is defined *within* a field section.
///
/// The label is `&'static str` rather than an enum for the same reason
/// `header_field_names_token_valid` passes one -- a finding says which
/// section it came from and nothing else turns on the distinction.
///
/// cite(RFC 9110 § 6.5): "Fields (Section 5) that are located within a "trailer section" are referred to as "trailer fields""
pub fn response_field_sections(
    resp: &crate::http_transaction::ResponseInfo,
) -> impl Iterator<Item = (&'static str, &HeaderMap)> {
    message_field_sections(
        &resp.headers,
        resp.trailers.as_ref(),
        ("header section", "trailer section"),
    )
}

/// The field sections of one message, in wire order, under the names its
/// caller's findings use.
///
/// This is the sentence both public walks rest on and the only thing they
/// share: **a message has exactly two field sections, in this order, and they
/// are never joined to each other** — appending a field line to the one before
/// it is defined *within* a field section, which is why a value spanning the
/// two is two values and not one.
///
/// The labels are a parameter because they are the *finding's* wording rather
/// than a decision the walk makes: a rule that reads one direction says "header
/// section" because there is no other, and a rule reading both has to say which
/// direction or its findings are ambiguous. Nothing else turns on the string.
fn message_field_sections<'a>(
    headers: &'a HeaderMap,
    trailers: Option<&'a HeaderMap>,
    labels: (&'static str, &'static str),
) -> impl Iterator<Item = (&'static str, &'a HeaderMap)> {
    [Some((labels.0, headers)), trailers.map(|t| (labels.1, t))]
        .into_iter()
        .flatten()
}

/// Every field section a transaction carries, in wire order, each named by the
/// direction it belongs to as well as by its position.
///
/// Four at most: the request's two, then the response's two when the upstream
/// answered at all. This is [`response_field_sections`]'s question asked of a
/// whole transaction, and the two exist separately because their labels differ
/// and the labels are what a finding prints — a response-only rule saying
/// *"response header section"* is naming a direction its scope already fixed.
///
/// A rule reaching for this is one whose governing sentence names neither a
/// direction nor a section, which is what makes all four in scope. That is a
/// claim about the sentence and has to be checked per rule: `User-Agent`'s
/// SHOULD is about a request's header section, and reading its trailer section
/// for one would count a field § 6.5.1 forbids as satisfying § 10.1.5.
///
/// cite(RFC 9110 § 5): "Fields are sent and received within the header and trailer sections of messages"
/// cite(RFC 9110 § 6.5): "Fields (Section 5) that are located within a "trailer section" are referred to as "trailer fields""
pub fn transaction_field_sections(
    tx: &crate::http_transaction::HttpTransaction,
) -> impl Iterator<Item = (&'static str, &HeaderMap)> {
    message_field_sections(
        &tx.request.headers,
        tx.request.trailers.as_ref(),
        ("request header section", "request trailer section"),
    )
    .chain(tx.response.iter().flat_map(|resp| {
        message_field_sections(
            &resp.headers,
            resp.trailers.as_ref(),
            ("response header section", "response trailer section"),
        )
    }))
}

/// The same combined field value as [`combined_field_value_as_written`], as the
/// octets themselves.
///
/// Every octet crosses into a `char` of the same value and back without loss, so
/// the two functions differ only in what the caller finds convenient: a parser
/// written against a grammar whose terminals are octet ranges (`ctext`,
/// `obs-text`, `quoted-pair`) reads bytes, and one comparing tokens reads a
/// `&str`. The join itself -- and the sentence that licenses it -- lives here
/// once, so neither caller decides separately what a field's value is.
pub fn combined_field_value_octets(headers: &HeaderMap, name: &str) -> Option<Vec<u8>> {
    let mut lines = headers.get_all(name).iter().peekable();
    lines.peek()?;
    let mut combined: Vec<u8> = Vec::new();
    // The separator goes between the lines, and "between" is a count of lines and
    // not of the characters written so far: a first line carrying nothing is a
    // line, and joining on "is there anything yet" swallowed it — putting the one
    // empty member the joining exists to expose back out of reach.
    let mut first = true;
    for hv in lines {
        if !first {
            combined.push(b',');
        }
        first = false;
        combined.extend_from_slice(hv.as_bytes());
    }
    Some(combined)
}

/// Trim `OWS` -- and only `OWS` -- from both ends of a field value or one of its
/// members.
///
/// `str::trim` trims Unicode whitespace, and a value read through
/// [`combined_field_value_as_written`] carries one `char` per octet -- so U+00A0
/// in it is the octet %xA0, which is `obs-text` and not whitespace of any kind.
/// Trimming it would turn a member no production admits into an empty one,
/// reporting the list for a defect the element has. U+0085 is the same story at
/// %x85. Every list-based field measuring what a sender wrote needs this, so it
/// is transcribed once rather than per rule.
///
/// cite(RFC 9110 § 5.6.3): "The OWS rule is used where zero or more linear whitespace octets might appear."
/// cite(RFC 9110 § 5.6.3, label: OWS grammar): "OWS            = *( SP / HTAB )"
pub fn trim_ows(s: &str) -> &str {
    s.trim_matches(|c| c == ' ' || c == '\t')
}

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

#[cfg(test)]
mod validator_extraction_tests {
    use super::extract_strong_validators_from_response;
    use super::extract_validators_from_response;
    use hyper::header::HeaderValue;
    use hyper::HeaderMap;

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
}

#[cfg(test)]
mod concat_header_tests {
    use super::get_all_header_values;
    use super::inm_matches_known;
    use hyper::header::HeaderValue;
    use hyper::HeaderMap;

    #[test]
    fn concat_single_value() {
        let mut headers = HeaderMap::new();
        headers.insert("foo", HeaderValue::from_static("bar"));
        assert_eq!(
            get_all_header_values(&headers, "foo"),
            Some("bar".to_string())
        );
    }

    #[test]
    fn concat_multiple_values() {
        let mut headers = HeaderMap::new();
        headers.append("foo", HeaderValue::from_static("bar"));
        headers.append("foo", HeaderValue::from_static("baz"));
        assert_eq!(
            get_all_header_values(&headers, "foo"),
            Some("bar, baz".to_string())
        );
    }

    #[test]
    fn trim_and_missing() {
        let mut headers = HeaderMap::new();
        headers.insert("foo", HeaderValue::from_static("  bar  "));
        assert_eq!(
            get_all_header_values(&headers, "foo"),
            Some("bar".to_string())
        );
        assert_eq!(get_all_header_values(&headers, "bar"), None);
    }

    #[test]
    fn inm_matches_known_behaviour() {
        assert!(inm_matches_known("\"a\"", "\"a\""));
        assert!(inm_matches_known("W/\"a\"", "\"a\""));
        assert!(!inm_matches_known("\"b\"", "\"a\""));
        assert!(!inm_matches_known("*", "\"a\""));
    }
}
/// Field names that cannot appear in a trailer section, by category.
///
/// This is the fixed half of the question "may this field be a trailer". The other
/// half is [`is_nominated_by_connection`], which depends on the message.
///
/// **This table is a subset, and deliberately so.** The requirement is stated the
/// other way round — a trailer field is forbidden *unless* the sender knows the
/// field's own definition permits it, and the registry guidance says that by default
/// no definition does. A table of names answers the opposite question, so every field
/// nobody thought of passes. It cannot be inverted here: for a field this codebase
/// holds no definition of (`X-Checksum`, `Grpc-Status`), only the sender knows whether
/// a definition permits the usage, and reporting all of them would report the senders
/// that read their own specification. What the table can hold honestly is the fields
/// whose definitions are in the specifications this crate cites and do *not* permit
/// trailers; `trailer_fields_valid` says so where an operator reads it.
///
/// The categories below are the ones §6.5.1 names, in its order. The last group is
/// here because a connection-specific field is, by definition, needed before the
/// content is read; `trailer` is here because a Trailer field inside a trailer
/// section announces nothing.
///
/// Membership is per field *definition*, never per category: RFC 9110 puts
/// `Authentication-Info` and `Proxy-Authentication-Info` under authentication and
/// then permits both in trailers, so neither is here. See
/// [`is_prohibited_trailer_field`] for where that is written down.
///
// cite(RFC 9110 § 6.5.1): "Many fields cannot be processed outside the header section because their evaluation is necessary prior to receiving the content, such as those that describe message framing, routing, authentication, request modifiers, response controls, or content format."
// cite(RFC 9110 § 6.5.1): "A sender MUST NOT generate a trailer field unless the sender knows the corresponding header field name's definition permits the field to be sent in trailers."
// cite(RFC 9110 § 16.3.2): "If the field is allowable in trailers; by default, it will not be (see Section 6.5.1)."
pub static PROHIBITED_TRAILER_FIELDS: &[&str] = &[
    // Message framing
    "content-length",
    "transfer-encoding",
    // Routing
    "host",
    // `Forwarded` is routing too, and RFC 7239 defines it for the header
    // section and nowhere else — so the sender does not know its definition
    // permits a trailer, because it does not.
    "forwarded",
    // Request modifiers — controls
    "cache-control",
    "expect",
    "max-forwards",
    "pragma",
    "range",
    "te",
    // Request modifiers — conditionals
    "if-match",
    "if-modified-since",
    "if-none-match",
    "if-range",
    "if-unmodified-since",
    // Authentication (RFC 9110 §11). `Authentication-Info` and
    // `Proxy-Authentication-Info` are the two that §11 takes back out again, and
    // they are not here.
    "authorization",
    "proxy-authenticate",
    "proxy-authorization",
    "www-authenticate",
    // Response control data. These are the fields §6.5.1's "response controls"
    // names in prose; §6.2 "Control Data" is the start line, not this.
    "age",
    "date",
    "expires",
    "location",
    "retry-after",
    "vary",
    "warning",
    // Payload processing
    "content-encoding",
    "content-range",
    "content-type",
    "trailer",
    // Connection-specific (RFC 9110 §7.6.1). The section's own list is bullets
    // too short to cite; the citable form is RFC 9113's parenthetical, a
    // published reading of that list, and it names `Proxy-Connection` in it —
    // the member this table omitted while `CONNECTION_SPECIFIC_FIELDS` below
    // held it, which is what made the omission a reading rather than a
    // decision (RULECITES P46). `transfer-encoding` and `te` are §7.6.1's too
    // and sit above under the framing and request-modifier categories §6.5.1
    // names them by.
    // cite(RFC 9113 § 8.2.2): "This includes the Connection header field and those listed as having connection-specific semantics in Section 7.6.1 of [HTTP] (that is, Proxy-Connection, Keep-Alive, Transfer-Encoding, and Upgrade)."
    "connection",
    "keep-alive",
    "proxy-connection",
    "upgrade",
    // The cleanest member of this list: § 6.5.1 asks whether the field's own
    // definition permits the usage, and this field's definition answers by name.
    // The same sentence forbids it in a response, which is
    // `early_data_header_safe_method`'s finding — a response *trailer* is
    // both, and is reported here.
    // cite(RFC 8470 § 5.1): "An Early-Data header field MUST NOT be included in responses or request trailers."
    "early-data",
];

/// Whether `name` cannot appear in a trailer section because of what it is.
///
/// See [`is_nominated_by_connection`] for the half that depends on the message.
///
/// Two fields this returns `false` for used to be in the table, on the strength of
/// the category §6.5.1 lists them under. Both definitions say the opposite in one
/// sentence each, and the sentence is the thing §6.5.1 asks the sender to know — so
/// a sender whose scheme allows it is conforming, and the rule that reports this
/// cannot tell which scheme is in use. The permission is conditional and the
/// condition is not on the wire; a name the RFC permits at all does not belong in a
/// table of names the RFC forbids.
///
// cite(RFC 9110 § 11.6.3): "Authentication-Info can be sent as a trailer field (Section 6.5) when the authentication scheme explicitly allows this."
// cite(RFC 9110 § 11.7.3): "Proxy-Authentication-Info can be sent as a trailer field (Section 6.5) when the authentication scheme explicitly allows this."
pub fn is_prohibited_trailer_field(name: &str) -> bool {
    let name_l = name.trim().to_ascii_lowercase();
    PROHIBITED_TRAILER_FIELDS.contains(&name_l.as_str())
}

/// Fields that are connection-specific whatever the message says.
///
/// The first six are RFC 9110 § 7.6.1's own list, plus `connection` itself, which the
/// same section has an intermediary remove after acting on it. The last two are not
/// § 7.6.1's: they are single-hop by their own definitions in § 11.7.1 and § 11.7.2.
///
/// `trailer` is deliberately not here — § 6.6.2 has it surviving the hop. It cannot be
/// a *trailer field*, but that is § 6.5.1's business and
/// [`PROHIBITED_TRAILER_FIELDS`] is where it says so.
// cite(RFC 9110 § 7.6.1): "Furthermore, intermediaries SHOULD remove or replace fields that are known to require removal before forwarding, whether or not they appear as a connection-option, after applying those fields' semantics."
static CONNECTION_SPECIFIC_FIELDS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "transfer-encoding",
    "upgrade",
    // Single-hop by their own definitions, not by § 7.6.1's list.
    "proxy-authenticate",
    "proxy-authorization",
];

/// Whether `name` is connection-specific — either always, or because this message's
/// `Connection` header nominated it.
pub fn is_connection_specific_field(name: &str, connection_header_value: Option<&str>) -> bool {
    let name_l = name.trim().to_ascii_lowercase();
    CONNECTION_SPECIFIC_FIELDS.contains(&name_l.as_str())
        || is_nominated_by_connection(name, connection_header_value)
}

/// Whether `name` was named as a connection-option in this message's `Connection`
/// header, which disqualifies it from the trailer section for this message only.
///
/// The cited sentence says "header **or trailer** field(s)", and that is the whole
/// reason a connection-option reaches into a trailer section at all.
///
/// Every caller passes a value joined by [`combined_field_value_as_written`], i.e.
/// one `char` per octet, so the member walk is the `OWS`-trimming one: a member
/// padded with an `obs-text` octet that renders like a space is not the
/// `connection-option` it resembles, and no sentence lets this function pretend it
/// is. The fold *is* licensed -- a `connection-option` is a field name, and those
/// are case-insensitive.
// cite(RFC 9110 § 5.1): "Field names are case-insensitive"
pub fn is_nominated_by_connection(name: &str, connection_header_value: Option<&str>) -> bool {
    // cite(RFC 9110 § 7.6.1): "Intermediaries MUST parse a received Connection header field before a message is forwarded and, for each connection-option in this field, remove any header or trailer field(s) from the message with the same name as the connection-option, and then remove the Connection header field itself (or replace it with the intermediary's own control options for the forwarded message)."
    let name_l = name.trim().to_ascii_lowercase();
    let Some(conn) = connection_header_value else {
        return false;
    };
    list_members(conn).any(|tok| tok.eq_ignore_ascii_case(name_l.as_str()))
}

/// What a response's `Vary` nominates.
///
/// The two arms are the two alternatives of `Vary = #( "*" / field-name )`, and
/// they are kept apart because a caller cannot treat them the same: `*` says the
/// response varies on something a request's fields do not name, which RFC 9111
/// § 4.1 turns into *always fails to match*, while a list of names is something
/// a cache can compare. A member of `*` anywhere in the list makes the whole
/// value that, since the sentence says *containing a member*.
pub enum VaryNomination {
    /// Some member is `*`.
    Wildcard,
    /// The field names nominated, folded to lowercase, in the order written.
    /// Empty for a field that is absent and for a zero-element list, which
    /// nominate the same nothing.
    Fields(Vec<String>),
}

impl VaryNomination {
    /// Whether `name` is nominated. `*` nominates every name.
    pub fn nominates(&self, name: &str) -> bool {
        match self {
            Self::Wildcard => true,
            Self::Fields(fields) => {
                let name = name.trim().to_ascii_lowercase();
                fields.contains(&name)
            }
        }
    }

    /// Whether some member is `*`.
    pub fn is_wildcard(&self) -> bool {
        matches!(self, Self::Wildcard)
    }
}

/// Read a response's `Vary` field.
///
/// **Three rules asked this question and the three disagreed; two of them were
/// wrong, and in the same two ways.** Both read `get_all("vary")` line by line
/// and bailed on a line `to_str` refused — one returning no finding, the other
/// silently skipping the line — so a single `obs-text` octet anywhere in the
/// value stood the whole rule down. And neither joined the lines, so a `*`
/// written on a second field line was a `*` to the third rule and not to them.
/// § 5.3 makes the lines one value; the field is a `#` list, which is what
/// licenses the join.
///
/// The walk is [`list_members`] — a naive comma split, `OWS`-trimmed, empty
/// members dropped — and this is its second caller. **Naive is the right answer
/// here and it is the grammar that says so**: `Vary`'s members are `"*"` and
/// `field-name`, and a `field-name` is a `token`, which admits no
/// `quoted-string`. Where an element cannot hold one, a DQUOTE is a character
/// the member may not have, and reading it as opening a quoted-string makes the
/// *next* comma data when there is no quoted-string for it to be data in — so
/// `Vary: "x, prefer` nominates `Prefer`, and the quote-aware walk one caller
/// used said it did not.
///
/// The fold is licensed: a `field-name` is a field name.
// cite(RFC 9110 § 12.5.5, label: Vary grammar): "Vary = #( "*" / field-name )"
// cite(RFC 9110 § 5.1): "Field names are case-insensitive"
// cite(RFC 9110 § 5.3): "A recipient MAY combine multiple field lines within a field section that have the same field name into one field line, without changing the semantics of the message, by appending each subsequent field line value to the initial field line value in order, separated by a comma (",") and optional whitespace (OWS, defined in Section 5.6.3)."
// cite(RFC 9111 § 4.1): "A stored response with a Vary header field value containing a member "*" always fails to match."
pub fn vary_nomination(response_headers: &HeaderMap) -> VaryNomination {
    let Some(value) = combined_field_value_as_written(response_headers, "vary") else {
        return VaryNomination::Fields(Vec::new());
    };
    let mut fields = Vec::new();
    for member in list_members(&value) {
        if member == "*" {
            return VaryNomination::Wildcard;
        }
        fields.push(member.to_ascii_lowercase());
    }
    VaryNomination::Fields(fields)
}

/// The sentence a singleton field says when a message carries more than one of
/// its field lines.
///
/// **Only the first sentence, and that is the whole design.** Five rules say it;
/// four of them then append a second sentence saying *why* the join is wrong,
/// and those four are four different facts, because the join is wrong in a
/// different way per field. For `Max-Forwards` the comma is
/// malformed inside `1*DIGIT`. For `Location` it is a valid data character
/// inside a `URI-reference`, so the joined value is a well-formed reference to
/// neither resource. For `Referer` and `Content-Location`, which share one
/// production, it is a `sub-delims` character both alternatives admit inside a
/// path or a query. For `From` it is `mailbox-list`'s separator — a well-formed
/// production of RFC 5322 that the field does not import. So the caller appends
/// its own; what is shared ends at the semicolon-joined clause below.
///
/// The parameters are in the order the sentence reads them, which is what keeps
/// two adjacent `&str` arguments from being swappable in silence: the field, how
/// many lines it was written on, what those lines recombine into, and the
/// field's own reason for being a singleton.
///
/// `shown_value` is already rendered for a finding, because the four callers
/// render differently on purpose — `escape_debug`, [`shown_in_finding`](crate::helpers::shown::shown_in_finding), and a
/// `Referer`-specific one that withholds a userinfo. What a finding may print is
/// the field's question, not this function's.
///
/// **Not for a field counted across two sections.** The recombining clause is
/// § 5.2's, and § 5.2 is *within a section*; § 5.3's MUST NOT is about the whole
/// message and says so (*"whether in the headers or trailers"*). A rule counting
/// both sections at once — `content_disposition_token_valid` does — is
/// answering § 5.3 correctly and cannot honestly say what § 5.2 recombines,
/// which is why it says something else instead.
///
// cite(RFC 9110 § 5.5): "Fields that only anticipate a single member as the field value are referred to as "singleton fields"."
// cite(RFC 9110 § 5.5): "This is true for both list-based and singleton fields, since a singleton field might be erroneously sent with multiple members and detecting such errors improves interoperability."
// cite(RFC 9110 § 5.2): "When a field name is repeated within a section, its combined field value consists of the list of corresponding field line values within that section, concatenated in order, with each field line value separated by a comma."
// cite(RFC 9110 § 5.3): "a sender MUST NOT generate multiple field lines with the same name in a message (whether in the headers or trailers) or append a field line when a field line of the same name already exists in the message, unless that field's definition allows multiple field line values to be recombined as a comma-separated list"
pub fn singleton_field_preamble(
    field: &str,
    lines: usize,
    shown_value: &str,
    grammar: &str,
) -> String {
    format!(
        "{field} is written on {lines} header lines, which recombine into the one value \
         '{shown_value}'; the field is a singleton — {grammar} — so a sender must not generate \
         more than one field line for it (RFC 9110 §5.3)"
    )
}

/// Why a value derives from neither alternative of `( token / quoted-string )`.
///
/// Data rather than a sentence, and that is the whole reason this extraction was
/// possible at all. The alternation is one production; the finding is not. Seven
/// sites read this pair and each says something about its own field — an
/// `Alt-Svc` parameter, a `Server-Timing` parameter, a `Pragma` directive, a
/// media type's parameter, a `Keep-Alive` parameter, a `Prefer` preference. Six
/// of them had also decided, separately and in four different ways, what an
/// empty value means. So what is shared here is the decision and the two
/// measurements behind it; **the wording, and the verdict on
/// [`WordDefect::Empty`], stay at the caller** — which is where each field's own
/// sentence about it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WordDefect {
    /// The value is empty, and neither alternative derives the empty string:
    /// `token = 1*tchar` has a one-character floor, and the shortest
    /// `quoted-string` is its two DQUOTEs. That is arithmetic on two
    /// productions and is not a per-field question — but what a field *does*
    /// about it is, and two rules in this tree tolerate it on the record.
    Empty,
    /// An unquoted value holding a character no `tchar` admits. Unquoted by
    /// elimination rather than by inspection: see [`token_or_quoted_string`].
    NotToken(char),
    /// A leading DQUOTE opened something that is not a well-formed
    /// `quoted-string`, carrying the interior walk's own account of it.
    NotQuotedString(String),
}

/// Read one `( token / quoted-string )` and return what it holds.
///
/// The alternation is decided by the first octet and by nothing else: RFC 9110
/// § 5.6.2 makes DQUOTE a delimiter, so no `token` can open with one and a value
/// that does is trying to be a `quoted-string` and nothing else. A value that
/// does not open with one is a `token` by elimination, which is why the `tchar`
/// scan below is the whole of that half.
///
/// The content returned is what the field means by the value: a `token` as
/// written, a `quoted-string` after `quoted-pair` substitution. A caller that
/// only judges the value may discard it — [`unescape_quoted_string`] opens by
/// asking [`validate_quoted_string`], so the two accept exactly the same strings
/// and the `Err` is the same `Err`.
///
/// RFC 7230 named this pair `word`; RFC 9110 kept both halves and dropped the
/// name, which is why the two productions cited here are the halves and not the
/// whole. Callers whose own document writes its own name for it —
/// `server-timing-param-value`, `parameter-value`, RFC 2068's `value` — cite
/// that at their site.
///
// cite(RFC 9110 § 5.6.2): "Delimiters are chosen from the set of US-ASCII visual characters not allowed in a token (DQUOTE and "(),/:;<=>?@[\]{}")."
// cite(RFC 9110 § 5.6.2): "token = 1*tchar tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA"
// cite(RFC 9110 § 5.6.4): "quoted-string  = DQUOTE *( qdtext / quoted-pair ) DQUOTE"
pub fn token_or_quoted_string(value: &str) -> Result<std::borrow::Cow<'_, str>, WordDefect> {
    if value.is_empty() {
        return Err(WordDefect::Empty);
    }
    if value.starts_with('"') {
        return unescape_quoted_string(value)
            .map(std::borrow::Cow::Owned)
            .map_err(WordDefect::NotQuotedString);
    }
    match crate::helpers::token::find_invalid_token_char(value) {
        Some(c) => Err(WordDefect::NotToken(c)),
        None => Ok(std::borrow::Cow::Borrowed(value)),
    }
}

/// One `token [ BWS "=" BWS word ]` pair, parsed.
///
/// RFC 7240 writes that production three times — `preference`, `parameter` and
/// `applied-pref` — and says in prose that the third is the first minus its
/// parameters, so the pair itself is one thing written once here rather than
/// per field. `word` is the name RFC 7230 gave `( token / quoted-string )`;
/// RFC 9110 kept both halves and dropped the name, which is why the pair is
/// cited by its halves at [`token_or_quoted_string`], where it is read, and not
/// under a name no document in force writes.
pub struct TokenBwsWord<'a> {
    /// The `token`, exactly as written. Case folding is the caller's: whether
    /// two names are the same string is a question each field answers for
    /// itself.
    pub name: &'a str,
    /// The `word`'s content — `None` when the optional group is absent, and for
    /// a `quoted-string` the octets after `quoted-pair` substitution rather than
    /// the quoted form. An empty `Some` can only come from `""`, which some
    /// fields define as meaning no value; that reading belongs to the field, so
    /// it is reported here as what was written.
    pub value: Option<String>,
    /// Whether whitespace appeared beside the `=`.
    ///
    /// The member handed in has already lost the `OWS` its list prints around
    /// the commas, so anything still adjacent to the `=` is the `BWS` the
    /// grammar admits only for historical reasons — and that is a statement
    /// about the sender, which is why this is returned instead of being
    /// silently absorbed by the trim that has to happen anyway.
    pub bws: bool,
}

/// Parse `token [ BWS "=" BWS word ]` from one already-`OWS`-trimmed member.
///
/// Callers reading a field through [`combined_field_value_as_written`] hand this
/// one `char` per octet, and that is the intended input: an `obs-text` octet is
/// admitted by the `quoted-string` half and by no part of the `token` half, so
/// only the octets say which side of the alternation it landed on.
///
/// The shape itself is cited at the field that has it, not here — a helper
/// shared by three productions can honestly quote only the halves they agree
/// on. `token` is transcribed once at [`crate::helpers::token::is_tchar`], and
/// the `word` half is read by [`token_or_quoted_string`]; what is left here is
/// the part RFC 7240 owns, which is the optional group and the `BWS`.
///
/// cite(RFC 9110 § 5.6.3): "The BWS rule is used where the grammar allows optional whitespace only for historical reasons."
pub fn parse_token_bws_word(member: &str) -> Result<TokenBwsWord<'_>, String> {
    // `token` admits neither `=` nor DQUOTE, so nothing can precede the `=` the
    // production prints except the name -- there is no quoted-string in front of
    // it for one to hide in, and the first `=` is therefore the delimiter even
    // when the `word` after it is a quoted-string containing more of them.
    let (name_written, value_written) = match member.find('=') {
        Some(i) => (&member[..i], Some(&member[i + 1..])),
        None => (member, None),
    };
    let name = trim_ows(name_written);
    let value_written_trimmed = value_written.map(trim_ows);
    let bws = name != name_written || value_written_trimmed != value_written;

    if name.is_empty() {
        return Err("no token before the \"=\"".to_string());
    }
    if let Some(c) = crate::helpers::token::find_invalid_token_char(name) {
        return Err(format!("token contains {}", describe_char(c)));
    }

    let value = match value_written_trimmed {
        None => None,
        Some(v) => match token_or_quoted_string(v) {
            Ok(content) => Some(content.into_owned()),
            // `word` is `token / quoted-string` and `token` is `1*tchar`, so the
            // optional group cannot close on an empty value: a field that means
            // to say "no value" writes no `=`, or writes `""`. RFC 7240 grants
            // no tolerance for the third spelling, so this is a defect here.
            Err(WordDefect::Empty) => {
                return Err("nothing after the \"=\", where the grammar has a word".to_string())
            }
            Err(WordDefect::NotToken(c)) => {
                return Err(format!("value contains {}", describe_char(c)))
            }
            Err(WordDefect::NotQuotedString(e)) => return Err(e),
        },
    };

    Ok(TokenBwsWord { name, value, bws })
}

/// Validate qvalue syntax: `0`, `1`, `0.5`, `0.123`, `1.000` — up to three
/// digits after the point, and only zeroes after a leading `1`.
///
/// Written as the production reads rather than as a list of the strings it
/// generates. The enumeration this replaced (`s == "1" || s == "1.0" || ...`)
/// missed `0.` and `1.`, which `0*3DIGIT` and `0*3("0")` both admit at zero
/// repetitions — so two conforming values were reported as malformed by every
/// rule that asks this question.
///
/// The leading/trailing trim is a tolerance, not the grammar: a `qvalue` has no
/// whitespace in it anywhere. Every caller trims before asking, so it changes
/// no verdict today; it is kept because nothing depends on it being strict and
/// removing it would be a silent trap for a caller that does not trim.
pub fn valid_qvalue(s: &str) -> bool {
    let s = s.trim();
    // The three-decimal cap and the "1 may only be followed by zeroes" asymmetry are
    // both in the production; neither is arbitrary.
    // cite(RFC 9110 § 12.4.2, label: qvalue grammar): "qvalue = ( "0" [ "." 0*3DIGIT ] ) / ( "1" [ "." 0*3("0") ] )"
    let (rest, digit_ok): (&str, fn(u8) -> bool) = if let Some(rest) = s.strip_prefix('0') {
        (rest, |b| b.is_ascii_digit())
    } else if let Some(rest) = s.strip_prefix('1') {
        (rest, |b| b == b'0')
    } else {
        return false;
    };

    // `[ "." 0*3DIGIT ]` — the fraction is optional, and so is every digit in it.
    match rest.strip_prefix('.') {
        None => rest.is_empty(),
        Some(fraction) => fraction.len() <= 3 && fraction.bytes().all(digit_ok),
    }
}

/// Validate an RFC 8187 `ext-value` (e.g. `UTF-8''%e2%82%ac%20rates`).
/// Returns Ok(()) if the value matches the expected pattern and contains
/// only allowed characters/percent-escapes, or Err(msg) describing the
/// problem.
///
/// This said RFC 5987, which RFC 8187 obsoletes and moved to Historic. The
/// pointer is worth correcting and worth not overstating: the two documents'
/// `ext-value`, `value-chars`, `pct-encoded` and `attr-char` productions are
/// byte-for-byte identical, so nothing here changed meaning when the reference
/// did. What 8187 changed is elsewhere -- the ISO-8859-1 requirement is gone,
/// and it stopped trying to define a generic `parameter` rule.
///
/// The `charset` is checked only for being ASCII and quote-free, which is far
/// looser than `mime-charset`, so that production is deliberately not quoted
/// below -- it would describe a check this function does not make.
///
// cite(RFC 8187 § 3.2.1): "ext-value = charset  "'" [ language ] "'" value-chars"
pub fn validate_ext_value(val: &str) -> Result<(), String> {
    // Must contain at least two single quotes separating charset, optional language, and value-chars
    let first_quote = val
        .find('\'')
        .ok_or_else(|| "ext-value missing charset separator".to_string())?;
    let rest = &val[first_quote + 1..];
    let second_quote = rest
        .find('\'')
        .ok_or_else(|| "ext-value missing language separator".to_string())?
        + first_quote
        + 1;

    let charset = &val[..first_quote];
    if charset.is_empty() {
        return Err("charset in ext-value must not be empty".into());
    }
    // Basic charset sanity: must be ASCII and not contain quote
    if !charset.is_ascii() || charset.contains('\'') {
        return Err("invalid charset in ext-value".into());
    }

    // Language part may be empty; we don't strictly validate language tags here
    let value_chars = &val[second_quote + 1..];
    if value_chars.is_empty() {
        // empty value is allowed
        return Ok(());
    }

    let mut i = 0usize;
    let bytes = value_chars.as_bytes();
    // cite(RFC 8187 § 3.2.1): "value-chars   = *( pct-encoded / attr-char )"
    while i < bytes.len() {
        let b = bytes[i];
        // This branch is why `%` is absent from the attr-char table below rather
        // than merely unreachable in it: a `%` here is always the start of an
        // escape, and the two productions do not overlap.
        //
        // cite(RFC 8187 § 3.2.1): "pct-encoded   = "%" HEXDIG HEXDIG"
        if b == b'%' {
            // Expect two hex digits
            if i + 2 >= bytes.len() {
                return Err("incomplete percent-encoding in ext-value".into());
            }
            let hi = bytes[i + 1];
            let lo = bytes[i + 2];
            if !((hi as char).is_ascii_hexdigit() && (lo as char).is_ascii_hexdigit()) {
                return Err("invalid percent-encoding in ext-value".into());
            }
            i += 3;
            continue;
        }
        let ch = bytes[i] as char;
        // The table carried a `'%'` for as long as it has existed, under a comment
        // claiming it was RFC 5987's attr-char. It was not: both documents spell
        // this production identically and both exclude `%`, along with `*` and `'`.
        // It was dead as well as wrong -- the branch above consumes every `%` before
        // this arm is reached -- so removing it moved no test.
        //
        // cite(RFC 8187 § 3.2.1): "attr-char     = ALPHA / DIGIT / "!" / "#" / "$" / "&" / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~" ; token except ( "*" / "'" / "%" )"
        if ch.is_ascii_alphanumeric()
            || matches!(
                ch,
                '!' | '#' | '$' | '&' | '+' | '-' | '.' | '^' | '_' | '`' | '|' | '~'
            )
        {
            i += 1;
            continue;
        }
        return Err(format!("invalid character '{}' in ext-value", ch));
    }

    Ok(())
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
    fn test_get_header_str() {
        let mut map = HeaderMap::new();
        map.insert("x-foo", HeaderValue::from_static("bar"));
        map.insert("x-bin", HeaderValue::from_bytes(b"\xff").unwrap());

        assert_eq!(get_header_str(&map, "x-foo"), Some("bar"));
        assert_eq!(get_header_str(&map, "x-bin"), None);
        assert_eq!(get_header_str(&map, "x-missing"), None);
    }

    /// The three decodes of one field line, side by side, on the value that
    /// tells them apart. `to_str` refuses it outright; `from_utf8_lossy` reads
    /// the octets as UTF-8 and hands back the text they spell; this one hands
    /// back the octets. %xC3 %xA9 is two `obs-text` octets a sender wrote and
    /// U+00E9 is not either of them, and %xA0 begins no valid sequence at all —
    /// so the lossy reading names a character (U+FFFD) that no `field-content`
    /// admits and no message carried.
    #[test]
    fn field_line_as_written_is_the_octets_and_from_utf8_lossy_is_not() {
        let hv = HeaderValue::from_bytes(b"caf\xC3\xA9").unwrap();
        assert!(hv.to_str().is_err());
        assert_eq!(String::from_utf8_lossy(hv.as_bytes()), "café");
        assert_eq!(
            field_line_as_written(&hv)
                .chars()
                .map(|c| c as u32)
                .collect::<Vec<_>>(),
            [0x63, 0x61, 0x66, 0xC3, 0xA9]
        );

        let lone = HeaderValue::from_bytes(b"x\xA0y").unwrap();
        assert!(String::from_utf8_lossy(lone.as_bytes()).contains('\u{FFFD}'));
        assert_eq!(field_line_as_written(&lone), "x\u{A0}y");
    }

    /// The inverse round-trips. A caller comparing a value against a body needs
    /// the octets back; `as_bytes` would re-encode U+00A0 into the two it is not.
    ///
    /// **The `None` guard reaches above U+00FF and no lower, and that is not a
    /// gap that can be closed.** `as_written_octets("é")` is `Some([0xE9])`,
    /// because U+00E9 is exactly what the octet %xE9 reads as — the two strings
    /// are the same string, and no function can tell which one a caller meant.
    /// What the guard catches is a string that was never an as-written value at
    /// all, which is the mistake worth catching: it fails loudly instead of
    /// truncating U+1F600 into one octet nobody wrote.
    #[test]
    fn as_written_octets_inverts_the_reader_and_refuses_what_was_never_one() {
        let hv = HeaderValue::from_bytes(b"x\xA0y\xFF").unwrap();
        let written = field_line_as_written(&hv);
        assert_eq!(as_written_octets(&written).as_deref(), Some(hv.as_bytes()));
        assert_ne!(written.as_bytes(), hv.as_bytes(), "as_bytes re-encodes");

        assert_eq!(as_written_octets("é"), Some(vec![0xE9]));
        assert_eq!(as_written_octets("😀"), None);
    }

    /// Why converting `parse_list_header`'s thirty-six call sites changed
    /// nothing at twenty-nine of them and everything at seven. Twenty-six read
    /// their value back through `to_str`, which returns `Err` for every octet
    /// outside `%x20-7E` plus HTAB, so the `&str` it hands back cannot hold a
    /// whitespace character the two trims disagree about; three more are Rust
    /// string literals in a test's own fixture. The disagreement is reachable
    /// only through a reader that does not refuse those octets.
    ///
    /// **The octet is placed at both ends, which is the only place a trim can
    /// see it.** An earlier spelling of this test wrapped it as `a<octet>b`,
    /// where both trims are the identity for every input and the assertion says
    /// `s == s`. A test whose fixture cannot reach the branch it is about is the
    /// already-clean-fixture shape, one level in from the message it asserts.
    #[test]
    fn to_str_admits_no_whitespace_the_two_trims_disagree_about() {
        for b in 0u8..=0xFF {
            let Ok(hv) = HeaderValue::from_bytes(&[b, b'a', b]) else {
                continue;
            };
            let Ok(s) = hv.to_str() else { continue };
            assert_eq!(
                s.trim(),
                trim_ows(s),
                "octet {b:#04x} reached `to_str` and the two trims disagree on it"
            );
        }
    }

    /// Each row is a weight and whether the `qvalue` production admits it. A
    /// table rather than a run of `assert!` lines, so a failure names the value.
    #[test]
    fn test_valid_qvalue() {
        const CASES: &[(&str, bool)] = &[
            ("1", true),
            ("1.0", true),
            ("1.00", true),
            ("1.000", true),
            ("0", true),
            ("0.5", true),
            ("0.123", true),
            ("0.000", true),
            // `0*3DIGIT` and `0*3("0")` are satisfied by no digits at all, so a
            // point with nothing after it conforms. The enumeration this replaced
            // reported both as malformed.
            ("0.", true),
            ("1.", true),
            ("1.0000", false),
            ("0.1234", false),
            // Only zeroes may follow a leading 1: the weight is capped at 1.
            ("1.1", false),
            ("1.001", false),
            ("abc", false),
            ("", false),
            ("2", false),
            ("-1", false),
            ("0.5.5", false),
            ("00", false),
            ("0.a", false),
        ];

        for (value, is_qvalue) in CASES {
            assert_eq!(valid_qvalue(value), *is_qvalue, "for {value:?}");
        }
    }

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

    /// The alternation is decided by the first octet and by nothing else, and
    /// each of the three defects is a distinct answer rather than one `Err`:
    /// the seven callers that used to write this out disagree about `Empty` in
    /// particular, so it has to arrive as something they can match on.
    #[test]
    fn token_or_quoted_string_separates_its_three_defects() {
        assert_eq!(token_or_quoted_string("abc").unwrap(), "abc");
        // The content is what the field means by the value, so the DQUOTEs come
        // off and a `quoted-pair` is substituted.
        assert_eq!(token_or_quoted_string("\"a\\\"b\"").unwrap(), "a\"b");
        // `""` is two DQUOTEs and derives from the production; its content is
        // empty, which is not the same fact as the value being empty.
        assert_eq!(token_or_quoted_string("\"\"").unwrap(), "");

        assert_eq!(token_or_quoted_string(""), Err(WordDefect::Empty));
        assert_eq!(
            token_or_quoted_string("a b"),
            Err(WordDefect::NotToken(' '))
        );
        // A leading DQUOTE commits the value to the `quoted-string` half: RFC
        // 9110 § 5.6.2 makes DQUOTE a delimiter, so this is not a `token`
        // holding a bad character, it is a malformed `quoted-string`.
        assert!(matches!(
            token_or_quoted_string("\"abc"),
            Err(WordDefect::NotQuotedString(_))
        ));
        assert!(matches!(
            token_or_quoted_string("\"abc\"x"),
            Err(WordDefect::NotQuotedString(_))
        ));
    }

    /// The reader is handed one `char` per octet by every caller that reads a
    /// field through [`combined_field_value_as_written`], and the two halves
    /// answer an `obs-text` octet differently on purpose: `qdtext` admits it and
    /// `tchar` does not.
    #[test]
    fn obs_text_lands_on_the_side_of_the_alternation_the_grammar_puts_it() {
        let quoted: String = [b'"', 0xE9, b'"'].iter().map(|&b| b as char).collect();
        assert_eq!(
            token_or_quoted_string(&quoted).unwrap().chars().count(),
            1,
            "an obs-text octet is qdtext and comes back as one octet"
        );
        let bare: String = [0xE9u8].iter().map(|&b| b as char).collect();
        assert_eq!(
            token_or_quoted_string(&bare),
            Err(WordDefect::NotToken('\u{E9}'))
        );
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

    /// `%` is not an attr-char. It reaches this function only as the opening of a
    /// `pct-encoded`, and the branch handling that runs first -- so a `%` that is
    /// not two hex digits is an incomplete escape, never a literal.
    #[test]
    fn percent_is_only_ever_an_escape() {
        assert!(validate_ext_value("UTF-8''%41").is_ok());
        assert!(validate_ext_value("UTF-8''a%20b").is_ok());
        assert!(validate_ext_value("UTF-8''%").is_err());
        assert!(validate_ext_value("UTF-8''a%b").is_err());
        assert!(validate_ext_value("UTF-8''100%").is_err());
    }

    /// The three characters `token` has and `attr-char` does not.
    #[test]
    fn attr_char_excludes_star_quote_and_percent() {
        assert!(validate_ext_value("UTF-8''a*b").is_err());
        assert!(validate_ext_value("UTF-8''a{b").is_err());
        assert!(validate_ext_value("UTF-8''ok-name.ext~1").is_ok());
    }

    #[test]
    fn test_validate_ext_value() {
        // Valid ext-values
        assert!(validate_ext_value("UTF-8''%e2%82%ac%20rates").is_ok());
        assert!(validate_ext_value("iso-8859-1'en'%A3%20rates").is_ok());
        assert!(validate_ext_value("UTF-8''simple-ascii").is_ok());
        assert!(validate_ext_value("UTF-8''").is_ok()); // empty value-chars allowed

        // Invalid: missing quotes
        assert!(validate_ext_value("UTF-8%e2%82%ac").is_err());
        // Invalid: incomplete percent
        assert!(validate_ext_value("UTF-8''%e2%2").is_err());
        // Invalid: bad hex
        assert!(validate_ext_value("UTF-8''%ZZ").is_err());
        // Invalid: invalid attr-char
        assert!(validate_ext_value("UTF-8''hello@world").is_err());
    }

    /// The four axes the three hand copies of this predicate disagreed on: the
    /// join across field lines, an `obs-text` octet, the walk, and the fold.
    #[test]
    fn vary_nomination_reads_the_whole_field() {
        use hyper::header::{HeaderName, HeaderValue};
        let read = |lines: &[&[u8]]| {
            let mut h = HeaderMap::new();
            for l in lines {
                h.append(
                    HeaderName::from_static("vary"),
                    HeaderValue::from_bytes(l).expect("a test Vary value"),
                );
            }
            vary_nomination(&h)
        };

        // A `*` written on a second field line is a `*`: §5.3 makes the lines
        // one value and `#` is what licenses the join. Two of the three rules
        // read the lines one at a time and said it was not.
        assert!(read(&[b"accept", b"*"]).is_wildcard());
        assert!(read(&[b"*"]).is_wildcard());
        assert!(read(&[b"accept, *, accept-encoding"]).is_wildcard());

        // One `obs-text` octet used to stand the whole rule down, in two rules,
        // by two different routes. It is a member that nominates nothing and it
        // does not reach the other members.
        let n = read(&[b"accept-encoding, caf\xe9", b"*"]);
        assert!(n.is_wildcard(), "the second line still answers");
        let n = read(&[b"accept-encoding, caf\xe9"]);
        assert!(
            n.nominates("Accept-Encoding"),
            "the first member still reads"
        );
        // The octet stays inside the member it was written in — it is no `OWS`
        // character and nothing trims it — so that member nominates no field a
        // request could carry under the name without it.
        assert!(!n.nominates("caf"), "the octet is part of the member");
        assert!(
            n.nominates("caf\u{e9}"),
            "and the member is read as written"
        );

        // `field-name = token` admits no `quoted-string`, so a DQUOTE is a
        // character no member may hold and the comma after it is still a
        // separator. The quote-aware walk one caller used said otherwise.
        assert!(read(&[b"\"x, prefer"]).nominates("prefer"));

        // Field names are case-insensitive, both directions.
        assert!(read(&[b"Accept-Encoding"]).nominates("accept-encoding"));
        assert!(read(&[b"accept-encoding"]).nominates("ACCEPT-ENCODING"));

        // Absent and zero-element nominate the same nothing, and an empty member
        // is not an element.
        assert!(!read(&[]).nominates("accept"));
        assert!(!read(&[b""]).nominates("accept"));
        assert!(!read(&[b"a,,b"]).nominates(""));
        assert!(read(&[b"a,,b"]).nominates("b"));
    }

    /// Wire order, the four labels, and the two ways a section is absent — a
    /// framing that carried no trailers, and an upstream that never answered.
    #[test]
    fn transaction_field_sections_walks_all_four_in_wire_order() {
        let labels = |tx: &crate::http_transaction::HttpTransaction| -> Vec<&'static str> {
            transaction_field_sections(tx)
                .map(|(label, _)| label)
                .collect()
        };

        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "text/plain")],
        );
        assert_eq!(
            labels(&tx),
            vec!["request header section", "response header section"]
        );

        tx.request.trailers = Some(crate::test_helpers::make_headers_from_pairs(&[(
            "x-a", "1",
        )]));
        tx.response.as_mut().expect("a response").trailers = Some(
            crate::test_helpers::make_headers_from_pairs(&[("x-b", "2")]),
        );
        assert_eq!(
            labels(&tx),
            vec![
                "request header section",
                "request trailer section",
                "response header section",
                "response trailer section",
            ]
        );

        // A transaction the upstream never answered has a request half and
        // nothing else.
        let unanswered = crate::test_helpers::make_test_transaction();
        assert_eq!(labels(&unanswered), vec!["request header section"]);

        // The response-only walk answers the same question one direction wide,
        // and names the sections without a direction because its callers'
        // scope already fixes one.
        let resp = tx.response.as_ref().expect("a response");
        assert_eq!(
            response_field_sections(resp)
                .map(|(label, _)| label)
                .collect::<Vec<_>>(),
            vec!["header section", "trailer section"]
        );
    }

    #[test]
    fn test_is_prohibited_trailer_field() {
        // Fields the cited categories name, case-insensitively.
        assert!(is_prohibited_trailer_field("Connection"));
        assert!(is_prohibited_trailer_field("connection"));
        assert!(is_prohibited_trailer_field("keep-alive"));
        // The categories reach well past the connection-specific ones: framing,
        // routing, conditionals, response control data.
        assert!(is_prohibited_trailer_field("Content-Length"));
        assert!(is_prohibited_trailer_field("host"));
        assert!(is_prohibited_trailer_field("If-Match"));
        assert!(is_prohibited_trailer_field("date"));
        // A Trailer field inside a trailer section announces nothing.
        assert!(is_prohibited_trailer_field("trailer"));
        // An extension field is not prohibited by what it is.
        assert!(!is_prohibited_trailer_field("x-foo"));
        assert!(!is_prohibited_trailer_field("x-checksum"));
    }

    #[test]
    fn test_is_nominated_by_connection() {
        // Nomination is per-message: this field is disqualified only because this
        // message's Connection header names it.
        assert!(is_nominated_by_connection(
            "X-Special",
            Some("keep-alive, X-Special")
        ));
        // Not nominated if not listed.
        assert!(!is_nominated_by_connection("X-Special", Some("keep-alive")));
        // Both sides match case-insensitively.
        assert!(is_nominated_by_connection(
            "x-special",
            Some("KEEP-ALIVE, x-special")
        ));
        // No Connection header nominates nothing.
        assert!(!is_nominated_by_connection("x-special", None));
        // A substring is not a token.
        assert!(!is_nominated_by_connection(
            "upgrade",
            Some("super-upgrade")
        ));
    }
}
