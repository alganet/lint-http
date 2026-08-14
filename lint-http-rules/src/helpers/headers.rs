// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

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
        for t in parse_list_header(s) {
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
/// A value that does not parse leaves no number and `message_content_length`
/// reports it; a declared length that disagrees with the captured octets is
/// `message_request_body_length_accuracy`'s finding.
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
/// The `|` inside the second quote is not a typo and must not be tidied. That
/// sentence sits in one of the RFC's indented note blocks, whose gutter markers
/// survive extraction, so the `|` is genuinely part of what the document says as
/// far as verification is concerned.
///
// cite(RFC 9110 § 5.3): "A recipient MAY combine multiple field lines within a field section that have the same field name into one field line, without changing the semantics of the message, by appending each subsequent field line value to the initial field line value in order, separated by a comma (",") and optional whitespace (OWS, defined in Section 5.6.3).  For consistency, use comma SP."
// cite(RFC 9110 § 5.3): "Since it cannot be combined into a single field value, | recipients ought to handle "Set-Cookie" as a special case while | processing fields."
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
/// `message_header_field_names_token` passes one -- a finding says which
/// section it came from and nothing else turns on the distinction.
///
/// cite(RFC 9110 § 6.5): "Fields (Section 5) that are located within a "trailer section" are referred to as "trailer fields""
pub fn response_field_sections(
    resp: &crate::http_transaction::ResponseInfo,
) -> impl Iterator<Item = (&'static str, &HeaderMap)> {
    [
        Some(("header section", &resp.headers)),
        resp.trailers.as_ref().map(|t| ("trailer section", t)),
    ]
    .into_iter()
    .flatten()
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

/// Render an octet for a finding message without letting a raw control or
/// `obs-text` byte into the output.
///
/// A finding names the octet that stopped a parse, and that octet is by
/// definition one the grammar did not admit -- often a control character, which
/// written through would corrupt the message rather than describe it.
pub fn describe_octet(b: u8) -> String {
    if (0x20..0x7f).contains(&b) {
        format!("'{}'", b as char)
    } else {
        format!("0x{:02X}", b)
    }
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
/// See [`stateful_cache_validation_chain`] for an example consumer.
pub fn extract_validators_from_response(headers: &HeaderMap) -> (Option<String>, Option<String>) {
    let etag = headers
        .get("etag")
        .and_then(|hv| hv.to_str().ok())
        .map(str::trim)
        .map(ToString::to_string);

    let last_modified = headers
        .get("last-modified")
        .and_then(|hv| hv.to_str().ok())
        .map(str::trim)
        .map(ToString::to_string);

    (etag, last_modified)
}

/// Extract **strong** validators from a response's headers.
///
/// This is the original implementation of [`extract_validators_from_response`];
/// it filters out weak ETags (`W/` prefix) because they are not suitable for
/// certain cache validation scenarios.  Rules that do not accept weak ETags
/// (for example, `stateful_range_request_and_caching`) should call this
/// helper instead of `extract_validators_from_response`.
pub fn extract_strong_validators_from_response(
    headers: &HeaderMap,
) -> (Option<String>, Option<String>) {
    // ETag: pick first header, ensure UTF-8 and strong
    let etag = headers
        .get("etag")
        .and_then(|hv| hv.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.starts_with("W/"))
        .map(ToString::to_string);

    let last_modified = headers
        .get("last-modified")
        .and_then(|hv| hv.to_str().ok())
        .map(str::trim)
        .map(ToString::to_string);

    (etag, last_modified)
}

/// Parse a comma-separated list of header values (e.g., Connection, Transfer-Encoding).
///
/// This iterator splits by comma, trims whitespace, and skips empty parts.
///
/// "Skips empty parts" is the interesting one, and it is a requirement rather
/// than a convenience: `a,,b` is a two-element list, not a malformed one, and the
/// seventy-odd callers that reach this are all recipients. A sender must not
/// produce empty elements (§ 5.6.1.1), which is a different rule for a different
/// party -- so a *rule* wanting to flag `a,,b` as bad output cannot ask this
/// function, because by the time it answers, the evidence is gone.
///
/// § 5.6.1.2 bounds the requirement -- ignore "a reasonable number", but not so
/// many that it becomes a denial-of-service vector -- and this imposes no cap.
/// That is deliberate rather than overlooked: the bound protects a recipient from
/// the cost of the ignoring, and `split` + `filter` is linear with no
/// amplification. There is nothing here to exhaust.
///
// cite(RFC 9110 § 5.6.1.2): "Empty elements do not contribute to the count of elements present."
// cite(RFC 9110 § 5.6.1.2): "#element => [ element ] *( OWS "," OWS [ element ] )"
pub fn parse_list_header(val: &str) -> impl Iterator<Item = &str> {
    val.split(',').map(|s| s.trim()).filter(|s| !s.is_empty())
}

/// The same walk as [`parse_list_header`], trimming the whitespace the production
/// actually prints.
///
/// Four decisions make up a `#rule` walk -- where to split, what to trim, whether
/// to drop an empty element, and whether to fold case -- and this differs from its
/// neighbour in exactly one of them. `OWS` is `*( SP / HTAB )`; `str::trim` removes
/// every character `char::is_whitespace` admits. On a value read back through
/// `to_str` the two are the same function, because that reader lets no other
/// whitespace octet into the string at all. On a value read one `char` per octet
/// ([`combined_field_value_as_written`]) they are not: %xA0 and %x85 are `obs-text`
/// octets a sender wrote *inside* a member, and trimming them hands the member's
/// own grammar a value the sender did not write.
///
/// [`parse_list_header`] keeps the Unicode trim and its seventy-odd callers. They
/// read `to_str` values, where the answer is the same one; converting them would
/// change what every one of those sites reports, which is each of their audits'
/// work rather than this helper's.
// cite(RFC 9110 § 5.6.1.2): "#element => [ element ] *( OWS "," OWS [ element ] )"
// cite(RFC 9110 § 5.6.1.2): "Empty elements do not contribute to the count of elements present."
// cite(RFC 9110 § 5.6.3, label: OWS grammar): "OWS            = *( SP / HTAB )"
pub fn list_members(val: &str) -> impl Iterator<Item = &str> {
    val.split(',').map(trim_ows).filter(|s| !s.is_empty())
}

/// Parse a semicolon-separated list of directive values.
///
/// This iterator splits by semicolon, trims whitespace, and skips empty parts.
/// IMPORTANT: This is a *naive* splitter that simply calls `split(';')` and does
/// NOT respect quoted-strings. Do NOT use this helper for header parameter
/// parsing where quoted-string values may themselves contain semicolons
/// (for example, `Content-Disposition` parameters). For quote-aware splitting,
/// use `split_semicolons_respecting_quotes` which understands DQUOTE quoting and
/// backslash escapes.
///
/// Use `parse_semicolon_list` only for simple cases where you are certain
/// values cannot include quoted semicolons.
pub fn parse_semicolon_list(val: &str) -> impl Iterator<Item = &str> {
    val.split(';').map(|s| s.trim()).filter(|s| !s.is_empty())
}

/// Extract the numeric value of a `max-age` directive from one of the
/// `Cache-Control` header fields, if present and syntactically valid.
///
/// The `Cache-Control` syntax permits multiple directives separated by commas
/// (the canonical form) or, in some user agents, semicolons.  This helper
/// therefore splits on both characters and returns the first `max-age` value
/// it encounters that parses to a non-negative integer.  If multiple header
/// fields are present the values are considered in header order.
///
/// The return value represents the freshness lifetime advertised by the
/// response.  Callers needing more sophisticated freshness handling (Expires
/// headers, heuristics, etc.) will need to layer their own logic on top of
/// this primitive.
///
/// This logic was previously duplicated across several stateful caching rules;
/// consolidating it here makes future maintenance easier.
pub fn get_cache_control_max_age(headers: &HeaderMap) -> Option<i64> {
    for hv in headers.get_all("cache-control").iter() {
        if let Ok(s) = hv.to_str() {
            // if the header value contains no-store or no-cache, we treat it as
            // forbidding caching (RFC 9111 §5.2) and ignore any max-age that may
            // appear alongside.  Lowercase search is sufficient for our purposes.
            let l = s.to_ascii_lowercase();
            if l.contains("no-store") || l.contains("no-cache") {
                continue;
            }

            for part in s.split(|c| [',', ';'].contains(&c)) {
                let part = part.trim();
                // look for name=value pairs so we can compare the name without
                // depending on the case used by the sender.  RFC9111 §5.2 says
                // directive names are case‑insensitive.
                if let Some(idx) = part.find('=') {
                    let (name, value) = part.split_at(idx);
                    if name.trim().eq_ignore_ascii_case("max-age") {
                        let eq = &value[1..]; // drop the '='
                        if let Ok(n) = eq.trim().parse::<i64>() {
                            if n >= 0 {
                                return Some(n);
                            }
                        }
                    }
                }
            }
        }
    }
    None
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

/// Extract the numeric value of an `s-maxage` directive from one of the
/// `Cache-Control` header fields, if present and syntactically valid.
///
/// The semantics mirror `get_cache_control_max_age` but apply to shared caches
/// only.  Private caches must ignore `s-maxage` when computing freshness
/// lifetime, so this helper is mainly useful for rules verifying that clients
/// or caches are not misapplying the directive.  As with the max-age helper,
/// directives that explicitly forbid caching (`no-store`/`no-cache`) cause the
/// value to be ignored.
pub fn get_cache_control_s_maxage(headers: &HeaderMap) -> Option<i64> {
    // First, scan all Cache-Control header values for directives that forbid
    // caching. If any header contains `no-store` or `no-cache`, the combined
    // semantics require caches to treat the response as non-cacheable and to
    // ignore freshness directives such as `s-maxage`.
    for hv in headers.get_all("cache-control").iter() {
        if let Ok(s) = hv.to_str() {
            let l = s.to_ascii_lowercase();
            if l.contains("no-store") || l.contains("no-cache") {
                return None;
            }
        }
    }
    // No `no-store`/`no-cache` was found across any Cache-Control header value;
    // now look for a syntactically valid `s-maxage` directive.
    for hv in headers.get_all("cache-control").iter() {
        if let Ok(s) = hv.to_str() {
            for part in s.split(|c| [',', ';'].contains(&c)) {
                let part = part.trim();
                if let Some(idx) = part.find('=') {
                    let (name, value) = part.split_at(idx);
                    if name.trim().eq_ignore_ascii_case("s-maxage") {
                        let eq = &value[1..];
                        if let Ok(n) = eq.trim().parse::<i64>() {
                            if n >= 0 {
                                return Some(n);
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

/// Compute the freshness lifetime (in whole seconds) advertised by a response.
/// This helper first consults `Cache-Control: max-age` (ignoring any values when
/// `no-store` or `no-cache` are also present) and falls back to the `Expires`
/// header if no max-age is available.  A missing or invalid value is treated as
/// zero, representing an immediately stale entry.  Callers may use this to
/// drive caching-related stateful rules without duplicating parsing logic.
pub fn compute_freshness_lifetime(
    headers: &HeaderMap,
    resp_timestamp: chrono::DateTime<chrono::Utc>,
) -> i64 {
    // if any Cache-Control value forbids caching, the response should be
    // treated as immediately stale regardless of max-age or Expires.  This
    // mirrors the more careful scan performed by `get_cache_control_s_maxage`
    // and ensures that split header fields cannot defeat the check.
    for hv in headers.get_all("cache-control").iter() {
        if let Ok(s) = hv.to_str() {
            let l = s.to_ascii_lowercase();
            if l.contains("no-store") || l.contains("no-cache") {
                return 0;
            }
        }
    }

    // The order is the sentence's order, and it is "use the first match". s-maxage is
    // the arm above these two and is deliberately absent: it applies only to a shared
    // cache, and this helper is not told whether it is one.
    // cite(RFC 9111 § 4.2.1): "If the max-age response directive (Section 5.2.2.1) is present, use its value, or * If the Expires response header field (Section 5.3) is present, use its value minus the value of the Date response header field (using the time the message was received if it is not present, as per Section 6.6.1 of [HTTP]), or"
    if let Some(max_age) = get_cache_control_max_age(headers) {
        return max_age;
    }
    if let Some(hv) = headers.get("expires") {
        if let Ok(s) = hv.to_str() {
            if let Ok(dt) = crate::http_date::parse_http_date_to_datetime(s.trim()) {
                // Subtract Date, not the time we happened to receive this. The origin's
                // clock is the one the sentence asks for, and `resp_timestamp` is only
                // the fallback it names for when Date is absent.
                // cite(RFC 9111 § 4.2.1): "Note that this calculation is intended to reduce clock skew by using the clock information provided by the origin server whenever possible."
                let basis = headers
                    .get("date")
                    .and_then(|d| d.to_str().ok())
                    .and_then(|d| crate::http_date::parse_http_date_to_datetime(d.trim()).ok())
                    .unwrap_or(resp_timestamp);
                let diff = dt.signed_duration_since(basis).num_seconds();
                if diff > 0 {
                    return diff;
                }
            }
        }
    }
    0
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
/// trailers; `message_trailer_fields_validity` says so where an operator reads it.
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
    // Connection-specific (RFC 9110 §7.6.1)
    "connection",
    "keep-alive",
    "upgrade",
    // The cleanest member of this list: § 6.5.1 asks whether the field's own
    // definition permits the usage, and this field's definition answers by name.
    // The same sentence forbids it in a response, which is
    // `message_early_data_header_safe_method`'s finding — a response *trailer* is
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

/// Split a comma-separated header value into top-level members while respecting quoted-strings
/// and backslash escapes. Returns a Vec of slices referencing the original string.
///
/// This is useful for header grammars like `Cache-Control` and `Pragma` where members
/// may contain quoted-strings with commas that must not be treated as separators.
pub fn split_commas_respecting_quotes(s: &str) -> Vec<&str> {
    let bytes = s.as_bytes();
    let mut res = Vec::new();
    let mut start = 0usize;
    let mut i = 0usize;
    let mut in_quote = false;
    let mut prev_backslash = false;

    while i < bytes.len() {
        let b = bytes[i];
        if prev_backslash {
            prev_backslash = false;
        // A backslash escapes only inside a quoted-string: `quoted-pair` is
        // defined as part of `quoted-string` and nowhere else, so outside one
        // a backslash is an ordinary octet. Both productions are transcribed
        // at `validate_quoted_string` below, which owns them; honouring an
        // escape out here let a stray backslash suppress the DQUOTE after it,
        // flipping quote parity for the rest of the value and swallowing every
        // later member into one segment.
        } else if b == b'\\' && in_quote {
            prev_backslash = true;
        } else if b == b'"' {
            in_quote = !in_quote;
        } else if b == b',' && !in_quote {
            res.push(&s[start..i]);
            start = i + 1;
        }
        i += 1;
    }
    // push remaining
    if start <= s.len() {
        res.push(&s[start..]);
    }
    res
}

/// Split a semicolon-separated header value into top-level members while respecting quoted-strings
/// and backslash escapes. Returns a Vec of slices referencing the original string.
///
/// Useful for header grammars like `Strict-Transport-Security` where directives are separated
/// with `;` and may include quoted-strings (rare but defensive).
pub fn split_semicolons_respecting_quotes(s: &str) -> Vec<&str> {
    let bytes = s.as_bytes();
    let mut res = Vec::new();
    let mut start = 0usize;
    let mut i = 0usize;
    let mut in_quote = false;
    let mut prev_backslash = false;

    while i < bytes.len() {
        let b = bytes[i];
        if prev_backslash {
            prev_backslash = false;
        // Same as the comma splitter: `quoted-pair` lives inside
        // `quoted-string`, so a backslash outside one escapes nothing.
        } else if b == b'\\' && in_quote {
            prev_backslash = true;
        } else if b == b'"' {
            in_quote = !in_quote;
        } else if b == b';' && !in_quote {
            res.push(&s[start..i]);
            start = i + 1;
        }
        i += 1;
    }
    // push remaining
    if start <= s.len() {
        res.push(&s[start..]);
    }
    // Each segment comes back without the `OWS` the grammars print around their
    // semicolons, so no caller repeats the trim.
    //
    // `str::trim` was wrong here for the same reason it is wrong on a member: a
    // value read through [`combined_field_value_as_written`] carries one `char`
    // per octet, so %xA0 in it arrives as U+00A0 — `obs-text`, which no
    // parameter production admits and which `str::trim` removed, handing the
    // caller an *empty* segment and hiding the octet behind whichever finding
    // the caller has for emptiness. [`trim_ows`] is the same three characters of
    // intent bounded to what `OWS` is.
    res.into_iter().map(trim_ows).collect()
}

/// Whether every DQUOTE in `s` closes, under exactly the escape rules the two
/// splitters above use.
///
/// A quote-respecting splitter cannot return a trustworthy member list when the
/// quoting never closes: everything after the stray DQUOTE collapses into one
/// member, and no separator past it is a separator. A rule whose finding is
/// that some member is *absent* has to ask this first, or it states as missing
/// what is merely unreadable. Rules that judge a member they did find need no
/// such gate — that member was legible.
///
/// It lives beside the splitters because it has to agree with them about what a
/// quote is; a gate with its own idea of escaping would pass values the splitter
/// then mangles, or vice versa.
pub fn quoting_is_balanced(s: &str) -> bool {
    let mut in_quote = false;
    let mut prev_backslash = false;
    for b in s.bytes() {
        if prev_backslash {
            prev_backslash = false;
        // `quoted-pair` lives inside `quoted-string`, so a backslash outside
        // one escapes nothing.
        // cite(RFC 9110 § 5.6.4): "quoted-pair    = "\" ( HTAB / SP / VCHAR / obs-text )"
        } else if b == b'\\' && in_quote {
            prev_backslash = true;
        } else if b == b'"' {
            in_quote = !in_quote;
        }
    }
    !in_quote
}

/// The index of the DQUOTE that closes the `quoted-string` starting at `s[0]`,
/// or `None` when nothing closes it.
///
/// Grammars that put a `quoted-string` in the middle of a construct --
/// `expectation`'s value with `parameters` behind it, `Warning`'s `warn-text`
/// with a `warn-date` behind it -- have to know where the construct ends before
/// they can look at what follows. [`validate_quoted_string`] judges a slice
/// someone else has already cut, which is the question after this one.
///
/// The escape rule is the splitters' and [`quoting_is_balanced`]'s: a backslash
/// inside the string suppresses the next octet. Both call sites had transcribed
/// this loop by hand, identically, which is two copies of a decision that has to
/// agree with three other functions in this file.
///
/// Returns `None` when `s` does not open with a DQUOTE either -- there is no
/// `quoted-string` to find the end of.
///
/// cite(RFC 9110 § 5.6.4): "quoted-string  = DQUOTE *( qdtext / quoted-pair ) DQUOTE"
/// cite(RFC 9110 § 5.6.4): "quoted-pair    = "\" ( HTAB / SP / VCHAR / obs-text )"
pub fn quoted_string_end(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    if bytes.first() != Some(&b'"') {
        return None;
    }
    let mut i = 1usize;
    let mut prev_backslash = false;
    while i < bytes.len() {
        let b = bytes[i];
        if prev_backslash {
            prev_backslash = false;
        } else if b == b'\\' {
            prev_backslash = true;
        } else if b == b'"' {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Validate a quoted-string per HTTP rules: must start and end with DQUOTE, support backslash escapes,
/// must not contain unescaped control characters (except HTAB). Returns Ok(()) on success, Err(msg)
/// on failure.
///
/// The two octet sets below are worth reading side by side, because the whole
/// function is the difference between them. `qdtext` is what may appear bare;
/// `quoted-pair` is what may appear after a backslash. HTAB and obs-text are in
/// both -- HTTP is not Structured Fields, and the same-looking helper in
/// `structured_fields.rs` is right to reject exactly what this one accepts.
///
/// The two DQUOTEs of the production are stripped by [`quoted_string_interior`],
/// which both this function and [`unescape_quoted_string`] ask, so what counts
/// as "properly quoted" is decided once.
///
/// The walk is over `chars` and not over `as_bytes`, and the difference is the
/// whole of `obs-text`. A caller reading a value through
/// [`combined_field_value_as_written`] holds one `char` per octet, so %xE9 in it
/// is `U+00E9` -- which `as_bytes` re-encodes as the *two* octets %xC3 %xA9, a
/// pair the sender did not write. `to_str` callers cannot tell the two walks
/// apart, because that reader admits no octet at or above %x80 in the first
/// place.
///
/// The `*( qdtext / quoted-pair )` between a `quoted-string`'s two DQUOTEs,
/// with nothing inside it examined.
///
/// A lone DQUOTE strips its prefix and then has no suffix left to strip, so the
/// one-character string is `None` rather than an empty interior — which is the
/// distinction the production draws, `DQUOTE DQUOTE` being the shortest value it
/// generates. [`validate_quoted_string`] and [`unescape_quoted_string`] both ask
/// this rather than each slicing the ends off, because "is this quoted at all"
/// has to be one answer for the pair of them.
// cite(RFC 9110 § 5.6.4): "quoted-string  = DQUOTE *( qdtext / quoted-pair ) DQUOTE"
pub fn quoted_string_interior(val: &str) -> Option<&str> {
    val.strip_prefix('"')?.strip_suffix('"')
}

// cite(RFC 9110 § 5.6.4): "quoted-string  = DQUOTE *( qdtext / quoted-pair ) DQUOTE"
// cite(RFC 9110 § 5.6.4): "qdtext         = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text"
pub fn validate_quoted_string(val: &str) -> Result<(), String> {
    let Some(inner) = quoted_string_interior(val) else {
        return Err(format!("Quoted-string not properly quoted: '{}'", val));
    };

    // Walk the interior checking for unescaped control chars and ensuring proper escaping
    let mut prev_backslash = false;
    for c in inner.chars() {
        if prev_backslash {
            // A backslash does not make anything quotable. The escaped octet has its
            // own set, and it is not the same as qdtext's: SP and VCHAR and HTAB and
            // obs-text may follow a backslash, the remaining controls may not.
            //
            // cite(RFC 9110 § 5.6.4): "quoted-pair    = "\" ( HTAB / SP / VCHAR / obs-text )"
            if !(c == '\t' || ('\u{20}'..='\u{7e}').contains(&c) || c >= '\u{80}') {
                return Err(format!("Invalid quoted-pair in quoted-string: '{}'", val));
            }
            prev_backslash = false;
        } else if c == '\\' {
            prev_backslash = true;
        } else if c == '"' {
            // unescaped quote before the terminating one -> invalid
            return Err(format!("Unescaped quote in quoted-string: '{}'", val));
        } else if (c < '\u{20}' && c != '\t') || c == '\u{7f}' {
            return Err(format!("Control character in quoted-string: '{}'", val));
        }
    }

    if prev_backslash {
        return Err(format!(
            "Quoted-string ends with escape character: '{}'",
            val
        ));
    }

    Ok(())
}

/// Check whether a quoted-string's unescaped inner content, after trimming,
/// is empty. Returns Ok(true) if the inner content is empty after trimming,
/// Ok(false) if it contains any non-whitespace character, or Err(msg) if the
/// input is not a well-formed quoted-string. This is useful for treating
/// quoted-empty values (e.g., `""` or `"   "`) as empty for presence checks.
pub fn quoted_string_inner_trimmed_is_empty(val: &str) -> Result<bool, String> {
    // Reuse `unescape_quoted_string` to perform unescaping and validation
    match unescape_quoted_string(val) {
        Ok(s) => Ok(s.trim().is_empty()),
        Err(e) => Err(e),
    }
}

/// Unescape a well-formed HTTP `quoted-string` value and return its inner contents.
/// - Input must include surrounding DQUOTE characters (e.g., `"a\"b"`).
/// - Returns `Ok(inner_string)` on success or `Err(msg)` if the input is not a valid quoted-string.
///
/// This helper centralizes quoted-string unescaping to avoid duplication across rules.
///
/// Unlike its neighbours, the sentence below is not a grammar -- it is an
/// instruction about what a recipient must *do*, and every caller here is a
/// recipient. It also says why the substitution is unconditional: the octet
/// following the backslash, not some interpretation of it, which is why there is
/// no escape table in this function and should never be one. `\n` in a
/// quoted-string is the letter n.
///
/// The walk is [`validate_quoted_string`]'s, and over `chars` for the same
/// reason: `as_bytes` re-encoded a value already holding one `char` per octet,
/// so an `obs-text` octet inside a `quoted-string` -- which `qdtext` admits --
/// came back out as the two octets of its UTF-8 form and every finding naming
/// it named a pair nobody wrote.
///
// cite(RFC 9110 § 5.6.4): "Recipients that process the value of a quoted-string MUST handle a quoted-pair as if it were replaced by the octet following the backslash."
pub fn unescape_quoted_string(val: &str) -> Result<String, String> {
    validate_quoted_string(val)?;
    let inner = quoted_string_interior(val).expect("validation accepted the quoting");
    let mut out = String::with_capacity(inner.len());
    let mut prev_backslash = false;
    for c in inner.chars() {
        // One statement, because the sentence cited above is one: a backslash
        // that is not itself escaped is consumed, and everything else -- escaped
        // or not -- is the octet it is. A trailing backslash cannot reach the end
        // of this loop, because the validation above rejects that value.
        if !prev_backslash && c == '\\' {
            prev_backslash = true;
        } else {
            out.push(c);
            prev_backslash = false;
        }
    }

    Ok(out)
}

/// Render a value -- a field value, one member of it, or any other protocol
/// element read back from a capture -- into a finding.
///
/// A value read through [`combined_field_value_as_written`] carries one `char`
/// per octet, so it can hold octets that would corrupt the message rather than
/// appear in it -- an HTAB inside a `quoted-string` is legal and reachable, and
/// a lone backslash reads as an escape to whoever sees the finding next.
///
/// It is not the answer for `obs-text`: `escape_debug` leaves a printable code
/// point alone, so %xE9 arrives in the message as `é`. That is legible and
/// deliberate -- naming the offending octet is [`describe_octet`]'s job, and the
/// findings that turn on one call it.
pub fn shown_in_finding(s: &str) -> String {
    s.escape_debug().to_string()
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
/// render differently on purpose — `escape_debug`, [`shown_in_finding`], and a
/// `Referer`-specific one that withholds a userinfo. What a finding may print is
/// the field's question, not this function's.
///
/// **Not for a field counted across two sections.** The recombining clause is
/// § 5.2's, and § 5.2 is *within a section*; § 5.3's MUST NOT is about the whole
/// message and says so (*"whether in the headers or trailers"*). A rule counting
/// both sections at once — `message_content_disposition_token_valid` does — is
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

/// [`describe_octet`] for a `char` that came from an octet.
///
/// Every input to [`parse_token_bws_word`] is one `char` per octet, so the cast
/// is exact; the fallback exists only so a caller that decoded some other way
/// still gets a finding rather than a panic.
///
/// Public because every rule reading a value through
/// [`combined_field_value_as_written`] and naming the octet a parse stopped on
/// needs exactly this cast, and two of them had written it out privately -- with
/// the same doc comment and a `debug_assert` plus a truncating `as u8`, which
/// answers the out-of-range case differently from this one. The cast is one
/// decision, so it is made in one place.
pub fn describe_char(c: char) -> String {
    match u8::try_from(c as u32) {
        Ok(b) => describe_octet(b),
        Err(_) => format!("'{}'", c),
    }
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

/// Validate an entity-tag (ETag) value. Accepts '*' or an entity-tag
/// which may be weak (prefix 'W/'). Returns Ok(()) on success or Err(msg) describing the problem.
pub fn validate_entity_tag(val: &str) -> Result<(), String> {
    // cite(RFC 9110 § 8.8.3, label: entity-tag grammar): "entity-tag = [ weak ] opaque-tag weak = %s"W/" opaque-tag = DQUOTE *etagc DQUOTE"
    let s = val.trim();
    if s == "*" {
        return Ok(());
    }

    let rest = if let Some(stripped) = s.strip_prefix("W/") {
        stripped
    } else {
        s
    };
    // rest must be a quoted-string
    validate_quoted_string(rest)
}

/// Represents a parsed Media Type (e.g. "text/html; charset=utf-8").
#[derive(Debug, PartialEq, Eq)]
pub struct ParsedMediaType<'a> {
    pub type_: &'a str,
    pub subtype: &'a str,
    pub params: Option<&'a str>,
}

/// Parse a Media Type string into type, subtype, and optional params.
///
/// This does NOT fully validate the tokens (e.g. wildcards or invalid chars),
/// but it separates the structure. [`media_type_parts_defect`] below is the
/// other half.
/// Returns an error message if the structure is invalid (missing slash, empty parts).
///
/// Every trim here is [`trim_ows`] and none of them is `str::trim`, which trims
/// Unicode whitespace: a caller reading a field through
/// [`combined_field_value_as_written`] hands this one `char` per octet, so %xA0
/// arrives as U+00A0 and %x85 as U+0085 — both `obs-text`, which no part of
/// `media-type` admits and both of which `str::trim` silently removed. That
/// erased the one unambiguous defect in `application/example%xA0`, which came
/// back as a clean `subtype` of `example`. The same reasoning is written out at
/// [`split_semicolons_respecting_quotes`], which had already been fixed.
///
/// The two halves of `type "/" subtype` are **not** trimmed at all, because the
/// production prints no `OWS` between them: `application / example` derives from
/// nothing, and trimming each side handed the character scan two clean tokens.
/// What is trimmed is the whole value (§ 5.5) and the run before the first
/// semicolon, where `parameters` does print `OWS`.
///
/// cite(RFC 9110 § 5.6.6): "parameters      = *( OWS ";" OWS [ parameter ] )"
/// cite(RFC 9110 § 5.5): "A field value does not include leading or trailing whitespace.  When a specific version of HTTP allows such whitespace to appear in a message, a field parsing implementation MUST exclude such whitespace prior to evaluating the field value."
pub fn parse_media_type(val: &str) -> Result<ParsedMediaType<'_>, String> {
    let trimmed = trim_ows(val);
    if trimmed.is_empty() {
        return Err("Empty media-type".into());
    }

    let mut parts = trimmed.splitn(2, ';');
    let media = trim_ows(
        parts
            .next()
            .expect("splitn always yields at least one element"),
    );
    let params = parts.next().map(trim_ows).filter(|p| !p.is_empty());

    // cite(RFC 9110 § 8.3.1, label: media-type grammar): "media-type = type "/" subtype parameters"
    if !media.contains('/') {
        return Err(format!(
            "Invalid media-type '{}': missing '/' between type and subtype",
            val
        ));
    }

    let mut ts = media.splitn(2, '/');
    let type_ = ts.next().unwrap_or("");
    let subtype = ts.next().unwrap_or("");

    if type_.is_empty() || subtype.is_empty() {
        return Err(format!(
            "Invalid media-type '{}': empty type or subtype",
            val
        ));
    }

    Ok(ParsedMediaType {
        type_,
        subtype,
        params,
    })
}

/// The half of `media-type` that `parse_media_type` above deliberately leaves:
/// having separated the parts, what each of them must *be*.
///
/// `None` where the parts derive from the production; otherwise the reason they
/// do not, phrased as a clause a caller prints after naming its own field. That
/// shape is what lets the two rules measuring a `media-type` — one reading
/// `Content-Type`, one reading each member of `Accept-Patch`'s `1#media-type` —
/// share one transcription of § 8.3.1 and § 5.6.6 while each says which field
/// the defect was found in. Written when the second caller arrived; before that
/// these four checks lived inside the first rule, where a second copy was the
/// only way to ask the same question of another field.
///
/// **The asterisk is not judged here.** `*` is a `tchar`, so `*/plain` and
/// `*/*` both derive from `media-type`; what an asterisk *means* is each
/// field's own question — `Content-Type` states one representation's media
/// type, while `Accept-Patch` is a list of them with no `media-range` anywhere
/// in its grammar — and the two rules answer it separately, at different
/// strengths, from different sentences.
///
/// **Every value this interpolates is escaped for display**, and it has to be:
/// the octets a `tchar` test rejects include the ones that print as nothing, so
/// a raw HTAB or CR reaching a finding breaks the line it is printed on rather
/// than appearing in it. `escape_debug` is not the `obs-text` answer — a
/// printable code point survives it, so %xC9 still shows as `É` — and naming an
/// octet is [`describe_octet`]'s job; the `#token` walks in this tree that do
/// name it are measuring a value whose every octet is one `char`, which a
/// `media-type` reaching this function is not guaranteed to be.
///
/// **One inherited leniency, and it is the fourth copy of it.** `parameter` is
/// `parameter-name "=" parameter-value` with no `OWS` anywhere in it, and
/// § 5.6.6 says so again in prose — yet the whitespace beside the `=` is trimmed
/// here, so `text/example; charset = utf-8` passes. That is the reading the
/// `Content-Type`, multipart-boundary and charset rules already publish as a
/// known leniency; it moved in with the code rather than being decided here, and
/// changing it changes those rules' verdicts. Recorded at the shared site so the
/// next reader does not take it for the grammar.
///
/// cite(RFC 9110 § 8.3.1): "type       = token subtype    = token"
/// cite(RFC 9110 § 8.3.1): "The type and subtype tokens are case-insensitive."
pub fn media_type_parts_defect(parsed: &ParsedMediaType<'_>) -> Option<String> {
    // Case is not checked because there is nothing to check: both halves are
    // case-insensitive, so no spelling of them is wrong.
    if let Some(c) = crate::helpers::token::find_invalid_token_char(parsed.type_) {
        return Some(format!("invalid character '{}' in type", c.escape_debug()));
    }

    // Same production, other half; the quote above covers both lines of it.
    if let Some(c) = crate::helpers::token::find_invalid_token_char(parsed.subtype) {
        return Some(format!(
            "invalid character '{}' in subtype",
            c.escape_debug()
        ));
    }

    // A media type with no parameters is a media type: the term is `parameters`,
    // whose whole expansion is starred, so a value that stops after the subtype
    // has satisfied it and there is nothing below to run.
    // cite(RFC 9110 § 8.3.1): "The type/subtype MAY be followed by semicolon-delimited parameters (Section 5.6.6) in the form of name/value pairs."
    let params = parsed.params?;

    // Quote-aware, because a `;` inside a `quoted-string` parameter value does
    // not start the next parameter. Each segment comes back already trimmed of
    // the `OWS` the production prints beside its semicolons -- re-trimming it
    // with `str::trim` here undid that helper's own fix and put %xA0 and %x85
    // back out of reach.
    for p in split_semicolons_respecting_quotes(params) {
        // `[ parameter ]` is bracketed, so a semicolon with nothing after it is
        // a conforming zero-parameter repetition rather than a defect --
        // `text/plain; charset=utf-8;` is well formed.
        // cite(RFC 9110 § 5.6.6): "parameters      = *( OWS ";" OWS [ parameter ] )"
        if p.is_empty() {
            continue;
        }

        let Some(eq) = p.find('=') else {
            // The "=" is not optional inside `parameter`, so a bare token among
            // the parameters is not a valueless flag.
            // cite(RFC 9110 § 5.6.6): "parameter       = parameter-name "=" parameter-value"
            return Some(format!("parameter '{}' missing '='", p.escape_debug()));
        };

        // The two trims are the leniency named above, bounded to `OWS` so that
        // an `obs-text` octet beside the `=` is not mistaken for whitespace and
        // removed.
        let (name, value) = p.split_at(eq);
        let name = trim_ows(name);
        let value = trim_ows(&value[1..]); // skip '='

        if name.is_empty() {
            return Some("empty parameter name".to_string());
        }
        // cite(RFC 9110 § 5.6.6): "parameter-name  = token"
        if let Some(c) = crate::helpers::token::find_invalid_token_char(name) {
            return Some(format!(
                "invalid character '{}' in parameter name '{}'",
                c.escape_debug(),
                name.escape_debug()
            ));
        }

        if value.starts_with('"') {
            // The `quoted-string` production belongs to the shared helper, which
            // walks the interior; asking only that the value start and end with
            // DQUOTE accepts `foo="a\"`, whose closing quote is escaped, and
            // `foo="a"b"`.
            if let Err(e) = validate_quoted_string(value) {
                // The helper's reason quotes the value it was handed, so the
                // escape goes around the whole clause rather than around the
                // name alone -- a control octet inside the quoted-string is
                // exactly what that reason is about, and it arrived raw.
                return Some(format!(
                    "parameter '{}' has invalid quoted-string: {}",
                    name.escape_debug(),
                    e.escape_debug()
                ));
            }
        } else {
            // The alternation is exclusive: a value that does not open with
            // DQUOTE has to satisfy `token`, which is why an unquoted `utf 8` is
            // a defect rather than a curiosity.
            // cite(RFC 9110 § 5.6.6): "parameter-value = ( token / quoted-string )"
            if let Some(c) = crate::helpers::token::find_invalid_token_char(value) {
                return Some(format!(
                    "invalid character '{}' in parameter value '{}'",
                    c.escape_debug(),
                    value.escape_debug()
                ));
            }
        }
    }

    None
}

/// Extract the value of a `boundary` parameter from a `multipart/*` Content-Type header.
/// - Returns `Some(boundary)` unquoted/unescaped when present and well-structured, `None` otherwise.
/// - This helper is intentionally conservative: it returns `None` when the Content-Type cannot be
///   parsed or the boundary parameter is missing or not well-formed (e.g., invalid quoted-string).
pub fn extract_multipart_boundary(val: &str) -> Option<String> {
    let parsed = parse_media_type(val).ok()?;
    if !parsed.type_.eq_ignore_ascii_case("multipart") {
        return None;
    }
    let params = parsed.params?;
    // Quote-aware, because a `;` inside a quoted parameter value does not start
    // a new parameter. A raw `split(';')` cut such a value apart and read the
    // pieces as parameters, so `foo="a; boundary=abc; b=1"` — which has no
    // boundary parameter at all — yielded `abc`, and the caller then hunted a
    // body for `--abc` delimiters that were never declared.
    // cite(RFC 9110 § 5.6.6): "parameters      = *( OWS ";" OWS [ parameter ] )"
    for raw in split_semicolons_respecting_quotes(params) {
        let p = raw.trim();
        if p.is_empty() {
            continue;
        }
        if let Some(eq) = p.find('=') {
            let (name, value) = p.split_at(eq);
            let name = name.trim();
            let value = value[1..].trim(); // skip '='
                                           // cite(RFC 9110 § 5.6.6): "Parameter names are case-insensitive."
            if name.eq_ignore_ascii_case("boundary") {
                if value.is_empty() {
                    return None;
                }
                if value.starts_with('"') {
                    // quoted-string: unescape using existing helper; if it fails, treat as missing
                    match unescape_quoted_string(value) {
                        Ok(u) => {
                            // Empty boundary (after unquoting) is invalid -> treat as missing
                            if u.trim().is_empty() {
                                return None;
                            }
                            return Some(u);
                        }
                        Err(_) => return None,
                    }
                } else {
                    return Some(value.to_string());
                }
            }
        }
    }
    None
}

/// Return the structured-syntax suffix part of a subtype if present (the part after the last `+`).
/// For example, `ld+json` -> `json`. This is a small helper for rules that need to inspect
/// subtype suffixes. Returns `None` for subtypes with no `+`.
pub fn media_type_subtype_suffix(subtype: &str) -> Option<&str> {
    if let Some(pos) = subtype.rfind('+') {
        Some(&subtype[pos + 1..])
    } else {
        None
    }
}

/// Validate a serialized-origin as defined by RFC 6454: scheme "://" host [":" port]
/// The grammar has no path component, so nothing may follow the authority — not
/// even a bare trailing slash, which a byte-for-byte origin comparison rejects.
/// This is a conservative validator: it ensures scheme chars, presence of host,
/// and numeric port (if present). It does not attempt full IDNA or host label validation.
// Both callers (Timing-Allow-Origin, Access-Control-Allow-Origin) take their value
// grammar from Fetch, whose production supplants RFC 6454's. The two agree on the
// shape checked here — an authority and nothing after it — so both are quoted.
// cite(Fetch): "serialized-origin = serialized-scheme "://" serialized-host [ ":" serialized-port ]"
// cite(Fetch): "This supplants the definition in The Web Origin Concept"
// cite(RFC 6454 § 7.1): "serialized-origin = scheme "://" host [ ":" port ]"
// Where they differ, Fetch is the stricter of the two, which is the direction this
// validator is deliberately permissive in: it accepts host shapes (IDNA, label
// syntax) that Fetch's serialization would reject.
// cite(Fetch): "The origin serialization defined here is more constrained than [RFC3986]’s grammar in two substantial ways."
pub fn is_valid_serialized_origin(val: &str) -> bool {
    let s = val.trim();
    if s.is_empty() {
        return false;
    }

    // Split scheme://rest
    let parts: Vec<&str> = s.splitn(2, "://").collect();
    if parts.len() != 2 {
        return false;
    }
    let scheme = parts[0];
    let rest = parts[1];

    // Scheme: ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ) per RFC3986
    let mut chars = scheme.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() => (),
        _ => return false,
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.') {
        return false;
    }

    // rest should be host[:port] and must not contain '/', whitespace or userinfo '@'
    if rest.is_empty()
        || rest.contains('/')
        || rest.contains('\t')
        || rest.contains(' ')
        || rest.contains('@')
    {
        return false;
    }

    if let Some(colon_pos) = rest.rfind(':') {
        // If colon exists, treat as host:port candidate. But IPv6 address may contain ':' and be bracketed.
        if rest.starts_with('[') {
            // Use the ipv6 helper to parse bracketed IPv6 and optional port
            if let Some((_, port_opt)) = crate::helpers::ipv6::parse_bracketed_ipv6(rest) {
                if let Some(port_str) = port_opt {
                    return crate::helpers::ipv6::parse_port_str(port_str).is_some();
                }
                return true;
            } else {
                return false; // malformed or unmatched '['
            }
        }

        let host = &rest[..colon_pos];
        let port = &rest[colon_pos + 1..];
        if host.is_empty() || port.is_empty() {
            return false;
        }
        // Parse and validate port using helper
        return crate::helpers::ipv6::parse_port_str(port).is_some();
    }

    // No port: ensure host is non-empty
    !rest.is_empty()
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

    #[test]
    fn test_parse_list_header() {
        let input = " foo, bar , , baz ";
        let tokens: Vec<_> = parse_list_header(input).collect();
        assert_eq!(tokens, vec!["foo", "bar", "baz"]);
    }

    #[test]
    fn test_parse_media_type() {
        let res = parse_media_type("text/html; charset=utf-8").unwrap();
        assert_eq!(res.type_, "text");
        assert_eq!(res.subtype, "html");
        assert_eq!(res.params, Some("charset=utf-8"));

        let res = parse_media_type(" application/json ").unwrap();
        assert_eq!(res.type_, "application");
        assert_eq!(res.subtype, "json");
        assert_eq!(res.params, None);

        assert!(parse_media_type("text").is_err());
        assert!(parse_media_type("/html").is_err());
        assert!(parse_media_type("text/").is_err());
    }

    #[test]
    fn test_media_type_subtype_suffix() {
        // No suffix
        assert_eq!(media_type_subtype_suffix("html"), None);
        // Common suffix
        assert_eq!(media_type_subtype_suffix("ld+json"), Some("json"));
        // Vendor with suffix
        assert_eq!(media_type_subtype_suffix("vnd.foo+xml"), Some("xml"));
        // Trailing plus (empty suffix)
        assert_eq!(media_type_subtype_suffix("foo+"), Some(""));
        // Multiple plus (take last)
        assert_eq!(media_type_subtype_suffix("a+b+json"), Some("json"));
    }

    #[test]
    fn extract_multipart_boundary_basic() {
        assert_eq!(
            extract_multipart_boundary("multipart/mixed; boundary=gc0p4Jq0M2Yt08j34c0p"),
            Some("gc0p4Jq0M2Yt08j34c0p".to_string())
        );
        assert_eq!(
            extract_multipart_boundary("multipart/mixed; boundary=\"a b\""),
            Some("a b".to_string())
        );
        assert_eq!(extract_multipart_boundary("text/plain; boundary=abc"), None);
        assert_eq!(extract_multipart_boundary("multipart/mixed"), None);
    }

    #[test]
    fn extract_multipart_boundary_edge_cases() {
        // quoted empty boundary -> treated as missing
        assert_eq!(
            extract_multipart_boundary("multipart/mixed; boundary=\"\""),
            None
        );
        // unquoted empty boundary -> treated as missing
        assert_eq!(
            extract_multipart_boundary("multipart/mixed; boundary="),
            None
        );
        // malformed quoted-string -> treated as missing
        assert_eq!(
            extract_multipart_boundary("multipart/mixed; boundary=\"unterminated"),
            None
        );
        // multiple params and surrounding whitespace
        assert_eq!(
            extract_multipart_boundary("multipart/mixed; foo=bar; boundary=abc ; baz=1"),
            Some("abc".to_string())
        );
        // A `;` inside a quoted value is not a parameter separator, so there is
        // no boundary parameter here. Returning one made the caller look for
        // delimiters the message never declared.
        assert_eq!(
            extract_multipart_boundary("multipart/mixed; foo=\"a; boundary=abc; b=1\""),
            None
        );
        // A quoted value carrying a `;` does not hide the real boundary after it.
        assert_eq!(
            extract_multipart_boundary("multipart/mixed; foo=\"a;b\"; boundary=abc"),
            Some("abc".to_string())
        );
    }

    #[test]
    fn test_valid_qvalue() {
        assert!(valid_qvalue("1"));
        assert!(valid_qvalue("1.0"));
        assert!(valid_qvalue("1.00"));
        assert!(valid_qvalue("1.000"));
        assert!(valid_qvalue("0"));
        assert!(valid_qvalue("0.5"));
        assert!(valid_qvalue("0.123"));
        assert!(valid_qvalue("0.000"));
        // `0*3DIGIT` and `0*3("0")` are satisfied by no digits at all, so a
        // point with nothing after it conforms. The enumeration this replaced
        // reported both as malformed.
        assert!(valid_qvalue("0."));
        assert!(valid_qvalue("1."));
        assert!(!valid_qvalue("1.0000"));
        assert!(!valid_qvalue("0.1234"));
        // Only zeroes may follow a leading 1: the weight is capped at 1.
        assert!(!valid_qvalue("1.1"));
        assert!(!valid_qvalue("1.001"));
        assert!(!valid_qvalue("abc"));
        assert!(!valid_qvalue(""));
        assert!(!valid_qvalue("2"));
        assert!(!valid_qvalue("-1"));
        assert!(!valid_qvalue("0.5.5"));
        assert!(!valid_qvalue("00"));
        assert!(!valid_qvalue("0.a"));
    }

    #[test]
    fn test_is_valid_serialized_origin() {
        assert!(is_valid_serialized_origin("https://example.com"));
        assert!(is_valid_serialized_origin("http://example.com:8080"));
        assert!(is_valid_serialized_origin("https://localhost"));
        assert!(is_valid_serialized_origin("https://[::1]:8080"));
        assert!(is_valid_serialized_origin("https://[::1]"));

        // Port range & formatting checks
        assert!(is_valid_serialized_origin("http://example.com:1"));
        assert!(is_valid_serialized_origin("http://example.com:65535"));
        assert!(is_valid_serialized_origin("http://example.com:080")); // leading zero allowed -> 80

        assert!(!is_valid_serialized_origin("http://example.com:0")); // port 0 invalid
        assert!(!is_valid_serialized_origin("http://example.com:65536")); // out of range
        assert!(!is_valid_serialized_origin(
            "http://example.com:999999999999"
        )); // too large

        // The grammar has no path component, and a browser compares the value
        // byte-for-byte against a serialized origin, which never carries one.
        assert!(!is_valid_serialized_origin("https://example.com/"));
        assert!(!is_valid_serialized_origin("https://example.com/path"));
        assert!(!is_valid_serialized_origin("https://example.com:8080/"));
        assert!(!is_valid_serialized_origin("https://[::1]/path"));

        assert!(!is_valid_serialized_origin("example.com"));
        assert!(!is_valid_serialized_origin("https:///foo"));
        assert!(!is_valid_serialized_origin("https://"));
        assert!(!is_valid_serialized_origin("http://host:notaport"));
        assert!(!is_valid_serialized_origin("https://user@example.com"));
        assert!(!is_valid_serialized_origin("https://[::1"));
        assert!(!is_valid_serialized_origin(""));
    }

    use rstest::rstest;

    #[rstest]
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

    /// `qdtext` and `quoted-pair` allow different octets after their respective
    /// positions, and a backslash does not widen the set to "anything".
    #[test]
    fn quoted_pair_octet_is_constrained() {
        // HTAB / SP / VCHAR / obs-text may follow a backslash.
        assert!(validate_quoted_string("\"\\\t\"").is_ok());
        assert!(validate_quoted_string("\"\\ \"").is_ok());
        assert!(validate_quoted_string("\"\\a\"").is_ok());
        assert!(validate_quoted_string("\"\\\u{80}\"").is_ok());
        // The other controls may not, escaped or otherwise.
        assert!(validate_quoted_string("\"\\\u{1}\"").is_err());
        assert!(validate_quoted_string("\"\\\n\"").is_err());
        assert!(validate_quoted_string("\"\\\u{7f}\"").is_err());
    }

    /// HTTP's `qdtext` admits HTAB and obs-text, which is the opposite of the
    /// Structured Fields String rule -- same shape, different document.
    #[test]
    fn qdtext_admits_htab_and_obs_text() {
        assert!(validate_quoted_string("\"a\tb\"").is_ok());
        assert!(validate_quoted_string("\"caf\u{e9}\"").is_ok());
        assert!(validate_quoted_string("\"a\u{1}b\"").is_err());
    }

    #[test]
    fn validate_quoted_string_control_char_reports_violation() {
        let s = "\"bad\x01str\"";
        let res = validate_quoted_string(s);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("Control character"));
    }

    #[test]
    fn validate_quoted_string_unterminated_reports_violation() {
        let s = "\"unfinished";
        let res = validate_quoted_string(s);
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .contains("Quoted-string not properly quoted"));
    }

    #[test]
    fn validate_quoted_string_extra_chars_reports_violation() {
        let s = "\"abc\"x";
        let res = validate_quoted_string(s);
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .contains("Quoted-string not properly quoted"));
    }

    #[test]
    fn validate_quoted_string_with_escaped_quote_is_valid() {
        let s = "\"a\\\"b\""; // "a\"b"
        let res = validate_quoted_string(s);
        assert!(res.is_ok());
    }

    #[test]
    fn validate_quoted_string_unescaped_quote_reports_violation() {
        // inner unescaped quote before the terminating quote
        let s = "\"a\"b\""; // "a"b"
        let res = validate_quoted_string(s);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("Unescaped quote"));
    }

    #[test]
    fn validate_quoted_string_ends_with_escape_reports_violation() {
        let s = "\"abc\\\""; // ends with escaped state before final quote
        let res = validate_quoted_string(s);
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .contains("Quoted-string ends with escape character"));
    }

    #[test]
    fn quoted_string_inner_trimmed_is_empty_true_cases() {
        assert!(quoted_string_inner_trimmed_is_empty("\"\"").unwrap());
        assert!(quoted_string_inner_trimmed_is_empty("\"   \"").unwrap());
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

    #[test]
    fn unescape_quoted_string_basic_cases() {
        assert_eq!(unescape_quoted_string("\"\"").unwrap(), "");
        assert_eq!(unescape_quoted_string("\"a\"").unwrap(), "a");
        assert_eq!(unescape_quoted_string("\"a\\\"b\"").unwrap(), "a\"b");
        assert_eq!(unescape_quoted_string("\"a\\\\b\"").unwrap(), "a\\b");
    }

    /// `qdtext` admits `obs-text`, so an octet at or above %x80 inside a
    /// `quoted-string` is conforming and has to come back out as itself. Both
    /// functions used to walk `as_bytes`, which re-encoded the one `char` per
    /// octet a caller reading through `combined_field_value_as_written` holds:
    /// %xE9 went in and %xC3 %xA9 came out, so a finding naming the octet named
    /// a pair the sender never wrote.
    #[test]
    fn an_obs_text_octet_survives_the_round_trip_as_one_octet() {
        let as_written: String = [b'"', 0xE9, b'x', b'"']
            .iter()
            .map(|&b| b as char)
            .collect();
        assert!(validate_quoted_string(&as_written).is_ok());
        let inner = unescape_quoted_string(&as_written).expect("qdtext admits obs-text");
        assert_eq!(inner.chars().count(), 2);
        assert_eq!(inner.chars().next().map(|c| c as u32), Some(0xE9));

        // The same octet after a backslash: `quoted-pair` admits it too.
        let escaped: String = [b'"', b'\\', 0xE9, b'"']
            .iter()
            .map(|&b| b as char)
            .collect();
        let inner = unescape_quoted_string(&escaped).expect("quoted-pair admits obs-text");
        assert_eq!(inner.chars().map(|c| c as u32).collect::<Vec<_>>(), [0xE9]);
    }

    #[test]
    fn unescape_quoted_string_invalid_cases() {
        assert!(unescape_quoted_string("\"unterminated").is_err());
        assert!(unescape_quoted_string("\"bad\x01\"").is_err()); // control char
        assert!(unescape_quoted_string("\"a\"b\"").is_err()); // unescaped quote
    }

    #[test]
    fn quoted_string_inner_trimmed_is_empty_false_and_invalid_cases() {
        assert!(!quoted_string_inner_trimmed_is_empty("\"a\"").unwrap());
        // escaped quote inside is a non-empty inner
        assert!(!quoted_string_inner_trimmed_is_empty("\"\\\"\"").unwrap());
        // unterminated quoted-string is an error
        assert!(quoted_string_inner_trimmed_is_empty("\"unterminated").is_err());
    }

    #[test]
    fn quoted_string_inner_unescaped_quote_reports_error() {
        let s = "\"a\"b\""; // inner unescaped quote before terminating quote
        let r = quoted_string_inner_trimmed_is_empty(s);
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("Unescaped quote"));
    }

    // Entity-tag helper tests
    #[test]
    fn validate_entity_tag_cases() {
        assert!(validate_entity_tag("*").is_ok());
        assert!(validate_entity_tag("\"abc\"").is_ok());
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

    #[test]
    fn a_backslash_outside_a_quoted_string_escapes_nothing() {
        // `quoted-pair` is part of `quoted-string`, so outside one a backslash
        // is an ordinary octet. Honouring it there let a stray backslash eat
        // the DQUOTE after it, flipping quote parity and swallowing the rest of
        // the value into a single member.
        assert_eq!(
            split_commas_respecting_quotes(r#"text/html\, application/z+bogus"#),
            vec![r#"text/html\"#, " application/z+bogus"]
        );
        assert_eq!(
            split_semicolons_respecting_quotes(r#"text/html; p=a\; charset=utf-8"#),
            vec!["text/html", r#"p=a\"#, "charset=utf-8"]
        );
        // Inside a quoted-string it still escapes, including an escaped DQUOTE.
        assert_eq!(
            split_commas_respecting_quotes(r#"a;p="x\",y", b"#),
            vec![r#"a;p="x\",y""#, " b"]
        );
        assert_eq!(
            split_semicolons_respecting_quotes(r#"a; p="x\";y"; q=1"#),
            vec!["a", r#"p="x\";y""#, "q=1"]
        );
    }

    #[test]
    fn test_split_commas_respecting_quotes() {
        let cases = vec![
            ("a, b, c", vec!["a", "b", "c"]),
            ("token=\"a,b\", other", vec!["token=\"a,b\"", "other"]),
            (r#"token="a\"b",c"#, vec![r#"token="a\"b""#, "c"]),
            (
                "no-cache, foo=bar, token=\"quoted,comma\",baz",
                vec!["no-cache", "foo=bar", "token=\"quoted,comma\"", "baz"],
            ),
            ("", vec![""]),
            ("a,b,", vec!["a", "b", ""]),
            (",,", vec!["", "", ""]),
        ];

        for (input, expected) in cases {
            let got: Vec<String> = split_commas_respecting_quotes(input)
                .iter()
                .map(|s| s.trim().to_string())
                .collect();
            let exp: Vec<String> = expected.iter().map(|s| s.to_string()).collect();
            assert_eq!(got, exp, "input: {:?}", input);
        }
    }

    /// The gate has to agree with the splitters about what a quote is, so the
    /// pairs below are the cases where the two could disagree: a backslash
    /// outside a quoted-string escapes nothing, one inside escapes the next
    /// octet — including a DQUOTE that would otherwise close the string.
    #[test]
    fn test_quoting_is_balanced() {
        for s in [
            "",
            "a; b",
            "token=\"a;b\";x",
            "p=\"\"",
            "p=\"a\\\"b\"",
            // The backslash is outside a quoted-string, so it escapes nothing
            // and leaves no quote open.
            "p=a\\",
            "p=a\\; q=b",
        ] {
            assert!(quoting_is_balanced(s), "{s:?} should be balanced");
        }
        for s in [
            "p=\"x",
            "p=a\"b",
            "p=\"a\"\"",
            // The escaped DQUOTE does not close the string.
            "p=\"a\\\"",
        ] {
            assert!(!quoting_is_balanced(s), "{s:?} should be unbalanced");
        }
    }

    #[test]
    fn test_split_semicolons_respecting_quotes() {
        let cases = vec![
            ("a; b; c", vec!["a", "b", "c"]),
            (
                "max-age=63072000; includeSubDomains; preload",
                vec!["max-age=63072000", "includeSubDomains", "preload"],
            ),
            ("token=\"a;b\";x", vec!["token=\"a;b\"", "x"]),
            ("a;;b", vec!["a", "", "b"]),
            ("", vec![""]),
            ("a;", vec!["a", ""]),
        ];

        for (input, expected) in cases {
            let got: Vec<String> = split_semicolons_respecting_quotes(input)
                .iter()
                .map(|s| s.to_string())
                .collect();
            assert_eq!(got, expected);
        }
    }

    #[test]
    fn cache_control_max_age_helper_works() {
        use super::get_cache_control_max_age;

        let mut hm = HeaderMap::new();
        assert!(get_cache_control_max_age(&hm).is_none());

        hm.clear();
        hm.append("cache-control", "max-age=10".parse().unwrap());
        assert_eq!(get_cache_control_max_age(&hm), Some(10));

        // semicolon separators should also parse
        hm.clear();
        hm.append("cache-control", "private; max-age=5".parse().unwrap());
        assert_eq!(get_cache_control_max_age(&hm), Some(5));

        // directive names are case-insensitive
        hm.clear();
        hm.append("cache-control", "Max-Age=20".parse().unwrap());
        assert_eq!(get_cache_control_max_age(&hm), Some(20));
        hm.clear();
        hm.append("cache-control", "MAX-AGE=30".parse().unwrap());
        assert_eq!(get_cache_control_max_age(&hm), Some(30));

        // invalid values produce None, not previous result
        hm.clear();
        hm.append("cache-control", "max-age=xyz".parse().unwrap());
        assert!(get_cache_control_max_age(&hm).is_none());

        // negative values are ignored

        // now exercises the new helper for s-maxage
        use super::get_cache_control_s_maxage;

        // no header
        hm.clear();
        assert!(get_cache_control_s_maxage(&hm).is_none());

        hm.append("cache-control", "s-maxage=15".parse().unwrap());
        assert_eq!(get_cache_control_s_maxage(&hm), Some(15));

        // semicolon separators
        hm.clear();
        hm.append("cache-control", "public; s-maxage=7".parse().unwrap());
        assert_eq!(get_cache_control_s_maxage(&hm), Some(7));

        // case-insensitive name
        hm.clear();
        hm.append("cache-control", "S-MAXAGE=9".parse().unwrap());
        assert_eq!(get_cache_control_s_maxage(&hm), Some(9));

        // invalid value yields None
        hm.clear();
        hm.append("cache-control", "s-maxage=bad".parse().unwrap());
        assert!(get_cache_control_s_maxage(&hm).is_none());

        // negative is ignored
        hm.clear();
        hm.append("cache-control", "s-maxage=-1".parse().unwrap());
        assert!(get_cache_control_s_maxage(&hm).is_none());

        // no-store or no-cache cause helper to ignore
        hm.clear();
        hm.append("cache-control", "s-maxage=30, no-store".parse().unwrap());
        assert!(get_cache_control_s_maxage(&hm).is_none());
        hm.clear();
        hm.append("cache-control", "no-cache, s-maxage=30".parse().unwrap());
        assert!(get_cache_control_s_maxage(&hm).is_none());
        hm.clear();
        hm.append("cache-control", "max-age=-1".parse().unwrap());
        assert!(get_cache_control_max_age(&hm).is_none());

        // directives forbidding caching return None
        let mut hm2 = HeaderMap::new();
        hm2.append("cache-control", "max-age=30, no-store".parse().unwrap());
        assert!(get_cache_control_max_age(&hm2).is_none());
    }

    #[test]
    fn compute_freshness_lifetime_helper_works() {
        use super::compute_freshness_lifetime;

        let now = chrono::Utc::now();
        let mut hm = HeaderMap::new();

        // no freshness info -> zero
        assert_eq!(compute_freshness_lifetime(&hm, now), 0);

        // max-age takes precedence
        hm.clear();
        hm.append("cache-control", "max-age=30".parse().unwrap());
        assert_eq!(compute_freshness_lifetime(&hm, now), 30);

        // expires fallback
        hm.clear();
        let later = (now + chrono::Duration::seconds(20))
            .format("%a, %d %b %Y %H:%M:%S GMT")
            .to_string();
        hm.append("expires", later.parse().unwrap());
        let val = compute_freshness_lifetime(&hm, now);
        assert!((val - 20).abs() <= 1, "got {} seconds", val);

        // expires in past -> zero
        hm.clear();
        let past = (now - chrono::Duration::seconds(5))
            .format("%a, %d %b %Y %H:%M:%S GMT")
            .to_string();
        hm.append("expires", past.parse().unwrap());
        assert_eq!(compute_freshness_lifetime(&hm, now), 0);

        // invalid date -> zero
        hm.clear();
        hm.append("expires", "not-a-date".parse().unwrap());
        assert_eq!(compute_freshness_lifetime(&hm, now), 0);

        // max-age still wins even if expires present
        hm.clear();
        hm.append("cache-control", "max-age=5".parse().unwrap());
        hm.append("expires", later.parse().unwrap());
        assert_eq!(compute_freshness_lifetime(&hm, now), 5);

        // multiple cache-control headers: no-cache in one should zero out
        hm.clear();
        hm.append("cache-control", "max-age=100".parse().unwrap());
        hm.append("cache-control", "no-cache".parse().unwrap());
        assert_eq!(compute_freshness_lifetime(&hm, now), 0);

        // Expires is measured from Date when Date is present, not from when we
        // happened to receive the message. Here the origin's clock is 60s behind
        // ours: Expires - Date is 20s, Expires - now is -40s. Reading it from `now`
        // would call a fresh response stale.
        hm.clear();
        let origin_now = now - chrono::Duration::seconds(60);
        let fmt =
            |d: chrono::DateTime<chrono::Utc>| d.format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        hm.append("date", fmt(origin_now).parse().unwrap());
        hm.append(
            "expires",
            fmt(origin_now + chrono::Duration::seconds(20))
                .parse()
                .unwrap(),
        );
        let val = compute_freshness_lifetime(&hm, now);
        assert!(
            (val - 20).abs() <= 1,
            "expected ~20s from Date, got {}",
            val
        );

        // With no Date, the time the message was received is the fallback the
        // sentence names.
        hm.clear();
        hm.append(
            "expires",
            fmt(now + chrono::Duration::seconds(20)).parse().unwrap(),
        );
        let val = compute_freshness_lifetime(&hm, now);
        assert!(
            (val - 20).abs() <= 1,
            "expected ~20s from receipt, got {}",
            val
        );
    }

    #[test]
    fn test_parse_semicolon_list_basic_cases() {
        let got: Vec<&str> = parse_semicolon_list("a; b; ; c; ").collect();
        assert_eq!(got, vec!["a", "b", "c"]);

        let got2: Vec<&str> = parse_semicolon_list("   ").collect();
        assert!(got2.is_empty());
    }

    #[test]
    fn test_parse_semicolon_list_unsafe_for_quoted_strings() {
        // Demonstrate that the naive parser does not respect quoted-strings.
        // This shows why callers that parse header parameters with quoted values
        // should prefer `split_semicolons_respecting_quotes`.
        let got: Vec<&str> = parse_semicolon_list("token=\"a;b\";x").collect();
        // naive split will break the quoted-string into multiple parts
        assert_eq!(got, vec!["token=\"a", "b\"", "x"]);
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

    #[test]
    fn validate_quoted_string_cases() {
        // valid
        assert!(validate_quoted_string("\"ok\"").is_ok());
        // not quoted
        assert!(validate_quoted_string("noquotes").is_err());
        // unescaped quote inside
        assert!(validate_quoted_string("\"bad\"inner\"").is_err());
        // control character inside
        assert!(validate_quoted_string("\"a\x01b\"").is_err());
        // ends with escape char
        assert!(validate_quoted_string("\"abc\\\"").is_err());
    }
}
