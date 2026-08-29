// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Getting a field value out of a `HeaderMap`, and saying which section it came
//! from.
//!
//! **This module is named for a data structure, and that is now the truth about
//! it rather than an excuse.** It held seventy items and eleven unrelated
//! questions, because "arrives in a `HeaderMap`" is true of every field in HTTP
//! and so shelved nothing. What is left is the part that really is about the
//! map: reading a value, reading the field *lines* separately, recovering the
//! octets as written when `to_str` would refuse them, and naming the section —
//! header or trailer — a field was found in.
//!
//! Everything that asked a *grammar* question about the value has gone to the
//! module named for that grammar: `list`, `quoted_string`, `word`, `parameter`,
//! `media_type`, `qvalue`, `validator`, `vary`, `content_length`,
//! `field_placement`, `shown`. The import list below is the evidence that the
//! split landed — one line, and nothing from any of them.
//!
//! The test of whether something belongs here: does it need the `HeaderMap`, or
//! only a `&str` that happened to come out of one?

use hyper::HeaderMap;

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

#[cfg(test)]
mod concat_header_tests {
    use super::get_all_header_values;
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
}
