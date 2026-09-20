// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! How a protocol element is shown to whoever reads the finding.
//!
//! A finding names the thing that stopped a parse, and that thing is by
//! definition one the grammar did not admit — very often a control octet. Every
//! function here exists because writing such a value straight into a message
//! *corrupts the message instead of describing it*: a raw CR ends the line a
//! reader is looking at, a lone backslash reads as an escape nobody wrote, and
//! a NUL simply vanishes.
//!
//! The three answers are one question at three widths — a whole value, one
//! `char`, one octet — and they already knew it, which is why they lived
//! interleaved among the field-reading functions in `headers.rs` while
//! referring to each other across three hundred lines. [`shown_in_finding`]
//! renders a value and deliberately leaves printable `obs-text` alone;
//! [`describe_octet`] names a single offending byte, which is the case that
//! needs the hex; [`describe_char`] is the cast between them, made in one place
//! because two rules had written it out privately and disagreed about the
//! out-of-range arm.
//!
//! What is not here: [`singleton_field_preamble`] and the other message
//! *templates*. Those compose a sentence for a particular defect and take an
//! already-rendered value — they are a finding's wording, not its escaping, and
//! the boundary is exactly the `shown_value` parameter one of them takes.
//!
//! [`singleton_field_preamble`]: crate::helpers::headers::singleton_field_preamble

/// Render an octet for a finding message without letting a raw control or
/// `obs-text` byte into the output.
///
/// A finding names the octet that stopped a parse, and that octet is by
/// definition one the grammar did not admit -- often a control character, which
/// written through would corrupt the message rather than describe it.
///
/// The split at `0x20..0x7f` is SP plus VCHAR: everything below is a control
/// octet and everything above is `obs-text`. Printing the second group as hex
/// rather than as characters is the sentence below applied to a message — an
/// octet a recipient is told to treat as opaque is not one to render as though
/// it meant something, and %xE9 is a byte here, not `é`.
// cite(RFC 9110 § 5.5): "A recipient SHOULD treat other allowed octets in field content (i.e., obs-text) as opaque data."
pub fn describe_octet(b: u8) -> String {
    if (0x20..0x7f).contains(&b) {
        format!("'{}'", b as char)
    } else {
        format!("0x{:02X}", b)
    }
}

/// Render a value -- a field value, one member of it, or any other protocol
/// element read back from a capture -- into a finding.
///
/// A value read through [`combined_field_value_as_written`](crate::helpers::headers::combined_field_value_as_written) carries one `char`
/// per octet, so it can hold octets that would corrupt the message rather than
/// appear in it -- an HTAB inside a `quoted-string` is legal and reachable, and
/// a lone backslash reads as an escape to whoever sees the finding next.
///
/// It is not the answer for `obs-text`: `escape_debug` leaves a printable code
/// point alone, so %xE9 arrives in the message as `é`. That is legible and
/// deliberate -- naming the offending octet is [`describe_octet`]'s job, and the
/// findings that turn on one call it.
///
/// **The DQUOTE is shown as written, and it is the one character `escape_debug`
/// gets wrong here.** That function renders a Rust string *literal*, where the
/// quote has to be escaped because it would otherwise end the literal. A finding
/// is not a literal: it is a sentence quoting octets an operator is about to go
/// and grep the response for, and there is no delimiter for a quote to end. So
/// escaping it bought nothing and cost the only thing the rendering is for --
/// `ETag`, `alt-authority`, every auth-param and every media-type parameter are
/// written in a production that *requires* DQUOTE, and a `Report-To` or a `P3P`
/// is a value made of almost nothing else, so the string the message showed was
/// reliably not the string in the response.
///
/// **The backslash still is escaped, and that is why the split below is on the
/// quote alone.** A lone `\` in a message reads as an escape nobody wrote, which
/// is the case the paragraph above this one argues and is untouched; so is every
/// control octet. What that leaves is a rendering that round-trips: a backslash
/// the sender wrote comes back doubled, so a quote behind an even run of them is
/// a quote the wire carried behind a real backslash, and a quote behind an odd
/// run cannot occur at all.
///
/// **Split on the DQUOTE and hand the runs between to [`str::escape_debug`]
/// unchanged**, rather than escaping each `char` and skipping the quote. The two
/// are not the same function, and the difference is every decision that is not
/// being changed here: the apostrophe, which both the old rendering and this one
/// escape, is escaped by [`str::escape_debug`] and would keep being escaped
/// either way -- but a `char` walk would also have to re-derive the leading
/// grapheme-extended rule, and a rendering that changes one character should
/// change one character. This form cannot change a second by accident.
pub fn shown_in_finding(s: &str) -> String {
    s.split('"')
        .map(|run| run.escape_debug().to_string())
        .collect::<Vec<_>>()
        .join("\"")
}

/// [`describe_octet`] for a `char` that came from an octet.
///
/// Every input to [`parse_token_bws_word`](crate::helpers::word::parse_token_bws_word)
/// is one `char` per octet, so the cast
/// is exact; the fallback exists only so a caller that decoded some other way
/// still gets a finding rather than a panic.
///
/// Public because every rule reading a value through
/// [`combined_field_value_as_written`](crate::helpers::headers::combined_field_value_as_written) and naming the octet a parse stopped on
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

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// The quote is the character this rendering exists to get right, and each
    /// row is a production that requires one: an `entity-tag`, an
    /// `alt-authority`, an `auth-param`, and a field whose value is JSON.
    #[rstest]
    #[case("\"abc\"", "\"abc\"")]
    #[case("W/\"abc\"", "W/\"abc\"")]
    #[case("h3=\":443\"; ma=2592000", "h3=\":443\"; ma=2592000")]
    #[case("Basic realm=\"simple\"", "Basic realm=\"simple\"")]
    #[case("{\"group\":\"default\"}", "{\"group\":\"default\"}")]
    fn a_quote_the_sender_wrote_is_shown_as_the_sender_wrote_it(
        #[case] wire: &str,
        #[case] shown: &str,
    ) {
        assert_eq!(shown_in_finding(wire), shown);
    }

    /// The other half, and the reason the split is on the quote alone: the
    /// cases the doc argues are unchanged. A lone backslash still reads as an
    /// escape nobody wrote unless it is doubled, and a control octet still
    /// cannot corrupt the message it is named in.
    #[rstest]
    #[case("a\\b", "a\\\\b")]
    #[case("a\tb", "a\\tb")]
    #[case("a\nb", "a\\nb")]
    #[case("a\u{1}b", "a\\u{1}b")]
    fn a_backslash_or_a_control_octet_is_still_escaped(#[case] wire: &str, #[case] shown: &str) {
        assert_eq!(shown_in_finding(wire), shown);
    }

    /// **Exactly one character changed, and this is the assertion that says
    /// so.** The apostrophe is escaped, as it was before -- which is the
    /// opposite of what the first draft of this function's doc claimed, and the
    /// claim was wrong about `str::escape_debug` rather than about the change.
    /// Pinned because a value carrying an apostrophe is common and the
    /// messages that wrap a value delimit it with one, so a later reader has
    /// every reason to think this rendering ought to leave it alone; it does
    /// not, it never did, and that is a separate question from the DQUOTE.
    #[test]
    fn an_apostrophe_is_escaped_now_exactly_as_it_was_before() {
        assert_eq!(shown_in_finding("it's"), "it\\'s");
    }

    /// **The rendering round-trips, which is what makes the harness ratchet
    /// legible.** A backslash the sender wrote comes back doubled, so a quote
    /// standing behind an even run of backslashes carried one on the wire and a
    /// quote behind an odd run cannot be produced at all. A reader counting
    /// that parity can tell an escaped quote from a quoted backslash, and
    /// before this change it could not: both were `\"`.
    #[rstest]
    #[case("\"a\\\"b\"", "\"a\\\\\"b\"")]
    #[case("a\\\"", "a\\\\\"")]
    fn a_wire_backslash_before_a_quote_comes_back_doubled(#[case] wire: &str, #[case] shown: &str) {
        assert_eq!(shown_in_finding(wire), shown);
        // No quote in the output stands behind an odd run of backslashes.
        let mut run = 0usize;
        for c in shown.chars() {
            match c {
                '\\' => run += 1,
                '"' => {
                    assert_eq!(
                        run % 2,
                        0,
                        "a quote behind an odd run of backslashes: {shown}"
                    );
                    run = 0;
                }
                _ => run = 0,
            }
        }
    }
}
