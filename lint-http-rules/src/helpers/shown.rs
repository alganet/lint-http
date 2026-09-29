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
/// **Both quotes are shown as written, and they are the two characters
/// `escape_debug` gets wrong here.** That function renders a Rust *literal*,
/// where a quote has to be escaped because it would otherwise end the literal —
/// the DQUOTE ends a string literal and the apostrophe ends a `char` one. A
/// finding is neither: it is a sentence quoting octets an operator is about to
/// go and grep the response for, and there is no literal for a quote to end. So
/// escaping them bought nothing and cost the only thing the rendering is for --
/// `ETag`, `alt-authority`, every auth-param and every media-type parameter are
/// written in a production that *requires* DQUOTE, and a `Report-To` or a `P3P`
/// is a value made of almost nothing else, so the string the message showed was
/// reliably not the string in the response.
///
/// **The apostrophe is the same argument and was left for a second reading,
/// which measured it.** A field whose value is JSON is written with DQUOTE by
/// every serializer that emits JSON and with `'` by every hand that writes one
/// out, and the second is common enough on the web to reach three entries on
/// one origin: a `NEL` and a `Report-To` spelled `{'report_to':'default'}` drew
/// `nel_malformed` and `report_to_malformed`, whose whole finding is *that the
/// apostrophes belong to no JSON string* — and the sentence naming them wrote a
/// backslash before each one, so the value an operator was told to go and fix
/// was shown as carrying octets nobody sent, and the defect it was shown as
/// carrying was stray backslashes.
///
/// A message's own punctuation is not an argument against this. The sentences
/// that wrap a value delimit it with apostrophes, so an apostrophe inside one
/// blurs where the value ends — and that was already true of the DQUOTE for
/// every sentence that delimits with DQUOTE, and is true of SP and `,` for all
/// of them. Prose punctuation is not a grammar, and a reader who cannot tell
/// where the value ends is better served than one who is shown a value that is
/// not the one on the wire.
///
/// **The backslash still is escaped, and that is why the split below is on the
/// quotes alone.** A lone `\` in a message reads as an escape nobody wrote,
/// which is the case the paragraphs above argue and is untouched; so is every
/// control octet. What that leaves is a rendering that round-trips: a backslash
/// the sender wrote comes back doubled, so a quote behind an even run of them is
/// a quote the wire carried behind a real backslash, and a quote behind an odd
/// run cannot occur at all.
///
/// **Keep the quote, hand the runs between quotes to [`str::escape_debug`]
/// unchanged**, rather than escaping each `char` and skipping the quotes. The
/// two are not the same function: a `char` walk would have to re-derive the
/// leading grapheme-extended rule that `escape_debug` applies to the front of a
/// string, and the run form applies it to the front of each run, which is what
/// the single-quote split did before this and is unchanged by widening it to
/// two.
pub fn shown_in_finding(s: &str) -> String {
    let shown_as_written = |c: char| c == '"' || c == '\'';
    let mut out = String::with_capacity(s.len());
    let mut run = 0;
    for (i, c) in s.char_indices() {
        if shown_as_written(c) {
            out.push_str(&s[run..i].escape_debug().to_string());
            out.push(c);
            run = i + c.len_utf8();
        }
    }
    out.push_str(&s[run..].escape_debug().to_string());
    out
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

/// Where a field line first leaves US-ASCII: the octet, rendered by
/// [`describe_octet`], and the text the line carried before it.
///
/// For a field whose parse fails at the first octet above %x7F, where the
/// finding is about that octet and not the line: a Structured Field fails at
/// its conversion to ASCII, before anything else in it is read. The line is not
/// shown whole, because the octet would be shown as the character it is not,
/// and nothing after it was read; what comes before it is ASCII by
/// construction and is how an operator finds the place.
///
/// Every caller asks after `HeaderValue::to_str` refused the line, and a line a
/// `HeaderValue` holds is refused for an octet above %x7F and nothing else, so
/// one is always there. A line without one is answered in the words the
/// sentence used before it named the octet, rather than with a panic.
pub fn first_octet_outside_ascii(line: &[u8]) -> String {
    let Some(at) = line.iter().position(|b| !b.is_ascii()) else {
        return "an octet outside US-ASCII".to_string();
    };
    let before: String = line[..at].iter().copied().map(char::from).collect();
    if before.is_empty() {
        format!("{}, its first octet", describe_octet(line[at]))
    } else {
        format!(
            "{} after '{}'",
            describe_octet(line[at]),
            shown_in_finding(&before)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// The octet is named in hex and never printed as the character it would
    /// decode to, and the ASCII before it is what locates it.
    #[rstest]
    #[case(b"u=1\xa0", "0xA0 after 'u=1'")]
    #[case(b"\xc3\xa9", "0xC3, its first octet")]
    #[case(
        b"camera=(self \"https://ex\xe4mple\")",
        "0xE4 after 'camera=(self \"https://ex'"
    )]
    #[case(b"geolocation=()", "an octet outside US-ASCII")]
    fn the_first_octet_outside_ascii_is_named_with_what_precedes_it(
        #[case] line: &[u8],
        #[case] shown: &str,
    ) {
        assert_eq!(first_octet_outside_ascii(line), shown);
    }

    /// A quote is the thing this rendering exists to get right, and each row is
    /// a production that requires one: an `entity-tag`, an `alt-authority`, an
    /// `auth-param`, and a field whose value is JSON — written with DQUOTE by
    /// anything that serializes JSON, and with the apostrophe by the hands that
    /// write one out, which is the shape three entries meet on the counted web.
    #[rstest]
    #[case("\"abc\"", "\"abc\"")]
    #[case("W/\"abc\"", "W/\"abc\"")]
    #[case("h3=\":443\"; ma=2592000", "h3=\":443\"; ma=2592000")]
    #[case("Basic realm=\"simple\"", "Basic realm=\"simple\"")]
    #[case("{\"group\":\"default\"}", "{\"group\":\"default\"}")]
    #[case("{'group':'default'}", "{'group':'default'}")]
    #[case(
        "{'report_to':'default','max_age': 604800,'failure_fraction':0.01}",
        "{'report_to':'default','max_age': 604800,'failure_fraction':0.01}"
    )]
    #[case("it's", "it's")]
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

    /// **Neither quote is escaped, and this is the assertion that says which
    /// characters that covers.** The apostrophe was pinned as escaped for one
    /// reading, on the ground that changing one character at a time is how a
    /// rendering stays reviewable -- and the pin is what made the question
    /// answerable: it named the apostrophe as the remaining case, which then
    /// turned out to be nine findings on the counted web rather than a
    /// hypothetical. The rendering escapes what would corrupt or mislead, which
    /// is the backslash and the control octets, and nothing else.
    #[rstest]
    #[case("it's", "it's")]
    #[case("'", "'")]
    #[case("''", "''")]
    #[case("a\"b'c", "a\"b'c")]
    fn neither_quote_is_escaped(#[case] wire: &str, #[case] shown: &str) {
        assert_eq!(shown_in_finding(wire), shown);
    }

    /// **The parity argument holds for the apostrophe exactly as for the
    /// DQUOTE**, and it is what lets a reader tell a wire backslash before a
    /// quote from a quote the renderer escaped: the first comes back doubled and
    /// the second cannot be produced at all.
    #[rstest]
    #[case("a\\'b", "a\\\\'b")]
    #[case("'\\'", "'\\\\'")]
    fn a_wire_backslash_before_an_apostrophe_comes_back_doubled(
        #[case] wire: &str,
        #[case] shown: &str,
    ) {
        assert_eq!(shown_in_finding(wire), shown);
    }

    /// **The rendering round-trips, so a reader can tell the two apart.** A
    /// backslash the sender wrote comes back doubled, so a quote
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
