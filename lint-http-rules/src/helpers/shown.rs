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
pub fn shown_in_finding(s: &str) -> String {
    s.escape_debug().to_string()
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
