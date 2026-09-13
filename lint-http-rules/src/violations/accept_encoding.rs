// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Accept-Encoding` defects — the two ways a request asks for no compression.
//!
//! The field's *reading* is spoken for elsewhere: `#( codings [ weight ] )`
//! makes the list construct [`list`](crate::violations::list)'s, a coding name
//! [`token`](crate::violations::token)'s, and everything after the `;`
//! [`qvalue`](crate::violations::qvalue)'s. What is here is neither a grammar
//! defect nor a broken requirement — **both entries are about a conforming
//! request that will not be compressed**, and § 12.5.3 spells out what each of
//! them means, which is exactly why neither can be `warn`.
//!
//! **The two are `_missing` and `_empty`, and this field is where the pair is
//! easiest to get backwards.** Absence is the *most permissive* state the field
//! has — every content coding is acceptable, and a server that compresses
//! anyway conforms. A value written and left blank is the *most restrictive* —
//! the user agent wants no content coding at all. One rule reported the
//! permissive case under a rationale describing the restrictive one and passed
//! the restrictive one in silence, which is what a single scalar over two
//! opposite meanings buys you.
//!
//! Not here: a request that refuses everything by *weight* rather than by
//! omission. `*;q=0`, or `identity;q=0` with no more specific entry, excludes
//! even the unencoded representation — a stronger refusal than an empty field
//! and a judgement computed from qvalues rather than a reading of whether a
//! preference was expressed.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// The field: its grammar, and the two sentences giving absence and emptiness
/// their opposite meanings.
pub const RFC_9110_12_5_3: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("12.5.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.3",
    note: "`Accept-Encoding`: `#( codings [ weight ] )`, and the two sentences that make absence the most permissive value the field has and an empty value the most restrictive",
};

defects! {
    /// A request that carries no `Accept-Encoding` at all.
    ///
    /// Nothing is broken: the quoted sentence makes every content coding
    /// acceptable, so a server is free to compress and the exchange conforms
    /// either way. What is worth saying is what deployments do — most servers
    /// will not compress without an explicit signal — so the bytes travel
    /// uncompressed because nobody asked, not because anybody refused.
    ///
    /// `info`, and it is one of the few entries in this catalogue reporting a
    /// message that breaks no sentence at all. The finding is about a transfer,
    /// not about a defect.
    ///
    // cite(RFC 9110 § 12.5.3): "If no Accept-Encoding header field is in the request, any content coding is considered acceptable by the user agent."
    ACCEPT_ENCODING_MISSING = {
        id: "accept_encoding_missing",
        title: "Request expresses no content-coding preference",
        message: "",
        default_severity: Severity::Info,
        spec: &[RFC_9110_12_5_3],
    }

    /// An `Accept-Encoding` written and left with nothing in it — including a
    /// value that is only commas, since an empty member is not an element.
    ///
    /// The opposite statement to [`ACCEPT_ENCODING_MISSING`] and the same
    /// outcome on the wire, which is the whole reason both are here and both
    /// are `info`: one request said nothing and one refused everything, and a
    /// report that called them one thing would tell an operator that a client
    /// forgot the field when it had in fact set it deliberately.
    ///
    /// A sender that meant "no preference" writes no field. A sender that means
    /// this one is asking for the representation as stored, which is a thing a
    /// client may legitimately want.
    ///
    // cite(RFC 9110 § 12.5.3): "An Accept-Encoding header field with a field value that is empty implies that the user agent does not want any content coding in response."
    ACCEPT_ENCODING_EMPTY = {
        id: "accept_encoding_empty",
        title: "Request declines every content coding",
        message: "",
        default_severity: Severity::Info,
        spec: &[RFC_9110_12_5_3],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pair `docs/development.md` calls never interchangeable, on the field
    /// where they mean opposite things. Neither outranks the other, because
    /// neither is wrong — what separates them is which one the sender chose.
    #[test]
    fn the_absent_field_and_the_blank_one_are_two_ids_at_one_level() {
        assert_ne!(ACCEPT_ENCODING_MISSING.id, ACCEPT_ENCODING_EMPTY.id);
        assert_eq!(
            ACCEPT_ENCODING_MISSING.default_severity,
            ACCEPT_ENCODING_EMPTY.default_severity
        );
        assert_eq!(ACCEPT_ENCODING_MISSING.default_severity, Severity::Info);
    }
}
