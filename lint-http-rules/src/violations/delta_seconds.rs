// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `delta-seconds` defects — the production every field that carries a time in
//! seconds writes its value in.
//!
//! `delta-seconds = 1*DIGIT`, defined once in RFC 9111 § 1.2.2 and read by four
//! fields in this tree: `Age`'s whole value, `Cache-Control`'s `max-age` and
//! `s-maxage` arguments, `Alt-Svc`'s `ma`, and the `timeout` an expired draft
//! gave `Keep-Alive`. A subject rather than a field, for the reason the domain
//! name syntax is one: the sign in `-1` is the same defect wherever it is
//! written, and an operator silencing it means the defect and not the carrier.
//!
//! **There is no entry here for a numeral too large to represent, and that
//! absence is a reading rather than an omission.** § 1.2.2 tells a cache
//! meeting an unrepresentable value to clamp it, so a run of forty digits is a
//! *conforming* `delta-seconds` that a recipient is instructed what to do with.
//! `content_length_numeral_invalid` is the same arithmetic in a field whose
//! document says nothing of the sort, and it *does* get an entry — so the width
//! of the reader is never what decides, the production's own document is.
//
// cite(RFC 9111 § 1.2.2): "If a cache receives a delta-seconds value greater than the greatest integer it can represent, or if any of its subsequent calculations overflows, the cache MUST consider the value to be 2147483648"

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// Where the production is written, and what a recipient does with a value it
/// cannot hold.
pub const RFC_9111_1_2_2: SpecRef = SpecRef {
    spec: "RFC 9111",
    section: Some("1.2.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-1.2.2",
    note: "`delta-seconds = 1*DIGIT` — the production every field carrying a time in seconds \
           writes its value in, and the clamp that makes an over-long run of digits conforming",
};

defects! {
    /// A value with no digit in it at all, where a `delta-seconds` was due.
    /// `1*DIGIT` has a floor of one, so such a value states no time — which is
    /// not the same as stating zero, and a recipient reading it as zero
    /// believes something the sender did not say.
    ///
    // cite(RFC 9111 § 1.2.2, label: delta-seconds): "delta-seconds  = 1*DIGIT"
    DELTA_SECONDS_EMPTY = {
        id: "delta_seconds_empty",
        title: "A time in seconds is stated with no digits",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9111_1_2_2],
    }

    /// An octet the production does not admit: the sign of `-1` or `+5`, the
    /// radix point of `1.5`, a letter, a separator, or an octet outside
    /// US-ASCII entirely.
    ///
    /// The sign is the one worth naming, because every standard-library integer
    /// parser accepts it and the production does not — so a reader that parses
    /// instead of measuring agrees with the sender and disagrees with the
    /// document. The whole alphabet is ten characters of visible US-ASCII,
    /// which is also why a field whose value is a `delta-seconds` has nothing
    /// to say about its own encoding.
    ///
    // cite(RFC 9111 § 1.2.2, label: delta-seconds): "delta-seconds  = 1*DIGIT"
    DELTA_SECONDS_CHARACTER_FORBIDDEN = {
        id: "delta_seconds_character_forbidden",
        title: "A time in seconds holds an octet DIGIT does not admit",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9111_1_2_2],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two halves of `1*DIGIT` are two entries, and they rank together:
    /// nothing about a time in seconds is invisible to the sender, so the
    /// ranking rule of thumb that lifts a control octet above a chosen
    /// character has nothing to separate here.
    #[test]
    fn the_floor_and_the_alphabet_are_two_entries_of_one_rank() {
        assert_ne!(DELTA_SECONDS_EMPTY.id, DELTA_SECONDS_CHARACTER_FORBIDDEN.id);
        for def in [&DELTA_SECONDS_EMPTY, &DELTA_SECONDS_CHARACTER_FORBIDDEN] {
            assert_eq!(def.default_severity, Severity::Warn, "{}", def.id);
            assert_eq!(def.spec, [RFC_9111_1_2_2], "{}", def.id);
        }
    }
}
