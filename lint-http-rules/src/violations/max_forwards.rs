// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Max-Forwards` defects — the two ways `1*DIGIT` is not written.
//!
//! **The subject is small on purpose, and what it leaves out is the point.**
//! § 7.6.2 says three things about the field beyond its grammar — an
//! intermediary must check and update the value, must not forward at zero, and
//! must not invent the field for a request that arrived without one — and every
//! one of them is about a message this catalogue does not hold. A capture
//! records the request as received on one leg; what the next hop was sent, and
//! who wrote the field, are outside it. So the entries here are the grammar and
//! nothing else, and the rule's own prose says why rather than leaving the
//! silence to read as a verdict.
//!
//! **The value is also never parsed into a number.** A decimal integer too
//! large for any integer type is still `1*DIGIT`, and a parse failure is not a
//! grammar failure — so there is no `_invalid` entry here and cannot be one.

use crate::lint::Severity;
use crate::lint::Strength;
use crate::rules::SpecRef;
use crate::violations::defects;

/// The field: its grammar, the methods it works with, and the requirements on
/// intermediaries that no single captured leg can measure.
pub const RFC_9110_7_6_2: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("7.6.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6.2",
    note: "The field: its grammar (`1*DIGIT`), the methods it works with, and the recipient's permission to ignore it on the others. The section's requirements on intermediaries — check and update the value, do not forward at zero — are stated here and are not measurable from one captured leg",
};

defects! {
    /// `Max-Forwards:` written with nothing on it.
    ///
    /// `1*DIGIT` derives no empty string, so this is the grammar broken at its
    /// floor rather than a value measured past it — and it is separated from
    /// the entry below because the senders differ: one wrote a number wrong,
    /// the other wrote no number.
    ///
    // cite(RFC 9110 § 7.6.2): "Max-Forwards = 1*DIGIT"
    MAX_FORWARDS_EMPTY = {
        id: "max_forwards_empty",
        title: "Max-Forwards is written with no digits on it",
        message: "Max-Forwards is present with no digits; the field is `Max-Forwards = 1*DIGIT`, which requires at least one",
        default_severity: Severity::Error,
        spec: &[RFC_9110_7_6_2],
        strength: Strength::Grammar,
    }

    /// A `Max-Forwards` holding an octet that is not a `DIGIT`.
    ///
    /// The message names the octet, because a space, a `+` and an `obs-text`
    /// byte are three different mistakes with three different repairs and the
    /// id is the same for all of them.
    ///
    // cite(RFC 9110 § 7.6.2): "Max-Forwards = 1*DIGIT"
    MAX_FORWARDS_MALFORMED = {
        id: "max_forwards_malformed",
        title: "Max-Forwards holds something that is not a digit",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_7_6_2],
        strength: Strength::Grammar,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two entries and no `_invalid` between them: the value is never parsed
    /// into a number, so no value can be grammatical and unacceptable.
    #[test]
    fn the_subject_has_no_entry_past_the_grammar() {
        for def in [&MAX_FORWARDS_EMPTY, &MAX_FORWARDS_MALFORMED] {
            assert!(!def.id.ends_with("_invalid"), "{}", def.id);
        }
    }
}
