// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Expect` defects — the shape of an expectation, and what the one defined
//! expectation means.
//!
//! `expectation = token [ "=" ( token / quoted-string ) parameters ]`, and
//! almost every way of failing it belongs to something else: the name is a
//! [`token`](crate::violations::token), the value's quoted arm is a
//! [`quoted_string`](crate::violations::quoted_string), everything after the
//! first `;` is [`parameter`](crate::violations::parameter)'s — § 5.6.6's
//! production, imported here by name rather than restated — and an empty member
//! is the [`list`](crate::violations::list)'s.
//!
//! **What is left is the assembly**, which is what this subject holds: the
//! optional group is opened by an `=` and by nothing else, so an octet where the
//! `=` would go, and octets left over after the value ends, are both the member
//! failing to derive rather than any of its parts failing. They are one entry:
//! the position differs and the defect does not.
//!
//! **The value's emptiness is this field's own verdict and not the
//! alternation's.** `( token / quoted-string )` derives no empty string, and
//! the catalogue declines that verdict in general — six fields settled it four
//! ways — so each production says what it means for itself.
//! [`parameter_value_empty`](crate::violations::parameter) answers for a
//! parameter, which is a different half of the same member.
//!
//! **What the one defined expectation *means* is not written yet**, and it is
//! three more entries: a `100-continue` in a request with no content (§ 10.1.1
//! states it as a MUST NOT), the same expectation repeated after a `417` said
//! the response chain does not support expectations, and a `100-continue`
//! written with an argument — which the grammar admits, no sentence forbids,
//! and a recipient comparing members may answer `417` to.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// Where the field, its production and its one defined expectation are all
/// written — including the sentences about what `100-continue` means, which the
/// entries this subject has yet to gain will name.
pub const RFC_9110_10_1_1: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("10.1.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1.1",
    note: "Expect: the field's grammar, the one expectation this specification defines, and the four client requirements — of which the MUST NOT on a request without content and the SHOULD after a 417 are the two a captured message can measure",
};

defects! {
    /// A member holding octets the production does not admit: an octet after
    /// the expectation's name where only the `=` opening the optional group may
    /// stand, or octets left over after the value ended and before any `;`.
    ///
    /// **One entry for two positions.** Both are the same failure — the member
    /// does not derive from `expectation` — and neither is a defect of any part
    /// the member is assembled from: the name is a well-formed `token` that
    /// ended, and the value is a well-formed `token` or `quoted-string` that
    /// ended. What is wrong is what came next. The site's message says where.
    ///
    /// `warn`, with the rest of the grammar entries a member can reach: a
    /// recipient that cannot read an expectation answers `417` at worst, and the
    /// request itself is intact.
    ///
    // cite(RFC 9110 § 10.1.1, label: expectation production): "expectation = token [ "=" ( token / quoted-string ) parameters ]"
    EXPECT_MEMBER_MALFORMED = {
        id: "expect_member_malformed",
        title: "Expect member holds octets the expectation production does not admit",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_10_1_1],
    }

    /// A member ending on its `=`. The optional group writes the delimiter and
    /// the value together, and neither arm of `( token / quoted-string )`
    /// derives the empty string — a `token` has a one-character floor and the
    /// shortest `quoted-string` is its two DQUOTEs — so the `=` says a value was
    /// due and nothing the grammar can generate followed it.
    ///
    /// **This field's verdict rather than the alternation's**, which is the line
    /// the catalogue draws wherever `( token / quoted-string )` appears: the
    /// shared reader answers "empty" without naming a defect, because six fields
    /// settled that question four ways and two tolerate it outright. This one
    /// does not tolerate it, and says so here rather than in the reader.
    ///
    // cite(RFC 9110 § 10.1.1, label: expectation production): "expectation = token [ "=" ( token / quoted-string ) parameters ]"
    EXPECT_VALUE_EMPTY = {
        id: "expect_value_empty",
        title: "Expect writes an expectation '=' with no value after it",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_10_1_1],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The assembly and the empty value are two entries of one rank, and both
    /// name the section that writes the production — the same section the three
    /// entries about what `100-continue` *means* will name, which is why the
    /// reference is defined here rather than inside either.
    #[test]
    fn the_assembly_and_the_empty_value_are_two_entries_of_one_rank() {
        assert_ne!(EXPECT_MEMBER_MALFORMED.id, EXPECT_VALUE_EMPTY.id);
        for def in [&EXPECT_MEMBER_MALFORMED, &EXPECT_VALUE_EMPTY] {
            assert_eq!(def.default_severity, Severity::Warn, "{}", def.id);
            assert_eq!(def.spec, [RFC_9110_10_1_1], "{}", def.id);
        }
    }
}
