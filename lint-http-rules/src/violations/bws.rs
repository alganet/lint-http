// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `BWS` defects — the whitespace a grammar prints only because something once
//! generated it.
//!
//! One entry, and the subject exists because `BWS` is a terminal rather than a
//! field: `transfer-parameter = token BWS "=" BWS ( token / quoted-string )`,
//! `preference = token [ BWS "=" BWS word ]`, `link-param = token BWS [ "=" BWS
//! ( token / quoted-string ) ]`. Four documents, four fields, one production —
//! and each of the rules reading them had written its own sentence about a
//! space nobody should have typed.
//!
//! **This is not `parameter_equals_whitespace_forbidden`, and the difference is
//! which sentence refuses the octet.** § 5.6.6's `parameter` prints no
//! whitespace at all and adds a Note refusing even the "bad" kind, so there the
//! whitespace derives from nothing. Here it *derives*: the production writes
//! `BWS` where it sits, and what refuses it is § 5.6.3's requirement on the
//! sender. Two sentences, two ids, and a rule that reads both productions
//! declares both — which the `Prefer` rules do, since RFC 7240 writes `BWS` and
//! RFC 9110 writes the media type's `=`.
//!
//! **Both default to `info`, and they arrive there by different routes.** The
//! parameter's is `info` because six rules in this tree trim the whitespace and
//! publish the leniency; this one is `info` because § 5.6.3 states the
//! recipient's half in the same breath — a recipient MUST parse for the bad
//! whitespace and remove it — so the value is read as intended and what is
//! wrong is the spelling. **A requirement whose counterpart obliges the other
//! party to cope is a requirement about hygiene**, which is 2.28's ranking read
//! at a terminal instead of at a format.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// `BWS`, both directions of it: what a sender may not generate and what a
/// recipient must do about it anyway.
pub const RFC_9110_5_6_3: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("5.6.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.3",
    note: "Whitespace — `BWS` is printed where a grammar allows optional whitespace for historical reasons only, with a MUST NOT on the sender and a matching MUST on the recipient to remove it before interpreting the element",
};

defects! {
    /// Whitespace written where a production prints `BWS`.
    ///
    /// The grammar admits it, which is the whole of what makes this its own
    /// entry: nothing about the value is malformed, and a recipient is required
    /// to remove the octets and read what is left. What a sender is told is
    /// that the allowance is historical and not for it to use.
    ///
    /// Not the `<subject>_whitespace_or_control_forbidden` half of the pair
    /// `docs/development.md` mandates, for the same reason
    /// `parameter_equals_whitespace_forbidden` is not: that pair is about an
    /// octet *inside* a value whose alphabet excludes it — something that
    /// happened to the value — and this one sits between two constructs, where
    /// a sender put it on purpose.
    ///
    // cite(RFC 9110 § 5.6.3): "A sender MUST NOT generate BWS in messages."
    BWS_FORBIDDEN = {
        id: "bws_forbidden",
        title: "Whitespace written where the grammar admits BWS",
        message: "",
        default_severity: Severity::Info,
        spec: Some(RFC_9110_5_6_3),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::violations::parameter::PARAMETER_EQUALS_WHITESPACE_FORBIDDEN;

    /// The two whitespace-beside-an-`=` entries are separate on purpose and
    /// level on purpose, and a later commit will want to merge them.
    ///
    /// They cannot merge: `every_violation_spec_is_declared_by_its_rule`
    /// compares the const a def carries against the ones its rule declares, so
    /// one id cannot hold two sections — and the two sections say different
    /// things about the same octet. One production prints the whitespace and
    /// one does not.
    #[test]
    fn the_admitted_whitespace_and_the_underived_one_are_two_ids_at_one_level() {
        assert_ne!(BWS_FORBIDDEN.id, PARAMETER_EQUALS_WHITESPACE_FORBIDDEN.id);
        assert_eq!(
            BWS_FORBIDDEN.default_severity,
            PARAMETER_EQUALS_WHITESPACE_FORBIDDEN.default_severity,
        );
        assert_ne!(
            BWS_FORBIDDEN.spec.expect("a sentence").section,
            PARAMETER_EQUALS_WHITESPACE_FORBIDDEN
                .spec
                .expect("a sentence")
                .section,
        );
    }
}
