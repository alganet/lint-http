// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Range` defects — what a client asks for, in the units the request names.
//!
//! The mirror of [`content_range`](crate::violations::content_range), and the
//! two subjects are worth reading side by side: the same numerals, the same
//! backwards range, and two sections stating them once each because a request
//! asking for octets and a response describing octets are not the same message.
//! **A requirement written once per direction is two entries**, which is the
//! opposite of a requirement written once per protocol version — there the
//! defect is one and the entry names both sections.
//!
//! `Range = ranges-specifier`, and `ranges-specifier = range-unit "="
//! range-set` with `range-set = 1#range-spec`. So the list construct's two
//! floors are [`list`](crate::violations::list)'s, reported here with the ids
//! any other `1#` field reports them with, the unit before the `=` is a
//! [`token`](crate::violations::token) unmodified and reports with that
//! production's ids, and what is left for this subject is the delimiter between
//! them and everything after it.
//!
//! **The unit decides how much of a specifier can be read.** § 14.1.1 writes a
//! generic `range-spec` whose third alternative, `other-range`, is any run of
//! `%x21-2B / %x2D-7E` — everything visible except the comma that separates
//! members — and each unit supplies the meaning. For `bytes` the specification
//! withdraws that alternative outright, so a specifier that is neither an
//! `int-range` nor a `suffix-range` derives from nothing. **The octet entry
//! applies to every unit and the three below it only to `bytes`**, which is why
//! the first is about a character and the rest are about arithmetic.
//!
//! Not here: whether the range can be satisfied. A `suffix-length` of zero and a
//! `first-pos` past the end of the representation are both inside the production
//! and outside what the representation holds — questions about a document this
//! request has not seen.

use crate::lint::Severity;
use crate::lint::Strength;
use crate::rules::SpecRef;
use crate::violations::{defects, ViolationDef};

/// The field's grammar: the generic specifier, the two `bytes` forms under it,
/// and the sentence that makes a backwards `int-range` invalid.
pub const RFC_9110_14_1_1: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("14.1.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-14.1.1",
    note: "Range Specifiers: `ranges-specifier = range-unit \"=\" range-set`, and the grammar under it is generic — each range unit says which of `int-range`, `suffix-range` and `other-range` its specifiers may use. A ranges-specifier is invalid when it holds a range-spec \"that is invalid or undefined for the indicated range-unit\", which is the sentence every check here rests on and the one that bounds them to the unit the rule knows",
};

/// What the `bytes` unit means by a specifier, and the alternative it withdraws.
pub const RFC_9110_14_1_2: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("14.1.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-14.1.2",
    note: "Byte Ranges: the two forms the `bytes` unit defines, both `1*DIGIT`, with `other-range` withdrawn for this unit. It also requires recipients to anticipate potentially large decimal numerals and prevent parsing errors due to integer conversion overflows — so positions are compared as digits and no ceiling is imposed — and it defines satisfiability, which is a question about the representation and not about the field",
};

defects! {
    /// An octet no `range-spec` admits, whatever the unit is.
    ///
    /// The three alternatives are digits, a hyphen, and `other-range`'s
    /// `%x21-2B / %x2D-7E` — so a space, a control octet or anything at or above
    /// %x80 is outside all of them at once, and the finding needs no knowledge
    /// of the unit to be certain. **The comma is not measured here** and cannot
    /// be: the list has already been cut on it, so no member reaching this entry
    /// holds one.
    ///
    /// **Asked at two granularities and one entry all the same.** A rule reads
    /// the whole field value before it can cut it up, and the octets this
    /// entry refuses are exactly the ones that stop it being read at all — so
    /// the first ask is of the value and the second of each member. The
    /// alphabet quoted below is the widest in the production: anything outside
    /// `%x21-2B / %x2D-7E` is outside `tchar` and is not the `=` either, so an
    /// octet the whole-value ask finds is refused by every part of a
    /// `ranges-specifier` and not only by the part it happened to sit in. *Two
    /// ids for one repair would be two names for one thing.*
    ///
    /// `error`, with the rest of the subject's grammar. A recipient that cannot
    /// read a `range-spec` ignores the field and sends the whole
    /// representation, which is a larger response rather than a wrong one — the
    /// cost, not the rank.
    ///
    // cite(RFC 9110 § 14.1.1, label: other-range octets): "other-range   = 1*( %x21-2B / %x2D-7E )"
    RANGE_SPEC_CHARACTER_FORBIDDEN = {
        id: "range_spec_character_forbidden",
        title: "Range specifier holds an octet no range-spec admits",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_14_1_1],
        strength: Strength::Grammar,
    }

    /// A `bytes` specifier that is neither an `int-range` nor a
    /// `suffix-range` — most often one with no hyphen in it at all.
    ///
    /// **The alternative that would have caught it is withdrawn by name.**
    /// `other-range` is what any other unit falls back on, and § 14.1.2 says
    /// byte ranges do not use it, so for this one unit a specifier that derives
    /// from neither numeric form derives from nothing. That is why the entry
    /// cites the unit's section rather than the grammar's.
    ///
    // cite(RFC 9110 § 14.1.2): "Each byte range is expressed as an integer range at some offset, relative to either the beginning (int-range) or end (suffix-range) of the representation data.  Byte ranges do not use the other-range specifier."
    // cite(RFC 9110 § 14.1.1, label: int-range grammar): "int-range     = first-pos "-" [ last-pos ]"
    // cite(RFC 9110 § 14.1.1, label: suffix-range grammar): "suffix-range  = "-" suffix-length"
    RANGE_SPEC_MALFORMED = {
        id: "range_spec_malformed",
        title: "A bytes range specifier derives from neither of the unit's two forms",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_14_1_2],
        strength: Strength::Grammar,
    }

    /// A position that is not `1*DIGIT`: the `first-pos`, the `last-pos`, or the
    /// `suffix-length` after a leading hyphen.
    ///
    /// **One entry for three positions**, because the production is the same one
    /// written three times and a sender that put a sign or a letter in a
    /// position made one mistake, not three. Which position it was is in the
    /// message; the id is what an operator configures, and nobody silences a bad
    /// `first-pos` while keeping a bad `last-pos`.
    ///
    /// An *absent* `last-pos` is not this entry: `int-range = first-pos "-" [
    /// last-pos ]` brackets it, and a client that omits it is asking for the
    /// remainder of the representation without needing to know its length.
    ///
    // cite(RFC 9110 § 14.1.1, label: range position grammar): "first-pos     = 1*DIGIT last-pos      = 1*DIGIT"
    RANGE_POSITION_MALFORMED = {
        id: "range_position_malformed",
        title: "Range position is not 1*DIGIT",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_14_1_1],
        strength: Strength::Grammar,
    }

    /// A `last-pos` below its `first-pos`: a range that runs backwards.
    ///
    /// Every octet derives from the production and the arithmetic is what fails,
    /// which is the same shape
    /// [`content_range_positions_conflicting`](crate::violations::content_range)
    /// has one direction over. **Two entries and not one**, because the sentence
    /// is written once per field — § 14.1.1 for what a client may ask and § 14.4
    /// for what a server may answer — and an id spelled for one of them would
    /// name the wrong section on half its findings.
    ///
    /// `error`, matching the sibling: the value states something no
    /// representation can satisfy, and a recipient that acts on it is addressing
    /// octets in an order the representation does not have.
    ///
    // cite(RFC 9110 § 14.1.1): "An int-range is invalid if the last-pos value is present and less than the first-pos."
    RANGE_POSITIONS_CONFLICTING = {
        id: "range_positions_conflicting",
        title: "Range asks for a last-pos below its first-pos",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_14_1_1],
    }

    /// A `Range` value with no `=` in it at all.
    ///
    /// **The delimiter is written between the two halves and nothing brackets
    /// it**, so a value with no `=` is not a range-set with an implied unit and
    /// not a unit with an implied set — it derives from nothing. `range-unit`
    /// is a `token`, which cannot hold an `=`, so the first one is the
    /// separator whatever follows it and there is no reading in which a value
    /// without one splits.
    ///
    /// **The other two ways to fail the same production are not here**, and
    /// that is the split this subject draws everywhere: an `=` with nothing
    /// before it is `token = 1*tchar`'s floor and a unit holding a character
    /// `tchar` does not admit is that production's alphabet, so both report
    /// with [`crate::violations::token`]'s ids — the same ids a media type's
    /// parameter name and a cache directive report with.
    ///
    /// `error`, with the rest of the subject's grammar: `ranges-specifier`
    /// prints the `=`, and a recipient that cannot read the specifier sends the
    /// whole representation.
    ///
    // cite(RFC 9110 § 14.1.1, label: ranges-specifier grammar): "ranges-specifier = range-unit "=" range-set"
    RANGE_EQUALS_MISSING = {
        id: "range_equals_missing",
        title: "Range value is written without its '='",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_14_1_1],
        strength: Strength::Grammar,
    }
}

/// The entry one `ranges-specifier` reading reports as.
///
/// The reader is [`crate::helpers::content_range::split_ranges_specifier`], and
/// only one of its three verdicts is this subject's: the missing delimiter.
/// The other two are the `token` the unit is written in, which is why this
/// mapping reaches across to that subject rather than growing two entries here.
pub fn ranges_specifier_defect(
    defect: crate::helpers::content_range::RangesSpecifierDefect,
) -> &'static ViolationDef {
    use crate::helpers::content_range::RangesSpecifierDefect as D;
    match defect {
        D::EqualsMissing => &RANGE_EQUALS_MISSING,
        D::UnitEmpty => &crate::violations::token::TOKEN_EMPTY,
        D::UnitCharacter(c) => crate::violations::token::token_character(c),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::violations::content_range::CONTENT_RANGE_POSITIONS_CONFLICTING;

    /// The backwards range is one defect written once per direction, so the two
    /// ids rank together and name different sections — which is exactly the
    /// arrangement a requirement written once per *version* refuses, where one
    /// entry names both.
    #[test]
    fn the_backwards_range_is_two_ids_of_one_rank() {
        assert_ne!(
            RANGE_POSITIONS_CONFLICTING.id,
            CONTENT_RANGE_POSITIONS_CONFLICTING.id
        );
        assert_eq!(
            RANGE_POSITIONS_CONFLICTING.default_severity,
            CONTENT_RANGE_POSITIONS_CONFLICTING.default_severity
        );
        assert_ne!(
            RANGE_POSITIONS_CONFLICTING.spec[0].section,
            CONTENT_RANGE_POSITIONS_CONFLICTING.spec[0].section
        );
    }

    /// The grammar entries used to rank below the one that reads a range
    /// running backwards, and the one that reads a unit's withdrawal of
    /// `other-range` is still the only one citing the unit's section.
    ///
    /// § 14.1.1 calls an `int-range` whose `last-pos` precedes its `first-pos`
    /// invalid, and § 2.2 refuses a value that derives from no production at
    /// all. Both are sentences addressed to whoever wrote the field, so both
    /// arrive at the same level; the citation is what still tells them apart.
    #[test]
    fn the_grammar_entries_rank_with_the_arithmetic() {
        for def in [
            &RANGE_SPEC_CHARACTER_FORBIDDEN,
            &RANGE_SPEC_MALFORMED,
            &RANGE_POSITION_MALFORMED,
        ] {
            assert_eq!(def.default_severity, Severity::Error, "{}", def.id);
        }
        assert_eq!(RANGE_SPEC_MALFORMED.spec, [RFC_9110_14_1_2]);
    }

    /// Only one of the reader's three verdicts belongs to this subject, and the
    /// mapping is what says so: the unit is a `token` written unmodified, so
    /// the two verdicts about it leave the subject entirely.
    #[test]
    fn the_units_own_defects_report_as_the_production_it_is() {
        use crate::helpers::content_range::RangesSpecifierDefect as D;
        assert_eq!(
            ranges_specifier_defect(D::EqualsMissing).id,
            "range_equals_missing"
        );
        assert_eq!(ranges_specifier_defect(D::UnitEmpty).id, "token_empty");
        assert_eq!(
            ranges_specifier_defect(D::UnitCharacter('@')).id,
            "token_character_forbidden"
        );
        assert_eq!(
            ranges_specifier_defect(D::UnitCharacter(' ')).id,
            "token_whitespace_or_control_forbidden"
        );
    }
}
