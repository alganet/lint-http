// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! The `qvalue` production — one entry, and four fields asking for it.
//!
//! A weight is how a request says which of several acceptable things it would
//! rather have, and RFC 9110 § 12.4.2 writes the number once for all of them:
//! `Accept`, `Accept-Encoding`, `Accept-Language` and `TE` each carry
//! `weight = OWS ";" OWS "q=" qvalue` and none of them restates what a
//! `qvalue` is. So a `q=1.5` in an `Accept` and a `q=1.5` in a `TE` are the
//! same defect, and before this subject existed they were four sentences with
//! four severities — one per rule, whichever the operator had configured for
//! everything else that rule says.
//!
//! **The assembly around the weight is here too, and the paragraph this
//! replaces said it was not.** That paragraph reasoned that a `;` with no
//! weight after it, a second weight in one member and a parameter that is not
//! `q` are statements about how a *member* is put together, so they belong to
//! the fields that make them — "and each is read by one rule". The second half
//! was asserted and never counted. `Accept-Encoding` and `Accept-Language`
//! report all three apiece, in code that reads the same because the grammar
//! does: `#( codings [ weight ] )` and `#( language-range [ weight ] )` admit
//! exactly one thing after the primary, and it is this production. A
//! `gzip;q=0.5;q=0.8` and an `en;q=0.5;q=0.8` are one defect with one fix.
//!
//! **What keeps `Accept` and `TE` out of it is the same reading from the other
//! side.** A `media-range` carries `parameters = *( OWS ";" OWS [ parameter ] )`
//! and a `transfer-coding` carries `*( OWS ";" OWS transfer-parameter )`, so a
//! `;` in those two fields may introduce something that is not a weight at all:
//! a trailing one is a bracketed empty repetition and conforms, and a
//! `charset=utf-8` after a media-range is a parameter the production prints.
//! The three assembly entries here are for the fields where nothing but a
//! weight can stand in that position — which is why they are the weight's
//! defects and not the member's.
//!
//! **The weight's own spelling is a different question and is here**, under a
//! `weight_` prefix rather than a `qvalue_` one — the file stem groups a
//! subject and does not have to prefix its ids, the way
//! [`uri`](crate::violations::uri) holds the `percent_encoding_*` entries.
//! `weight = OWS ";" OWS "q=" qvalue` prints `q=` as a single literal with
//! nothing optional inside it, so whitespace written into that literal is not
//! bad whitespace a recipient parses out: it is characters the production does
//! not generate, in the one place this construct has no `OWS` to spare.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// Quality Values, whole: the production, its two alternatives, the bound on
/// its fraction and the parameter that carries it. One section, and five rules
/// had written five notes for it.
pub const RFC_9110_12_4_2: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("12.4.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-12.4.2",
    note: "Quality Values — `weight = OWS \";\" OWS \"q=\" qvalue`, the `qvalue` production and its three-digit fraction, the case-insensitive `q` parameter name, and what a weight of zero means",
};

defects! {
    /// A weight that derives from neither alternative of the production.
    ///
    /// The two alternatives are asymmetric on purpose — anything from `0` to
    /// `0.999` on one side, and on the other a `1` that may only be followed by
    /// zeroes — so `1.5` and `0.1234` fail for different arithmetic and the
    /// same reason: the value names no quality between none and all of it. Both
    /// are one fix, which is why they are one entry.
    ///
    /// `warn` rather than `error`: the member is still a member and a recipient
    /// that cannot read the weight has a default to fall back on, so what is
    /// lost is the preference the sender meant to express rather than the
    /// message. It sits above nothing and below the invisible-octet defects the
    /// same rules report, which is the ranking those rules could not make while
    /// this shared one scalar with them.
    ///
    // cite(RFC 9110 § 12.4.2): "qvalue = ( "0" [ "." 0*3DIGIT ] ) / ( "1" [ "." 0*3("0") ] )"
    QVALUE_MALFORMED = {
        id: "qvalue_malformed",
        title: "Weight is not a qvalue",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_12_4_2],
    }

    /// Whitespace beside the weight's `=`: `q =0.5`, `q= 0.5`. The three
    /// characters of `"q="` are one ABNF string literal, and the two `OWS` the
    /// production does print are both before it — so a recipient matching the
    /// literal finds no weight here, and the preference the sender wrote is
    /// lost rather than misread.
    ///
    /// **Not [`BWS_FORBIDDEN`](crate::violations::bws::BWS_FORBIDDEN), and the
    /// distinction is the whole reason this entry exists.** A
    /// `transfer-parameter` prints `BWS` around its `=`, so whitespace there is
    /// admitted-for-historical-reasons and answers to § 5.6.3's sentence about
    /// a sender who generates it. Nothing of the kind is written into `weight`.
    /// The same three characters, two productions, and only one of them has a
    /// sentence about bad whitespace to quote — which is why reporting this as
    /// `bws_forbidden` would name a requirement about a construct that is not
    /// here.
    ///
    /// Nor is it
    /// [`PARAMETER_EQUALS_WHITESPACE_FORBIDDEN`](crate::violations::parameter::PARAMETER_EQUALS_WHITESPACE_FORBIDDEN),
    /// which is `info` because § 5.6.6's Note acknowledges the habit and six
    /// rules in this tree trim it on the record. No sentence acknowledges this
    /// one, and no reader here trims it, so it ranks with the malformed number
    /// above it: in both cases the member arrives and its weight does not.
    ///
    // cite(RFC 9110 § 12.4.2, label: the weight production): "weight = OWS ";" OWS "q=" qvalue"
    WEIGHT_EQUALS_WHITESPACE_FORBIDDEN = {
        id: "weight_equals_whitespace_forbidden",
        title: "Whitespace is written beside the weight's '='",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_12_4_2],
    }

    /// A `;` with nothing after it, in a field where the `;` can only be the
    /// weight's own: `en;`, `gzip;;q=0.5`.
    ///
    /// The production brackets nothing inside itself. The separator, the
    /// literal and the number are one alternative-free sequence, so writing the
    /// `;` is what owes the rest of it — a member ending there has begun a
    /// weight and abandoned it.
    ///
    /// `_missing` and not `_empty`: the `;` is the weight's own first
    /// character, not a container a sender filled with nothing, so what is
    /// absent is `"q=" qvalue` — a thing never written where the separator
    /// requires it.
    ///
    /// **The same octet conforms in an `Accept` and in a `TE`**, and that is
    /// the whole reason this entry can be shared by only two fields.
    /// `parameters = *( OWS ";" OWS [ parameter ] )` brackets the parameter, so
    /// `text/plain;` is a zero-parameter repetition and derives; a
    /// `transfer-coding` prints the same repetition. Only where the field's own
    /// production puts `[ weight ]` and nothing else after the primary is a
    /// dangling `;` a defect, and then it is this one.
    ///
    // cite(RFC 9110 § 12.4.2, label: the weight production): "weight = OWS ";" OWS "q=" qvalue"
    WEIGHT_MISSING = {
        id: "weight_missing",
        title: "Member writes the weight's ';' and no weight after it",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_12_4_2],
    }

    /// Something stands where the weight must and is not one: `en;charset=utf-8`,
    /// `gzip;foo="a;b"`, `en;q`.
    ///
    /// **Two spellings, one entry, because the production draws no line between
    /// them.** `"q="` is a single ABNF string literal with nothing optional
    /// inside it, so a segment naming any other parameter and a segment naming
    /// `q` without the `=` both fail to write it — and a recipient that matched
    /// the literal found no weight either way. The message names which was
    /// written.
    ///
    /// **Not [`PARAMETER_EQUALS_MISSING`](crate::violations::parameter::PARAMETER_EQUALS_MISSING),
    /// and the difference is which field is being read.** `te_header_valid`
    /// reports a segment with no `=` under that id, correctly: a `TE` member may
    /// carry `transfer-parameter`s, so § 5.6.6's `name "=" value` is a
    /// production the segment could have been trying to write. These two fields
    /// have no parameter list at all — nothing but a weight derives here — so
    /// naming a `parameter` requirement would cite a construct the field does
    /// not have.
    ///
    /// Ranked with [`QVALUE_MALFORMED`] rather than above it: in both cases the
    /// member arrives and the preference does not.
    ///
    // cite(RFC 9110 § 12.4.2): "The content negotiation fields defined by this specification use a common parameter, named "q" (case-insensitive), to assign a relative "weight" to the preference for that associated kind of content."
    WEIGHT_MALFORMED = {
        id: "weight_malformed",
        title: "Something other than a weight follows the member's ';'",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_12_4_2],
    }

    /// Two weights in one member: `en;q=0.5;q=0.8`.
    ///
    /// `[ weight ]` is a single optional repetition, so the second one derives
    /// from nothing, and a recipient that reads the first and a recipient that
    /// reads the last disagree about a preference the sender wrote twice.
    ///
    /// **Uncited, and for a reason none of the other uncited entries has.** The
    /// bracket is written once per field — RFC 9110 § 10.1.4, § 12.5.1, § 12.5.3
    /// and § 12.5.4 each print it for their own — and one entry is declared by
    /// the rules that read those fields.
    /// `every_violation_spec_is_declared_by_its_rule` compares a def's
    /// references against *each* declaring rule's, so a shared entry may only
    /// name a sentence every declarer states, and no rule here states another
    /// field's production. A `spec` that is a slice answers a def whose sections
    /// are all stated by one rule; it cannot answer a def whose sections are
    /// stated one per rule, so the finding names its own section in its message
    /// as it already did.
    WEIGHT_DUPLICATED = {
        id: "weight_duplicated",
        title: "Member carries more than one weight",
        message: "",
        default_severity: Severity::Warn,
        spec: &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The one thing a single-entry subject can get wrong on its own: the
    /// default, which is what four rules stop imposing on this defect.
    #[test]
    fn a_weight_that_is_not_one_is_a_warning() {
        assert_eq!(QVALUE_MALFORMED.default_severity, Severity::Warn);
    }

    /// Every way a member can fail to carry one readable weight leaves the
    /// member itself standing and the preference unread, so nothing here
    /// outranks anything else. The flat rank is the claim; do not split it to
    /// make the subject look finer than the defects are.
    #[test]
    fn every_way_of_losing_the_preference_sits_at_one_level() {
        for def in [
            &QVALUE_MALFORMED,
            &WEIGHT_MISSING,
            &WEIGHT_MALFORMED,
            &WEIGHT_DUPLICATED,
            &WEIGHT_EQUALS_WHITESPACE_FORBIDDEN,
        ] {
            assert_eq!(def.default_severity, Severity::Warn, "{}", def.id);
        }
    }

    /// The separator written with nothing after it and the separator written
    /// with the wrong thing after it are two ids. `docs/development.md` reads
    /// `_missing` as a thing never written where it is required and
    /// `_malformed` as one written and not deriving, which is exactly the line
    /// between `en;` and `en;charset=utf-8` — different senders, different
    /// fixes.
    #[test]
    fn the_absent_weight_and_the_underived_one_are_two_ids() {
        assert_eq!(WEIGHT_MISSING.id, "weight_missing");
        assert_eq!(WEIGHT_MALFORMED.id, "weight_malformed");
    }

    /// The one entry in this subject that names no sentence, and the assertion
    /// is what keeps the reason honest: four sections print `[ weight ]`, one
    /// per field, and a shared entry may only cite what every declarer states.
    /// If a single sentence is ever found that bounds the repetition for all of
    /// them, this is the test that has to change first.
    #[test]
    fn the_bracket_is_written_once_per_field_so_the_entry_names_none_of_them() {
        assert!(WEIGHT_DUPLICATED.spec.is_empty());
        assert!(!WEIGHT_MISSING.spec.is_empty());
    }
}
