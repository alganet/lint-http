// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `parameter` defects — the halves of `name=value` that were never written.
//!
//! `parameters = *( OWS ";" OWS [ parameter ] )` is the tail of a
//! `media-type`, of a `Content-Disposition`, of an `Accept` member's
//! `media-range` and of an `Expect` expectation, and
//! [`crate::helpers::parameter`] is the one walk over it. That walk
//! deliberately judges neither half: whether a name is a `token` and whether a
//! value derives from `( token / quoted-string )` are questions the halves'
//! own productions answer, and both have subjects here already —
//! [`crate::violations::token`] for a name and for an unquoted value,
//! [`crate::violations::quoted_string`] for a quoted one.
//!
//! What is left is this subject, and it is exactly the two positions the
//! production fills with something and a sender filled with nothing.
//! `parameter = parameter-name "=" parameter-value` brackets no part of
//! itself, so a segment with no `=` is not a valueless flag and a `name=` with
//! nothing after it is not a parameter whose value happens to be short:
//! neither derives from `parameter` at all.
//!
//! **The empty value is the verdict [`crate::violations::token::word_defect`]
//! leaves to the field, answered here for one production rather than for one
//! field.** `WordDefect::Empty` has no id because six callers of the
//! alternation had settled it four different ways — `Pragma` and
//! `Cache-Control` tolerate an empty directive argument on the record. A
//! *parameter* value is not one of those: four sites in this tree report it,
//! independently, and all four cite the same line to do it —
//! [`media_type_parts_defect`](crate::helpers::media_type::media_type_parts_defect),
//! `accept_header_media_type_syntax`, `charset_registered` for its `charset`
//! and `multipart_boundary_syntax` for its `boundary`. Where the callers
//! already agree, the def records the agreement rather than making it.
//!
//! **Both entries default to `warn`, and the flatness is the finding.** Every
//! other subject with two entries has had something to rank — an invisible
//! octet against a chosen one, a value that parses against one that does not.
//! Here both defects are a construct a sender wrote short, in a position the
//! grammar prints; there is no octet, nothing parses, and neither leaves a
//! recipient reading the wrong thing. 2.6 is the precedent: do not manufacture
//! a split to make a subject look converted.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// The whole production, in the one section that writes it. Every field
/// carrying a `;`-separated tail reaches this sentence, which is why the
/// reference lives on the subject rather than in the rules that noticed it.
pub const RFC_9110_5_6_6: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("5.6.6"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.6",
    note: "Parameters — `parameters = *( OWS \";\" OWS [ parameter ] )`, the `name=value` pair inside it with neither half optional, and the bracketing that leaves a trailing `;` conforming",
};

defects! {
    /// A segment among the parameters with no `=` in it. The delimiter is
    /// written between the two halves of `parameter` and nothing brackets it,
    /// so a bare word here is not a flag whose value is implied — it derives
    /// from the production not at all.
    ///
    /// The empty segment is *not* this defect and never reaches it:
    /// `[ parameter ]` is bracketed, so `text/plain;` and `a=b;;c=d` are
    /// conforming zero-parameter repetitions, and the walk drops them before a
    /// caller sees one.
    ///
    // cite(RFC 9110 § 5.6.6): "parameter       = parameter-name "=" parameter-value"
    PARAMETER_EQUALS_MISSING = {
        id: "parameter_equals_missing",
        title: "Parameter is written without its '='",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_9110_5_6_6),
    }

    /// An `=` with nothing after it. Neither alternative of
    /// `( token / quoted-string )` derives the empty string — `token = 1*tchar`
    /// has a one-character floor and the shortest `quoted-string` is its two
    /// DQUOTEs — so `charset=` names no charset and `boundary=` frames no body.
    ///
    /// `charset=""` is a different value and conforms: it is a `quoted-string`
    /// whose interior is empty, which the production does derive.
    ///
    /// A `tchar` scan cannot see this defect, and that is how it was missed at
    /// three sites before it was named: the empty string holds no invalid
    /// character, so a walk looking for one finds nothing and calls the value
    /// clean.
    ///
    // cite(RFC 9110 § 5.6.6): "parameter-value = ( token / quoted-string )"
    PARAMETER_VALUE_EMPTY = {
        id: "parameter_value_empty",
        title: "Parameter is written with no value after its '='",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_9110_5_6_6),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two ids are `_missing` and `_empty`, which `docs/development.md`
    /// says are never interchangeable: never written at all against written
    /// blank. This subject is where the pair is easiest to get backwards, since
    /// both defects are about a parameter that is too short.
    #[test]
    fn the_absent_delimiter_and_the_blank_value_are_two_ids() {
        assert_eq!(PARAMETER_EQUALS_MISSING.id, "parameter_equals_missing");
        assert_eq!(PARAMETER_VALUE_EMPTY.id, "parameter_value_empty");
    }

    /// Nothing here is invisible and nothing here parses, so the two entries
    /// sit at one level. Asserted so that a later commit adding a third entry
    /// has to decide whether it is ranking against this floor deliberately.
    #[test]
    fn neither_half_outranks_the_other() {
        assert_eq!(
            PARAMETER_EQUALS_MISSING.default_severity,
            PARAMETER_VALUE_EMPTY.default_severity,
        );
        assert_eq!(PARAMETER_EQUALS_MISSING.default_severity, Severity::Warn);
    }
}
