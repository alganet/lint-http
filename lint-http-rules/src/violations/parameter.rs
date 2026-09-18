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
//! **The two absences default to `warn` and the third entry to `info`.**
//! Nothing separates a segment with no `=` from an `=` with nothing after it:
//! both are a construct a sender wrote short, in a position the grammar prints,
//! and neither leaves a recipient reading the wrong thing — do not manufacture
//! a split to make a subject look converted. The whitespace beside the `=` is
//! below both, because once it is trimmed the parameter is intact and what is
//! wrong is only the spelling; the entry says so at length.

use crate::lint::Severity;
use crate::lint::Strength;
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
        default_severity: Severity::Error,
        spec: &[RFC_9110_5_6_6],
        strength: Strength::Grammar,
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
        default_severity: Severity::Error,
        spec: &[RFC_9110_5_6_6],
        strength: Strength::Grammar,
    }

    /// Whitespace beside the `=`. The production writes none — `parameter =
    /// parameter-name "=" parameter-value` has no `OWS` anywhere inside it —
    /// and § 5.6.6 says so a second time in prose, naming the character and
    /// refusing even the "bad" whitespace HTTP tolerates elsewhere.
    ///
    /// **`error`, and this entry used to be the one `_forbidden` in the
    /// catalogue that was not.** For a while after the level was raised, the
    /// rules reading a media type still trimmed this whitespace and published
    /// the leniency in their `description()`, so `expect_header_valid` was the
    /// only reporter and the level described a check that a `Content-Type`
    /// never ran. Every reader in the tree reports it now.
    ///
    /// The argument that closed it is the one the level was raised on: the
    /// production prints no `OWS` anywhere inside itself and § 5.6.6 says so
    /// again in prose, so the value derives from nothing. The two other ways a
    /// `parameter` fails to derive were already reported at this level from the
    /// same reader — a reader enforcing two thirds of one sentence was making a
    /// claim about the third that nothing backed. Nothing about the value is
    /// ambiguous once it is trimmed, which is why the leniency was tenable for
    /// as long as it was; an operator who wants it back turns this one entry
    /// down.
    ///
    /// Not the `<subject>_whitespace_or_control_forbidden` half of the pair
    /// `docs/development.md` mandates, and deliberately not spelled like it:
    /// that pair is about an octet *inside* a value whose grammar admits none,
    /// which is something that happened to the value. This octet sits between
    /// two constructs, where a sender put it on purpose.
    ///
    // cite(RFC 9110 § 5.6.6): "parameter       = parameter-name "=" parameter-value"
    // cite(RFC 9110 § 5.6.6): "Note: Parameters do not allow whitespace (not even "bad" whitespace) around the "=" character."
    PARAMETER_EQUALS_WHITESPACE_FORBIDDEN = {
        id: "parameter_equals_whitespace_forbidden",
        title: "Parameter writes whitespace beside its '='",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_5_6_6],
        strength: Strength::Grammar,
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

    /// All three are one production refusing one value, so all three rank
    /// together.
    ///
    /// **The whitespace entry used to sit below the two absences**, on the
    /// argument that six rules trim it before reading and publish the leniency
    /// in their `description()`. That argument is about what this crate does
    /// with the octet. `parameter = parameter-name "=" parameter-value` prints
    /// no `OWS` anywhere inside it and § 5.6.6 says so again in prose, so a
    /// value carrying one derives from nothing — which is what the level now
    /// reports. The leniency is still true, still documented on the entry, and
    /// still what an operator switches the entry off for.
    #[test]
    fn the_three_ways_a_parameter_fails_to_derive_rank_together() {
        assert_eq!(
            PARAMETER_EQUALS_MISSING.default_severity,
            PARAMETER_VALUE_EMPTY.default_severity,
        );
        assert_eq!(PARAMETER_EQUALS_MISSING.default_severity, Severity::Error);
        assert_eq!(
            PARAMETER_EQUALS_WHITESPACE_FORBIDDEN.default_severity,
            PARAMETER_VALUE_EMPTY.default_severity,
        );
    }
}
