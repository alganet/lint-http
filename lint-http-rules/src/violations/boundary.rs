// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `boundary` defects — the delimiter that tells one body part from the next.
//!
//! The parameter is a `parameter` like any other, so a missing `=`, an empty
//! value or a `quoted-string` that never closes answer under those subjects.
//! What is here is the *value* against RFC 2046 § 5.1.1's own production, which
//! is not an HTTP one and is deliberately narrower than `token`: `bchars` is a
//! set chosen to survive mail gateways, and it admits SP everywhere but at the
//! end.
//!
//! **The alphabet is not `token`'s and the two are incomparable**, which is why
//! this subject exists rather than borrowing: `(`, `)`, `,`, `/`, `:`, `=`, `?`
//! and SP are `bchars` and are not `tchar`s, while `!`, `#`, `$`, `&`, `*`,
//! `^`, `` ` `` and `|` are `tchar`s and not `bchars`. A boundary written with
//! either set alone would be reported by the wrong sentence.
//!
//! **Every entry here is about the delimiter working**, not about framing: HTTP
//! does not use the boundary to find where the message ends (RFC 9110 § 8.3.3
//! says so outright), so what a bad boundary costs is a recipient that cannot
//! separate the parts it was handed.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// The multipart common syntax: the required parameter, its grammar, its
/// length, and the trailing space that is not allowed to be there.
pub const RFC_2046_5_1_1: SpecRef = SpecRef {
    spec: "RFC 2046",
    section: Some("5.1.1"),
    url: "https://www.rfc-editor.org/rfc/rfc2046.html#section-5.1.1",
    note: "Multipart common syntax: the required `boundary` parameter, the `boundary`/`bchars`/`bcharsnospace` grammar, the 1-to-70-character limit and the ban on a trailing space, and the warning that a boundary often has to be quoted",
};

defects! {
    /// A multipart media type with no `boundary` at all. Absence is the whole
    /// defect and it is a requirement rather than a default: the delimiter line
    /// is two hyphens followed by this value, so without it there is no line
    /// that separates anything and the parts are indistinguishable from their
    /// own content.
    ///
    // cite(RFC 2046 § 5.1.1): "The Content-Type field for multipart entities requires one parameter, "boundary"."
    BOUNDARY_MISSING = {
        id: "boundary_missing",
        title: "A multipart media type carries no boundary parameter",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_2046_5_1_1],
    }

    /// A character the delimiter set does not hold. The set is small and
    /// chosen, not an accident of the grammar: RFC 2046 picked characters
    /// "known to be very robust through mail gateways", so an octet outside it
    /// is one a gateway may rewrite — and a rewritten delimiter separates
    /// nothing.
    ///
    // cite(RFC 2046 § 5.1.1, label: bchars with space): "bchars := bcharsnospace / " ""
    // cite(RFC 2046 § 5.1.1, label: bcharsnospace): "bcharsnospace := DIGIT / ALPHA / "'" / "(" / ")" / "+" / "_" / "," / "-" / "." / "/" / ":" / "=" / "?""
    BOUNDARY_CHARACTER_FORBIDDEN = {
        id: "boundary_character_forbidden",
        title: "Boundary holds a character outside the delimiter set",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_2046_5_1_1],
    }

    /// A boundary of no characters, or of more than seventy. The production
    /// states the ceiling as `0*69<bchars>` followed by one more character and
    /// the prose states it again in words, so both ends are the document's:
    /// there is no empty alternative, and `boundary=""` reaches this entry
    /// after the quotes come off.
    ///
    // cite(RFC 2046 § 5.1.1, label: boundary production): "boundary := 0*69<bchars> bcharsnospace"
    // cite(RFC 2046 § 5.1.1): "The only mandatory global parameter for the "multipart" media type is the boundary parameter, which consists of 1 to 70 characters from a set of characters known to be very robust through mail gateways, and NOT ending with white space."
    BOUNDARY_LENGTH_INVALID = {
        id: "boundary_length_invalid",
        title: "Boundary is empty or longer than seventy characters",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_2046_5_1_1],
    }

    /// A boundary whose last character is a space. SP is a `bchar` everywhere
    /// else in the value, which is why this is its own entry rather than a case
    /// of the alphabet: the production spells the exception into its shape by
    /// ending on `bcharsnospace`.
    ///
    /// The reason is a recipient's rather than a sender's. A gateway may append
    /// whitespace to a line, so a delimiter that legitimately ends in a space
    /// cannot be told from one that was padded in transit — and the recipient
    /// has to guess which of the two it is holding.
    ///
    // cite(RFC 2046 § 5.1.1, label: boundary production): "boundary := 0*69<bchars> bcharsnospace"
    BOUNDARY_TRAILING_SPACE_FORBIDDEN = {
        id: "boundary_trailing_space_forbidden",
        title: "Boundary ends with a space",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_2046_5_1_1],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One document behind all four, and it is not an HTTP one — which is the
    /// subject's reason for existing. A boundary borrowed `token`'s ids would
    /// be measured against an alphabet that neither contains nor is contained
    /// by the one its own document prints.
    #[test]
    fn every_entry_is_measured_against_the_multipart_document() {
        for def in [
            &BOUNDARY_MISSING,
            &BOUNDARY_CHARACTER_FORBIDDEN,
            &BOUNDARY_LENGTH_INVALID,
            &BOUNDARY_TRAILING_SPACE_FORBIDDEN,
        ] {
            assert_eq!(def.spec, [RFC_2046_5_1_1], "{}", def.id);
        }
    }
}
