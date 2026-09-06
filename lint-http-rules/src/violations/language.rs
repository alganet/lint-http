// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Language tag defects — the seven ways a tag or a range is not one.
//!
//! Two fields carry two different productions: `Content-Language` a
//! `language-tag` and `Accept-Language` the broader `language-range`. One
//! validator serves both and checks only what the two agree on, so these
//! defects are the agreement — the character set, the hyphen as a separator,
//! and a first subtag that opens with a letter. A defect that only one of the
//! two productions has does not belong here, which is why there is no
//! subtag-ordering entry.
//!
//! The severities differ for one reason worth stating: the invisible defects
//! default higher than the visible ones. A control character in a tag is a
//! thing nobody typed and something upstream mangled; a subtag that ran to
//! nine characters is a sender being wrong on purpose.

use crate::helpers::language::LanguageTagDefect;
use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::{defects, ViolationDef};

/// What a tag is made of — the sentence behind every entry here except the
/// empty one. It gives the character set, the hyphen's job as a separator and,
/// with the ABNF beside it, the eight-character ceiling on a subtag.
pub const RFC_5646_2_1: SpecRef = SpecRef {
    spec: "RFC 5646",
    section: Some("2.1"),
    url: "https://www.rfc-editor.org/rfc/rfc5646.html#section-2.1",
    note: "Syntax: the `Language-Tag` production Content-Language carries. Its prose properties are enforced; its subtag ordering and length classes are not",
};

defects! {
    /// A member with nothing in it: `Accept-Language: en,,fr` or a field whose
    /// whole value is a comma. Nothing is trimmed first, so a member of
    /// spaces reports as a character defect rather than as this one.
    ///
    // cite(RFC 5646 § 2.1): "Language-Tag  = langtag             ; normal language tags"
    LANGUAGE_TAG_EMPTY = {
        id: "language_tag_empty",
        title: "Language tag is empty",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_5646_2_1),
    }

    /// A control octet or whitespace inside the tag — neither of which any
    /// sender types. `error` by default: both productions are ASCII
    /// alphanumerics and hyphens throughout, so an octet outside that set in a
    /// field this small is something that happened to the value in transit or
    /// in whatever assembled it.
    ///
    // cite(RFC 5646 § 2.1): "are a sequence of alphanumeric characters (letters and digits), distinguished and separated from other subtags in a tag by a hyphen"
    LANGUAGE_TAG_WHITESPACE_OR_CONTROL_FORBIDDEN = {
        id: "language_tag_whitespace_or_control_forbidden",
        title: "Language tag holds whitespace or a control character",
        message: "",
        default_severity: Severity::Error,
        spec: Some(RFC_5646_2_1),
    }

    /// A visible octet outside the alphanumerics and `-`: the underscore of
    /// `en_US`, most often, which is the locale spelling of a different
    /// ecosystem.
    ///
    // cite(RFC 5646 § 2.1): "alphanum      = (ALPHA / DIGIT)     ; letters and numbers"
    LANGUAGE_TAG_CHARACTER_FORBIDDEN = {
        id: "language_tag_character_forbidden",
        title: "Language tag holds a character outside letters, digits and hyphen",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_5646_2_1),
    }

    /// A leading or trailing `-`. The hyphen separates subtags, so one at
    /// either end describes a subtag that is not there.
    ///
    // cite(RFC 5646 § 2.1): "are a sequence of alphanumeric characters (letters and digits), distinguished and separated from other subtags in a tag by a hyphen"
    LANGUAGE_TAG_EDGE_HYPHEN_FORBIDDEN = {
        id: "language_tag_edge_hyphen_forbidden",
        title: "Language tag starts or ends with a hyphen",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_5646_2_1),
    }

    /// Two adjacent hyphens, which is the same missing subtag as the edge case
    /// with neighbours on both sides.
    ///
    // cite(RFC 5646 § 2.1): "are a sequence of alphanumeric characters (letters and digits), distinguished and separated from other subtags in a tag by a hyphen"
    LANGUAGE_TAG_SUBTAG_EMPTY = {
        id: "language_tag_subtag_empty",
        title: "Language tag has an empty subtag",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_5646_2_1),
    }

    /// A first subtag opening on a digit. The one property RFC 5646's
    /// `language` and RFC 4647's `language-range` agree on where they
    /// otherwise diverge, which is why a validator serving both fields may
    /// still enforce it.
    ///
    // cite(RFC 5646 § 2.1): "language      = 2*3ALPHA            ; shortest ISO 639 code"
    LANGUAGE_TAG_LEADING_LETTER_MISSING = {
        id: "language_tag_leading_letter_missing",
        title: "Language tag does not begin with a letter",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_5646_2_1),
    }

    /// A subtag over eight characters. Every subtag alternative in the grammar
    /// is bounded at eight, the private-use one included, so nothing longer
    /// derives from either production.
    ///
    // cite(RFC 5646 § 2.1): "privateuse    = "x" 1*("-" (1*8alphanum))"
    LANGUAGE_TAG_SUBTAG_LENGTH_INVALID = {
        id: "language_tag_subtag_length_invalid",
        title: "Language subtag is longer than eight characters",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_5646_2_1),
    }
}

/// The defect a parsed [`LanguageTagDefect`] reports as.
pub fn tag_defect(defect: LanguageTagDefect<'_>) -> &'static ViolationDef {
    match defect {
        LanguageTagDefect::Empty => &LANGUAGE_TAG_EMPTY,
        LanguageTagDefect::WhitespaceOrControl => &LANGUAGE_TAG_WHITESPACE_OR_CONTROL_FORBIDDEN,
        LanguageTagDefect::BadCharacter(_) => &LANGUAGE_TAG_CHARACTER_FORBIDDEN,
        LanguageTagDefect::HyphenPlacement => &LANGUAGE_TAG_EDGE_HYPHEN_FORBIDDEN,
        LanguageTagDefect::DoesNotBeginWithLetter => &LANGUAGE_TAG_LEADING_LETTER_MISSING,
        LanguageTagDefect::EmptySubtag => &LANGUAGE_TAG_SUBTAG_EMPTY,
        LanguageTagDefect::SubtagTooLong(_) => &LANGUAGE_TAG_SUBTAG_LENGTH_INVALID,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Seven variants, seven ids, spelled out: the helper's split is only
    /// worth having if it survives the mapping, and a variant answering with
    /// its neighbour's def would report the right sentence under the wrong
    /// name at the wrong configured severity.
    #[test]
    fn each_language_tag_defect_maps_to_its_own_id() {
        for (defect, id) in [
            (LanguageTagDefect::Empty, "language_tag_empty"),
            (
                LanguageTagDefect::WhitespaceOrControl,
                "language_tag_whitespace_or_control_forbidden",
            ),
            (
                LanguageTagDefect::BadCharacter('_'),
                "language_tag_character_forbidden",
            ),
            (
                LanguageTagDefect::HyphenPlacement,
                "language_tag_edge_hyphen_forbidden",
            ),
            (
                LanguageTagDefect::DoesNotBeginWithLetter,
                "language_tag_leading_letter_missing",
            ),
            (LanguageTagDefect::EmptySubtag, "language_tag_subtag_empty"),
            (
                LanguageTagDefect::SubtagTooLong("toolongsubtag"),
                "language_tag_subtag_length_invalid",
            ),
        ] {
            assert_eq!(tag_defect(defect).id, id);
        }
    }
}
