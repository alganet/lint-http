// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Content-Length` defects — the declared length against the octets that came,
//! and against the grammar that spells it.
//!
//! The field is framing before it is metadata: RFC 9112 § 6.2 makes its value
//! the information a recipient uses to decide where the message ends, so a
//! value that disagrees with the body is not a description that happens to be
//! stale — it is a recipient reading the next message from the wrong offset.
//! That is why the entries here default to `error` while most grammar defects in
//! this catalogue default to `warn`, and it is not this catalogue's judgment
//! alone: the two rules that report the mismatch had each chosen `error` in
//! their own configuration example, separately, before there was one place to
//! say it.
//!
//! **The grammar entries inherit that reasoning rather than the catalogue's
//! usual ranking**, because RFC 9112 § 6.3 says so in as many words: a message
//! with an invalid `Content-Length` and no `Transfer-Encoding` is a framing
//! error a recipient must treat as unrecoverable. A value that is not `1*DIGIT`
//! and a value the sender wrote twice with two different numbers land in the
//! same place as a value that is simply wrong, so they are ranked the same.
//! The one entry below that is *not* `error` is the one no sentence asks for.
//!
//! One id for both directions. A request whose declared length is wrong and a
//! response whose declared length is wrong are the same defect at opposite ends
//! of the same exchange, and the mirror rules that report them differ in which
//! message they read and in nothing else.

use crate::helpers::content_length::ContentLengthError;
use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::{defects, ViolationDef};

/// Why a mismatch matters rather than merely differing: the value is what a
/// recipient frames the message with — and, in the same section, why the field
/// may not be written at all where a transfer coding is already framing.
pub const RFC_9112_6_2: SpecRef = SpecRef {
    spec: "RFC 9112",
    section: Some("6.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-6.2",
    note: "Content-Length as framing — the declared length is how a recipient determines where the data and the message end, and the sender-side prohibition on sending it in a message that carries a Transfer-Encoding",
};

/// Where `Content-Length = 1*DIGIT` is defined — the grammar every value is
/// measured against, and the floor of one digit a value has to reach.
pub const RFC_9110_8_6: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("8.6"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.6",
    note: "Where `Content-Length = 1*DIGIT` is defined — the grammar every value here is checked against",
};

/// Why an invalid or self-contradictory value is a framing error rather than a
/// description that is merely wrong, and why one field line may carry a
/// comma-separated list provided every member is valid and identical.
pub const RFC_9112_6_3: SpecRef = SpecRef {
    spec: "RFC 9112",
    section: Some("6.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3",
    note: "Why differing values are an error and why a single field line may carry a comma-separated list, provided every member is valid and identical",
};

defects! {
    /// The declared length and the octets that arrived do not agree, whichever
    /// way the difference runs. Too few octets and the recipient waits for a
    /// message that has ended; too many and it reads the surplus as the start
    /// of the next one.
    ///
    /// The comparison is only ever made where the two are comparable: the
    /// captured length counts octets with the transfer coding resolved and any
    /// `Content-Encoding` left alone, which is what the field counts too.
    ///
    // cite(RFC 9112 § 6.2): "For messages that do include content, the Content-Length field value provides the framing information necessary for determining where the data (and message) ends."
    CONTENT_LENGTH_CONFLICTING = {
        id: "content_length_conflicting",
        title: "Content-Length disagrees with the octets received",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9112_6_2],
    }

    /// The field written at all, in a message a transfer coding is already
    /// framing. Nothing is wrong with the number; what is wrong is that it is
    /// there, because the message now states where it ends twice and the two
    /// statements are resolved by different recipients at different times.
    ///
    /// **This is the entry with an attack behind it.** § 6.3 tells a recipient
    /// to let the `Transfer-Encoding` win and an intermediary to strip the
    /// `Content-Length` before forwarding; where that does not happen
    /// consistently along a chain, two recipients disagree about where the
    /// message ends, which is the whole of request smuggling and response
    /// splitting. Both of those sentences are the reading
    /// `content_length_vs_transfer_encoding` cites at its own site — what is
    /// quoted here is the sender's prohibition, which is the defect.
    ///
    /// One id for both directions, like the mismatch above: a request that
    /// frames itself twice and a response that does are the same message
    /// written at opposite ends of the exchange.
    ///
    // cite(RFC 9112 § 6.2, label: Content-Length not in a transfer-coded message): "A sender MUST NOT send a Content-Length header field in any message that contains a Transfer-Encoding header field."
    CONTENT_LENGTH_FORBIDDEN = {
        id: "content_length_forbidden",
        title: "Content-Length is sent in a message that is transfer-coded",
        message: "Both Content-Length and Transfer-Encoding present",
        default_severity: Severity::Error,
        spec: &[RFC_9112_6_2],
    }

    /// A field line carrying no digit at all: an empty value, or one written as
    /// nothing but the commas of a list. `1*DIGIT` has a floor of one, so such
    /// a line declares no length — which is not the same as declaring zero, and
    /// a recipient that reads it as zero frames the message short.
    ///
    // cite(RFC 9110 § 8.6, label: Content-Length grammar): "Content-Length = 1*DIGIT"
    CONTENT_LENGTH_EMPTY = {
        id: "content_length_empty",
        title: "Content-Length declares no length",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_8_6],
    }

    /// An octet in the value that `DIGIT` does not admit — the sign of `-1`,
    /// the point of `1.5`, a letter, or an octet outside US-ASCII entirely.
    ///
    /// The whole production is `DIGIT`, which is ten characters of visible
    /// US-ASCII, so every octet a string reader would have refused is already
    /// an octet this entry answers for: there is nothing for the field to say
    /// about its own encoding that the grammar has not said first.
    ///
    // cite(RFC 9110 § 8.6, label: Content-Length grammar): "Content-Length = 1*DIGIT"
    CONTENT_LENGTH_CHARACTER_FORBIDDEN = {
        id: "content_length_character_forbidden",
        title: "Content-Length value holds an octet DIGIT does not admit",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_8_6],
    }

    /// A numeral that *is* `1*DIGIT` and is larger than a reader can hold. It
    /// derives from the grammar — no sentence caps the digits, unlike
    /// `delta-seconds`, and none tells a recipient to clamp — so this is a
    /// tolerance of this crate rather than a requirement it quotes, which is
    /// why it carries no citation and is the one entry in the subject that is
    /// not `error`. It takes a 39-digit value to reach.
    CONTENT_LENGTH_NUMERAL_INVALID = {
        id: "content_length_numeral_invalid",
        title: "Content-Length numeral is too large to represent",
        message: "",
        default_severity: Severity::Warn,
        spec: &[],
    }

    /// Two lengths declared in one message that are not the same number.
    /// § 5.3 makes the field lines of one section a single list, so a value
    /// repeated across lines and a value written `5, 6` on one line are the
    /// same message and the same defect — a recipient has two offsets to end
    /// the message at and no sentence choosing between them.
    ///
    // cite(RFC 9112 § 6.3): "If a message is received without Transfer-Encoding and with an invalid Content-Length header field, then the message framing is invalid and the recipient MUST treat it as an unrecoverable error, unless the field value can be successfully parsed as a comma-separated list (Section 5.6.1 of [HTTP]), all values in the list are valid, and all values in the list are the same (in which case, the message is processed with that single value used as the Content-Length field value)."
    CONTENT_LENGTH_MEMBERS_CONFLICTING = {
        id: "content_length_members_conflicting",
        title: "Content-Length is declared twice with different numbers",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9112_6_3],
    }
}

/// The defect a [`ContentLengthError`] reports as.
///
/// Exhaustive, so a new way for the field to fail does not compile until the
/// catalogue names it.
pub fn content_length_defect(defect: &ContentLengthError) -> &'static ViolationDef {
    match defect {
        ContentLengthError::Empty => &CONTENT_LENGTH_EMPTY,
        ContentLengthError::InvalidCharacter(..) => &CONTENT_LENGTH_CHARACTER_FORBIDDEN,
        ContentLengthError::TooLarge(_) => &CONTENT_LENGTH_NUMERAL_INVALID,
        ContentLengthError::MultipleValuesDiffer(..) => &CONTENT_LENGTH_MEMBERS_CONFLICTING,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every way of getting the framing wrong ranks the same, which is the
    /// subject's whole argument: the field is what a recipient ends the message
    /// with, so a value that is not a numeral is no better than one that
    /// contradicts the octets.
    #[test]
    fn every_framing_defect_defaults_above_a_grammar_defect() {
        for def in [
            &CONTENT_LENGTH_CONFLICTING,
            &CONTENT_LENGTH_FORBIDDEN,
            &CONTENT_LENGTH_EMPTY,
            &CONTENT_LENGTH_CHARACTER_FORBIDDEN,
            &CONTENT_LENGTH_MEMBERS_CONFLICTING,
        ] {
            assert_eq!(def.default_severity, Severity::Error, "{}", def.id);
        }
    }

    /// The exception, and the two halves of it are one fact: an overlong
    /// numeral is refused by this crate and by no sentence, so it carries no
    /// citation and does not rank with the defects a document asks for.
    #[test]
    fn the_entry_no_sentence_asks_for_is_the_one_that_is_not_an_error() {
        assert_eq!(
            CONTENT_LENGTH_NUMERAL_INVALID.default_severity,
            Severity::Warn
        );
        assert!(CONTENT_LENGTH_NUMERAL_INVALID.spec.is_empty());
    }

    /// Four ways the field fails, four ids — the mapping is the catalogue's
    /// half of the helper's enum, and it is spelled out so a collapse would be
    /// a decision on the page rather than a `match` arm nobody re-read.
    #[test]
    fn each_content_length_error_maps_to_its_own_id() {
        for (defect, id) in [
            (ContentLengthError::Empty, "content_length_empty"),
            (
                ContentLengthError::InvalidCharacter('x', "x".into()),
                "content_length_character_forbidden",
            ),
            (
                ContentLengthError::TooLarge("1".into()),
                "content_length_numeral_invalid",
            ),
            (
                ContentLengthError::MultipleValuesDiffer("1".into(), "2".into()),
                "content_length_members_conflicting",
            ),
        ] {
            assert_eq!(content_length_defect(&defect).id, id);
        }
    }
}
