// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Content-Range` defects — the ways a server's account of what it sent is not
//! one.
//!
//! `Content-Range = range-unit SP ( range-resp / unsatisfied-range )`, and the
//! first eleven entries below follow the value left to right the way the parser
//! does: the field, the unit, the single space, the `/`, the `-`, the numerals,
//! and then the two conditions that are not grammar at all.
//!
//! **Those two are why this subject has two severities.** § 14.4 writes one
//! sentence declaring a value *invalid* when its `last-pos` precedes its
//! `first-pos`, or when its `complete-length` does not exceed its `last-pos`.
//! Such a value is well formed by the ABNF; what is wrong with it is that no
//! representation has the shape it describes, and a cache that recombines on it
//! writes octets nobody sent. Everything else there is a value a recipient
//! cannot parse — bad, and bad in a way that stops at the parse.
//!
//! **The four after them are not read out of the value at all**, and they are
//! the field's rather than the response's for one reason: § 14.4 gives the
//! field two meanings, one per status code that describes a semantic for it, so
//! whether the field is due, prohibited, or written in the wrong one of its two
//! forms is settled by *this* field's own section. The status code is the
//! condition; the field is the subject. Where a defect is the status code's
//! instead — a 206 answering a request that named no range — the entry is in
//! `violations/status.rs` and the reason is written there.

use crate::helpers::content_range::ContentRangeDefect;
use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::status::RFC_9110_15_3_7;
use crate::violations::{defects, ViolationDef};

/// The field: its grammar, and the sentence that says which well-formed values
/// are invalid anyway.
pub const RFC_9110_14_4: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("14.4"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-14.4",
    note: "Content-Range: syntax of `Content-Range` and the semantics for satisfied and unsatisfiable ranges",
};

/// The MUST that asks a single-part 206 for the field. Its sibling below is the
/// MUST NOT that refuses the same field to a multipart one: two subsections of
/// one status code, wanting opposite things of the same header section.
pub const RFC_9110_15_3_7_1: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("15.3.7.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.7.1",
    note: "206 Partial Content, single part: the response MUST carry a `Content-Range` describing the enclosed range",
};

/// The other half: where the parts carry the field, the header section may not.
pub const RFC_9110_15_3_7_2: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("15.3.7.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.7.2",
    note: "206 Partial Content, multiple parts: the parts carry the `Content-Range` fields and the header section MUST NOT carry one; a request for a single range MUST NOT be answered with a multipart response",
};

/// Range units: what the name at the front of the value has to be.
pub const RFC_9110_14_1: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("14.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-14.1",
    note: "Range Units — the `range-unit` token, case-insensitive and registered",
};

/// The sentence asking a recipient to anticipate numerals larger than it can
/// hold, which is what the overflow defect reports rather than suffers.
pub const RFC_9110_14_1_2: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("14.1.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-14.1.2",
    note: "Byte Ranges — positions are decimal numbers of octets, and recipients must anticipate large ones rather than overflow on them",
};

defects! {
    /// A `Content-Range` present with nothing in it once the field's own
    /// whitespace is off.
    ///
    // cite(RFC 9110 § 14.4): "Content-Range = range-unit SP ( range-resp / unsatisfied-range )"
    CONTENT_RANGE_EMPTY = {
        id: "content_range_empty",
        title: "Content-Range is empty",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_9110_14_4),
    }

    /// A `range-unit` that is not a `token`. Not a unit this parser fails to
    /// model — an unmodelled one parses fine and is answered elsewhere — but a
    /// name no registry could hold.
    ///
    // cite(RFC 9110 § 14.1): "All range unit names are case-insensitive and ought to be registered within the "HTTP Range Unit Registry", as defined in Section 16.5.1."
    CONTENT_RANGE_UNIT_MALFORMED = {
        id: "content_range_unit_malformed",
        title: "Content-Range unit is not a token",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_9110_14_1),
    }

    /// A value that is a `range-unit` and then stops. The production is the
    /// unit, one space, and a form after it.
    ///
    // cite(RFC 9110 § 14.4): "Content-Range = range-unit SP ( range-resp / unsatisfied-range )"
    CONTENT_RANGE_SPEC_MISSING = {
        id: "content_range_spec_missing",
        title: "Content-Range has no range after its unit",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_9110_14_4),
    }

    /// Whitespace inside the part after the space. The production holds exactly
    /// one, and it has already been used by the time this part is read.
    ///
    // cite(RFC 9110 § 14.4): "Content-Range = range-unit SP ( range-resp / unsatisfied-range )"
    CONTENT_RANGE_SPEC_WHITESPACE_FORBIDDEN = {
        id: "content_range_spec_whitespace_forbidden",
        title: "Content-Range holds whitespace after its single space",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_9110_14_4),
    }

    /// No `/`. Both forms the field can take have one.
    ///
    // cite(RFC 9110 § 14.4): "range-resp = incl-range "/" ( complete-length / "*" )"
    CONTENT_RANGE_SLASH_MISSING = {
        id: "content_range_slash_missing",
        title: "Content-Range has no '/'",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_9110_14_4),
    }

    /// Something before the `/` that opens with `*` and is not exactly `*`.
    /// `unsatisfied-range` starts with a two-character literal rather than with
    /// a wildcard that can be decorated.
    ///
    // cite(RFC 9110 § 14.4): "unsatisfied-range = "*/" complete-length"
    CONTENT_RANGE_UNSATISFIED_RANGE_MALFORMED = {
        id: "content_range_unsatisfied_range_malformed",
        title: "Content-Range writes something other than '*' before its '/'",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_9110_14_4),
    }

    /// An `incl-range` that is not two positions around a `-`: the dash
    /// missing, or a dash with nothing on one side of it. One def for both,
    /// because one production answers for them and the fix is the same fix.
    ///
    // cite(RFC 9110 § 14.4): "incl-range = first-pos "-" last-pos"
    CONTENT_RANGE_INCL_RANGE_MALFORMED = {
        id: "content_range_incl_range_malformed",
        title: "Content-Range range is not first-pos '-' last-pos",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_9110_14_4),
    }

    /// A numeral that is not `1*DIGIT` — whichever of the three it was, which
    /// the message says.
    ///
    // cite(RFC 9110 § 14.4): "complete-length = 1*DIGIT"
    CONTENT_RANGE_NUMERAL_MALFORMED = {
        id: "content_range_numeral_malformed",
        title: "Content-Range numeral is not 1*DIGIT",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_9110_14_4),
    }

    /// A numeral that *is* `1*DIGIT` and is larger than a reader can hold. It
    /// derives from the grammar, so it is `_invalid` rather than `_malformed`:
    /// § 14.1.2 asks recipients to anticipate large numerals instead of
    /// overflowing on them, and this is that anticipation reported rather than
    /// suffered — a position no recipient can represent addresses the octets of
    /// no representation.
    ///
    // cite(RFC 9110 § 14.1.2): "In the byte-range syntax, first-pos, last-pos, and suffix-length are expressed as decimal number of octets.  Since there is no predefined limit to the length of content, recipients MUST anticipate potentially large decimal numerals and prevent parsing errors due to integer conversion overflows."
    CONTENT_RANGE_NUMERAL_INVALID = {
        id: "content_range_numeral_invalid",
        title: "Content-Range numeral is too large to represent",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_9110_14_1_2),
    }

    /// `last-pos` below `first-pos`. The first of § 14.4's two invalidity
    /// conditions: the value is well formed and describes a range that runs
    /// backwards, so nothing a server could have sent has that shape.
    /// `error` by default — a recipient acting on it recombines octets from
    /// positions the response never held.
    ///
    // cite(RFC 9110 § 14.4): "A Content-Range field value is invalid if it contains a range-resp that has a last-pos value less than its first-pos value, or a complete-length value less than or equal to its last-pos value."
    CONTENT_RANGE_POSITIONS_CONFLICTING = {
        id: "content_range_positions_conflicting",
        title: "Content-Range first-pos is greater than its last-pos",
        message: "",
        default_severity: Severity::Error,
        spec: Some(RFC_9110_14_4),
    }

    /// `complete-length` at or below `last-pos`. The second condition, and the
    /// same reading: positions are zero-based and inclusive, so a `last-pos` of
    /// 499 needs a length of 500 to be the last octet rather than one past the
    /// end. `error` for the same reason as its neighbour — a cache sizing a
    /// stored representation from this writes it short.
    ///
    // cite(RFC 9110 § 14.4): "A Content-Range field value is invalid if it contains a range-resp that has a last-pos value less than its first-pos value, or a complete-length value less than or equal to its last-pos value."
    CONTENT_RANGE_COMPLETE_LENGTH_CONFLICTING = {
        id: "content_range_complete_length_conflicting",
        title: "Content-Range complete-length does not exceed its last-pos",
        message: "",
        default_severity: Severity::Error,
        spec: Some(RFC_9110_14_4),
    }

    /// A response that has a range to describe and no field describing it: a
    /// single-part 206, or a 416 answering a byte-range request. The client is
    /// told to read this field to learn what it was sent, and there is nothing
    /// to read.
    ///
    /// **One entry for a MUST and a SHOULD**, which is a decision. § 15.3.7.1
    /// requires the field of a single-part 206 and § 15.5.17 recommends it of a
    /// 416 to a byte-range request; the sender's fix differs only in which of
    /// the field's two forms to write, and an operator silencing "the field
    /// that describes the range is absent" means both. What follows is that the
    /// entry **defaults to the weaker of the two sentences**: raising it would
    /// raise the SHOULD half with the MUST half, and a recommendation is not an
    /// error because it shares an id with a requirement.
    ///
    /// The 416 half is reported for byte ranges only — both sentences asking
    /// for the field there say so — which is a condition at the site rather
    /// than a second defect.
    ///
    // cite(RFC 9110 § 15.3.7.1): "If a single part is being transferred, the server generating the 206 response MUST generate a Content-Range header field, describing what range of the selected representation is enclosed, and a content consisting of the range."
    CONTENT_RANGE_MISSING = {
        id: "content_range_missing",
        title: "Content-Range is absent from a response whose range it would describe",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_9110_15_3_7_1),
    }

    /// The field written in the header section of a multipart 206, where each
    /// body part carries its own. Nothing is wrong with the value; what is
    /// wrong is that it is there, and § 15.3.7.2 says why in the sentence
    /// itself — a client reading it would take the response for a single part
    /// and the first range for the whole of what was sent.
    ///
    // cite(RFC 9110 § 15.3.7.2): "To avoid confusion with single-part responses, a server MUST NOT generate a Content-Range header field in the HTTP header section of a multiple part response (this field will be sent in each part instead)."
    CONTENT_RANGE_FORBIDDEN = {
        id: "content_range_forbidden",
        title: "Content-Range is written in the header section of a multipart 206",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_9110_15_3_7_2),
    }

    /// The wrong one of the field's two forms for the status carrying it. A 206
    /// encloses a part and says which one, so `*/complete-length` — which
    /// describes no enclosed range — says nothing a 206 has to say; a 416
    /// encloses nothing, so `first-pos-last-pos/complete-length` describes a
    /// part that is not there.
    ///
    /// `_invalid` rather than `_malformed`: both values are well formed, and
    /// both are the *other* status code's form. One entry for the two
    /// directions, because the quoted sentence states both meanings at once and
    /// the defect is the same one read from either end — the form and the
    /// status do not describe the same message.
    ///
    // cite(RFC 9110 § 14.4): "The "Content-Range" header field is sent in a single part 206 (Partial Content) response to indicate the partial range of the selected representation enclosed as the message content, sent in each part of a multipart 206 response to indicate the range enclosed within each body part (Section 14.6), and sent in 416 (Range Not Satisfiable) responses to provide information about the selected representation."
    CONTENT_RANGE_FORM_INVALID = {
        id: "content_range_form_invalid",
        title: "Content-Range uses the form belonging to the other status code",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_9110_14_4),
    }

    /// The range described and the length declared are not the same number of
    /// octets. In a 206 the `Content-Length` counts the content of *this*
    /// message, which for a single part is exactly the enclosed range, so
    /// `last-pos - first-pos + 1` and the declared length are two statements of
    /// one count.
    ///
    /// **Which of the two is wrong is not knowable here**, and that is what
    /// keeps this entry at `warn` while `content_length_conflicting` — the same
    /// disagreement measured against the octets that actually arrived — is an
    /// `error`. That one knows what came; this one has two claims and no
    /// evidence between them.
    ///
    /// Only for units whose positions count octets, which is `bytes` and
    /// whatever else the reading rule's operator has asserted the same of. For
    /// any other unit there is no equation to write down, so there is no defect
    /// to name.
    ///
    // cite(RFC 9110 § 15.3.7): "A Content-Length header field present in a 206 response indicates the number of octets in the content of this message, which is usually not the complete length of the selected representation."
    CONTENT_RANGE_LENGTH_CONFLICTING = {
        id: "content_range_length_conflicting",
        title: "Content-Range describes a range that is not the declared Content-Length",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_9110_15_3_7),
    }
}

/// The defect a parsed [`ContentRangeDefect`] reports as.
pub fn content_range_defect(defect: ContentRangeDefect<'_>) -> &'static ViolationDef {
    match defect {
        ContentRangeDefect::Empty => &CONTENT_RANGE_EMPTY,
        ContentRangeDefect::Unit(_) => &CONTENT_RANGE_UNIT_MALFORMED,
        ContentRangeDefect::MissingRangeResp => &CONTENT_RANGE_SPEC_MISSING,
        ContentRangeDefect::WhitespaceInRangeResp(_) => &CONTENT_RANGE_SPEC_WHITESPACE_FORBIDDEN,
        ContentRangeDefect::MissingSlash => &CONTENT_RANGE_SLASH_MISSING,
        ContentRangeDefect::ValueBeforeSlash => &CONTENT_RANGE_UNSATISFIED_RANGE_MALFORMED,
        ContentRangeDefect::MissingDash | ContentRangeDefect::MissingPosition => {
            &CONTENT_RANGE_INCL_RANGE_MALFORMED
        }
        ContentRangeDefect::NotDigits { .. } => &CONTENT_RANGE_NUMERAL_MALFORMED,
        ContentRangeDefect::TooLarge { .. } => &CONTENT_RANGE_NUMERAL_INVALID,
        ContentRangeDefect::FirstPosAfterLastPos => &CONTENT_RANGE_POSITIONS_CONFLICTING,
        ContentRangeDefect::CompleteLengthNotAfterLastPos { .. } => {
            &CONTENT_RANGE_COMPLETE_LENGTH_CONFLICTING
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::content_range::Numeral;

    /// Twelve variants, eleven ids: the two halves of a malformed `incl-range`
    /// answer with one def, which is a decision, and every other row is its
    /// own.
    #[test]
    fn each_content_range_defect_maps_to_its_own_id() {
        for (defect, id) in [
            (ContentRangeDefect::Empty, "content_range_empty"),
            (
                ContentRangeDefect::Unit("by tes"),
                "content_range_unit_malformed",
            ),
            (
                ContentRangeDefect::MissingRangeResp,
                "content_range_spec_missing",
            ),
            (
                ContentRangeDefect::WhitespaceInRangeResp("0-1 /2"),
                "content_range_spec_whitespace_forbidden",
            ),
            (
                ContentRangeDefect::MissingSlash,
                "content_range_slash_missing",
            ),
            (
                ContentRangeDefect::ValueBeforeSlash,
                "content_range_unsatisfied_range_malformed",
            ),
            (
                ContentRangeDefect::MissingDash,
                "content_range_incl_range_malformed",
            ),
            (
                ContentRangeDefect::MissingPosition,
                "content_range_incl_range_malformed",
            ),
            (
                ContentRangeDefect::NotDigits {
                    numeral: Numeral::FirstPos,
                    value: "x",
                },
                "content_range_numeral_malformed",
            ),
            (
                ContentRangeDefect::TooLarge {
                    numeral: Numeral::CompleteLength,
                    value: "9".repeat(40).leak(),
                },
                "content_range_numeral_invalid",
            ),
            (
                ContentRangeDefect::FirstPosAfterLastPos,
                "content_range_positions_conflicting",
            ),
            (
                ContentRangeDefect::CompleteLengthNotAfterLastPos {
                    length: 10,
                    last: 20,
                },
                "content_range_complete_length_conflicting",
            ),
        ] {
            assert_eq!(content_range_defect(defect).id, id);
        }
    }

    /// Two fields disagreeing ranks below one field disagreeing with the octets
    /// that arrived. `content_length_conflicting` is measured against the body
    /// and knows which claim is wrong; this one holds two claims and nothing to
    /// decide between them, so it advises where the other one condemns.
    #[test]
    fn a_disagreement_with_no_evidence_ranks_below_one_with_some() {
        assert_eq!(
            CONTENT_RANGE_LENGTH_CONFLICTING.default_severity,
            Severity::Warn
        );
        assert_eq!(
            crate::violations::content_length::CONTENT_LENGTH_CONFLICTING.default_severity,
            Severity::Error,
        );
    }

    /// An id shared by a MUST site and a SHOULD site defaults to the weaker of
    /// the two: the 206 half of `content_range_missing` is required and the 416
    /// half recommended, and an operator raising the entry would raise both.
    #[test]
    fn the_entry_two_sentences_share_defaults_to_the_weaker_one() {
        assert_eq!(CONTENT_RANGE_MISSING.default_severity, Severity::Warn);
    }

    /// The two conditions § 14.4 calls *invalid* rank above the ones a parser
    /// simply cannot get past: both of those values are well formed, and both
    /// describe a representation that cannot exist.
    #[test]
    fn the_two_invalidity_conditions_rank_above_the_parse_failures() {
        assert_eq!(
            CONTENT_RANGE_POSITIONS_CONFLICTING.default_severity,
            Severity::Error
        );
        assert_eq!(
            CONTENT_RANGE_COMPLETE_LENGTH_CONFLICTING.default_severity,
            Severity::Error
        );
        assert_eq!(CONTENT_RANGE_SLASH_MISSING.default_severity, Severity::Warn);
    }
}
