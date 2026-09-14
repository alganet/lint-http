// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Problem details defects — an error format offered, and an error format
//! promised and not delivered.
//!
//! The subject is RFC 9457's format rather than any field: two rules read it
//! from opposite ends, one asking whether an error response would be better off
//! carrying problem details and the other whether content labelled as problem
//! details is any.
//!
//! **One entry here is advice and the other three are contradictions, and the
//! ranking says which is which.** Nothing requires problem details — the
//! document twice says an application with an error format of its own should
//! keep it — so the entry for an error response carrying a generic media type
//! is `info`: no sentence is broken and nothing in the message disagrees with
//! anything else in it. The other three are `warn`, because there the message
//! contradicts itself: it names a format its content is not.
//!
//! **The three are one question answered by three different pieces of
//! evidence.** A recipient asking for `type`, `title` and `status` gets none of
//! them from an empty body, from octets that are not JSON, and from a JSON
//! array alike — but the repairs are three (send content, fix the serializer,
//! wrap the value in an object), so they are three entries and not one.
//!
//! **And emptiness is one entry found three ways**, which is the opposite
//! judgment reached by the same test: captured bytes of length zero, a capture
//! that counted zero content octets, and a declared `Content-Length: 0` are
//! three readings of one message with nothing in it. Same sender, same repair,
//! one id — the evidence path is not the defect.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// What the format is for, and which status codes it fits — between them, the
/// reason the first entry below is advice rather than a defect.
pub const RFC_9457_1: SpecRef = SpecRef {
    spec: "RFC 9457",
    section: Some("1"),
    url: "https://www.rfc-editor.org/rfc/rfc9457.html#section-1",
    note: "Which status codes problem details suit, and the two sentences saying an application-specific format is often the better answer — between them the reason this finding is advice and not a defect",
};

/// The problem details JSON object, and the media type that identifies it.
pub const RFC_9457_3: SpecRef = SpecRef {
    spec: "RFC 9457",
    section: Some("3"),
    url: "https://www.rfc-editor.org/rfc/rfc9457.html#section-3",
    note: "The problem details JSON object and the media type that identifies it; §3.1 and §3.1.1 are where every member is made optional and `type` is given a value for its own absence",
};

/// What a JSON text is — the measure for content that is empty or does not
/// parse.
pub const RFC_8259_2: SpecRef = SpecRef {
    spec: "RFC 8259",
    section: Some("2"),
    url: "https://www.rfc-editor.org/rfc/rfc8259.html#section-2",
    note: "What a JSON text is — the measure for content that is empty or does not parse; §8.1 adds the UTF-8 requirement the parser also enforces",
};

defects! {
    /// A `4xx` or `5xx` whose `Content-Type` is one of the three generic JSON
    /// or XML media types, where problem details would say something machine
    /// readable about the error.
    ///
    /// **`info`, and it is the whole shape of this entry.** No document
    /// requires the format; RFC 9457 says twice that a sender with an error
    /// format of its own should keep it, so a subtype ending in `+json` or
    /// `+xml` is never this finding. What is left once those exemptions are
    /// honoured is the case the document was written for — an application with
    /// no error format at all — and saying so is advice.
    ///
    /// `_missing` rather than `_empty`: nothing was written badly, something
    /// was never written.
    ///
    // cite(RFC 9457 § 1): "This specification's aim is to define common error formats for applications that need one so that they aren't required to define their own or, worse, tempted to redefine the semantics of existing HTTP status codes."
    PROBLEM_DETAILS_MISSING = {
        id: "problem_details_missing",
        title: "An error response carries a generic media type and no error format",
        message: "",
        default_severity: Severity::Info,
        spec: &[RFC_9457_1],
    }

    /// A response declaring `application/problem+json` and carrying no content.
    ///
    /// **One entry, three pieces of evidence**: captured bytes of length zero,
    /// a capture that counted zero content octets, and a declared
    /// `Content-Length: 0` with nothing overriding it. Which of them answered
    /// is a fact about the record, not about the message — same sender, same
    /// repair — so the id is one and the message names the evidence.
    ///
    /// A content coding does not except it: a coded representation of nothing
    /// is still nothing.
    ///
    // cite(RFC 8259 § 2): "A JSON text is a serialized value."
    PROBLEM_DETAILS_EMPTY = {
        id: "problem_details_empty",
        title: "A response labelled as problem details carries no content",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_8259_2],
    }

    /// Content labelled `application/problem+json` that does not parse as JSON
    /// at all — including octets that are not UTF-8, which the same document
    /// requires of any JSON text exchanged outside a closed ecosystem.
    ///
    /// Separate from the entry below because the recipient fails at a different
    /// step and the sender fixes a different thing: here a serializer emitted
    /// something that is not a JSON document, there it emitted the wrong JSON
    /// value.
    ///
    // cite(RFC 8259 § 2): "A JSON text is a serialized value."
    PROBLEM_DETAILS_MALFORMED = {
        id: "problem_details_malformed",
        title: "Content labelled as problem details is not a JSON document",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_8259_2],
    }

    /// Well-formed JSON that is not an object: an array, a string, a number, a
    /// boolean, `null`.
    ///
    /// `_invalid` and not `_malformed`, on this catalogue's usual line: the
    /// content derives perfectly well from JSON's grammar, and what refuses it
    /// is the format the media type names on top of that grammar.
    ///
    /// **An object of no members is not this finding.** Every member is
    /// optional and an absent `type` is defined to mean `about:blank`, so `{}`
    /// is a conforming problem details object saying the problem has no
    /// semantics beyond the status code.
    ///
    // cite(RFC 9457 § 3): "The canonical model for problem details is a JSON [JSON] object."
    PROBLEM_DETAILS_INVALID = {
        id: "problem_details_invalid",
        title: "Content labelled as problem details is a JSON value other than an object",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9457_3],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The advisory entry sits below the three that report a message
    /// contradicting itself — the only ranking this subject makes, and the
    /// document is what makes it.
    #[test]
    fn the_entry_no_sentence_supports_ranks_below_the_contradictions() {
        for def in [
            &PROBLEM_DETAILS_EMPTY,
            &PROBLEM_DETAILS_MALFORMED,
            &PROBLEM_DETAILS_INVALID,
        ] {
            assert!(
                PROBLEM_DETAILS_MISSING.default_severity < def.default_severity,
                "{}",
                def.id
            );
        }
    }

    /// Every entry names the media type that arrived or the shape the content
    /// turned out to be, so none carries its own message.
    #[test]
    fn every_entry_leaves_its_message_to_the_site() {
        for def in [
            &PROBLEM_DETAILS_MISSING,
            &PROBLEM_DETAILS_EMPTY,
            &PROBLEM_DETAILS_MALFORMED,
            &PROBLEM_DETAILS_INVALID,
        ] {
            assert!(def.message.is_empty(), "{}", def.id);
        }
    }
}
