// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Content-Type` defects — the field that says what the content is, and the
//! parameter that says how to read it.
//!
//! The subject is the *field*, not the production: what a value derives from
//! is [`media_type`](crate::violations::media_type)'s and what a `charset`
//! names is [`charset`](crate::violations::charset)'s. Both entries here are
//! about something not being written at all.
//!
//! **They rank apart because the documents do.** § 8.3 asks for the field with
//! a SHOULD and then spends two sentences on what a recipient does without it
//! — assume `application/octet-stream`, or sniff, which the same section calls
//! a security risk. § 8.3.2 says what a `charset` is *for* and asks for
//! nothing, so the parameter's absence is this crate's policy and is ranked as
//! one.

use crate::lint::Severity;
use crate::lint::Strength;
use crate::rules::SpecRef;
use crate::violations::defects;

/// Content-Type: the SHOULD, the exception that excuses a sender who does not
/// know the type, and what a recipient does when the field is not there.
pub const RFC_9110_8_3: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("8.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3",
    note: "Content-Type — the SHOULD, the exception that excuses a sender who does not know the type, the recipient's two fallbacks, and what sniffing costs",
};

/// Charset: what the parameter is for, and the fact that no sentence asks for
/// it.
pub const RFC_9110_8_3_2: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("8.3.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3.2",
    note: "What `charset` is for. Note it mandates nothing: no requirement to send the parameter exists, so reporting its absence is this crate's policy",
};

defects! {
    /// A message carrying content and no `Content-Type`.
    ///
    /// **The exception is in the sentence and this entry cannot see it**: the
    /// SHOULD excuses a sender whose intended media type is unknown to it,
    /// which nothing on the wire records. So the finding is made anyway and
    /// the sender is the one who knows whether the excuse applies.
    ///
    /// `warn`, and the same section is the argument: a recipient with no field
    /// to read may assume `application/octet-stream` or examine the data, and
    /// § 8.3 calls that second option a risk of drawing incorrect conclusions
    /// that can expose a user to privilege escalation. What is left out is not
    /// a label, it is the decision about how the bytes are read.
    ///
    // cite(RFC 9110 § 8.3): "A sender that generates a message containing content SHOULD generate a Content-Type header field in that message unless the intended media type of the enclosed representation is unknown to the sender."
    CONTENT_TYPE_MISSING = {
        id: "content_type_missing",
        title: "A message carries content and does not say what it is",
        message: "Response contains content but no Content-Type header",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_8_3],
        strength: Strength::Should,
    }

    /// A `text/*` media type written with no `charset` parameter.
    ///
    /// **No sentence asks for it, and the entry says so.** § 8.3.2 explains
    /// what `charset` is for and requires nothing, so this is a policy of this
    /// crate's — the same footing `problem_details_missing` is on, and ranked
    /// the same way.
    ///
    /// `info`.
    ///
    // cite(RFC 9110 § 8.3.2): "HTTP uses "charset" names to indicate or negotiate the character encoding scheme"
    CONTENT_TYPE_CHARSET_MISSING = {
        id: "content_type_charset_missing",
        title: "A text media type does not say which character encoding it used",
        message: "Text-based Content-Type header missing charset parameter.",
        default_severity: Severity::Info,
        spec: &[RFC_9110_8_3_2],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One absence is asked for by a SHOULD whose section then says what it
    /// costs a recipient; the other is asked for by nothing. That is the whole
    /// of the ranking.
    #[test]
    fn the_absence_a_sentence_asks_about_outranks_the_one_it_does_not() {
        assert!(
            CONTENT_TYPE_CHARSET_MISSING.default_severity < CONTENT_TYPE_MISSING.default_severity
        );
    }
}
