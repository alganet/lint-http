// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Content-Length` defects — the declared length against the octets that came.
//!
//! The field is framing before it is metadata: RFC 9112 § 6.2 makes its value
//! the information a recipient uses to decide where the message ends, so a
//! value that disagrees with the body is not a description that happens to be
//! stale — it is a recipient reading the next message from the wrong offset.
//! That is why the entry here defaults to `error` while most grammar defects in
//! this catalogue default to `warn`, and it is not this catalogue's judgment
//! alone: the two rules that report it had each chosen `error` in their own
//! configuration example, separately, before there was one place to say it.
//!
//! One id for both directions. A request whose declared length is wrong and a
//! response whose declared length is wrong are the same defect at opposite ends
//! of the same exchange, and the mirror rules that report them differ in which
//! message they read and in nothing else.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// Why a mismatch matters rather than merely differing: the value is what a
/// recipient frames the message with.
pub const RFC_9112_6_2: SpecRef = SpecRef {
    spec: "RFC 9112",
    section: Some("6.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-6.2",
    note: "Content-Length as framing — the declared length is how a recipient determines where the data and the message end",
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
        spec: Some(RFC_9112_6_2),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The default is the one thing worth pinning about a single-entry subject,
    /// because it is the reason the entry is not `warn` like its neighbours.
    #[test]
    fn a_framing_disagreement_defaults_above_a_grammar_defect() {
        assert_eq!(CONTENT_LENGTH_CONFLICTING.default_severity, Severity::Error);
    }
}
