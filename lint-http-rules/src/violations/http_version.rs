// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `HTTP-version` defects — the protocol element both start-lines carry.
//!
//! One production, `HTTP-name "/" DIGIT "." DIGIT`, written at the end of a
//! request-line and at the beginning of a status-line — and one entry for
//! failing it, because a value fails it the same way in either place. Which
//! message it came from is in the finding's wording, not in its id.
//!
//! **The second entry is the opposite case: a version that derives perfectly
//! and is still not enough.** Some exchanges name a floor — a WebSocket opening
//! handshake is *an HTTP/1.1 or higher GET request* — and a message below it is
//! refused by what it is trying to do rather than by the grammar. The sentence
//! stating the floor belongs to whichever document defines the exchange, so the
//! entry carries none of its own and the finding names the one it was read
//! from.
//!
//! **The subject exists although two of the three versions never put it on the
//! wire.** HTTP/2 and HTTP/3 carry no start-line, and a capture records a
//! version for them anyway, so this element is as much a fact about the record
//! as about the message — which is why the entry is careful to say that the
//! value reached a reader at all.

use crate::lint::Severity;
use crate::lint::Strength;
use crate::rules::SpecRef;
use crate::violations::defects;

/// The production, its case-sensitivity, and where it appears.
pub const RFC_9112_2_3: SpecRef = SpecRef {
    spec: "RFC 9112",
    section: Some("2.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-2.3",
    note: "The production, the sentence saying it is case-sensitive, and the sentence saying only an HTTP/1.x message carries it in a start-line",
};

defects! {
    /// A version deriving from no reading of `HTTP-version`: a name that is not
    /// the case-sensitive `HTTP`, a digit position holding something that is
    /// not a `DIGIT`, or more than one digit on either side of the dot.
    ///
    /// **One entry for both start-lines**, because the production is one and a
    /// value fails it identically wherever it was written. The message names
    /// the direction, since that is what a sender needs and it is the only
    /// thing that differs.
    ///
    /// **`_malformed` in its plainest sense** — the value derives from no
    /// reading of the grammar — and the modal behind it is § 2.2's MUST NOT
    /// against generating an element that does not match its ABNF, reached
    /// from RFC 9112 § 1.1.
    ///
    // cite(RFC 9112 § 2.3): "HTTP-version  = HTTP-name "/" DIGIT "." DIGIT"
    HTTP_VERSION_MALFORMED = {
        id: "http_version_malformed",
        title: "A protocol version derives from no reading of HTTP-version",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9112_2_3],
        strength: Strength::Grammar,
    }

    /// A version that derives from the production and is below the floor the
    /// exchange requires: a WebSocket opening handshake sent over HTTP/1.0.
    ///
    /// **`_invalid` and the split from its sibling is the whole of the
    /// subject.** `HTTP/1.0` is a perfectly good `HTTP-version`, written the
    /// way § 2.3 writes it; what refuses it is one level past the grammar, and
    /// the refusal comes from what the message is *trying to do* rather than
    /// from how it is spelled.
    ///
    /// **Uncited, and it is the fourth reason this catalogue has for that: the
    /// sentence exists, in a document the entry cannot name.** The floor is
    /// stated by whichever specification defines the exchange — RFC 6455
    /// § 4.2.1 for the WebSocket handshake, and any later exchange that names
    /// one will state it somewhere else again — so a reference here would put
    /// one protocol's section on another protocol's finding the moment a second
    /// declarer arrives. The message names the sentence it was read from,
    /// which is what a finding does when its def cannot.
    ///
    /// `error`, level with the entry beside it, which is where this subject
    /// puts both halves of one production. Nothing is unreadable and the
    /// request is a well-formed HTTP message; what it asks for is an exchange
    /// the version cannot carry, and the recipient's own instruction — stop
    /// processing and answer with an error status — is what the finding is
    /// predicting.
    HTTP_VERSION_INVALID = {
        id: "http_version_invalid",
        title: "A protocol version is below the floor the exchange requires",
        message: "",
        default_severity: Severity::Error,
        spec: &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One production, one entry, and the direction lives in the message —
    /// splitting by start-line would be two ids for one grammar.
    #[test]
    fn the_entry_does_not_split_by_which_start_line_carried_it() {
        assert!(!HTTP_VERSION_MALFORMED.id.contains("request"));
        assert!(!HTTP_VERSION_MALFORMED.id.contains("response"));
        assert!(HTTP_VERSION_MALFORMED.message.is_empty());
    }

    /// The two entries are the two sides of one production: one for a value
    /// that does not derive, one for a value that derives and is refused by
    /// what the message attempts. Only the first can name a sentence, because
    /// only the first is about the grammar.
    #[test]
    fn the_grammar_names_a_sentence_and_the_floor_cannot() {
        assert!(!HTTP_VERSION_MALFORMED.spec.is_empty());
        assert!(HTTP_VERSION_INVALID.spec.is_empty());
        assert_eq!(
            HTTP_VERSION_INVALID.default_severity,
            HTTP_VERSION_MALFORMED.default_severity
        );
    }
}
