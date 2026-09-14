// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `GOAWAY` defects — a shutdown that narrows, and a peer that reads it.
//!
//! HTTP/3's frame specifically, spelled `http3_` for the reason
//! [`http3_max_push_id`](crate::violations::http3_max_push_id) is: HTTP/2 has a
//! `GOAWAY` too, it carries a different identifier, and an operator silencing a
//! defect is naming a thing on one protocol's wire.
//!
//! **The two entries are the two sides of one frame**, and they rank
//! differently for the reason this catalogue always ranks: what the document
//! says happens next. An identifier that grew is a *connection error* of type
//! `H3_ID_ERROR` and is `error`; a stream opened past the limit breaks a plain
//! MUST NOT for which § 5.2 states no recipient's answer, and is `warn`.
//!
//! **What the identifier means depends on who sent it** — a server sends a
//! client-initiated bidirectional stream ID and a client sends a push ID — so
//! the two are different spaces and neither entry ever compares across them.
//! That is the rule's own reading and stays at its sites; what is here is the
//! pair of things a sender or a recipient did wrong.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// Connection Shutdown: what the identifier is, that it may only narrow, and
/// what an endpoint may no longer start once it has one.
pub const RFC_9114_5_2: SpecRef = SpecRef {
    spec: "RFC 9114",
    section: Some("5.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9114.html#section-5.2",
    note: "Connection Shutdown — the GOAWAY identifier and whose id space it is drawn from, the connection error a larger one draws, and the prohibition on starting anything new past it",
};

defects! {
    /// A `GOAWAY` whose identifier is larger than one the same endpoint
    /// already sent.
    ///
    /// A shutdown may narrow and may repeat; what it may not do is take back
    /// ground. `_invalid` and not `_malformed`, on
    /// [`http3_max_push_id`](crate::violations::http3_max_push_id)'s reading:
    /// the identifier is a perfectly legal variable-length integer, and what
    /// refuses it is the connection's own history. An equal identifier is not
    /// this defect — a repeated `GOAWAY` retracts nothing.
    ///
    /// `error`: § 5.2 makes the receipt a connection error of type
    /// `H3_ID_ERROR`.
    ///
    // cite(RFC 9114 § 5.2): "Receiving a GOAWAY containing a larger identifier than previously received MUST be treated as a connection error of type H3_ID_ERROR."
    HTTP3_GOAWAY_IDENTIFIER_INVALID = {
        id: "http3_goaway_identifier_invalid",
        title: "A GOAWAY identifier is larger than one already sent",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9114_5_2],
    }

    /// A request stream opened past the last stream id a server's `GOAWAY`
    /// named.
    ///
    /// **`_ignored` is the ending**, and it is the one place in this subject
    /// where the finding is about the *reader* of the frame rather than its
    /// sender: the server stated where it stops, correctly, and the peer
    /// started something beyond it. That is what `_ignored` is for — a
    /// requirement honoured by nobody rather than stated wrongly.
    ///
    /// **Only a server's `GOAWAY` can produce it.** A client's identifier is a
    /// push id and bounds no request stream, so comparing an opened stream
    /// against one would be comparing two id spaces.
    ///
    /// `warn` rather than the `error` beside it: § 5.2 states no answer a
    /// recipient owes this, unlike the identifier that grew.
    ///
    // cite(RFC 9114 § 5.2): "Endpoints MUST NOT initiate new requests or promise new pushes on the connection after receipt of a GOAWAY frame from the peer."
    HTTP3_GOAWAY_IGNORED = {
        id: "http3_goaway_ignored",
        title: "A request stream opens past the limit a server's GOAWAY set",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9114_5_2],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The split is the stated consequence and nothing else: one sentence ends
    /// in a connection error and the other ends.
    #[test]
    fn only_the_entry_whose_sentence_ends_the_connection_is_an_error() {
        assert_eq!(
            HTTP3_GOAWAY_IDENTIFIER_INVALID.default_severity,
            Severity::Error
        );
        assert_eq!(HTTP3_GOAWAY_IGNORED.default_severity, Severity::Warn);
    }

    /// One entry is about the frame's sender and the other about its reader,
    /// which is what the two endings say.
    #[test]
    fn the_endings_name_which_endpoint_is_at_fault() {
        assert!(HTTP3_GOAWAY_IDENTIFIER_INVALID.id.ends_with("_invalid"));
        assert!(HTTP3_GOAWAY_IGNORED.id.ends_with("_ignored"));
    }
}
