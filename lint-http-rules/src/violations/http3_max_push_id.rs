// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `MAX_PUSH_ID` defects — a limit only one endpoint sets, and only upward.
//!
//! The fourth protocol-element subject, and the second read out of a
//! connection rather than a message after
//! [`quic_transport_parameters`](crate::violations::quic_transport_parameters).
//! The element is HTTP/3's frame specifically: HTTP/2 has no `MAX_PUSH_ID` at
//! all, and the ids say `http3_` for the same reason `quic_` is spelled out —
//! an operator silencing a defect is naming a thing on one protocol's wire.
//!
//! **Both entries default to `error`, and RFC 9114 § 7.2.7 is why.** Each of
//! the two sentences here ends in *a connection error* — `H3_FRAME_UNEXPECTED`
//! for the frame the wrong endpoint sent, `H3_ID_ERROR` for the value that went
//! backwards — so neither is a value a peer tolerates and moves past. That is
//! the same standard [`websocket_frame`](crate::violations::websocket_frame)
//! reads its ranking off, arriving at a different protocol: an entry is `error`
//! where the document states the recipient's answer and the answer ends the
//! connection, not because the requirement is a MUST.
//!
//! **What is deliberately not an entry is the first frame, at any value.** The
//! maximum push ID is unset when a connection is created, so a `MAX_PUSH_ID` of
//! zero is a client saying the server may not push — a statement, not a
//! defect.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// The frame: who may send it, what it does, and the two connection errors its
/// misuse draws.
pub const RFC_9114_7_2_7: SpecRef = SpecRef {
    spec: "RFC 9114",
    section: Some("7.2.7"),
    url: "https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.7",
    note: "MAX_PUSH_ID — a client-only frame that raises the push limit, the prohibition on a server sending one, and the rule that a later frame cannot reduce the maximum",
};

defects! {
    /// A `MAX_PUSH_ID` frame a server sent.
    ///
    /// **The value is not read at all**, and that is the entry's shape: the
    /// frame controls how many pushes a client will accept, so it is the
    /// client's to send, and a server sending one is wrong before anything in
    /// it is looked at.
    ///
    /// `error`: the sentence beside the prohibition tells the client to treat
    /// the receipt as a connection error of type `H3_FRAME_UNEXPECTED`.
    ///
    // cite(RFC 9114 § 7.2.7): "A server MUST NOT send a MAX_PUSH_ID frame.  A client MUST treat the receipt of a MAX_PUSH_ID frame as a connection error of type H3_FRAME_UNEXPECTED."
    HTTP3_MAX_PUSH_ID_FORBIDDEN = {
        id: "http3_max_push_id_forbidden",
        title: "A server sent a MAX_PUSH_ID frame",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9114_7_2_7],
    }

    /// A `MAX_PUSH_ID` smaller than one already sent on the connection.
    ///
    /// **The value is a legal variable-length integer and what refuses it is
    /// the connection's history**, which is why the ending is `_invalid` rather
    /// than `_malformed`. An equal value is not this defect: re-sending the
    /// same limit reduces nothing, and the comparison is strict for that
    /// reason.
    ///
    /// `error`: the same sentence makes a smaller value a connection error of
    /// type `H3_ID_ERROR`.
    ///
    // cite(RFC 9114 § 7.2.7): "A MAX_PUSH_ID frame cannot reduce the maximum push ID; receipt of a MAX_PUSH_ID frame that contains a smaller value than previously received MUST be treated as a connection error of type H3_ID_ERROR"
    HTTP3_MAX_PUSH_ID_INVALID = {
        id: "http3_max_push_id_invalid",
        title: "A MAX_PUSH_ID reduces a maximum already set on the connection",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9114_7_2_7],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both sentences end in a connection error, so both entries end in
    /// `error` — the ranking is read off the stated consequence rather than off
    /// the MUST, and here the consequence is the same for both.
    #[test]
    fn both_entries_carry_the_severity_a_connection_error_earns() {
        assert_eq!(
            HTTP3_MAX_PUSH_ID_FORBIDDEN.default_severity,
            Severity::Error
        );
        assert_eq!(HTTP3_MAX_PUSH_ID_INVALID.default_severity, Severity::Error);
    }

    /// One entry names the sender and the other names two values, so both
    /// leave their message to the site.
    #[test]
    fn every_entry_leaves_its_message_to_the_site() {
        assert!(HTTP3_MAX_PUSH_ID_FORBIDDEN.message.is_empty());
        assert!(HTTP3_MAX_PUSH_ID_INVALID.message.is_empty());
    }
}
