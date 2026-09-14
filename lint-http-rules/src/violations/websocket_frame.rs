// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! WebSocket frame-header defects — bits a peer closes the connection over.
//!
//! **The third protocol-element subject**, after [`status`](crate::violations::status)
//! and [`quic_transport_parameters`](crate::violations::quic_transport_parameters),
//! and the first read frame by frame: these are facts about one frame's header
//! as the relay recorded it, not about any message a field appears in.
//!
//! **The ranking is what a conforming peer does about it, and RFC 6455 states
//! that for every entry here.** A server "MUST close the connection upon
//! receiving a frame that is not masked"; a client "MUST close a connection if
//! it detects a masked frame"; a receiving endpoint MUST *Fail the WebSocket
//! Connection* on a reserved bit no negotiated extension gives a meaning to.
//! None of these is a value a recipient tolerates and moves past — each one
//! ends the session at the other end — so three of the four entries default to
//! `error` where the rules reporting them said `warn`.
//!
//! **The fourth is not about the wire at all.** The header prints the reserved
//! bits as one bit each, so a recorded value above `0b111` is a claim about the
//! *record*: no frame could have carried it, and no negotiation could license
//! it. That is a defect in what is being read rather than in what was sent, and
//! it ranks below the three that name a peer's response, because no peer ever
//! saw it.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// Overview: both masking MUSTs, the reason the client's exists, and the two
/// recipient MUSTs that say what a conforming peer does about a breach.
pub const RFC_6455_5_1: SpecRef = SpecRef {
    spec: "RFC 6455",
    section: Some("5.1"),
    url: "https://www.rfc-editor.org/rfc/rfc6455.html#section-5.1",
    note: "Overview — both masking MUSTs, the reason the client's exists, and the two \
           recipient MUSTs that say what a conforming peer does about a breach",
};

/// Base Framing Protocol: the three reserved bits, their width, the conditional
/// MUST on the sender and the MUST-fail on the recipient.
pub const RFC_6455_5_2: SpecRef = SpecRef {
    spec: "RFC 6455",
    section: Some("5.2"),
    url: "https://www.rfc-editor.org/rfc/rfc6455.html#section-5.2",
    note: "Base Framing Protocol — the three reserved bits, their width, the \
           conditional MUST on the sender and the MUST-fail on the recipient",
};

defects! {
    /// A frame the client sent with the MASK bit clear.
    ///
    /// The requirement has no escape clause: § 5.8 hands extensions the
    /// reserved bits, the reserved opcodes and the Extension data field, and
    /// says nothing about this one, so no negotiation licenses an unmasked
    /// client frame — over TLS or otherwise.
    ///
    /// `error`, and the sentence beside the MUST is why: a conforming server
    /// does not report this frame, it closes the connection.
    ///
    // cite(RFC 6455 § 5.1): "To avoid confusing network intermediaries (such as intercepting proxies) and for security reasons that are further discussed in Section 10.3, a client MUST mask all frames that it sends to the server (see Section 5.3 for further details)."
    // cite(RFC 6455 § 5.1, label: the recipient's answer to an unmasked frame): "The server MUST close the connection upon receiving a frame that is not masked."
    WEBSOCKET_FRAME_MASK_MISSING = {
        id: "websocket_frame_mask_missing",
        title: "A client frame is not masked",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_6455_5_1],
    }

    /// A frame the server sent with the MASK bit set.
    ///
    /// The exact opposite of the entry above and one sentence away from it in
    /// the same section, which is why the two are separate entries rather than
    /// one "masked wrongly": no frame reaches both, the sender differs, and so
    /// does the repair — one endpoint has to start masking and the other has to
    /// stop.
    ///
    /// `error` for the same reason: a conforming client closes the connection
    /// on detecting one.
    ///
    // cite(RFC 6455 § 5.1): "A server MUST NOT mask any frames that it sends to the client."
    // cite(RFC 6455 § 5.1, label: the recipient's answer to a masked frame): "A client MUST close a connection if it detects a masked frame."
    WEBSOCKET_FRAME_MASK_FORBIDDEN = {
        id: "websocket_frame_mask_forbidden",
        title: "A server frame is masked",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_6455_5_1],
    }

    /// A reserved bit set in a session whose opening handshake accepted no
    /// extension.
    ///
    /// **The MUST here is conditional and the antecedent is not in the frame**
    /// — a reserved bit is zero *unless an extension is negotiated that defines
    /// meanings for non-zero values* — so the finding needs the `101` that
    /// opened the session, and exists only where that handshake accepted
    /// nothing. A handshake that accepted an extension says nothing here
    /// (which bit that extension defines is its own document's business), and
    /// neither does a record that did not capture the handshake: the antecedent
    /// is then not in evidence in either direction.
    ///
    /// `error`, because when the antecedent *is* settled the same section tells
    /// the recipient to fail the connection.
    ///
    // cite(RFC 6455 § 5.2): "MUST be 0 unless an extension is negotiated that defines meanings for non-zero values."
    // cite(RFC 6455 § 5.2, label: the recipient's answer to a bit nothing defines): "If a nonzero value is received and none of the negotiated extensions defines the meaning of such a nonzero value, the receiving endpoint MUST _Fail the WebSocket Connection_."
    WEBSOCKET_FRAME_RSV_FORBIDDEN = {
        id: "websocket_frame_rsv_forbidden",
        title: "A reserved bit is set and no extension was negotiated to give it a meaning",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_6455_5_2],
    }

    /// A recorded reserved-bits value the three-bit field has no room for.
    ///
    /// **The only entry in this subject that is about the record rather than
    /// the wire.** RSV1, RSV2 and RSV3 are one bit each, so a value above
    /// `0b111` did not come off any frame header — which is why it is decided
    /// before the negotiation question above: no extension can license a bit
    /// the header cannot hold.
    ///
    /// `warn` rather than the `error` its three neighbours carry, and the
    /// difference is that no peer ever saw this. The three above each name what
    /// a conforming recipient does about the frame; here there was no such
    /// frame, and what needs fixing is whatever wrote the record.
    ///
    // cite(RFC 6455 § 5.2): "RSV1, RSV2, RSV3:  1 bit each"
    WEBSOCKET_FRAME_RSV_MALFORMED = {
        id: "websocket_frame_rsv_malformed",
        title: "The recorded reserved bits do not fit the three the header holds",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_6455_5_2],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ranking is what a conforming peer does about the frame, and the one
    /// entry that names no peer sits below the three that do.
    #[test]
    fn only_the_entry_about_the_record_ranks_below_the_ones_a_peer_closes_over() {
        for def in [
            &WEBSOCKET_FRAME_MASK_MISSING,
            &WEBSOCKET_FRAME_MASK_FORBIDDEN,
            &WEBSOCKET_FRAME_RSV_FORBIDDEN,
        ] {
            assert_eq!(def.default_severity, Severity::Error, "{}", def.id);
        }
        assert!(WEBSOCKET_FRAME_RSV_MALFORMED.default_severity < Severity::Error);
    }

    /// Every entry names the sender or the recorded value in its message, so
    /// none of them carries one of its own.
    #[test]
    fn every_entry_leaves_its_message_to_the_site() {
        for def in [
            &WEBSOCKET_FRAME_MASK_MISSING,
            &WEBSOCKET_FRAME_MASK_FORBIDDEN,
            &WEBSOCKET_FRAME_RSV_FORBIDDEN,
            &WEBSOCKET_FRAME_RSV_MALFORMED,
        ] {
            assert!(def.message.is_empty(), "{}", def.id);
        }
    }
}
