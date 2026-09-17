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
//! **The ranking is what a conforming peer does about the frame, and it is read
//! off the document rather than off the severity of the prohibition.** Where
//! RFC 6455 states the recipient's answer, the entry is `error`: a server "MUST
//! close the connection upon receiving a frame that is not masked", a client
//! "MUST close a connection if it detects a masked frame", a receiving endpoint
//! MUST *Fail the WebSocket Connection* on a reserved bit — and on an unknown
//! opcode — that nothing gives a meaning to. None of those is a value a
//! recipient tolerates and moves past; each ends the session at the other end.
//!
//! **Everything else here is `warn`, including plain MUSTs**, and that is the
//! deliberate half. A control frame over 125 bytes, a fragmented control frame,
//! a one-byte Close body, a data frame after that endpoint's own Close, a
//! continuation with nothing open, two interleaved messages — every one of them
//! breaks a MUST, and for none of them does the document say what the peer
//! does. Ranking them by the strength of the word would put them all at the
//! top; ranking them by the stated consequence keeps `error` meaning *this
//! session ends*.
//!
//! **Two entries are not about the wire at all.** The header prints the
//! reserved bits as one bit each and the opcode as four bits, so a recorded
//! value above `0b111` or above 15 is a claim about the *record*: no frame
//! could have carried it, and no negotiation could license it. Those are
//! defects in what is being read rather than in what was sent, and they rank
//! below every entry that names a peer's response, because no peer ever saw
//! them.
//!
//! **Why § 5.2 appears twice below.** One reference is the reserved bits and
//! the other the opcode ranges; they are separate readings of one section, and
//! a rule declaring an entry must state the reference the entry names — so the
//! rule reading bits would otherwise have to publish a note about opcodes.

use crate::lint::Severity;
use crate::lint::Strength;
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
pub const RFC_6455_5_2_RSV_BITS: SpecRef = SpecRef {
    spec: "RFC 6455",
    section: Some("5.2"),
    url: "https://www.rfc-editor.org/rfc/rfc6455.html#section-5.2",
    note: "Base Framing Protocol — the three reserved bits, their width, the \
           conditional MUST on the sender and the MUST-fail on the recipient",
};

/// Base Framing Protocol: the opcode's two reserved ranges, what each is
/// reserved for, and the MUST-fail an unknown opcode draws.
pub const RFC_6455_5_2_OPCODES: SpecRef = SpecRef {
    spec: "RFC 6455",
    section: Some("5.2"),
    url: "https://www.rfc-editor.org/rfc/rfc6455.html#section-5.2",
    note: "Base Framing Protocol — the opcode definitions, the two reserved ranges and what \
           each is reserved for, and the MUST-fail a receiving endpoint owes an unknown opcode",
};

/// Fragmentation: what a fragmented message is made of, that a control frame
/// is never one, and that two messages may not interleave.
pub const RFC_6455_5_4: SpecRef = SpecRef {
    spec: "RFC 6455",
    section: Some("5.4"),
    url: "https://www.rfc-editor.org/rfc/rfc6455.html#section-5.4",
    note: "Fragmentation — what a fragmented message is made of, the MUST NOT against \
           fragmenting a control frame stated in its own right, and the MUST NOT against \
           interleaving two messages with its extension escape",
};

/// Control Frames: the class test, and the one sentence carrying both
/// constraints on a control frame.
pub const RFC_6455_5_5: SpecRef = SpecRef {
    spec: "RFC 6455",
    section: Some("5.5"),
    url: "https://www.rfc-editor.org/rfc/rfc6455.html#section-5.5",
    note: "Control Frames — the class test, and the sentence bounding a control frame's \
           payload at 125 bytes",
};

/// Close: the body's first two bytes, and the end of what its sender may send.
pub const RFC_6455_5_5_1: SpecRef = SpecRef {
    spec: "RFC 6455",
    section: Some("5.5.1"),
    url: "https://www.rfc-editor.org/rfc/rfc6455.html#section-5.5.1",
    note: "Close — the body is optional, a body that exists opens with a two-byte status \
           code, and a sender's own Close ends what it may send",
};

/// The opcode registry: the field's range, and how a new assignment arrives.
pub const RFC_6455_11_8: SpecRef = SpecRef {
    spec: "RFC 6455",
    section: Some("11.8"),
    url: "https://www.rfc-editor.org/rfc/rfc6455.html#section-11.8",
    note: "WebSocket Opcode Registry — the field's range, and the Standards Action policy \
           that makes an unassigned value one no deployment can outrun",
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
        strength: Strength::Must,
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
        strength: Strength::Must,
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
        spec: &[RFC_6455_5_2_RSV_BITS],
        strength: Strength::Must,
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
        spec: &[RFC_6455_5_2_RSV_BITS],
    }

    /// A recorded opcode the four-bit field has no room for.
    ///
    /// The twin of [`WEBSOCKET_FRAME_RSV_MALFORMED`] and read for the same
    /// reason: the frame header gives the opcode four bits, so a value above 15
    /// came off no wire. § 11.8 is quoted rather than the framing section
    /// because it is where the range is written as a range — § 5.2 prints a bit
    /// count and leaves the arithmetic to the reader.
    ///
    /// `warn`, below every entry that names what a peer does, because no peer
    /// saw this frame.
    ///
    // cite(RFC 6455 § 11.8): "The opcode is an integer number between 0 and 15, inclusive."
    WEBSOCKET_FRAME_OPCODE_MALFORMED = {
        id: "websocket_frame_opcode_malformed",
        title: "The recorded opcode does not fit the four bits the header holds",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_6455_11_8],
    }

    /// An opcode inside one of the two reserved ranges, in a session that
    /// negotiated no extension: `%x3-7` for further non-control frames and
    /// `%xB-F` for further control frames.
    ///
    /// **Two ranges and two sentences, one entry.** They reserve for two
    /// different things and the message says which, but the sender is the same
    /// (a frame naming a type this document does not define), the repair is the
    /// same (use a defined opcode, or negotiate the extension that means it),
    /// and so is the loss. A pair of sentences has never been an argument for a
    /// pair of ids.
    ///
    /// **`_unregistered` rather than `_forbidden`**, because there is a
    /// registry and this value is not in it. § 11.8 admits new opcodes only by
    /// Standards Action, and each would arrive with an extension to negotiate
    /// it — which is why there is no configurable list here and why the
    /// boundary is the honest answer.
    ///
    /// **The escape is § 5.8's** and it is read at the site: a session whose
    /// `101` accepted an extension may have been given a meaning for the
    /// opcode, and which one is that extension's document's business.
    ///
    /// `error`: this is the one entry in the group where the document says what
    /// the recipient does about it.
    ///
    // cite(RFC 6455 § 5.2): "%x3-7 are reserved for further non-control frames"
    // cite(RFC 6455 § 5.2): "%xB-F are reserved for further control frames"
    // cite(RFC 6455 § 5.2, label: the recipient's answer to an unknown opcode): "If an unknown opcode is received, the receiving endpoint MUST _Fail the WebSocket Connection_."
    WEBSOCKET_FRAME_OPCODE_UNREGISTERED = {
        id: "websocket_frame_opcode_unregistered",
        title: "The opcode is in a reserved range and denotes no frame type",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_6455_5_2_OPCODES],
        strength: Strength::Must,
    }

    /// A control frame carrying more than 125 bytes of payload.
    ///
    /// `_invalid` and not `_malformed`: the length field holds the value
    /// perfectly well, and what refuses it is a constraint past the grammar on
    /// the class the opcode puts the frame in.
    ///
    /// **Separate from the fragmentation entry beside it even though § 5.5
    /// states both in one sentence** — and the document is what separates them.
    /// It says "MUST NOT be fragmented" a second time, in § 5.4's own right;
    /// it says the payload bound once. An operator's repair differs by as much:
    /// an application wrote too large a Ping, or a framer fragmented something
    /// it must not.
    ///
    // cite(RFC 6455 § 5.5): "All control frames MUST have a payload length of 125 bytes or less and MUST NOT be fragmented."
    WEBSOCKET_FRAME_CONTROL_PAYLOAD_INVALID = {
        id: "websocket_frame_control_payload_invalid",
        title: "A control frame carries more payload than its class allows",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_6455_5_5],
        strength: Strength::Must,
    }

    /// A control frame with the FIN bit clear.
    ///
    /// The requirement § 5.5 states in half a sentence, and § 5.4 states again
    /// on its own — which is the reason this is an entry rather than half of
    /// the one above. The reference is § 5.4's, because that is where the
    /// sentence is about nothing else.
    ///
    // cite(RFC 6455 § 5.4): "Control frames themselves MUST NOT be fragmented."
    WEBSOCKET_FRAME_CONTROL_FRAGMENTATION_FORBIDDEN = {
        id: "websocket_frame_control_fragmentation_forbidden",
        title: "A control frame is fragmented",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_6455_5_4],
        strength: Strength::Must,
    }

    /// A Close frame whose payload is exactly one byte.
    ///
    /// **The permission is what makes this measurable.** A Close body is
    /// optional, so an empty payload says nothing; but a body that exists opens
    /// with a two-byte status code, and one byte is too short to be one. The
    /// bound holds under any extension, since the payload is Extension data
    /// followed by Application data and a single byte leaves at most one for
    /// either.
    ///
    // cite(RFC 6455 § 5.5.1): "If there is a body, the first two bytes of the body MUST be a 2-byte unsigned integer (in network byte order) representing a status code with value /code/ defined in Section 7.4."
    WEBSOCKET_FRAME_CLOSE_BODY_MALFORMED = {
        id: "websocket_frame_close_body_malformed",
        title: "A Close body is too short to hold the status code it opens with",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_6455_5_5_1],
        strength: Strength::Must,
    }

    /// A data frame an endpoint sent after its own Close.
    ///
    /// The sentence is about one endpoint, so this reads that endpoint's own
    /// history and says nothing about the peer, which is still owed the other
    /// half of the closing handshake. A session whose Close has aged out of the
    /// bounded event store stops producing the finding — silence, never a false
    /// report.
    ///
    // cite(RFC 6455 § 5.5.1): "The application MUST NOT send any more data frames after sending a Close frame."
    WEBSOCKET_FRAME_DATA_AFTER_CLOSE_FORBIDDEN = {
        id: "websocket_frame_data_after_close_forbidden",
        title: "A data frame follows the same endpoint's Close frame",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_6455_5_5_1],
        strength: Strength::Must,
    }

    /// A continuation frame with no fragmented message open to continue.
    ///
    /// **`_unsolicited` is the ending**, on the reading
    /// [`status_206_unsolicited`](crate::violations::status::STATUS_206_UNSOLICITED)
    /// established: nothing is malformed about the frame, and what is wrong is
    /// that it answers something that was never started. § 5.4's definition of
    /// a fragmented message is what says a continuation only exists inside one.
    ///
    // cite(RFC 6455 § 5.4): "A fragmented message consists of a single frame with the FIN bit clear and an opcode other than 0, followed by zero or more frames with the FIN bit clear and the opcode set to 0, and terminated by a single frame with the FIN bit set and an opcode of 0."
    WEBSOCKET_FRAME_CONTINUATION_UNSOLICITED = {
        id: "websocket_frame_continuation_unsolicited",
        title: "A continuation frame has no fragmented message to continue",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_6455_5_4],
    }

    /// A Text or Binary frame opening a second message while this endpoint's
    /// previous one is still unterminated.
    ///
    /// The prohibition carries its own escape — *unless an extension has been
    /// negotiated that can interpret the interleaving* — so this entry, like
    /// [`WEBSOCKET_FRAME_OPCODE_UNREGISTERED`] and
    /// [`WEBSOCKET_FRAME_RSV_FORBIDDEN`], is only reached where the handshake
    /// is in evidence and accepted nothing.
    ///
    // cite(RFC 6455 § 5.4): "The fragments of one message MUST NOT be interleaved between the fragments of another message unless an extension has been negotiated that can interpret the interleaving."
    WEBSOCKET_FRAME_MESSAGE_INTERLEAVING_FORBIDDEN = {
        id: "websocket_frame_message_interleaving_forbidden",
        title: "A second message opens while a fragmented one is unterminated",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_6455_5_4],
        strength: Strength::Must,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::violations::ViolationDef;

    /// Every entry in the subject, so a new one has to be ranked here on
    /// purpose rather than inherited.
    const ALL: &[&ViolationDef] = &[
        &WEBSOCKET_FRAME_MASK_MISSING,
        &WEBSOCKET_FRAME_MASK_FORBIDDEN,
        &WEBSOCKET_FRAME_RSV_FORBIDDEN,
        &WEBSOCKET_FRAME_RSV_MALFORMED,
        &WEBSOCKET_FRAME_OPCODE_MALFORMED,
        &WEBSOCKET_FRAME_OPCODE_UNREGISTERED,
        &WEBSOCKET_FRAME_CONTROL_PAYLOAD_INVALID,
        &WEBSOCKET_FRAME_CONTROL_FRAGMENTATION_FORBIDDEN,
        &WEBSOCKET_FRAME_CLOSE_BODY_MALFORMED,
        &WEBSOCKET_FRAME_DATA_AFTER_CLOSE_FORBIDDEN,
        &WEBSOCKET_FRAME_CONTINUATION_UNSOLICITED,
        &WEBSOCKET_FRAME_MESSAGE_INTERLEAVING_FORBIDDEN,
    ];

    /// `error` used to mean *this session ends*, and the four entries carrying
    /// it were the four whose sections state the recipient's answer — the old
    /// comment said outright that everything else here "breaks a MUST too and
    /// is ranked by the stated consequence rather than by the strength of the
    /// word."
    ///
    /// Nine of the twelve break a `MUST` addressed to whoever sent the frame,
    /// and they are the nine errors. The other three are the ones RFC 6455
    /// says nothing to a sender about: an opcode or a reserved bit this crate
    /// refuses because nothing defines it, and a continuation with nothing to
    /// continue.
    #[test]
    fn every_entry_quoting_a_must_is_an_error_and_the_other_three_are_not() {
        // The three that quote no sentence about the sender: two values this
        // crate refuses because no opcode or reserved bit can carry them, and a
        // continuation that arrives with nothing to continue.
        let claims_no_sentence = [
            "websocket_frame_opcode_malformed",
            "websocket_frame_rsv_malformed",
            "websocket_frame_continuation_unsolicited",
        ];
        for def in ALL {
            let expected = if claims_no_sentence.contains(&def.id) {
                Severity::Warn
            } else {
                Severity::Error
            };
            assert_eq!(def.default_severity, expected, "{}", def.id);
            assert_eq!(
                def.strength == crate::lint::Strength::Must,
                expected == Severity::Error,
                "{}",
                def.id,
            );
        }
    }

    /// The two entries about the record rather than the wire rank below every
    /// entry that names a peer's response, because no peer ever saw them.
    #[test]
    fn the_entries_about_the_record_rank_below_the_ones_a_peer_answers() {
        for def in [
            &WEBSOCKET_FRAME_RSV_MALFORMED,
            &WEBSOCKET_FRAME_OPCODE_MALFORMED,
        ] {
            assert!(def.default_severity < Severity::Error, "{}", def.id);
        }
    }

    /// Every entry names the sender, the recorded value or the opcode in its
    /// message, so none of them carries one of its own.
    #[test]
    fn every_entry_leaves_its_message_to_the_site() {
        for def in ALL {
            assert!(def.message.is_empty(), "{}", def.id);
        }
    }

    /// One section is referenced twice, under two readings, and the entries
    /// split across them: the bits and the opcode ranges never share a
    /// reference, because a rule declaring one must publish that reference.
    #[test]
    fn the_two_readings_of_section_5_2_stay_apart() {
        assert_eq!(RFC_6455_5_2_RSV_BITS.section, RFC_6455_5_2_OPCODES.section);
        assert_ne!(RFC_6455_5_2_RSV_BITS.note, RFC_6455_5_2_OPCODES.note);
        assert_eq!(WEBSOCKET_FRAME_RSV_FORBIDDEN.spec, &[RFC_6455_5_2_RSV_BITS]);
        assert_eq!(
            WEBSOCKET_FRAME_OPCODE_UNREGISTERED.spec,
            &[RFC_6455_5_2_OPCODES]
        );
    }
}
