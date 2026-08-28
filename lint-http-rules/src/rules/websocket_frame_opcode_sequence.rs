// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! WebSocket frame opcode and frame-sequence validation (RFC 6455 § 5).
//!
//! One frame event at a time, with the frames already seen in the same session
//! available for the questions that are about a sequence. Three groups, in the
//! order a receiving endpoint reaches them: what the opcode *is*, what the class
//! that opcode puts the frame in requires of *this* frame, and what the frames
//! already sent in that direction leave it free to be.
//!
//! **What can reach this rule.** The relay forwards bytes and observes each
//! frame header exactly as the wire spelled it — a reserved opcode, a control
//! frame over 125 bytes or with FIN clear, a one-byte Close body, and every
//! fragmentation shape included — so each of these defects arrives here live,
//! off this proxy's own relay, as well as through `lint` over any capture that
//! recorded frames. The one finding no wire can produce is an opcode above 15:
//! the field is four bits, so that one is a claim about the record itself.

use uuid::Uuid;

use crate::lint::Violation;
use crate::protocol_event::{
    MessageDirection, NegotiatedExtensions, ProtocolEvent, ProtocolEventHistory, ProtocolEventKind,
};
use crate::rules::ProtocolRule;

/// The frame fields this rule reads, lifted out of the event.
///
/// `fin` is here because it is a finding twice over and the destructuring used
/// to drop it into a `..`: a control frame is defined as one that is never
/// fragmented, and a data frame's FIN bit is the whole of what says whether a
/// fragmented message is still open.
struct Frame {
    session_id: Uuid,
    direction: MessageDirection,
    fin: bool,
    opcode: u8,
    payload_length: u64,
    /// What the `101` that opened this session accepted. Three of this rule's
    /// findings have an *unless an extension* clause in their own sentence, and
    /// until the capture carried this they were reported through it.
    extensions: NegotiatedExtensions,
}

impl Frame {
    /// Whether the escape clause the reserved opcodes and § 5.4's interleaving
    /// rule share is in evidence for this frame.
    ///
    /// **Only `Accepted` stands a finding down.** `Unrecorded` is every capture
    /// written before the field existed and every one written elsewhere, and
    /// reading it as *"no extension"* would be inventing evidence in the
    /// direction that reports; reading it as *"some extension"* would silence
    /// findings this rule has always made. It is neither, so the frame is
    /// measured as it was before — which is the only change-free answer for
    /// the captures that exist.
    fn an_extension_was_negotiated(&self) -> bool {
        matches!(self.extensions, NegotiatedExtensions::Accepted(_))
    }
}

impl Frame {
    /// Which endpoint sent it, for the finding. The recorded direction is
    /// relative to the proxy, and both sentences this rule rests a sequence
    /// finding on are about what *one* endpoint has already sent.
    fn sender(&self) -> &'static str {
        match self.direction {
            MessageDirection::Client => "client",
            MessageDirection::Server => "server",
        }
    }
}

pub struct WebsocketFrameOpcodeSequence;

impl WebsocketFrameOpcodeSequence {
    /// What the opcode is — the question ahead of every other one, because an
    /// opcode that names no frame type leaves nothing below it to decide.
    ///
    /// The four-bit field is the first bound. A value above 15 has no wire
    /// spelling at all, so a capture carrying one records something no frame
    /// header could have held; the sentence giving the field a range is in the
    /// registry that indexes it rather than in the framing section, which prints
    /// the width as a bit count and lets the reader do the arithmetic.
    ///
    /// The reserved ranges are the second. The two ranges are two sentences, not
    /// one, and they reserve for two different things — a further *non-control*
    /// frame below 8 and a further *control* frame above 10 — so the finding
    /// says which.
    ///
    /// **The escape, and it is in evidence now.** § 5.8 hands both ranges to
    /// extensions and says the endpoints negotiate any extension during the
    /// opening handshake. That negotiation is `Sec-WebSocket-Extensions` in an
    /// exchange the handshake rules read — and the frame event carries the
    /// `101`'s answer, so a session that accepted an extension stands both
    /// findings down rather than publishing the over-report in
    /// `description()`, which is what this rule did until the capture recorded
    /// it. A capture that does not say is measured as before.
    ///
    /// **And the registry is open.** § 11.8 registers opcodes by Standards
    /// Action, so a value assigned after this was written would land in the same
    /// report. There is no configured list for it: unlike a registry a
    /// deployment can outrun, this one has six assignments, admits new ones only
    /// by Standards Action, and each new one would arrive with an extension to
    /// negotiate it — so the honest answer is the boundary above, not an array
    /// an operator has to keep current.
    // cite(RFC 6455 § 11.8): "The opcode is an integer number between 0 and 15, inclusive."
    // cite(RFC 6455 § 11.8): "WebSocket Opcode numbers are subject to the "Standards Action" IANA registration policy [RFC5226]."
    // cite(RFC 6455 § 5.8): "This specification provides opcodes 0x3 through 0x7 and 0xB through 0xF, the "Extension data" field, and the frame-rsv1, frame-rsv2, and frame-rsv3 bits of the frame header for use by extensions."
    // cite(RFC 6455 § 5.8): "The endpoints of a connection MUST negotiate the use of any extensions during the opening handshake."
    fn opcode_defect(frame: &Frame) -> Option<String> {
        if frame.opcode > 15 {
            return Some(format!(
                "carries the opcode {}, which is outside the range a four-bit opcode field can \
                 hold, so no frame header on any wire carried this value",
                frame.opcode
            ));
        }

        // The escape clause, now in evidence. § 5.8 reserves both ranges *for
        // use by extensions*, and a session whose `101` accepted one is a
        // session where the opcode may have been given a meaning this document
        // does not define -- which is what the two findings below would
        // otherwise deny. Silence here is narrower than the rule used to be and
        // only for the captures that carry the handshake; see
        // `Frame::an_extension_was_negotiated` for why `Unrecorded` is not it.
        if frame.an_extension_was_negotiated() {
            return None;
        }

        // cite(RFC 6455 § 5.2): "If an unknown opcode is received, the receiving endpoint MUST _Fail the WebSocket Connection_."
        // cite(RFC 6455 § 5.2): "%x3-7 are reserved for further non-control frames"
        if (3..=7).contains(&frame.opcode) {
            return Some(format!(
                "carries the opcode {}, which is reserved for further non-control frames and \
                 denotes no frame type this document defines",
                frame.opcode
            ));
        }

        // cite(RFC 6455 § 5.2): "%xB-F are reserved for further control frames"
        if (11..=15).contains(&frame.opcode) {
            return Some(format!(
                "carries the opcode {}, which is reserved for further control frames and denotes \
                 no frame type this document defines",
                frame.opcode
            ));
        }

        None
    }

    /// What the control-frame class requires of one frame.
    ///
    /// The class test is the document's own, and it is a bit rather than a list:
    /// with the reserved opcodes already reported above, the frames reaching
    /// here with the high bit set are 8, 9 and 10.
    ///
    /// The two requirements are one sentence. Reading only as far as its comma
    /// leaves the second half — a control frame is never fragmented — enforced
    /// by nobody, and § 5.4 states it a second time in its own list, which is
    /// what makes the FIN bit measurable here rather than only alongside the
    /// message sequence below.
    ///
    /// The Close body is the third question and the one where a *permission* is
    /// load-bearing. The body is optional, so a Close with no payload is not a
    /// finding; but a body that exists has a fixed first two bytes, and a
    /// one-byte payload is too short to be either. The payload is "Extension
    /// data" followed by "Application data", so a length of 1 leaves at most one
    /// byte for the body under any extension — the finding does not depend on
    /// there being none.
    // cite(RFC 6455 § 5.5): "Control frames are identified by opcodes where the most significant bit of the opcode is 1."
    fn control_frame_defect(frame: &Frame) -> Option<String> {
        if frame.opcode < 8 {
            return None;
        }

        // cite(RFC 6455 § 5.5): "All control frames MUST have a payload length of 125 bytes or less and MUST NOT be fragmented."
        if frame.payload_length > 125 {
            return Some(format!(
                "is a control frame (opcode {}) carrying {} bytes of payload, where a control \
                 frame's payload is 125 bytes or less",
                frame.opcode, frame.payload_length
            ));
        }

        // cite(RFC 6455 § 5.4): "Control frames themselves MUST NOT be fragmented."
        if !frame.fin {
            return Some(format!(
                "is a control frame (opcode {}) with the FIN bit clear, and a control frame is \
                 never fragmented",
                frame.opcode
            ));
        }

        // cite(RFC 6455 § 5.5.1): "The Close frame contains an opcode of 0x8."
        // cite(RFC 6455 § 5.5.1): "The Close frame MAY contain a body (the "Application data" portion of the frame) that indicates a reason for closing"
        // cite(RFC 6455 § 5.5.1): "If there is a body, the first two bytes of the body MUST be a 2-byte unsigned integer (in network byte order) representing a status code with value /code/ defined in Section 7.4."
        if frame.opcode == 8 && frame.payload_length == 1 {
            return Some(
                "is a Close frame carrying a single payload byte, where a Close body that exists \
                 opens with a two-byte status code"
                    .into(),
            );
        }

        None
    }

    /// What the frames already sent in this direction leave this one free to be.
    ///
    /// One walk, newest first, answering both sequence questions at once: has
    /// this endpoint already sent a Close, and is a fragmented message still
    /// open. Session and direction are halves of both — one connection can carry
    /// more than one session, a Close says what its *own* sender may still send
    /// and nothing about the peer still finishing the closing handshake, and the
    /// two endpoints fragment independently of each other.
    ///
    /// Control frames are stepped over rather than counted, because the document
    /// says in as many words that they may sit inside a fragmented message. The
    /// most recent *data* frame is the one whose FIN bit answers the question,
    /// which is why the walk stops recording after it and why an eviction cannot
    /// mislead it: history is newest-first, so the frame it finds is the one
    /// immediately before this.
    ///
    /// A frame in the history whose opcode is above 15 decides neither question:
    /// a value that names no frame type is not evidence a message was opened or
    /// a Close was sent, and the event carrying it has its own finding.
    ///
    /// The after-close scan is the other shape — it reads the whole history, so
    /// a session long enough for its Close to fall out of the bounded store
    /// stops producing the finding. That direction is silence, not a false
    /// report, and the bound is the operator's `max_protocol_event_history`.
    fn sequence_defect(frame: &Frame, history: &ProtocolEventHistory) -> Option<String> {
        // Both sentences below are about what an endpoint may *send as data*, so
        // the class test is the gate for the whole function.
        // cite(RFC 6455 § 5.6): "Data frames (e.g., non-control frames) are identified by opcodes where the most significant bit of the opcode is 0."
        if frame.opcode >= 8 {
            return None;
        }

        let mut closed = false;
        let mut open_fragment: Option<bool> = None;
        for prev in history.iter() {
            let ProtocolEventKind::WebSocketFrame {
                session_id,
                direction,
                fin,
                opcode,
                ..
            } = &prev.kind
            else {
                continue;
            };
            if *session_id != frame.session_id || *direction != frame.direction {
                continue;
            }
            // cite(RFC 6455 § 5.5.1): "The Close frame contains an opcode of 0x8."
            if *opcode == 8 {
                closed = true;
            }
            // A control frame between two fragments is not a break in the
            // message, so the walk steps over every one of them and keeps the
            // most recent *data* frame's FIN bit.
            // cite(RFC 6455 § 5.4): "Control frames (see Section 5.5) MAY be injected in the middle of a fragmented message."
            else if *opcode < 8 && open_fragment.is_none() {
                open_fragment = Some(!*fin);
            }
        }

        // cite(RFC 6455 § 5.5.1): "The application MUST NOT send any more data frames after sending a Close frame."
        // cite(RFC 6455 § 5.1): "A data frame MAY be transmitted by either the client or the server at any time after opening handshake completion and before that endpoint has sent a Close frame (Section 5.5.1)."
        if closed {
            return Some(format!(
                "is a data frame (opcode {}) sent after this same endpoint's Close frame, which \
                 is where what it may send ends",
                frame.opcode
            ));
        }

        // cite(RFC 6455 § 5.2): "%x0 denotes a continuation frame"
        // cite(RFC 6455 § 5.4): "A fragmented message consists of a single frame with the FIN bit clear and an opcode other than 0, followed by zero or more frames with the FIN bit clear and the opcode set to 0, and terminated by a single frame with the FIN bit set and an opcode of 0."
        if frame.opcode == 0 && open_fragment != Some(true) {
            return Some(
                "is a continuation frame, and this endpoint has no fragmented message open for it \
                 to continue"
                    .into(),
            );
        }

        // A second message started before the first was terminated. The escape
        // clause names an extension, and the handshake that would have
        // negotiated one now travels with the frame -- so this finding stands
        // down for a session that accepted one, on the same terms as the
        // reserved opcodes above.
        // cite(RFC 6455 § 5.4): "The fragments of one message MUST NOT be interleaved between the fragments of another message unless an extension has been negotiated that can interpret the interleaving."
        // cite(RFC 6455 § 5.4): "An unfragmented message consists of a single frame with the FIN bit set (Section 5.2) and an opcode other than 0."
        if frame.opcode != 0 && open_fragment == Some(true) && !frame.an_extension_was_negotiated()
        {
            return Some(format!(
                "opens a second message (opcode {}) while this endpoint's previous message is \
                 still fragmented and unterminated",
                frame.opcode
            ));
        }

        None
    }
}

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_6455_5_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 6455",
    section: Some("5.1"),
    url: "https://www.rfc-editor.org/rfc/rfc6455.html#section-5.1",
    note: "Overview: when an endpoint may transmit a data frame",
};
const RFC_6455_5_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 6455",
    section: Some("5.2"),
    url: "https://www.rfc-editor.org/rfc/rfc6455.html#section-5.2",
    note: "Base Framing Protocol, opcode definitions and reserved ranges",
};
const RFC_6455_5_4: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 6455",
    section: Some("5.4"),
    url: "https://www.rfc-editor.org/rfc/rfc6455.html#section-5.4",
    note: "Fragmentation: what a fragmented message is made of",
};
const RFC_6455_5_5: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 6455",
    section: Some("5.5"),
    url: "https://www.rfc-editor.org/rfc/rfc6455.html#section-5.5",
    note: "Control Frames: the class test and its two constraints",
};
const RFC_6455_5_5_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 6455",
    section: Some("5.5.1"),
    url: "https://www.rfc-editor.org/rfc/rfc6455.html#section-5.5.1",
    note: "Close: the body's first two bytes, and the end of what a sender may send",
};
const RFC_6455_5_6: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 6455",
    section: Some("5.6"),
    url: "https://www.rfc-editor.org/rfc/rfc6455.html#section-5.6",
    note: "Data Frames: the class test for the sequence questions",
};
const RFC_6455_5_8: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 6455",
    section: Some("5.8"),
    url: "https://www.rfc-editor.org/rfc/rfc6455.html#section-5.8",
    note: "Extensibility: what the reserved opcodes are reserved for",
};
const RFC_6455_11_8: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 6455",
    section: Some("11.8"),
    url: "https://www.rfc-editor.org/rfc/rfc6455.html#section-11.8",
    note: "WebSocket Opcode Registry: the field's range and its registration policy",
};

impl ProtocolRule for WebsocketFrameOpcodeSequence {
    fn id(&self) -> &'static str {
        "websocket_frame_opcode_sequence"
    }

    fn findings(
        &self,
        event: &ProtocolEvent,
        history: &ProtocolEventHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // Single-finding body behind an Option: `?` ends it early, and the
        // one finding (or none) becomes the vector.
        let finding = || -> Option<Violation> {
            let ProtocolEventKind::WebSocketFrame {
                session_id,
                direction,
                fin,
                opcode,
                payload_length,
                extensions,
                rsv: _,
                masked: _,
            } = &event.kind
            else {
                return None;
            };
            let frame = Frame {
                session_id: *session_id,
                direction: *direction,
                fin: *fin,
                opcode: *opcode,
                payload_length: *payload_length,
                extensions: extensions.clone(),
            };

            // One frame carries one finding, and the order is the order a receiver
            // reaches the questions: an opcode that names no frame type leaves the
            // class questions nothing to be about, and a frame the class already
            // rejects is not yet a member of any sequence.
            let defect = Self::opcode_defect(&frame)
                .or_else(|| Self::control_frame_defect(&frame))
                .or_else(|| Self::sequence_defect(&frame, history))?;

            // Every gate above ends the rule, and reading the configuration is
            // several map probes and a hash of the id — so only a frame about to be
            // reported pays for it.

            Some(self.violation(
                ctx.severity,
                format!("A WebSocket frame the {} sent {}", frame.sender(), defect),
            ))
        };
        Vec::from_iter(finding())
    }

    fn title(&self) -> Option<&'static str> {
        Some("WebSocket Frame Opcode Sequence")
    }

    fn description(&self) -> &'static str {
        "Reads each WebSocket frame the relay observed and asks three groups of questions, in the order a receiving endpoint reaches them.\n\n**What the opcode is.** The opcode field is four bits, so a recorded value above 15 is one no frame header carried (RFC 6455 §11.8 gives the field its range).  Opcodes 3-7 are reserved for further non-control frames and 11-15 for further control frames; a frame carrying one denotes no frame type the document defines, and §5.2 has the receiving endpoint fail the connection on an unknown opcode.\n\n**What the frame's class requires of it.** §5.5 identifies a control frame by the high bit of its opcode and then states two things about it in one sentence: its payload is 125 bytes or less, and it is never fragmented — so a control frame with the FIN bit clear is reported alongside an oversized one.  A Close frame's body is optional, but a body that exists opens with a two-byte status code, so a Close carrying exactly one payload byte is too short to be either.\n\n**What the frames before it allow.** Once an endpoint has sent a Close, §5.5.1 ends what it may send; a data frame — continuation, Text or Binary — following that endpoint's own Close is reported, and the other direction is left alone, since it is still finishing the closing handshake.  §5.4's fragmentation rules supply the rest: a continuation frame with no fragmented message open in that direction has nothing to continue, and a Text or Binary frame arriving while one is still open interleaves two messages.  Control frames are stepped over when answering that question, because §5.4 permits them in the middle of a fragmented message.\n\n**The escape clause, and when it is in evidence.** §5.8 hands opcodes 3-7 and 11-15, and the reserved bits, to extensions negotiated in the opening handshake, and §5.4's interleaving rule has the same escape.  Each frame event now records what the `101` accepted in `Sec-WebSocket-Extensions`, so a session that accepted an extension stands those three findings down — the opcode may have been given a meaning this document does not define, and deciding which is that extension's document's business.  A capture that does not record the handshake — every one written before the field existed, and every one written by something other than this proxy — is measured exactly as before: reading its silence as *no extension* would invent evidence, and reading it as *some extension* would silence findings this rule has always made.  The reserved bits are `websocket_frame_rsv_bits`'s, on the same three-state reading.\n\n**Where these findings come from.** The relay forwards bytes and records each frame as the wire spelled it — reserved opcodes, control frames with FIN clear, and fragmentation included — so these findings arrive live off this proxy's own relay, and equally through `lint` over any capture that recorded frames."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_6455_5_1,
            RFC_6455_5_2,
            RFC_6455_5_4,
            RFC_6455_5_5,
            RFC_6455_5_5_1,
            RFC_6455_5_6,
            RFC_6455_5_8,
            RFC_6455_11_8,
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "# Frames relayed after a WebSocket upgrade, one line each.  The Ping\n# sits inside the client's fragmented message, which RFC 6455 §5.4 permits:\n# Client -> Server: opcode=1 (Text), FIN=0, 42 bytes\n# Client -> Server: opcode=9 (Ping), FIN=1, 0 bytes\n# Client -> Server: opcode=0 (Continuation), FIN=1, 17 bytes\n# Server -> Client: opcode=8 (Close), FIN=1, 2 bytes\n# Client -> Server: opcode=8 (Close), FIN=1, 2 bytes",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(reserved opcode)"),
                snippet: "# Client -> Server: opcode=5, FIN=1, 10 bytes\n# 5 is reserved for further non-control frames (RFC 6455 §5.2)",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(control frame too large)"),
                snippet: "# Client -> Server: opcode=9 (Ping), FIN=1, 200 bytes\n# A control frame's payload is 125 bytes or less (RFC 6455 §5.5)",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(fragmented control frame)"),
                snippet: "# Server -> Client: opcode=10 (Pong), FIN=0, 4 bytes\n# A control frame is never fragmented (RFC 6455 §5.5)",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(continuation with nothing to continue)"),
                snippet: "# Client -> Server: opcode=1 (Text), FIN=1, 12 bytes\n# Client -> Server: opcode=0 (Continuation), FIN=1, 8 bytes\n# The previous message was already terminated (RFC 6455 §5.4)",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(interleaved messages)"),
                snippet: "# Client -> Server: opcode=1 (Text), FIN=0, 12 bytes\n# Client -> Server: opcode=2 (Binary), FIN=1, 30 bytes\n# The Text message was never terminated (RFC 6455 §5.4)",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(data after close)"),
                snippet: "# Client -> Server: opcode=8 (Close), FIN=1, 2 bytes\n# Client -> Server: opcode=1 (Text), FIN=1, 50 bytes\n# A Close ends what that endpoint may send (RFC 6455 §5.5.1)",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_PROTOCOL_RULES)]
static REGISTRATION: &dyn crate::rules::ProtocolRule = &WebsocketFrameOpcodeSequence;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol_event::MessageDirection;
    use crate::protocol_event::{ProtocolEvent, ProtocolEventHistory, ProtocolEventKind};
    use chrono::Utc;
    use rstest::rstest;
    use uuid::Uuid;

    fn make_config() -> crate::config::Config {
        crate::test_helpers::make_test_config_with_enabled_rules(&[
            "websocket_frame_opcode_sequence",
        ])
    }

    fn make_ws_event(
        conn: Uuid,
        session: Uuid,
        direction: MessageDirection,
        opcode: u8,
        payload_length: u64,
    ) -> ProtocolEvent {
        make_ws_frame(conn, session, direction, opcode, payload_length, true)
    }

    fn make_ws_frame(
        conn: Uuid,
        session: Uuid,
        direction: MessageDirection,
        opcode: u8,
        payload_length: u64,
        fin: bool,
    ) -> ProtocolEvent {
        ProtocolEvent {
            timestamp: Utc::now(),
            connection_id: conn,
            kind: ProtocolEventKind::WebSocketFrame {
                session_id: session,
                direction,
                fin,
                opcode,
                rsv: 0,
                extensions: Default::default(),
                masked: None,
                payload_length,
            },
        }
    }

    /// The same frame, in a session whose `101` accepted `accepted`.
    fn with_extensions(mut event: ProtocolEvent, accepted: NegotiatedExtensions) -> ProtocolEvent {
        if let ProtocolEventKind::WebSocketFrame { extensions, .. } = &mut event.kind {
            *extensions = accepted;
        }
        event
    }

    /// History is newest-first, and these fixtures are written oldest-first
    /// because that is the order the frames were on the wire.
    fn history_of(mut events: Vec<ProtocolEvent>) -> ProtocolEventHistory {
        events.reverse();
        ProtocolEventHistory::new(events)
    }

    fn judge(event: &ProtocolEvent, history: &ProtocolEventHistory) -> Option<String> {
        crate::test_helpers::run_protocol_rule(
            &WebsocketFrameOpcodeSequence,
            event,
            history,
            &make_config(),
        )
        .map(|v| v.message)
    }

    #[test]
    fn valid_text_frame_passes() {
        let (conn, session) = (Uuid::new_v4(), Uuid::new_v4());
        let evt = make_ws_event(conn, session, MessageDirection::Client, 1, 42);
        assert_eq!(judge(&evt, &ProtocolEventHistory::empty()), None);
    }

    #[test]
    fn valid_binary_frame_passes() {
        let (conn, session) = (Uuid::new_v4(), Uuid::new_v4());
        let evt = make_ws_event(conn, session, MessageDirection::Server, 2, 1024);
        assert_eq!(judge(&evt, &ProtocolEventHistory::empty()), None);
    }

    #[test]
    fn valid_control_frames_pass() {
        let (conn, session) = (Uuid::new_v4(), Uuid::new_v4());
        for opcode in [8, 9, 10] {
            let evt = make_ws_event(conn, session, MessageDirection::Client, opcode, 10);
            assert_eq!(
                judge(&evt, &ProtocolEventHistory::empty()),
                None,
                "opcode {opcode} should pass"
            );
        }
    }

    #[test]
    fn reserved_opcode_fails() {
        let (conn, session) = (Uuid::new_v4(), Uuid::new_v4());
        for opcode in [3, 4, 5, 6, 7] {
            let evt = make_ws_event(conn, session, MessageDirection::Client, opcode, 0);
            let msg = judge(&evt, &ProtocolEventHistory::empty()).expect("must be reported");
            assert!(
                msg.contains("reserved for further non-control frames"),
                "{msg}"
            );
        }
        for opcode in [11, 12, 13, 14, 15] {
            let evt = make_ws_event(conn, session, MessageDirection::Client, opcode, 0);
            let msg = judge(&evt, &ProtocolEventHistory::empty()).expect("must be reported");
            assert!(msg.contains("reserved for further control frames"), "{msg}");
        }
    }

    /// The registry's own bound on the field, which had a citation in this rule
    /// and no branch under it: 16 and above are values a four-bit field never
    /// held, and only a capture file can carry one.
    #[test]
    fn an_opcode_wider_than_the_field_fails() {
        let (conn, session) = (Uuid::new_v4(), Uuid::new_v4());
        for opcode in [16, 128, 255] {
            let evt = make_ws_event(conn, session, MessageDirection::Client, opcode, 0);
            let msg = judge(&evt, &ProtocolEventHistory::empty()).expect("must be reported");
            assert!(msg.contains("four-bit opcode field"), "{msg}");
        }
    }

    #[test]
    fn control_frame_over_125_bytes_fails() {
        let (conn, session) = (Uuid::new_v4(), Uuid::new_v4());
        let evt = make_ws_event(conn, session, MessageDirection::Client, 9, 126);
        let msg = judge(&evt, &ProtocolEventHistory::empty()).expect("must be reported");
        assert!(msg.contains("125 bytes or less"), "{msg}");
    }

    /// The other half of the sentence carrying the 125-byte bound.
    #[test]
    fn fragmented_control_frame_fails() {
        let (conn, session) = (Uuid::new_v4(), Uuid::new_v4());
        for opcode in [8, 9, 10] {
            let evt = make_ws_frame(conn, session, MessageDirection::Server, opcode, 4, false);
            let msg = judge(&evt, &ProtocolEventHistory::empty()).expect("must be reported");
            assert!(msg.contains("never fragmented"), "{msg}");
        }
    }

    /// A body that exists opens with two bytes; one byte is neither a body nor
    /// its absence. Both spellings the document permits stay silent.
    #[test]
    fn close_frame_body_shorter_than_its_status_code_fails() {
        let (conn, session) = (Uuid::new_v4(), Uuid::new_v4());
        let evt = make_ws_event(conn, session, MessageDirection::Server, 8, 1);
        let msg = judge(&evt, &ProtocolEventHistory::empty()).expect("must be reported");
        assert!(msg.contains("two-byte status code"), "{msg}");

        for permitted in [0, 2, 125] {
            let evt = make_ws_event(conn, session, MessageDirection::Server, 8, permitted);
            assert_eq!(
                judge(&evt, &ProtocolEventHistory::empty()),
                None,
                "{permitted}"
            );
        }
    }

    /// A one-byte *Ping* is fine — the requirement is the Close body's, and the
    /// opcode is part of it.
    #[test]
    fn a_one_byte_ping_is_not_a_short_close_body() {
        let (conn, session) = (Uuid::new_v4(), Uuid::new_v4());
        let evt = make_ws_event(conn, session, MessageDirection::Client, 9, 1);
        assert_eq!(judge(&evt, &ProtocolEventHistory::empty()), None);
    }

    #[test]
    fn data_after_close_fails() {
        let (conn, session) = (Uuid::new_v4(), Uuid::new_v4());
        let history = history_of(vec![make_ws_event(
            conn,
            session,
            MessageDirection::Client,
            8,
            2,
        )]);
        let evt = make_ws_event(conn, session, MessageDirection::Client, 1, 50);
        let msg = judge(&evt, &history).expect("must be reported");
        assert!(
            msg.contains("after this same endpoint's Close frame"),
            "{msg}"
        );
    }

    /// The gap the old `opcode == 0` bail left: a continuation frame is a data
    /// frame, so a Close ends it too.
    #[test]
    fn continuation_after_close_fails() {
        let (conn, session) = (Uuid::new_v4(), Uuid::new_v4());
        let history = history_of(vec![
            make_ws_frame(conn, session, MessageDirection::Client, 1, 10, false),
            make_ws_event(conn, session, MessageDirection::Client, 8, 2),
        ]);
        let evt = make_ws_frame(conn, session, MessageDirection::Client, 0, 5, true);
        let msg = judge(&evt, &history).expect("must be reported");
        assert!(
            msg.contains("after this same endpoint's Close frame"),
            "{msg}"
        );
    }

    /// A Close does not stop that endpoint answering a Ping, and the sentence
    /// says data frames rather than frames.
    #[test]
    fn a_control_frame_after_close_passes() {
        let (conn, session) = (Uuid::new_v4(), Uuid::new_v4());
        let history = history_of(vec![make_ws_event(
            conn,
            session,
            MessageDirection::Client,
            8,
            2,
        )]);
        for opcode in [8, 9, 10] {
            let evt = make_ws_event(conn, session, MessageDirection::Client, opcode, 4);
            assert_eq!(judge(&evt, &history), None, "opcode {opcode}");
        }
    }

    #[test]
    fn data_from_other_direction_after_close_passes() {
        let (conn, session) = (Uuid::new_v4(), Uuid::new_v4());
        let history = history_of(vec![make_ws_event(
            conn,
            session,
            MessageDirection::Client,
            8,
            2,
        )]);
        let evt = make_ws_event(conn, session, MessageDirection::Server, 1, 50);
        assert_eq!(judge(&evt, &history), None);
    }

    /// A second session on the same connection is a second sequence.
    #[test]
    fn a_close_in_another_session_does_not_reach_this_one() {
        let conn = Uuid::new_v4();
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let history = history_of(vec![make_ws_event(conn, a, MessageDirection::Client, 8, 2)]);
        let evt = make_ws_event(conn, b, MessageDirection::Client, 1, 50);
        assert_eq!(judge(&evt, &history), None);
    }

    #[test]
    fn continuation_with_nothing_open_fails() {
        let (conn, session) = (Uuid::new_v4(), Uuid::new_v4());
        // No history at all.
        let evt = make_ws_frame(conn, session, MessageDirection::Client, 0, 5, true);
        let msg = judge(&evt, &ProtocolEventHistory::empty()).expect("must be reported");
        assert!(msg.contains("no fragmented message open"), "{msg}");

        // And a previous message that was already terminated.
        let history = history_of(vec![make_ws_event(
            conn,
            session,
            MessageDirection::Client,
            1,
            12,
        )]);
        let msg = judge(&evt, &history).expect("must be reported");
        assert!(msg.contains("no fragmented message open"), "{msg}");
    }

    /// The document's own worked example: opcode 1 with FIN clear, then 0 with
    /// FIN clear, then 0 with FIN set.
    #[test]
    fn the_documents_three_fragment_example_passes() {
        let (conn, session) = (Uuid::new_v4(), Uuid::new_v4());
        let first = make_ws_frame(conn, session, MessageDirection::Client, 1, 10, false);
        assert_eq!(judge(&first, &ProtocolEventHistory::empty()), None);

        let second = make_ws_frame(conn, session, MessageDirection::Client, 0, 10, false);
        assert_eq!(judge(&second, &history_of(vec![first.clone()])), None);

        let third = make_ws_frame(conn, session, MessageDirection::Client, 0, 4, true);
        assert_eq!(
            judge(&third, &history_of(vec![first.clone(), second.clone()])),
            None
        );

        // And the message after it starts cleanly.
        let next = make_ws_event(conn, session, MessageDirection::Client, 2, 7);
        assert_eq!(judge(&next, &history_of(vec![first, second, third])), None);
    }

    /// Control frames may be injected mid-message, so the walk steps over them
    /// to find the data frame whose FIN bit decides the question.
    #[test]
    fn a_ping_between_fragments_does_not_close_the_message() {
        let (conn, session) = (Uuid::new_v4(), Uuid::new_v4());
        let history = history_of(vec![
            make_ws_frame(conn, session, MessageDirection::Client, 1, 10, false),
            make_ws_event(conn, session, MessageDirection::Client, 9, 0),
        ]);
        let evt = make_ws_frame(conn, session, MessageDirection::Client, 0, 4, true);
        assert_eq!(judge(&evt, &history), None);
    }

    #[test]
    fn a_second_message_started_mid_fragment_fails() {
        let (conn, session) = (Uuid::new_v4(), Uuid::new_v4());
        let history = history_of(vec![make_ws_frame(
            conn,
            session,
            MessageDirection::Client,
            1,
            10,
            false,
        )]);
        for opcode in [1, 2] {
            let evt = make_ws_event(conn, session, MessageDirection::Client, opcode, 30);
            let msg = judge(&evt, &history).expect("must be reported");
            assert!(msg.contains("still fragmented and unterminated"), "{msg}");
        }
    }

    /// A value naming no frame type is not evidence of anything: it neither
    /// opens a message for a continuation to continue nor stands in for a Close.
    #[test]
    fn an_opcode_outside_the_field_decides_no_sequence_question() {
        let (conn, session) = (Uuid::new_v4(), Uuid::new_v4());
        let history = history_of(vec![make_ws_frame(
            conn,
            session,
            MessageDirection::Client,
            200,
            10,
            false,
        )]);

        let continuation = make_ws_frame(conn, session, MessageDirection::Client, 0, 5, true);
        let msg = judge(&continuation, &history).expect("must be reported");
        assert!(msg.contains("no fragmented message open"), "{msg}");

        let text = make_ws_event(conn, session, MessageDirection::Client, 1, 5);
        assert_eq!(judge(&text, &history), None);
    }

    /// The two endpoints fragment independently: an open message one way says
    /// nothing about a message the other way.
    #[test]
    fn fragmentation_state_is_per_direction() {
        let (conn, session) = (Uuid::new_v4(), Uuid::new_v4());
        let history = history_of(vec![make_ws_frame(
            conn,
            session,
            MessageDirection::Client,
            1,
            10,
            false,
        )]);
        let evt = make_ws_event(conn, session, MessageDirection::Server, 1, 30);
        assert_eq!(judge(&evt, &history), None);
    }

    /// The finding names the endpoint the recorded direction is about.
    #[test]
    fn the_finding_names_the_sender() {
        let (conn, session) = (Uuid::new_v4(), Uuid::new_v4());
        let client = make_ws_event(conn, session, MessageDirection::Client, 5, 0);
        assert!(judge(&client, &ProtocolEventHistory::empty())
            .expect("must be reported")
            .starts_with("A WebSocket frame the client sent"));

        let server = make_ws_event(conn, session, MessageDirection::Server, 5, 0);
        assert!(judge(&server, &ProtocolEventHistory::empty())
            .expect("must be reported")
            .starts_with("A WebSocket frame the server sent"));
    }

    #[test]
    fn non_websocket_event_ignored() {
        let evt = ProtocolEvent {
            timestamp: Utc::now(),
            connection_id: Uuid::new_v4(),
            kind: ProtocolEventKind::H3GoawayReceived {
                stream_id: None,
                direction: MessageDirection::Client,
            },
        };
        assert_eq!(judge(&evt, &ProtocolEventHistory::empty()), None);
    }

    /// § 5.8 reserves both opcode ranges *for use by extensions*, and the
    /// handshake that would have negotiated one now travels with the frame.
    /// Three fixtures, one per finding that has the escape clause in its own
    /// sentence, each reported under `NoneAccepted` and silent under
    /// `Accepted` — so neither half of the gate can be deleted with these
    /// green.
    #[rstest]
    #[case(3)]
    #[case(7)]
    #[case(11)]
    #[case(15)]
    fn a_reserved_opcode_stands_down_under_an_accepted_extension(#[case] opcode: u8) {
        let (conn, session) = (Uuid::new_v4(), Uuid::new_v4());
        let event = make_ws_event(conn, session, MessageDirection::Client, opcode, 3);
        let empty = ProtocolEventHistory::new(Vec::new());

        let reported = judge(
            &with_extensions(event.clone(), NegotiatedExtensions::NoneAccepted),
            &empty,
        );
        assert!(
            reported.is_some(),
            "opcode {opcode} with nothing negotiated"
        );

        let silent = judge(
            &with_extensions(
                event.clone(),
                NegotiatedExtensions::Accepted("x-frame-thing".into()),
            ),
            &empty,
        );
        assert!(silent.is_none(), "opcode {opcode}: {silent:?}");

        // The capture that does not say is measured exactly as it was before
        // the field existed, which is what keeps this change from silencing an
        // old capture file.
        assert!(
            judge(&event, &empty).is_some(),
            "opcode {opcode} unrecorded"
        );
    }

    /// § 5.4's interleaving MUST carries the same *unless an extension* clause.
    #[test]
    fn interleaving_stands_down_under_an_accepted_extension() {
        let (conn, session) = (Uuid::new_v4(), Uuid::new_v4());
        let opener = make_ws_frame(conn, session, MessageDirection::Client, 1, 3, false);
        let second = make_ws_frame(conn, session, MessageDirection::Client, 2, 3, true);
        let history = history_of(vec![opener]);

        let reported = judge(
            &with_extensions(second.clone(), NegotiatedExtensions::NoneAccepted),
            &history,
        );
        assert!(
            reported.is_some_and(|m| m.contains("opens a second message")),
            "the finding this case exists for"
        );

        let silent = judge(
            &with_extensions(
                second.clone(),
                NegotiatedExtensions::Accepted("x-interleave".into()),
            ),
            &history,
        );
        assert!(silent.is_none(), "{silent:?}");
        assert!(
            judge(&second, &history).is_some(),
            "unrecorded is unchanged"
        );
    }

    /// The findings with no escape clause are unmoved by the negotiation: an
    /// extension is licensed to define a reserved opcode, not to fragment a
    /// control frame or to send data after a Close.
    #[test]
    fn a_finding_whose_sentence_has_no_escape_clause_is_not_gated() {
        let (conn, session) = (Uuid::new_v4(), Uuid::new_v4());
        let oversized = make_ws_event(conn, session, MessageDirection::Client, 9, 126);
        let empty = ProtocolEventHistory::new(Vec::new());
        let v = judge(
            &with_extensions(
                oversized,
                NegotiatedExtensions::Accepted("permessage-deflate".into()),
            ),
            &empty,
        );
        assert!(
            v.is_some_and(|m| m.contains("125")),
            "the control-frame cap"
        );
    }
}
