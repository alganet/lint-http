// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! WebSocket reserved-bit validation (RFC 6455 § 5.2).
//!
//! One frame at a time, and the whole rule turns on a fact the frame did not
//! use to carry: what the `101` that opened the session accepted in
//! `Sec-WebSocket-Extensions`. § 5.2's MUST is conditional — a reserved bit is
//! zero *unless an extension is negotiated that defines meanings for non-zero
//! values* — so without the handshake this rule would report every
//! `permessage-deflate` frame, which sets RSV1 on the compressed ones. The
//! event carries the answer now (`NegotiatedExtensions`), and the three states
//! it distinguishes are exactly the three verdicts here.

use crate::lint::Violation;
use crate::protocol_event::{
    MessageDirection, NegotiatedExtensions, ProtocolEvent, ProtocolEventHistory, ProtocolEventKind,
};
use crate::rules::ProtocolRule;

pub struct WebsocketFrameRsvBits;

/// The bits, most significant first, under the names the framing section gives
/// them. The packing is the capture's — RSV1 is bit 2 — and this is the only
/// place it is read back into names.
const BITS: [(u8, &str); 3] = [(0b100, "RSV1"), (0b010, "RSV2"), (0b001, "RSV3")];

impl WebsocketFrameRsvBits {
    /// Which reserved bits this frame set, written for a finding.
    fn named(rsv: u8) -> String {
        let set: Vec<&str> = BITS
            .iter()
            .filter(|(mask, _)| rsv & mask != 0)
            .map(|(_, name)| *name)
            .collect();
        set.join(" and ")
    }
}

impl ProtocolRule for WebsocketFrameRsvBits {
    fn id(&self) -> &'static str {
        "websocket_frame_rsv_bits"
    }

    fn check_event(
        &self,
        event: &ProtocolEvent,
        _history: &ProtocolEventHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Option<Violation> {
        let ProtocolEventKind::WebSocketFrame {
            direction,
            rsv,
            extensions,
            ..
        } = &event.kind
        else {
            return None;
        };

        // Zero is what the production generates without a negotiation, and it is
        // what every frame this proxy relays carries: tungstenite's reader
        // refuses a non-zero reserved bit, and the assembled `Message` variants
        // it does return have no header to read one from. So this branch ends
        // the rule for all live traffic, and the findings below are reachable
        // through `lint` over a capture written elsewhere.
        //
        // cite(RFC 6455 § 5.2, label: frame-rsv1 production): "frame-rsv1 = %x0 / %x1 ; 1 bit in length, MUST be 0 unless ; negotiated otherwise"
        if *rsv == 0 {
            return None;
        }

        let sender = match direction {
            MessageDirection::Client => "client",
            MessageDirection::Server => "server",
        };

        // Three bits, and a value needing a fourth is a claim about the record
        // rather than about the wire. The header prints the three as one bit
        // each, so no frame could have carried the value this event holds --
        // the same shape as the sibling rule's opcode above 15, and decided
        // before the negotiation question because no extension can license a
        // bit the header has no room for.
        //
        // cite(RFC 6455 § 5.2): "RSV1, RSV2, RSV3:  1 bit each"
        if *rsv > 0b111 {
            return Some(Violation {
                rule: self.id().into(),
                severity: ctx.severity,
                message: format!(
                    "A WebSocket frame the {sender} sent records the reserved bits as {rsv:#05b}, \
                     and the frame header holds three of them — one bit each — so no frame on any \
                     wire carried this value"
                ),
            });
        }

        // The MUST is conditional, and this is the antecedent. § 5.8 hands the
        // three bits to extensions and requires the negotiation to happen in the
        // opening handshake; § 9.1 makes the *server's* list the one in use. So
        // a session whose `101` accepted no extension has nothing that could
        // give a non-zero bit a meaning, and the sentence closes.
        //
        // `Accepted` is not read further: which extension defines which bit is
        // that extension's document, not this one, and § 9.1 says the parameters
        // supplied with any given extension MUST be defined for that extension.
        // Reporting an RSV1 against `permessage-deflate` would mean this rule
        // deciding what RFC 7692 says.
        //
        // `Unrecorded` is the older capture and the foreign one. Silence there
        // is the honest answer for the same reason the finding below is honest
        // when the handshake is known: the antecedent is not in evidence.
        //
        // cite(RFC 6455 § 5.2): "MUST be 0 unless an extension is negotiated that defines meanings for non-zero values."
        // cite(RFC 6455 § 5.2): "If a nonzero value is received and none of the negotiated extensions defines the meaning of such a nonzero value, the receiving endpoint MUST _Fail the WebSocket Connection_."
        // cite(RFC 6455 § 5.8): "This specification provides opcodes 0x3 through 0x7 and 0xB through 0xF, the "Extension data" field, and the frame-rsv1, frame-rsv2, and frame-rsv3 bits of the frame header for use by extensions."
        if !matches!(extensions, NegotiatedExtensions::NoneAccepted) {
            return None;
        }

        // `Rule::violation` is a trait default on the *transaction* trait; a
        // `ProtocolRule` builds the struct, as every other one in this
        // catalogue does.
        Some(Violation {
            rule: self.id().into(),
            severity: ctx.severity,
            message: format!(
                "A WebSocket frame the {sender} sent has {} set, and the 101 that opened this \
                 session accepted no extension: RFC 6455 §5.2 makes a reserved bit non-zero only \
                 under an extension that defines a meaning for it, and it has the receiving \
                 endpoint fail the connection when none does",
                Self::named(*rsv)
            ),
        })
    }

    fn title(&self) -> Option<&'static str> {
        Some("WebSocket Frame Reserved Bits")
    }

    fn description(&self) -> &'static str {
        "Reports a WebSocket frame whose RSV1, RSV2 or RSV3 bit is set in a session whose opening handshake accepted no extension.\n\n**The requirement is conditional, and the condition is not in the frame.** RFC 6455 §5.2 says each reserved bit *MUST be 0 unless an extension is negotiated that defines meanings for non-zero values*, and — for the other party — *If a nonzero value is received and none of the negotiated extensions defines the meaning of such a nonzero value, the receiving endpoint MUST _Fail the WebSocket Connection_.* §5.8 is what hands the bits to extensions, and it requires the negotiation to happen in the opening handshake. That handshake is an HTTP exchange, and a frame-level rule is handed protocol events rather than transactions — so until the capture carried the answer, the only honest reading of a non-zero bit was *no reading*: `permessage-deflate` (RFC 7692) sets RSV1 on every compressed frame, and a rule reporting the bit alone would report ordinary traffic.\n\n**What changed is the capture, not the sentence.** Each frame event now records what the `101` accepted in `Sec-WebSocket-Extensions`, and §9.1 is why the *server's* field is the whole of the agreement: *The extensions listed by the server in response represent the extensions actually in use for the connection*, and a client *MUST NOT use them unless the server indicates that it wishes to use the extension*. So a `101` carrying no such field settles that nothing can give a non-zero bit a meaning, and the sentence closes.\n\n**Three states, three verdicts.** A handshake that accepted **no** extension is the finding above. A handshake that accepted **one** draws nothing: which bit that extension defines is its own document's business, and deciding it here would mean this rule reading RFC 7692 for RFC 6455. A capture that does **not record** the handshake also draws nothing — every capture written before this field existed, and every one written by something other than this proxy — because the antecedent is then not in evidence in either direction. Silence there is the same decision as silence under an accepted extension, reached for a different reason, and it is why enabling this rule cannot make old captures noisy.\n\n**One finding does not wait for the handshake.** The header prints the three bits as *1 bit each*, so a recorded value above `0b111` is a claim about the record rather than about the wire — no frame header has room for it, and no negotiation could license one. That is the sibling shape of `websocket_frame_opcode_sequence`'s opcode above 15.\n\n**Where these findings come from.** The relay reads frames through tokio-tungstenite, whose parser refuses a non-zero reserved bit before the proxy is handed a message, and whose assembled `Message` variants carry no frame header to read one from. So every finding here is reachable through `lint`, over a capture file written by something other than this proxy — which is a reason to say so, not a reason to soften them: a capture is a record of what was on the wire.\n\n**Not reported: what the bits mean when an extension is negotiated.** Whether the accepted extension actually defines the bit that was set, whether the extension was one the client offered, and whether the `Sec-WebSocket-Extensions` value derives from §9.1's `extension-list` grammar are three other questions; the second is `websocket_handshake_valid`'s and the third is `sec_websocket_extensions_syntax`'s."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 6455",
                section: Some("5.2"),
                url: "https://www.rfc-editor.org/rfc/rfc6455.html#section-5.2",
                note: "Base Framing Protocol — the three reserved bits, their width, the \
                       conditional MUST on the sender and the MUST-fail on the recipient",
            },
            crate::rules::SpecRef {
                spec: "RFC 6455",
                section: Some("5.8"),
                url: "https://www.rfc-editor.org/rfc/rfc6455.html#section-5.8",
                note: "Extensibility — what the reserved bits are reserved for, and that the \
                       negotiation happens in the opening handshake",
            },
            crate::rules::SpecRef {
                spec: "RFC 6455",
                section: Some("9.1"),
                url: "https://www.rfc-editor.org/rfc/rfc6455.html#section-9.1",
                note: "Negotiating Extensions — why the server's response field is the whole of \
                       the agreement, and the client's own field only an offer",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("No extension accepted, and the bits are zero"),
                snippet: "101 Switching Protocols (no Sec-WebSocket-Extensions)\nframe: opcode=1 FIN=1 RSV=000",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("RSV1 under an extension that was accepted — permessage-deflate's compressed frame"),
                snippet: "101 Switching Protocols\nSec-WebSocket-Extensions: permessage-deflate\n\nframe: opcode=1 FIN=1 RSV=100",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("The same bit, with nothing negotiated to give it a meaning"),
                snippet: "101 Switching Protocols (no Sec-WebSocket-Extensions)\nframe: opcode=1 FIN=1 RSV=100",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("A value the three-bit field has no room for"),
                snippet: "101 Switching Protocols (no Sec-WebSocket-Extensions)\nframe: opcode=1 FIN=1 RSV=1000",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected protocol catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_PROTOCOL_RULES)]
static REGISTRATION: &dyn ProtocolRule = &WebsocketFrameRsvBits;

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use rstest::rstest;
    use uuid::Uuid;

    const RULE: WebsocketFrameRsvBits = WebsocketFrameRsvBits;

    fn frame(rsv: u8, extensions: NegotiatedExtensions) -> ProtocolEvent {
        frame_from(MessageDirection::Client, rsv, extensions)
    }

    fn frame_from(
        direction: MessageDirection,
        rsv: u8,
        extensions: NegotiatedExtensions,
    ) -> ProtocolEvent {
        ProtocolEvent {
            timestamp: Utc::now(),
            connection_id: Uuid::new_v4(),
            kind: ProtocolEventKind::WebSocketFrame {
                session_id: Uuid::new_v4(),
                direction,
                fin: true,
                opcode: 1,
                rsv,
                payload_length: 3,
                extensions,
                masked: None,
            },
        }
    }

    fn judge(event: &ProtocolEvent) -> Option<Violation> {
        crate::test_helpers::run_protocol_rule(
            &RULE,
            event,
            &ProtocolEventHistory::new(Vec::new()),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[RULE.id()]),
        )
    }

    /// The bit is set and the handshake accepted nothing that could mean it.
    #[rstest]
    #[case(0b100, "RSV1")]
    #[case(0b010, "RSV2")]
    #[case(0b001, "RSV3")]
    #[case(0b101, "RSV1 and RSV3")]
    #[case(0b111, "RSV1 and RSV2 and RSV3")]
    fn a_reserved_bit_with_no_extension_accepted_is_the_finding(
        #[case] rsv: u8,
        #[case] named: &str,
    ) {
        let v = judge(&frame(rsv, NegotiatedExtensions::NoneAccepted)).expect("violation");
        assert!(v.message.contains(named), "{}", v.message);
        assert!(v.message.contains("accepted no extension"), "{}", v.message);
    }

    /// The same bit under an accepted extension is what `permessage-deflate`
    /// does on every compressed frame. Which bit RFC 7692 defines is RFC 7692's
    /// business, so this rule says nothing.
    #[rstest]
    #[case("permessage-deflate")]
    #[case("permessage-deflate; client_max_window_bits=15")]
    #[case("some-unregistered-thing")]
    fn a_reserved_bit_under_an_accepted_extension_is_not_this_rules_finding(
        #[case] accepted: &str,
    ) {
        let v = judge(&frame(
            0b100,
            NegotiatedExtensions::Accepted(accepted.to_string()),
        ));
        assert!(v.is_none(), "{v:?}");
    }

    /// The capture that does not say. Every event written before the field
    /// existed deserializes to this, so enabling the rule must not turn an old
    /// capture noisy.
    #[test]
    fn an_unrecorded_handshake_leaves_the_antecedent_out_of_evidence() {
        let v = judge(&frame(0b100, NegotiatedExtensions::Unrecorded));
        assert!(v.is_none(), "{v:?}");
    }

    /// And that is what an event written before the field existed deserializes
    /// to — asserted through serde rather than by construction, because the
    /// claim is about the wire format and not about `Default`.
    #[test]
    fn an_event_written_without_the_field_reads_back_as_unrecorded() {
        let json = serde_json::json!({
            "timestamp": Utc::now(),
            "connection_id": Uuid::new_v4(),
            "kind": {
                "type": "web_socket_frame",
                "session_id": Uuid::new_v4(),
                "direction": "client",
                "fin": true,
                "opcode": 1,
                "rsv": 4,
                "payload_length": 3,
            }
        })
        .to_string();
        let event: ProtocolEvent = serde_json::from_str(&json).expect("an older frame event");
        let ProtocolEventKind::WebSocketFrame { extensions, .. } = &event.kind else {
            panic!("a frame event");
        };
        assert_eq!(*extensions, NegotiatedExtensions::Unrecorded);
        assert!(judge(&event).is_none());
    }

    /// Zero is what the production generates, whatever the handshake said.
    #[rstest]
    #[case(NegotiatedExtensions::NoneAccepted)]
    #[case(NegotiatedExtensions::Unrecorded)]
    #[case(NegotiatedExtensions::Accepted("permessage-deflate".to_string()))]
    fn zero_reserved_bits_are_never_a_finding(#[case] extensions: NegotiatedExtensions) {
        assert!(judge(&frame(0, extensions)).is_none());
    }

    /// Three bits, so a fourth is a claim about the record — decided before the
    /// negotiation question, because no extension can license a bit the header
    /// has no room for.
    #[rstest]
    #[case(NegotiatedExtensions::Unrecorded)]
    #[case(NegotiatedExtensions::Accepted("permessage-deflate".to_string()))]
    #[case(NegotiatedExtensions::NoneAccepted)]
    fn a_value_the_field_has_no_room_for_is_a_finding_whatever_was_negotiated(
        #[case] extensions: NegotiatedExtensions,
    ) {
        let v = judge(&frame(0b1000, extensions)).expect("violation");
        assert!(
            v.message
                .contains("no frame on any wire carried this value"),
            "{}",
            v.message
        );
    }

    /// The finding names the endpoint that sent the frame, which is the only
    /// thing distinguishing two identical frames in one session.
    #[rstest]
    #[case(MessageDirection::Client, "the client sent")]
    #[case(MessageDirection::Server, "the server sent")]
    fn the_finding_names_the_sender(#[case] direction: MessageDirection, #[case] expected: &str) {
        let v = judge(&frame_from(
            direction,
            0b100,
            NegotiatedExtensions::NoneAccepted,
        ))
        .expect("violation");
        assert!(v.message.contains(expected), "{}", v.message);
    }

    /// A protocol event of another kind is not this rule's.
    #[test]
    fn another_event_kind_is_not_measured() {
        let event = ProtocolEvent {
            timestamp: Utc::now(),
            connection_id: Uuid::new_v4(),
            kind: ProtocolEventKind::H3StreamOpened { stream_id: 1 },
        };
        assert!(judge(&event).is_none());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "websocket_frame_rsv_bits");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
