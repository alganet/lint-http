// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! WebSocket masking validation (RFC 6455 § 5.1).
//!
//! Two MUSTs about one bit, and which one a frame is measured against is
//! decided entirely by who sent it: a client masks every frame, a server masks
//! none. Both are unconditional — unlike the reserved bits next door, no
//! extension can license either — so the whole of this rule is the MASK bit
//! and the direction, and the only reason a frame goes unmeasured is that the
//! capture did not record the bit.

use crate::lint::Violation;
use crate::protocol_event::{
    MessageDirection, ProtocolEvent, ProtocolEventHistory, ProtocolEventKind,
};
use crate::rules::ProtocolRule;

pub struct WebsocketFrameMasking;

impl ProtocolRule for WebsocketFrameMasking {
    fn id(&self) -> &'static str {
        "websocket_frame_masking"
    }

    fn findings(
        &self,
        event: &ProtocolEvent,
        _history: &ProtocolEventHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // Single-finding body behind an Option: `?` ends it early, and the
        // one finding (or none) becomes the vector.
        let finding = || -> Option<Violation> {
            let ProtocolEventKind::WebSocketFrame {
                direction, masked, ..
            } = &event.kind
            else {
                return None;
            };

            // `None` is *not recorded*, and it is the whole of what this rule
            // declines. An assembled message carries no frame header for the bit to
            // come from, and every event written before the field existed reads
            // back as this. Treating it as `false` would report every capture that
            // predates the field — and *"the client did not mask"* is a finding
            // about the wire, not about the record.
            let masked = (*masked)?;

            // The two sentences are one sentence apart in the section and they are
            // exact opposites, so the direction picks which one applies and there is
            // no frame both reach. `MessageDirection` is the sender's role on the
            // observed connection, which is the grammatical subject of each.
            //
            // Neither has an escape clause. § 5.8 hands extensions the reserved
            // bits and the reserved opcodes and says nothing about the MASK bit, so
            // unlike its neighbour this rule does not read the handshake — the
            // parenthetical *"(These rules might be relaxed in a future
            // specification.)"* is about a future document, not about a negotiation
            // this one permits.
            //
            // cite(RFC 6455 § 5.1): "To avoid confusing network intermediaries (such as intercepting proxies) and for security reasons that are further discussed in Section 10.3, a client MUST mask all frames that it sends to the server (see Section 5.3 for further details)."
            // cite(RFC 6455 § 5.1): "A server MUST NOT mask any frames that it sends to the client."
            let defect = match (direction, masked) {
                (MessageDirection::Client, false) => {
                    // The consequence is the recipient's, and it is a MUST too: an
                    // unmasked frame from a client does not merely violate a
                    // sentence, it ends the connection at a conforming server.
                    //
                    // cite(RFC 6455 § 5.1): "The server MUST close the connection upon receiving a frame that is not masked."
                    "the client sent an unmasked frame: RFC 6455 §5.1 has a client mask all frames it \
                     sends to the server, whether or not the connection is running over TLS, and a \
                     conforming server must close the connection on receiving one"
                }
                (MessageDirection::Server, true) => {
                    // cite(RFC 6455 § 5.1): "A client MUST close a connection if it detects a masked frame."
                    "the server sent a masked frame: RFC 6455 §5.1 has a server mask none of the \
                     frames it sends to the client, and a conforming client must close the connection \
                     on detecting one"
                }
                _ => return None,
            };

            Some(self.violation(ctx.severity, format!("A WebSocket frame where {defect}")))
        };
        Vec::from_iter(finding())
    }

    fn title(&self) -> Option<&'static str> {
        Some("WebSocket Frame Masking")
    }

    fn description(&self) -> &'static str {
        "Reports a client frame that is not masked, and a server frame that is.\n\n**Two MUSTs about one bit, and the sender decides which applies.** RFC 6455 §5.1: *a client MUST mask all frames that it sends to the server* — for the reason the same sentence gives, that an unmasked payload confuses network intermediaries such as intercepting proxies (§10.3 is the attack) — and, three sentences later, *A server MUST NOT mask any frames that it sends to the client.* They are exact opposites, so no frame is measured against both. Each has a recipient's MUST beside it: a server *MUST close the connection upon receiving a frame that is not masked*, and a client *MUST close a connection if it detects a masked frame*, which is why the findings say what the peer is required to do about it.\n\n**Neither MUST has an escape clause.** The reserved bits next door are zero *unless an extension is negotiated*, and `websocket_frame_rsv_bits` reads the handshake for exactly that reason; §5.8 hands extensions the reserved bits, the reserved opcodes and the Extension data field, and says nothing about the MASK bit. §5.1's own parenthetical — *(These rules might be relaxed in a future specification.)* — is about a future document rather than about anything this one lets two endpoints agree, so this rule does not read the negotiation at all.\n\n**A frame whose MASK bit was not recorded is not measured.** The bit is `None` unless the capture read a frame header: tokio-tungstenite hands the relay assembled messages, which have no header, so only the raw-frame path answers it. Every event written before the field existed reads back as `None` too. Reading that as *not masked* would turn every such record into a finding against a client — a claim about the wire made from a gap in the record, which is the one direction that must not be guessed.\n\n**Where these findings come from.** The relay reads frames through tokio-tungstenite, which enforces both sentences before the proxy is handed a message: tungstenite 0.30.0 returns `ProtocolError::UnmaskedFrameFromClient` from its frame reader on the `Role::Server` side (`protocol/frame/mod.rs`) and `ProtocolError::MaskedFrameFromServer` from the `Role::Client` side (`protocol/mod.rs`). So these findings are reachable through `lint`, over capture files written by something other than this proxy — a capture is a record of what was on the wire, and this is the rule that reads it.\n\n**Not reported: the masking key itself.** §5.3 has the client pick a *fresh masking key* per frame, derived from a *strong source of entropy*, and unpredictable from the previous one — the key is not recorded, and unpredictability is not a property of one observation anyway. Nor is any payload unmasked and re-checked: the capture holds the message the relay assembled, not the octets as framed."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 6455",
                section: Some("5.1"),
                url: "https://www.rfc-editor.org/rfc/rfc6455.html#section-5.1",
                note: "Overview — both masking MUSTs, the reason the client's exists, and the two \
                       recipient MUSTs that say what a conforming peer does about a breach",
            },
            crate::rules::SpecRef {
                spec: "RFC 6455",
                section: Some("5.2"),
                url: "https://www.rfc-editor.org/rfc/rfc6455.html#section-5.2",
                note: "Base Framing Protocol — the MASK bit itself: what it means, and that a \
                       masking key is present exactly when it is set",
            },
            crate::rules::SpecRef {
                spec: "RFC 6455",
                section: Some("5.3"),
                url: "https://www.rfc-editor.org/rfc/rfc6455.html#section-5.3",
                note: "Client-to-Server Masking — the key's own requirements, which a capture \
                       holding no key cannot measure",
            },
            crate::rules::SpecRef {
                spec: "RFC 6455",
                section: Some("10.3"),
                url: "https://www.rfc-editor.org/rfc/rfc6455.html#section-10.3",
                note: "Attacks On Infrastructure (Masking) — why the client's MUST is there, and \
                       why an intercepting proxy is the party it protects",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("The two directions, each as its own sentence requires"),
                snippet: "client -> server: opcode=1 FIN=1 MASK=1\nserver -> client: opcode=1 FIN=1 MASK=0",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("A client frame with the bit clear — the server must close the connection"),
                snippet: "client -> server: opcode=1 FIN=1 MASK=0",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("A server frame with the bit set — the client must close the connection"),
                snippet: "server -> client: opcode=1 FIN=1 MASK=1",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected protocol catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_PROTOCOL_RULES)]
static REGISTRATION: &dyn ProtocolRule = &WebsocketFrameMasking;

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use rstest::rstest;
    use uuid::Uuid;

    const RULE: WebsocketFrameMasking = WebsocketFrameMasking;

    fn frame(direction: MessageDirection, masked: Option<bool>) -> ProtocolEvent {
        ProtocolEvent {
            timestamp: Utc::now(),
            connection_id: Uuid::new_v4(),
            kind: ProtocolEventKind::WebSocketFrame {
                session_id: Uuid::new_v4(),
                direction,
                fin: true,
                opcode: 1,
                rsv: 0,
                payload_length: 3,
                extensions: Default::default(),
                masked,
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

    /// The two sentences, each against the direction it is about.
    #[rstest]
    #[case(MessageDirection::Client, true, false)]
    #[case(MessageDirection::Client, false, true)]
    #[case(MessageDirection::Server, false, false)]
    #[case(MessageDirection::Server, true, true)]
    fn the_sender_decides_which_sentence_applies(
        #[case] direction: MessageDirection,
        #[case] masked: bool,
        #[case] expect_violation: bool,
    ) {
        let v = judge(&frame(direction, Some(masked)));
        assert_eq!(
            v.is_some(),
            expect_violation,
            "{direction:?} {masked}: {v:?}"
        );
    }

    /// Each finding names the sender and what the *peer* is required to do,
    /// which is the half of §5.1 an operator acts on.
    #[test]
    fn the_client_finding_names_the_servers_obligation() {
        let v = judge(&frame(MessageDirection::Client, Some(false))).expect("violation");
        assert!(
            v.message.contains("the client sent an unmasked frame"),
            "{}",
            v.message
        );
        assert!(
            v.message
                .contains("conforming server must close the connection"),
            "{}",
            v.message
        );
    }

    #[test]
    fn the_server_finding_names_the_clients_obligation() {
        let v = judge(&frame(MessageDirection::Server, Some(true))).expect("violation");
        assert!(
            v.message.contains("the server sent a masked frame"),
            "{}",
            v.message
        );
        assert!(
            v.message
                .contains("conforming client must close the connection"),
            "{}",
            v.message
        );
    }

    /// The bit that was never recorded is not the bit that was clear. Both
    /// directions, because reading `None` as `false` would report one of them
    /// and reading it as `true` would report the other.
    #[rstest]
    #[case(MessageDirection::Client)]
    #[case(MessageDirection::Server)]
    fn a_frame_whose_mask_bit_was_not_recorded_is_not_measured(
        #[case] direction: MessageDirection,
    ) {
        let v = judge(&frame(direction, None));
        assert!(v.is_none(), "{v:?}");
    }

    /// And that is what an event written before the field existed deserializes
    /// to — asserted through serde, because the claim is about the wire format
    /// rather than about `Default`.
    #[test]
    fn an_event_written_without_the_field_reads_back_as_not_recorded() {
        let json = serde_json::json!({
            "timestamp": Utc::now(),
            "connection_id": Uuid::new_v4(),
            "kind": {
                "type": "web_socket_frame",
                "session_id": Uuid::new_v4(),
                "direction": "client",
                "fin": true,
                "opcode": 1,
                "rsv": 0,
                "payload_length": 3,
            }
        })
        .to_string();
        let event: ProtocolEvent = serde_json::from_str(&json).expect("an older frame event");
        let ProtocolEventKind::WebSocketFrame { masked, .. } = &event.kind else {
            panic!("a frame event");
        };
        assert_eq!(*masked, None);
        assert!(judge(&event).is_none());
    }

    /// No extension can license either sentence, so the handshake this rule's
    /// neighbour reads changes nothing here.
    #[rstest]
    #[case(crate::protocol_event::NegotiatedExtensions::NoneAccepted)]
    #[case(crate::protocol_event::NegotiatedExtensions::Unrecorded)]
    #[case(crate::protocol_event::NegotiatedExtensions::Accepted("permessage-deflate".to_string()))]
    fn the_negotiated_extensions_do_not_reach_this_sentence(
        #[case] extensions: crate::protocol_event::NegotiatedExtensions,
    ) {
        let mut event = frame(MessageDirection::Client, Some(false));
        if let ProtocolEventKind::WebSocketFrame { extensions: e, .. } = &mut event.kind {
            *e = extensions;
        }
        assert!(judge(&event).is_some());
    }

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
        crate::test_helpers::enable_rule(&mut cfg, "websocket_frame_masking");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
