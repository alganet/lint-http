// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! WebSocket upgrade handshake and bidirectional frame relay.
//!
//! The module splits along its seams: detection and the extension-negotiation
//! surface live here, the upgrade handshake in [`handshake`], and the post-101
//! frame relay in [`relay`].

use hyper::Request;

use super::hop_by_hop::parse_connection_tokens;

mod frame;
mod handshake;
mod observer;
mod relay;

pub(super) use handshake::{handle_websocket_upgrade, WsUpgradeRequest};

/// Check if a request is a WebSocket upgrade request.
///
/// A WebSocket handshake requires `Connection: Upgrade` (as a distinct token,
/// possibly alongside others) and an `Upgrade` list containing `websocket`.
///
/// Both sentences say "include", not "equal", so both checks are membership
/// tests -- `Connection: keep-alive, Upgrade` is a valid handshake, and so is
/// `Upgrade: websocket, h2c`: a client may offer several protocols in
/// preference order and `websocket` among them is an offer this proxy can
/// serve. The `Upgrade` field is read through the same list reader the rules
/// use (joined across however many lines carry it), so the proxy routes
/// exactly the handshakes the rules would lint as handshakes. The keyword and
/// the token are matched case-insensitively, which the document establishes
/// elsewhere for each field rather than here.
///
// cite(RFC 6455 § 4.1): "The request MUST contain an |Upgrade| header field whose value MUST include the "websocket" keyword."
// cite(RFC 6455 § 4.1): "The request MUST contain a |Connection| header field whose value MUST include the "Upgrade" token."
pub(super) fn is_websocket_upgrade<B>(req: &Request<B>) -> bool {
    let connection_tokens = parse_connection_tokens(req.headers().get(hyper::header::CONNECTION));
    let has_upgrade = connection_tokens.contains("upgrade");
    let is_websocket =
        crate::helpers::headers::combined_field_value_as_written(req.headers(), "upgrade")
            .is_some_and(|upgrade| {
                crate::helpers::list::list_members(&upgrade)
                    .any(|m| m.eq_ignore_ascii_case("websocket"))
            });
    has_upgrade && is_websocket
}

/// What a `101` settled about extensions, read from the response and not from
/// the offer.
///
/// **Presence is the whole decision, and that is why the value is not parsed
/// here.** RFC 6455 § 9.1 makes the server's list the extensions in use, and a
/// client's own field only an offer it may not act on — so a `101` with no such
/// field is the connection's answer that nothing was accepted, which is what
/// lets a frame rule read the reserved bits and opcodes at all. A `101` that
/// carries the field stands those findings down whatever it holds: which
/// extension defines which bit is that extension's document's business.
///
/// **An unreadable value is still a field.** Reading it through a UTF-8 decoder
/// would turn a `Sec-WebSocket-Extensions` carrying `obs-text` into a handshake
/// that accepted nothing — a claim about the exchange, and the one direction
/// that *licenses* findings. The shared as-written reader gives one `char` per
/// octet and joins the lines the way § 5.2 does, so the record holds what the
/// server wrote.
///
/// The absent case is `NoneAccepted` and never `Unrecorded`: this proxy watched
/// the handshake, so it knows a difference a capture written elsewhere cannot
/// state.
///
// cite(RFC 6455 § 9.1): "The extensions listed by the server in response represent the extensions actually in use for the connection."
fn accepted_extensions(headers: &hyper::HeaderMap) -> crate::protocol_event::NegotiatedExtensions {
    use crate::protocol_event::NegotiatedExtensions;
    match crate::helpers::headers::combined_field_value_as_written(
        headers,
        "sec-websocket-extensions",
    ) {
        Some(value) => NegotiatedExtensions::Accepted(value),
        None => NegotiatedExtensions::NoneAccepted,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use rstest::rstest;

    /// The one line that turns a `101` into the fact a frame rule reads.
    ///
    /// The absent case is the load-bearing one: it says *the server accepted
    /// nothing*, which is what licenses `websocket_frame_rsv_bits` to
    /// report a reserved bit at all. The `obs-text` case is the mirror — a
    /// field that is there and unreadable must not become "accepted nothing",
    /// or an unreadable handshake would start licensing findings.
    #[test]
    fn accepted_extensions_reads_the_response_field() {
        use crate::protocol_event::NegotiatedExtensions;
        use hyper::header::{HeaderName, HeaderValue};

        let name = HeaderName::from_static("sec-websocket-extensions");

        let mut none = hyper::HeaderMap::new();
        none.insert(
            hyper::header::UPGRADE,
            HeaderValue::from_static("websocket"),
        );
        assert_eq!(
            accepted_extensions(&none),
            NegotiatedExtensions::NoneAccepted
        );

        let mut one = hyper::HeaderMap::new();
        one.insert(name.clone(), HeaderValue::from_static("permessage-deflate"));
        assert_eq!(
            accepted_extensions(&one),
            NegotiatedExtensions::Accepted("permessage-deflate".into())
        );

        // Several field lines in one section are one value.
        let mut two = hyper::HeaderMap::new();
        two.append(name.clone(), HeaderValue::from_static("foo"));
        two.append(name.clone(), HeaderValue::from_static("bar; baz=2"));
        assert_eq!(
            accepted_extensions(&two),
            NegotiatedExtensions::Accepted("foo,bar; baz=2".into())
        );

        let mut obs = hyper::HeaderMap::new();
        obs.insert(
            name,
            HeaderValue::from_bytes(&[0xff]).expect("obs-text is a field-content"),
        );
        assert!(
            matches!(accepted_extensions(&obs), NegotiatedExtensions::Accepted(_)),
            "an unreadable value is still a field the server sent"
        );
    }

    #[test]
    fn is_websocket_upgrade_detects_valid_upgrade() {
        let req = Request::builder()
            .method("GET")
            .uri("http://example.com/ws")
            .header("connection", "Upgrade")
            .header("upgrade", "websocket")
            .body(Full::new(Bytes::new()).boxed())
            .unwrap();
        assert!(is_websocket_upgrade(&req));
    }

    #[test]
    fn is_websocket_upgrade_case_insensitive() {
        let req = Request::builder()
            .method("GET")
            .uri("http://example.com/ws")
            .header("connection", "upgrade")
            .header("upgrade", "WebSocket")
            .body(Full::new(Bytes::new()).boxed())
            .unwrap();
        assert!(is_websocket_upgrade(&req));
    }

    #[rstest]
    #[case(Some("keep-alive"), Some("websocket"), false)]
    #[case(Some("Upgrade"), None, false)]
    #[case(None, Some("websocket"), false)]
    #[case(None, None, false)]
    #[case(Some("Upgrade"), Some("h2c"), false)]
    // Connection contains "upgrade" only as a substring of another token, and
    // RFC 9110 §7.6.1 makes Connection a list of tokens, not a string to search.
    // The sentence is cited where the splitting happens, in `parse_connection_tokens`.
    #[case(Some("super-upgrade"), Some("websocket"), false)]
    #[case(Some("upgrades"), Some("websocket"), false)]
    // Upgrade is a list too, and § 4.1 says "include": `websocket` among other
    // offered protocols is a handshake this proxy can serve, whichever position
    // it holds. A keyword that merely contains "websocket" is not a member.
    #[case(Some("Upgrade"), Some("websocket, h2c"), true)]
    #[case(Some("Upgrade"), Some("h2c, websocket"), true)]
    #[case(Some("Upgrade"), Some("websockets"), false)]
    fn is_websocket_upgrade_negative(
        #[case] connection: Option<&str>,
        #[case] upgrade: Option<&str>,
        #[case] expected: bool,
    ) {
        let mut builder = Request::builder()
            .method("GET")
            .uri("http://example.com/ws");
        if let Some(c) = connection {
            builder = builder.header("connection", c);
        }
        if let Some(u) = upgrade {
            builder = builder.header("upgrade", u);
        }
        let req = builder.body(Full::new(Bytes::new()).boxed()).unwrap();
        assert_eq!(is_websocket_upgrade(&req), expected);
    }

    /// An `Upgrade` list split across field lines is one list; the membership
    /// test reads the joined value the way the rules do.
    #[test]
    fn is_websocket_upgrade_reads_a_multi_line_upgrade_field() {
        let req = Request::builder()
            .method("GET")
            .uri("http://example.com/ws")
            .header("connection", "Upgrade")
            .header("upgrade", "h2c")
            .header("upgrade", "websocket")
            .body(Full::new(Bytes::new()).boxed())
            .unwrap();
        assert!(is_websocket_upgrade(&req));
    }
}
