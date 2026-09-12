// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Sec-WebSocket-Protocol` defects — what a subprotocol list says beyond its
//! grammar.
//!
//! The spelling is borrowed and § 4.1 says so twice over: the alphabet the
//! sentence spells out — U+0021 to U+007E less the separators — is `tchar`, and
//! the ABNF beside it writes `1#token` in one word. So an octet no `token`
//! admits, a member written blank and a value naming nothing are the
//! [`token`](crate::violations::token) and [`list`](crate::violations::list)
//! subjects', on both sides of the exchange.
//!
//! **What is left is what the list is, rather than how it is written.** § 4.1
//! item 10 asks the client's names to be *unique strings*, and § 5.6.1.1 says
//! nothing about a set: a list may repeat a member and still be a list. That is
//! this subject's first entry, and the comparison behind it is of what was
//! written — this document folds case where it means to, saying so in as many
//! words for the two fields where it does, and saying nothing of the kind here.
//!
//! **The response's half of the field is the same subject, and it is two more
//! entries.** § 4.3 gives the server `Sec-WebSocket-Protocol-Server = token`
//! against the client's `1#token`, so the direction that carries a list is the
//! one whose emptiness the list owns; what § 4.2.2 adds are two sentences no
//! production carries, that the empty string is not a legal value and that the
//! name has to be one the client offered. Both are the field's own and both are
//! declared by `websocket_handshake_valid`, which is the rule that holds the
//! request beside the response and so the only one able to ask the second.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;
use crate::violations::sec_websocket_key::RFC_6455_4_1;

/// The section a server's half of the handshake is written from, and the one
/// that says the two things about this field its grammar does not.
///
/// `websocket_handshake_valid` imports it back rather than keeping the equal
/// copy it had: two definitions of one section would pass
/// `every_violation_spec_is_declared_by_its_rule` today and drift apart on the
/// first edit to either.
pub const RFC_6455_4_2_2: SpecRef = SpecRef {
    spec: "RFC 6455",
    section: Some("4.2.2"),
    url: "https://www.rfc-editor.org/rfc/rfc6455.html#section-4.2.2",
    note: "Sending the Server's Opening Handshake — what a server sends if it accepts, the five things it sends instead if it does not, and how `Sec-WebSocket-Accept`, `/subprotocol/` and `/extensions/` are derived from the request",
};

defects! {
    /// The same subprotocol name written twice in one request's list.
    ///
    /// Nothing about the grammar objects — `1#token` counts members and does
    /// not compare them — so the requirement is item 10's own, and it is about
    /// the *set* the list stands for: a client's names are ordered by
    /// preference, and a name preferred twice states nothing a server can act
    /// on that the first mention did not.
    ///
    /// `warn`. The handshake completes: a server picks one name it is willing
    /// to speak, and a repeat leaves that choice exactly where it was. What is
    /// wrong is the value rather than the outcome.
    ///
    /// The comparison is of the octets as written. This document folds case
    /// where it means to — `Connection`'s token and `Upgrade`'s keyword are
    /// each *treated as an ASCII case-insensitive value* in as many words — and
    /// says nothing of the kind for these names, so `chat` and `Chat` are two
    /// strings and two subprotocols.
    ///
    // cite(RFC 6455 § 4.1): "The elements that comprise this value MUST be non-empty strings with characters in the range U+0021 to U+007E not including separator characters as defined in [RFC2616] and MUST all be unique strings."
    SEC_WEBSOCKET_PROTOCOL_DUPLICATED = {
        id: "sec_websocket_protocol_duplicated",
        title: "Sec-WebSocket-Protocol names one subprotocol twice",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_6455_4_1],
    }

    /// The server's field written with nothing in it.
    ///
    /// **The response's emptiness is the field's where the request's is the
    /// list's**, and one sentence is the whole of the difference. A client
    /// writes `1#token`, so an element with nothing in it and a value naming no
    /// element at all are arithmetic on a production and belong to
    /// [`list`](crate::violations::list). A server writes one `token`, which
    /// has a floor of its own — but § 4.2.2 does not leave it at the floor: it
    /// says in as many words that the empty string *is not the same as the null
    /// value* here and is not legal. That distinction is what
    /// [`token_empty`](crate::violations::token) cannot carry, since a token
    /// with no characters in it is the same defect wherever it is written and
    /// this one is only a defect in a field whose absence means something.
    ///
    /// `error`. Absence is how a server says it agreed to no subprotocol, and
    /// the sentence exists to stop a reader taking this for that: the two sides
    /// come out of the handshake without agreeing on whether a subprotocol is
    /// in use, and a client reading the field at all finds it naming nothing it
    /// offered.
    ///
    // cite(RFC 6455 § 4.2.2): "The empty string is not the same as the null value for these purposes and is not a legal value for this field."
    SEC_WEBSOCKET_PROTOCOL_EMPTY = {
        id: "sec_websocket_protocol_empty",
        title: "Sec-WebSocket-Protocol is written with no subprotocol in it",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_6455_4_2_2],
    }

    /// A subprotocol the request never offered: a name outside the client's
    /// list, or any name at all where the client sent no list.
    ///
    /// `_unsolicited` is the ending whose evidence is in the *other* message,
    /// and this is its plainest case. Nothing is wrong with the value as
    /// written — it is a `token`, and it may well be a registered subprotocol —
    /// and what condemns it is a field in the request it answers. § 4.2.2 says
    /// where the value comes from in as many words, *by selecting one of the
    /// values* the client sent, so a name that was not among them was derived
    /// from something other than the handshake.
    ///
    /// A request that offered none is the same defect and not a milder one: the
    /// set to select from is empty, so every name is outside it, and the same
    /// section tells a server unwilling to agree to send no field at all.
    ///
    /// `error`, and the client's own list is why: it is handed one instruction
    /// for this exact case and it is to fail the connection. The handshake
    /// completes on the wire and the connection it opens does not survive being
    /// read.
    ///
    /// The comparison is of the octets as written, the same choice
    /// [`SEC_WEBSOCKET_PROTOCOL_DUPLICATED`] records and for the same reason:
    /// this document folds case at the two fields where it says so, and says
    /// nothing of the kind about a subprotocol name.
    ///
    // cite(RFC 6455 § 4.2.2): "The value chosen MUST be derived from the client's handshake, specifically by selecting one of the values from the |Sec-WebSocket-Protocol| field that the server is willing to use for this connection (if any)."
    SEC_WEBSOCKET_PROTOCOL_UNSOLICITED = {
        id: "sec_websocket_protocol_unsolicited",
        title: "Sec-WebSocket-Protocol names a subprotocol the request did not offer",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_6455_4_2_2],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rank that separates the request's entry from the response's two: a
    /// repeated preference is a value a server reads straight past, and both
    /// halves of what a server may write wrong are a connection the client is
    /// told to fail.
    #[test]
    fn a_repeated_name_leaves_the_handshake_working() {
        assert_eq!(
            SEC_WEBSOCKET_PROTOCOL_DUPLICATED.default_severity,
            Severity::Warn
        );
        assert_eq!(SEC_WEBSOCKET_PROTOCOL_DUPLICATED.spec, [RFC_6455_4_1]);
        for def in [
            &SEC_WEBSOCKET_PROTOCOL_EMPTY,
            &SEC_WEBSOCKET_PROTOCOL_UNSOLICITED,
        ] {
            assert_eq!(def.default_severity, Severity::Error, "{}", def.id);
            assert_eq!(def.spec, [RFC_6455_4_2_2], "{}", def.id);
        }
    }

    /// The two sections this subject cites are one field read from both ends,
    /// and nothing here may collapse them: § 4.1 states what a client writes
    /// and § 4.2.2 what a server may answer with, so an entry taking the wrong
    /// one would cite a sentence addressed to the other sender.
    #[test]
    fn the_two_directions_cite_different_sections() {
        assert_ne!(RFC_6455_4_1.section, RFC_6455_4_2_2.section);
    }
}
