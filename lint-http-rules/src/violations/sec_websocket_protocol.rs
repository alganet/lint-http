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
//! **The response's half of the field is the same subject and is not written
//! yet.** § 4.3 gives the server `Sec-WebSocket-Protocol-Server = token` against
//! the client's `1#token`, and § 4.2.2 adds two sentences no production carries:
//! that the empty string is not a legal value, and that the name has to be one
//! the client offered. The second is `_unsolicited`'s shape exactly — a value
//! whose evidence is in the other message — and both are `websocket_handshake_
//! valid`'s to declare when they land.

use crate::lint::Severity;
use crate::violations::defects;
use crate::violations::sec_websocket_key::RFC_6455_4_1;

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
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The one entry this subject has so far, and the rank that separates it
    /// from the handshake's fatal halves: a repeated preference is a value a
    /// server reads straight past.
    #[test]
    fn a_repeated_name_leaves_the_handshake_working() {
        assert_eq!(
            SEC_WEBSOCKET_PROTOCOL_DUPLICATED.default_severity,
            Severity::Warn
        );
        assert_eq!(SEC_WEBSOCKET_PROTOCOL_DUPLICATED.spec, [RFC_6455_4_1]);
    }
}
