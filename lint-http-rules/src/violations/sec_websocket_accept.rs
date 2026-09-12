// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Sec-WebSocket-Accept` defects — the one field that proves a server read the
//! request.
//!
//! Every other field of a `101` a server could write from a template. This one
//! it cannot: the value is the request's `Sec-WebSocket-Key` concatenated with a
//! fixed GUID, hashed, and base64-encoded, so a server that answers with
//! anything else either did not read the key or is not the server the client
//! opened a handshake with. That is the whole of the field, and it is two
//! entries — the field is absent, or the value is not the one the key derives.
//!
//! **Nothing here is a grammar entry, and the absence is deliberate.** § 4.3
//! writes `Sec-WebSocket-Accept = base64-value-non-empty`, and a subject that
//! measured a value against it would report every non-conforming value twice:
//! the derived value is canonical base64 of twenty octets, so a value the
//! grammar rejects is a value the comparison rejects, and the comparison's
//! message can name what the server should have written where the production
//! could only say it did not derive. **A production nothing can fail on its own
//! earns no entry** — the [`base64`](crate::violations::base64) ids stay with
//! the request's key, which is a value nothing else in the exchange constrains.
//!
//! **Both entries are `error`**, and the question
//! [`status`](crate::violations::status) ranks by is answered by § 4.1 rather
//! than by this subject: a client that finds either of them is told to _Fail the
//! WebSocket Connection_, and by then the HTTP conversation is over — the `101`
//! has handed the connection to a protocol whose first message the client will
//! never send.

use crate::lint::Severity;
use crate::violations::defects;
use crate::violations::sec_websocket_protocol::RFC_6455_4_2_2;

defects! {
    /// A `101` completing a WebSocket handshake with no `Sec-WebSocket-Accept`
    /// on it at all.
    ///
    /// Kept apart from the value that does not derive, the way this catalogue
    /// keeps every absence apart from every wrong value: a server that wrote no
    /// field never ran the derivation, and one that wrote the wrong value ran it
    /// over something other than the key it was sent. The fixes are not the
    /// same, and neither is what an operator learns from the finding.
    ///
    /// Not to be confused with [`upgrade_101_missing`](crate::violations::upgrade),
    /// which every `101` owes whatever it switched to. This field is owed by the
    /// handshake this document defines, and a `101` that is not one of those
    /// owes nothing here.
    ///
    // cite(RFC 6455 § 4.2.2): "A |Sec-WebSocket-Accept| header field.  The value of this header field is constructed by concatenating /key/, defined above in step 4 in Section 4.2.2, with the string "258EAFA5-E914-47DA-95CA-C5AB0DC85B11", taking the SHA-1 hash of this concatenated value to obtain a 20-byte value and base64-encoding (see Section 4 of [RFC4648]) this 20-byte hash."
    SEC_WEBSOCKET_ACCEPT_MISSING = {
        id: "sec_websocket_accept_missing",
        title: "A WebSocket handshake response carries no Sec-WebSocket-Accept",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_6455_4_2_2],
    }

    /// A value that is not the one the request's `Sec-WebSocket-Key` derives.
    ///
    /// `_conflicting` and not `_invalid`: nothing about the value can be
    /// measured on its own. It is a perfectly good base64 string as often as
    /// not, and what is wrong is that it disagrees with a field in the other
    /// message — the two things this document requires to agree are the key the
    /// client sent and the hash the server echoed, and a finding here is the
    /// disagreement rather than either value's own defect.
    ///
    /// **A second field line is this entry too**, and the reason is worth
    /// keeping: the field is not list-based, so two lines do not make two
    /// members — the value is the join, comma and all, and the join derives from
    /// no key. The finding is worded from what the message says rather than from
    /// what one of its lines says.
    ///
    /// The derivation is the sentence, so the message names the value the server
    /// should have written. This is the entry whose finding an operator can act
    /// on without reading the specification at all.
    ///
    // cite(RFC 6455 § 4.2.2): "A |Sec-WebSocket-Accept| header field.  The value of this header field is constructed by concatenating /key/, defined above in step 4 in Section 4.2.2, with the string "258EAFA5-E914-47DA-95CA-C5AB0DC85B11", taking the SHA-1 hash of this concatenated value to obtain a 20-byte value and base64-encoding (see Section 4 of [RFC4648]) this 20-byte hash."
    SEC_WEBSOCKET_ACCEPT_CONFLICTING = {
        id: "sec_websocket_accept_conflicting",
        title: "Sec-WebSocket-Accept is not the value the request's key derives",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_6455_4_2_2],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One field, one sentence, two ways of failing it — and the rank is the
    /// same for both because the client's instruction is: the connection has
    /// already left HTTP, so neither can be repaired by a later message.
    #[test]
    fn the_absent_field_and_the_wrong_value_are_two_ids_of_one_rank() {
        assert_eq!(
            SEC_WEBSOCKET_ACCEPT_MISSING.id,
            "sec_websocket_accept_missing"
        );
        assert_eq!(
            SEC_WEBSOCKET_ACCEPT_CONFLICTING.id,
            "sec_websocket_accept_conflicting"
        );
        for def in [
            &SEC_WEBSOCKET_ACCEPT_MISSING,
            &SEC_WEBSOCKET_ACCEPT_CONFLICTING,
        ] {
            assert_eq!(def.default_severity, Severity::Error, "{}", def.id);
            assert_eq!(def.spec, [RFC_6455_4_2_2], "{}", def.id);
        }
    }
}
