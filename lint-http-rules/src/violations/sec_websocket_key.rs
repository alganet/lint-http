// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Sec-WebSocket-Key` defects — what the field carries, rather than how it is
//! spelled.
//!
//! `Sec-WebSocket-Key = base64-value-non-empty` and RFC 6455 hands the encoding
//! to RFC 4648 without restating a character of it, so an octet outside the
//! alphabet, a symbol count no group of twenty-four bits accounts for and a
//! final symbol carrying bits a conforming encoder zeroes are all
//! [`base64`](crate::violations::base64)'s — the same three defects an
//! `Authorization: Basic` value can have.
//!
//! **What is left is item 7 of § 4.1's list, and it is two sentences about a
//! nonce**: that the field is there at all, and that what it carries is a
//! randomly selected sixteen-byte value. Neither is an encoding question — a
//! base64 spelling of twelve octets is a perfectly good base64 spelling — which
//! is why the encoding subject's mapping had one verdict it could not answer
//! and this subject is what answers it.
//!
//! **The two entries rank apart, on whether the handshake can complete.** A
//! request with no key at all cannot be answered: § 4.2.2 derives
//! `Sec-WebSocket-Accept` from the key's octets, so a server has nothing to
//! compute from and § 4.2.1 tells it to stop and answer with an error status. A
//! key of the wrong length is answered normally — the accept value is the SHA-1
//! of the field *as a string*, whatever length it decodes to — and what is lost
//! is the guarantee the nonce exists for: that this handshake cannot be
//! replayed from a cached response. **Ask whether the exchange can continue**,
//! which is the same question [`status`](crate::violations::status) is ranked
//! by, and here it separates the pair.
//!
//! Not here: whether the nonce was *randomly* selected, or reused across
//! connections. Both are properties of how a value was chosen and a capture of
//! one handshake holds no evidence of either.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// Client Requirements, item 7: the field, the nonce it carries, and the
/// sixteen bytes that nonce is. The two entries below split one numbered item
/// into its two sentences.
pub const RFC_6455_4_1: SpecRef = SpecRef {
    spec: "RFC 6455",
    section: Some("4.1"),
    url: "https://www.rfc-editor.org/rfc/rfc6455.html#section-4.1",
    note: "Client Requirements — the numbered list this rule measures: GET, HTTP version at least 1.1, `Upgrade: websocket`, the `Upgrade` connection-option, the `Sec-WebSocket-Key` nonce, `Sec-WebSocket-Version: 13`, and `Sec-WebSocket-Protocol`'s non-empty unique `token` members",
};

defects! {
    /// An opening handshake with no `Sec-WebSocket-Key` field on it at all.
    ///
    /// `error`, and the server's side of the same document is why: the accept
    /// value a `101` owes is derived from this field's octets, so a request
    /// without one asks for a handshake no server can complete. What a server
    /// does instead is stop and answer with an error status.
    ///
    /// Over HTTP/2 and HTTP/3 the field is not sent and not processed — RFC
    /// 8441 replaces the nonce with the extended CONNECT — so a rule reporting
    /// this entry has to know which version carried the request.
    ///
    // cite(RFC 6455 § 4.1): "The request MUST include a header field with the name |Sec-WebSocket-Key|."
    SEC_WEBSOCKET_KEY_MISSING = {
        id: "sec_websocket_key_missing",
        title: "WebSocket handshake carries no Sec-WebSocket-Key",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_6455_4_1],
    }

    /// A field whose value is a well-formed base64 encoding of some number of
    /// octets other than sixteen.
    ///
    /// **Not an encoding defect**, which is the whole reason this entry exists
    /// beside [`base64`](crate::violations::base64)'s three: every symbol is in
    /// the alphabet, the quantum count is whole and the padding is where it
    /// belongs. What the value fails is the sentence saying what the field
    /// carries — a nonce of sixteen bytes — and that sentence is this
    /// document's.
    ///
    /// `_invalid` and not `_malformed`: the value derives from
    /// `base64-value-non-empty` exactly as written, and what refuses it is a
    /// requirement past the grammar, which is the line
    /// `docs/development.md` draws between the two words.
    ///
    /// `warn`, where the absent field is an `error`. The handshake still
    /// completes: § 4.2.2 hashes the field as a string rather than the octets
    /// it decodes to, so a server answers a twelve-octet key with a perfectly
    /// valid accept value. What is lost is what the length is *for* — a nonce
    /// wide enough that a `101` cannot be replayed out of a cache.
    ///
    // cite(RFC 6455 § 4.1): "The value of this header field MUST be a nonce consisting of a randomly selected 16-byte value that has been base64-encoded (see Section 4 of [RFC4648])."
    SEC_WEBSOCKET_KEY_LENGTH_INVALID = {
        id: "sec_websocket_key_length_invalid",
        title: "Sec-WebSocket-Key is not a sixteen-byte nonce",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_6455_4_1],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One numbered item, two sentences, two entries — and the rank is what
    /// they disagree about: a server can answer one of these and not the other.
    #[test]
    fn the_absent_field_outranks_the_wrong_length() {
        assert!(
            SEC_WEBSOCKET_KEY_LENGTH_INVALID.default_severity
                < SEC_WEBSOCKET_KEY_MISSING.default_severity
        );
        assert_eq!(SEC_WEBSOCKET_KEY_MISSING.default_severity, Severity::Error);
    }

    /// Both are item 7's, which is the one place the field's own requirements
    /// are written; the encoding's sentences live with the encoding.
    #[test]
    fn both_entries_name_the_field_s_own_item() {
        assert_eq!(SEC_WEBSOCKET_KEY_MISSING.spec, [RFC_6455_4_1]);
        assert_eq!(SEC_WEBSOCKET_KEY_LENGTH_INVALID.spec, [RFC_6455_4_1]);
    }
}
