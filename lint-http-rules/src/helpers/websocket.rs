// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Utilities for WebSocket handshake processing.
//!
//! Currently only provides helpers for computing the expected value of
//! `Sec-WebSocket-Accept` given a client's `Sec-WebSocket-Key` as defined by
//! RFC 6455 §4.2.2.

use base64::Engine;
use sha1::Digest;

/// The GUID a server concatenates to the client's key. This constant *is* the
/// specification: get one character wrong and every handshake we judge is judged
/// against nonsense, with no other symptom.
///
/// The quote below is from § 4.2.2's worked example rather than from the normative
/// step above it, and that is not laziness. RFC 6455's line width breaks this GUID
/// across a line everywhere it is *stated* — the extracted text reads
/// `"258EAFA5- E914-47DA-95CA-C5AB0DC85B11"`, with a space. The example is one of
/// only two places in the document where all 36 characters survive on one line, so
/// it is the only passage that can pin the value at all.
// cite(RFC 6455 § 4.2.2): "server would append the string "258EAFA5-E914-47DA-95CA-C5AB0DC85B11" to form the string"
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Compute the `Sec-WebSocket-Accept` value from the client's request key.
///
/// The input string is trimmed of whitespace. If the client key is not valid
/// base64 or decodes to a length other than 16 bytes, this function returns
/// `None`, mirroring the requirements of RFC 6455.
///
/// Otherwise the result is the base64 encoding of the SHA-1 hash of the key **as a
/// string** concatenated with the well-known GUID — not of the bytes it decodes to.
pub fn compute_accept(key: &str) -> Option<String> {
    let key_trim = key.trim();
    // decode key to ensure it is 16 bytes long. Returning None on a malformed
    // encoding is RFC 4648's instruction, and RFC 6455 does not state otherwise.
    // cite(RFC 4648 § 3.3): "Implementations MUST reject the encoded data if it contains characters outside the base alphabet when interpreting base-encoded data, unless the specification referring to this document explicitly states otherwise."
    match base64::engine::general_purpose::STANDARD.decode(key_trim) {
        // cite(RFC 6455 § 4.1): "The value of this header field MUST be a nonce consisting of a randomly selected 16-byte value that has been base64-encoded"
        Ok(bytes) if bytes.len() == 16 => {
            let mut hasher = sha1::Sha1::new();
            // The decode above is a length check and nothing more. What gets hashed is
            // the key exactly as it arrived on the wire — the easiest thing here to get
            // wrong is to hash the 16 bytes we just decoded, which produces a
            // plausible-looking accept value that is always wrong.
            // cite(RFC 6455 § 4.1): "(as a string, not base64-decoded) with the string"
            hasher.update(key_trim.as_bytes());
            hasher.update(WS_GUID.as_bytes());
            // cite(RFC 6455 § 4.2.2): "taking the SHA-1 hash of this concatenated value to obtain a 20-byte value"
            let digest = hasher.finalize();
            Some(base64::engine::general_purpose::STANDARD.encode(digest))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_accept_valid_key() {
        // example from RFC 6455 Appendix A.1
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let expected = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
        assert_eq!(compute_accept(key).as_deref(), Some(expected));
    }

    #[test]
    fn compute_accept_trims_spaces() {
        let key = "  dGhlIHNhbXBsZSBub25jZQ==  ";
        let expected = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
        assert_eq!(compute_accept(key).as_deref(), Some(expected));
    }

    #[test]
    fn compute_accept_invalid_length() {
        // decodes fine but wrong length
        let key = base64::engine::general_purpose::STANDARD.encode("not16bytes");
        assert_eq!(compute_accept(&key), None);
    }

    #[test]
    fn compute_accept_invalid_base64() {
        assert_eq!(compute_accept("!!notbase64!!"), None);
    }
}
