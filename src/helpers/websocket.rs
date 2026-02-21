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

const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Compute the `Sec-WebSocket-Accept` value from the client's request key.
///
/// The input string is trimmed of whitespace. If the client key is not valid
/// base64 or decodes to a length other than 16 bytes, this function returns
/// `None`, mirroring the requirements of RFC 6455.
///
/// Otherwise the result is the base64 encoding of the SHA-1 hash of the
/// concatenation of the key bytes and the well-known GUID.
pub fn compute_accept(key: &str) -> Option<String> {
    let key_trim = key.trim();
    // decode key to ensure it is 16 bytes long
    match base64::engine::general_purpose::STANDARD.decode(key_trim) {
        Ok(bytes) if bytes.len() == 16 => {
            let mut hasher = sha1::Sha1::new();
            hasher.update(key_trim.as_bytes());
            hasher.update(WS_GUID.as_bytes());
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
