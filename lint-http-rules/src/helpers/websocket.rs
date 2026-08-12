// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Utilities for WebSocket handshake processing.
//!
//! Two things live here, and they are two halves of one production. The client's
//! `Sec-WebSocket-Key` has to be read the same way by the rule that reports it and
//! by the function that derives the server's `Sec-WebSocket-Accept` from it — one
//! decodes to say what is wrong with the value, the other decodes to find out
//! whether there is anything to hash at all — so the reading is written once and
//! the two callers differ only in what they do with the verdict.

use crate::helpers::headers::{describe_octet, trim_ows};
use base64::Engine;
use sha1::Digest;

/// Which of `Sec-WebSocket-Key`'s two requirements a value failed.
///
/// One variant per mistake rather than a single "malformed" verdict, because a
/// value outside the alphabet, a value the encoding does not generate, and a
/// perfectly good encoding of the wrong number of octets are three different things
/// for an operator to go and fix.
// cite(RFC 6455 § 4.3, label: Sec-WebSocket-Key): "Sec-WebSocket-Key = base64-value-non-empty"
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SecWebSocketKeyDefect {
    /// An octet that `base64-character` does not derive.
    Alphabet(u8),
    /// Every octet is one the alphabet holds, but the sequence is not one the
    /// encoding generates: a symbol count no quantum accounts for, a pad character
    /// somewhere other than the end, absent padding, or a last symbol carrying
    /// bits a conforming encoder sets to zero.
    Shape,
    /// A well-formed encoding of some number of octets other than sixteen.
    Length(usize),
}

impl std::fmt::Display for SecWebSocketKeyDefect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Alphabet(b) => write!(
                f,
                "it contains {}, which is not one of the sixty-four base64 characters",
                describe_octet(*b)
            ),
            Self::Shape => f.write_str(
                "its characters are all base64 characters, but the sequence is not one \
                 base64 encoding produces: the symbol count, the placement of the padding, \
                 or the bits carried by the last symbol",
            ),
            Self::Length(n) => write!(
                f,
                "it is base64 for {n} octets, and the nonce it carries is sixteen"
            ),
        }
    }
}

/// What is wrong with a `Sec-WebSocket-Key` value, if anything.
///
/// The whitespace either side is not part of the value: no `base64-character`
/// derives SP or HTAB, and a field value does not include the whitespace a version
/// of HTTP allowed around it.
///
/// Rejecting an octet outside the alphabet is the referenced document's own
/// instruction rather than a choice made here, and RFC 6455 does not take it back;
/// so is refusing a last symbol whose discarded bits are not zero, which is the
/// same document saying what a conforming encoder writes.
// cite(RFC 9110 § 5.5): "A field value does not include leading or trailing whitespace.  When a specific version of HTTP allows such whitespace to appear in a message, a field parsing implementation MUST exclude such whitespace prior to evaluating the field value."
// cite(RFC 4648 § 3.3): "Implementations MUST reject the encoded data if it contains characters outside the base alphabet when interpreting base-encoded data, unless the specification referring to this document explicitly states otherwise."
// cite(RFC 4648 § 3.5): "These pad bits MUST be set to zero by conforming encoders, which is described in the descriptions on padding below."
// cite(RFC 6455 § 4.1, label: Sec-WebSocket-Key nonce): "The value of this header field MUST be a nonce consisting of a randomly selected 16-byte value that has been base64-encoded"
pub fn sec_websocket_key_defect(value: &str) -> Option<SecWebSocketKeyDefect> {
    let value = trim_ows(value);
    // Every character the alphabet holds is one octet, and the reader that hands a
    // captured value here gives one `char` per octet -- so a `char` above %x7F costs
    // two bytes the moment the string is read as bytes, and the decoder would name
    // %xC2 or %xC3 where the sender wrote %xA0 or %xE9. One scan, before the decode,
    // keeps the finding pointed at the octet that is actually in the message.
    if let Some(c) = value.chars().find(|c| !c.is_ascii()) {
        return Some(SecWebSocketKeyDefect::Alphabet(c as u8));
    }
    match base64::engine::general_purpose::STANDARD.decode(value) {
        Ok(bytes) if bytes.len() == 16 => None,
        Ok(bytes) => Some(SecWebSocketKeyDefect::Length(bytes.len())),
        // A pad character reported as an invalid byte is a pad character in the
        // wrong place, which is a shape mistake and not an alphabet one -- `=` is
        // in the grammar, as `base64-padding`.
        Err(base64::DecodeError::InvalidByte(_, b'=')) => Some(SecWebSocketKeyDefect::Shape),
        Err(base64::DecodeError::InvalidByte(_, b)) => Some(SecWebSocketKeyDefect::Alphabet(b)),
        Err(_) => Some(SecWebSocketKeyDefect::Shape),
    }
}

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
/// Returns `None` for any key [`sec_websocket_key_defect`] objects to: there is no
/// accept value to expect from a server handed a key the client should not have
/// sent, and the rule reading the request is where that gets *reported*.
///
/// Otherwise the result is the base64 encoding of the SHA-1 hash of the key **as a
/// string** concatenated with the well-known GUID — not of the bytes it decodes to.
///
/// The whitespace stripped either side is the whitespace this step is told to
/// ignore — its own sentence, which happens to agree with the field-value one.
// cite(RFC 6455 § 4.1): "but ignoring any leading and trailing whitespace"
pub fn compute_accept(key: &str) -> Option<String> {
    let key_trim = trim_ows(key);
    // There is nothing to derive from a value that is not the nonce, and which of
    // the three ways it failed is the reading rule's to report.
    if sec_websocket_key_defect(key_trim).is_some() {
        return None;
    }
    let mut hasher = sha1::Sha1::new();
    // The check above reads a length and nothing more. What gets hashed is the key
    // exactly as it arrived on the wire — the easiest thing here to get wrong is to
    // hash the sixteen octets it decodes to, which produces a plausible-looking
    // accept value that is always wrong.
    // cite(RFC 6455 § 4.1): "(as a string, not base64-decoded) with the string"
    hasher.update(key_trim.as_bytes());
    hasher.update(WS_GUID.as_bytes());
    // cite(RFC 6455 § 4.2.2): "taking the SHA-1 hash of this concatenated value to obtain a 20-byte value"
    let digest = hasher.finalize();
    Some(base64::engine::general_purpose::STANDARD.encode(digest))
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

    /// The key RFC 6455 carries through its worked handshake, in § 1.2 and again in
    /// Appendix A.1, has nothing wrong with it.
    #[test]
    fn the_specifications_own_nonce_is_clean() {
        assert_eq!(sec_websocket_key_defect("dGhlIHNhbXBsZSBub25jZQ=="), None);
    }

    /// § 4.1's NOTE says that for the sixteen octets 0x01 through 0x10 "the value of
    /// the header field would be `AQIDBAUGBwgJCgsMDQ4PEC==`", and it would not: the
    /// last symbol is `C`, whose six bits are `000010`, and the four of them that a
    /// two-symbol final quantum discards are therefore not zero. The canonical
    /// spelling ends `EA==`, and both decode to the sixteen octets the NOTE names.
    ///
    /// Recorded as a test rather than worked around. A decoder that accepted this
    /// would be one that could not tell a truncated key from a whole one, and the
    /// sentence saying so is RFC 4648's rather than something chosen here.
    #[test]
    fn the_notes_own_example_key_is_not_canonical_base64() {
        assert_eq!(
            sec_websocket_key_defect("AQIDBAUGBwgJCgsMDQ4PEC=="),
            Some(SecWebSocketKeyDefect::Shape)
        );
        assert_eq!(sec_websocket_key_defect("AQIDBAUGBwgJCgsMDQ4PEA=="), None);
    }

    /// The three mistakes are three verdicts, and an octet outside the alphabet
    /// gets named rather than swallowed.
    #[rstest::rstest]
    #[case("dGhlIHNhbXBsZSBub25jZQ*=", SecWebSocketKeyDefect::Alphabet(b'*'))]
    // %xE9 is `obs-text`, which no field but one carrying opaque data may hold and
    // `base64-character` certainly does not.
    #[case("dGhlIHNhbXBsZSBub25jZQ\u{e9}=", SecWebSocketKeyDefect::Alphabet(0xe9))]
    // A pad character is in the grammar; a pad character here is not.
    #[case("dGhs=IHNhbXBsZSBub25jZQ==", SecWebSocketKeyDefect::Shape)]
    // Twenty-two symbols and no padding: the count is right and the spelling is not.
    #[case("dGhlIHNhbXBsZSBub25jZQ", SecWebSocketKeyDefect::Shape)]
    // Sixteen octets need twenty-two symbols; four fewer is four octets fewer.
    #[case("dGhlIHNhbXBsZSBub25j", SecWebSocketKeyDefect::Length(15))]
    #[case("YQ==", SecWebSocketKeyDefect::Length(1))]
    fn each_way_a_key_fails_has_its_own_verdict(
        #[case] value: &str,
        #[case] expected: SecWebSocketKeyDefect,
    ) {
        assert_eq!(sec_websocket_key_defect(value), Some(expected));
    }

    /// A value padded with the two octets `OWS` names is the same value; one padded
    /// with an octet that merely looks like a space is not, and the octet is the
    /// finding.
    #[test]
    fn only_ows_is_trimmed_off_a_key() {
        assert_eq!(
            sec_websocket_key_defect("\tdGhlIHNhbXBsZSBub25jZQ== "),
            None
        );
        assert_eq!(
            sec_websocket_key_defect("\u{a0}dGhlIHNhbXBsZSBub25jZQ=="),
            Some(SecWebSocketKeyDefect::Alphabet(0xa0))
        );
    }
}
