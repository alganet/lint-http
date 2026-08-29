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
//!
//! The third thing is the question those two rules ask *before* either half: which
//! captured messages are an opening handshake at all. One rule measures the
//! request and one measures the response, and a message that is a handshake to one
//! of them and not to the other would be a gap no test could see from inside
//! either.

use crate::helpers::headers::{combined_field_value_as_written, trim_ows};
use crate::helpers::list::list_members;
use crate::helpers::shown::describe_octet;
use base64::Engine;
use sha1::Digest;

/// Which of `version`'s terminals a `Sec-WebSocket-Version` value failed, worded for
/// the operator who has to go and look at it.
///
/// The production is three alternatives over one to three digits, plus a comment
/// bounding the number they spell. Reading it as "the value 13 and nothing else" --
/// which is what a `!= "13"` comparison does -- collapses six different mistakes
/// into one sentence, and the advice that sentence gives ("expected 13") is not
/// something the sender of `Sec-WebSocket-Version: 013` can act on.
///
/// The alternation on its own derives `256` through `299`; the comment printed
/// beneath it is what stops there, which is why it is quoted with the productions
/// rather than separately.
///
/// **Shared on its second caller, and the two read different productions out of
/// the same terminal.** A request's field is `Sec-WebSocket-Version-Client =
/// version` — one value — and a response's is
/// `Sec-WebSocket-Version-Server = 1#version`, so the server rule asks this of
/// each member of a list. What is shared is the terminal; the list, the floor
/// and the wording of every finding stay at each caller, because § 4.3's
/// `-Client`/`-Server` suffixes make those the two fields' own questions.
// cite(RFC 6455 § 4.3, label: Sec-WebSocket-Version): "Sec-WebSocket-Version-Client = version"
// cite(RFC 6455 § 4.3, label: version): "version = DIGIT | (NZDIGIT DIGIT) | ("1" DIGIT DIGIT) | ("2" DIGIT DIGIT) ; Limited to 0-255 range, with no leading zeros"
pub fn version_production_defect(value: &str) -> Option<String> {
    if value.is_empty() {
        return Some(
            "it is empty, and every alternative of `version` spells at least one DIGIT".into(),
        );
    }
    if let Some(c) = value.chars().find(|c| !c.is_ascii_digit()) {
        return Some(format!(
            "it contains {}, and `version` is spelled in DIGITs alone",
            describe_octet(c as u8)
        ));
    }
    if value.len() > 3 {
        return Some(format!(
            "it is {} characters, and no alternative of `version` is longer than three digits",
            value.len()
        ));
    }
    if value.len() > 1 && value.starts_with('0') {
        return Some(
            "it carries a leading zero, and the production admits none: `NZDIGIT` is the \
             first digit of every alternative longer than one"
                .into(),
        );
    }
    // Three digits beginning with a `2` do derive from the alternation, and the
    // comment printed under it is what stops at 255 -- so this last one is
    // arithmetic rather than shape.
    if value.parse::<u16>().is_ok_and(|n| n > 255) {
        return Some(
            "it is above 255, which is where the comment printed under the production stops".into(),
        );
    }
    None
}

/// Whether this request is RFC 6455's opening handshake, and the version it
/// arrived under.
///
/// Three questions, and the third is the one a reader does not expect.
///
/// The method and the `Upgrade` keyword are the two halves of what makes a GET
/// this document's handshake rather than any other GET; the first half of the
/// sentence stating the method is used here to scope rather than to report, since
/// saying "this should have been a GET" of every POST in a capture would be saying
/// it of traffic that never claimed to be a handshake. Its second half — the
/// version floor — is a finding, and belongs to the rule measuring the request.
///
/// The third question is the messaging syntax. Above major version 1 this
/// handshake does not exist: the opening request is an extended CONNECT carrying
/// `:protocol`, the `Connection` and `Upgrade` fields are ones those versions
/// forbid outright, and `Sec-WebSocket-Key` and `Sec-WebSocket-Accept` are not
/// processed at all — so neither the request's fields nor the response's are there
/// to measure, and demanding them would be telling an operator to add fields the
/// message may not carry. RFC 8441 updates RFC 6455 to say so for HTTP/2 and
/// RFC 9220 gives HTTP/3 the same answer; those two are the whole of what exists
/// above 1, and a major digit beyond them names no wire format.
///
/// A value deriving from no `HTTP-version` names no version, so there is nothing
/// here to compare against and no handshake to claim; `http_version_syntax`
/// is the rule that reports the value itself.
// cite(RFC 6455 § 4.1): "The method of the request MUST be GET, and the HTTP version MUST be at least 1.1."
// cite(RFC 6455 § 4.1): "The request MUST contain an |Upgrade| header field whose value MUST include the "websocket" keyword."
// cite(RFC 6455 § 4.2.1): "An |Upgrade| header field containing the value "websocket", treated as an ASCII case-insensitive value."
// cite(RFC 8441 § 5): "This request replaces the GET-based request in [RFC6455] and is used to process the WebSockets opening handshake."
// cite(RFC 8441 § 5): "[RFC6455] requires the use of Connection and Upgrade header fields that are not part of HTTP/2.  They MUST NOT be included in the CONNECT request defined here."
// cite(RFC 8441 § 5): "Implementations using this extended CONNECT to bootstrap WebSockets do not do the processing of the Sec-WebSocket-Key and Sec-WebSocket-Accept header fields of [RFC6455] as that functionality has been superseded by the :protocol pseudo-header field."
// cite(RFC 9220 § 3): "The semantics of the pseudo-header fields and setting are identical to those in HTTP/2 as defined in [RFC8441]."
pub fn opening_handshake_version(
    req: &crate::http_transaction::RequestInfo,
) -> Option<crate::http_version::HttpVersion> {
    if req.method != "GET" {
        return None;
    }
    // The keyword is matched without case because the section describing how a
    // server reads this field says to; the lines are joined first because `Upgrade`
    // is one list however many of them carry it.
    let upgrade = combined_field_value_as_written(&req.headers, "upgrade")?;
    if !list_members(&upgrade).any(|m| m.eq_ignore_ascii_case("websocket")) {
        return None;
    }
    let version = crate::http_version::parse(&req.version).ok()?;
    if version.major >= 2 {
        return None;
    }
    Some(version)
}

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
    /// somewhere other than the end, or absent padding.
    Shape,
    /// A base64 spelling of sixteen octets whose last symbol carries bits a
    /// conforming encoder sets to zero.
    ///
    /// Its own variant, and the reason is that this is the only defect here that
    /// two documents answer differently. The alphabet and the shape are things
    /// `base64-value-non-empty` does not derive and the length is a count RFC 6455
    /// states in words; a value in this variant derives from that production, and
    /// is sixteen octets, and is rejected only because RFC 4648 says what a
    /// conforming *encoder* writes. That document leaves the decoder a choice in
    /// the same breath — *"MAY chose to reject an encoding if the pad bits have
    /// not been set to zero."* — and RFC 6455 exercises it in neither direction,
    /// while printing such a value in its own NOTE.
    ///
    /// So the value is reported to whoever wrote it, and no requirement addressed
    /// to a *recipient* of it can be read off this verdict. The rule measuring the
    /// server's answer is where that distinction is paid.
    // cite(RFC 4648 § 3.5): "MAY chose to reject an encoding if the pad bits have not been set to zero."
    PadBits,
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
                 base64 encoding produces: the symbol count, or the placement of the \
                 padding",
            ),
            Self::PadBits => f.write_str(
                "it is a base64 spelling of sixteen octets whose last symbol carries bits a \
                 conforming encoder sets to zero, so the same nonce has a canonical spelling \
                 this is not",
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
        // The one refusal the strict engine makes that no production of RFC 6455's
        // asks for. The symbols are all in the alphabet and the padding is where it
        // belongs; what the decoder objects to is the four or two bits a final
        // quantum discards being something other than zero. The value still spells
        // some number of octets, and *which* number is the more useful thing to
        // report -- so it is decoded again by an engine told to allow exactly this,
        // and the length answers first when it is not sixteen.
        Err(base64::DecodeError::InvalidLastSymbol { .. }) => {
            match lenient_engine().decode(value) {
                Ok(bytes) if bytes.len() == 16 => Some(SecWebSocketKeyDefect::PadBits),
                Ok(bytes) => Some(SecWebSocketKeyDefect::Length(bytes.len())),
                Err(_) => Some(SecWebSocketKeyDefect::Shape),
            }
        }
        Err(_) => Some(SecWebSocketKeyDefect::Shape),
    }
}

/// The standard alphabet and padding, with the one check relaxed that RFC 4648
/// leaves to the decoder rather than to the encoder.
///
/// Used to answer "how many octets is this" about a value the strict engine has
/// already refused, never to decide whether a value is acceptable.
fn lenient_engine() -> base64::engine::GeneralPurpose {
    base64::engine::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::general_purpose::GeneralPurposeConfig::new()
            .with_decode_allow_trailing_bits(true),
    )
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
/// Returns `None` when the value is not a base64 spelling of sixteen octets: there
/// is no accept value to expect from a server handed something that is not the
/// nonce at all, and the rule reading the request is where that gets *reported*.
///
/// A [`SecWebSocketKeyDefect::PadBits`] value is **not** one of those. It spells
/// the sixteen octets, the server is told it need not decode the field to answer
/// it, and what gets hashed is the string as written — so the answer a server owes
/// such a key is as well defined as any other, and refusing to compute it here
/// would quietly excuse the server from being checked.
///
/// Otherwise the result is the base64 encoding of the SHA-1 hash of the key **as a
/// string** concatenated with the well-known GUID — not of the bytes it decodes to.
///
/// The whitespace stripped either side is the whitespace this step is told to
/// ignore — its own sentence, which happens to agree with the field-value one.
// cite(RFC 6455 § 4.2.2): "It is not necessary for the server to base64-decode the |Sec-WebSocket-Key| value."
// cite(RFC 6455 § 4.1): "but ignoring any leading and trailing whitespace"
pub fn compute_accept(key: &str) -> Option<String> {
    let key_trim = trim_ows(key);
    // There is nothing to derive from a value that is not the nonce, and which of
    // the ways it failed is the reading rule's to report. A non-canonical last
    // symbol is not one of those ways: it is the sixteen octets, spelled a way
    // RFC 4648 leaves a decoder free to accept.
    if !matches!(
        sec_websocket_key_defect(key_trim),
        None | Some(SecWebSocketKeyDefect::PadBits)
    ) {
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
    /// silently would be one that could not tell a truncated key from a whole one,
    /// and the sentence saying so is RFC 4648's rather than something chosen here.
    ///
    /// It is its own verdict rather than a `Shape`, and that is what keeps the
    /// finding where it belongs. The value derives from `base64-value-non-empty`
    /// and decodes to the sixteen octets the NOTE names, so a rule enforcing a
    /// requirement addressed to a *recipient* of the value has nothing here — only
    /// the party that wrote it does. `websocket_handshake_valid` is
    /// where that distinction is paid, and the accept value stays derivable so the
    /// server is still measured on its answer.
    #[test]
    fn the_notes_own_example_key_is_not_canonical_base64() {
        assert_eq!(
            sec_websocket_key_defect("AQIDBAUGBwgJCgsMDQ4PEC=="),
            Some(SecWebSocketKeyDefect::PadBits)
        );
        assert_eq!(sec_websocket_key_defect("AQIDBAUGBwgJCgsMDQ4PEA=="), None);
        // Both spellings name the same sixteen octets, so both have the same answer
        // and it is the one a server derives from the string it was sent.
        assert_ne!(
            compute_accept("AQIDBAUGBwgJCgsMDQ4PEC=="),
            compute_accept("AQIDBAUGBwgJCgsMDQ4PEA==")
        );
        assert!(compute_accept("AQIDBAUGBwgJCgsMDQ4PEC==").is_some());
    }

    /// A non-canonical last symbol on a value that is *not* sixteen octets reports
    /// the length, because that is the more useful of the two things wrong with it
    /// and the only one RFC 6455 states itself.
    #[test]
    fn a_short_key_with_non_canonical_padding_reports_its_length() {
        assert_eq!(
            sec_websocket_key_defect("YR=="),
            Some(SecWebSocketKeyDefect::Length(1))
        );
        assert_eq!(compute_accept("YR=="), None);
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
