// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Base64 defects — a value that does not decode, wherever it was carried.
//!
//! RFC 4648's encoding is read in at least three places here: the
//! `basic-credentials` of an `Authorization`, the `Sec-WebSocket-Key` of a
//! handshake, and its `Sec-WebSocket-Accept` answer. None of those fields
//! restates a character of it, so what is wrong with a mangled value is never a
//! fact about credentials or about WebSockets, and an operator who does not
//! care about a mangled encoding says so in one place for all of them.
//!
//! **Four entries, and one of them is deliberately coarse.**
//! `base64::DecodeError` is what the `Basic` reader has, and it distinguishes
//! nothing this catalogue could name, so `base64_malformed` answers for all of
//! it. The WebSocket reader splits the same failure three ways — the alphabet,
//! the quantum, and pad bits a conforming encoder zeroes — and those three sit
//! *beside* the coarse one rather than replacing it. **A coarse def and a fine
//! one in the same subject are two readers, not two vocabularies**, and an
//! operator who wants the whole encoding quiet raises four entries rather than
//! one. Say so here, because the next commit's instinct is to collapse them.
//!
//! **The whitespace/control split `docs/development.md` mandates is declined,
//! and the reason is that no second sentence draws it.** Where a subject
//! separates the octets nobody typed from the ones a sender chose, it does so
//! because two different sentences refuse them — a field value's grammar
//! excludes the control octet, the production's alphabet excludes the rest.
//! RFC 4648 § 3.3 is one MUST over every character outside the sixty-four, and
//! it does not care which one; the message names the octet, and the catalogue
//! does not pretend to a distinction the specification declines to make.

use crate::helpers::websocket::SecWebSocketKeyDefect;
use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::{defects, ViolationDef};

/// The instruction that makes a malformed encoding a finding rather than a
/// judgment call — and it is addressed to the *decoder*, which is what a proxy
/// reading someone else's credentials is.
pub const RFC_4648_3_3: SpecRef = SpecRef {
    spec: "RFC 4648",
    section: Some("3.3"),
    url: "https://www.rfc-editor.org/rfc/rfc4648.html#section-3.3",
    note: "Interpretation of non-alphabet characters — a MUST to reject data outside the base alphabet, unless the referring specification says otherwise",
};

/// The shape of an encoding, stated as arithmetic: four characters per
/// twenty-four bits, and a final group padded out to them.
pub const RFC_4648_4: SpecRef = SpecRef {
    spec: "RFC 4648",
    section: Some("4"),
    url: "https://www.rfc-editor.org/rfc/rfc4648.html#section-4",
    note: "Base 64 Encoding — the 24-bit group written as four characters, and the padding that completes a final group of fewer bits",
};

/// The one requirement here that a decoder is free to ignore, which is why the
/// defect it names defaults below the other three.
pub const RFC_4648_3_5: SpecRef = SpecRef {
    spec: "RFC 4648",
    section: Some("3.5"),
    url: "https://www.rfc-editor.org/rfc/rfc4648.html#section-3.5",
    note: "Canonical encoding — the discarded bits of a final symbol MUST be zero in what an encoder writes, and a decoder MAY reject an encoding where they are not",
};

defects! {
    /// A value that is not an encoding the alphabet and the quantum produce: an
    /// octet outside the sixty-four characters, a length no group of symbols
    /// accounts for, or padding somewhere other than the end.
    ///
    // cite(RFC 4648 § 3.3): "Implementations MUST reject the encoded data if it contains characters outside the base alphabet when interpreting base-encoded data, unless the specification referring to this document explicitly states otherwise."
    BASE64_MALFORMED = {
        id: "base64_malformed",
        title: "Value is not a base64 encoding",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_4648_3_3],
    }

    /// An octet the sixty-four characters do not hold. The finer half of
    /// [`BASE64_MALFORMED`], reported where the reader knows *which* octet —
    /// and § 3.3's MUST is the whole of what makes it a finding rather than a
    /// curiosity, since the encoding itself has no opinion about what a decoder
    /// does with a stray byte.
    ///
    // cite(RFC 4648 § 3.3): "Implementations MUST reject the encoded data if it contains characters outside the base alphabet when interpreting base-encoded data, unless the specification referring to this document explicitly states otherwise."
    BASE64_CHARACTER_FORBIDDEN = {
        id: "base64_character_forbidden",
        title: "Value holds an octet outside the base64 alphabet",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_4648_3_3],
    }

    /// Every character is one the alphabet holds, and the sequence of them is
    /// still not one the encoding produces: a symbol count no group of
    /// twenty-four bits accounts for, or a pad character somewhere other than
    /// the end. **The arithmetic, rather than the alphabet** — which is why it
    /// is a separate entry from the one above and not a severity of it: the
    /// fix is a different fix, and the encoder that produced it failed at a
    /// different step.
    ///
    // cite(RFC 4648 § 4): "The encoding process represents 24-bit groups of input bits as output strings of 4 encoded characters."
    BASE64_QUANTUM_MALFORMED = {
        id: "base64_quantum_malformed",
        title: "Value is not a whole number of base64 groups",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_4648_4],
    }

    /// A final symbol carrying bits a conforming encoder sets to zero. The
    /// value decodes, and to exactly the octets it meant; what is wrong is that
    /// the same octets have a canonical spelling and this is not it.
    ///
    /// **`info`, and the ranking is the `http_date` subject's read through the
    /// recipient again.**
    /// The other three entries name values a decoder is instructed to reject;
    /// § 3.5 leaves a decoder a choice in the same breath it states the
    /// requirement — *"MAY chose to reject an encoding if the pad bits have not
    /// been set to zero"* — and the document defining the field this is first
    /// reported for prints such a value in its own NOTE. So the message
    /// arrives, the octets are the right octets, and the finding is addressed
    /// to whoever wrote the encoder.
    ///
    /// `_invalid` rather than `_malformed` for the same reason: the value
    /// derives from the production, and what refuses it is a sentence past the
    /// grammar.
    ///
    // cite(RFC 4648 § 3.5): "These pad bits MUST be set to zero by conforming encoders, which is described in the descriptions on padding below."
    BASE64_PAD_BITS_INVALID = {
        id: "base64_pad_bits_invalid",
        title: "Final base64 symbol carries bits a conforming encoder zeroes",
        message: "",
        default_severity: Severity::Info,
        spec: &[RFC_4648_3_5],
    }
}

/// The defect a [`SecWebSocketKeyDefect`] reports as.
///
/// Three of the four verdicts are this subject's and the fourth is not an
/// encoding defect at all: a base64 spelling of twelve octets is a perfectly
/// good base64 spelling, and the sixteen is RFC 6455's sentence about what the
/// field carries. That one is
/// [`sec_websocket_key`](crate::violations::sec_websocket_key)'s, which is why
/// this mapping crosses subjects rather than answering `None` — **a reader
/// whose verdicts belong to two subjects is still one mapping**, the shape
/// `word_defect` has for the alternation it splits.
///
/// The mapping lives here rather than in a file named after the helper for the
/// reason every mapping in this catalogue is shelved that way — the first thing
/// this reader measures is the encoding, and a
/// subject file holding nothing but a mapping fn would carry no `// cite` and
/// fail the citation ratchet on the spot.
pub fn sec_websocket_key_defect(defect: &SecWebSocketKeyDefect) -> &'static ViolationDef {
    match defect {
        SecWebSocketKeyDefect::Alphabet(_) => &BASE64_CHARACTER_FORBIDDEN,
        SecWebSocketKeyDefect::Shape => &BASE64_QUANTUM_MALFORMED,
        SecWebSocketKeyDefect::PadBits => &BASE64_PAD_BITS_INVALID,
        SecWebSocketKeyDefect::Length(_) => {
            &crate::violations::sec_websocket_key::SEC_WEBSOCKET_KEY_LENGTH_INVALID
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::websocket::sec_websocket_key_defect as read_key;

    /// The mapping, written against the reader: four verdicts, four ids, and
    /// the fourth belonging to the field rather than to the encoding. The
    /// values are the ones RFC 6455's own examples and NOTE reach.
    #[test]
    fn the_three_encoding_verdicts_are_three_ids_and_the_length_is_another_subjects() {
        let id = |value: &str| {
            let defect = read_key(value).expect("a defect");
            sec_websocket_key_defect(&defect).id
        };

        // `!` is not one of the sixty-four, and `=` inside the value is a pad
        // character where no padding goes.
        assert_eq!(id("dGhlIHNhbXBsZSBub25jZQ!="), "base64_character_forbidden");
        assert_eq!(id("dGhlIHNhbXBsZ=Sbm9uY2U="), "base64_quantum_malformed");
        // § 4.1's own NOTE prints this spelling of the octets 0x01..0x10.
        assert_eq!(id("AQIDBAUGBwgJCgsMDQ4PEC=="), "base64_pad_bits_invalid");
        // A well-formed encoding of the wrong number of octets is not the
        // encoding's defect, and the id it answers with says whose it is.
        assert_eq!(id("dGhlIHNhbXBsZQ=="), "sec_websocket_key_length_invalid");
        // And the value § 4.1 prints as the field's example is no defect at all.
        assert!(read_key("dGhlIHNhbXBsZSBub25jZQ==").is_none());
    }

    /// The coarse entry and the fine ones are one subject read by two readers,
    /// and each rule declares only what its reader can answer.
    ///
    /// Asserted because the shape looks like a mistake from either side: a
    /// later commit reading `basic_auth_base64_valid` will want to give it the
    /// three fine ids it cannot reach, and one reading this rule will want to
    /// delete the coarse one it does not use. Both would be wrong, and the
    /// module doc says why.
    #[test]
    fn the_coarse_reader_and_the_fine_one_declare_different_halves() {
        let declared = |id: &str| {
            crate::rules::all_rules()
                .find(|rule| rule.id() == id)
                .expect("a registered rule")
                .violations()
                .iter()
                .map(|def| def.id)
                .collect::<Vec<_>>()
        };

        let basic = declared("basic_auth_base64_valid");
        assert!(basic.contains(&"base64_malformed"), "{basic:?}");
        assert!(!basic.contains(&"base64_character_forbidden"), "{basic:?}");

        let websocket = declared("sec_websocket_headers_consistent");
        assert!(
            websocket.contains(&"base64_character_forbidden"),
            "{websocket:?}"
        );
        assert!(!websocket.contains(&"base64_malformed"), "{websocket:?}");
    }

    /// The value every decoder reads correctly sits below the three it is told
    /// to reject.
    #[test]
    fn the_spelling_a_decoder_may_accept_sits_below_the_ones_it_must_not() {
        assert!(
            BASE64_PAD_BITS_INVALID.default_severity < BASE64_CHARACTER_FORBIDDEN.default_severity
        );
        assert_eq!(
            BASE64_QUANTUM_MALFORMED.default_severity,
            BASE64_CHARACTER_FORBIDDEN.default_severity,
        );
        // The coarse entry cannot rank against the fine ones — it is what a
        // reader that distinguishes none of this reports.
        assert_eq!(
            BASE64_MALFORMED.default_severity,
            BASE64_CHARACTER_FORBIDDEN.default_severity,
        );
    }
}
