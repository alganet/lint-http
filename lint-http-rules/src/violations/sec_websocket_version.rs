// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Sec-WebSocket-Version` defects — the number a handshake is negotiated on.
//!
//! The field is one production and borrows nothing. `version` is three
//! alternatives over one to three DIGITs with a comment stopping the number they
//! spell at 255, so there is no `token` in it, no list member, no octet class
//! any other subject holds — a value that fails it fails RFC 6455's own grammar
//! and nobody else's.
//!
//! **One field name, two productions, two directions.** § 4.3 writes
//! `Sec-WebSocket-Version-Client = version` and
//! `Sec-WebSocket-Version-Server = 1#version`: a request carries one number and
//! a response carries the list of numbers a server will speak. The terminal is
//! the same either way, which is why both rules that read this field declare the
//! entries below, and why the reader answering for it is shared.
//!
//! **Two entries for five verdicts, and the reader is deliberately finer than
//! the catalogue.** A leading zero, a non-digit, four digits and `299` are four
//! different things to go and fix, and the message says which — but they are one
//! sender who wrote a number this production does not spell, and an operator
//! silencing one has no reason to keep the others. The value written blank is
//! the exception the id vocabulary always makes: a sender who wrote the field
//! and put nothing in it.
//!
//! **Both are `error`, on the question the handshake is ranked by**: a version a
//! recipient cannot read is a version nobody can negotiate on. § 4.2.1 has a
//! server stop and answer with an error status, and § 4.4's advertisement — the
//! reply that would let a client retry — is written for a version the server
//! *understood* and does not speak. Neither of these is that.
//!
//! Not here: a request whose version is a perfectly good number other than 13.
//! That value derives from the production and what refuses it is § 4.1's item 9,
//! which is the field's requirement rather than its grammar — a separate entry,
//! and one that has to be read beside § 4.4 before it is written.

use crate::helpers::websocket::VersionDefect;
use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::{defects, ViolationDef};

/// The collected ABNF: the `version` production, the comment bounding it, and
/// the `-Client`/`-Server` suffixes that make one field name two grammars.
pub const RFC_6455_4_3: SpecRef = SpecRef {
    spec: "RFC 6455",
    section: Some("4.3"),
    url: "https://www.rfc-editor.org/rfc/rfc6455.html#section-4.3",
    note: "Collected ABNF — `version = DIGIT | (NZDIGIT DIGIT) | (\"1\" DIGIT DIGIT) | (\"2\" DIGIT DIGIT)` with the comment limiting it to 0-255 and no leading zeros, the `-Client`/`-Server` suffixes that make a request's field one version and a response's a list of them, and the handshake's other fields collected beside it: `Sec-WebSocket-Key = base64-value-non-empty` and `Sec-WebSocket-Protocol-Client = 1#token`",
};

defects! {
    /// The field written with nothing in it, on either side of the exchange.
    ///
    /// Every alternative of the production spells at least one DIGIT, so an
    /// empty value derives from none of them — but it is kept apart from the
    /// values that merely fail, because a sender who wrote `Sec-WebSocket-
    /// Version:` and stopped is not the sender who wrote `013`. The first has a
    /// field they did not fill in; the second has a number they believe in.
    ///
    // cite(RFC 6455 § 4.3, label: version): "version = DIGIT | (NZDIGIT DIGIT) | ("1" DIGIT DIGIT) | ("2" DIGIT DIGIT) ; Limited to 0-255 range, with no leading zeros"
    SEC_WEBSOCKET_VERSION_EMPTY = {
        id: "sec_websocket_version_empty",
        title: "Sec-WebSocket-Version is written with no value",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_6455_4_3],
    }

    /// A value that is not empty and derives from no alternative of `version`:
    /// an octet that is no DIGIT, more digits than three, a leading zero, or a
    /// number above the range the comment stops at.
    ///
    /// **Four verdicts and one entry**, which is the opposite direction from
    /// the split above and rests on the same test. The reader keeps all four
    /// apart and the message says which — "expected 13" is no help to whoever
    /// sent `013` — while the *defect* is one: a number this production does
    /// not spell. An operator who tolerates one spelling of that has no reason
    /// to refuse the others.
    ///
    /// `_malformed` and not `_invalid`: what refuses these values is the
    /// grammar itself. A well-formed number that is simply not 13 is the
    /// field's requirement rather than its production, and is not this entry.
    ///
    // cite(RFC 6455 § 4.3, label: version): "version = DIGIT | (NZDIGIT DIGIT) | ("1" DIGIT DIGIT) | ("2" DIGIT DIGIT) ; Limited to 0-255 range, with no leading zeros"
    SEC_WEBSOCKET_VERSION_MALFORMED = {
        id: "sec_websocket_version_malformed",
        title: "Sec-WebSocket-Version derives from no version production",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_6455_4_3],
    }
}

/// The entry a [`VersionDefect`] reports as.
///
/// The mapping is where the reader's five verdicts become the catalogue's two,
/// and it is the whole of the coarsening: every caller keeps the reader's own
/// message beside the id, so nothing an operator would act on is lost by the
/// entries being fewer than the verdicts.
pub fn version_defect(defect: VersionDefect) -> &'static ViolationDef {
    match defect {
        VersionDefect::Empty => &SEC_WEBSOCKET_VERSION_EMPTY,
        VersionDefect::Character(_)
        | VersionDefect::TooLong(_)
        | VersionDefect::LeadingZero
        | VersionDefect::AboveRange => &SEC_WEBSOCKET_VERSION_MALFORMED,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::websocket::version_production_defect as read;

    /// The coarsening, written against the reader: four verdicts to one entry
    /// and the blank value to its own. The values are the shapes § 4.3's
    /// comment and alternation each refuse.
    #[test]
    fn four_ways_of_failing_the_production_are_one_entry_and_the_blank_value_is_another() {
        let id = |value: &str| version_defect(read(value).expect("a defect")).id;

        assert_eq!(id(""), "sec_websocket_version_empty");
        assert_eq!(id("1x"), "sec_websocket_version_malformed");
        assert_eq!(id("0013"), "sec_websocket_version_malformed");
        assert_eq!(id("013"), "sec_websocket_version_malformed");
        assert_eq!(id("299"), "sec_websocket_version_malformed");
        // The one value § 4.1 requires, and the range's edges the production
        // does derive.
        assert!(read("13").is_none());
        assert!(read("0").is_none());
        assert!(read("255").is_none());
    }

    /// A version nobody can read is a handshake nobody can negotiate, whichever
    /// side wrote it — so the pair ranks together and ranks at the top.
    #[test]
    fn a_version_that_cannot_be_read_ends_the_negotiation() {
        assert_eq!(
            SEC_WEBSOCKET_VERSION_EMPTY.default_severity,
            Severity::Error
        );
        assert_eq!(
            SEC_WEBSOCKET_VERSION_MALFORMED.default_severity,
            Severity::Error
        );
    }
}
