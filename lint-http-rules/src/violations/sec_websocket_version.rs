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
//! **The response's list has two entries of its own**, and neither is the
//! terminal's: a `1#version` advertising nothing at all, and an advertisement
//! that names the very version the request asked for. The first is the 1997
//! notation's floor — the same `#rule`
//! [`sec_websocket_extensions`](crate::violations::sec_websocket_extensions)
//! reads, permitting null elements and requiring one that is not — and the
//! second is what the field is *for*: § 11.3.5 has a server send it when the
//! version it received is not one it understood, so a list holding that version
//! says both things about one handshake.
//!
//! **The other two entries are the field's requirement rather than its grammar**,
//! and they are one numbered item: § 4.1 item 9 asks a request for the field and
//! for the value `13`. A request with no field at all is not a handshake this
//! document can answer; a request with a good number that is not 13 is one it
//! answers by refusing, which is where the two part company in rank.

use crate::helpers::websocket::VersionDefect;
use crate::lint::Severity;
use crate::rules::SpecRef;
// Item 9 is one numbered item of the same list item 7 is in, so the reference is
// written once — in the subject that reached it first — and the two subjects
// name the same `SpecRef` rather than two equal ones.
use crate::violations::sec_websocket_extensions::RFC_2616_2_1;
use crate::violations::sec_websocket_key::RFC_6455_4_1;
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

    /// An opening handshake with no `Sec-WebSocket-Version` field on it at all.
    ///
    /// The first half of item 9, and `error` for the reason the grammar's two
    /// are: a server has no version to check and § 4.2.1 has it stop and answer
    /// with an error status. There is nothing to advertise back either — § 4.4's
    /// reply lists the versions a server will speak *in answer to* one it was
    /// asked for.
    ///
    // cite(RFC 6455 § 4.1): "The request MUST include a header field with the name |Sec-WebSocket-Version|.  The value of this header field MUST be 13."
    SEC_WEBSOCKET_VERSION_MISSING = {
        id: "sec_websocket_version_missing",
        title: "WebSocket handshake carries no Sec-WebSocket-Version",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_6455_4_1],
    }

    /// A request whose version derives from the production and is not 13.
    ///
    /// **`_invalid` is the vocabulary's word for exactly this**: the value is
    /// grammatical and a requirement past the grammar refuses it. The rule
    /// reporting it had declined the word on the grounds that § 4.4 prints a
    /// request like this one — `Sec-WebSocket-Version: 25`, answered with a 400
    /// listing what the server will speak — but that section describes how a
    /// server *answers* a version it does not understand, and item 9 is what
    /// says which version a request may carry. Both are true, and only one of
    /// them is addressed to the sender.
    ///
    /// `warn`, alone in this subject, and § 4.4 is why: the exchange has a
    /// defined outcome that leaves the connection an ordinary HTTP one and the
    /// client able to ask again. A version nobody can *read* has no such reply —
    /// the advertisement is written for a version a server understood and does
    /// not speak.
    ///
    /// The NOTE beside item 9 is worth knowing before raising this: the draft
    /// values 9 through 12 were reserved in the registry and never used, so a
    /// capture carrying one is a client built against a draft rather than a
    /// client speaking a version that exists.
    ///
    // cite(RFC 6455 § 4.1): "The request MUST include a header field with the name |Sec-WebSocket-Version|.  The value of this header field MUST be 13."
    SEC_WEBSOCKET_VERSION_INVALID = {
        id: "sec_websocket_version_invalid",
        title: "WebSocket handshake asks for a version other than 13",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_6455_4_1],
    }

    /// A response whose `1#version` advertises nothing: written empty, or
    /// written as nothing but the commas of a list.
    ///
    /// **The floor, not the terminal**, which is why this is a second entry
    /// beside the blank value above and cites another document entirely. § 4.3
    /// imports RFC 2616's notation by name, so a null element conforms —
    /// `13,,8` advertises two versions — and what pays for that permission is
    /// the sentence requiring one element that is not null. A request's field
    /// cannot reach this entry: it is one `version` and not a list of them.
    ///
    /// `error`, with the rest of the subject. A 400 that advertises nothing is
    /// the answer § 4.4 asks a server for, minus the only part a client can act
    /// on.
    ///
    // cite(RFC 2616 § 2.1): "Therefore, where at least one element is required, at least one non-null element MUST be present."
    SEC_WEBSOCKET_VERSION_LIST_EMPTY = {
        id: "sec_websocket_version_list_empty",
        title: "Sec-WebSocket-Version advertises no version",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_2616_2_1],
    }

    /// A response advertising a list that holds the version the request asked
    /// for.
    ///
    /// **Two claims about one handshake, and they disagree**: § 11.3.5 has a
    /// server send this field *when the version received from the client does
    /// not match a version understood by the server*, and says the field holds
    /// the versions the server supports. Listing the requested one therefore
    /// says both that the server does not speak it and that it does — which is
    /// `_conflicting`'s definition and not `_invalid`'s, since no value here is
    /// measured against anything but the other message.
    ///
    /// The comparison is exact. Both sides derive from `version`, which is
    /// DIGITs, so there is no case to fold and no leading zero to normalise —
    /// the production admits none.
    ///
    /// `warn`, where the subject's other entries are `error`. Everything in the
    /// exchange is readable and the client is left with a list it can choose
    /// from; what it cannot do is trust the choice, since one of the two claims
    /// is wrong and the message does not say which.
    ///
    // cite(RFC 6455 § 11.3.5): "The |Sec-WebSocket-Version| header field is also sent from the server to the client on WebSocket handshake error, when the version received from the client does not match a version understood by the server."
    SEC_WEBSOCKET_VERSION_CONFLICTING = {
        id: "sec_websocket_version_conflicting",
        title: "Sec-WebSocket-Version advertises the version the request asked for",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_6455_11_3_5],
    }
}

/// The field's registration: when a server sends it, and that it holds the
/// versions the server supports — which is what a list holding the requested one
/// contradicts.
pub const RFC_6455_11_3_5: SpecRef = SpecRef {
    spec: "RFC 6455",
    section: Some("11.3.5"),
    url: "https://www.rfc-editor.org/rfc/rfc6455.html#section-11.3.5",
    note: "The field's registration — when a server sends it, and that it holds the \
           versions the server supports, which is what a list holding the requested \
           one contradicts",
};

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
    /// side wrote it — so those rank at the top, and the one value the document
    /// answers by refusing ranks below them.
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
        assert_eq!(
            SEC_WEBSOCKET_VERSION_MISSING.default_severity,
            Severity::Error
        );
        assert!(
            SEC_WEBSOCKET_VERSION_INVALID.default_severity
                < SEC_WEBSOCKET_VERSION_MALFORMED.default_severity
        );
    }

    /// Which sentence each half names: the grammar for the two that fail the
    /// production, item 9 for the two that fail what the field is for.
    #[test]
    fn the_grammar_and_the_requirement_are_two_sections() {
        assert_eq!(SEC_WEBSOCKET_VERSION_MALFORMED.spec, [RFC_6455_4_3]);
        assert_eq!(SEC_WEBSOCKET_VERSION_INVALID.spec, [RFC_6455_4_1]);
    }
}
