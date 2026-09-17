// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `SETTINGS` defects — a frame each peer sends once, and what may be in it.
//!
//! HTTP/3's frame, spelled `http3_` for the reason
//! [`http3_goaway`](crate::violations::http3_goaway) and
//! [`http3_max_push_id`](crate::violations::http3_max_push_id) are: HTTP/2 has
//! a `SETTINGS` too, several of its identifiers are precisely what this one
//! reserves, and an operator silencing a defect names a thing on one protocol's
//! wire.
//!
//! **Two entries end in `_duplicated` and the part is what tells them apart** —
//! the *frame* repeated on a connection, and an *identifier* repeated inside
//! one frame. They are different senders with different repairs (a control
//! stream that wrote `SETTINGS` twice; one frame carrying one parameter twice),
//! and naming the part rather than inventing a second ending is what
//! `<subject>[_<part>]_<defect>` is for.
//!
//! **The ranking is the stated consequence, and it splits the three.** § 7.2.4.1
//! makes the receipt of a reserved identifier a connection error of type
//! `H3_SETTINGS_ERROR`, so that entry is `error`; the two repetitions break
//! MUST NOTs for which § 7.2.4 states no recipient's answer — it says elsewhere
//! that a receiver *MAY* reject the frame — so they are `warn`.

use crate::lint::Severity;
use crate::lint::Strength;
use crate::rules::SpecRef;
use crate::violations::defects;

/// SETTINGS: that each peer sends one and only one, and that an identifier
/// appears in it at most once.
pub const RFC_9114_7_2_4: SpecRef = SpecRef {
    spec: "RFC 9114",
    section: Some("7.2.4"),
    url: "https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.4",
    note: "SETTINGS — the frame each peer sends first on its control stream and never again, and the prohibition on one identifier occurring twice inside it",
};

/// Defined SETTINGS Parameters: the identifiers this protocol reserves, and the
/// connection error their receipt draws.
pub const RFC_9114_7_2_4_1: SpecRef = SpecRef {
    spec: "RFC 9114",
    section: Some("7.2.4.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.4.1",
    note: "Defined SETTINGS Parameters — the reserved identifiers must not be sent, and their receipt is a connection error of type H3_SETTINGS_ERROR",
};

defects! {
    /// A second `SETTINGS` frame from the same peer on one connection.
    ///
    /// The requirement is per peer — each sends one as the first frame of its
    /// own control stream — so the other endpoint's `SETTINGS` is its own first
    /// frame and never this defect. What is reported is one endpoint writing
    /// the frame twice.
    ///
    /// `error`: § 7.2.4 says the frame MUST NOT be sent after the first one on
    /// a control stream. **This used to rank below the reserved identifier
    /// below it**, because that section states a connection error the recipient
    /// answers with and this sentence states none. A `MUST NOT` with no stated
    /// answer is still a `MUST NOT`.
    ///
    // cite(RFC 9114 § 7.2.4): "A SETTINGS frame MUST be sent as the first frame of each control stream (see Section 6.2.1) by each peer, and it MUST NOT be sent subsequently"
    HTTP3_SETTINGS_DUPLICATED = {
        id: "http3_settings_duplicated",
        title: "A peer sent a second SETTINGS frame on one connection",
        message: "HTTP/3 duplicate SETTINGS frame from the same peer on one connection",
        default_severity: Severity::Error,
        spec: &[RFC_9114_7_2_4],
        strength: Strength::Must,
    }

    /// A `SETTINGS` carrying one of the identifiers HTTP/3 reserves.
    ///
    /// **`_forbidden` and not `_unregistered`**: these values *are* in the
    /// registry, registered as `Reserved` precisely so that an HTTP/2 setting
    /// cannot be carried across by its number. A sender putting one on the wire
    /// is doing something the document forbids outright, not naming something
    /// nobody has assigned.
    ///
    /// `error`: § 7.2.4.1 makes the receipt a connection error of type
    /// `H3_SETTINGS_ERROR`.
    ///
    // cite(RFC 9114 § 7.2.4.1): "These reserved settings MUST NOT be sent, and their receipt MUST be treated as a connection error of type H3_SETTINGS_ERROR"
    HTTP3_SETTINGS_IDENTIFIER_FORBIDDEN = {
        id: "http3_settings_identifier_forbidden",
        title: "SETTINGS carries an identifier HTTP/3 reserves",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9114_7_2_4_1],
        strength: Strength::Must,
    }

    /// One `SETTINGS` frame carrying the same identifier twice.
    ///
    /// The same ending as the frame entry above and a different part, because
    /// they are different mistakes: that one is a control stream writing the
    /// frame a second time, this one is a single frame stating a parameter
    /// twice and leaving a recipient no sentence saying which value wins.
    ///
    /// `error` for the same reason: the `MUST NOT` is on the sender, and the
    /// document leaving the receiver a choice rather than an obligation is a
    /// fact about the receiver.
    ///
    // cite(RFC 9114 § 7.2.4): "The same setting identifier MUST NOT occur more than once in the SETTINGS frame"
    HTTP3_SETTINGS_IDENTIFIER_DUPLICATED = {
        id: "http3_settings_identifier_duplicated",
        title: "One SETTINGS frame states the same identifier twice",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9114_7_2_4],
        strength: Strength::Must,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// All three now rank together, and the old comment named the reason they
    /// did not: the other two "break MUST NOTs the document attaches no
    /// recipient answer to". A `MUST NOT` with no stated answer is still a
    /// `MUST NOT`, and § 7.2.4 addresses both of these to the peer that sends
    /// the frame.
    #[test]
    fn every_entry_breaks_a_must_and_the_repetitions_are_no_exception() {
        assert_eq!(
            HTTP3_SETTINGS_IDENTIFIER_FORBIDDEN.default_severity,
            Severity::Error
        );
        assert_eq!(HTTP3_SETTINGS_DUPLICATED.default_severity, Severity::Error);
        assert_eq!(
            HTTP3_SETTINGS_IDENTIFIER_DUPLICATED.default_severity,
            Severity::Error
        );
    }

    /// Two entries share an ending and the part is what separates them — the
    /// frame from what is inside it.
    #[test]
    fn the_part_separates_the_two_repetitions() {
        assert!(HTTP3_SETTINGS_DUPLICATED.id.ends_with("_duplicated"));
        assert!(HTTP3_SETTINGS_IDENTIFIER_DUPLICATED
            .id
            .ends_with("_duplicated"));
        assert_ne!(
            HTTP3_SETTINGS_DUPLICATED.id,
            HTTP3_SETTINGS_IDENTIFIER_DUPLICATED.id
        );
    }

    /// The frame entry carries its whole message: nothing about it varies, so
    /// there is nothing for a site to format.
    #[test]
    fn only_the_entries_naming_an_identifier_leave_their_message_to_the_site() {
        assert!(!HTTP3_SETTINGS_DUPLICATED.message.is_empty());
        assert!(HTTP3_SETTINGS_IDENTIFIER_FORBIDDEN.message.is_empty());
        assert!(HTTP3_SETTINGS_IDENTIFIER_DUPLICATED.message.is_empty());
    }
}
