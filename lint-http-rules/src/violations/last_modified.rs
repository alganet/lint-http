// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Last-Modified` defects — a modification time measured against the message
//! that carries it.
//!
//! **The timestamp's *syntax* is not here.** `Last-Modified` is an `HTTP-date`
//! like every other date-valued field, so a value that does not derive from one
//! of the three formats is [`http_date`](crate::violations::http_date)'s and
//! reported by the rule that reads it. What is left for this subject is the one
//! thing only the surrounding message can decide.

use crate::lint::Severity;
use crate::lint::Strength;
use crate::rules::SpecRef;
use crate::violations::defects;

/// The origin server's MUST NOT: a modification time cannot be later than the
/// message's own origination time.
pub const RFC_9110_8_8_2_1: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("8.8.2.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8.2.1",
    note: "Generation — an origin server with a clock MUST NOT generate a `Last-Modified` date later than its own `Date`",
};

defects! {
    /// A `Last-Modified` naming a time after the `Date` on the same response.
    ///
    /// **A flat MUST NOT, and the one qualification is about the sender rather
    /// than the value**: § 8.8.2.1 addresses an origin server *with a clock*, so
    /// a server that has none is outside the sentence — and a response arriving
    /// with both fields is one whose sender demonstrably had one to write the
    /// `Date` with.
    ///
    /// **`_conflicting` because the pair is what fails.** Either timestamp
    /// alone is an ordinary `HTTP-date`, and what the two say together is that
    /// a representation changed after the message describing it was generated.
    /// A cache comparing them has been handed a story it cannot order.
    ///
    /// **The comparison allows a skew**, which is the rule's tolerance rather
    /// than the sentence's: clocks disagree by seconds and reporting that would
    /// report the world.
    ///
    /// `error`: § 8.8.2.1 says an origin server with a clock MUST NOT generate
    /// a `Last-Modified` later than its own `Date`. Nothing is unreadable and
    /// the response is usable; what is wrong is that its two timestamps cannot
    /// both be right.
    ///
    // cite(RFC 9110 § 8.8.2.1): "An origin server with a clock (as defined in Section 5.6.7) MUST NOT generate a Last-Modified date that is later than the server's time of message origination (Date, Section 6.6.1)."
    LAST_MODIFIED_CONFLICTING = {
        id: "last_modified_conflicting",
        title: "A Last-Modified is later than the Date beside it",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_8_8_2_1],
        strength: Strength::Must,
    }
}
