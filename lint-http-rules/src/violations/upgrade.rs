// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Upgrade` defects — the field two status codes owe, and what is on it.
//!
//! A `101 (Switching Protocols)` is a connection changing hands: everything
//! after the response's empty line is spoken in another protocol. The status
//! code says the change happened and the `Upgrade` field says *what to*, which
//! is why RFC 9110 § 15.2.2 requires the field of the response rather than
//! merely recommending it — a client that has stopped speaking HTTP and does
//! not know what it is now speaking has no way to continue and no way to ask.
//!
//! A `426 (Upgrade Required)` is the same field asked for by the opposite
//! event: the server refuses the request *under the current protocol* and the
//! field names what it would accept instead. § 15.5.22 states that MUST from
//! the status's side and § 7.8 from the field's, in the same words either way —
//! sent *to indicate* the protocols — so a 426 with no field, or with a field
//! naming nothing, asks for a change it does not describe.
//!
//! **The subject is the field even though the requirement is written into a
//! status code's section**, which is the line `content_range` draws for the
//! same shape: the sentence is addressed to the field's presence, and it is the
//! field an operator would look for in the message. What the status code owes
//! *about itself* — that it may not be sent at all over a version with no
//! upgrade mechanism, that it may not switch to something nobody offered —
//! belongs to [`status`](crate::violations::status).
//!
//! **Four entries: the same two defects under each of the two status codes**,
//! and the ids say which because the conditions and the sentences both differ.
//! An entry naming § 15.2.2 and § 15.5.22 together would give up the citation
//! its findings can carry — 2 sites out of 2 know which status they read — and
//! it would flatten a difference in rank that is real.
//!
//! **The rank is where the two codes part.** A `101` has already ended the HTTP
//! conversation, so there is no later message in which the omission can be
//! repaired: both of its entries are `error`. A `426` is an ordinary response a
//! client can read; what it loses is the advice, and the request can be made
//! again. Both of those are `warn`. **Ask whether the exchange can continue**,
//! which is the same question `status`'s entries are ranked by.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// The status code's section: what the code indicates, and the requirement on
/// the field written into the same paragraph. Shared with
/// [`status`](crate::violations::status), whose entry reads the first half of it
/// — a connection that changed protocol — where the two entries here read the
/// second.
pub const RFC_9110_15_2_2: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("15.2.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.2.2",
    note: "101 Switching Protocols — the status code is a change in the application protocol being used on this connection, and the response MUST generate an `Upgrade` field naming the protocol(s) in effect after it",
};

/// The 426's section: what the status code refuses, and the MUST that the
/// response name what it would accept. The field's own section states the same
/// requirement — § 7.8, worded with the ordering clause — and a requirement
/// written twice in one document is quoted once, at the sentence that also
/// carries the condition.
pub const RFC_9110_15_5_22: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("15.5.22"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5.22",
    note: "426 Upgrade Required — the server refuses the request under the current protocol, and MUST send an `Upgrade` field to indicate the required protocol(s). RFC 9110 §7.8 states the same MUST from the field's side.",
};

defects! {
    /// A `101` response with no `Upgrade` field on it at all. The connection
    /// has changed protocol and the message that changed it does not say to
    /// what.
    ///
    // cite(RFC 9110 § 15.2.2): "The server MUST generate an Upgrade header field in the response that indicates which protocol(s) will be in effect after this response."
    UPGRADE_101_MISSING = {
        id: "upgrade_101_missing",
        title: "A 101 response carries no Upgrade field",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_15_2_2],
    }

    /// The field written, and no protocol name on it: an empty value, or one
    /// made of nothing but the commas of a list.
    ///
    /// Separated from the absent field the way `docs/development.md` requires,
    /// and here the two senders really are different: a field that is not there
    /// is a server that never learned the requirement, while `Upgrade:` with
    /// nothing after it is a server that built the value from a list and found
    /// the list empty. The recipient is equally stuck either way, which is why
    /// the two rank the same.
    ///
    // cite(RFC 9110 § 15.2.2): "The server MUST generate an Upgrade header field in the response that indicates which protocol(s) will be in effect after this response."
    UPGRADE_101_EMPTY = {
        id: "upgrade_101_empty",
        title: "A 101 response names no protocol on its Upgrade field",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_15_2_2],
    }

    /// A `426` response with no `Upgrade` field on it at all. The status code
    /// says the server refuses the request under the current protocol but might
    /// comply after the client upgrades, and the field is what names the
    /// protocol to upgrade *to* — so without it the response asks for a change
    /// it does not describe.
    ///
    /// **A trailer does not answer it**, and the site that reports this says so
    /// when it finds one: the requirement names a header field, and § 6.5.1
    /// forbids a trailer field unless the field's own definition permits it,
    /// which § 7.8 does not. That the placement is itself a defect is
    /// `trailer_fields_valid`'s finding rather than this entry's.
    ///
    /// `warn`, where the `101` pair is `error`: this response is ordinary HTTP a
    /// client can read to the end, and what it loses is the advice — the request
    /// can be made again over a protocol the client guesses at or gives up on.
    /// The conversation continues, badly.
    ///
    // cite(RFC 9110 § 15.5.22): "The server MUST send an Upgrade header field in a 426 response to indicate the required protocol(s) (Section 7.8)."
    UPGRADE_426_MISSING = {
        id: "upgrade_426_missing",
        title: "A 426 response carries no Upgrade field",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_15_5_22],
    }

    /// The field written on a `426`, and no protocol name on it. `Upgrade` is
    /// `#protocol`, so a value of none is a well-formed list and no grammar rule
    /// has anything to say — what is broken is the clause after *to indicate*,
    /// which is why this is the status's requirement and not the field's
    /// syntax. On any other response the same value is nobody's finding.
    ///
    /// Separated from the absent field for the reason the `101` pair is: a field
    /// that is not there is a server that never learned the requirement, and
    /// `Upgrade:` with nothing after it is a server that built the value from a
    /// list and found the list empty.
    ///
    // cite(RFC 9110 § 15.5.22): "The server MUST send an Upgrade header field in a 426 response to indicate the required protocol(s) (Section 7.8)."
    UPGRADE_426_EMPTY = {
        id: "upgrade_426_empty",
        title: "A 426 response names no protocol on its Upgrade field",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_15_5_22],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pair `docs/development.md` keeps apart everywhere: never written
    /// against written blank. Each status code's two rank together, because the
    /// *recipient* is in the same position for both halves of either pair.
    #[test]
    fn the_absent_field_and_the_blank_one_are_two_ids_of_one_rank() {
        assert_eq!(UPGRADE_101_MISSING.id, "upgrade_101_missing");
        assert_eq!(UPGRADE_101_EMPTY.id, "upgrade_101_empty");
        assert_eq!(UPGRADE_101_MISSING.default_severity, Severity::Error);
        assert_eq!(UPGRADE_101_EMPTY.default_severity, Severity::Error);
        assert_eq!(UPGRADE_426_MISSING.id, "upgrade_426_missing");
        assert_eq!(UPGRADE_426_EMPTY.id, "upgrade_426_empty");
        assert_eq!(UPGRADE_426_MISSING.default_severity, Severity::Warn);
        assert_eq!(UPGRADE_426_EMPTY.default_severity, Severity::Warn);
    }

    /// The id names the status code because the sentence requiring the field
    /// does: one entry over both codes would name two sections and carry
    /// neither onto a finding, and every site here knows which status it read.
    /// The ranks differ for a reason no shared entry could hold — a `101` has
    /// left HTTP and a `426` has not.
    #[test]
    fn each_status_codes_pair_names_its_own_sentence() {
        assert_eq!(UPGRADE_101_MISSING.spec, [RFC_9110_15_2_2]);
        assert_eq!(UPGRADE_426_MISSING.spec, [RFC_9110_15_5_22]);
        assert_ne!(
            UPGRADE_101_MISSING.default_severity,
            UPGRADE_426_MISSING.default_severity
        );
    }
}
