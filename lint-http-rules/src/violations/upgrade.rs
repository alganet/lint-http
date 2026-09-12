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
//! **The fifth entry is not a status code's**, and it is the only one here that
//! is about a *different* field: a sender that writes `Upgrade` owes the field's
//! name as a `connection-option` on `Connection`, because that option is the
//! whole of what makes the field hop-by-hop. It sits in this subject for the
//! reason the registry family settled — the sentence is written once per field,
//! § 7.8 for this one and § 10.1.4 for `TE`, so the shape being identical does
//! not make the requirement shared, and [`te`](crate::violations::te) already
//! carries its own.
//!
//! **A sixth entry is the only one about a value.** The two `101` entries below
//! ask whether a protocol was named at all; RFC 6455 asks *which*, because a
//! WebSocket handshake's response carries the field with the value `websocket`
//! and nothing beside it. HTTP sets no such ceiling — § 15.2.2's field names
//! *which protocol(s) will be in effect* — so an entry about the value can only
//! come from the protocol the handshake belongs to.
//!
//! **Four of the six are the same two defects under each of the two status
//! codes**,
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
// The section a server's half of a WebSocket handshake is written from, defined
// where its first entry landed and named here for the one entry of this subject
// that is not HTTP's own requirement.
use crate::violations::sec_websocket_protocol::RFC_6455_4_2_2;

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

/// The field's own section, and the sentence that pairs it with `Connection`.
/// § 7.6.1 states the same obligation for every connection-specific field; this
/// is where it is written for this one, which is why the entry below can name a
/// field at all.
pub const RFC_9110_7_8: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("7.8"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-7.8",
    note: "Upgrade — the sender's obligation to name the field as a connection-option \
           beside it, and the `#protocol` grammar that makes the field's presence the \
           thing the obligation turns on",
};

defects! {
    /// A message carrying `Upgrade` and no `upgrade` connection-option in
    /// `Connection`. The field applies to the immediate connection; the option
    /// is what stops an intermediary from relaying it, and § 7.6.1 tells the
    /// recipient of a relayed one to ignore it — so the upgrade this message
    /// asks for is lost in both directions rather than merely mis-declared.
    ///
    /// **One entry where this catalogue usually writes two.** A `Connection`
    /// that names other options and a message with no `Connection` at all are
    /// two shapes and they are one absence: what is missing is the *option*, and
    /// it is equally missing whichever way the container turned out. **Split
    /// when the thing that is absent differs, not when what surrounds it does**
    /// — which is exactly what separates the two pairs above, where a field that
    /// was never written and a field written blank are two different absences of
    /// a protocol name. The site keeps both shapes in its message.
    ///
    /// **Asked only of the versions that have a `Connection` field**, which is
    /// the reading of whichever rule reports it and not this entry's: over
    /// HTTP/2 and HTTP/3 the option cannot be sent at all, so an entry demanding
    /// it would ask a sender to make its own message malformed.
    ///
    /// `warn` rather than `error` despite the MUST, and
    /// [`te_connection_option_missing`](crate::violations::te) is the sibling
    /// that ranked it first: nothing about this message is unreadable, and the
    /// defect is a guard that was not set rather than a statement that is wrong.
    /// What it risks is a *later* hop being misled, which no recipient of this
    /// message can detect.
    ///
    // cite(RFC 9110 § 7.8): "A sender of Upgrade MUST also send an "Upgrade" connection option in the Connection header field (Section 7.6.1) to inform intermediaries not to forward this field."
    UPGRADE_CONNECTION_OPTION_MISSING = {
        id: "upgrade_connection_option_missing",
        title: "Upgrade is sent with no upgrade connection-option in Connection",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_7_8],
    }

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

    /// A `101` whose `Upgrade` names a protocol the exchange it completes does
    /// not permit there.
    ///
    /// **The third thing that can be wrong with a `101`'s `Upgrade`, and the
    /// only one about the value rather than its presence.** The two entries
    /// above are read from § 15.2.2 alone and apply to every `101`; this one
    /// takes a second sentence from whichever protocol the handshake belongs
    /// to, because HTTP itself sets no ceiling — `Upgrade` names *which
    /// protocol(s) will be in effect*, and several is a value § 15.2.2 admits.
    /// RFC 6455 does set one: a WebSocket handshake's response carries the field
    /// *with value "websocket"*, so a member beside it is a protocol this
    /// connection cannot be speaking.
    ///
    /// Not [`STATUS_101_PROTOCOL_FORBIDDEN`](crate::violations::status), which
    /// is § 7.8's MUST NOT about switching to something the *client* never
    /// indicated. A client that offered `websocket, h2c` indicated both, so that
    /// entry is silent on a response naming both — and this one is not, because
    /// what the handshake permits is not a matter of what was offered.
    ///
    /// `_invalid` and not `_forbidden`: the value derives from `#protocol` and
    /// every member is a protocol name, and what it fails is a requirement past
    /// the grammar about which name may appear.
    ///
    /// `error`, with the `101` pair above and for their reason: the connection
    /// has been handed over, so there is no later message in which a client that
    /// cannot tell what it is now speaking can ask.
    ///
    // cite(RFC 6455 § 4.2.2): "An |Upgrade| header field with value "websocket" as per RFC 2616 [RFC2616]."
    UPGRADE_101_INVALID = {
        id: "upgrade_101_invalid",
        title: "A 101 response names a protocol its handshake does not permit",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_6455_4_2_2],
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
