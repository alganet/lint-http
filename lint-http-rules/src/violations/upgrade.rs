// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Upgrade` defects — the field a `101` owes, and what is on it.
//!
//! A `101 (Switching Protocols)` is a connection changing hands: everything
//! after the response's empty line is spoken in another protocol. The status
//! code says the change happened and the `Upgrade` field says *what to*, which
//! is why RFC 9110 § 15.2.2 requires the field of the response rather than
//! merely recommending it — a client that has stopped speaking HTTP and does
//! not know what it is now speaking has no way to continue and no way to ask.
//!
//! **The subject is the field even though the requirement is written into a
//! status code's section**, which is the line `content_range` draws for the
//! same shape: the sentence is addressed to the field's presence, and it is the
//! field an operator would look for in the message. What the status code owes
//! *about itself* — that it may not be sent at all over a version with no
//! upgrade mechanism, that it may not switch to something nobody offered —
//! belongs to [`status`](crate::violations::status).
//!
//! Both entries are `error`, and it is the same argument in two halves: the
//! response has already ended the HTTP conversation, so there is no later
//! message in which the omission can be repaired.

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

defects! {
    /// A `101` response with no `Upgrade` field on it at all. The connection
    /// has changed protocol and the message that changed it does not say to
    /// what.
    ///
    // cite(RFC 9110 § 15.2.2): "The server MUST generate an Upgrade header field in the response that indicates which protocol(s) will be in effect after this response."
    UPGRADE_MISSING = {
        id: "upgrade_missing",
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
    UPGRADE_EMPTY = {
        id: "upgrade_empty",
        title: "A 101 response names no protocol on its Upgrade field",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_15_2_2],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pair `docs/development.md` keeps apart everywhere: never written
    /// against written blank. They rank together because the *recipient* is in
    /// the same position for both — the conversation has already left HTTP.
    #[test]
    fn the_absent_field_and_the_blank_one_are_two_ids_of_one_rank() {
        assert_eq!(UPGRADE_MISSING.id, "upgrade_missing");
        assert_eq!(UPGRADE_EMPTY.id, "upgrade_empty");
        assert_eq!(UPGRADE_MISSING.default_severity, Severity::Error);
        assert_eq!(UPGRADE_EMPTY.default_severity, Severity::Error);
    }
}
