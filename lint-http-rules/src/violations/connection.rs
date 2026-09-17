// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Connection` defects — what a sender may declare about the current hop.
//!
//! **One entry, and the field's syntax is not it.** `Connection =
//! #connection-option` with `connection-option = token`, so an empty member is
//! [`list`](crate::violations::list)'s and an octet no `tchar` admits is
//! [`token`](crate::violations::token)'s — every part of the value is written
//! in a production that already has a subject. What is left is the one
//! sentence § 7.6.1 spends on what an option may *name*.
//!
//! **The field is about a hop and the entry is about the message that outlives
//! it**, which is why the neighbouring subjects sort out the way they do:
//! [`trailer`](crate::violations::trailer) holds what naming a field here costs
//! a trailer section, and
//! [`field_connection_specific_forbidden`](crate::violations::field) holds the
//! versions that abolished the mechanism. This subject holds only the
//! declaration itself.

use crate::lint::Severity;
use crate::lint::Strength;
use crate::rules::SpecRef;
use crate::violations::defects;

/// The field itself: its grammar, the case-insensitivity of its options, and
/// the MUST NOT on naming a field the content's recipients are meant to read.
pub const RFC_9110_7_6_1: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("7.6.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6.1",
    note: "The field itself: its grammar, the case-insensitivity of its options, the note that an option need not correspond to a field present in the message, and the MUST NOT on naming a field that is intended for all recipients of the content",
};

defects! {
    /// A connection-option naming a field intended for all recipients of the
    /// content — `Cache-Control`, which § 7.6.1 names as the example.
    ///
    /// **A well-formed token in a well-formed list saying something a sender
    /// MUST NOT say**, which is the whole reason the field has a rule of its
    /// own rather than being one more `#token` reader. What the option means is
    /// "strip this before forwarding"; a field the content's recipients are
    /// meant to read is one every hop must pass on, so the two statements
    /// cannot both be honoured and the document resolves it against the sender.
    ///
    /// **The one field this catalogue can name, and the silence is not a
    /// verdict.** Whether some *other* field is intended for all recipients of
    /// the content is a property of that field's definition and not of anything
    /// the message carries, so a rule reporting only the named example is
    /// reporting what it can decide — never saying that listing anything else
    /// is allowed.
    ///
    /// `error`. A `MUST NOT` addressed to the sender, and what it costs is real
    /// without being what ranks it: a cache directive removed at the first
    /// intermediary is a directive the origin wrote and nobody downstream sees,
    /// while nothing is unreadable and the hop itself works exactly as
    /// declared.
    ///
    // cite(RFC 9110 § 7.6.1): "A sender MUST NOT send a connection option corresponding to a field that is intended for all recipients of the content.  For example, Cache-Control is never appropriate as a connection option (Section 5.2 of [CACHING])."
    CONNECTION_OPTION_FORBIDDEN = {
        id: "connection_option_forbidden",
        title: "A connection-option names a field the whole chain must read",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_7_6_1],
        strength: Strength::Must,
    }
}
