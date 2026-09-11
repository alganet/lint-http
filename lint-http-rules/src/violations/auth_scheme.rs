// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Authentication scheme defects — the name at the front of a challenge and of
//! credentials alike.
//!
//! `auth-scheme = token` is written once in RFC 9110 § 11.2 and used by both
//! sides of the framework: § 11.3's `challenge`, which a server writes into
//! `WWW-Authenticate`, and § 11.4's `credentials`, which a user agent writes
//! into `Authorization`. So an octet no `token` admits is one defect with two
//! senders, and this is where it lives — not in
//! [`crate::violations::challenge`], which is where it was first written and
//! where it was named after the half of the framework that happened to be
//! converted first.
//!
//! The messages still name the field, because the helper enums that produce
//! them do; the id does not, which is the half that has to be right while
//! configuration is being written against it.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// Where the scheme is defined and where the registry that ought to hold it
/// is named.
pub const RFC_9110_11_1: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("11.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-11.1",
    note: "Authentication Scheme — `auth-scheme = token`, and where new schemes are registered",
};

/// The framework's vocabulary: the scheme's `token`, the `auth-param` pair
/// built on it, and the `token68` alternative. One section behind all three,
/// which is why `challenge` and `credentials` both point their parameter
/// defects here.
pub const RFC_9110_11_2: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("11.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-11.2",
    note: "Authentication Parameters — `auth-scheme = token`, `auth-param = token BWS \"=\" BWS ( token / quoted-string )`, and `token68`'s alphabet",
};

defects! {
    /// A non-`tchar` octet in the scheme name. A recipient matches the scheme
    /// case-insensitively against a registry, so an octet outside the class is
    /// a name nothing can be looked up under — whichever direction the field
    /// was travelling.
    ///
    // cite(RFC 9110 § 11.1): "It uses a case-insensitive token to identify the authentication scheme"
    AUTH_SCHEME_CHARACTER_FORBIDDEN = {
        id: "auth_scheme_character_forbidden",
        title: "Authentication scheme holds a character outside token",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_11_2],
    }

    /// A scheme name that is a perfectly good `token` and is not one the
    /// deployment expects. Nothing about the value is malformed: what is
    /// reported is that a recipient meeting it has nothing to look it up in.
    ///
    /// **The comparison is against the operator's `allowed` list, not against
    /// the registry itself**, and that is a deliberate stand-in rather than an
    /// approximation of one: this crate ships no snapshot of IANA's table, a
    /// snapshot would be stale the day it was written, and a deployment
    /// generally accepts far fewer schemes than are registered. So the list is
    /// the operator's answer to § 11.1's *ought to*, and the id names the
    /// sentence rather than the list — an operator silencing this is saying
    /// "unrecognised schemes are fine here", which is what they mean.
    ///
    /// `warn`, and the sentence quoted is why it is not an error: schemes ought
    /// to be registered, and a private scheme between two parties that know
    /// each other breaks nothing.
    ///
    // cite(RFC 9110 § 11.1): "New and existing authentication schemes are specified independently and ought to be registered"
    AUTH_SCHEME_UNREGISTERED = {
        id: "auth_scheme_unregistered",
        title: "Authentication scheme is not one the deployment recognises",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_11_1],
    }
}
