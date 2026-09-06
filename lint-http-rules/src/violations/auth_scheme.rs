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
        spec: Some(RFC_9110_11_2),
    }
}
