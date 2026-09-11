// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Credentials defects — the request half of the authentication framework.
//!
//! `credentials = auth-scheme [ 1*SP ( token68 / #auth-param ) ]` is RFC 9110
//! § 11.4's, and it is `challenge`'s mirror image: the same vocabulary, written
//! by the user agent instead of by the server. The subject is the production,
//! so `Proxy-Authorization` reports these same three.
//!
//! Only three, because this is deliberately the shallow reading. What the
//! credentials have to *be* is the scheme's own document's question — RFC 7617
//! for `Basic`, RFC 6750 for `Bearer` — and those have their own subjects. What
//! is here is the framework's shape: something is there, and the octets are
//! ones a field value may carry.
//!
//! The scheme name is not here either: `auth-scheme = token` is § 11.2's and
//! shared with the challenge side, so it reports as
//! [`crate::violations::auth_scheme`]'s one defect from both directions.

use crate::helpers::auth::AuthorizationDefect;
use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::auth_scheme::AUTH_SCHEME_CHARACTER_FORBIDDEN;
use crate::violations::{defects, ViolationDef};

/// The production: a scheme, and then — optionally, as far as the framework is
/// concerned — what the scheme's own document asks for.
pub const RFC_9110_11_4: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("11.4"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-11.4",
    note: "Credentials — `credentials = auth-scheme [ 1*SP ( token68 / #auth-param ) ]`, the request-side mirror of `challenge`",
};

/// The field, and the sentence that says its value carries the user agent's
/// authentication information — which is what makes a bare scheme a finding
/// where the framework grammar alone would not.
pub const RFC_9110_11_6_2: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("11.6.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-11.6.2",
    note: "Authorization — the field's value *consists of* credentials, which is stricter than § 11.4's optional second half",
};

defects! {
    /// A field that is present and carries nothing at all. `credentials` opens
    /// with an `auth-scheme`, which is a `token`, so the empty value derives
    /// from nothing.
    ///
    // cite(RFC 9110 § 11.4): "credentials = auth-scheme [ 1*SP ( token68 / #auth-param ) ]"
    CREDENTIALS_EMPTY = {
        id: "credentials_empty",
        title: "Credentials are empty",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_11_6_2],
    }

    /// A scheme with nothing after it. § 11.4's grammar makes the second half
    /// optional, so this defect is *not* the framework's — it is every
    /// concrete scheme's. `Basic` (RFC 7617), `Bearer` (RFC 6750) and `Digest`
    /// (RFC 7616) each mandate credentials, and the field's own definition says
    /// its value consists of them, which is the sentence carried here.
    ///
    // cite(RFC 9110 § 11.6.2): "Its value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested"
    CREDENTIALS_MISSING = {
        id: "credentials_missing",
        title: "Credentials are absent after the scheme",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_11_6_2],
    }

    /// A control octet in the credentials. `error` by default, for the reason
    /// every other subject's invisible defect earns it: neither alternative of
    /// the production admits one — `token68`'s alphabet has none and an
    /// `auth-param` is tokens and quoted-strings — so an octet below %x20 in a
    /// value this shape is something that happened to it in transit.
    ///
    // cite(RFC 9110 § 11.4): "credentials = auth-scheme [ 1*SP ( token68 / #auth-param ) ]"
    CREDENTIALS_CONTROL_CHARACTER_FORBIDDEN = {
        id: "credentials_control_character_forbidden",
        title: "Credentials hold a control character",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_11_4],
    }
}

/// The defect a parsed [`AuthorizationDefect`] reports as.
///
/// The scheme arm leaves this subject on purpose: an octet no `token` admits is
/// the same defect in a `WWW-Authenticate` challenge, and reports under the
/// same id.
pub fn credentials_defect(defect: AuthorizationDefect) -> &'static ViolationDef {
    match defect {
        AuthorizationDefect::Empty => &CREDENTIALS_EMPTY,
        AuthorizationDefect::SchemeCharacter(_) => &AUTH_SCHEME_CHARACTER_FORBIDDEN,
        AuthorizationDefect::MissingCredentials => &CREDENTIALS_MISSING,
        AuthorizationDefect::CredentialsControlCharacter => {
            &CREDENTIALS_CONTROL_CHARACTER_FORBIDDEN
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Four variants, four ids — one of which is the challenge side's too,
    /// which is the row this test exists for.
    #[test]
    fn each_authorization_defect_maps_to_its_own_id() {
        for (defect, id) in [
            (AuthorizationDefect::Empty, "credentials_empty"),
            (
                AuthorizationDefect::SchemeCharacter('@'),
                "auth_scheme_character_forbidden",
            ),
            (
                AuthorizationDefect::MissingCredentials,
                "credentials_missing",
            ),
            (
                AuthorizationDefect::CredentialsControlCharacter,
                "credentials_control_character_forbidden",
            ),
        ] {
            assert_eq!(credentials_defect(defect).id, id);
        }
    }

    /// The same defect, reported from both directions, is one entry: a server
    /// writing `b@d` into a challenge and a user agent writing it into
    /// `Authorization` are configured together, which is the whole reason the
    /// scheme is not one of this subject's own.
    #[test]
    fn the_scheme_defect_is_the_challenge_sides_too() {
        assert!(std::ptr::eq(
            credentials_defect(AuthorizationDefect::SchemeCharacter('@')),
            crate::violations::challenge::challenge_defect(
                crate::helpers::auth::ChallengeDefect::SchemeCharacter('@')
            ),
        ));
    }
}
