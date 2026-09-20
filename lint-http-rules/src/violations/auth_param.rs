// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `auth-param` defects — the production's own, on whichever side of the
//! framework wrote it.
//!
//! `auth-param = token BWS "=" BWS ( token / quoted-string )` is RFC 9110
//! § 11.2's, read from both sides of the framework: a `WWW-Authenticate`
//! challenge and an `Authorization` credential are made of these.
//!
//! **Four of the five arrived here from [`challenge`](crate::violations::challenge),
//! and the argument for moving them is the one that module already made about
//! its neighbours.** § 11.2 defines three constructs — the `auth-scheme`, the
//! `token68` and this — and `challenge` moved the first two out on the grounds
//! that § 11.4's `credentials` is written from the same three. It kept the
//! third, and predicted in its own doc that "no id has to change" when a second
//! field came to report one. That was wrong in exactly the way the prediction
//! was checkable: `challenge_parameter_name_empty` names a challenge, and an
//! `Authorization` carries none. A defect of a production the two sides share
//! cannot be spelled after one of them.
//!
//! **What is still not here is what belongs to the list around them.** An empty
//! member is [`list`](crate::violations::list)'s — `#auth-param` is the list
//! construct and § 5.6.1.1 is the sentence — and a value between two DQUOTEs is
//! [`quoted_string`](crate::violations::quoted_string)'s, wherever it is
//! carried.
//!
//! **The lookalike is [`parameter`](crate::violations::parameter).** § 5.6.6's
//! `parameter = parameter-name "=" parameter-value` has no `OWS` anywhere
//! inside it and a Note saying so a second time; § 11.2's `auth-param` prints
//! `BWS` on both sides of its `=`. Two documents' worth of the same-looking
//! construct, and a member with no `=` breaks a different sentence in each — so
//! reporting an `Authorization` under `parameter_equals_missing` would carry a
//! requirement about whitespace this production explicitly admits.
//!
//! The subject file sits beside [`token68`](crate::violations::token68) for the
//! same reason that one does: § 11.2 defines three things, and each of them is
//! its own production with its own callers.

use crate::lint::Severity;
use crate::lint::Strength;
use crate::rules::SpecRef;
use crate::violations::auth_scheme::RFC_9110_11_2;
use crate::violations::defects;

/// The realm: what it names, and the one spelling a sender may write it in.
///
/// **It lives here rather than beside the challenge entries that also quote
/// it**, because the section is about a parameter and not about a field.
/// § 11.5 opens "The "realm" authentication parameter is reserved for use by
/// authentication schemes that wish to indicate a scope of protection" and
/// closes with a MUST about how to spell its value; a challenge is one of the
/// four things that carry it, and [`challenge`](crate::violations::challenge)
/// imports the reference from here for the entry that reads realms across a
/// response.
pub const RFC_9110_11_5: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("11.5"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-11.5",
    note: "Establishing a Protection Space (Realm) — a realm names one protection space, each with its own authentication scheme, and a response may carry several challenges of one scheme with different realms; the section closes by admitting one spelling of the value",
};

defects! {
    /// A member of an `#auth-param` list with no `=` in it: `Digest username`,
    /// a `WWW-Authenticate` challenge whose second parameter is a bare word.
    ///
    /// The `=` is written between the two halves and nothing brackets it, so a
    /// bare word among the parameters is not a flag whose value is implied — it
    /// derives from `auth-param` not at all. The `BWS` on either side of the
    /// delimiter is what a recipient parses away, and it cannot parse away a
    /// delimiter that is not there.
    ///
    /// **Not
    /// [`PARAMETER_EQUALS_MISSING`](crate::violations::parameter::PARAMETER_EQUALS_MISSING),
    /// and the module doc above is the argument.** The two productions are
    /// written in two documents and differ in exactly the whitespace one of
    /// them prints; borrowing that id would put § 5.6.6's Note behind a finding
    /// about a construct § 5.6.6 does not describe.
    ///
    /// `error`, from `auth-param`'s own production, which prints the `=`
    /// between the two halves. What follows is the cost and not the rank: the
    /// member is unreadable and the scheme's own definition decides what
    /// happens next, which for `Digest` is a credential no verifier can compute
    /// a response over and for a challenge is a parameter the client never
    /// sees.
    ///
    // cite(RFC 9110 § 11.2, label: auth-param grammar): "auth-param     = token BWS "=" BWS ( token / quoted-string )"
    AUTH_PARAM_EQUALS_MISSING = {
        id: "auth_param_equals_missing",
        title: "An authentication parameter is written without its '='",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_11_2],
        strength: Strength::Grammar,
    }

    /// A parameter whose name is empty — `=x`, which has a value and nothing
    /// for it to belong to. `token` has a floor of one character and the `BWS`
    /// beside the `=` is not part of the name, so there is no reading of the
    /// production under which the half before the delimiter may be absent.
    ///
    // cite(RFC 9110 § 11.2, label: auth-param grammar): "auth-param     = token BWS "=" BWS ( token / quoted-string )"
    AUTH_PARAM_NAME_EMPTY = {
        id: "auth_param_name_empty",
        title: "An authentication parameter has an empty name",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_11_2],
        strength: Strength::Grammar,
    }

    /// A non-`tchar` octet in a parameter name. The same complaint as
    /// [`AUTH_SCHEME_CHARACTER_FORBIDDEN`](crate::violations::auth_scheme::AUTH_SCHEME_CHARACTER_FORBIDDEN)
    /// under a different production, and kept apart from it for exactly that
    /// reason: an operator reading a report is told which half of the value the
    /// octet was in. Kept apart from
    /// [`TOKEN_CHARACTER_FORBIDDEN`](crate::violations::token::TOKEN_CHARACTER_FORBIDDEN)
    /// for the same reason one step further out — a `token` is what a dozen
    /// productions are made of, and an operator silencing this one is silencing
    /// authentication parameters rather than every token on the wire.
    ///
    // cite(RFC 9110 § 11.2, label: auth-param grammar): "auth-param     = token BWS "=" BWS ( token / quoted-string )"
    AUTH_PARAM_NAME_CHARACTER_FORBIDDEN = {
        id: "auth_param_name_character_forbidden",
        title: "An authentication parameter name holds a character outside token",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_11_2],
        strength: Strength::Grammar,
    }

    /// A parameter whose `=` is written and whose value is not: `realm=`, or
    /// `realm= ,`. **Not
    /// [`AUTH_PARAM_EQUALS_MISSING`], and the
    /// difference is what the sender left out.** One entry answered both while
    /// the two shapes reached it through one variant, and they are two mistakes:
    /// a member with no `=` was written as though the name were a flag, and a
    /// member with an `=` and nothing after it was written as though the value
    /// were optional. `token` and `quoted-string` both have a floor of one
    /// character, so neither alternative derives the empty value.
    ///
    // cite(RFC 9110 § 11.2, label: auth-param grammar): "auth-param     = token BWS "=" BWS ( token / quoted-string )"
    AUTH_PARAM_VALUE_EMPTY = {
        id: "auth_param_value_empty",
        title: "An authentication parameter is written with no value after its '='",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_11_2],
        strength: Strength::Grammar,
    }

    /// A non-`tchar` octet in an unquoted parameter value. The value has a
    /// second alternative — the quoted one — which is where such an octet is
    /// admitted, so this is also the defect whose fix is most often a pair of
    /// DQUOTEs rather than a different character.
    ///
    // cite(RFC 9110 § 11.2, label: auth-param grammar): "auth-param     = token BWS "=" BWS ( token / quoted-string )"
    AUTH_PARAM_VALUE_CHARACTER_FORBIDDEN = {
        id: "auth_param_value_character_forbidden",
        title: "An authentication parameter value holds a character outside token",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_11_2],
        strength: Strength::Grammar,
    }

    /// A `realm` written as a `token`: `Basic realm=foo`, where § 11.5 admits
    /// only `realm="foo"`.
    ///
    /// **`_invalid` and not `_malformed`, because the value derives.**
    /// `auth-param` offers `token / quoted-string` and produces the unquoted
    /// spelling as readily as the quoted one; § 11.5 then removes the choice
    /// for this one parameter, and says why in the same breath — "for
    /// historical reasons". That is the sibling relation to
    /// [`DIGEST_CREDENTIALS_QUOTING_INVALID`](crate::violations::digest_credentials::DIGEST_CREDENTIALS_QUOTING_INVALID),
    /// which is RFC 7616 § 3.4 saying the identical thing about seven Digest
    /// parameters at once, and which keeps the one value both sentences bind: a
    /// realm in Digest credentials is answered by the document that defines
    /// that credential, so one repair stays one finding.
    ///
    /// **The subject is the parameter and not the field, which is the whole of
    /// why it is here.** § 11.5 binds "a sender" — every sender — and a realm
    /// is written by a server in a `WWW-Authenticate` or `Proxy-Authenticate`
    /// challenge and by a client in an `Authorization` or `Proxy-Authorization`
    /// credential. All four are `auth-scheme [ 1*SP ( token68 / #auth-param ) ]`
    /// and all four reach this through one reading of it. An id naming any one
    /// of them would have been wrong for the other three.
    ///
    /// **The grammar outranks it.** A realm that is unquoted *and* holds an
    /// octet no `token` admits is answered by
    /// [`AUTH_PARAM_VALUE_CHARACTER_FORBIDDEN`] instead: the historical reason
    /// is a spelling a recipient may still read, and a value outside both
    /// alternatives is not. So this is reported only where the parameters
    /// carrying it are otherwise well formed.
    ///
    /// `error`, from the keyword as it binds the sender. What the next sentence
    /// grants is the recipient's leniency and not the sender's — "Recipients
    /// might have to support both token and quoted-string syntax for maximum
    /// interoperability" describes what a parser has to survive, and says
    /// nothing about what a sender may generate.
    ///
    // cite(RFC 9110 § 11.5): "For historical reasons, a sender MUST only generate the quoted-string syntax."
    AUTH_PARAM_REALM_QUOTING_INVALID = {
        id: "auth_param_realm_quoting_invalid",
        title: "A realm is written in the syntax its section refuses",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_11_5],
        strength: Strength::Must,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::violations::parameter::PARAMETER_EQUALS_MISSING;

    /// The two ids for the two productions, and the assertion is the claim:
    /// they are never interchangeable, because the sections they name say
    /// different things about the whitespace beside the delimiter.
    #[test]
    fn the_two_missing_delimiters_are_two_ids() {
        assert_ne!(AUTH_PARAM_EQUALS_MISSING.id, PARAMETER_EQUALS_MISSING.id);
        let [auth] = AUTH_PARAM_EQUALS_MISSING.spec else {
            panic!("one sentence")
        };
        let [parameter] = PARAMETER_EQUALS_MISSING.spec else {
            panic!("one sentence")
        };
        assert_ne!(auth.section, parameter.section);
    }
}
