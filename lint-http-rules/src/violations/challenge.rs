// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Challenge defects — the ways an authentication challenge is not one.
//!
//! The subject is `challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]`,
//! RFC 9110 § 11.3's production, and not the field carrying it.
//! `WWW-Authenticate` is the one this crate reads today; `Proxy-Authenticate`
//! is the same production under a different name, and a rule for it declares
//! these same ten rather than ten of its own.
//!
//! The scheme at the front of a challenge is *not* here, and neither is the
//! `token68` after it. `auth-scheme = token` and `token68` are both § 11.2's,
//! shared with § 11.4's `credentials`, so they live in
//! [`crate::violations::auth_scheme`] and [`crate::violations::token68`] where
//! an `Authorization` value reports the same ones.
//!
//! **The wording is still the field's, and that is the part left to move.**
//! The messages come from [`crate::helpers::auth::ChallengeDefect`], which was
//! written for one field and says `WWW-Authenticate` in every sentence. The
//! ids do not, so the catalogue is already right; the day a second field
//! reports one of these, the sentence is what has to be parameterised, and no
//! id has to change. That is the order this campaign wants those two things
//! done in.
//!
//! Two defects here are the *list's* rather than one challenge's — an empty
//! member, and a parameter arriving before any scheme — because
//! `WWW-Authenticate = #challenge` is read before its members are, and the
//! member boundaries are where those two are visible.

use crate::helpers::auth::ChallengeDefect;
use crate::lint::Severity;
use crate::lint::Strength;
use crate::rules::SpecRef;
use crate::violations::auth_scheme::{AUTH_SCHEME_CHARACTER_FORBIDDEN, RFC_9110_11_2};
use crate::violations::quoted_string::quoted_string_defect;
use crate::violations::token68::TOKEN68_WHITESPACE_OR_CONTROL_FORBIDDEN;
use crate::violations::{defects, ViolationDef};

/// The challenge itself: a scheme, and then one of two alternatives.
pub const RFC_9110_11_3: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("11.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-11.3",
    note: "Challenge and Response — `challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]`",
};

/// The field as a list, which is what the two member defects are answered by.
/// Protection spaces: what a `realm` names, and what a server is partitioning
/// its resources into when it writes one.
pub const RFC_9110_11_5: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("11.5"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-11.5",
    note: "Establishing a Protection Space (Realm) — a realm names one protection space, each with its own authentication scheme, and a response may carry several challenges of one scheme with different realms",
};

pub const RFC_9110_11_6_1: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("11.6.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-11.6.1",
    note: "`WWW-Authenticate = #challenge` — the list whose members are grouped into challenges before any of them is read",
};

defects! {
    /// An empty member of the field's `#challenge` list — a doubled comma, or
    /// one at either end. **The only id for a challenge with nothing in it**,
    /// because a challenge is a member of this list: the grouping refuses every
    /// empty member, so no reader downstream is handed one to call empty on its
    /// own account. It may sit between two challenges that are each well
    /// formed, which is why the sentence it cites is the list's.
    ///
    // cite(RFC 9110 § 11.6.1): "WWW-Authenticate = #challenge"
    CHALLENGE_MEMBER_EMPTY = {
        id: "challenge_member_empty",
        title: "Authentication challenge list has an empty member",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_11_6_1],
        strength: Strength::Grammar,
    }

    /// An `auth-param` where the list has not had an `auth-scheme` yet. The
    /// parameter belongs to a challenge, and there is no challenge for it to
    /// belong to.
    ///
    // cite(RFC 9110 § 11.3): "challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]"
    CHALLENGE_SCHEME_MISSING = {
        id: "challenge_scheme_missing",
        title: "Authentication parameter arrives before any scheme",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_11_3],
        strength: Strength::Grammar,
    }

    /// A single bare word after the scheme: `token68` by the grammar, and an
    /// `auth-param` whose value someone forgot by eye. The one entry here that
    /// no sentence refuses — which is why it carries no `spec` and defaults to
    /// `info`. An operator reading challenges as data leaves it there; one who
    /// has been bitten by `Bearer realm` raises it. Neither was expressible
    /// while a rule had one severity, and flattening the heuristic in with the
    /// grammar verdicts is what made it look like one.
    CHALLENGE_TOKEN68_INVALID = {
        id: "challenge_token68_invalid",
        title: "Authentication token68 is indistinguishable from a parameter",
        message: "",
        default_severity: Severity::Info,
        spec: &[],
    }

    /// A parameter whose name is empty — `=x`, which has a value and nothing
    /// for it to belong to.
    ///
    // cite(RFC 9110 § 11.2): "auth-param     = token BWS "=" BWS ( token / quoted-string )"
    CHALLENGE_PARAMETER_NAME_EMPTY = {
        id: "challenge_parameter_name_empty",
        title: "Authentication parameter has an empty name",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_11_2],
        strength: Strength::Grammar,
    }

    /// An `auth-param` with no value. The production writes the `"="` and both
    /// alternatives after it, so the value is not optional — `Basic realm` is
    /// the shortest way to reach this.
    ///
    // cite(RFC 9110 § 11.2): "auth-param     = token BWS "=" BWS ( token / quoted-string )"
    CHALLENGE_PARAMETER_VALUE_MISSING = {
        id: "challenge_parameter_value_missing",
        title: "Authentication parameter has no value",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_11_2],
        strength: Strength::Grammar,
    }

    /// A non-`tchar` octet in an `auth-param` name. The same complaint as
    /// [`AUTH_SCHEME_CHARACTER_FORBIDDEN`] under a different production,
    /// and kept apart from it for exactly that reason: an operator reading a
    /// report is told which half of the challenge the octet was in.
    ///
    // cite(RFC 9110 § 11.2): "auth-param     = token BWS "=" BWS ( token / quoted-string )"
    CHALLENGE_PARAMETER_NAME_CHARACTER_FORBIDDEN = {
        id: "challenge_parameter_name_character_forbidden",
        title: "Authentication parameter name holds a character outside token",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_11_2],
        strength: Strength::Grammar,
    }

    /// A non-`tchar` octet in an unquoted `auth-param` value. The value has a
    /// second alternative — the quoted one — which is where such an octet is
    /// admitted, so this is also the defect whose fix is most often a pair of
    /// DQUOTEs rather than a different character.
    ///
    // cite(RFC 9110 § 11.2): "auth-param     = token BWS "=" BWS ( token / quoted-string )"
    CHALLENGE_PARAMETER_VALUE_CHARACTER_FORBIDDEN = {
        id: "challenge_parameter_value_character_forbidden",
        title: "Authentication parameter value holds a character outside token",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_11_2],
        strength: Strength::Grammar,
    }

    /// One `realm` value carried by challenges of two different auth-schemes in
    /// one response.
    ///
    /// **The third entry here that is the list's rather than one challenge's**,
    /// and the only one that is not about how the list was written: the two
    /// above are visible at a member boundary, this one is visible only across
    /// members, because a realm advertised once is nothing at all.
    ///
    /// **`_ambiguous`, and the ending's own words are the argument**: the
    /// report is about the ambiguity and not about a defect the message can be
    /// shown to have. § 11.5 partitions a server's resources into protection
    /// spaces, each with its own authentication scheme, so a realm spanning two
    /// schemes names one space twice over — and a client selecting stored
    /// credentials for that realm has nothing in the response to tell it which
    /// space it is authenticating to.
    ///
    /// **The converse is explicitly permitted and is not this**: § 11.5 says a
    /// response may carry several challenges of one scheme with *different*
    /// realms, which is a server offering several spaces rather than blurring
    /// one. That is why the count is schemes-per-realm and never the other way
    /// round.
    ///
    /// **Nothing forbids it**, which is what keeps the entry at the ending it
    /// has: no MUST, no SHOULD, and two responses that differ only in this are
    /// both conforming. `warn`, which is where this ending sits and where it
    /// stops — an `error` would claim a defect the message cannot be shown to
    /// have.
    ///
    // cite(RFC 9110 § 11.5): "These realms allow the protected resources on a server to be partitioned into a set of protection spaces, each with its own authentication scheme and/or authorization database."
    CHALLENGE_REALM_AMBIGUOUS = {
        id: "challenge_realm_ambiguous",
        title: "One realm is advertised by two authentication schemes",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_11_5],
    }
}

/// The defect a parsed [`ChallengeDefect`] reports as.
///
/// The last arm hands the question to [`crate::violations::quoted_string`],
/// which is the point of that module: a value between two DQUOTEs is the same
/// production in an `auth-param` as in a `Cache-Control` directive, and reports
/// under the same names.
pub fn challenge_defect(defect: ChallengeDefect<'_>) -> &'static ViolationDef {
    match defect {
        ChallengeDefect::EmptyMember => &CHALLENGE_MEMBER_EMPTY,
        ChallengeDefect::SchemeMissing => &CHALLENGE_SCHEME_MISSING,
        ChallengeDefect::SchemeCharacter(_) => &AUTH_SCHEME_CHARACTER_FORBIDDEN,
        ChallengeDefect::Token68ControlCharacter => &TOKEN68_WHITESPACE_OR_CONTROL_FORBIDDEN,
        ChallengeDefect::SuspiciousSingleToken(_) => &CHALLENGE_TOKEN68_INVALID,
        ChallengeDefect::EmptyParameterName => &CHALLENGE_PARAMETER_NAME_EMPTY,
        ChallengeDefect::ParameterMissingValue(_) => &CHALLENGE_PARAMETER_VALUE_MISSING,
        ChallengeDefect::ParameterNameCharacter(_) => &CHALLENGE_PARAMETER_NAME_CHARACTER_FORBIDDEN,
        ChallengeDefect::ParameterValueCharacter(_) => {
            &CHALLENGE_PARAMETER_VALUE_CHARACTER_FORBIDDEN
        }
        ChallengeDefect::ParameterQuotedValue { defect, .. } => quoted_string_defect(defect),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ten variants, ten ids, spelled out — two of them belonging to other
    /// subjects, which are the mappings most worth pinning: the scheme is
    /// § 11.2's `auth-scheme` wherever it was written, and a quoted value
    /// inside an `auth-param` is a `quoted-string` defect and not a challenge
    /// one.
    #[test]
    fn each_challenge_defect_maps_to_its_own_id() {
        for (defect, id) in [
            (ChallengeDefect::EmptyMember, "challenge_member_empty"),
            (ChallengeDefect::SchemeMissing, "challenge_scheme_missing"),
            (
                ChallengeDefect::SchemeCharacter('@'),
                "auth_scheme_character_forbidden",
            ),
            (
                ChallengeDefect::Token68ControlCharacter,
                "token68_whitespace_or_control_forbidden",
            ),
            (
                ChallengeDefect::SuspiciousSingleToken("realm"),
                "challenge_token68_invalid",
            ),
            (
                ChallengeDefect::EmptyParameterName,
                "challenge_parameter_name_empty",
            ),
            (
                ChallengeDefect::ParameterMissingValue("realm"),
                "challenge_parameter_value_missing",
            ),
            (
                ChallengeDefect::ParameterNameCharacter('@'),
                "challenge_parameter_name_character_forbidden",
            ),
            (
                ChallengeDefect::ParameterValueCharacter('@'),
                "challenge_parameter_value_character_forbidden",
            ),
            (
                ChallengeDefect::ParameterQuotedValue {
                    name: "realm",
                    value: "\"x",
                    defect: crate::helpers::quoted_string::QuotedStringDefect::NotQuoted,
                },
                "quoted_string_delimiter_missing",
            ),
        ] {
            assert_eq!(challenge_defect(defect).id, id);
        }
    }

    /// The heuristic is the one entry with no sentence behind it, and it sits
    /// below every grammar verdict this rule can reach — which is what a rule
    /// reporting all of them at one severity could never have said.
    #[test]
    fn the_heuristic_is_the_one_without_a_spec() {
        assert!(CHALLENGE_TOKEN68_INVALID.spec.is_empty());
        assert_eq!(CHALLENGE_TOKEN68_INVALID.default_severity, Severity::Info);
        assert_eq!(CHALLENGE_MEMBER_EMPTY.default_severity, Severity::Error);
    }
}
