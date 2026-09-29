// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Challenge defects — the ways an authentication challenge is not one.
//!
//! The subject is `challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]`,
//! RFC 9110 § 11.3's production, and not the field carrying it.
//! `WWW-Authenticate` and `Proxy-Authenticate` are the same production under
//! two names, and the rules for them declare these same four rather than four
//! apiece.
//!
//! **None of § 11.2's three constructs is here.** `auth-scheme = token`,
//! `token68` and `auth-param` are all § 11.2's, shared with § 11.4's
//! `credentials`, so they live in [`crate::violations::auth_scheme`],
//! [`crate::violations::token68`] and [`crate::violations::auth_param`] where an
//! `Authorization` value reports the same ones.
//!
//! **One § 11.2 sentence is here anyway, and its scope term is why.** "Each
//! parameter name MUST only occur once per challenge" is stated about an
//! `auth-param` like the four ids above it, and it counts *per challenge* —
//! a unit § 11.4 has no analogue of, since a credentials field carries one
//! `credentials` and no list around it. So the sentence reaches one side of
//! the shared production and an `auth_param_duplicated` would claim a
//! requirement no document states about an `Authorization`. That is the
//! argument the paragraph above runs in the other direction: an id spelled
//! after one side of a shared production is a claim about which side wrote
//! it, and here the claim is the true one.
//!
//! **The `auth-param` four were the last to go, and this module's own doc had
//! predicted they would not have to.** It said the wording was the field's and
//! the ids were not, so "the day a second field reports one of these, the
//! sentence is what has to be parameterised, and no id has to change". The
//! sentences were parameterised and the prediction still failed, because a
//! `challenge_parameter_name_empty` reported about an `Authorization` names a
//! challenge that is not in the message. An id spelled after one side of a
//! shared production is a claim about which side wrote it.
//!
//! Two defects here are the *list's* rather than one challenge's — an empty
//! member, and a parameter arriving before any scheme — because
//! `WWW-Authenticate = #challenge` is read before its members are, and the
//! member boundaries are where those two are visible.

use crate::helpers::auth::AuthDefect;
use crate::lint::Severity;
use crate::lint::Strength;
use crate::rules::SpecRef;
use crate::violations::auth_param::{
    AUTH_PARAM_EQUALS_MISSING, AUTH_PARAM_NAME_CHARACTER_FORBIDDEN, AUTH_PARAM_NAME_EMPTY,
    AUTH_PARAM_REALM_QUOTING_INVALID, AUTH_PARAM_VALUE_CHARACTER_FORBIDDEN, AUTH_PARAM_VALUE_EMPTY,
    RFC_9110_11_5,
};
use crate::violations::auth_scheme::{AUTH_SCHEME_CHARACTER_FORBIDDEN, RFC_9110_11_2};
use crate::violations::list::LIST_MEMBER_EMPTY;
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

    /// One challenge naming the same `auth-param` twice: `Basic realm="a",
    /// realm="b"`.
    ///
    /// **Per challenge, and the sentence says so.** A `WWW-Authenticate` is
    /// `#challenge`, so one field value commonly carries several — § 11.6.1
    /// prints `Basic realm="simple", Newauth realm="apps", type=1,
    /// title="Login to \"apps\""` as the ordinary case — and each of them
    /// names its own `realm`. The count is therefore taken inside a challenge
    /// after the members have been grouped, never across a field line, and a
    /// walk that counted names per line would report § 11.6.1's own example.
    ///
    /// **The names are folded before they are compared**, because the same
    /// sentence says the name token is matched case-insensitively:
    /// `realm=a, REALM=b` is one parameter written twice and not two extension
    /// parameters.
    ///
    /// **The first occurrence is the one that binds**, which is what makes this
    /// a finding about the value rather than only about the count. Nothing in
    /// § 11.2 says which of the two a recipient takes, so what the entry
    /// reports is one protection space that two readers may describe
    /// differently — and every other duplicate walk in this catalogue grades
    /// the first and skips the rest, [`forwarded_parameter_duplicated`](crate::violations::forwarded::FORWARDED_PARAMETER_DUPLICATED)
    /// among them. A reader keeping the *last* is worse than one keeping
    /// either: appending a well-formed parameter to a malformed one then takes
    /// the malformed one's own finding away.
    ///
    /// **Not the list's, though the two above it are.** An empty member and a
    /// parameter before any scheme are visible at a member boundary, before
    /// anything is assembled; this is visible only once a challenge exists to
    /// count within.
    ///
    /// `error` from the keyword as it binds the sender. Both values are well
    /// formed and nothing is unreadable — what is lost is which of them the
    /// challenge meant.
    ///
    // cite(RFC 9110 § 11.2): "Authentication parameters are name/value pairs, where the name token is matched case-insensitively and each parameter name MUST only occur once per challenge."
    CHALLENGE_PARAMETER_DUPLICATED = {
        id: "challenge_parameter_duplicated",
        title: "Authentication challenge names one parameter more than once",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_11_2],
        strength: Strength::Must,
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

/// The defect a parsed [`AuthDefect`] reports as.
///
/// The last arm hands the question to [`crate::violations::quoted_string`],
/// which is the point of that module: a value between two DQUOTEs is the same
/// production in an `auth-param` as in a `Cache-Control` directive, and reports
/// under the same names.
pub fn challenge_defect(defect: AuthDefect<'_>) -> &'static ViolationDef {
    match defect {
        AuthDefect::EmptyMember => &CHALLENGE_MEMBER_EMPTY,
        AuthDefect::SchemeMissing => &CHALLENGE_SCHEME_MISSING,
        AuthDefect::SchemeCharacter(_) => &AUTH_SCHEME_CHARACTER_FORBIDDEN,
        AuthDefect::Token68ControlCharacter => &TOKEN68_WHITESPACE_OR_CONTROL_FORBIDDEN,
        AuthDefect::SuspiciousSingleToken(_) => &CHALLENGE_TOKEN68_INVALID,
        AuthDefect::ParameterMemberEmpty => &LIST_MEMBER_EMPTY,
        AuthDefect::EmptyParameterName => &AUTH_PARAM_NAME_EMPTY,
        AuthDefect::ParameterEqualsMissing(_) => &AUTH_PARAM_EQUALS_MISSING,
        AuthDefect::ParameterValueEmpty(_) => &AUTH_PARAM_VALUE_EMPTY,
        AuthDefect::ParameterNameCharacter(_) => &AUTH_PARAM_NAME_CHARACTER_FORBIDDEN,
        AuthDefect::ParameterValueCharacter(_) => &AUTH_PARAM_VALUE_CHARACTER_FORBIDDEN,
        AuthDefect::ParameterQuotedValue { defect, .. } => quoted_string_defect(defect),
        AuthDefect::ParameterDuplicated(_) => &CHALLENGE_PARAMETER_DUPLICATED,
        AuthDefect::RealmUnquoted(_) => &AUTH_PARAM_REALM_QUOTING_INVALID,
        AuthDefect::ParameterBws(_) => &crate::violations::bws::BWS_FORBIDDEN,
    }
}

/// Every defect in one field's `#challenge` list, as the id it reports under
/// and the sentence it renders, in the order the members were written.
///
/// **The reading is the production's and not the field's**, which is why both
/// fields defined as `#challenge` call it: § 11.7.1 defines
/// `Proxy-Authenticate` as § 11.6.1's field addressed to a different
/// recipient, and neither sentence says anything about the grammar that the
/// other does not. `field` is only how the sentence names what carried the
/// value.
///
/// **A defect of the *list* ends the reading, and a defect of a member does
/// not.** A value that could not be split into members has no members to
/// answer for, so it yields one finding; past that, every member is a subject
/// of its own and the comma beside a malformed one is not a reason to stop
/// reading the one after it.
///
/// The tuple is the judge-then-report shape: nothing here builds a `Violation`,
/// because the party and the context belong to the rule that asked.
// cite(RFC 9110 § 11.6.1): "WWW-Authenticate = #challenge"
// cite(RFC 9110 § 11.7.1): "Proxy-Authenticate = #challenge"
pub fn challenge_list_defects(field: &str, value: &str) -> Vec<(&'static ViolationDef, String)> {
    let challenges = match crate::helpers::auth::split_and_group_challenges(value) {
        Ok(c) => c,
        Err(defect) => return vec![(challenge_defect(defect), defect.message(field))],
    };
    challenges
        .iter()
        .filter_map(|challenge| {
            crate::helpers::auth::validate_challenge_syntax(challenge)
                .err()
                .map(|defect| (challenge_defect(defect), defect.message(field)))
        })
        .collect()
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
            (AuthDefect::EmptyMember, "challenge_member_empty"),
            (AuthDefect::SchemeMissing, "challenge_scheme_missing"),
            (
                AuthDefect::SchemeCharacter('@'),
                "auth_scheme_character_forbidden",
            ),
            (
                AuthDefect::Token68ControlCharacter,
                "token68_whitespace_or_control_forbidden",
            ),
            (
                AuthDefect::SuspiciousSingleToken("realm"),
                "challenge_token68_invalid",
            ),
            (AuthDefect::EmptyParameterName, "auth_param_name_empty"),
            (
                AuthDefect::ParameterEqualsMissing("flag"),
                "auth_param_equals_missing",
            ),
            (
                AuthDefect::ParameterValueEmpty("realm"),
                "auth_param_value_empty",
            ),
            (AuthDefect::ParameterMemberEmpty, "list_member_empty"),
            (
                AuthDefect::ParameterNameCharacter('@'),
                "auth_param_name_character_forbidden",
            ),
            (
                AuthDefect::ParameterValueCharacter('@'),
                "auth_param_value_character_forbidden",
            ),
            (
                AuthDefect::RealmUnquoted("foo"),
                "auth_param_realm_quoting_invalid",
            ),
            (AuthDefect::ParameterBws("realm = \"x\""), "bws_forbidden"),
            (
                AuthDefect::ParameterQuotedValue {
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
