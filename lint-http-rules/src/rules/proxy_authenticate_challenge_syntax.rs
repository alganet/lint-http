// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::auth_scheme::{AUTH_SCHEME_CHARACTER_FORBIDDEN, RFC_9110_11_2};
use crate::violations::challenge::{
    CHALLENGE_MEMBER_EMPTY, CHALLENGE_PARAMETER_NAME_CHARACTER_FORBIDDEN,
    CHALLENGE_PARAMETER_NAME_EMPTY, CHALLENGE_PARAMETER_VALUE_CHARACTER_FORBIDDEN,
    CHALLENGE_PARAMETER_VALUE_MISSING, CHALLENGE_SCHEME_MISSING, CHALLENGE_TOKEN68_INVALID,
    RFC_9110_11_3, RFC_9110_11_6_1,
};
use crate::violations::proxy_authenticate::RFC_9110_11_7_1;
use crate::violations::quoted_pair::QUOTED_PAIR_MALFORMED;
use crate::violations::quoted_string::{
    QUOTED_STRING_CONTROL_CHARACTER_FORBIDDEN, QUOTED_STRING_DELIMITER_MISSING,
    QUOTED_STRING_QUOTE_ESCAPE_MISSING, RFC_9110_5_6_4,
};
use crate::violations::token68::TOKEN68_WHITESPACE_OR_CONTROL_FORBIDDEN;
use crate::violations::ViolationDef;

/// The response-side twin of `www_authenticate_challenge_syntax`, over the
/// field § 11.7.1 defines in § 11.6.1's terms.
///
/// **Not one entry of its own.** `challenge = auth-scheme [ 1*SP ( token68 /
/// #auth-param ) ]` is § 11.3's production and neither field owns it, so what
/// is wrong with a challenge is the same defect wherever it was written and
/// reports under the same id. What this rule adds is a second *reader*, and the
/// only thing that had to move first was the sentence: the messages named
/// `WWW-Authenticate` in every arm, so a `Proxy-Authenticate` reported through
/// them would have named the wrong field on a true finding.
///
/// **Why it existed as a gap at all.** `Proxy-Authenticate: Basic
/// realm="unfinished` on a `407` drew nothing, where the identical value in a
/// `WWW-Authenticate` is an `error`. Nothing decided that; the rule that owns
/// the production read one field because it was written for one field, and its
/// own module doc had recorded the other as the same production under a
/// different name for as long as it had said anything.
///
/// **The § 11.7.1 difference does not reach the grammar.** That section limits
/// the field to the next outbound client on the response chain, which is why
/// `proxy_authenticate_redundant` is advisory about a `Proxy-Authenticate`
/// outside a `407`, and why an *absent* one is weaker evidence about the proxy
/// that generated the status than a missing `WWW-Authenticate` is about an
/// origin. None of that bears on whether a challenge that *is* there parses:
/// the one recipient the field addresses has to read it, and a value the
/// production does not derive is unreadable to that recipient exactly as it
/// would be to any other.
pub struct ProxyAuthenticateChallengeSyntax;

/// The same thirteen `www_authenticate_challenge_syntax` declares, because they
/// are the production's rather than the field's. A defect list that differed
/// between the two fields would be claiming the grammar does.
static DECLARED: &[&ViolationDef] = &[
    &CHALLENGE_MEMBER_EMPTY,
    &CHALLENGE_SCHEME_MISSING,
    &AUTH_SCHEME_CHARACTER_FORBIDDEN,
    &TOKEN68_WHITESPACE_OR_CONTROL_FORBIDDEN,
    &CHALLENGE_TOKEN68_INVALID,
    &CHALLENGE_PARAMETER_NAME_EMPTY,
    &CHALLENGE_PARAMETER_VALUE_MISSING,
    &CHALLENGE_PARAMETER_NAME_CHARACTER_FORBIDDEN,
    &CHALLENGE_PARAMETER_VALUE_CHARACTER_FORBIDDEN,
    &QUOTED_STRING_DELIMITER_MISSING,
    &QUOTED_PAIR_MALFORMED,
    &QUOTED_STRING_QUOTE_ESCAPE_MISSING,
    &QUOTED_STRING_CONTROL_CHARACTER_FORBIDDEN,
];

impl RuleMeta for ProxyAuthenticateChallengeSyntax {
    fn id(&self) -> &'static str {
        "proxy_authenticate_challenge_syntax"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn description(&self) -> &'static str {
        "The `Proxy-Authenticate` response header field carries the challenges a proxy applies to a request, and RFC 9110 §11.7.1 defines it as `#challenge` — the same production `WWW-Authenticate` is a list of. This rule reads that grammar over this field: each member is an `auth-scheme` (a `token`) followed, optionally, by a `token68` or a comma-separated list of `auth-param`.\n\nEvery defect it reports is declared by `www_authenticate_challenge_syntax` too, under the same id, because the defect belongs to §11.3's production and not to the field that carried it. The two rules are separate so that a deployment can silence the grammar on one field without silencing it on the other.\n\n**What §11.7.1 says about this field does not reach its grammar.** The section limits `Proxy-Authenticate` to the next outbound client on the response chain, which is why a `Proxy-Authenticate` on a status other than `407` is only advisory (`status_code_semantics`) and why an absent one is weaker evidence about the proxy that generated a `407`. A challenge that *is* present still has to be readable by the one recipient the field addresses, and a value the production does not derive is not.\n\nThe rule says nothing about which schemes are acceptable — that is `auth_scheme_registered`'s allowlist — nor about `Proxy-Authorization`, which carries `credentials` rather than `challenge`."
    }

    /// § 11.6.1 is here on a `Proxy-Authenticate` rule because two of the
    /// defects reported are the *list's* rather than one challenge's, and
    /// § 11.6.1 is where the catalogue records `#challenge` — which is the
    /// production § 11.7.1 then defines this field as. A rule declares the
    /// sections its entries cite, and those entries cite the place the list
    /// construct is written down.
    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_9110_11_7_1,
            RFC_9110_11_6_1,
            RFC_9110_11_3,
            RFC_9110_11_2,
            RFC_9110_5_6_4,
        ]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    fn party(&self) -> crate::rules::RuleParty {
        // Whoever wrote the response wrote this field. A proxy inserting its
        // own challenge occupies the server position on the seam this reads,
        // which is what `Party::Server` names — the sender of the response,
        // not the origin specifically.
        crate::rules::RuleParty::Presumed(crate::lint::Party::Server)
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 407 Proxy Authentication Required\nProxy-Authenticate: Basic realm=\"proxy\"",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 407 Proxy Authentication Required\nProxy-Authenticate: Negotiate YIIFxAYGKwYBBQUCoIIFuDCCBbSgh==",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 407 Proxy Authentication Required\nProxy-Authenticate: Basic realm=\"unfinished",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 407 Proxy Authentication Required\nProxy-Authenticate: b@d realm=\"x\"",
            },
        ]
    }
}

impl Rule for ProxyAuthenticateChallengeSyntax {
    fn needs_response(&self) -> bool {
        // `Proxy-Authenticate` is a response header field.
        true
    }

    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // Read as octets and joined across field lines, for the reasons the
        // twin reads its field that way: `#challenge` makes several lines one
        // list, and an octet outside visible US-ASCII belongs to whichever
        // production it landed in rather than to a reader that refused the
        // line.
        // cite(RFC 9110 § 11.7.1): "A proxy MUST send at least one Proxy-Authenticate header field in each 407 (Proxy Authentication Required) response that it generates."
        let Some(resp) = &tx.response else {
            return Vec::new();
        };
        let Some(value) = crate::helpers::headers::combined_field_value_as_written(
            &resp.headers,
            "proxy-authenticate",
        ) else {
            return Vec::new();
        };
        crate::violations::challenge::challenge_list_defects("Proxy-Authenticate", value.as_str())
            .into_iter()
            .map(|(def, message)| ctx.report_with(def, message))
            .collect()
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ProxyAuthenticateChallengeSyntax;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn make_resp(v: &str) -> crate::http_transaction::HttpTransaction {
        crate::test_helpers::make_test_transaction_with_response(407, &[("proxy-authenticate", v)])
    }

    fn found(val: &str) -> Vec<(String, String)> {
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "proxy_authenticate_challenge_syntax",
        ]);
        crate::test_helpers::run_rule_all(
            &ProxyAuthenticateChallengeSyntax,
            &make_resp(val),
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .into_iter()
        .map(|v| (v.violation.to_string(), v.message))
        .collect()
    }

    /// The gap this rule closes, stated as the value that used to draw nothing.
    #[rstest]
    #[case("Basic realm=\"unfinished", "quoted_string_delimiter_missing")]
    #[case("b@d realm=\"x\"", "challenge_scheme_missing")]
    #[case("Basic re@alm=\"x\"", "challenge_parameter_name_character_forbidden")]
    #[case("Basic realm", "challenge_token68_invalid")]
    #[case(", Basic realm=\"x\"", "challenge_member_empty")]
    fn a_challenge_defect_is_reported_on_this_field_too(#[case] val: &str, #[case] expected: &str) {
        let got = found(val);
        assert_eq!(got.len(), 1, "val={val:?} got={got:?}");
        assert_eq!(got[0].0, expected);
    }

    /// The sentence names the field that carried the value, which is the whole
    /// of what had to move before a second reader could exist: every arm of
    /// `ChallengeDefect::message` used to say `WWW-Authenticate`, so a true
    /// finding here would have sent a reader to the wrong header field.
    #[test]
    fn the_finding_names_the_field_it_was_read_from() {
        let got = found("Basic realm");
        assert!(
            got[0].1.starts_with("Proxy-Authenticate challenge carries"),
            "{:?}",
            got[0].1
        );
        assert!(!got[0].1.contains("WWW-Authenticate"), "{:?}", got[0].1);
    }

    /// What the production derives is not reported, `token68` padding
    /// included — the same reading the twin makes, because it is one reading.
    #[rstest]
    #[case("Basic realm=\"proxy\"")]
    #[case("Negotiate YIIFxAYGKwYBBQUCoIIFuDCCBbSgh==")]
    #[case("NewScheme abcdef123=")]
    fn a_challenge_the_production_derives_is_not_reported(#[case] val: &str) {
        assert!(found(val).is_empty(), "val={val:?}");
    }

    /// Members answer one at a time here for the same reason they do on the
    /// twin: `#challenge` makes each one a subject.
    #[test]
    fn every_defective_member_answers_for_itself() {
        let ids: Vec<String> = found("Basic realm, Bearer realm=\"unfinished")
            .into_iter()
            .map(|(id, _)| id)
            .collect();
        assert_eq!(
            ids,
            [
                "challenge_token68_invalid",
                "quoted_string_delimiter_missing"
            ]
        );
    }

    /// A response without the field is not a response with an empty one.
    #[test]
    fn a_response_without_the_field_is_silent() {
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "proxy_authenticate_challenge_syntax",
        ]);
        let tx = crate::test_helpers::make_test_transaction_with_response(
            407,
            &[("www-authenticate", "b@d realm=\"x\"")],
        );
        assert!(crate::test_helpers::run_rule_all(
            &ProxyAuthenticateChallengeSyntax,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .is_empty());
    }
}
