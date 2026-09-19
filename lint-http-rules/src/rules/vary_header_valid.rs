// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::list::{LIST_MEMBER_EMPTY, RFC_9110_5_6_1_1};
use crate::violations::token::{
    token_character, RFC_9110_5_6_2, TOKEN_CHARACTER_FORBIDDEN,
    TOKEN_WHITESPACE_OR_CONTROL_FORBIDDEN,
};
use crate::violations::ViolationDef;

/// Validate the `Vary` response header against RFC 9110 §12.5.5:
/// `Vary = #( "*" / field-name )`. Each field-name must conform to the `token`
/// grammar (tchar). Because it is a `#`-list, an empty value is a legal
/// zero-element list; `*` is an ordinary list member and may appear alongside
/// field-names (RFC 7231's `"*" / 1#field-name` exclusivity was dropped).
pub struct VaryHeaderValid;

/// The same three `Allow` declares, for the same reason: `Vary = #( "*" /
/// field-name )` is a list of `token`s and the field's own contribution is what
/// the tokens *mean*, not what they may be. One rule reads methods and the
/// other field names; a stray comma and an octet outside `tchar` are the same
/// two defects in both.
static DECLARED: &[&ViolationDef] = &[
    &LIST_MEMBER_EMPTY,
    &TOKEN_WHITESPACE_OR_CONTROL_FORBIDDEN,
    &TOKEN_CHARACTER_FORBIDDEN,
];

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9110_12_5_5: crate::rules::SpecRef = crate::rules::SpecRef {
spec: "RFC 9110",
section: Some("12.5.5"),
url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.5",
note: "Vary = #( \"*\" / field-name ) — a comma-separated list; \"*\" is an ordinary member (RFC 7231's \"*\"-or-a-list form is obsolete). Not checked: the same section's \"A proxy MUST NOT generate \\\"*\\\"\", since a forwarded \"*\" is indistinguishable from a generated one in an observed response",
        };

impl RuleMeta for VaryHeaderValid {
    fn id(&self) -> &'static str {
        "vary_header_valid"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn description(&self) -> &'static str {
        "Validate the `Vary` response header against its grammar `Vary = #( \"*\" / field-name )` (RFC 9110 §12.5.5). This rule enforces that:\n\n- Each field-name conforms to the `token` grammar (RFC `tchar`).\n- The list contains no empty elements (a stray, leading, or trailing comma).\n\nBecause `Vary` is a comma-separated (`#`) list, an entirely empty value is a legal zero-element list and is not flagged. The wildcard `*` is an ordinary list member: under RFC 9110 it may appear alongside field-names, so the combination is not reported (RFC 7231's `\"*\" / 1#field-name` exclusivity no longer applies)."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_9110_12_5_5, RFC_9110_5_6_1_1, RFC_9110_5_6_2]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::Presumed(crate::lint::Party::Server)
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "Vary: Accept-Encoding\nVary: User-Agent",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "Vary: Accept-Encoding, User-Agent",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "Vary: *",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("— '*' may accompany field-names under RFC 9110"),
                snippet: "Vary: *, Accept-Encoding",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "Vary: x@bad                # invalid token characters in field-name\nVary: Accept-Encoding,     # empty element (trailing comma) is invalid",
            },
        ]
    }
}

impl Rule for VaryHeaderValid {
    fn needs_response(&self) -> bool {
        true
    }

    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // One finding per member. `Vary = #( "*" / field-name )` names one
        // field per position, and a cache reading the value has to find every
        // one of them -- so a value naming two field-names that are not tokens
        // is two selecting fields the operator has to correct, and a walk that
        // stopped at the first reported one of them.
        let findings = || -> Vec<Violation> {
            // Vary is a response header field; the rule inspects responses only.
            // cite(RFC 9110 § 12.5.5): "The "Vary" header field in a response describes what parts of a request message, aside from the method and target URI, might have influenced the origin server's process for selecting the content of this response."
            let Some(resp) = tx.response.as_ref() else {
                return Vec::new();
            };
            let mut out = Vec::new();

            // The whole check transcribes the field grammar: a comma list whose members
            // are each "*" or a field-name.
            // cite(RFC 9110 § 12.5.5): "Vary = #( "*" / field-name )"
            // Read as the octets the sender wrote. Every member is `*` or a
            // `field-name`, which is a `token`, so an octet no `tchar` admits is
            // the production's defect and the member walk below reports it under
            // the id this rule already declares. Per line rather than joined,
            // because the empty-whole-value case below is a judgment about what
            // one line held.
            for line in crate::helpers::headers::field_lines_as_written(&resp.headers, "vary") {
                let s = line.as_str();

                // Vary is a `#`-list, so an entirely empty value is a legal zero-element
                // list (the degenerate "does not vary" case), not a malformed header.
                // Distinct from an empty *element* within a non-empty list, flagged below.
                if crate::helpers::headers::trim_ows(s).is_empty() {
                    continue;
                }

                // An empty element within the list (trailing/leading/consecutive commas)
                // is forbidden, unlike the empty whole value skipped above. The
                // sentence that forbids it is on the def, where the twenty-odd
                // other fields reporting a stray comma read the same one.
                //
                // One finding for the line however many gaps it holds: what
                // § 5.6.1.1 forbids generating is an empty *element*, and a line
                // with three of them is one list written with gaps in it. The
                // token scan below is the member's defect and is counted per
                // member; this is the list's.
                if s.split(',')
                    .any(|raw| crate::helpers::headers::trim_ows(raw).is_empty())
                {
                    out.push(ctx.report_with(&LIST_MEMBER_EMPTY, "Vary header contains empty token (e.g., trailing or consecutive commas)".into()));
                }

                for token in crate::helpers::list::list_members(s) {
                    // "*" is a valid list member. Under RFC 9110 it may appear alongside
                    // field-names (RFC 7231's "*"-or-a-list exclusivity was dropped), so
                    // no combination check is made — only field-name tokens are validated.
                    //
                    // §12.5.5's one MUST on "*" — "A proxy MUST NOT generate "*" in a Vary
                    // field value." — is deliberately not enforced, and not merely because
                    // the sender's role is unknown. It forbids *generating*, not carrying:
                    // an intermediary that forwards an origin's `Vary: *` is compliant, and
                    // an origin may send it freely. So even a definite "a proxy handled
                    // this" signal (a `Via` field) would not identify who authored the
                    // header, and no field records authorship. The check is undecidable
                    // from an observed response rather than merely unimplemented, so the
                    // sentence stays uncited here: the code does not enforce it.
                    if token == "*" {
                        continue;
                    }

                    // Every other member is a field-name, i.e. a token.
                    if let Some(c) = crate::helpers::token::find_invalid_token_char(token) {
                        // The member is named, and it has to be: once a value
                        // reports every member it offends in, two findings that
                        // said only which octet was wrong would be one sentence
                        // twice for `Vary: Acc@pt, Us@r` and the operator could
                        // not tell which field-name either was about.
                        out.push(ctx.report_with(
                            token_character(c),
                            format!(
                                "Vary header member '{}' contains {}, which is not a `tchar`, so it derives from no `token` and therefore from no `field-name`",
                                crate::helpers::shown::shown_in_finding(token),
                                crate::helpers::shown::describe_char(c)
                            ),
                        ));
                    }
                }
            }

            out
        };
        findings()
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &VaryHeaderValid;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// `Allow` and `Vary` are one grammar apart: `#method` against
    /// `#( "*" / field-name )`, both lists of `token`s, and the field's own
    /// contribution is what the tokens mean rather than what they may be. So a
    /// stray comma and an octet outside `tchar` draw one id from each rule —
    /// which is what a rule that owns none of its defects looks like from
    /// outside.
    #[test]
    fn a_list_of_tokens_reports_the_same_two_defects_as_allow() {
        let vary = |value: &str| {
            let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
            tx.response.as_mut().expect("a response").headers =
                crate::test_helpers::make_headers_from_pairs(&[("vary", value)]);
            crate::test_helpers::run_rule(
                &VaryHeaderValid,
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &crate::test_helpers::make_test_config_with_enabled_rules(&["vary_header_valid"]),
            )
            .expect("a finding")
        };
        let allow = |value: &str| {
            let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
            tx.response.as_mut().expect("a response").headers =
                crate::test_helpers::make_headers_from_pairs(&[("allow", value)]);
            crate::test_helpers::run_rule(
                &crate::rules::allow_header_method_tokens_valid::AllowHeaderMethodTokensValid,
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &crate::test_helpers::make_test_config_with_enabled_rules(&[
                    "allow_header_method_tokens_valid",
                ]),
            )
            .expect("a finding")
        };

        assert_eq!(
            vary("accept-encoding,,user-agent").violation,
            "list_member_empty"
        );
        assert_eq!(allow("GET,,POST").violation, "list_member_empty");
        assert_eq!(vary("x@bad").violation, "token_character_forbidden");
        assert_eq!(allow("PO@T").violation, "token_character_forbidden");
    }

    #[rstest]
    #[case(None, false)]
    #[case(Some("*"), false)]
    #[case(Some("accept-encoding"), false)]
    #[case(Some("Accept-Encoding, User-Agent"), false)]
    // '*' alongside field-names is valid under RFC 9110's #-list grammar.
    #[case(Some("accept-encoding, *"), false)]
    #[case(Some("*, accept-encoding"), false)]
    // Empty value / whitespace-only is a legal zero-element list.
    #[case(Some(""), false)]
    #[case(Some("   "), false)]
    #[case(Some("x@bad"), true)]
    // Empty *elements* within a non-empty list remain violations.
    #[case(Some("Accept-Encoding,"), true)]
    #[case(Some(",Accept-Encoding"), true)]
    #[case(Some("Accept-Encoding,,User-Agent"), true)]
    #[case(Some(","), true)]
    #[case(Some("\"Accept-Encoding\""), true)]
    fn vary_cases(#[case] header: Option<&str>, #[case] expect_violation: bool) {
        let rule = VaryHeaderValid;
        let tx = match header {
            Some(h) => {
                crate::test_helpers::make_test_transaction_with_response(200, &[("vary", h)])
            }
            None => crate::test_helpers::make_test_transaction_with_response(200, &[]),
        };

        let config = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        );
        if expect_violation {
            assert!(v.is_some(), "expected violation for header={:?}", header);
        } else {
            assert!(
                v.is_none(),
                "unexpected violation for header={:?}: {:?}",
                header,
                v
            );
        }
    }

    /// **Every field-name the response listed is answered.** `Vary` names the
    /// selecting fields a cache has to key on, and a value naming three that
    /// are not tokens is three keys the operator has to correct — a walk that
    /// stopped at the first named one, and could not say which.
    #[test]
    fn every_defective_field_name_is_reported() {
        let rule = VaryHeaderValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("vary", "Acc@pt, User Agent, X=Key")],
        );
        let found = crate::test_helpers::run_rule_all(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert_eq!(
            found.len(),
            3,
            "{:?}",
            found.iter().map(|v| &v.message).collect::<Vec<_>>()
        );
        for member in ["Acc@pt", "User Agent", "X=Key"] {
            assert!(
                found.iter().any(|v| v.message.contains(member)),
                "no finding names the member '{member}': {:?}",
                found.iter().map(|v| &v.message).collect::<Vec<_>>()
            );
        }
    }

    /// The empty member stays one finding for the line, and this pins the
    /// split: § 5.6.1.1 forbids generating an empty *element*, and a line with
    /// three gaps is one list written with gaps in it.
    #[test]
    fn three_empty_members_are_one_finding_and_the_tokens_are_their_own() {
        let rule = VaryHeaderValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("vary", "Acc@pt,,Us@r,,")],
        );
        let found = crate::test_helpers::run_rule_all(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        let empties = found
            .iter()
            .filter(|v| v.violation == "list_member_empty")
            .count();
        assert_eq!(empties, 1, "the gaps are one list defect: {found:?}");
        assert_eq!(found.len() - empties, 2, "{found:?}");
    }

    #[test]
    fn multiple_header_fields_merged() {
        let rule = VaryHeaderValid;

        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("vary", "Accept-Encoding"), ("vary", "User-Agent")],
        );

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn star_combined_across_header_fields_is_allowed() {
        // RFC 9110's `#( "*" / field-name )` permits '*' alongside field-names,
        // including when split across multiple Vary field lines.
        let rule = VaryHeaderValid;

        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("vary", "*"), ("vary", "Accept-Encoding")],
        );

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn an_obs_text_octet_in_a_field_name_is_a_token_defect() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;
        let rule = VaryHeaderValid;

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        let bad = HeaderValue::from_bytes(&[0xff]).expect("should construct non-utf8 header");
        hm.insert("vary", bad);
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,

            body_length: None,
            body_interrupted: false,
            trailers: None,
        });

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        let v = v.expect("a finding");
        assert_eq!(v.violation, "token_character_forbidden");
        // Both halves, and they answer differently on purpose: the octet is
        // *named*, because the octets that fail a `tchar` test are very often
        // the ones that print as nothing; the member is *escaped for display*,
        // which leaves 0xFF showing as `ÿ` — legibly and wrongly as to
        // encoding, which is exactly why the named octet stands beside it.
        assert_eq!(
            v.message,
            "Vary header member 'ÿ' contains 0xFF, which is not a `tchar`, so it derives from no `token` and therefore from no `field-name`"
        );
        Ok(())
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "vary_header_valid");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn needs_a_response() {
        let rule = VaryHeaderValid;
        assert!(rule.needs_response());
    }

    #[test]
    fn no_response_returns_none() {
        let rule = VaryHeaderValid;
        let tx = crate::test_helpers::make_test_transaction(); // request-only, no response
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }
}
