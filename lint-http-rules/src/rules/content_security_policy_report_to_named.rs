// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::content_security_policy::{
    CONTENT_SECURITY_POLICY_REPORT_TO_MALFORMED, CSP3_2_2_1, CSP3_6_5_2,
};
use crate::violations::ViolationDef;

/// The `report-to` directive of every policy a response delivers, read for the
/// one thing § 6.5.2 says its value is: the name of a reporting endpoint group.
pub struct ContentSecurityPolicyReportToNamed;

/// One entry. What the value may name is `report_to_groups_valid`'s and
/// `structured_headers_valid`'s question — this rule asks only whether the
/// directive wrote a name at all.
static DECLARED: &[&ViolationDef] = &[&CONTENT_SECURITY_POLICY_REPORT_TO_MALFORMED];

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const CSP3_2_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "CSP3",
    section: Some("2.2"),
    url: "https://www.w3.org/TR/CSP3/#framework-policy",
    note: "Policies — a field line is a comma-delimited series of serialized CSPs, each enforced on its own, which is why the directives of one policy are not read against another's",
};
const CSP3_6_5_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "CSP3",
    section: Some("6.5.1"),
    url: "https://www.w3.org/TR/CSP3/#directive-report-uri",
    note: "`report-uri` — the deprecated directive whose value really is a URI-reference, which this rule exists to tell apart from its neighbour, and whose presence beside a `report-to` is suggested rather than reported",
};

impl RuleMeta for ContentSecurityPolicyReportToNamed {
    fn id(&self) -> &'static str {
        "content_security_policy_report_to_named"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn title(&self) -> Option<&'static str> {
        Some("CSP report-to Names A Group")
    }

    fn description(&self) -> &'static str {
        "Reads the `report-to` directive of every policy a response delivers, in both `Content-Security-Policy` and `Content-Security-Policy-Report-Only`, and reports one thing: that the directive wrote no endpoint group name.\n\n**The value is a name, not a location.** CSP3 §6.5.2 writes `directive-value = token` — one token, which §5.5 looks up as the name of a reporting endpoint group declared elsewhere in the response by `Reporting-Endpoints` (or by the `Report-To` it replaced). A value that is no token names no group, and the violation report has nowhere to go.\n\n**The mistake this catches is a URL**, and it is the neighbouring directive's value. §6.5.1 gives the deprecated `report-uri` a `uri-reference *( required-ascii-whitespace uri-reference )`; §6.5.2 gives `report-to` a bare `token`. One subsection apart, and a deployment that pastes its collector's URL into both has not merely failed to improve on `report-uri` — §5.5 skips `report-uri` outright whenever a `report-to` is present, so writing the broken directive disables the working one.\n\n**A `report-uri` beside a well-formed `report-to` is not reported.** §6.5.1 asks for exactly that pairing to keep older user agents working, and a finding against it would contradict the sentence this rule rests on.\n\n**Nothing here asks whether the group exists.** Reporting configuration is registered per origin and a response need not carry the declaration it names, so a rule reading one message cannot tell a name nothing declares from one an earlier response declared. What is decidable from the message alone is whether a name was written at all, and that is the whole of this reading.\n\n**Scope.** A field line is a comma-delimited series of serialized policies (§2.2) and each is enforced on its own, so the policies are separated before the directives are; within one policy a directive name written twice keeps the first (§2.2.1), which is the occurrence a user agent acts on and therefore the one read here. Directive names are matched case-insensitively, as §2.2.1 requires. The value is split on ASCII whitespace, which is §2.2.1's own step — so `report-to  grp` is one token and `report-to a b` is two.\n\n**Whether the policy is enforced or merely monitored makes no difference to this finding, and the report-only field is where it costs most.** §3.2 delivers a policy so a developer can watch it; a monitored policy whose reports go nowhere is a header that does nothing at all."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[CSP3_6_5_2, CSP3_6_5_1, CSP3_2_2, CSP3_2_2_1]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    /// The policy is delivered in a response field and the directive is the
    /// sender's, so the peer answerable is the server. The reader below is
    /// handed the response's headers and nothing else.
    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::Presumed(crate::lint::Party::Server)
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("(the token names a group the response declares)"),
                snippet: "HTTP/1.1 200 OK\nReporting-Endpoints: csp-endpoint=\"https://example.com/csp\"\nContent-Security-Policy: script-src 'self'; report-to csp-endpoint",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(a report-uri beside it is what \u{a7} 6.5.1 suggests)"),
                snippet: "HTTP/1.1 200 OK\nContent-Security-Policy: script-src 'self'; report-uri https://example.com/csp; report-to csp-endpoint",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(a URL is report-uri's value, and report-to takes a name)"),
                snippet: "HTTP/1.1 200 OK\nContent-Security-Policy: script-src 'self'; report-to https://example.com/csp",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(the directive is named and lists nothing)"),
                snippet: "HTTP/1.1 200 OK\nContent-Security-Policy-Report-Only: script-src 'self'; report-to",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(one reporting endpoint, so two tokens name none)"),
                snippet: "HTTP/1.1 200 OK\nContent-Security-Policy: script-src 'self'; report-to primary backup",
            },
        ]
    }
}

impl Rule for ContentSecurityPolicyReportToNamed {
    fn needs_response(&self) -> bool {
        true
    }

    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        let Some(resp) = tx.response.as_ref() else {
            return Vec::new();
        };

        let mut out: Vec<Violation> = Vec::new();
        // Both fields carry `1#serialized-policy` and this defect is a defect
        // of a policy rather than of the field that delivered one. The
        // report-only field is the one it costs most: a policy delivered to be
        // watched, whose reports go nowhere, is a header with no effect at all.
        for field in [
            "content-security-policy",
            "content-security-policy-report-only",
        ] {
            // Read as written rather than through a UTF-8 decode: an octet no
            // `token` admits is exactly what this rule is looking for, and a
            // decoder that folds the line into "no such field here" would
            // answer "nothing to report" for the worst value there is.
            for line in crate::helpers::headers::field_lines_as_written(&resp.headers, field) {
                // Policies before directives. A field line is a comma-delimited
                // series of serialized CSPs, each enforced on its own, so a
                // `;` split alone would read the last directive of one policy
                // and the first of the next as one directive.
                //
                // cite(CSP3 § 2.2): "a comma-delimited series of serialized CSPs"
                for policy in crate::helpers::list::list_members(&line) {
                    if let Some(v) = self.report_to_finding(policy, field, ctx) {
                        out.push(v);
                    }
                }
            }
        }
        out
    }
}

impl ContentSecurityPolicyReportToNamed {
    /// Read one serialized policy's `report-to`, answering with the finding it
    /// earns or `None`.
    ///
    /// Every `return` here answers the one question *did this policy write an
    /// endpoint group name* — the absent directive and the three malformed
    /// shapes are branches of that question and not four different questions
    /// sharing a closure.
    fn report_to_finding(
        &self,
        policy: &str,
        field: &str,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Option<Violation> {
        // The **first** occurrence, because that is the one the user agent
        // keeps: a directive whose name is already in the policy's directive
        // set makes the parser skip the later one. Reading the last would
        // report a value no recipient ever looks at.
        //
        // Names are matched without case, which is the step beside it.
        //
        // cite(CSP3 § 2.2.1): "directive set contains a directive whose name is directive name"
        // cite(CSP3 § 2.2.1): "Directive names are case-insensitive"
        let directive = crate::helpers::list::parse_semicolon_list(policy).find(|d| {
            d.split_ascii_whitespace()
                .next()
                .is_some_and(|name| name.eq_ignore_ascii_case("report-to"))
        })?;

        // § 2.2.1's own step, so `report-to   grp` is one token rather than
        // three empty ones.
        //
        // cite(CSP3 § 2.2.1): "Let directive value be the result of splitting token on ASCII whitespace"
        let tokens: Vec<&str> = directive.split_ascii_whitespace().skip(1).collect();

        // `directive-value = token`: exactly one, and it derives from the
        // `token` production. Each branch names what was written, because the
        // three repairs are the same repair and only the reading knows which
        // shape produced it.
        //
        // cite(CSP3 § 6.5.2, label: report-to grammar): "directive-value = token"
        let says = match tokens.as_slice() {
            [] => "lists nothing".to_string(),
            // The `token` production, whose first offending character is named
            // rather than left for the reader to find: in the value a real
            // origin writes, it is the `:` of a scheme.
            // `?` is the whole test: a value the `token` production accepts
            // yields no offending character, and this rule has nothing to say
            // about it.
            [one] => {
                let bad = crate::helpers::token::find_invalid_token_char(one)?;
                format!(
                    "is '{}', which is no token — {} is a character no token admits, and that \
                     value is `report-uri`'s; § 6.5.2 gives this directive the name of a \
                     reporting endpoint group instead",
                    crate::helpers::shown::shown_in_finding(one),
                    crate::helpers::shown::describe_char(bad)
                )
            }
            many => format!(
                "lists {} tokens ('{}'), and § 6.5.2 defines one reporting endpoint",
                many.len(),
                crate::helpers::shown::shown_in_finding(&many.join(" "))
            ),
        };

        Some(ctx.report_with(
            &CONTENT_SECURITY_POLICY_REPORT_TO_MALFORMED,
            format!(
                "{}'s report-to directive {}, so this policy names no endpoint group and every \
                 violation it reports is discarded — and a report-uri beside it is skipped \
                 outright because a report-to is present",
                field, says
            ),
        ))
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ContentSecurityPolicyReportToNamed;

#[cfg(test)]
mod tests {
    use super::*;

    use rstest::rstest;

    /// Run the rule over a response carrying the given field lines and answer
    /// with the messages it drew.
    fn messages_for(lines: &[(&str, &str)]) -> Vec<String> {
        let tx = crate::test_helpers::make_test_transaction_with_response(200, lines);
        let rule = ContentSecurityPolicyReportToNamed;
        crate::test_helpers::run_rule_all(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .iter()
        .map(|f| f.message.clone())
        .collect()
    }

    fn csp(value: &str) -> Vec<String> {
        messages_for(&[("content-security-policy", value)])
    }

    /// A token names a group, and that is all this rule asks. Whether the group
    /// is declared anywhere is not decidable from one message.
    #[rstest]
    #[case("script-src 'self'; report-to csp-endpoint")]
    #[case("script-src 'self'; report-to default")]
    #[case::extra_whitespace_is_one_token("script-src 'self'; report-to   csp-endpoint")]
    #[case::no_report_to_at_all("script-src 'self'; object-src 'none'")]
    #[case::report_uri_beside_it_is_suggested(
        "script-src 'self'; report-uri https://e.example/csp; report-to grp"
    )]
    #[case::report_uri_alone_is_another_rules_business(
        "script-src 'self'; report-uri https://e.example/csp"
    )]
    fn a_policy_that_names_a_group_draws_nothing(#[case] value: &str) {
        assert!(csp(value).is_empty(), "`{}` drew {:?}", value, csp(value));
    }

    /// The shape a real origin writes: `report-uri`'s value in `report-to`.
    #[test]
    fn a_url_is_the_other_directives_value() {
        let m = csp("script-src 'self'; report-to https://e.example/r/t/csp/enforce");
        assert_eq!(m.len(), 1, "{:?}", m);
        assert!(
            m[0].contains("https://e.example/r/t/csp/enforce"),
            "{}",
            m[0]
        );
        assert!(m[0].contains("no token"), "{}", m[0]);
    }

    /// The three shapes, each naming what was written rather than restating the
    /// production.
    #[rstest]
    #[case::nothing_at_all("script-src 'self'; report-to", "lists nothing")]
    #[case::two_tokens("script-src 'self'; report-to primary backup", "lists 2 tokens")]
    #[case::a_quoted_word("script-src 'self'; report-to \"grp\"", "no token")]
    fn each_shape_says_which_one_it_was(#[case] value: &str, #[case] says: &str) {
        let m = csp(value);
        assert_eq!(m.len(), 1, "{:?}", m);
        assert!(m[0].contains(says), "{}", m[0]);
    }

    /// The report-only field carries the same production and the same defect,
    /// and it is where the defect costs the whole header.
    #[test]
    fn the_report_only_field_is_read_too() {
        let m = messages_for(&[(
            "content-security-policy-report-only",
            "script-src 'self'; report-to https://e.example/csp",
        )]);
        assert_eq!(m.len(), 1, "{:?}", m);
        assert!(
            m[0].starts_with("content-security-policy-report-only"),
            "{}",
            m[0]
        );
    }

    /// **Policies are separated before directives are.** Without the comma
    /// split the last directive of the first policy and the first of the second
    /// read as one, so the good `report-to` swallows `default-src` and the
    /// second policy's broken one is never reached.
    #[test]
    fn each_policy_in_one_field_line_is_read_on_its_own() {
        let m = csp("script-src 'self'; report-to good, default-src 'none'; report-to https://e.example/csp");
        assert_eq!(m.len(), 1, "{:?}", m);
        assert!(m[0].contains("https://e.example/csp"), "{}", m[0]);
    }

    /// A directive name written twice keeps the first, because that is the one
    /// the parser puts in the directive set and the only one a user agent acts
    /// on. Reading the last would report a value nothing looks at.
    #[test]
    fn the_first_occurrence_of_the_directive_is_the_one_read() {
        assert!(csp("report-to grp; report-to https://e.example/csp").is_empty());
        let m = csp("report-to https://e.example/csp; report-to grp");
        assert_eq!(m.len(), 1, "{:?}", m);
    }

    /// Directive names are case-insensitive, so a `Report-To` is the directive
    /// and not an unknown one this rule may skip.
    #[test]
    fn the_directive_name_is_matched_without_case() {
        let m = csp("script-src 'self'; Report-To https://e.example/csp");
        assert_eq!(m.len(), 1, "{:?}", m);
    }

    /// Two field lines are two deliveries of a policy and both are read; a rule
    /// stopping at the first would answer for one of them.
    #[test]
    fn every_field_line_is_read() {
        let m = messages_for(&[
            (
                "content-security-policy",
                "script-src 'self'; report-to https://a.example/1",
            ),
            (
                "content-security-policy",
                "object-src 'none'; report-to https://b.example/2",
            ),
        ]);
        assert_eq!(m.len(), 2, "{:?}", m);
    }
}
