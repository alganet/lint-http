// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::field::{FIELD_LINE_DUPLICATED, RFC_9110_5_3};
use crate::violations::origin_agent_cluster::{
    HTML_7_1_2, ORIGIN_AGENT_CLUSTER_EMPTY, ORIGIN_AGENT_CLUSTER_INVALID,
    ORIGIN_AGENT_CLUSTER_MALFORMED,
};
use crate::violations::ViolationDef;

/// One entry every field has available — its own repetition, which § 5.3
/// forbids a field with no list form — and the three the value itself can
/// reach: nothing written, more than one thing written, and one thing written
/// that is not the boolean the header exists to carry.
static DECLARED: &[&ViolationDef] = &[
    &FIELD_LINE_DUPLICATED,
    &ORIGIN_AGENT_CLUSTER_EMPTY,
    &ORIGIN_AGENT_CLUSTER_MALFORMED,
    &ORIGIN_AGENT_CLUSTER_INVALID,
];

pub struct OriginIsolatedHeaderValid;

/// The one reference this rule still owns, and it is the further reading
/// `specifications()` is deliberately wider by: it defines the boolean the
/// header's value is, and no finding is measured against it directly. The two
/// that a finding does enforce belong to the catalogue — `HTML § 7.1.2` beside
/// the defects it condemns, RFC 9110 § 5.3 beside the repeated line.
const RFC_9651_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9651",
    section: Some("3"),
    url: "https://www.rfc-editor.org/rfc/rfc9651.html#section-3",
    note: "Structured Headers boolean values (§3–§4)",
};

impl RuleMeta for OriginIsolatedHeaderValid {
    fn id(&self) -> &'static str {
        "origin_isolated_header_valid"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn description(&self) -> &'static str {
        "Checks the `Origin-Agent-Cluster` response header, whose value is one structured-field boolean. `?1` requests that documents from the origin be placed in an origin-keyed agent cluster. A value that is not a boolean at all — a comma-separated list, a bare token such as `unsafe-none`, or nothing — breaks the grammar and leaves a recipient with a field it cannot read. `?0` does not: it is the field's other value, well-formed, and it asks for what an absent header already gives, which the specification ignores and this rule reports as advice. The header must also appear on one field line only.\n\n(The `Origin-Isolation` name used by the original proposal never shipped; the header that browsers actually honour is `Origin-Agent-Cluster`.)"
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[HTML_7_1_2, RFC_9651_3, RFC_9110_5_3]
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
                snippet: "HTTP/1.1 200 OK\nOrigin-Agent-Cluster: ?1",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(the boolean, written false)"),
                snippet: "HTTP/1.1 200 OK\nOrigin-Agent-Cluster: ?0",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(a list where a boolean is due)"),
                snippet: "HTTP/1.1 200 OK\nOrigin-Agent-Cluster: ?1, ?1",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(a token, which no boolean admits)"),
                snippet: "HTTP/1.1 200 OK\nOrigin-Agent-Cluster: unsafe-none",
            },
        ]
    }
}

impl Rule for OriginIsolatedHeaderValid {
    fn needs_response(&self) -> bool {
        true
    }

    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // Single-finding body behind an Option: `?` ends it early, and the
        // one finding (or none) becomes the vector.
        let finding = || -> Option<Violation> {
            let resp = if let Some(r) = &tx.response {
                r
            } else {
                return None;
            };

            // The response is where this header is read, and the field name is
            // the shipped one: `Origin-Isolation`, which this rule is named
            // after, was the proposal and never arrived.
            // cite(HTML § 7.1.2): "A Document delivered over a secure context can request that it be placed in an origin-keyed agent cluster, by using the `Origin-Agent-Cluster` HTTP response header."
            let count = resp.headers.get_all("origin-agent-cluster").iter().count();
            if count == 0 {
                return None;
            }

            if count > 1 {
                return Some(ctx.report_with(
                    &FIELD_LINE_DUPLICATED,
                    "Multiple Origin-Agent-Cluster header fields present".into(),
                ));
            }

            // Read as the octets the sender wrote. The only value this field ever
            // carries is the two characters `?1`, so an octet outside visible
            // US-ASCII is a value that is not it — which the finding at the end
            // says, with the value in hand.
            let hv = resp
                .headers
                .get_all("origin-agent-cluster")
                .iter()
                .next()
                .expect("a field line, since the count above is one");
            let line = crate::helpers::headers::field_line_as_written(hv);
            let val = crate::helpers::headers::trim_ows(&line);

            // How many things the sender wrote, which is the question the
            // field's value being a single Item asks. None and several are
            // separate defects: a line with nothing on it states no
            // preference, a line with two states one the recipient may not
            // resolve.
            let members = crate::helpers::list::list_members(val).count();
            if members == 0 {
                return Some(ctx.report(&ORIGIN_AGENT_CLUSTER_EMPTY));
            }
            if members > 1 {
                return Some(ctx.report_with(
                    &ORIGIN_AGENT_CLUSTER_MALFORMED,
                    format!(
                        "Origin-Agent-Cluster carries {members} values ('{}') where the field's \
                         value is one boolean",
                        crate::helpers::shown::shown_in_finding(val)
                    ),
                ));
            }

            // What is written is one thing; the question left is whether it is
            // a boolean. `?1` and `?0` are the only two strings that parse as
            // one, and the reader every structured field shares says so — this
            // rule used to compare against `?1` and call the rest invalid,
            // which put a token and a false boolean under one sentence.
            // cite(RFC 9651 § 4.2.8, label: origin_isolated_header_valid): "If the first character of input_string is not "?", fail parsing."
            if !crate::helpers::structured_fields::is_boolean(val) {
                return Some(ctx.report_with(
                    &ORIGIN_AGENT_CLUSTER_MALFORMED,
                    format!(
                        "Origin-Agent-Cluster value '{}' is not a structured-field boolean; the \
                         field carries `?1` or `?0` and nothing else",
                        crate::helpers::shown::shown_in_finding(val)
                    ),
                ));
            }

            // `?1` is the boolean's true value and the one thing this field
            // exists to say. What is left is `?0` — the check above admits no
            // third string — so the entry below is about that value alone and
            // carries its own sentence. The specification ignores it; this rule
            // reports it as advice, because a header was written and requests
            // nothing that omitting it would not.
            if val.eq("?1") {
                return None;
            }

            Some(ctx.report(&ORIGIN_AGENT_CLUSTER_INVALID))
        };
        Vec::from_iter(finding())
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &OriginIsolatedHeaderValid;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(Some("?1"), false)]
    #[case(Some(" ?1 "), false)]
    #[case(Some("?0"), true)]
    #[case(Some("1"), true)]
    #[case(Some("?1, ?1"), true)]
    #[case(Some(""), true)]
    fn check_values(#[case] val: Option<&str>, #[case] expect_violation: bool) {
        let rule = OriginIsolatedHeaderValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(v) = val {
            tx = crate::test_helpers::make_test_transaction_with_response(
                200,
                &[("origin-agent-cluster", v)],
            );
        }

        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "origin_isolated_header_valid",
        ]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(v.is_some(), "expected violation for '{:?}', got none", val);
        } else {
            assert!(
                v.is_none(),
                "did not expect violation for '{:?}': got {:?}",
                val,
                v
            );
        }
    }

    /// Four ways to write something other than the true boolean, and each
    /// answers under the id its own defect belongs to — a line with nothing on
    /// it, a line with two things on it, and a line with one thing that is no
    /// boolean are all the grammar broken, while `?0` is the grammar kept and
    /// the preference declined. `unsafe-none`, `1` and `true` are the values
    /// that used to answer under `?0`'s id: they are not booleans, and RFC 9651
    /// § 4.2.8 admits exactly the two strings that are. The commas-only value
    /// is the one worth pinning for its own reason: it holds octets and no
    /// member, which is the same reading `Content-Length` makes of `,,`.
    #[test]
    fn each_shape_of_wrong_value_reports_its_own_id() {
        for (value, id) in [
            ("", "origin_agent_cluster_empty"),
            (",,", "origin_agent_cluster_empty"),
            ("?1, ?1", "origin_agent_cluster_malformed"),
            ("unsafe-none", "origin_agent_cluster_malformed"),
            ("1", "origin_agent_cluster_malformed"),
            ("true", "origin_agent_cluster_malformed"),
            ("?0", "origin_agent_cluster_invalid"),
        ] {
            let tx = crate::test_helpers::make_test_transaction_with_response(
                200,
                &[("origin-agent-cluster", value)],
            );
            let found = crate::test_helpers::run_rule(
                &OriginIsolatedHeaderValid,
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &crate::test_helpers::make_test_config_with_enabled_rules(&[
                    "origin_isolated_header_valid",
                ]),
            )
            .expect("a finding");
            assert_eq!(found.violation, id, "{value}");
        }
    }

    #[test]
    fn multiple_headers_violation() {
        use hyper::header::HeaderValue;
        let rule = OriginIsolatedHeaderValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hdrs =
            crate::test_helpers::make_headers_from_pairs(&[("origin-agent-cluster", "?1")]);
        hdrs.append("origin-agent-cluster", HeaderValue::from_static("?1"));
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hdrs,
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
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Multiple Origin-Agent-Cluster"));
    }

    #[test]
    fn an_obs_text_octet_is_a_value_that_is_not_the_boolean() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        let rule = OriginIsolatedHeaderValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hdrs =
            crate::test_helpers::make_headers_from_pairs(&[("origin-agent-cluster", "?1")]);
        hdrs.insert("origin-agent-cluster", HeaderValue::from_bytes(&[0xff])?);
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hdrs,
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
        let found = v.expect("a finding");
        assert_eq!(found.violation, "origin_agent_cluster_malformed");
        assert_eq!(
            found.message,
            "Origin-Agent-Cluster value '\u{ff}' is not a structured-field boolean; the field \
             carries `?1` or `?0` and nothing else"
        );
        Ok(())
    }

    /// The finding quotes the value back even though the catalogue holds the
    /// sentence: `?0` is the only value that can reach this entry, so naming it
    /// costs nothing at the site and an operator still reads which value
    /// arrived.
    #[test]
    fn the_false_boolean_is_named_in_the_message() {
        let rule = OriginIsolatedHeaderValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("origin-agent-cluster", "?0")],
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("?0"));
    }

    #[test]
    fn comma_list_names_how_many_values_it_carries() {
        let rule = OriginIsolatedHeaderValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("origin-agent-cluster", "?1, ?1")],
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        let found = v.expect("a finding");
        assert_eq!(found.violation, "origin_agent_cluster_malformed");
        assert!(found.message.contains("2 values"), "{}", found.message);
        assert!(found.message.contains("one boolean"), "{}", found.message);
    }

    #[test]
    fn the_shipped_field_name_is_the_one_that_is_read() {
        // The shipped header is `Origin-Agent-Cluster` (the `Origin-Isolation`
        // proposal name never shipped). A value on it must be answered; before
        // the retarget the rule watched the dead name and returned None.
        let rule = OriginIsolatedHeaderValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("origin-agent-cluster", "?0")],
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some(), "a value on Origin-Agent-Cluster is read");
    }

    #[test]
    fn no_response_returns_none() {
        let rule = OriginIsolatedHeaderValid;
        let tx = crate::test_helpers::make_test_transaction(); // no response set
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn needs_a_response() {
        let r = OriginIsolatedHeaderValid;
        assert!(r.needs_response());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let rule = OriginIsolatedHeaderValid;
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "origin_isolated_header_valid");
        rule.prepare(&cfg)?;
        Ok(())
    }
}
