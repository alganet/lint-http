// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct OriginIsolatedHeaderValid;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const HTML_7_1_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "HTML",
    section: Some("7.1.2"),
    url: "https://html.spec.whatwg.org/multipage/browsers.html#origin-keyed-agent-clusters",
    note: "`Origin-Agent-Cluster` — a structured-header boolean; only the `?1` true value requests an origin-keyed agent cluster",
};
const RFC_9651_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9651",
    section: Some("3"),
    url: "https://www.rfc-editor.org/rfc/rfc9651.html#section-3",
    note: "Structured Headers boolean values (§3–§4)",
};

impl Rule for OriginIsolatedHeaderValid {
    fn id(&self) -> &'static str {
        "origin_isolated_header_valid"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
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

            let count = resp.headers.get_all("origin-agent-cluster").iter().count();
            if count == 0 {
                return None;
            }

            if count > 1 {
                return Some(self.violation(
                    ctx.severity,
                    "Multiple Origin-Agent-Cluster header fields present".into(),
                ));
            }

            let val = match crate::helpers::headers::get_header_str(
                &resp.headers,
                "origin-agent-cluster",
            ) {
                Some(v) => v.trim(),
                None => {
                    return Some(
                        self.violation(
                            ctx.severity,
                            "Origin-Agent-Cluster header contains non-ASCII or control characters"
                                .into(),
                        ),
                    )
                }
            };

            // Must not be a comma-separated list
            // cite(HTML § 7.1.2): "This header is a structured header whose value must be a boolean."
            if crate::helpers::list::list_members(val).count() != 1 {
                return Some(self.cited(
                    &HTML_7_1_2,
                    ctx.severity,
                    "Origin-Agent-Cluster must be a single value".into(),
                ));
            }

            // `?1` is the structured-header boolean true value that requests an
            // origin-keyed agent cluster. The spec *ignores* any other value; this
            // rule is deliberately stricter and reports it, since a non-`?1` value
            // (`?0`, `unsafe-none`, …) is almost always a server misconfiguration.
            // cite(HTML § 7.1.2): "values that are not the structured header boolean true value (i.e., `?1`) will be ignored."
            if val.eq("?1") {
                return None;
            }

            Some(self.cited(&HTML_7_1_2, ctx.severity, format!("Origin-Agent-Cluster header value '{}' is invalid: expected '?1' to request an origin-keyed agent cluster", val)))
        };
        Vec::from_iter(finding())
    }

    fn description(&self) -> &'static str {
        "Checks the `Origin-Agent-Cluster` response header and ensures it uses the structured-header boolean value `?1` to request an origin-keyed agent cluster. The header must be a single value and must not contain comma-separated lists or multiple header fields. `?1` requests that documents from the origin be placed in an origin-keyed agent cluster; the specification ignores any other value, but this rule reports it because a non-`?1` value is almost always a server misconfiguration.\n\n(The `Origin-Isolation` name used by the original proposal never shipped; the header that browsers actually honour is `Origin-Agent-Cluster`.)"
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[HTML_7_1_2, RFC_9651_3]
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
                label: None,
                snippet: "HTTP/1.1 200 OK\nOrigin-Agent-Cluster: ?0",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nOrigin-Agent-Cluster: ?1, ?1",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nOrigin-Agent-Cluster: unsafe-none",
            },
        ]
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
    fn non_utf8_is_violation() -> anyhow::Result<()> {
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
            trailers: None,
        });

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn non_utf8_is_violation_message_contains_hint() -> anyhow::Result<()> {
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
            trailers: None,
        });

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        let msg = v.unwrap().message;
        assert!(msg.contains("non-ASCII") || msg.contains("control"));
        Ok(())
    }

    #[test]
    fn invalid_value_includes_value_in_message() {
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
    fn comma_list_reports_single_value_message() {
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
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("single value"));
    }

    #[test]
    fn origin_agent_cluster_invalid_is_flagged() {
        // The shipped header is `Origin-Agent-Cluster` (the `Origin-Isolation`
        // proposal name never shipped). A malformed value on it must be flagged;
        // before the retarget the rule watched the dead name and returned None.
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
        assert!(v.is_some(), "Origin-Agent-Cluster: ?0 should be flagged");
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
    fn scope_is_server() {
        let r = OriginIsolatedHeaderValid;
        assert_eq!(r.scope(), crate::rules::RuleScope::Server);
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
