// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::priority::{PRIORITY_CACHEABILITY_MISSING, RFC_9218_5};
use crate::violations::ViolationDef;

pub struct PriorityAndCacheabilityConsistent;

/// One entry, on the subject `priority_header_syntax` opened. The two rules do
/// not overlap: that one reads a `Priority` that was written and asks what it
/// says, this one reads a `Priority` that was written and asks what the rest of
/// the response says about caching it.
static DECLARED: &[&ViolationDef] = &[&PRIORITY_CACHEABILITY_MISSING];

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9111: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9111",
    section: None,
    url: "https://www.rfc-editor.org/rfc/rfc9111.html",
    note: "HTTP caching and `Cache-Control`/`Vary` semantics (informative)",
};

impl RuleMeta for PriorityAndCacheabilityConsistent {
    fn id(&self) -> &'static str {
        "priority_and_cacheability_consistent"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn title(&self) -> Option<&'static str> {
        Some("Server Priority and Cacheability Consistency")
    }

    fn description(&self) -> &'static str {
        "When an origin server includes a `Priority` response header (RFC 9218 §5) it is expected to control the cacheability or applicability of the cached response by using cache-control related fields (for example `Cache-Control` and/or `Vary`). This rule warns when a response includes `Priority` but lacks an explicit caching directive such as `Cache-Control` or `Vary` which can lead to incorrect caching of responses that differ by request properties."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_9218_5, RFC_9111]
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
                snippet:
                    "HTTP/1.1 200 OK\nCache-Control: public, max-age=60\nPriority: u=3\n\n<body...>",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(Vary is present)"),
                snippet: "HTTP/1.1 200 OK\nVary: Accept-Encoding\nPriority: u=1\n\n<body...>",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nPriority: u=2\n\n<body...>",
            },
        ]
    }
}

impl Rule for PriorityAndCacheabilityConsistent {
    fn needs_response(&self) -> bool {
        // The expectation is scoped by its own opening clause, which is what
        // this rule reads to decide it inspects responses and nothing else: a
        // request carrying a `Priority` is asked for nothing here. The other
        // half of the sentence -- what such a server is expected to do -- is
        // the entry's, and sits on it beside its reference.
        // cite(RFC 9218 § 5): "When an origin server generates the Priority response header field based on properties of an HTTP request it receives"
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
            let resp = tx.response.as_ref()?;

            // Only consider responses that include a Priority header field (§5: the
            // field "can appear in requests and responses"). This is a presence test
            // only — the value feeds the message, never a Dictionary parse — so the
            // first non-empty ASCII field line is taken; a Priority header that is
            // empty or non-ASCII on every line is treated as absent and skipped.
            let mut priority_val: Option<&str> = None;
            for s in crate::helpers::headers::field_lines(&resp.headers, "priority") {
                let s = s.trim();
                if !s.is_empty() {
                    priority_val = Some(s);
                    break;
                }
            }
            let priority = priority_val?;

            // Restrict to "cacheable-ish" 2xx/3xx responses. This is a heuristic range,
            // not RFC 9110 §15.1's set of responses cacheable by default: it over-includes
            // non-default-cacheable 3xx (302, 303, 307) and omits the heuristically
            // cacheable 404, 410, and 451. The imprecision is tolerable because the check
            // is a soft best-practice warning, not a MUST; tightening it to §15.1's exact
            // list would be a behavior change. No sentence licenses this exact bound, so it
            // carries no cite.
            if !(200..400).contains(&resp.status) {
                return None;
            }

            let has_cache_control = resp.headers.contains_key("cache-control");
            let has_vary = resp.headers.contains_key("vary");

            // Either field answers, which is § 5's own parenthesis rather than a
            // tolerance: it asks for "header fields that control the caching
            // behavior" and names these two as examples. So the entry is named
            // for the class and the message names the two that would have done.
            // (This replaced a mis-anchored RFC 9111 § 4.2.2 heuristic-freshness
            // MAY, which spoke to neither the Priority expectation nor the Vary
            // half of the check.)
            if !has_cache_control && !has_vary {
                return Some(ctx.report_with(&PRIORITY_CACHEABILITY_MISSING, format!(
                        "Response includes Priority header ('{}') but lacks Cache-Control or Vary to control cacheability",
                        priority
                    )));
            }

            None
        };
        Vec::from_iter(finding())
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &PriorityAndCacheabilityConsistent;

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;
    use rstest::rstest;

    #[rstest]
    fn priority_without_cache_control_or_vary_reports_violation() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("priority", "u=3")]);

        let rule = PriorityAndCacheabilityConsistent;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        let v = v.unwrap();
        assert_eq!(v.violation, "priority_cacheability_missing");
        assert!(v.message.contains("Priority header"));
    }

    #[rstest]
    fn priority_with_cache_control_is_ok() {
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("priority", "u=1"), ("cache-control", "public, max-age=60")],
        );
        let rule = PriorityAndCacheabilityConsistent;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[rstest]
    fn priority_with_vary_is_ok() {
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("priority", "u=1"), ("vary", "Accept-Encoding")],
        );
        let rule = PriorityAndCacheabilityConsistent;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[rstest]
    fn no_priority_is_ignored() {
        let tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let rule = PriorityAndCacheabilityConsistent;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[rstest]
    fn priority_non_utf8_is_ignored() -> anyhow::Result<()> {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = hyper::HeaderMap::new();
        hm.insert("priority", HeaderValue::from_bytes(&[0xff])?);
        tx.response.as_mut().unwrap().headers = hm;

        let rule = PriorityAndCacheabilityConsistent;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
        Ok(())
    }

    #[rstest]
    fn priority_multiple_fields_prefers_ascii_value() -> anyhow::Result<()> {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = hyper::HeaderMap::new();
        // Non-UTF8 first, ASCII second
        hm.insert("priority", HeaderValue::from_bytes(&[0xff])?);
        hm.append("priority", HeaderValue::from_static("u=2"));
        tx.response.as_mut().unwrap().headers = hm;

        let rule = PriorityAndCacheabilityConsistent;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        Ok(())
    }

    #[rstest]
    fn priority_on_non_cacheable_status_is_ignored() {
        let tx =
            crate::test_helpers::make_test_transaction_with_response(503, &[("priority", "u=1")]);
        let rule = PriorityAndCacheabilityConsistent;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[rstest]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "priority_and_cacheability_consistent");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn needs_a_response() {
        let rule = PriorityAndCacheabilityConsistent;
        assert!(rule.needs_response());
    }
}
