// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct CacheControlAndPragmaConsistent;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9111_5_4: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9111",
    section: Some("5.4"),
    url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-5.4",
    note: "`Pragma` and its relationship to `Cache-Control`",
};

impl Rule for CacheControlAndPragmaConsistent {
    fn id(&self) -> &'static str {
        "cache_control_and_pragma_consistent"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
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
            // Check requests: Pragma: no-cache vs Cache-Control: only-if-cached contradiction
            // `Pragma` is the HTTP/1.0 spelling of a request `no-cache`, and `Cache-Control`
            // is the one that means anything now. A message carrying both is asking to be
            // read by two generations of cache and had better say the same thing to each.
            // cite(RFC 9111 § 5.4): "The "Pragma" request header field was defined for HTTP/1.0 caches, so that clients could specify a "no-cache" request"
            for hv in tx.request.headers.get_all("pragma").iter() {
                let s = match hv.to_str() {
                    Ok(v) => v,
                    Err(_) => {
                        // Ignore non-UTF8 header values here and let dedicated
                        // syntax/token rules (e.g., `pragma_token_valid`) handle encoding errors.
                        continue;
                    }
                };
                for m in crate::helpers::headers::list_members(s) {
                    if m.eq_ignore_ascii_case("no-cache") {
                        // if request also contains Cache-Control: only-if-cached, that's contradictory
                        for cc in tx.request.headers.get_all("cache-control").iter() {
                            if let Ok(ccv) = cc.to_str() {
                                for part in
                                    crate::helpers::headers::split_commas_respecting_quotes(ccv)
                                {
                                    let name = part.split('=').next().unwrap().trim();
                                    if name.eq_ignore_ascii_case("only-if-cached") {
                                        // No sentence says this combination is illegal; it is a
                                        // heuristic — Pragma: no-cache asks a cache to revalidate,
                                        // only-if-cached asks it to serve from cache or fail. Recorded
                                        // in the tracker.
                                        return Some(self.violation(ctx.severity, "Request contains 'Pragma: no-cache' and 'Cache-Control: only-if-cached' which are contradictory (RFC 9111 §5.4)".to_string()));
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // A Pragma in a response is deprecated, so flag any response Pragma. §5.4 also carries a
            // gutter Note that "Pragma: no-cache" in responses "was never specified" and so cannot
            // reliably replace Cache-Control: no-cache — that Note can't be machine-cited (its `|`
            // gutter markers break extraction), so it is paraphrased in the message, not cited.
            // cite(RFC 9111 § 5.4): "However, support for Cache-Control is now widespread.  As a result, this specification deprecates Pragma."
            if let Some(resp) = &tx.response {
                if resp.headers.contains_key("pragma") {
                    return Some(self.violation(ctx.severity, "Response contains 'Pragma' header; its meaning in responses was never specified and Pragma is deprecated — use 'Cache-Control' instead (RFC 9111 §5.4)".into()));
                }
            }

            None
        };
        Vec::from_iter(finding())
    }

    fn description(&self) -> &'static str {
        "Flags contradictions between `Pragma` and `Cache-Control` in requests (for example, `Pragma: no-cache` together with `Cache-Control: only-if-cached`), and warns when `Pragma` appears in responses since its meaning there is unspecified. This helps avoid ambiguous or conflicting cache directives that can lead to cache-serving mistakes."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_9111_5_4]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "GET /resource HTTP/1.1\nHost: example.com\nCache-Control: no-cache, max-age=0\n\nHTTP/1.1 200 OK\nCache-Control: no-cache",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "GET /resource HTTP/1.1\nHost: example.com\nPragma: no-cache\nCache-Control: only-if-cached\n\n# Contradictory directives: 'no-cache' requests should not force 'only-if-cached'",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nPragma: no-cache\n\n# 'Pragma' in responses has unspecified semantics; use 'Cache-Control' instead",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nPragma: foo\n\n# Any Pragma in responses is discouraged; prefer Cache-Control",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &CacheControlAndPragmaConsistent;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(Some("no-cache"), Some("only-if-cached"), true)]
    #[case(Some("no-cache"), Some("no-cache"), false)]
    #[case(Some("no-cache"), None, false)]
    #[case(None, Some("only-if-cached"), false)]
    fn request_pragma_and_cache_control_cases(
        #[case] pragma_val: Option<&str>,
        #[case] cc_val: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = CacheControlAndPragmaConsistent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "cache_control_and_pragma_consistent",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        // Build headers map and append values so both headers can coexist
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        if let Some(p) = pragma_val {
            hm.append(
                "pragma",
                hyper::header::HeaderValue::from_str(p).expect("valid header value"),
            );
        }
        if let Some(cc) = cc_val {
            hm.append(
                "cache-control",
                hyper::header::HeaderValue::from_str(cc).expect("valid header value"),
            );
        }
        tx.request.headers = hm;

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(v.is_some());
            let m = v.unwrap().message;
            assert!(m.contains("Pragma") || m.contains("Cache-Control"));
        } else {
            assert!(v.is_none());
        }
        Ok(())
    }

    #[test]
    fn response_with_pragma_reports_violation() {
        let rule = CacheControlAndPragmaConsistent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "cache_control_and_pragma_consistent",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("pragma", "no-cache")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Pragma"));
    }

    #[test]
    fn non_utf8_pragma_is_ignored() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        let rule = CacheControlAndPragmaConsistent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "cache_control_and_pragma_consistent",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        let bad = HeaderValue::from_bytes(&[0xff])?;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        hm.append("pragma", bad);
        tx.request.headers = hm;

        // Non-UTF8 values are ignored by this consistency rule; syntax/token rules should report encoding problems.
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn request_multiple_cache_control_headers_detection() -> anyhow::Result<()> {
        let rule = CacheControlAndPragmaConsistent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "cache_control_and_pragma_consistent",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        hm.append(
            "pragma",
            hyper::header::HeaderValue::from_static("no-cache"),
        );
        hm.append(
            "cache-control",
            hyper::header::HeaderValue::from_static("public"),
        );
        hm.append(
            "cache-control",
            hyper::header::HeaderValue::from_static("only-if-cached"),
        );
        tx.request.headers = hm;

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn request_non_no_cache_pragma_no_violation() {
        let rule = CacheControlAndPragmaConsistent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "cache_control_and_pragma_consistent",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        hm.append("pragma", hyper::header::HeaderValue::from_static("foo"));
        hm.append(
            "cache-control",
            hyper::header::HeaderValue::from_static("only-if-cached"),
        );
        tx.request.headers = hm;

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn response_non_no_cache_pragma_reports_violation() -> anyhow::Result<()> {
        let rule = CacheControlAndPragmaConsistent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "cache_control_and_pragma_consistent",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("pragma", "foo")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn pragma_with_multiple_members_triggers_on_no_cache() {
        let rule = CacheControlAndPragmaConsistent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "cache_control_and_pragma_consistent",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        hm.append(
            "pragma",
            hyper::header::HeaderValue::from_static("no-cache, foo"),
        );
        hm.append(
            "cache-control",
            hyper::header::HeaderValue::from_static("only-if-cached"),
        );
        tx.request.headers = hm;

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn multiple_pragma_headers_trigger_on_response() {
        let rule = CacheControlAndPragmaConsistent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "cache_control_and_pragma_consistent",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        hm.append("pragma", hyper::header::HeaderValue::from_static("foo"));
        hm.append("pragma", hyper::header::HeaderValue::from_static("bar"));
        tx.response.as_mut().unwrap().headers = hm;

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn validate_rules_with_invalid_config_missing_severity() {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "cache_control_and_pragma_consistent");
        // remove severity to simulate invalid config
        if let Some(toml::Value::Table(ref mut table)) =
            cfg.rules.get_mut("cache_control_and_pragma_consistent")
        {
            table.remove("severity");
        }

        let err = crate::rules::validate_rules(&cfg).expect_err("expected validation to fail");
        assert!(err.to_string().contains("Missing required 'severity'"));
    }
}
