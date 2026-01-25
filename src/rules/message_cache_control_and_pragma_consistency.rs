// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageCacheControlAndPragmaConsistency;

impl Rule for MessageCacheControlAndPragmaConsistency {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_cache_control_and_pragma_consistency"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _previous: Option<&crate::http_transaction::HttpTransaction>,
        config: &Self::Config,
    ) -> Option<Violation> {
        // Check requests: Pragma: no-cache vs Cache-Control: only-if-cached contradiction
        for hv in tx.request.headers.get_all("pragma").iter() {
            let s = match hv.to_str() {
                Ok(v) => v,
                Err(_) => {
                    // Ignore non-UTF8 header values here and let dedicated
                    // syntax/token rules (e.g., `message_pragma_token_valid`) handle encoding errors.
                    continue;
                }
            };
            for member in crate::helpers::headers::parse_list_header(s) {
                let m = member.trim();
                if m.eq_ignore_ascii_case("no-cache") {
                    // if request also contains Cache-Control: only-if-cached, that's contradictory
                    for cc in tx.request.headers.get_all("cache-control").iter() {
                        if let Ok(ccv) = cc.to_str() {
                            for part in crate::helpers::headers::split_commas_respecting_quotes(ccv)
                            {
                                let name = part.split('=').next().unwrap().trim();
                                if name.eq_ignore_ascii_case("only-if-cached") {
                                    return Some(Violation {
                                        rule: self.id().into(),
                                        severity: config.severity,
                                        message: "Request contains 'Pragma: no-cache' and 'Cache-Control: only-if-cached' which are contradictory (RFC 7234 §5.4)".to_string(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        // Check responses: presence of Pragma (especially 'no-cache') is not specified and should be replaced by Cache-Control
        if let Some(resp) = &tx.response {
            if resp.headers.contains_key("pragma") {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Response contains 'Pragma' header; the meaning of 'Pragma' in responses is not specified by RFC 7234 §5.4 - use 'Cache-Control' instead".into(),
                });
            }
        }

        None
    }
}

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
        let rule = MessageCacheControlAndPragmaConsistency;
        let cfg = crate::test_helpers::make_test_rule_config();

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

        let v = rule.check_transaction(&tx, None, &cfg);
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
        let rule = MessageCacheControlAndPragmaConsistency;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("pragma", "no-cache")]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Pragma"));
    }

    #[test]
    fn non_utf8_pragma_is_ignored() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        let rule = MessageCacheControlAndPragmaConsistency;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        let bad = HeaderValue::from_bytes(&[0xff])?;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        hm.append("pragma", bad);
        tx.request.headers = hm;

        // Non-UTF8 values are ignored by this consistency rule; syntax/token rules should report encoding problems.
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn request_multiple_cache_control_headers_detection() -> anyhow::Result<()> {
        let rule = MessageCacheControlAndPragmaConsistency;
        let cfg = crate::test_helpers::make_test_rule_config();

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

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn request_non_no_cache_pragma_no_violation() {
        let rule = MessageCacheControlAndPragmaConsistency;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        hm.append("pragma", hyper::header::HeaderValue::from_static("foo"));
        hm.append(
            "cache-control",
            hyper::header::HeaderValue::from_static("only-if-cached"),
        );
        tx.request.headers = hm;

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn response_non_no_cache_pragma_reports_violation() -> anyhow::Result<()> {
        let rule = MessageCacheControlAndPragmaConsistency;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("pragma", "foo")]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn pragma_with_multiple_members_triggers_on_no_cache() {
        let rule = MessageCacheControlAndPragmaConsistency;
        let cfg = crate::test_helpers::make_test_rule_config();

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

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
    }

    #[test]
    fn multiple_pragma_headers_trigger_on_response() {
        let rule = MessageCacheControlAndPragmaConsistency;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        hm.append("pragma", hyper::header::HeaderValue::from_static("foo"));
        hm.append("pragma", hyper::header::HeaderValue::from_static("bar"));
        tx.response.as_mut().unwrap().headers = hm;

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
    }

    #[test]
    fn validate_rules_with_invalid_config_missing_severity() {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_cache_control_and_pragma_consistency");
        // remove severity to simulate invalid config
        if let Some(toml::Value::Table(ref mut table)) = cfg
            .rules
            .get_mut("message_cache_control_and_pragma_consistency")
        {
            table.remove("severity");
        }

        let err = crate::rules::validate_rules(&cfg).expect_err("expected validation to fail");
        assert!(err.to_string().contains("Missing required 'severity'"));
    }
}
