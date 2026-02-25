// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageContentLocationAndUriConsistency;

impl Rule for MessageContentLocationAndUriConsistency {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_content_location_and_uri_consistency"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        config: &Self::Config,
    ) -> Option<Violation> {
        let Some(resp) = &tx.response else {
            return None;
        };

        for hv in resp.headers.get_all("content-location") {
            // UTF-8 check
            let Ok(s) = hv.to_str() else {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Content-Location header value is not valid UTF-8".into(),
                });
            };

            if s.trim().is_empty() {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Content-Location header must not be empty".into(),
                });
            }

            if crate::helpers::uri::contains_whitespace(s) {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Content-Location header must not contain whitespace".into(),
                });
            }

            if let Some(msg) = crate::helpers::uri::check_percent_encoding(s) {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: msg,
                });
            }

            if let Some(msg) = crate::helpers::uri::validate_scheme_if_present(s) {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: msg,
                });
            }

            // Consistency check: if response is 2xx, compare Content-Location to target URI
            if (200..300).contains(&resp.status) {
                // Request path (if any) — preserve query when present and ignore fragment
                let req_path_opt = crate::helpers::uri::extract_path_and_query_from_request_target(
                    &tx.request.uri,
                );

                // If the request-target carries no path (authority-form or '*'), skip the consistency check
                if req_path_opt.is_none() {
                    continue;
                }

                // Try to get path+query from Content-Location (if any)
                let cl_path_opt =
                    crate::helpers::uri::extract_path_and_query_from_request_target(s);

                // If absolute, also compare origin
                let cl_origin_opt = crate::helpers::uri::extract_origin_if_absolute(s);
                let req_origin_opt =
                    crate::helpers::uri::extract_origin_if_absolute(&tx.request.uri);

                // If we can obtain a path for Content-Location, compare; require origin match when both are absolute
                let mut matches = false;
                if let (Some(req_path), Some(cl_path)) =
                    (req_path_opt.as_deref(), cl_path_opt.as_deref())
                {
                    if let (Some(req_origin), Some(cl_origin)) =
                        (req_origin_opt.as_deref(), cl_origin_opt.as_deref())
                    {
                        // both absolute: require both origin and path+query to match
                        if req_origin.eq_ignore_ascii_case(cl_origin) && req_path == cl_path {
                            matches = true;
                        }
                    } else {
                        // partial or both path-only: compare path+query
                        if req_path == cl_path {
                            matches = true;
                        }
                    }
                }

                if !matches {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Content-Location does not match the request target; content may identify a different resource".into(),
                    });
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;
    use rstest::rstest;

    fn make_tx_with_req_uri(
        req_uri: &str,
        status: u16,
        headers: &[(&str, &str)],
    ) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.uri = req_uri.into();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(headers),
            body_length: None,
        });
        tx
    }

    #[rstest]
    #[case("/foo", 200, &[ ("content-location", "/foo") ], false)]
    #[case("/foo", 200, &[ ("content-location", "/bar") ], true)]
    #[case("/foo", 200, &[ ("content-location", "http://example.com/foo") ], false)]
    #[case("http://example.com/foo", 200, &[ ("content-location", "http://example.com/foo") ], false)]
    #[case("http://example.com/foo", 200, &[ ("content-location", "http://example.com/bar") ], true)]
    // Query-string preservation: mismatched queries should be considered inconsistent
    #[case("/foo?x=1", 200, &[ ("content-location", "/foo?x=1") ], false)]
    #[case("/foo?x=1", 200, &[ ("content-location", "/foo?x=2") ], true)]
    #[case("http://example.com/foo?x=1", 200, &[ ("content-location", "http://example.com/foo?x=2") ], true)]
    // Authority-form request-targets (e.g., CONNECT) carry no path — skip consistency check
    #[case("example.com:443", 200, &[ ("content-location", "/foo") ], false)]
    fn check_consistency_cases(
        #[case] req_uri: &str,
        #[case] status: u16,
        #[case] headers: &[(&str, &str)],
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageContentLocationAndUriConsistency;
        let cfg = crate::test_helpers::make_test_rule_config();
        let tx = make_tx_with_req_uri(req_uri, status, headers);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(v.is_some());
        } else {
            assert!(v.is_none());
        }
        Ok(())
    }

    #[test]
    fn bad_percent_encoding_reports_violation() {
        let rule = MessageContentLocationAndUriConsistency;
        let cfg = crate::test_helpers::make_test_rule_config();
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-location", "/bad%2G")],
        );
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Invalid percent-encoding"));
    }

    #[test]
    fn whitespace_in_value_reports_violation() {
        let rule = MessageContentLocationAndUriConsistency;
        let cfg = crate::test_helpers::make_test_rule_config();
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-location", "/a b")],
        );
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("must not contain whitespace"));
    }

    #[test]
    fn non_utf8_header_value_is_violation() {
        let rule = MessageContentLocationAndUriConsistency;
        let cfg = crate::test_helpers::make_test_rule_config();
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = hyper::HeaderMap::new();
        hm.insert(
            "content-location",
            HeaderValue::from_bytes(&[0xff]).unwrap(),
        );
        tx.response.as_mut().unwrap().headers = hm;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn empty_value_reports_violation() {
        let rule = MessageContentLocationAndUriConsistency;
        let cfg = crate::test_helpers::make_test_rule_config();
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-location", "")],
        );
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn fragment_in_content_location_is_ignored_for_matching() {
        let rule = MessageContentLocationAndUriConsistency;
        let cfg = crate::test_helpers::make_test_rule_config();
        let tx = make_tx_with_req_uri("/foo", 200, &[("content-location", "/foo#frag")]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn trailing_slash_mismatch_reports_violation() {
        let rule = MessageContentLocationAndUriConsistency;
        let cfg = crate::test_helpers::make_test_rule_config();
        let tx = make_tx_with_req_uri("/foo", 200, &[("content-location", "/foo/")]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn origin_case_insensitive_match() {
        let rule = MessageContentLocationAndUriConsistency;
        let cfg = crate::test_helpers::make_test_rule_config();
        let tx = make_tx_with_req_uri(
            "http://EXAMPLE.com/foo",
            200,
            &[("content-location", "http://example.com/foo")],
        );
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_content_location_and_uri_consistency");
        let _ = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn validate_rules_with_invalid_config_missing_severity() {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_content_location_and_uri_consistency");
        // remove severity to simulate invalid config
        if let Some(toml::Value::Table(ref mut table)) = cfg
            .rules
            .get_mut("message_content_location_and_uri_consistency")
        {
            table.remove("severity");
        }

        let err = crate::rules::validate_rules(&cfg).expect_err("expected validation to fail");
        assert!(err.to_string().contains("Missing required 'severity'"));
    }

    #[test]
    fn scope_is_server() {
        let rule = MessageContentLocationAndUriConsistency;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }
}
