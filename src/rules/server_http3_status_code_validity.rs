// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ServerHttp3StatusCodeValidity;

impl Rule for ServerHttp3StatusCodeValidity {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "server_http3_status_code_validity"
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
        // Only applies to HTTP/3 connections.
        if tx.request.version != "HTTP/3" {
            return None;
        }

        let resp = tx.response.as_ref()?;

        // Only check responses that are themselves HTTP/3. In a reverse-proxy
        // setup the upstream response may be HTTP/1.1 (where 101 is valid).
        if resp.version != "HTTP/3" {
            return None;
        }

        // RFC 9114 §4.5: HTTP/3 does not use the 101 (Switching Protocols)
        // informational status code.
        if resp.status == 101 {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message:
                    "HTTP/3 does not support 101 (Switching Protocols); use extended CONNECT instead"
                        .into(),
            });
        }

        // RFC 9110 §15.2, RFC 9114 §4.1: Informational (1xx) responses
        // consist of only a HEADERS frame — no content, no trailers.
        if (100..200).contains(&resp.status) {
            // Content-Length MUST NOT appear on 1xx responses (RFC 9110 §15.2).
            if resp.headers.contains_key("content-length") {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!(
                        "HTTP/3 {} informational response must not include Content-Length",
                        resp.status
                    ),
                });
            }

            // A captured body on a 1xx response indicates DATA frames were
            // sent after an informational HEADERS frame, which is invalid.
            if let Some(len) = resp.body_length {
                if len > 0 {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!(
                            "HTTP/3 {} informational response must not contain a message body",
                            resp.status
                        ),
                    });
                }
            }

            // Informational responses do not carry trailers (RFC 9110 §15.2).
            if resp.trailers.is_some() {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!(
                        "HTTP/3 {} informational response must not contain trailer fields",
                        resp.status
                    ),
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

    fn make_h3_transaction_with_response(
        status: u16,
        resp_headers: &[(&str, &str)],
    ) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(status, resp_headers);
        tx.request.version = "HTTP/3".into();
        if let Some(ref mut resp) = tx.response {
            resp.version = "HTTP/3".into();
        }
        tx
    }

    // --- 101 Switching Protocols is forbidden ---

    #[test]
    fn status_101_is_violation() {
        let rule = ServerHttp3StatusCodeValidity;
        let tx = make_h3_transaction_with_response(101, &[("upgrade", "websocket")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        let v = v.expect("should be a violation");
        assert_eq!(v.rule, "server_http3_status_code_validity");
        assert_eq!(v.severity, crate::lint::Severity::Warn);
        assert!(v.message.contains("101"));
    }

    #[test]
    fn status_101_bare_is_violation() {
        // 101 without any extra headers is still a violation
        let rule = ServerHttp3StatusCodeValidity;
        let tx = make_h3_transaction_with_response(101, &[]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("101"));
    }

    // --- Valid 1xx informational responses ---

    #[rstest]
    #[case(100, &[])]
    #[case(102, &[])]
    #[case(103, &[("link", "</style.css>; rel=preload; as=style")])]
    fn valid_1xx_is_ok(#[case] status: u16, #[case] headers: &[(&str, &str)]) {
        let rule = ServerHttp3StatusCodeValidity;
        let tx = make_h3_transaction_with_response(status, headers);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    // --- 1xx with Content-Length is violation ---

    #[test]
    fn informational_100_with_content_length_is_violation() {
        let rule = ServerHttp3StatusCodeValidity;
        let tx = make_h3_transaction_with_response(100, &[("content-length", "0")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        let v = v.expect("should be a violation");
        assert_eq!(v.rule, "server_http3_status_code_validity");
        assert!(v.message.contains("100"));
        assert!(v.message.contains("Content-Length"));
    }

    #[test]
    fn informational_103_with_content_length_is_violation() {
        let rule = ServerHttp3StatusCodeValidity;
        let tx = make_h3_transaction_with_response(103, &[("content-length", "42")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("103"));
        assert!(msg.contains("Content-Length"));
    }

    // --- 1xx with body is violation ---

    #[test]
    fn informational_with_body_is_violation() {
        let rule = ServerHttp3StatusCodeValidity;
        let mut tx = make_h3_transaction_with_response(100, &[]);
        if let Some(ref mut resp) = tx.response {
            resp.body_length = Some(10);
        }

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("message body"));
    }

    #[test]
    fn informational_with_zero_body_length_is_ok() {
        let rule = ServerHttp3StatusCodeValidity;
        let mut tx = make_h3_transaction_with_response(100, &[]);
        if let Some(ref mut resp) = tx.response {
            resp.body_length = Some(0);
        }

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    // --- 1xx with trailers is violation ---

    #[test]
    fn informational_with_trailers_is_violation() {
        let rule = ServerHttp3StatusCodeValidity;
        let mut tx = make_h3_transaction_with_response(100, &[]);
        if let Some(ref mut resp) = tx.response {
            resp.trailers = Some(crate::test_helpers::make_headers_from_pairs(&[(
                "x-checksum",
                "abc",
            )]));
        }

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("trailer"));
    }

    // --- Non-informational statuses are ok ---

    #[rstest]
    #[case(200)]
    #[case(204)]
    #[case(301)]
    #[case(304)]
    #[case(404)]
    #[case(500)]
    fn non_informational_status_is_ok(#[case] status: u16) {
        let rule = ServerHttp3StatusCodeValidity;
        let tx = make_h3_transaction_with_response(status, &[]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    // --- HTTP version gating ---

    #[test]
    fn http11_101_is_not_checked() {
        let rule = ServerHttp3StatusCodeValidity;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            101,
            &[("upgrade", "websocket")],
        );

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn h3_request_non_h3_response_101_is_not_checked() {
        // Reverse-proxy scenario: client is HTTP/3 but upstream is HTTP/1.1
        let rule = ServerHttp3StatusCodeValidity;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            101,
            &[("upgrade", "websocket")],
        );
        tx.request.version = "HTTP/3".into();
        // response.version stays HTTP/1.1

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    // --- No response case ---

    #[test]
    fn no_response_is_ok() {
        let rule = ServerHttp3StatusCodeValidity;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.version = "HTTP/3".into();

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    // --- Edge cases: 1xx boundary ---

    #[test]
    fn status_199_with_content_length_is_violation() {
        // 199 is still in the 1xx informational range
        let rule = ServerHttp3StatusCodeValidity;
        let tx = make_h3_transaction_with_response(199, &[("content-length", "0")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("199"));
    }

    #[test]
    fn status_200_with_content_length_is_ok() {
        // 200 is not informational; Content-Length is allowed
        let rule = ServerHttp3StatusCodeValidity;
        let tx = make_h3_transaction_with_response(200, &[("content-length", "42")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    // --- Edge cases: non-informational with body/trailers are ok ---

    #[test]
    fn non_informational_with_body_is_ok() {
        let rule = ServerHttp3StatusCodeValidity;
        let mut tx = make_h3_transaction_with_response(200, &[]);
        if let Some(ref mut resp) = tx.response {
            resp.body_length = Some(100);
        }

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn non_informational_with_trailers_is_ok() {
        let rule = ServerHttp3StatusCodeValidity;
        let mut tx = make_h3_transaction_with_response(200, &[]);
        if let Some(ref mut resp) = tx.response {
            resp.trailers = Some(crate::test_helpers::make_headers_from_pairs(&[(
                "x-checksum",
                "abc",
            )]));
        }

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    // --- Edge cases: priority of checks ---

    #[test]
    fn content_length_check_takes_priority_over_body_check() {
        // When both Content-Length and body are present, Content-Length is flagged first
        let rule = ServerHttp3StatusCodeValidity;
        let mut tx = make_h3_transaction_with_response(100, &[("content-length", "10")]);
        if let Some(ref mut resp) = tx.response {
            resp.body_length = Some(10);
        }

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Content-Length"));
    }

    #[test]
    fn status_101_takes_priority_over_1xx_checks() {
        // 101 is flagged as forbidden before any 1xx content checks
        let rule = ServerHttp3StatusCodeValidity;
        let mut tx = make_h3_transaction_with_response(101, &[("content-length", "0")]);
        if let Some(ref mut resp) = tx.response {
            resp.body_length = Some(10);
        }

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("101"));
    }

    // --- Edge cases: informational with no body_length (None) ---

    #[test]
    fn informational_with_no_body_length_is_ok() {
        let rule = ServerHttp3StatusCodeValidity;
        let mut tx = make_h3_transaction_with_response(100, &[]);
        if let Some(ref mut resp) = tx.response {
            resp.body_length = None;
        }

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    // --- Edge case: HTTP/2 request with version gating ---

    #[test]
    fn http2_request_is_not_checked() {
        let rule = ServerHttp3StatusCodeValidity;
        let mut tx =
            crate::test_helpers::make_test_transaction_with_response(101, &[("upgrade", "h2c")]);
        tx.request.version = "HTTP/2.0".into();

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    // --- Edge case: 102 Processing with body ---

    #[test]
    fn informational_102_with_body_is_violation() {
        let rule = ServerHttp3StatusCodeValidity;
        let mut tx = make_h3_transaction_with_response(102, &[]);
        if let Some(ref mut resp) = tx.response {
            resp.body_length = Some(5);
        }

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("102"));
    }

    // --- Edge case: empty trailers HeaderMap is still a violation ---

    #[test]
    fn informational_with_empty_trailers_is_violation() {
        // Even an empty trailing HEADERS frame is invalid on 1xx (RFC 9110 §15.2)
        let rule = ServerHttp3StatusCodeValidity;
        let mut tx = make_h3_transaction_with_response(100, &[]);
        if let Some(ref mut resp) = tx.response {
            resp.trailers = Some(hyper::HeaderMap::new());
        }

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("trailer"));
    }

    // --- Edge case: 103 Early Hints with trailers ---

    #[test]
    fn informational_103_with_trailers_is_violation() {
        let rule = ServerHttp3StatusCodeValidity;
        let mut tx = make_h3_transaction_with_response(
            103,
            &[("link", "</style.css>; rel=preload; as=style")],
        );
        if let Some(ref mut resp) = tx.response {
            resp.trailers = Some(crate::test_helpers::make_headers_from_pairs(&[(
                "x-timing", "50ms",
            )]));
        }

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("trailer"));
    }

    // --- Scope and config validation ---

    #[test]
    fn scope_is_server() {
        let rule = ServerHttp3StatusCodeValidity;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "server_http3_status_code_validity");
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
