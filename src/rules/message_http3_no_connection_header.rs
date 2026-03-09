// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// Connection-specific headers that MUST NOT appear in HTTP/3 messages.
const FORBIDDEN_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
];

pub struct MessageHttp3NoConnectionHeader;

impl Rule for MessageHttp3NoConnectionHeader {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_http3_no_connection_header"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        config: &Self::Config,
    ) -> Option<Violation> {
        // Only applies to HTTP/3 transactions.
        if tx.request.version != "HTTP/3" {
            return None;
        }

        // Check request headers.
        if let Some(msg) = check_forbidden_headers(&tx.request.headers) {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: msg,
            });
        }

        // Check TE header in request: only "trailers" is allowed.
        if let Some(msg) = check_te_header(&tx.request.headers) {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: msg,
            });
        }

        // Check response headers only when the response itself is HTTP/3.
        // In a reverse-proxy setup the upstream response may be HTTP/1.1 or
        // HTTP/2 and legitimately carry Connection/Transfer-Encoding headers
        // that are later stripped before forwarding over HTTP/3.
        if let Some(resp) = &tx.response {
            if resp.version == "HTTP/3" {
                if let Some(msg) = check_forbidden_headers(&resp.headers) {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: msg,
                    });
                }

                // TE is a request-only header (RFC 9110 §10.1.4); any
                // presence in an HTTP/3 response is invalid.
                if resp.headers.contains_key("te") {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "HTTP/3 response must not contain TE header (request-only field)"
                            .into(),
                    });
                }
            }
        }

        None
    }
}

/// Check for the presence of any forbidden connection-specific header.
fn check_forbidden_headers(headers: &hyper::HeaderMap) -> Option<String> {
    for &name in FORBIDDEN_HEADERS {
        if headers.contains_key(name) {
            return Some(format!(
                "HTTP/3 message must not contain connection-specific header '{}'",
                name
            ));
        }
    }
    None
}

/// Check that the TE header, if present, contains only "trailers".
fn check_te_header(headers: &hyper::HeaderMap) -> Option<String> {
    if let Some(val) = headers.get("te") {
        if let Ok(s) = val.to_str() {
            let has_non_trailers = crate::helpers::headers::parse_list_header(s)
                .any(|token| !token.eq_ignore_ascii_case("trailers"));
            if has_non_trailers {
                return Some(
                    "HTTP/3 TE header must not contain any value other than 'trailers'".into(),
                );
            }
        } else {
            return Some("HTTP/3 TE header contains non-UTF-8 value".into());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn make_h3_transaction() -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.version = "HTTP/3".into();
        tx
    }

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

    // --- Request header tests ---

    #[rstest]
    #[case("connection", "keep-alive")]
    #[case("keep-alive", "timeout=5")]
    #[case("proxy-connection", "keep-alive")]
    #[case("transfer-encoding", "chunked")]
    #[case("upgrade", "websocket")]
    fn request_forbidden_header_is_violation(
        #[case] header_name: &str,
        #[case] header_value: &str,
    ) {
        let rule = MessageHttp3NoConnectionHeader;
        let mut tx = make_h3_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[(header_name, header_value)]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains(header_name));
    }

    #[test]
    fn request_no_forbidden_headers_is_ok() {
        let rule = MessageHttp3NoConnectionHeader;
        let mut tx = make_h3_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("accept", "text/html")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    // --- Response header tests ---

    #[rstest]
    #[case("connection", "close")]
    #[case("keep-alive", "timeout=5")]
    #[case("proxy-connection", "keep-alive")]
    #[case("transfer-encoding", "chunked")]
    #[case("upgrade", "h2c")]
    fn response_forbidden_header_is_violation(
        #[case] header_name: &str,
        #[case] header_value: &str,
    ) {
        let rule = MessageHttp3NoConnectionHeader;
        let tx = make_h3_transaction_with_response(200, &[(header_name, header_value)]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains(header_name));
    }

    #[test]
    fn response_no_forbidden_headers_is_ok() {
        let rule = MessageHttp3NoConnectionHeader;
        let tx = make_h3_transaction_with_response(200, &[("content-type", "text/html")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    // --- TE header tests ---

    #[test]
    fn request_te_trailers_is_ok() {
        let rule = MessageHttp3NoConnectionHeader;
        let mut tx = make_h3_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[("te", "trailers")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn request_te_non_trailers_is_violation() {
        let rule = MessageHttp3NoConnectionHeader;
        let mut tx = make_h3_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[("te", "gzip")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("TE header"));
    }

    #[test]
    fn request_te_trailers_mixed_case_is_ok() {
        let rule = MessageHttp3NoConnectionHeader;
        let mut tx = make_h3_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[("te", "Trailers")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn request_te_trailers_with_other_value_is_violation() {
        let rule = MessageHttp3NoConnectionHeader;
        let mut tx = make_h3_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("te", "trailers, gzip")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("TE header"));
    }

    // --- HTTP version gating ---

    #[test]
    fn http11_with_connection_header_is_not_checked() {
        let rule = MessageHttp3NoConnectionHeader;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.version = "HTTP/1.1".into();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("connection", "keep-alive")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn http2_with_connection_header_is_not_checked() {
        let rule = MessageHttp3NoConnectionHeader;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.version = "HTTP/2".into();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("connection", "keep-alive")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    // --- No response case ---

    #[test]
    fn h3_request_only_no_response_is_ok_when_clean() {
        let rule = MessageHttp3NoConnectionHeader;
        let mut tx = make_h3_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[("accept", "*/*")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    // --- Response TE header tests ---

    #[test]
    fn response_te_any_value_is_violation() {
        // TE is a request-only header; any presence in HTTP/3 response is invalid.
        let rule = MessageHttp3NoConnectionHeader;
        let tx = make_h3_transaction_with_response(200, &[("te", "trailers")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("request-only"));
    }

    // --- Response version gating ---

    #[test]
    fn response_non_h3_version_with_connection_headers_is_ok() {
        // Upstream HTTP/1.1 response with Connection headers should not be flagged,
        // even when the request is HTTP/3 (reverse-proxy scenario).
        let rule = MessageHttp3NoConnectionHeader;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[
                ("connection", "keep-alive"),
                ("transfer-encoding", "chunked"),
            ],
        );
        tx.request.version = "HTTP/3".into();
        // Response version stays HTTP/1.1 (upstream)

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    // --- Non-UTF-8 TE value ---

    #[test]
    fn request_te_non_utf8_is_violation() {
        let rule = MessageHttp3NoConnectionHeader;
        let mut tx = make_h3_transaction();
        let bad = hyper::header::HeaderValue::from_bytes(&[0xff])
            .expect("should construct non-utf8 header");
        tx.request.headers.insert("te", bad);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("non-UTF-8"));
    }

    // --- Edge cases: empty TE, request with forbidden + TE ---

    #[test]
    fn request_te_empty_is_ok() {
        let rule = MessageHttp3NoConnectionHeader;
        let mut tx = make_h3_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[("te", "")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        // Empty TE is not a violation (parse_list_header filters empty tokens)
        assert!(v.is_none());
    }

    #[test]
    fn request_forbidden_header_takes_priority_over_te() {
        let rule = MessageHttp3NoConnectionHeader;
        let mut tx = make_h3_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("connection", "keep-alive"),
            ("te", "gzip"),
        ]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        // Forbidden header check runs first
        assert!(v.unwrap().message.contains("connection"));
    }

    // --- Scope and config validation ---

    #[test]
    fn scope_is_both() {
        let rule = MessageHttp3NoConnectionHeader;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_http3_no_connection_header");
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
