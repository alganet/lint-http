// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ClientRequestMethodBodyConsistency;

impl Rule for ClientRequestMethodBodyConsistency {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "client_request_method_body_consistency"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _previous: Option<&crate::http_transaction::HttpTransaction>,
        config: &Self::Config,
    ) -> Option<Violation> {
        let method = tx.request.method.as_str();

        // Only apply to GET and HEAD for now: these methods have no defined request payload semantics
        if !(method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD")) {
            return None;
        }

        // Transfer-Encoding presence indicates a request body (flagged as unexpected rather than normative)
        if tx.request.headers.contains_key("transfer-encoding") {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!(
                    "{} request contains an unexpected message body (Transfer-Encoding present)",
                    method
                ),
            });
        }

        // Content-Length: treat numeric, non-negative values > 0 as an unexpected body.
        // Invalid or non-digit values are delegated to `message_content_length` and are not flagged here.
        if let Some(cl_raw) =
            crate::helpers::headers::get_header_str(&tx.request.headers, "content-length")
        {
            let cl = cl_raw.trim();
            if !cl.is_empty() && cl.chars().all(|c| c.is_ascii_digit()) {
                if let Ok(n) = cl.parse::<u128>() {
                    if n > 0 {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!(
                                "{} request contains an unexpected message body (Content-Length {})",
                                method, n
                            ),
                        });
                    }
                }
                // If parse overflow / too large, let message_content_length rule handle it.
            }
            // Non-digit or empty values are validated by `message_content_length` rule; do nothing here.
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn make_tx_with_req(
        method: &str,
        headers: Vec<(&str, &str)>,
    ) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = method.to_string();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&headers);
        tx
    }

    #[rstest]
    #[case("GET", vec![], false)]
    #[case("GET", vec![("content-length", "0")], false)]
    #[case("GET", vec![("content-length", " 0 ")], false)]
    #[case("GET", vec![("content-length", "10")], true)]
    #[case("GET", vec![("transfer-encoding", "chunked")], true)]
    #[case("HEAD", vec![("content-length", "1")], true)]
    #[case("HEAD", vec![("transfer-encoding", "chunked")], true)]
    #[case("POST", vec![("content-length", "10")], false)]
    fn method_body_cases(
        #[case] method: &str,
        #[case] headers: Vec<(&str, &str)>,
        #[case] expect_violation: bool,
    ) {
        let rule = ClientRequestMethodBodyConsistency;
        let tx = make_tx_with_req(method, headers);
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);

        if expect_violation {
            assert!(v.is_some(), "expected violation for {}", method);
        } else {
            assert!(v.is_none(), "unexpected violation for {}: {:?}", method, v);
        }
    }

    #[test]
    fn invalid_content_length_is_violation() {
        let rule = ClientRequestMethodBodyConsistency;
        let tx = make_tx_with_req("GET", vec![("content-length", "not-a-number")]);
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        // Invalid Content-Length parsing is delegated to `message_content_length` rule; this rule should not flag it as a body.
        assert!(v.is_none());
    }

    #[test]
    fn content_length_overflow_is_delegated() {
        let rule = ClientRequestMethodBodyConsistency;
        let huge = "9".repeat(100); // > u128::MAX digits to force parse overflow
        let tx = make_tx_with_req("GET", vec![("content-length", huge.as_str())]);
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        // Overflowing Content-Length should be validated by `message_content_length` and not treated as a body here.
        assert!(
            v.is_none(),
            "expected no violation for overflowed Content-Length; got {:?}",
            v
        );
    }

    #[test]
    fn empty_or_whitespace_content_length_is_ignored() {
        let rule = ClientRequestMethodBodyConsistency;
        let tx_empty = make_tx_with_req("GET", vec![("content-length", "")]);
        let tx_space = make_tx_with_req("GET", vec![("content-length", "   ")]);
        let cfg = crate::test_helpers::make_test_rule_config();

        let v_empty = rule.check_transaction(&tx_empty, None, &cfg);
        assert!(
            v_empty.is_none(),
            "expected no violation for empty Content-Length; got {:?}",
            v_empty
        );

        let v_space = rule.check_transaction(&tx_space, None, &cfg);
        assert!(
            v_space.is_none(),
            "expected no violation for whitespace Content-Length; got {:?}",
            v_space
        );
    }

    #[test]
    fn violation_messages_are_informative() {
        let rule = ClientRequestMethodBodyConsistency;
        let cfg = crate::test_helpers::make_test_rule_config();

        let tx = make_tx_with_req("GET", vec![("content-length", "10")]);
        let v = rule.check_transaction(&tx, None, &cfg).unwrap();
        assert!(v.message.contains("Content-Length 10"));

        let tx2 = make_tx_with_req("HEAD", vec![("transfer-encoding", "chunked")]);
        let v2 = rule.check_transaction(&tx2, None, &cfg).unwrap();
        assert!(v2.message.contains("Transfer-Encoding present"));
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "client_request_method_body_consistency");
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
