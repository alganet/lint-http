// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct Server200Vs204BodyConsistency;

impl Rule for Server200Vs204BodyConsistency {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "server_200_vs_204_body_consistency"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _previous: Option<&crate::http_transaction::HttpTransaction>,
        config: &Self::Config,
    ) -> Option<Violation> {
        let resp = match &tx.response {
            Some(r) => r,
            None => return None,
        };

        // Only consider 200 responses
        if resp.status != 200 {
            return None;
        }

        // HEAD responses do not have a body by design
        if tx.request.method.eq_ignore_ascii_case("HEAD") {
            return None;
        }

        // If Transfer-Encoding present, assume body may be present
        if resp.headers.contains_key("transfer-encoding") {
            return None;
        }

        // If Content-Length header present and equals numeric zero => no content.
        match crate::helpers::headers::validate_content_length(&resp.headers) {
            Ok(Some(n)) => {
                if n == 0 {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "200 response contains no body (Content-Length: 0); consider using 204 No Content when no content is appropriate (RFC 9110 §15.3.1)".into(),
                    });
                } else {
                    // content-length > 0 -> has body
                    return None;
                }
            }
            Ok(None) => { /* no Content-Length header: continue to other checks */ }
            Err(_) => {
                // Invalid/malformed Content-Length is a separate violation handled by
                // `message_content_length`. Be conservative here and do not report.
                return None;
            }
        }

        // If decoded body length known and zero -> suggest 204
        if let Some(len) = resp.body_length {
            if len == 0 {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "200 response contains no body (captured length 0); consider using 204 No Content when no content is appropriate (RFC 9110 §15)".into(),
                });
            } else {
                return None;
            }
        }

        // If no explicit indicators (no content-length, no transfer-encoding, and unknown body length), be conservative and do not report.
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn make_tx_with_response(
        status: u16,
        method: &str,
        headers: &[(&str, &str)],
    ) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(status, headers);
        tx.request.method = method.into();
        tx
    }

    #[rstest]
    #[case(200, "POST", &[("content-length","0")], None, true)]
    #[case(200, "GET", &[("content-length","0")], None, true)]
    #[case(200, "GET", &[("content-length","0"),("transfer-encoding","chunked")], None, false)]
    #[case(200, "GET", &[("content-length","00")], None, true)]
    #[case(200, "GET", &[("content-length","10"), ("content-length","20")], None, false)]
    #[case(200, "GET", &[("content-length","abc")], None, false)]
    #[case(200, "HEAD", &[("content-length","0")], None, false)]
    #[case(200, "GET", &[("content-length","123")], None, false)]
    #[case(200, "GET", &[], None, false)]
    #[case(200, "GET", &[], Some(0), true)]
    #[case(200, "GET", &[], Some(10), false)]
    #[case(200, "GET", &[ ("transfer-encoding", "chunked") ], None, false)]
    #[case(204, "GET", &[ ("content-length", "0") ], None, false)]
    fn check_cases(
        #[case] status: u16,
        #[case] method: &str,
        #[case] headers: &[(&str, &str)],
        #[case] body_len: Option<u64>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = Server200Vs204BodyConsistency;
        let mut tx = make_tx_with_response(status, method, headers);
        // If the test case specifies a captured body length, apply it to the response
        // so the rule can observe it during checking.
        if let Some(len) = body_len {
            if let Some(resp) = tx.response.as_mut() {
                resp.body_length = Some(len);
            }
        }

        let cfg = crate::test_helpers::make_test_rule_config();

        let v = rule.check_transaction(&tx, None, &cfg);
        if expect_violation {
            assert!(
                v.is_some(),
                "expected violation for status {} method {} headers {:?} body_len {:?}",
                status,
                method,
                headers,
                body_len
            );
        } else {
            assert!(v.is_none(), "unexpected violation: {:?}", v);
        }
        Ok(())
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "server_200_vs_204_body_consistency");
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn no_response_returns_none() -> anyhow::Result<()> {
        let rule = Server200Vs204BodyConsistency;
        let tx = crate::test_helpers::make_test_transaction();
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn violation_message_for_content_length_zero() -> anyhow::Result<()> {
        let rule = Server200Vs204BodyConsistency;
        let tx = make_tx_with_response(200, "GET", &[("content-length", "0")]);
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule
            .check_transaction(&tx, None, &cfg)
            .expect("expected violation");
        assert!(v.message.contains("Content-Length: 0"));
        Ok(())
    }

    #[test]
    fn violation_message_for_captured_zero() -> anyhow::Result<()> {
        let rule = Server200Vs204BodyConsistency;
        let mut tx = make_tx_with_response(200, "GET", &[]);
        // Simulate a captured decoded response body of length zero
        if let Some(resp) = tx.response.as_mut() {
            resp.body_length = Some(0);
        }
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule
            .check_transaction(&tx, None, &cfg)
            .expect("expected violation");
        assert!(v.message.contains("captured length 0"));
        Ok(())
    }

    #[test]
    fn scope_is_server() {
        let rule = Server200Vs204BodyConsistency;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }

    #[test]
    fn id_is_rule_name() {
        let rule = Server200Vs204BodyConsistency;
        assert_eq!(rule.id(), "server_200_vs_204_body_consistency");
    }

    #[test]
    fn non_utf8_content_length_is_ignored() -> anyhow::Result<()> {
        // Create a response with a non-UTF8 Content-Length header and ensure
        // the rule does not report a violation (another rule handles malformed CL).
        let rule = Server200Vs204BodyConsistency;
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = hyper::HeaderMap::new();
        let bad_value = hyper::header::HeaderValue::from_bytes(&[0xFF])?;
        hm.insert(hyper::header::CONTENT_LENGTH, bad_value);
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,
            body_length: None,
        });

        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
        Ok(())
    }
}
