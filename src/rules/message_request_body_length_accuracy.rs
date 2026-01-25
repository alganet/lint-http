// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageRequestBodyLengthAccuracy;

impl Rule for MessageRequestBodyLengthAccuracy {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_request_body_length_accuracy"
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
        let req = &tx.request;

        // If any Content-Length header(s) are present, validate each value and compare
        use hyper::header::CONTENT_LENGTH;
        let entries: Vec<_> = req
            .headers
            .get_all(CONTENT_LENGTH)
            .iter()
            .map(|v| v.to_owned())
            .collect();
        if !entries.is_empty() {
            let mut nums: Vec<u128> = Vec::with_capacity(entries.len());
            let mut raw_values: Vec<String> = Vec::with_capacity(entries.len());

            for hv in &entries {
                let s = match hv.to_str() {
                    Ok(s) => s,
                    Err(_) => {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: "Invalid Content-Length value (non-UTF8)".into(),
                        })
                    }
                };
                raw_values.push(s.to_string());
                let t = s.trim();
                // Per RFC, Content-Length must be 1*DIGIT
                if t.is_empty() || !t.chars().all(|c| c.is_ascii_digit()) {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!("Invalid Content-Length value: '{}'", s),
                    });
                }

                match t.parse::<u128>() {
                    Ok(n) => nums.push(n),
                    Err(_) => {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!("Content-Length value too large: '{}'", s),
                        })
                    }
                }
            }

            // If multiple entries present ensure they are identical
            if nums.len() > 1 {
                let first = nums[0];
                for (i, n) in nums.iter().enumerate().skip(1) {
                    if *n != first {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!(
                                "Multiple Content-Length headers with differing values: '{}' vs '{}'",
                                raw_values[0], raw_values[i]
                            ),
                        });
                    }
                }
            }

            // Compare to captured body length when available
            if let Some(body_len) = req.body_length {
                let cl_v = nums[0];
                if cl_v != body_len as u128 {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!(
                            "Content-Length ({}) does not match captured body bytes ({})",
                            cl_v, body_len
                        ),
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

    #[test]
    fn matching_content_length_and_body_no_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request = crate::http_transaction::RequestInfo {
            method: "POST".into(),
            uri: "http://example/".into(),
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[("content-length", "3")]),
            body_length: Some(3),
        };

        let rule = MessageRequestBodyLengthAccuracy;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn mismatching_content_length_and_body_reports_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request = crate::http_transaction::RequestInfo {
            method: "POST".into(),
            uri: "http://example/".into(),
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[("content-length", "10")]),
            body_length: Some(3),
        };

        let rule = MessageRequestBodyLengthAccuracy;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Content-Length"));
    }

    #[test]
    fn invalid_content_length_reports_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request = crate::http_transaction::RequestInfo {
            method: "POST".into(),
            uri: "http://example/".into(),
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[("content-length", "abc")]),
            body_length: Some(3),
        };

        let rule = MessageRequestBodyLengthAccuracy;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Invalid Content-Length"));
    }

    #[test]
    fn no_content_length_present_no_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request = crate::http_transaction::RequestInfo {
            method: "POST".into(),
            uri: "http://example/".into(),
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[]),
            body_length: Some(5),
        };

        let rule = MessageRequestBodyLengthAccuracy;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn plus_sign_in_content_length_reports_invalid() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request = crate::http_transaction::RequestInfo {
            method: "POST".into(),
            uri: "http://example/".into(),
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[("content-length", "+1")]),
            body_length: Some(1),
        };

        let rule = MessageRequestBodyLengthAccuracy;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Invalid Content-Length"));
    }

    #[test]
    fn multiple_content_length_headers_conflict_reports_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        use hyper::header::HeaderValue;
        hm.append("content-length", HeaderValue::from_static("10"));
        hm.append("content-length", HeaderValue::from_static("20"));
        tx.request = crate::http_transaction::RequestInfo {
            method: "POST".into(),
            uri: "http://example/".into(),
            version: "HTTP/1.1".into(),
            headers: hm,
            body_length: Some(10),
        };

        let rule = MessageRequestBodyLengthAccuracy;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        assert!(v
            .unwrap()
            .message
            .contains("Multiple Content-Length headers"));
    }

    #[test]
    fn non_utf8_content_length_header_is_invalid() -> anyhow::Result<()> {
        let mut tx = crate::test_helpers::make_test_transaction();
        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        let bad = HeaderValue::from_bytes(&[0xff])?;
        hm.insert("content-length", bad);
        tx.request = crate::http_transaction::RequestInfo {
            method: "POST".into(),
            uri: "http://example/".into(),
            version: "HTTP/1.1".into(),
            headers: hm,
            body_length: Some(3),
        };

        let rule = MessageRequestBodyLengthAccuracy;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("non-UTF8") || msg.contains("Invalid Content-Length"));
        Ok(())
    }

    #[test]
    fn content_length_present_but_no_captured_body_no_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request = crate::http_transaction::RequestInfo {
            method: "POST".into(),
            uri: "http://example/".into(),
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[("content-length", "3")]),
            body_length: None,
        };

        let rule = MessageRequestBodyLengthAccuracy;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn content_length_value_too_large_reports_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request = crate::http_transaction::RequestInfo {
            method: "POST".into(),
            uri: "http://example/".into(),
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[(
                "content-length",
                "340282366920938463463374607431768211456",
            )]),
            body_length: Some(0),
        };

        let rule = MessageRequestBodyLengthAccuracy;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("too large"));
    }

    #[test]
    fn multiple_identical_content_length_headers_no_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        use hyper::header::HeaderValue;
        hm.append("content-length", HeaderValue::from_static("10"));
        hm.append("content-length", HeaderValue::from_static("10"));
        tx.request = crate::http_transaction::RequestInfo {
            method: "POST".into(),
            uri: "http://example/".into(),
            version: "HTTP/1.1".into(),
            headers: hm,
            body_length: Some(10),
        };

        let rule = MessageRequestBodyLengthAccuracy;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn whitespace_in_content_length_is_accepted() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request = crate::http_transaction::RequestInfo {
            method: "POST".into(),
            uri: "http://example/".into(),
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[("content-length", "  3  ")]),
            body_length: Some(3),
        };

        let rule = MessageRequestBodyLengthAccuracy;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_request_body_length_accuracy");
        let _ = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn validate_rules_with_invalid_config_missing_severity() {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_request_body_length_accuracy");
        // remove severity to simulate invalid config
        if let Some(toml::Value::Table(ref mut table)) =
            cfg.rules.get_mut("message_request_body_length_accuracy")
        {
            table.remove("severity");
        }

        let err = crate::rules::validate_rules(&cfg).expect_err("expected validation to fail");
        assert!(err.to_string().contains("Missing required 'severity'"));
    }
}
