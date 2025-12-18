// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageContentLength;

impl Rule for MessageContentLength {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_content_length"
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
        // Helper checks a HeaderMap for Content-Length problems
        let check = |headers: &hyper::HeaderMap| -> Option<Violation> {
            let entries: Vec<_> = headers
                .get_all(hyper::header::CONTENT_LENGTH)
                .iter()
                .map(|v| v.to_owned())
                .collect();

            if entries.is_empty() {
                return None;
            }

            // Parse and validate each value
            let mut nums: Vec<Option<u128>> = Vec::with_capacity(entries.len());
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
                if t.is_empty() || !t.chars().all(|c| c.is_ascii_digit()) {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!("Invalid Content-Length value: '{}'", s),
                    });
                }
                // Explicitly check for parse overflow (too large values)
                match t.parse::<u128>() {
                    Ok(n) => nums.push(Some(n)),
                    Err(_) => {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!("Content-Length value too large: '{}'", s),
                        })
                    }
                }
            }

            // If multiple entries present ensure they are consistent
            if nums.len() > 1 {
                let first = nums[0];
                for (i, n) in nums.iter().enumerate().skip(1) {
                    if n.is_none() || first.is_none() || n != &first {
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

            None
        };

        // Request
        if let Some(v) = check(&tx.request.headers) {
            return Some(v);
        }

        // Response
        if let Some(resp) = &tx.response {
            if let Some(v) = check(&resp.headers) {
                return Some(v);
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

    #[rstest]
    #[case("0", false)]
    #[case("  20  ", false)]
    #[case("", true)]
    #[case("abc", true)]
    #[case("-1", true)]
    #[case("+1", true)]
    #[case("1.5", true)]
    #[case("340282366920938463463374607431768211456", true)]
    fn check_single_request_values(
        #[case] value: &str,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageContentLength;

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = hyper::HeaderMap::new();
        hm.insert(hyper::header::CONTENT_LENGTH, HeaderValue::from_str(value)?);
        tx.request.headers = hm;

        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        if expect_violation {
            assert!(v.is_some(), "value '{}' expected violation", value);
        } else {
            assert!(v.is_none(), "value '{}' expected no violation", value);
        }

        Ok(())
    }

    #[rstest]
    #[case("0", false)]
    #[case("  20  ", false)]
    #[case("", true)]
    #[case("abc", true)]
    #[case("-1", true)]
    #[case("+1", true)]
    #[case("1.5", true)]
    fn check_single_response_values(
        #[case] value: &str,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageContentLength;

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = hyper::HeaderMap::new();
        hm.insert(hyper::header::CONTENT_LENGTH, HeaderValue::from_str(value)?);
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            headers: hm,
        });

        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        if expect_violation {
            assert!(v.is_some(), "response value '{}' expected violation", value);
        } else {
            assert!(
                v.is_none(),
                "response value '{}' expected no violation",
                value
            );
        }

        Ok(())
    }

    #[rstest]
    #[case(vec!["10", " 10 "], false)]
    #[case(vec!["10", "20"], true)]
    fn check_multiple_values(
        #[case] values: Vec<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageContentLength;

        // request
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = hyper::HeaderMap::new();
        for v in &values {
            hm.append(hyper::header::CONTENT_LENGTH, HeaderValue::from_str(v)?);
        }
        tx.request.headers = hm;

        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        if expect_violation {
            assert!(
                v.is_some(),
                "request values '{:?}' expected violation",
                values
            );
        } else {
            assert!(
                v.is_none(),
                "request values '{:?}' expected no violation",
                values
            );
        }

        // response
        let mut tx2 = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm2 = hyper::HeaderMap::new();
        for v in &values {
            hm2.append(hyper::header::CONTENT_LENGTH, HeaderValue::from_str(v)?);
        }
        tx2.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            headers: hm2,
        });

        let v2 = rule.check_transaction(&tx2, None, &crate::test_helpers::make_test_rule_config());
        if expect_violation {
            assert!(
                v2.is_some(),
                "response values '{:?}' expected violation",
                values
            );
        } else {
            assert!(
                v2.is_none(),
                "response values '{:?}' expected no violation",
                values
            );
        }

        Ok(())
    }

    #[test]
    fn check_non_utf8() -> anyhow::Result<()> {
        let rule = MessageContentLength;
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = hyper::HeaderMap::new();
        // 0xFF is not a valid UTF-8 character
        let bad_value = HeaderValue::from_bytes(&[0xFF])?;
        hm.insert(hyper::header::CONTENT_LENGTH, bad_value);
        tx.request.headers = hm;

        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("non-UTF8"));
        Ok(())
    }
}
