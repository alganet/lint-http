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
        _history: &crate::transaction_history::TransactionHistory,
        config: &Self::Config,
    ) -> Option<Violation> {
        let check = |headers: &hyper::HeaderMap| -> Option<Violation> {
            match crate::helpers::headers::validate_content_length(headers) {
                Ok(_) => None,
                Err(e) => {
                    let message = match e {
                        crate::helpers::headers::ContentLengthError::NonUtf8 => {
                            "Invalid Content-Length value (non-UTF8)".into()
                        }
                        crate::helpers::headers::ContentLengthError::InvalidCharacter(s) => {
                            format!("Invalid Content-Length value: '{}'", s)
                        }
                        crate::helpers::headers::ContentLengthError::TooLarge(s) => {
                            format!("Content-Length value too large: '{}'", s)
                        }
                        crate::helpers::headers::ContentLengthError::MultipleValuesDiffer(a, b) => {
                            format!(
                                "Multiple Content-Length headers with differing values: '{}' vs '{}'",
                                a, b
                            )
                        }
                    };

                    Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message,
                    })
                }
            }
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

        let tx =
            crate::test_helpers::make_test_transaction_with_headers(&[("content-length", value)]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
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

        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-length", value)],
        );

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
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
        let pairs: Vec<(&str, &str)> = values.iter().map(|v| ("content-length", *v)).collect();
        let tx = crate::test_helpers::make_test_transaction_with_headers(&pairs);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
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
            version: "HTTP/1.1".into(),
            headers: hm2,
            body_length: None,
        });

        let v2 = rule.check_transaction(
            &tx2,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
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

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("non-UTF8"));
        Ok(())
    }

    #[test]
    fn scope_is_both() {
        let rule = MessageContentLength;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }
}
