// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageAgeHeaderNumeric;

impl Rule for MessageAgeHeaderNumeric {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_age_header_numeric"
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
        // Applies to responses only
        let resp = match &tx.response {
            Some(r) => r,
            None => return None,
        };

        for val in resp.headers.get_all("age").iter() {
            let s = match val.to_str() {
                Ok(s) => s.trim(),
                Err(_) => {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Age header contains non-UTF8 value".into(),
                    })
                }
            };

            // Age must be a non-negative integer (delta-seconds)
            if s.parse::<u64>().is_ok() {
                continue;
            }

            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!(
                    "Age value '{}' is invalid: must be a non-negative integer (delta-seconds)",
                    s
                ),
            });
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(200, &[("age", "120")], false)]
    #[case(200, &[("age", "0")], false)]
    #[case(200, &[("age", "-1")], true)]
    #[case(200, &[("age", "abc")], true)]
    fn check_cases(
        #[case] status: u16,
        #[case] hdrs: &[(&str, &str)],
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageAgeHeaderNumeric;
        let tx = crate::test_helpers::make_test_transaction_with_response(status, hdrs);
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());

        if expect_violation {
            assert!(v.is_some(), "expected violation for headers: {:?}", hdrs);
        } else {
            assert!(
                v.is_none(),
                "did not expect violation for headers: {:?}",
                hdrs
            );
        }
        Ok(())
    }

    #[test]
    fn comma_separated_values_are_invalid() -> anyhow::Result<()> {
        let rule = MessageAgeHeaderNumeric;
        let tx =
            crate::test_helpers::make_test_transaction_with_response(200, &[("age", "120, 240")]);
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn non_utf8_header_value_is_violation() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;
        let rule = MessageAgeHeaderNumeric;
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        // create non-utf8 header value
        let bad = HeaderValue::from_bytes(&[0xff]).expect("should construct non-utf8 header");
        hm.insert("age", bad);
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            headers: hm,
        });

        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("non-UTF8") || msg.contains("invalid"));
        Ok(())
    }

    #[test]
    fn no_response_no_violation() -> anyhow::Result<()> {
        let rule = MessageAgeHeaderNumeric;
        let tx = crate::test_helpers::make_test_transaction();
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn scope_is_server() {
        let rule = MessageAgeHeaderNumeric;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }

    #[test]
    fn violation_message_meaningful() -> anyhow::Result<()> {
        let rule = MessageAgeHeaderNumeric;
        let tx = crate::test_helpers::make_test_transaction_with_response(200, &[("age", "bad")]);
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("invalid"));
        Ok(())
    }
}
