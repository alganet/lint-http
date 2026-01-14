// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageMaxForwardsNumeric;

impl Rule for MessageMaxForwardsNumeric {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_max_forwards_numeric"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        // Max-Forwards is a request header (used by TRACE and OPTIONS)
        crate::rules::RuleScope::Client
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _previous: Option<&crate::http_transaction::HttpTransaction>,
        config: &Self::Config,
    ) -> Option<Violation> {
        // Only applies to requests
        for val in tx.request.headers.get_all("max-forwards").iter() {
            let s = match val.to_str() {
                Ok(s) => s.trim(),
                Err(_) => {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Max-Forwards header contains non-UTF8 value".into(),
                    })
                }
            };

            // Per RFC 9110 §7.6.2, Max-Forwards = 1*DIGIT (one or more digits)
            if s.is_empty() || !s.chars().all(|c| c.is_ascii_digit()) {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!(
                        "Max-Forwards value '{}' is invalid: must be one or more ASCII digits (1*DIGIT)",
                        s
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

    #[rstest]
    #[case(&[("max-forwards", "0")], false)]
    #[case(&[("max-forwards", "10")], false)]
    #[case(&[("max-forwards", "01")], false)]
    #[case(&[("max-forwards", "-1")], true)]
    #[case(&[("max-forwards", "1.0")], true)]
    #[case(&[("max-forwards", "abc")], true)]
    #[case(&[("max-forwards", "120, 240")], true)]
    fn check_request_cases(
        #[case] hdrs: &[(&str, &str)],
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageMaxForwardsNumeric;

        use crate::test_helpers::make_test_transaction;
        let mut tx = make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(hdrs);
        let violation =
            rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());

        if expect_violation {
            assert!(
                violation.is_some(),
                "expected violation for headers: {:?}",
                hdrs
            );
        } else {
            assert!(
                violation.is_none(),
                "did not expect violation for headers: {:?}",
                hdrs
            );
        }
        Ok(())
    }

    #[test]
    fn non_utf8_header_value_is_violation() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;
        let rule = MessageMaxForwardsNumeric;
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        // create non-utf8 header value
        let bad = HeaderValue::from_bytes(&[0xff]).expect("should construct non-utf8 header");
        hm.insert("max-forwards", bad);
        tx.request.headers = hm;

        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("non-UTF8"));
        Ok(())
    }

    #[test]
    fn scope_is_client() {
        let rule = MessageMaxForwardsNumeric;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Client);
    }
}
