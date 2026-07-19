// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageRetryAfterDateOrDelay;

impl Rule for MessageRetryAfterDateOrDelay {
    fn id(&self) -> &'static str {
        "message_retry_after_date_or_delay"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
        // Applies to responses only
        let resp = tx.response.as_ref()?;

        // Iterate all Retry-After header occurrences; each value must be either
        // a non-negative integer (delta-seconds) or an IMF-fixdate (HTTP-date)
        for val in resp.headers.get_all("retry-after").iter() {
            let s = match val.to_str() {
                Ok(s) => s.trim(),
                Err(_) => {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Retry-After header contains non-UTF8 value".into(),
                    })
                }
            };

            // Try parse non-negative integer first
            if s.parse::<u64>().is_ok() {
                continue;
            }

            // Try parse HTTP-date (IMF-fixdate) using shared helper
            if crate::http_date::is_valid_http_date(s) {
                continue;
            }

            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!(
                    "Retry-After value '{}' is invalid: must be a non-negative delta-seconds integer or an HTTP-date (IMF-fixdate)",
                    s
                ),
            });
        }

        None
    }

    fn title(&self) -> Option<&'static str> {
        Some("Message Retry-After Date or Delay")
    }

    fn description(&self) -> &'static str {
        "The `Retry-After` header, when present in responses, MUST be either a non-negative integer (delay-seconds) or an HTTP-date (IMF-fixdate). This rule flags `Retry-After` values that do not match either form."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[crate::rules::SpecRef {
            spec: "RFC 9110",
            section: Some("10.2.3"),
            url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.3",
            note: "Retry-After header",
        }]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 503 Service Unavailable\nRetry-After: 120\n\nHTTP/1.1 503 Service Unavailable\nRetry-After: Wed, 21 Oct 2015 07:28:00 GMT",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 503 Service Unavailable\nRetry-After: tomorrow\n\nHTTP/1.1 503 Service Unavailable\nRetry-After: -1",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &MessageRetryAfterDateOrDelay;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(200, &[("retry-after", "120")], false)]
    #[case(503, &[("retry-after", "0")], false)]
    #[case(503, &[("retry-after", "Wed, 21 Oct 2015 07:28:00 GMT")], false)]
    #[case(503, &[("retry-after", "tomorrow")], true)]
    #[case(503, &[("retry-after", "-1")], true)]
    fn check_cases(
        #[case] status: u16,
        #[case] hdrs: &[(&str, &str)],
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageRetryAfterDateOrDelay;
        let tx = crate::test_helpers::make_test_transaction_with_response(status, hdrs);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );

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
    fn multiple_values_all_valid() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;
        let rule = MessageRetryAfterDateOrDelay;
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        hm.append("retry-after", HeaderValue::from_static("120"));
        hm.append(
            "retry-after",
            HeaderValue::from_static("Wed, 21 Oct 2015 07:28:00 GMT"),
        );
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 503,
            version: "HTTP/1.1".into(),
            headers: hm,

            body_length: None,
            trailers: None,
        });

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn no_response_no_violation() -> anyhow::Result<()> {
        let rule = MessageRetryAfterDateOrDelay;
        let tx = crate::test_helpers::make_test_transaction();
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn scope_is_server() {
        let rule = MessageRetryAfterDateOrDelay;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }

    #[test]
    fn violation_message_meaningful() -> anyhow::Result<()> {
        let rule = MessageRetryAfterDateOrDelay;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            503,
            &[("retry-after", "bad")],
        );
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("invalid"));
        Ok(())
    }

    #[test]
    fn non_utf8_header_value_is_violation() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;
        let rule = MessageRetryAfterDateOrDelay;
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        // create non-utf8 header value
        let bad = HeaderValue::from_bytes(&[0xff]).expect("should construct non-utf8 header");
        hm.insert("retry-after", bad);
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 503,
            version: "HTTP/1.1".into(),
            headers: hm,

            body_length: None,
            trailers: None,
        });

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("non-UTF8"));
        Ok(())
    }

    #[test]
    fn comma_separated_values_are_invalid() -> anyhow::Result<()> {
        let rule = MessageRetryAfterDateOrDelay;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            503,
            &[("retry-after", "120, 240")],
        );
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        Ok(())
    }
}
