// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// `If-Unmodified-Since` header must be a valid HTTP-date (IMF-fixdate) as defined by RFC 9110 §7.8.2.
pub struct MessageIfUnmodifiedSinceDateFormat;

impl Rule for MessageIfUnmodifiedSinceDateFormat {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_if_unmodified_since_date_format"
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
        // Applies to requests only
        for hv in tx.request.headers.get_all("if-unmodified-since").iter() {
            let s = match hv.to_str() {
                Ok(s) => s,
                Err(_) => {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "If-Unmodified-Since header contains non-UTF8 value".into(),
                    })
                }
            };

            if s.trim().is_empty() {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "If-Unmodified-Since header is empty or contains only whitespace"
                        .into(),
                });
            }

            if !crate::http_date::is_valid_http_date(s.trim()) {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message:
                        "If-Unmodified-Since header is not a valid IMF-fixdate (RFC 9110 §7.8.2)"
                            .into(),
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
    #[case(Some("Wed, 21 Oct 2015 07:28:00 GMT"), false)]
    #[case(Some("not-a-date"), true)]
    #[case(None, false)]
    fn if_unmodified_since_cases(
        #[case] header: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageIfUnmodifiedSinceDateFormat;
        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(h) = header {
            tx.request.headers =
                crate::test_helpers::make_headers_from_pairs(&[("if-unmodified-since", h)]);
        }

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        if expect_violation {
            assert!(v.is_some());
        } else {
            assert!(v.is_none());
        }
        Ok(())
    }

    #[test]
    fn non_utf8_header_value_is_violation() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;
        let rule = MessageIfUnmodifiedSinceDateFormat;

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        let bad = HeaderValue::from_bytes(&[0xff]).expect("should construct non-utf8 header");
        hm.insert("if-unmodified-since", bad);
        tx.request.headers = hm;

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn empty_header_value_reports_violation() {
        let rule = MessageIfUnmodifiedSinceDateFormat;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-unmodified-since", "")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("empty or contains only whitespace"));
    }

    #[test]
    fn multiple_header_fields_one_invalid_reports_violation() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;
        let rule = MessageIfUnmodifiedSinceDateFormat;

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        hm.append(
            "if-unmodified-since",
            HeaderValue::from_static("Wed, 21 Oct 2015 07:28:00 GMT"),
        );
        hm.append(
            "if-unmodified-since",
            HeaderValue::from_static("not-a-date"),
        );
        tx.request.headers = hm;

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn multiple_header_fields_merged_and_valid() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;
        let rule = MessageIfUnmodifiedSinceDateFormat;

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        hm.append(
            "if-unmodified-since",
            HeaderValue::from_static("Wed, 21 Oct 2015 07:28:00 GMT"),
        );
        hm.append(
            "if-unmodified-since",
            HeaderValue::from_static("Wed, 02 Jan 2030 12:00:00 GMT"),
        );
        tx.request.headers = hm;

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        // Using multiple valid headers is acceptable (validate each); no violation expected if all valid
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_if_unmodified_since_date_format");
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn id_and_scope_are_expected() {
        let r = MessageIfUnmodifiedSinceDateFormat;
        assert_eq!(r.id(), "message_if_unmodified_since_date_format");
        assert_eq!(r.scope(), crate::rules::RuleScope::Both);
    }
}
