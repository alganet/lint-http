// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// `Sec-Fetch-User` header must be the structured-boolean true (serialized as `?1`) when present.
/// The header is request-scoped and only expected on navigation requests. Multiple header
/// fields or non-ASCII values are flagged as violations.
pub struct MessageSecFetchUserValueValid;

impl Rule for MessageSecFetchUserValueValid {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_sec_fetch_user_value_valid"
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
        let headers = &tx.request.headers;
        let count = headers.get_all("sec-fetch-user").iter().count();
        if count == 0 {
            return None;
        }

        if count > 1 {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Multiple Sec-Fetch-User header fields present".into(),
            });
        }

        let val = match crate::helpers::headers::get_header_str(headers, "sec-fetch-user") {
            Some(v) => v.trim(),
            None => {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Sec-Fetch-User header contains non-ASCII or control characters"
                        .into(),
                })
            }
        };

        if val.is_empty() {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Sec-Fetch-User header is empty".into(),
            });
        }

        // The canonical serialization for a structured-boolean true is `?1`.
        if val != "?1" {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!(
                    "Unrecognized Sec-Fetch-User value: '{}'; expected '?1'",
                    val
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
    #[case(Some("?1"), false)]
    #[case(Some(" ?1 "), false)]
    #[case(Some("true"), true)]
    #[case(Some("1"), true)]
    #[case(Some(""), true)]
    #[case(None, false)]
    fn sec_fetch_user_cases(#[case] header: Option<&str>, #[case] expect_violation: bool) {
        let rule = MessageSecFetchUserValueValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(v) = header {
            tx.request.headers =
                crate::test_helpers::make_headers_from_pairs(&[("sec-fetch-user", v)]);
        }

        let v = rule.check_transaction(&tx, None, &cfg);
        if expect_violation {
            assert!(v.is_some(), "expected violation for header={:?}", header);
        } else {
            assert!(
                v.is_none(),
                "unexpected violation for header={:?}: {:?}",
                header,
                v
            );
        }
    }

    #[test]
    fn false_serialization_reports_violation() {
        let rule = MessageSecFetchUserValueValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("sec-fetch-user", "?0")]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Unrecognized Sec-Fetch-User"));
    }

    #[test]
    fn structured_boolean_with_suffix_reports_violation() {
        let rule = MessageSecFetchUserValueValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("sec-fetch-user", "?1;param")]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Unrecognized Sec-Fetch-User"));
    }

    #[test]
    fn comma_separated_single_field_reports_violation() {
        let rule = MessageSecFetchUserValueValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("sec-fetch-user", "?1,?1")]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Unrecognized Sec-Fetch-User"));
    }

    #[test]
    fn whitespace_only_header_reports_violation() {
        let rule = MessageSecFetchUserValueValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("sec-fetch-user", "   ")]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("is empty"));
    }

    #[test]
    fn multiple_header_fields_reports_violation() {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;

        let rule = MessageSecFetchUserValueValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        hm.append("sec-fetch-user", HeaderValue::from_static("?1"));
        hm.append("sec-fetch-user", HeaderValue::from_static("?1"));
        tx.request.headers = hm;

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Multiple Sec-Fetch-User"));
    }

    #[test]
    fn non_utf8_is_violation() {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;

        let rule = MessageSecFetchUserValueValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        let bad = HeaderValue::from_bytes(&[0xff]).expect("should construct non-utf8 header");
        hm.insert("sec-fetch-user", bad);
        tx.request.headers = hm;

        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("non-ASCII"));
    }

    #[test]
    fn message_and_id() {
        let rule = MessageSecFetchUserValueValid;
        assert_eq!(rule.id(), "message_sec_fetch_user_value_valid");
        assert_eq!(rule.scope(), crate::rules::RuleScope::Client);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_sec_fetch_user_value_valid");
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
