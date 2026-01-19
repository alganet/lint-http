// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageEarlyDataHeaderSafeMethod;

impl Rule for MessageEarlyDataHeaderSafeMethod {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_early_data_header_safe_method"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        // This rule applies to client requests only
        crate::rules::RuleScope::Client
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _previous: Option<&crate::http_transaction::HttpTransaction>,
        config: &Self::Config,
    ) -> Option<Violation> {
        // Early-Data is defined as a request header (RFC 8470). If present and equal to '1',
        // it should only be used with safe methods (GET, HEAD, OPTIONS, TRACE).
        // A request may include multiple Early-Data header fields. Per RFC 8470, any
        // instance whose value is "1" indicates the request may have been sent in
        // early data and must therefore be restricted to safe methods. Iterate over
        // all header instances and consider any valid UTF-8 value equal to "1".
        for hv in tx.request.headers.get_all("early-data").iter() {
            if let Ok(s) = hv.to_str() {
                if s.trim() == "1" {
                    let m = tx.request.method.trim().to_ascii_uppercase();
                    if !(m == "GET" || m == "HEAD" || m == "OPTIONS" || m == "TRACE") {
                        return Some(Violation {
                            rule: MessageEarlyDataHeaderSafeMethod.id().into(),
                            severity: config.severity,
                            message: format!(
                                "Invalid Early-Data header on non-safe method '{}'; Early-Data: 1 is only allowed on safe methods",
                                tx.request.method
                            ),
                        });
                    }
                }
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
    #[case("GET", Some("1"), false)]
    #[case("HEAD", Some("1"), false)]
    #[case("OPTIONS", Some("1"), false)]
    #[case("TRACE", Some("1"), false)]
    #[case("POST", Some("1"), true)]
    #[case("PUT", Some("1"), true)]
    #[case("DELETE", Some("1"), true)]
    #[case("GET", Some("0"), false)]
    #[case("POST", Some("0"), false)]
    #[case("GET", None, false)]
    fn early_data_header_cases(
        #[case] method: &str,
        #[case] header: Option<&str>,
        #[case] expect_violation: bool,
    ) {
        let rule = MessageEarlyDataHeaderSafeMethod;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = method.to_string();
        if let Some(h) = header {
            tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[("early-data", h)]);
        }

        let v = rule.check_transaction(&tx, None, &cfg);
        if expect_violation {
            assert!(
                v.is_some(),
                "expected violation for {:?} {:?}",
                method,
                header
            );
        } else {
            assert!(
                v.is_none(),
                "unexpected violation for {:?} {:?}: {:?}",
                method,
                header,
                v
            );
        }
    }

    #[test]
    fn scope_is_client() {
        let rule = MessageEarlyDataHeaderSafeMethod;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Client);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let rule = MessageEarlyDataHeaderSafeMethod;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_early_data_header_safe_method",
        ]);
        let boxed = rule.validate_and_box(&cfg)?;
        let _arc = boxed
            .downcast::<crate::rules::RuleConfig>()
            .map_err(|_| anyhow::anyhow!("downcast failed"))?;
        Ok(())
    }

    #[test]
    fn multiple_header_instances_with_one_1_reports_violation() {
        let rule = MessageEarlyDataHeaderSafeMethod;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "POST".to_string();

        let mut hm = hyper::HeaderMap::new();
        hm.append("early-data", "0".parse::<HeaderValue>().unwrap());
        hm.append("early-data", "1".parse::<HeaderValue>().unwrap());
        tx.request.headers = hm;

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
    }

    #[test]
    fn non_utf8_header_value_is_ignored() {
        let rule = MessageEarlyDataHeaderSafeMethod;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "POST".to_string();

        let mut hm = hyper::HeaderMap::new();
        let bad = HeaderValue::from_bytes(&[0xff]).expect("should create non-utf8");
        hm.append("early-data", bad);
        tx.request.headers = hm;

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
    }
}
