// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// Stateful rule: when a request uses `Expect: 100-continue` the client SHOULD
/// wait for a `100 (Continue)` interim response before sending a request body.
/// This rule flags requests that include the expectation and appear to have
/// sent a body (Content-Length > 0, Transfer-Encoding present, or captured
/// request body length > 0) but where the previous transaction for the same
/// client+resource was not a `100` interim response.
pub struct ClientExpect100ContinueStateful;

impl Rule for ClientExpect100ContinueStateful {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "client_expect_100_continue_stateful"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        previous: Option<&crate::http_transaction::HttpTransaction>,
        config: &Self::Config,
    ) -> Option<Violation> {
        // Detect presence of 100-continue expectation (case-insensitive)
        let mut expect_100 = false;
        for hv in tx.request.headers.get_all("expect").iter() {
            let s = match hv.to_str() {
                Ok(s) => s,
                Err(_) => continue, // ignore non-utf8
            };
            for part in s.split(',') {
                let token = part.trim();
                if token.is_empty() {
                    continue;
                }
                let mut iter = token.splitn(2, '=');
                let name = iter.next().unwrap().trim();
                if name.eq_ignore_ascii_case("100-continue") {
                    // presence is enough; syntax/parameter correctness is handled by
                    // `client_expect_header_valid` (this rule is stateful only)
                    expect_100 = true;
                    break;
                }
            }
            if expect_100 {
                break;
            }
        }

        if !expect_100 {
            return None;
        }

        // Detect whether a body was (or likely was) sent with the request
        let mut body_present = false;

        if let Some(len) = tx.request.body_length {
            if len > 0 {
                body_present = true;
            }
        }

        if tx.request.headers.contains_key("transfer-encoding") {
            body_present = true;
        }

        if let Some(cl_raw) =
            crate::helpers::headers::get_header_str(&tx.request.headers, "content-length")
        {
            let cl = cl_raw.trim();
            if !cl.is_empty() && cl.chars().all(|c| c.is_ascii_digit()) {
                if let Ok(n) = cl.parse::<u128>() {
                    if n > 0 {
                        body_present = true;
                    }
                }
            }
        }

        if !body_present {
            return None;
        }

        // Ok if previous transaction exists and its response was a 100 Continue
        if let Some(prev) = previous {
            if let Some(resp) = &prev.response {
                if resp.status == 100 {
                    return None;
                }
            }
        }

        Some(Violation {
            rule: self.id().into(),
            severity: config.severity,
            message: "Request used 'Expect: 100-continue' but sent a request body without a prior 100 (Continue) interim response".into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn make_req(
        expect: Option<&str>,
        body_len: Option<u64>,
        extra: &[(&str, &str)],
    ) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(e) = expect {
            // build headers with Expect plus any extra headers
            let mut pairs = vec![("expect", e)];
            pairs.extend_from_slice(extra);
            tx.request.headers = crate::test_helpers::make_headers_from_pairs(&pairs);
        } else {
            tx.request.headers = crate::test_helpers::make_headers_from_pairs(extra);
        }
        tx.request.body_length = body_len;
        tx
    }

    #[rstest]
    #[case(Some("100-continue"), Some(100), None, true)]
    #[case(Some("100-continue"), Some(0), None, false)]
    #[case(Some("100-continue"), None, Some(("transfer-encoding","chunked")), true)]
    #[case(Some("100-continue"), None, Some(("content-length","10")), true)]
    fn basic_expect_cases(
        #[case] expect: Option<&str>,
        #[case] body_len: Option<u64>,
        #[case] extra: Option<(&str, &str)>,
        #[case] expect_violation: bool,
    ) {
        let rule = ClientExpect100ContinueStateful;
        let extra_vec: Vec<(&str, &str)> = match extra {
            Some(p) => vec![p],
            None => vec![],
        };
        let tx = make_req(expect, body_len, extra_vec.as_slice());
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        if expect_violation {
            assert!(v.is_some());
        } else {
            assert!(v.is_none());
        }
    }

    #[test]
    fn expect_with_prev_100_no_violation() {
        let rule = ClientExpect100ContinueStateful;
        let tx = make_req(Some("100-continue"), Some(10), &[]);

        let mut prev = crate::test_helpers::make_test_transaction_with_response(100, &[]);
        prev.request.uri = tx.request.uri.clone();

        let v = rule.check_transaction(
            &tx,
            Some(&prev),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn expect_with_prev_200_reports_violation() {
        let rule = ClientExpect100ContinueStateful;
        let tx = make_req(Some("100-continue"), Some(10), &[]);

        let mut prev = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        prev.request.uri = tx.request.uri.clone();

        let v = rule.check_transaction(
            &tx,
            Some(&prev),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
    }

    #[test]
    fn expect_without_body_no_violation() {
        let rule = ClientExpect100ContinueStateful;
        let tx = make_req(Some("100-continue"), Some(0), &[]);
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn non_utf8_expect_header_ignored() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;
        let rule = ClientExpect100ContinueStateful;

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        let bad = HeaderValue::from_bytes(&[0xff]).expect("should construct non-utf8 header");
        hm.insert("expect", bad);
        tx.request.headers = hm;
        tx.request.body_length = Some(10);

        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        // Non-utf8 Expect is ignored by this rule
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn expect_list_and_mixed_case_detected() {
        let rule = ClientExpect100ContinueStateful;
        let tx = make_req(Some("foo, 100-Continue, bar"), Some(10), &[]);
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
    }

    #[test]
    fn content_length_non_numeric_ignored() {
        let rule = ClientExpect100ContinueStateful;
        let tx = make_req(Some("100-continue"), None, &[("content-length", "abc")]);
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        // Non-numeric Content-Length should not be treated as body indication
        assert!(v.is_none());
    }

    #[test]
    fn prev_exists_but_no_response_reports_violation() {
        let rule = ClientExpect100ContinueStateful;
        let tx = make_req(Some("100-continue"), Some(10), &[]);
        let mut prev = crate::test_helpers::make_test_transaction();
        prev.request.uri = tx.request.uri.clone();
        // prev.response is None by default
        let v = rule.check_transaction(
            &tx,
            Some(&prev),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
    }

    #[test]
    fn expect_with_parameter_counts_as_presence() {
        let rule = ClientExpect100ContinueStateful;
        let tx = make_req(Some("100-continue=param"), Some(10), &[]);
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        // This stateful rule treats presence of the expectation (even with params) as an indication
        assert!(v.is_some());
    }

    #[test]
    fn content_length_zero_no_violation() {
        let rule = ClientExpect100ContinueStateful;
        let tx = make_req(Some("100-continue"), None, &[("content-length", "0")]);
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn scope_is_client() {
        let r = ClientExpect100ContinueStateful;
        assert_eq!(
            crate::rules::Rule::scope(&r),
            crate::rules::RuleScope::Client
        );
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "client_expect_100_continue_stateful");
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
