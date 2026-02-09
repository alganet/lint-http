// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// Ensure servers use appropriate status codes for redirects when the request method
/// is unsafe (e.g., POST). Specifically, returning 301 or 302 in response to POST
/// is historically ambiguous: use 303 to indicate the client should follow using GET,
/// or use 307/308 when the server intends the client to preserve method and body.
/// See RFC 9110 §6.4.
pub struct Server3xxVsRequestMethod;

impl Rule for Server3xxVsRequestMethod {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "server_3xx_vs_request_method"
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
        // Only applies to responses
        let resp = match &tx.response {
            Some(r) => r,
            None => return None,
        };

        let status = resp.status;

        // Only consider redirection responses that include a Location header
        if !(300..400).contains(&status) {
            return None;
        }
        // Return early if there's no Location header (use `?` style early-return via Option)
        let _ = resp.headers.get_all("location").iter().next()?;

        // Determine request method (case-insensitive)
        let method = tx.request.method.as_str();
        // Treat known safe methods as not ambiguous when redirected
        if method.eq_ignore_ascii_case("GET")
            || method.eq_ignore_ascii_case("HEAD")
            || method.eq_ignore_ascii_case("OPTIONS")
            || method.eq_ignore_ascii_case("TRACE")
        {
            return None;
        }

        // If the request used an unsafe method (POST, PUT, PATCH, DELETE etc.) and
        // the server responded with 301 or 302, this is ambiguous. Recommend using
        // 303 for redirect-to-GET or 307/308 to preserve method and body.
        if matches!(status, 301 | 302) {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!("{} response to '{}' request is ambiguous: use 303 to redirect to GET, or 307/308 to preserve the method and body (RFC 9110 §6.4)", status, method),
            });
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tx(
        status: u16,
        method: &str,
        with_location: bool,
    ) -> crate::http_transaction::HttpTransaction {
        let mut tx = if with_location {
            crate::test_helpers::make_test_transaction_with_response(
                status,
                &[("location", "/new")],
            )
        } else {
            crate::test_helpers::make_test_transaction_with_response(status, &[])
        };
        tx.request.method = method.to_string();
        tx
    }

    #[test]
    fn post_301_with_location_reports_violation() {
        let rule = Server3xxVsRequestMethod;
        let cfg = crate::test_helpers::make_test_rule_config();
        let tx = make_tx(301, "POST", true);
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        let v = v.unwrap();
        assert_eq!(v.rule, "server_3xx_vs_request_method");
        assert!(v.message.contains("301"));
        assert!(v.message.contains("POST"));
    }

    #[test]
    fn post_302_with_location_reports_violation() {
        let rule = Server3xxVsRequestMethod;
        let cfg = crate::test_helpers::make_test_rule_config();
        let tx = make_tx(302, "POST", true);
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
    }

    #[test]
    fn post_303_with_location_is_ok() {
        let rule = Server3xxVsRequestMethod;
        let cfg = crate::test_helpers::make_test_rule_config();
        let tx = make_tx(303, "POST", true);
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn post_200_with_location_is_ignored() {
        // Non-3xx status codes should be ignored even if a Location header is present
        let rule = Server3xxVsRequestMethod;
        let cfg = crate::test_helpers::make_test_rule_config();
        let tx = make_tx(200, "POST", true);
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none(), "non-3xx status should be ignored");
    }

    #[test]
    fn post_307_with_location_is_ok() {
        let rule = Server3xxVsRequestMethod;
        let cfg = crate::test_helpers::make_test_rule_config();
        let tx = make_tx(307, "POST", true);
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn get_301_with_location_is_ok() {
        let rule = Server3xxVsRequestMethod;
        let cfg = crate::test_helpers::make_test_rule_config();
        let tx = make_tx(301, "GET", true);
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn post_301_without_location_is_ignored() {
        let rule = Server3xxVsRequestMethod;
        let cfg = crate::test_helpers::make_test_rule_config();
        let tx = make_tx(301, "POST", false);
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn lower_case_method_post_reports_violation() {
        let rule = Server3xxVsRequestMethod;
        let cfg = crate::test_helpers::make_test_rule_config();
        let tx = make_tx(301, "post", true);
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
    }

    #[test]
    fn non_utf8_location_still_counts() {
        use hyper::header::HeaderValue;
        let rule = Server3xxVsRequestMethod;
        let cfg = crate::test_helpers::make_test_rule_config();
        let mut tx = make_tx(301, "POST", true);
        // Replace location header with a non-UTF8 value; presence alone should trigger the rule
        let mut hm = hyper::HeaderMap::new();
        hm.insert("location", HeaderValue::from_bytes(b"\xff").unwrap());
        tx.response.as_mut().unwrap().headers = hm;
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
    }

    #[test]
    fn options_and_trace_are_treated_as_safe() {
        let rule = Server3xxVsRequestMethod;
        let cfg = crate::test_helpers::make_test_rule_config();
        for m in &["OPTIONS", "TRACE"] {
            let tx = make_tx(301, m, true);
            let v = rule.check_transaction(&tx, None, &cfg);
            assert!(v.is_none(), "method {} should be treated as safe", m);
        }
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "server_3xx_vs_request_method");
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn post_300_with_location_is_ok() {
        let rule = Server3xxVsRequestMethod;
        let cfg = crate::test_helpers::make_test_rule_config();
        let tx = make_tx(300, "POST", true);
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn post_308_with_location_is_ok() {
        let rule = Server3xxVsRequestMethod;
        let cfg = crate::test_helpers::make_test_rule_config();
        let tx = make_tx(308, "POST", true);
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn head_301_with_location_is_ok() {
        let rule = Server3xxVsRequestMethod;
        let cfg = crate::test_helpers::make_test_rule_config();
        let tx = make_tx(301, "HEAD", true);
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn put_301_with_location_reports_violation() {
        let rule = Server3xxVsRequestMethod;
        let cfg = crate::test_helpers::make_test_rule_config();
        let tx = make_tx(301, "PUT", true);
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
    }

    #[test]
    fn patch_301_with_location_reports_violation() {
        let rule = Server3xxVsRequestMethod;
        let cfg = crate::test_helpers::make_test_rule_config();
        let tx = make_tx(301, "PATCH", true);
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
    }

    #[test]
    fn delete_301_with_location_reports_violation() {
        let rule = Server3xxVsRequestMethod;
        let cfg = crate::test_helpers::make_test_rule_config();
        let tx = make_tx(301, "DELETE", true);
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
    }

    #[test]
    fn empty_method_reports_violation() {
        let rule = Server3xxVsRequestMethod;
        let cfg = crate::test_helpers::make_test_rule_config();
        let mut tx = make_tx(301, "POST", true);
        tx.request.method = "".to_string();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
    }

    #[test]
    fn multiple_location_headers_count() {
        use hyper::header::HeaderValue;
        let rule = Server3xxVsRequestMethod;
        let cfg = crate::test_helpers::make_test_rule_config();
        let mut tx = make_tx(301, "POST", false);
        let mut hm = hyper::HeaderMap::new();
        hm.append("location", HeaderValue::from_static("/first"));
        hm.append("location", HeaderValue::from_static("/second"));
        tx.response.as_mut().unwrap().headers = hm;
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
    }

    #[test]
    fn empty_location_value_counts() {
        use hyper::header::HeaderValue;
        let rule = Server3xxVsRequestMethod;
        let cfg = crate::test_helpers::make_test_rule_config();
        let mut tx = make_tx(301, "POST", false);
        let mut hm = hyper::HeaderMap::new();
        hm.insert("location", HeaderValue::from_static(""));
        tx.response.as_mut().unwrap().headers = hm;
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
    }

    #[test]
    fn no_response_is_ignored() {
        // If there's no response, rule should return None
        let rule = Server3xxVsRequestMethod;
        let cfg = crate::test_helpers::make_test_rule_config();
        let tx = crate::test_helpers::make_test_transaction(); // no response
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn post_302_violation_message_and_severity() {
        let rule = Server3xxVsRequestMethod;
        let mut cfg = crate::test_helpers::make_test_rule_config();
        cfg.severity = crate::lint::Severity::Error;
        let tx = make_tx(302, "POST", true);
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        let v = v.unwrap();
        assert_eq!(v.severity, crate::lint::Severity::Error);
        assert!(v.message.contains("302"));
        assert!(v.message.contains("POST"));
    }

    #[test]
    fn connect_301_with_location_reports_violation() {
        let rule = Server3xxVsRequestMethod;
        let cfg = crate::test_helpers::make_test_rule_config();
        let tx = make_tx(301, "CONNECT", true);
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(
            v.is_some(),
            "CONNECT should be treated as unsafe and report a violation"
        );
        let v = v.unwrap();
        assert!(v.message.contains("CONNECT"));
    }

    #[test]
    fn options_mixed_case_treated_as_safe() {
        let rule = Server3xxVsRequestMethod;
        let cfg = crate::test_helpers::make_test_rule_config();
        let tx = make_tx(301, "oPtIoNs", true);
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none(), "mixed-case OPTIONS should be treated as safe");
    }

    #[test]
    fn trace_mixed_case_treated_as_safe() {
        let rule = Server3xxVsRequestMethod;
        let cfg = crate::test_helpers::make_test_rule_config();
        let tx = make_tx(302, "TrAcE", true);
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none(), "mixed-case TRACE should be treated as safe");
    }

    #[test]
    fn connect_302_with_location_reports_violation() {
        let rule = Server3xxVsRequestMethod;
        let cfg = crate::test_helpers::make_test_rule_config();
        let tx = make_tx(302, "CONNECT", true);
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(
            v.is_some(),
            "CONNECT should be treated as unsafe and report a violation on 302"
        );
    }

    #[test]
    fn put_302_with_location_reports_violation() {
        let rule = Server3xxVsRequestMethod;
        let cfg = crate::test_helpers::make_test_rule_config();
        let tx = make_tx(302, "PUT", true);
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        let v = v.unwrap();
        assert!(v.message.contains("302"));
        assert!(v.message.contains("PUT"));
    }

    #[test]
    fn post_304_with_location_is_ok() {
        let rule = Server3xxVsRequestMethod;
        let cfg = crate::test_helpers::make_test_rule_config();
        let tx = make_tx(304, "POST", true);
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(
            v.is_none(),
            "304 should not be treated as a redirect for this rule"
        );
    }

    #[test]
    fn connect_lowercase_reports_violation() {
        let rule = Server3xxVsRequestMethod;
        let cfg = crate::test_helpers::make_test_rule_config();
        let tx = make_tx(301, "connect", true);
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(
            v.is_some(),
            "lowercase connect should also report a violation"
        );
    }

    #[test]
    fn id_and_scope() {
        let rule = Server3xxVsRequestMethod;
        assert_eq!(rule.id(), "server_3xx_vs_request_method");
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }
}
