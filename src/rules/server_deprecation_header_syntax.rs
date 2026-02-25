// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ServerDeprecationHeaderSyntax;

impl Rule for ServerDeprecationHeaderSyntax {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "server_deprecation_header_syntax"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        config: &Self::Config,
    ) -> Option<Violation> {
        // Applies to responses only
        let resp = match &tx.response {
            Some(r) => r,
            None => return None,
        };

        let mut vals = Vec::new();
        for hv in resp.headers.get_all("deprecation").iter() {
            vals.push(hv);
        }

        // Multiple Deprecation header fields are prohibited
        if vals.len() > 1 {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Multiple Deprecation header fields present; servers MUST NOT include more than one Deprecation header field in the same response".into(),
            });
        }

        let hv = vals.into_iter().next()?;

        let s = match hv.to_str() {
            Ok(s) => s.trim(),
            Err(_) => {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Deprecation header contains non-UTF8 value".into(),
                })
            }
        };

        // Structured Field Date syntax (RFC 9745 / RFC 9651): @DIGITS
        if s.starts_with('@') && s.len() > 1 && s[1..].chars().all(|c| c.is_ascii_digit()) {
            return None; // valid per RFC 9745
        }

        // Legacy forms: HTTP-date (IMF-fixdate) or literal 'true' were used historically.
        if s.eq_ignore_ascii_case("true") {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Deprecation header uses legacy token 'true'; RFC 9745 defines Deprecation as a structured date '@<epoch>' (prefer '@<seconds>' form)".into(),
            });
        }

        // Accept legacy HTTP-date but report it as deprecated (helpful message)
        if crate::http_date::is_valid_http_date(s) {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Deprecation header uses legacy HTTP-date format; RFC 9745 specifies Deprecation as a structured date '@<seconds>' (see RFC 9745 §2)".into(),
            });
        }

        // Otherwise it's invalid
        Some(Violation {
            rule: self.id().into(),
            severity: config.severity,
            message: format!("Deprecation value '{}' is invalid: must be a structured Date item (e.g., '@1688169599') per RFC 9745", s),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;
    use hyper::HeaderMap;
    use rstest::rstest;

    #[rstest]
    #[case(200, &[("deprecation", "@1688169599")], false)]
    #[case(200, &[("deprecation", "@0")], false)]
    #[case(200, &[("deprecation", "true")], true)]
    #[case(200, &[("deprecation", "Sun, 11 Nov 2018 23:59:59 GMT")], true)]
    #[case(200, &[("deprecation", "bad")], true)]
    fn check_cases(
        #[case] status: u16,
        #[case] hdrs: &[(&str, &str)],
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = ServerDeprecationHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(status, hdrs);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
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
    fn multiple_headers_are_rejected() -> anyhow::Result<()> {
        let rule = ServerDeprecationHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = HeaderMap::new();
        hm.append("deprecation", HeaderValue::from_static("@1688169599"));
        hm.append("deprecation", HeaderValue::from_static("@1688169598"));
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,

            body_length: None,
        });

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn non_utf8_is_reported() -> anyhow::Result<()> {
        let rule = ServerDeprecationHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = HeaderMap::new();
        let bad = HeaderValue::from_bytes(&[0xff]).expect("should construct non-utf8 header");
        hm.insert("deprecation", bad);
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,

            body_length: None,
        });

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("non-UTF8"));
        Ok(())
    }

    #[test]
    fn whitespace_trim_valid_and_no_violation() -> anyhow::Result<()> {
        let rule = ServerDeprecationHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("deprecation", "   @1688169599   ")],
        );
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn starts_with_at_but_nondigits_is_invalid() -> anyhow::Result<()> {
        let rule = ServerDeprecationHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("deprecation", "@abc")],
        );
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("invalid"));
        assert!(msg.contains("@abc"));
        Ok(())
    }

    #[test]
    fn single_at_is_invalid() -> anyhow::Result<()> {
        let rule = ServerDeprecationHeaderSyntax;
        let tx =
            crate::test_helpers::make_test_transaction_with_response(200, &[("deprecation", "@")]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn negative_number_after_at_is_invalid() -> anyhow::Result<()> {
        let rule = ServerDeprecationHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("deprecation", "@-1")],
        );
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn uppercase_true_reports_legacy() -> anyhow::Result<()> {
        let rule = ServerDeprecationHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("deprecation", "TRUE")],
        );
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("'true'"));
        Ok(())
    }

    #[test]
    fn no_response_no_violation() {
        let rule = ServerDeprecationHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction();
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn scope_is_server() {
        let rule = ServerDeprecationHeaderSyntax;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }
}
