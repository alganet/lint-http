// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ServerLastModifiedRfc1123Format;

impl Rule for ServerLastModifiedRfc1123Format {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "server_last_modified_rfc1123_format"
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
        let Some(resp) = &tx.response else {
            return None;
        };

        if let Some(s) = crate::helpers::headers::get_header_str(&resp.headers, "last-modified") {
            if !crate::http_date::is_valid_http_date(s) {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Last-Modified header is not a valid IMF-fixdate (RFC 9110)".into(),
                });
            }
        } else if resp.headers.contains_key("last-modified") {
            // Non-UTF8 header values are considered invalid for date parsing
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Last-Modified header contains non-UTF8 bytes and is invalid".into(),
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
    #[case(Some(vec![("last-modified", "Wed, 21 Oct 2015 07:28:00 GMT")] ), false)]
    #[case(Some(vec![("last-modified", "not-a-date")] ), true)]
    #[case(Some(vec![("last-modified", "Wed, 02 Jan 2030 12:00:00 GMT")] ), false)]
    #[case(None, false)]
    fn check_last_modified_cases(
        #[case] headers: Option<Vec<(&str, &str)>>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = ServerLastModifiedRfc1123Format;
        let mut tx = crate::test_helpers::make_test_transaction();

        if let Some(h) = headers {
            tx.response = Some(crate::http_transaction::ResponseInfo {
                status: 200,
                version: "HTTP/1.1".into(),
                headers: crate::test_helpers::make_headers_from_pairs(&h),

                body_length: None,
            });
        }

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        if expect_violation {
            assert!(v.is_some());
            let m = v.unwrap().message;
            assert!(m.contains("Last-Modified"));
        } else {
            assert!(v.is_none());
        }
        Ok(())
    }

    #[test]
    fn invalid_non_utf8_last_modified_is_violation() -> anyhow::Result<()> {
        let rule = ServerLastModifiedRfc1123Format;
        let mut tx = crate::test_helpers::make_test_transaction();

        // Construct a response with non-UTF8 Last-Modified header
        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        let bad = HeaderValue::from_bytes(&[0xff])?;
        hm.insert("last-modified", bad);
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
    fn scope_is_server() {
        let rule = ServerLastModifiedRfc1123Format;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }
}
