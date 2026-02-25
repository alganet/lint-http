// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ServerResponseLocationOnRedirect;

impl Rule for ServerResponseLocationOnRedirect {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "server_response_location_on_redirect"
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
        let resp = match &tx.response {
            Some(r) => r,
            None => return None,
        };

        let status = resp.status;

        // RFC 9110: 201 (Created) SHOULD include Location for the created resource.
        // 3xx redirection codes that SHOULD include Location when a preferred target exists:
        // 300, 301, 302, 303, 307, 308 (see §15.4 and §10.2.2).
        let should_have_location = matches!(status, 201 | 300 | 301 | 302 | 303 | 307 | 308);

        if should_have_location && resp.headers.get_all("location").iter().next().is_none() {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!("Response with status {} SHOULD include a Location header (RFC 9110 §10.2.2, §15.4)", status),
            });
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn make_tx(status: u16, loc: Option<&str>) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status,
            version: "HTTP/1.1".into(),
            headers: match loc {
                Some(l) => crate::test_helpers::make_headers_from_pairs(&[("location", l)]),
                None => crate::test_helpers::make_headers_from_pairs(&[]),
            },
            body_length: None,
        });
        tx
    }

    #[rstest]
    #[case(201, None, true)]
    #[case(201, Some("/created"), false)]
    #[case(300, None, true)]
    #[case(300, Some("/choice"), false)]
    #[case(301, None, true)]
    #[case(302, Some("https://ex.com/"), false)]
    #[case(303, None, true)]
    #[case(307, None, true)]
    #[case(308, Some("/new"), false)]
    #[case(304, None, false)]
    #[case(200, Some("/ok"), false)]
    #[case(200, None, false)]
    fn check_location_presence(
        #[case] status: u16,
        #[case] loc: Option<&str>,
        #[case] expect_violation: bool,
    ) {
        let rule = ServerResponseLocationOnRedirect;
        let tx = make_tx(status, loc);
        let config = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        );
        if expect_violation {
            assert!(v.is_some(), "expected violation for status {}", status);
        } else {
            assert!(
                v.is_none(),
                "did not expect violation for status {}",
                status
            );
        }
    }

    #[test]
    fn scope_is_server() {
        let rule = ServerResponseLocationOnRedirect;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }

    #[test]
    fn no_response_returns_none() {
        let rule = ServerResponseLocationOnRedirect;
        let tx = crate::test_helpers::make_test_transaction();
        let config = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        );
        assert!(v.is_none());
    }
}
