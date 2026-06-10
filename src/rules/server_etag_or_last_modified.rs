// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ServerEtagOrLastModified;

impl Rule for ServerEtagOrLastModified {
    fn id(&self) -> &'static str {
        "server_etag_or_last_modified"
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
        let Some(resp) = &tx.response else {
            return None;
        };
        let status = resp.status;
        if status == 200
            && !resp.headers.contains_key("etag")
            && !resp.headers.contains_key("last-modified")
        {
            Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Response 200 without ETag or Last-Modified validator".into(),
            })
        } else {
            None
        }
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ServerEtagOrLastModified;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(200, &[], true)]
    #[case(200, &[("etag", "\"12345\"")], false)]
    #[case(200, &[("last-modified", "Wed, 21 Oct 2015 07:28:00 GMT")], false)]
    #[case(404, &[], false)]
    fn check_response_validation(
        #[case] status: u16,
        #[case] headers: &[(&str, &str)],
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = ServerEtagOrLastModified;

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(headers),

            body_length: None,
            trailers: None,
        });

        let violation = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        if expect_violation {
            assert!(violation.is_some());
            assert_eq!(
                violation.map(|v| v.message),
                Some("Response 200 without ETag or Last-Modified validator".to_string())
            );
        } else {
            assert!(violation.is_none());
        }
        Ok(())
    }

    #[test]
    fn check_missing_response() {
        let rule = ServerEtagOrLastModified;
        let tx = crate::test_helpers::make_test_transaction();
        let violation = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(violation.is_none());
    }
}
