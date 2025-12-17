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
        _previous: Option<&crate::http_transaction::HttpTransaction>,
        config: &crate::config::Config,
    ) -> Option<Violation> {
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
                severity: crate::rules::get_rule_severity(config, self.id()),
                message: "Response 200 without ETag or Last-Modified validator".into(),
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_response_200_missing_headers() -> anyhow::Result<()> {
        let rule = ServerEtagOrLastModified;

        let status = 200;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status,
            headers: crate::test_helpers::make_headers_from_pairs(&[]),
        });
        let violation = rule.check_transaction(&tx, None, &crate::config::Config::default());
        assert!(violation.is_some());
        assert_eq!(
            violation.map(|v| v.message),
            Some("Response 200 without ETag or Last-Modified validator".to_string())
        );
        Ok(())
    }

    #[test]
    fn check_response_200_present_etag() -> anyhow::Result<()> {
        let rule = ServerEtagOrLastModified;

        let status = 200;

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status,
            headers: crate::test_helpers::make_headers_from_pairs(&[("etag", "\"12345\"")]),
        });
        let violation = rule.check_transaction(&tx, None, &crate::config::Config::default());
        assert!(violation.is_none());
        Ok(())
    }

    #[test]
    fn check_response_200_present_last_modified() -> anyhow::Result<()> {
        let rule = ServerEtagOrLastModified;

        let status = 200;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status,
            headers: crate::test_helpers::make_headers_from_pairs(&[(
                "last-modified",
                "Wed, 21 Oct 2015 07:28:00 GMT",
            )]),
        });
        let violation = rule.check_transaction(&tx, None, &crate::config::Config::default());
        assert!(violation.is_none());
        Ok(())
    }

    #[test]
    fn check_response_404_missing_headers() {
        let rule = ServerEtagOrLastModified;

        let status = 404;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status,
            headers: crate::test_helpers::make_headers_from_pairs(&[]),
        });
        let violation = rule.check_transaction(&tx, None, &crate::config::Config::default());
        assert!(violation.is_none());
    }
}
