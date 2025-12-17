// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ClientAcceptEncodingPresent;

impl Rule for ClientAcceptEncodingPresent {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "client_accept_encoding_present"
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
        if !tx.request.headers.contains_key("accept-encoding") {
            Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Request missing Accept-Encoding header".into(),
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
    fn check_request_missing_header() -> anyhow::Result<()> {
        let rule = ClientAcceptEncodingPresent;
        let tx = crate::test_helpers::make_test_transaction();
        let violation =
            rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(violation.is_some());
        assert_eq!(
            violation.map(|v| v.message),
            Some("Request missing Accept-Encoding header".to_string())
        );
        Ok(())
    }

    #[test]
    fn check_request_present_header() -> anyhow::Result<()> {
        let rule = ClientAcceptEncodingPresent;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request
            .headers
            .insert("accept-encoding", "gzip".parse()?);
        let violation =
            rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(violation.is_none());
        Ok(())
    }
}
