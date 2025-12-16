// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;
use crate::state::StateStore;

pub struct ClientAcceptEncodingPresent;

impl Rule for ClientAcceptEncodingPresent {
    fn id(&self) -> &'static str {
        "client_accept_encoding_present"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _conn: &crate::connection::ConnectionMetadata,
        _state: &StateStore,
        config: &crate::config::Config,
    ) -> Option<Violation> {
        if !tx.request.headers.contains_key("accept-encoding") {
            Some(Violation {
                rule: self.id().into(),
                severity: crate::rules::get_rule_severity(config, self.id()),
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
    use crate::test_helpers::{make_test_conn, make_test_context};

    #[test]
    fn check_request_missing_header() -> anyhow::Result<()> {
        let rule = ClientAcceptEncodingPresent;
        let (_client, state) = make_test_context();
        let conn = make_test_conn();
        let tx = crate::test_helpers::make_test_transaction();
        let violation =
            rule.check_transaction(&tx, &conn, &state, &crate::config::Config::default());
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
        let (_client, state) = make_test_context();
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request
            .headers
            .insert("accept-encoding", "gzip".parse()?);
        let conn = make_test_conn();
        let violation =
            rule.check_transaction(&tx, &conn, &state, &crate::config::Config::default());
        assert!(violation.is_none());
        Ok(())
    }
}
