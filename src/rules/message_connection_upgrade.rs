// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;
use crate::state::StateStore;

pub struct MessageConnectionUpgrade;

impl Rule for MessageConnectionUpgrade {
    fn id(&self) -> &'static str {
        "message_connection_upgrade"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _conn: &crate::connection::ConnectionMetadata,
        _state: &StateStore,
        _config: &crate::config::Config,
    ) -> Option<Violation> {
        // Check request headers
        if let Some(msg) = check_connection_upgrade_map(&tx.request.headers, _config) {
            return Some(Violation {
                rule: self.id().into(),
                severity: crate::rules::get_rule_severity(_config, self.id()),
                message: msg,
            });
        }
        // Check response headers if present
        if let Some(resp) = &tx.response {
            if let Some(msg) = check_connection_upgrade_map(&resp.headers, _config) {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: crate::rules::get_rule_severity(_config, self.id()),
                    message: msg,
                });
            }
        }
        None
    }
}
fn connection_contains_upgrade_map(headers: &hyper::HeaderMap) -> bool {
    if let Some(val) = headers.get("connection") {
        if let Ok(s) = val.to_str() {
            for token in s.split(',') {
                if token.trim().eq_ignore_ascii_case("upgrade") {
                    return true;
                }
            }
        }
    }
    false
}

fn check_connection_upgrade_map(
    headers: &hyper::HeaderMap,
    _config: &crate::config::Config,
) -> Option<String> {
    if connection_contains_upgrade_map(headers) && !headers.contains_key("upgrade") {
        return Some("Connection header includes 'upgrade' but Upgrade header is missing".into());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{make_test_conn, make_test_context};
    use rstest::rstest;

    #[rstest]
    #[case(vec![("connection", "upgrade")], true)]
    #[case(vec![("connection", "keep-alive, upgrade")], true)]
    #[case(vec![("connection", "Upgrade")], true)]
    #[case(vec![("connection", "upgrade"), ("upgrade", "websocket")], false)]
    #[case(vec![], false)]
    #[case(vec![("connection", "keep-alive")], false)]
    #[case(vec![("connection", "upgrade"), ("upgrade", "")], false)]
    fn check_request_cases(
        #[case] header_pairs: Vec<(&str, &str)>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageConnectionUpgrade;
        let (_client, state) = make_test_context();
        use crate::test_helpers::make_test_transaction;
        let conn = make_test_conn();
        let mut tx = make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(header_pairs.as_slice());
        let violation =
            rule.check_transaction(&tx, &conn, &state, &crate::config::Config::default());

        if expect_violation {
            assert!(violation.is_some());
        } else {
            assert!(violation.is_none());
        }
        Ok(())
    }

    #[rstest]
    #[case(vec![("connection", "upgrade")], true)]
    #[case(vec![("connection", "upgrade"), ("upgrade", "websocket")], false)]
    fn check_response_cases(
        #[case] header_pairs: Vec<(&str, &str)>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageConnectionUpgrade;
        let (_client, state) = make_test_context();
        let status = 101; // Switching Protocols
        use crate::test_helpers::make_test_transaction_with_response;
        let conn = make_test_conn();
        let tx = make_test_transaction_with_response(status, &header_pairs);
        let violation =
            rule.check_transaction(&tx, &conn, &state, &crate::config::Config::default());

        if expect_violation {
            assert!(violation.is_some());
        } else {
            assert!(violation.is_none());
        }
        Ok(())
    }
}
