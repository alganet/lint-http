// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;
use crate::state::{ClientIdentifier, StateStore};
use hyper::{HeaderMap, Method};

pub struct ConnectionUpgradeRequiresUpgradeHeader;

impl Rule for ConnectionUpgradeRequiresUpgradeHeader {
    fn id(&self) -> &'static str {
        "connection_upgrade_requires_upgrade_header"
    }

    fn check_request(
        &self,
        _client: &ClientIdentifier,
        _resource: &str,
        _method: &Method,
        headers: &HeaderMap,
        _conn: &crate::connection::ConnectionMetadata,
        _state: &StateStore,
        _config: &crate::config::Config,
    ) -> Option<Violation> {
        check_connection_upgrade(headers, _config).map(|msg| Violation {
            rule: self.id().into(),
            severity: crate::rules::get_rule_severity(_config, self.id()),
            message: msg,
        })
    }

    fn check_response(
        &self,
        _client: &ClientIdentifier,
        _resource: &str,
        _status: u16,
        headers: &HeaderMap,
        _conn: &crate::connection::ConnectionMetadata,
        _state: &StateStore,
        _config: &crate::config::Config,
    ) -> Option<Violation> {
        check_connection_upgrade(headers, _config).map(|msg| Violation {
            rule: self.id().into(),
            severity: crate::rules::get_rule_severity(_config, self.id()),
            message: msg,
        })
    }
}

fn connection_contains_upgrade(headers: &HeaderMap) -> bool {
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

fn check_connection_upgrade(
    headers: &HeaderMap,
    _config: &crate::config::Config,
) -> Option<String> {
    if connection_contains_upgrade(headers) && !headers.contains_key("upgrade") {
        return Some("Connection header includes 'upgrade' but Upgrade header is missing".into());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{make_headers_from_pairs, make_test_conn, make_test_context};
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
        let rule = ConnectionUpgradeRequiresUpgradeHeader;
        let (client, state) = make_test_context();
        let method = hyper::Method::GET;
        let headers = make_headers_from_pairs(&header_pairs);
        let conn = make_test_conn();
        let violation = rule.check_request(
            &client,
            "http://test.com",
            &method,
            &headers,
            &conn,
            &state,
            &crate::config::Config::default(),
        );

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
        let rule = ConnectionUpgradeRequiresUpgradeHeader;
        let (client, state) = make_test_context();
        let status = 101; // Switching Protocols
        let headers = make_headers_from_pairs(&header_pairs);
        let conn = make_test_conn();
        let violation = rule.check_response(
            &client,
            "http://test.com",
            status,
            &headers,
            &conn,
            &state,
            &crate::config::Config::default(),
        );

        if expect_violation {
            assert!(violation.is_some());
        } else {
            assert!(violation.is_none());
        }
        Ok(())
    }
}
