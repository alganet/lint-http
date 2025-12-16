// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;
use crate::state::StateStore;

pub struct ServerNoBodyFor1xx204304;

impl Rule for ServerNoBodyFor1xx204304 {
    fn id(&self) -> &'static str {
        "server_no_body_for_1xx_204_304"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _conn: &crate::connection::ConnectionMetadata,
        _state: &StateStore,
        _config: &crate::config::Config,
    ) -> Option<Violation> {
        let Some(resp) = &tx.response else {
            return None;
        };
        // Rules apply to 1xx, 204 and 304
        let status = resp.status;
        let is_no_body_status = (100..200).contains(&status) || status == 204 || status == 304;
        if !is_no_body_status {
            return None;
        }

        // If Transfer-Encoding present, that's indicative of a body
        if resp.headers.contains_key("transfer-encoding") {
            return Some(Violation {
                rule: self.id().into(),
                severity: crate::rules::get_rule_severity(_config, self.id()),
                message: format!(
                    "Response {} must not have a message body (Transfer-Encoding present)",
                    status
                ),
            });
        }

        // If Content-Length present and greater than zero, that's indicative of a body
        if let Some(cl) = resp.headers.get("content-length") {
            if let Some(n) = cl
                .to_str()
                .ok()
                .and_then(|s| s.trim().parse::<usize>().ok())
            {
                if n > 0 {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: crate::rules::get_rule_severity(_config, self.id()),
                        message: format!(
                            "Response {} must not have a message body (Content-Length {} > 0)",
                            status, n
                        ),
                    });
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{make_test_conn, make_test_context};
    use rstest::rstest;

    #[rstest]
    #[case(204, vec![("content-length", "10")], true, Some("Content-Length"))]
    #[case(204, vec![("content-length", "0")], false, None)]
    #[case(204, vec![("transfer-encoding", "chunked")], true, Some("Transfer-Encoding"))]
    #[case(200, vec![("content-length", "10")], false, None)]
    #[case(100, vec![("transfer-encoding", "chunked")], true, Some("Transfer-Encoding"))]
    #[case(304, vec![("content-length", "10")], true, Some("Content-Length"))]
    #[case(304, vec![], false, None)]
    fn check_response_cases(
        #[case] status: u16,
        #[case] header_pairs: Vec<(&str, &str)>,
        #[case] expect_violation: bool,
        #[case] expected_contains: Option<&str>,
    ) -> anyhow::Result<()> {
        let rule = ServerNoBodyFor1xx204304;
        let (_client, state) = make_test_context();
        let conn = make_test_conn();
        // Provide an explicit config with severity set to 'error' so tests assert correctly
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert(
            "severity".to_string(),
            toml::Value::String("error".to_string()),
        );
        cfg.rules.insert(
            "server_no_body_for_1xx_204_304".to_string(),
            toml::Value::Table(table),
        );

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status,
            headers: crate::test_helpers::make_headers_from_pairs(header_pairs.as_slice()),
        });

        let violation = rule.check_transaction(&tx, &conn, &state, &cfg);

        if expect_violation {
            assert!(violation.is_some());
            let v = violation.unwrap();
            assert_eq!(v.rule, "server_no_body_for_1xx_204_304");
            assert_eq!(v.severity, crate::lint::Severity::Error);
            if let Some(substr) = expected_contains {
                assert!(v.message.contains(substr));
            }
        } else {
            assert!(violation.is_none());
        }
        Ok(())
    }
}
