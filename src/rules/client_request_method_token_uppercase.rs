// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;
use crate::state::StateStore;

pub struct ClientRequestMethodTokenUppercase;

impl Rule for ClientRequestMethodTokenUppercase {
    fn id(&self) -> &'static str {
        "client_request_method_token_uppercase"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _conn: &crate::connection::ConnectionMetadata,
        _state: &StateStore,
        _config: &crate::config::Config,
    ) -> Option<Violation> {
        let m = tx.request.method.as_str();

        // Validate token characters per RFC token (tchar) and uppercase requirement using shared helpers
        if let Some(c) = crate::token::find_invalid_token_char(m) {
            return Some(Violation {
                rule: self.id().into(),
                severity: crate::rules::get_rule_severity(_config, self.id()),
                message: format!("Method token contains invalid character: '{}'", c),
            });
        }

        if crate::token::find_first_lowercase(m).is_some() {
            return Some(Violation {
                rule: self.id().into(),
                severity: crate::rules::get_rule_severity(_config, self.id()),
                message: "Method token should be uppercase".into(),
            });
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{make_test_conn, make_test_context};
    use hyper::Method;
    use rstest::rstest;

    #[rstest]
    #[case("GET", false)]
    #[case("POST", false)]
    #[case("gEt", true)]
    #[case("get", true)]
    #[case("G3T", false)]
    #[case("G-ET", false)]
    #[case("G@T", true)]
    fn check_request_cases(
        #[case] method_str: &str,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = ClientRequestMethodTokenUppercase;
        let (_client, state) = make_test_context();
        let method_res = Method::from_bytes(method_str.as_bytes());
        if method_res.is_err() {
            // Invalid method token cannot be constructed; treat as violation
            assert!(
                expect_violation,
                "method '{}' invalid but test expected no violation",
                method_str
            );
            return Ok(());
        }
        let method = method_res.unwrap();
        let conn = make_test_conn();
        use crate::test_helpers::make_test_transaction;
        let mut tx = make_test_transaction();
        tx.request.method = method.as_str().to_string();
        let violation =
            rule.check_transaction(&tx, &conn, &state, &crate::config::Config::default());

        if expect_violation {
            assert!(violation.is_some());
        } else {
            assert!(violation.is_none());
        }
        Ok(())
    }

    #[test]
    fn violation_messages_are_meaningful() -> anyhow::Result<()> {
        let rule = ClientRequestMethodTokenUppercase;
        let (_client, state) = make_test_context();
        let conn = make_test_conn();

        use crate::test_helpers::make_test_transaction;

        // Lowercase method -> should indicate uppercase requirement
        let mut tx = make_test_transaction();
        tx.request.method = "get".to_string();
        let v = rule.check_transaction(&tx, &conn, &state, &crate::config::Config::default());
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("uppercase"));

        // Invalid character should be reported with char in message
        let mut tx2 = make_test_transaction();
        tx2.request.method = "G@T".to_string();
        let v2 = rule.check_transaction(&tx2, &conn, &state, &crate::config::Config::default());
        assert!(v2.is_some());
        let msg2 = v2.unwrap().message;
        assert!(msg2.contains("invalid character") && msg2.contains("@"));

        Ok(())
    }
}
