// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

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
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
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
                severity: config.severity,
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
                        severity: config.severity,
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

    fn title(&self) -> Option<&'static str> {
        Some("Server No Body For 1xx, 204, 304")
    }

    fn description(&self) -> &'static str {
        "Responses with status codes in the 1xx range (Informational), `204 No Content`, and `304 Not Modified` MUST NOT include a message body. This rule flags responses that contain headers which indicate a body (for example, `Transfer-Encoding: chunked` or a `Content-Length` header whose value is greater than zero).\n\nWhen these statuses include a message body, intermediaries and clients can misinterpret the message framing, leading to incorrect behavior."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[crate::rules::SpecRef {
            spec: "RFC 9110",
            section: Some("6.4.1"),
            url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-6.4.1",
            note: "Message body for status codes 1xx, 204, 304",
        }]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("Response"),
                snippet: "HTTP/1.1 204 No Content\nContent-Type: text/plain\n# No Content-Length or Transfer-Encoding header",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("Response (Content-Length > 0)"),
                snippet: "HTTP/1.1 204 No Content\nContent-Type: text/plain\nContent-Length: 10",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("Response (Transfer-Encoding present)"),
                snippet: "HTTP/1.1 100 Continue\nTransfer-Encoding: chunked",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ServerNoBodyFor1xx204304;

#[cfg(test)]
mod tests {
    use super::*;

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
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(header_pairs.as_slice()),

            body_length: None,
            trailers: None,
        });

        let test_rule_config = crate::test_helpers::make_test_config_with_severity(
            "server_no_body_for_1xx_204_304",
            "error",
        );
        let violation = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &test_rule_config,
        );

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

    #[test]
    fn check_missing_response() {
        let rule = ServerNoBodyFor1xx204304;
        let tx = crate::test_helpers::make_test_transaction();
        let violation = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_severity(
                "server_no_body_for_1xx_204_304",
                "error",
            ),
        );
        assert!(violation.is_none());
    }
}
