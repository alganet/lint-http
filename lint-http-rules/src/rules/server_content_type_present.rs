// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ServerContentTypePresent;

impl Rule for ServerContentTypePresent {
    fn id(&self) -> &'static str {
        "server_content_type_present"
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

        // Per RFCs, no body is allowed for 1xx, 204, 304 responses
        let status = resp.status;
        if (100..200).contains(&status) || status == 204 || status == 304 {
            return None;
        }

        if resp.headers.contains_key("content-type") {
            return None;
        }

        // If response likely contains a body, require Content-Type.
        let has_nonzero_content_length =
            crate::helpers::headers::get_header_str(&resp.headers, "content-length")
                .and_then(|s| s.parse::<usize>().ok())
                .map(|n| n > 0)
                .unwrap_or(false);

        let has_transfer_encoding = resp.headers.contains_key("transfer-encoding");

        // There is likely a body if any of the following holds:
        // - non-zero Content-Length
        // - Transfer-Encoding is present
        // - 2xx status and neither Content-Length nor Transfer-Encoding is present
        let likely_has_body = has_nonzero_content_length
            || has_transfer_encoding
            || ((200..300).contains(&status) && !resp.headers.contains_key("content-length"));

        if likely_has_body {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Response likely has body but is missing Content-Type header".into(),
            });
        }

        None
    }

    fn title(&self) -> Option<&'static str> {
        Some("Server Content-Type Present")
    }

    fn description(&self) -> &'static str {
        "This rule ensures that responses which likely contain a body include a `Content-Type` header. This helps downstream components and user agents interpret the response bytes correctly.\n\nThe rule considers a response to likely have a body when any of:\n- `Content-Length` is present and > 0\n- `Transfer-Encoding` is present\n- Response status is 2xx and neither `Content-Length` nor `Transfer-Encoding` is present"
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("8.3"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3",
                note: "Content-Type header",
            },
            crate::rules::SpecRef {
                spec: "RFC 9112",
                section: Some("6"),
                url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-6",
                note: "Message body length rules",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("Response"),
                snippet:
                    "HTTP/1.1 200 OK\nContent-Type: text/html; charset=utf-8\nContent-Length: 123",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("Response"),
                snippet: "HTTP/1.1 200 OK\nContent-Length: 123\n# Missing Content-Type",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ServerContentTypePresent;

#[cfg(test)]
mod tests {
    use super::*;

    use rstest::rstest;

    #[rstest]
    #[case(200, vec![("content-type", "text/html")], false, None)]
    #[case(200, vec![], true, Some("Response likely has body but is missing Content-Type header"))]
    #[case(204, vec![], false, None)]
    #[case(100, vec![], false, None)]
    #[case(101, vec![], false, None)]
    #[case(304, vec![], false, None)]
    #[case(200, vec![("content-length", "0")], false, None)]
    #[case(200, vec![("content-length", "10")], true, Some("Response likely has body but is missing Content-Type header"))]
    #[case(404, vec![("content-type", "text/html")], false, None)]
    #[case(404, vec![("content-length", "10")], true, Some("Response likely has body but is missing Content-Type header"))]
    #[case(500, vec![("transfer-encoding", "chunked")], true, Some("Response likely has body but is missing Content-Type header"))]
    #[case(200, vec![("transfer-encoding", "chunked")], true, Some("Response likely has body but is missing Content-Type header"))]
    fn check_response_cases(
        #[case] status: u16,
        #[case] header_pairs: Vec<(&str, &str)>,
        #[case] expect_violation: bool,
        #[case] expected_message: Option<&str>,
    ) -> anyhow::Result<()> {
        let rule = ServerContentTypePresent;

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(header_pairs.as_slice()),

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
                expected_message.map(|s| s.to_string())
            );
        } else {
            assert!(violation.is_none());
        }
        Ok(())
    }

    #[test]
    fn check_missing_response() {
        let rule = ServerContentTypePresent;
        let tx = crate::test_helpers::make_test_transaction();
        let violation = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(violation.is_none());
    }
}
