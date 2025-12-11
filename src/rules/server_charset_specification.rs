// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;
use crate::state::{ClientIdentifier, StateStore};
use hyper::HeaderMap;

pub struct ServerCharsetSpecification;

impl Rule for ServerCharsetSpecification {
    fn id(&self) -> &'static str {
        "server_charset_specification"
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
        if let Some(content_type) = headers.get(hyper::header::CONTENT_TYPE) {
            if let Ok(ct_str) = content_type.to_str() {
                let ct_lower = ct_str.to_lowercase();
                if ct_lower.starts_with("text/")
                    && !ct_lower.contains(";charset=")
                    && !ct_lower.contains("; charset=")
                {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: "warn".into(),
                        message: "Text-based Content-Type header missing charset parameter.".into(),
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
    use crate::test_helpers::{make_headers_from_pairs, make_test_conn, make_test_context};
    use rstest::rstest;

    #[rstest]
    #[case("text/html; charset=utf-8", false, None)]
    #[case("text/html;charset=utf-8", false, None)]
    #[case("TEXT/HTML;CHARSET=UTF-8", false, None)]
    #[case(
        "text/html",
        true,
        Some("Text-based Content-Type header missing charset parameter.")
    )]
    #[case("application/json", false, None)]
    #[case("", false, None)]
    fn check_response_cases(
        #[case] content_type: &str,
        #[case] expect_violation: bool,
        #[case] expected_message: Option<&str>,
    ) -> anyhow::Result<()> {
        let rule = ServerCharsetSpecification;
        let (client, state) = make_test_context();
        let conn = make_test_conn();
        let headers = if content_type.is_empty() {
            make_headers_from_pairs(&[])
        } else {
            make_headers_from_pairs(&[("content-type", content_type)])
        };

        let violation = rule.check_response(
            &client,
            "http://test.com",
            200,
            &headers,
            &conn,
            &state,
            &crate::config::Config::default(),
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
}
