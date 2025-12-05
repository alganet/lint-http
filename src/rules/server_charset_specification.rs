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
    use crate::test_helpers::{make_test_conn, make_test_context};
    use hyper::HeaderMap;

    #[test]
    fn check_response_no_violation_with_charset() {
        let rule = ServerCharsetSpecification;
        let (client, state) = make_test_context();
        let conn = make_test_conn();
        let mut headers = HeaderMap::new();
        headers.insert(
            hyper::header::CONTENT_TYPE,
            "text/html; charset=utf-8".parse().unwrap(),
        );

        let violation =
            rule.check_response(&client, "http://test.com", 200, &headers, &conn, &state);
        assert!(violation.is_none());
    }

    #[test]
    fn check_response_no_violation_with_charset_nospace() {
        let rule = ServerCharsetSpecification;
        let (client, state) = make_test_context();
        let conn = make_test_conn();
        let mut headers = HeaderMap::new();
        headers.insert(
            hyper::header::CONTENT_TYPE,
            "text/html;charset=utf-8".parse().unwrap(),
        );

        let violation =
            rule.check_response(&client, "http://test.com", 200, &headers, &conn, &state);
        assert!(violation.is_none());
    }

    #[test]
    fn check_response_no_violation_with_charset_case_insensitive() {
        let rule = ServerCharsetSpecification;
        let (client, state) = make_test_context();
        let conn = make_test_conn();
        let mut headers = HeaderMap::new();
        headers.insert(
            hyper::header::CONTENT_TYPE,
            "TEXT/HTML;CHARSET=UTF-8".parse().unwrap(),
        );

        let violation =
            rule.check_response(&client, "http://test.com", 200, &headers, &conn, &state);
        assert!(violation.is_none());
    }

    #[test]
    fn check_response_violation_missing_charset() {
        let rule = ServerCharsetSpecification;
        let (client, state) = make_test_context();
        let conn = make_test_conn();
        let mut headers = HeaderMap::new();
        headers.insert(hyper::header::CONTENT_TYPE, "text/html".parse().unwrap());

        let violation =
            rule.check_response(&client, "http://test.com", 200, &headers, &conn, &state);
        assert!(violation.is_some());
        assert_eq!(
            violation.unwrap().message,
            "Text-based Content-Type header missing charset parameter."
        );
    }

    #[test]
    fn check_response_no_violation_non_text() {
        let rule = ServerCharsetSpecification;
        let (client, state) = make_test_context();
        let conn = make_test_conn();
        let mut headers = HeaderMap::new();
        headers.insert(
            hyper::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );

        let violation =
            rule.check_response(&client, "http://test.com", 200, &headers, &conn, &state);
        assert!(violation.is_none());
    }

    #[test]
    fn check_response_no_violation_no_content_type() {
        let rule = ServerCharsetSpecification;
        let (client, state) = make_test_context();
        let conn = make_test_conn();
        let headers = HeaderMap::new();

        let violation =
            rule.check_response(&client, "http://test.com", 200, &headers, &conn, &state);
        assert!(violation.is_none());
    }
}
