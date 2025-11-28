// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use hyper::HeaderMap;
use crate::lint::Violation;
use crate::rules::Rule;

pub struct ServerXContentTypeOptions;

impl Rule for ServerXContentTypeOptions {
    fn id(&self) -> &'static str {
        "server_x_content_type_options"
    }

    fn check_response(&self, status: u16, headers: &HeaderMap) -> Option<Violation> {
        if status >= 200 && !headers.contains_key("x-content-type-options") {
            Some(Violation {
                rule: self.id().into(),
                severity: "info".into(),
                message: "X-Content-Type-Options header missing (nosniff)".into(),
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::HeaderMap;

    #[test]
    fn check_response_200_missing_header() {
        let rule = ServerXContentTypeOptions;
        let status = 200;
        let headers = HeaderMap::new();
        let violation = rule.check_response(status, &headers);
        assert!(violation.is_some());
        assert_eq!(violation.unwrap().message, "X-Content-Type-Options header missing (nosniff)");
    }

    #[test]
    fn check_response_200_present_header() {
        let rule = ServerXContentTypeOptions;
        let status = 200;
        let mut headers = HeaderMap::new();
        headers.insert("x-content-type-options", "nosniff".parse().unwrap());
        let violation = rule.check_response(status, &headers);
        assert!(violation.is_none());
    }

    #[test]
    fn check_response_404_missing_header() {
        let rule = ServerXContentTypeOptions;
        let status = 404;
        let headers = HeaderMap::new();
        let violation = rule.check_response(status, &headers);
        assert!(violation.is_some());
        assert_eq!(violation.unwrap().message, "X-Content-Type-Options header missing (nosniff)");
    }

    #[test]
    fn check_response_101_missing_header() {
        let rule = ServerXContentTypeOptions;
        let status = 101;
        let headers = HeaderMap::new();
        let violation = rule.check_response(status, &headers);
        assert!(violation.is_none());
    }
}
