// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use hyper::HeaderMap;
use crate::lint::Violation;
use crate::rules::Rule;

pub struct ServerCacheControlPresent;

impl Rule for ServerCacheControlPresent {
    fn id(&self) -> &'static str {
        "server_cache_control_present"
    }

    fn check_response(&self, status: u16, headers: &HeaderMap) -> Option<Violation> {
        if status == 200 && !headers.contains_key("cache-control") {
            Some(Violation {
                rule: self.id().into(),
                severity: "warn".into(),
                message: "Response 200 without Cache-Control header".into(),
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
        let rule = ServerCacheControlPresent;
        let status = 200;
        let headers = HeaderMap::new();
        let violation = rule.check_response(status, &headers);
        assert!(violation.is_some());
        assert_eq!(violation.unwrap().message, "Response 200 without Cache-Control header");
    }

    #[test]
    fn check_response_200_present_header() {
        let rule = ServerCacheControlPresent;
        let status = 200;
        let mut headers = HeaderMap::new();
        headers.insert("cache-control", "no-cache".parse().unwrap());
        let violation = rule.check_response(status, &headers);
        assert!(violation.is_none());
    }

    #[test]
    fn check_response_404_missing_header() {
        let rule = ServerCacheControlPresent;
        let status = 404;
        let headers = HeaderMap::new();
        let violation = rule.check_response(status, &headers);
        assert!(violation.is_none());
    }
}
