// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use hyper::{HeaderMap, Method};
use crate::lint::Violation;
use crate::rules::Rule;

pub struct ClientUserAgentPresent;

impl Rule for ClientUserAgentPresent {
    fn id(&self) -> &'static str {
        "client_user_agent_present"
    }

    fn check_request(&self, _method: &Method, headers: &HeaderMap) -> Option<Violation> {
        if !headers.contains_key("user-agent") {
            Some(Violation {
                rule: self.id().into(),
                severity: "warn".into(),
                message: "User-Agent header missing".into(),
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
    fn check_request_missing_header() {
        let rule = ClientUserAgentPresent;
        let method = Method::GET;
        let headers = HeaderMap::new();
        let violation = rule.check_request(&method, &headers);
        assert!(violation.is_some());
        assert_eq!(violation.unwrap().message, "User-Agent header missing");
    }

    #[test]
    fn check_request_present_header() {
        let rule = ClientUserAgentPresent;
        let method = Method::GET;
        let mut headers = HeaderMap::new();
        headers.insert("user-agent", "curl/7.68.0".parse().unwrap());
        let violation = rule.check_request(&method, &headers);
        assert!(violation.is_none());
    }
}
