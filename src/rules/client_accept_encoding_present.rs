// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use hyper::{HeaderMap, Method};
use crate::lint::Violation;
use crate::rules::Rule;

pub struct ClientAcceptEncodingPresent;

impl Rule for ClientAcceptEncodingPresent {
    fn id(&self) -> &'static str {
        "client_accept_encoding_present"
    }

    fn check_request(&self, _method: &Method, headers: &HeaderMap) -> Option<Violation> {
        if !headers.contains_key("accept-encoding") {
            Some(Violation {
                rule: self.id().into(),
                severity: "info".into(),
                message: "Accept-Encoding header missing".into(),
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
        let rule = ClientAcceptEncodingPresent;
        let method = Method::GET;
        let headers = HeaderMap::new();
        let violation = rule.check_request(&method, &headers);
        assert!(violation.is_some());
        assert_eq!(violation.unwrap().message, "Accept-Encoding header missing");
    }

    #[test]
    fn check_request_present_header() {
        let rule = ClientAcceptEncodingPresent;
        let method = Method::GET;
        let mut headers = HeaderMap::new();
        headers.insert("accept-encoding", "gzip".parse().unwrap());
        let violation = rule.check_request(&method, &headers);
        assert!(violation.is_none());
    }
}
