// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use hyper::{HeaderMap, Method};
use crate::lint::Violation;
use crate::lint::rules::Rule;

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
