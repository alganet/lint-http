// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use hyper::HeaderMap;
use crate::lint::Violation;
use crate::lint::rules::Rule;

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
