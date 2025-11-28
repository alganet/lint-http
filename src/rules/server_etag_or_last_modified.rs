// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use hyper::HeaderMap;
use crate::lint::Violation;
use crate::lint::rules::Rule;

pub struct ServerEtagOrLastModified;

impl Rule for ServerEtagOrLastModified {
    fn id(&self) -> &'static str {
        "server_etag_or_last_modified"
    }

    fn check_response(&self, status: u16, headers: &HeaderMap) -> Option<Violation> {
        if status == 200 && !headers.contains_key("etag") && !headers.contains_key("last-modified") {
            Some(Violation {
                rule: self.id().into(),
                severity: "info".into(),
                message: "Consider providing ETag or Last-Modified for validation".into(),
            })
        } else {
            None
        }
    }
}
