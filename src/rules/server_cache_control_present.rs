// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use hyper::HeaderMap;
use crate::lint::Violation;
use crate::lint::rules::Rule;

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
