// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use hyper::{HeaderMap, Method};
use crate::lint::Violation;
use crate::lint::rules::Rule;

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
