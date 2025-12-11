// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;
use crate::state::{ClientIdentifier, StateStore};
use hyper::HeaderMap;

pub struct ClientCacheRespect;

impl Rule for ClientCacheRespect {
    fn id(&self) -> &'static str {
        "client_cache_respect"
    }

    fn check_request(
        &self,
        client: &ClientIdentifier,
        resource: &str,
        _method: &hyper::Method,
        headers: &HeaderMap,
        _conn: &crate::connection::ConnectionMetadata,
        state: &StateStore,
        _config: &crate::config::Config,
    ) -> Option<Violation> {
        // Check if we have a previous response for this client+resource
        let previous = state.get_previous(client, resource)?;

        // If the previous response had validators (ETag or Last-Modified),
        // the client should send conditional headers
        let has_validators = previous.etag.is_some() || previous.last_modified.is_some();

        if !has_validators {
            return None;
        }

        // Check if client is using conditional headers
        let has_if_none_match = headers.contains_key("if-none-match");
        let has_if_modified_since = headers.contains_key("if-modified-since");

        if !has_if_none_match && !has_if_modified_since {
            Some(Violation {
                rule: self.id().into(),
                severity: "warn".into(),
                message: format!(
                    "Client re-requesting resource without conditional headers. \
                     Server provided validators (ETag: {}, Last-Modified: {}) but client \
                     is not using If-None-Match or If-Modified-Since headers.",
                    previous.etag.as_deref().unwrap_or("none"),
                    previous.last_modified.as_deref().unwrap_or("none")
                ),
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::make_headers_from_pairs;
    use rstest::rstest;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_client() -> ClientIdentifier {
        ClientIdentifier::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            "test-client/1.0".to_string(),
        )
    }

    #[rstest]
    #[case(None, vec![], false)]
    #[case(Some(vec![("etag", "\"abc123\"")]), vec![("if-none-match","\"abc123\"")], false)]
    #[case(Some(vec![("etag", "\"abc123\"")]), vec![], true)]
    #[case(Some(vec![]), vec![], false)]
    fn check_request_cases(
        #[case] prev_resp_headers: Option<Vec<(&str, &str)>>,
        #[case] req_headers_pairs: Vec<(&str, &str)>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = ClientCacheRespect;
        let store = StateStore::new(300);
        let client = make_client();
        let resource = "http://example.com/api/data";

        // Record previous response if provided
        if let Some(pairs) = prev_resp_headers {
            let resp_headers = make_headers_from_pairs(&pairs);
            store.record_transaction(&client, resource, 200, &resp_headers);
        }

        let req_headers = make_headers_from_pairs(&req_headers_pairs);
        let conn = crate::connection::ConnectionMetadata::new("127.0.0.1:12345".parse()?);
        let cfg = crate::config::Config::default();
        let violation = rule.check_request(
            &client,
            resource,
            &hyper::Method::GET,
            &req_headers,
            &conn,
            &store,
            &cfg,
        );

        if expect_violation {
            assert!(violation.is_some());
            let v = violation.ok_or_else(|| anyhow::anyhow!("expected violation"))?;
            assert_eq!(v.rule, "client_cache_respect");
            assert_eq!(v.severity, "warn");
            assert!(v.message.contains("conditional headers"));
        } else {
            assert!(violation.is_none());
        }

        Ok(())
    }
}
