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
    use std::net::{IpAddr, Ipv4Addr};

    fn make_client() -> ClientIdentifier {
        ClientIdentifier::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            "test-client/1.0".to_string(),
        )
    }

    #[test]
    fn no_violation_on_first_request() -> anyhow::Result<()> {
        let rule = ClientCacheRespect;
        let store = StateStore::new(300);
        let client = make_client();
        let resource = "http://example.com/api/data";

        let headers = HeaderMap::new();
        let conn = crate::connection::ConnectionMetadata::new("127.0.0.1:12345".parse()?);
        let violation = rule.check_request(
            &client,
            resource,
            &hyper::Method::GET,
            &headers,
            &conn,
            &store,
        );

        assert!(violation.is_none());
        Ok(())
    }

    #[test]
    fn no_violation_when_using_conditional_headers() -> anyhow::Result<()> {
        let rule = ClientCacheRespect;
        let store = StateStore::new(300);
        let client = make_client();
        let resource = "http://example.com/api/data";

        // First, record a response with ETag
        let mut resp_headers = HeaderMap::new();
        resp_headers.insert("etag", "\"abc123\"".parse()?);
        store.record_transaction(&client, resource, 200, &resp_headers);

        // Second request with If-None-Match
        let mut req_headers = HeaderMap::new();
        req_headers.insert("if-none-match", "\"abc123\"".parse()?);
        let conn = crate::connection::ConnectionMetadata::new("127.0.0.1:12345".parse()?);
        let violation = rule.check_request(
            &client,
            resource,
            &hyper::Method::GET,
            &req_headers,
            &conn,
            &store,
        );

        assert!(violation.is_none());
        Ok(())
    }

    #[test]
    fn violation_when_missing_conditional_headers() -> anyhow::Result<()> {
        let rule = ClientCacheRespect;
        let store = StateStore::new(300);
        let client = make_client();
        let resource = "http://example.com/api/data";

        // First, record a response with ETag
        let mut resp_headers = HeaderMap::new();
        resp_headers.insert("etag", "\"abc123\"".parse()?);
        store.record_transaction(&client, resource, 200, &resp_headers);

        // Second request WITHOUT conditional headers
        let req_headers = HeaderMap::new();
        let conn = crate::connection::ConnectionMetadata::new("127.0.0.1:12345".parse()?);
        let violation = rule.check_request(
            &client,
            resource,
            &hyper::Method::GET,
            &req_headers,
            &conn,
            &store,
        );

        assert!(violation.is_some());
        let v = violation.ok_or_else(|| anyhow::anyhow!("expected violation"))?;
        assert_eq!(v.rule, "client_cache_respect");
        assert_eq!(v.severity, "warn");
        assert!(v.message.contains("conditional headers"));
        Ok(())
    }

    #[test]
    fn no_violation_when_previous_response_had_no_validators() -> anyhow::Result<()> {
        let rule = ClientCacheRespect;
        let store = StateStore::new(300);
        let client = make_client();
        let resource = "http://example.com/api/data";

        // First, record a response WITHOUT validators
        let resp_headers = HeaderMap::new();
        store.record_transaction(&client, resource, 200, &resp_headers);

        // Second request without conditional headers should be fine
        // since server didn't provide validators
        let req_headers = HeaderMap::new();
        let conn = crate::connection::ConnectionMetadata::new("127.0.0.1:12345".parse()?);
        let violation = rule.check_request(
            &client,
            resource,
            &hyper::Method::GET,
            &req_headers,
            &conn,
            &store,
        );

        assert!(violation.is_none());
        Ok(())
    }
}
