// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ClientCacheRespect;

impl Rule for ClientCacheRespect {
    fn id(&self) -> &'static str {
        "client_cache_respect"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
        // Use the previous transaction passed by the linter (if any)
        let previous_tx = history.previous()?;
        let resp = previous_tx.response.as_ref()?;

        // If the previous response had validators (ETag or Last-Modified),
        // the client should send conditional headers
        let has_validators =
            resp.headers.contains_key("etag") || resp.headers.contains_key("last-modified");

        if !has_validators {
            return None;
        }

        // Check if client is using conditional headers
        let has_if_none_match = tx.request.headers.contains_key("if-none-match");
        let has_if_modified_since = tx.request.headers.contains_key("if-modified-since");

        if !has_if_none_match && !has_if_modified_since {
            Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!(
                    "Client re-requesting resource without conditional headers. \
                     Server provided validators (ETag: {}, Last-Modified: {}) but client \
                     is not using If-None-Match or If-Modified-Since headers.",
                    resp.headers
                        .get("etag")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("none"),
                    resp.headers
                        .get("last-modified")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("none")
                ),
            })
        } else {
            None
        }
    }

    fn description(&self) -> &'static str {
        "This rule checks if the client correctly uses conditional headers (`If-None-Match` or `If-Modified-Since`) when re-requesting a resource it has previously fetched.\n\nIf a server provides validators (like `ETag` or `Last-Modified`) in a response, a well-behaved client should use them in subsequent requests for the same resource to allow the server to return a `304 Not Modified` response, saving bandwidth and processing time."
    }

    fn rfc_reference(&self) -> Option<&'static str> {
        Some("[RFC 9110 §13.1.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.2): If-None-Match")
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                snippet: "GET /image.png HTTP/1.1\nHost: example.com",
            },
            Example {
                compliance: Compliance::Compliant,
                snippet: "HTTP/1.1 200 OK\nETag: \"abcdef12345\"\nContent-Length: 1024",
            },
            Example {
                compliance: Compliance::Compliant,
                snippet:
                    "GET /image.png HTTP/1.1\nHost: example.com\nIf-None-Match: \"abcdef12345\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                snippet: "GET /image.png HTTP/1.1\nHost: example.com",
            },
            Example {
                compliance: Compliance::NonCompliant,
                snippet: "HTTP/1.1 200 OK\nETag: \"abcdef12345\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                snippet:
                    "GET /image.png HTTP/1.1\nHost: example.com\n# Missing If-None-Match header!",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ClientCacheRespect;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::ClientIdentifier;
    use crate::state::StateStore;
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
    #[case(Some(vec![("last-modified", "Mon, 01 Jan 2020 00:00:00 GMT")]), vec![], true)]
    #[case(Some(vec![]), vec![], false)]
    fn check_request_cases(
        #[case] prev_resp_headers: Option<Vec<(&str, &str)>>,
        #[case] req_headers_pairs: Vec<(&str, &str)>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = ClientCacheRespect;
        let store = StateStore::new(300, 10);
        let client = make_client();
        let resource = "http://example.com/api/data";

        // Record previous response if provided
        if let Some(pairs) = prev_resp_headers {
            let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &pairs);
            tx.client = client.clone();
            tx.request.uri = resource.to_string();
            store.record_transaction(&tx);
        }

        // build request headers from pairs when needed (assigned later into transaction)
        use crate::test_helpers::make_test_transaction;
        let mut tx = make_test_transaction();
        tx.client = client.clone();
        tx.request.uri = resource.to_string();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(req_headers_pairs.as_slice());
        let history = crate::queries::by_resource::by_resource(&store, &client, resource);
        let violation = rule.check_transaction(
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );

        if expect_violation {
            assert!(violation.is_some());
            let v = violation.ok_or_else(|| anyhow::anyhow!("expected violation"))?;
            assert_eq!(v.rule, "client_cache_respect");
            assert_eq!(v.severity, crate::lint::Severity::Warn);
            assert!(v.message.contains("conditional headers"));
        } else {
            assert!(violation.is_none());
        }

        Ok(())
    }

    #[test]
    fn previous_without_response_returns_none() -> anyhow::Result<()> {
        let rule = ClientCacheRespect;
        let store = StateStore::new(300, 10);
        let client = make_client();
        let resource = "http://example.com/api/no_resp";

        // Record a previous transaction that has no response
        let mut prev_tx = crate::test_helpers::make_test_transaction();
        prev_tx.client = client.clone();
        prev_tx.request.uri = resource.to_string();
        store.record_transaction(&prev_tx);

        // Build a fresh request transaction
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = client.clone();
        tx.request.uri = resource.to_string();

        let history = crate::queries::by_resource::by_resource(&store, &client, resource);
        let violation = rule.check_transaction(
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );

        assert!(violation.is_none());
        Ok(())
    }

    #[test]
    fn scope_is_client() {
        let r = ClientCacheRespect;
        assert_eq!(
            crate::rules::Rule::scope(&r),
            crate::rules::RuleScope::Client
        );
    }
}
