// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ClientCacheRespect;

impl Rule for ClientCacheRespect {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "client_cache_respect"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        previous: Option<&crate::http_transaction::HttpTransaction>,
        config: &Self::Config,
    ) -> Option<Violation> {
        // Use the previous transaction passed by the linter (if any)
        let previous_tx = previous?;
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
}

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
        let store = StateStore::new(300);
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
        let previous = store.get_previous(&client, resource);
        let violation = rule.check_transaction(
            &tx,
            previous.as_ref(),
            &crate::test_helpers::make_test_rule_config(),
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
        let store = StateStore::new(300);
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

        let previous = store.get_previous(&client, resource);
        let violation = rule.check_transaction(
            &tx,
            previous.as_ref(),
            &crate::test_helpers::make_test_rule_config(),
        );

        assert!(violation.is_none());
        Ok(())
    }
}
