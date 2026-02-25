// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct SemanticPostCreatesResource;

impl Rule for SemanticPostCreatesResource {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "semantic_post_creates_resource"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        config: &Self::Config,
    ) -> Option<Violation> {
        // only consider POST requests with a response
        if !tx.request.method.eq_ignore_ascii_case("POST") {
            return None;
        }
        let resp = match &tx.response {
            Some(r) => r,
            None => return None,
        };

        let status = resp.status;
        // only worry about successful (2xx) responses; other statuses have independent semantics
        if !(200..300).contains(&status) {
            return None;
        }

        let has_location = resp.headers.contains_key("location");

        if status == 201 && !has_location {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "201 Created response to POST should include a Location header (RFC 9110 §9.3.3)".into(),
            });
        }

        if status != 201 && has_location {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!(
                    "POST response with status {} includes a Location header; use 201 Created when a new resource is created (RFC 9110 §9.3.3)",
                    status
                ),
            });
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tx(
        status: u16,
        headers: Vec<(&str, &str)>,
    ) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(status, &[]);
        tx.request.method = "POST".to_string();
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&headers);
        tx
    }

    #[test]
    fn id_and_scope() {
        let r = SemanticPostCreatesResource;
        assert_eq!(r.id(), "semantic_post_creates_resource");
        assert_eq!(r.scope(), crate::rules::RuleScope::Server);
    }

    #[rstest::rstest]
    #[case(201, vec![], true)]
    #[case(201, vec![("location", "/new")] , false)]
    #[case(200, vec![("location", "/new")], true)]
    #[case(204, vec![("location", "/new")], true)]
    #[case(200, vec![], false)]
    #[case(204, vec![], false)]
    fn post_creation_cases(
        #[case] status: u16,
        #[case] headers: Vec<(&str, &str)>,
        #[case] expect_violation: bool,
    ) {
        let rule = SemanticPostCreatesResource;
        let tx = make_tx(status, headers);
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(v.is_some(), "expected violation for status {}", status);
        } else {
            assert!(
                v.is_none(),
                "unexpected violation for status {}: {:?}",
                status,
                v
            );
        }
    }

    #[test]
    fn location_header_case_insensitive() {
        let rule = SemanticPostCreatesResource;
        let tx = make_tx(200, vec![("Location", "/new")]);
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn non_utf8_header_value_counts_as_presence() {
        let rule = SemanticPostCreatesResource;
        let mut tx = make_tx(200, vec![]);
        // insert a non-utf8 value for Location
        let mut hm = hyper::HeaderMap::new();
        hm.insert(
            "location",
            hyper::header::HeaderValue::from_bytes(&[0xff]).unwrap(),
        );
        tx.response.as_mut().unwrap().headers = hm;
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(
            v.is_some(),
            "non-UTF8 header value should still count as presence"
        );
    }

    #[test]
    fn multiple_location_headers_treated_as_presence() {
        let rule = SemanticPostCreatesResource;
        // create headers with two Location lines; header-map will collapse but still
        // presence is what matters
        let tx = make_tx(200, vec![("location", "/a"), ("location", "/b")]);
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(
            v.is_some(),
            "multiple Location headers should still trigger violation"
        );
    }

    #[test]
    fn non_post_requests_are_ignored() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(201, &[]);
        tx.request.method = "PUT".to_string();
        let rule = SemanticPostCreatesResource;
        let cfg = crate::test_helpers::make_test_rule_config();
        assert!(rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg
            )
            .is_none());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "semantic_post_creates_resource");
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
