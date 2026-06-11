// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Transaction lint dispatch.
//!
//! `lint_transaction` iterates the rule catalogue, building each rule's
//! required cross-transaction history lazily from the [`StateStore`], and
//! collects the violations. It sits *above* the rule catalogue and the query
//! layer (it references both), so it lives in the rules crate rather than with
//! the [`Violation`](crate::lint::Violation) data type in core.

use crate::config::Config;
use crate::lint::Violation;

/// Lint an entire `HttpTransaction`.
pub fn lint_transaction(
    tx: &crate::http_transaction::HttpTransaction,
    cfg: &Config,
    state: &crate::state::StateStore,
) -> Vec<Violation> {
    let mut out = Vec::new();

    let mut history_by_resource: Option<crate::transaction_history::TransactionHistory> = None;
    let mut history_by_origin: Option<crate::transaction_history::TransactionHistory> = None;
    // separate cache for ByResourceAll queries to avoid mixing with
    // per-client histories.  If a ByResource rule runs first its history was
    // already computed and stored in `history_by_resource`; using that same
    // value for ByResourceAll would omit other clients' entries.
    let mut history_by_resource_all_clients: Option<
        crate::transaction_history::TransactionHistory,
    > = None;
    let mut history_by_connection: Option<crate::transaction_history::TransactionHistory> = None;
    // Rules that don't read history (the vast majority) are dispatched against
    // this shared empty history instead of an unused per-resource query.
    let empty_history = crate::transaction_history::TransactionHistory::empty();

    // Cache origin extraction since it's used by any rule requiring ByOrigin
    let origin = crate::helpers::uri::extract_origin_if_absolute(&tx.request.uri);

    // Dispatch only the rules whose scope matches the transaction shape:
    // `Server` rules are skipped when the response has not been collected yet.
    // See `Rule::scope` for the contract.
    for rule in crate::rules::rules_for_scope(tx.response.is_some()) {
        if !cfg.is_enabled(rule.id()) {
            continue;
        }
        let history = match crate::rules::query_type_for(rule.id()) {
            Some(crate::queries::QueryType::ByResource) => {
                history_by_resource.get_or_insert_with(|| {
                    crate::queries::by_resource::by_resource(state, &tx.client, &tx.request.uri)
                })
            }
            Some(crate::queries::QueryType::ByOrigin) => {
                history_by_origin.get_or_insert_with(|| {
                    if let Some(o) = &origin {
                        crate::queries::by_origin::by_origin(state, &tx.client, o)
                    } else {
                        crate::transaction_history::TransactionHistory::empty()
                    }
                })
            }
            Some(crate::queries::QueryType::ByResourceAll) => history_by_resource_all_clients
                .get_or_insert_with(|| {
                    crate::queries::by_resource_all_clients::by_resource_all_clients(
                        state,
                        &tx.request.uri,
                    )
                }),
            Some(crate::queries::QueryType::ByConnection) => history_by_connection
                .get_or_insert_with(|| {
                    if let Some(conn_id) = tx.connection_id {
                        crate::queries::by_connection::by_connection(state, conn_id)
                    } else {
                        crate::transaction_history::TransactionHistory::empty()
                    }
                }),
            // Rule reads no history.
            None => &empty_history,
        };

        out.extend(rule.check_transaction(tx, history, cfg));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::test_helpers::{disable_rule, make_test_config_with_enabled_rules};

    #[test]
    fn lint_response_rules_emit_when_enabled() {
        let state = crate::state::StateStore::new(300, 10);
        let cfg = make_test_config_with_enabled_rules(&[
            "server_cache_control_present",
            "server_etag_or_last_modified",
        ]);
        let tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let v = lint_transaction(&tx, &cfg, &state);

        assert!(v.iter().any(|x| x.rule == "server_cache_control_present"));
        assert!(v.iter().any(|x| x.rule == "server_etag_or_last_modified"));
    }

    #[test]
    fn lint_request_rules_emit_when_enabled() {
        let state = crate::state::StateStore::new(300, 10);
        let cfg = make_test_config_with_enabled_rules(&[
            "client_user_agent_present",
            "client_accept_encoding_present",
        ]);
        use crate::http_transaction::{HttpTransaction, TimingInfo};
        let mut tx = HttpTransaction::new(
            crate::test_helpers::make_test_client(),
            "GET".to_string(),
            "http://example/".to_string(),
        );
        tx.timing = TimingInfo { duration_ms: 5 };

        let v = lint_transaction(&tx, &cfg, &state);

        assert!(v.iter().any(|x| x.rule == "client_user_agent_present"));
        assert!(v.iter().any(|x| x.rule == "client_accept_encoding_present"));
    }

    #[test]
    fn rule_toggles_disable_rules() {
        let state = crate::state::StateStore::new(300, 10);
        let cfg_enabled = make_test_config_with_enabled_rules(&[
            "server_cache_control_present",
            "server_etag_or_last_modified",
        ]);
        let tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let v = lint_transaction(&tx, &cfg_enabled, &state);
        assert!(v.iter().any(|x| x.rule == "server_cache_control_present"));
        assert!(v.iter().any(|x| x.rule == "server_etag_or_last_modified"));

        let mut cfg_disabled = Config::default();
        disable_rule(&mut cfg_disabled, "server_cache_control_present");
        disable_rule(&mut cfg_disabled, "server_etag_or_last_modified");
        let v2 = lint_transaction(&tx, &cfg_disabled, &state);
        assert!(!v2.iter().any(|x| x.rule == "server_cache_control_present"));
        assert!(!v2.iter().any(|x| x.rule == "server_etag_or_last_modified"));
    }

    #[test]
    fn lint_transaction_handles_both_client_and_server_rules() {
        let state = crate::state::StateStore::new(300, 10);
        let cfg = make_test_config_with_enabled_rules(&[
            "client_user_agent_present",
            "server_cache_control_present",
        ]);
        use crate::http_transaction::{HttpTransaction, ResponseInfo, TimingInfo};
        let mut tx = HttpTransaction::new(
            crate::test_helpers::make_test_client(),
            "GET".to_string(),
            "http://example/".to_string(),
        );
        tx.timing = TimingInfo { duration_ms: 5 };
        tx.response = Some(ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hyper::HeaderMap::new(),
            body_length: None,
            trailers: None,
        });

        let violations = lint_transaction(&tx, &cfg, &state);

        assert!(!violations.is_empty());

        let client_violations: Vec<_> = violations
            .iter()
            .filter(|v| v.rule == "client_user_agent_present")
            .collect();
        let server_violations: Vec<_> = violations
            .iter()
            .filter(|v| v.rule == "server_cache_control_present")
            .collect();

        assert!(!client_violations.is_empty() || !server_violations.is_empty());
    }

    #[test]
    fn lint_transaction_with_connection_id() {
        // Exercises the lazy ByOrigin and general flow with a transaction
        // that has connection_id set (used by ByConnection queries).
        let state = crate::state::StateStore::new(300, 10);
        let cfg = make_test_config_with_enabled_rules(&["server_cache_control_present"]);
        use crate::http_transaction::{HttpTransaction, ResponseInfo, TimingInfo};
        let mut tx = HttpTransaction::new(
            crate::test_helpers::make_test_client(),
            "GET".to_string(),
            "http://example.com/path".to_string(),
        );
        tx.connection_id = Some(uuid::Uuid::new_v4());
        tx.sequence_number = Some(1);
        tx.timing = TimingInfo { duration_ms: 5 };
        tx.response = Some(ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hyper::HeaderMap::new(),
            body_length: None,
            trailers: None,
        });

        let violations = lint_transaction(&tx, &cfg, &state);
        assert!(violations
            .iter()
            .any(|v| v.rule == "server_cache_control_present"));
    }

    #[test]
    fn lint_transaction_exercises_by_origin_query() {
        // Enable a ByOrigin rule to exercise the lazy ByOrigin init path
        let state = crate::state::StateStore::new(300, 10);
        let cfg = make_test_config_with_enabled_rules(&["stateful_authentication_failure_loop"]);
        use crate::http_transaction::{HttpTransaction, ResponseInfo, TimingInfo};
        let mut tx = HttpTransaction::new(
            crate::test_helpers::make_test_client(),
            "GET".to_string(),
            "http://example.com/auth".to_string(),
        );
        tx.timing = TimingInfo { duration_ms: 5 };
        tx.response = Some(ResponseInfo {
            status: 401,
            version: "HTTP/1.1".into(),
            headers: hyper::HeaderMap::new(),
            body_length: None,
            trailers: None,
        });
        // Should not panic; exercises the ByOrigin lazy init
        let _violations = lint_transaction(&tx, &cfg, &state);
    }

    #[test]
    fn lint_transaction_exercises_by_resource_all_query() {
        // Enable a ByResourceAll rule to exercise the lazy ByResourceAll init path
        let state = crate::state::StateStore::new(300, 10);
        let cfg = make_test_config_with_enabled_rules(&["stateful_private_cache_visibility"]);
        use crate::http_transaction::{HttpTransaction, ResponseInfo, TimingInfo};
        let mut tx = HttpTransaction::new(
            crate::test_helpers::make_test_client(),
            "GET".to_string(),
            "http://example.com/private".to_string(),
        );
        tx.timing = TimingInfo { duration_ms: 5 };
        tx.response = Some(ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hyper::HeaderMap::new(),
            body_length: None,
            trailers: None,
        });
        // Should not panic; exercises the ByResourceAll lazy init
        let _violations = lint_transaction(&tx, &cfg, &state);
    }

    #[test]
    fn lint_transaction_by_origin_with_no_origin() {
        // Enable a ByOrigin rule with a relative URI to exercise the None path
        let state = crate::state::StateStore::new(300, 10);
        let cfg = make_test_config_with_enabled_rules(&["stateful_authentication_failure_loop"]);
        use crate::http_transaction::{HttpTransaction, ResponseInfo, TimingInfo};
        let mut tx = HttpTransaction::new(
            crate::test_helpers::make_test_client(),
            "GET".to_string(),
            "/no-origin-path".to_string(),
        );
        tx.timing = TimingInfo { duration_ms: 5 };
        tx.response = Some(ResponseInfo {
            status: 401,
            version: "HTTP/1.1".into(),
            headers: hyper::HeaderMap::new(),
            body_length: None,
            trailers: None,
        });
        // Should use empty history for the ByOrigin None case
        let _violations = lint_transaction(&tx, &cfg, &state);
    }

    #[test]
    fn server_scoped_rules_skipped_on_request_only_transaction() {
        // Smoke test: confirms `lint_transaction` runs cleanly on a
        // request-only transaction and that Server-scoped rules don't appear
        // in the violation list. The actual dispatch-routing invariant
        // (Server rules excluded from the iterated slice) is asserted by
        // `rules::tests::rules_for_scope_skips_server_when_no_response` —
        // this test would also pass by accident if a Server rule self-guarded
        // on `tx.response.is_none()`, so it carries no load alone.
        let state = crate::state::StateStore::new(300, 10);
        let cfg = make_test_config_with_enabled_rules(&[
            "server_cache_control_present",
            "client_user_agent_present",
        ]);
        use crate::http_transaction::{HttpTransaction, TimingInfo};
        let mut tx = HttpTransaction::new(
            crate::test_helpers::make_test_client(),
            "GET".to_string(),
            "http://example/".to_string(),
        );
        tx.timing = TimingInfo { duration_ms: 5 };
        // No tx.response set — this is the request-only path.

        let v = lint_transaction(&tx, &cfg, &state);

        assert!(
            v.iter().any(|x| x.rule == "client_user_agent_present"),
            "client-scoped rule should still run on request-only tx",
        );
        assert!(
            !v.iter().any(|x| x.rule == "server_cache_control_present"),
            "server-scoped rule must not emit on request-only tx",
        );
    }

    #[test]
    fn lint_transaction_with_no_origin() {
        // Transaction with a relative/invalid URI to exercise the ByOrigin None path
        let state = crate::state::StateStore::new(300, 10);
        let cfg = make_test_config_with_enabled_rules(&["server_cache_control_present"]);
        use crate::http_transaction::{HttpTransaction, ResponseInfo, TimingInfo};
        let mut tx = HttpTransaction::new(
            crate::test_helpers::make_test_client(),
            "GET".to_string(),
            "/relative-path".to_string(),
        );
        tx.timing = TimingInfo { duration_ms: 5 };
        tx.response = Some(ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hyper::HeaderMap::new(),
            body_length: None,
            trailers: None,
        });

        let violations = lint_transaction(&tx, &cfg, &state);
        // Should still run rules even with relative URI
        assert!(!violations.is_empty());
    }
}
