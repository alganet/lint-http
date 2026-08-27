// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Transaction lint dispatch.
//!
//! [`PreparedEngine`] precomputes the enabled rule set once per [`Config`]
//! (immutable after startup), then dispatches transactions and protocol events
//! against it — building each rule's required cross-transaction history lazily
//! from the [`StateStore`] and collecting the violations. It sits *above* the
//! rule catalogue and the query layer (it references both), so it lives in the
//! rules crate rather than with the [`Violation`](crate::lint::Violation) data
//! type in core.

use crate::config::Config;
use crate::lint::Violation;
use crate::rules::{ProtocolRule, Rule};

/// One enabled rule with everything the engine resolved about it at
/// construction: `query` is the [`crate::rules::STATEFUL_RULES`] lookup,
/// answered once here instead of hashing the rule id on every transaction,
/// and `resolved` is what the rule's own `prepare` made of its config.
/// Dispatch borrows `resolved` into a [`crate::rules::RuleContext`] per
/// transaction — no per-dispatch config reads.
struct PreparedRule {
    rule: &'static dyn Rule,
    query: Option<crate::queries::QueryType>,
    resolved: crate::rules::ResolvedRule,
}

/// One enabled protocol rule with its configuration resolved by its own
/// `prepare` at construction. Dispatch borrows `resolved` into a
/// [`crate::rules::RuleContext`] per event — no per-event config reads.
pub(crate) struct PreparedProtocolRule {
    pub(crate) rule: &'static dyn ProtocolRule,
    pub(crate) resolved: crate::rules::ResolvedRule,
}

/// The enabled rule set for one [`Config`], precomputed once so per-transaction
/// dispatch cost is proportional to the *enabled* rules rather than the full
/// catalogue. `is_enabled` is a pure function of the (immutable) config, so the
/// per-scope intersection is computed at construction instead of on every
/// transaction. Build once and reuse for the lifetime of the config.
pub struct PreparedEngine {
    /// Enabled rules for a full transaction (response collected).
    enabled_full: Vec<PreparedRule>,
    /// Enabled rules for a request-only transaction (Server-scoped excluded).
    enabled_request_only: Vec<PreparedRule>,
    /// Enabled protocol-event rules (consumed by `lint_protocol_event`).
    pub(crate) enabled_protocol: Vec<PreparedProtocolRule>,
}

impl PreparedEngine {
    /// Validate the config, then intersect the catalogue's precomputed scope
    /// views with `cfg.is_enabled`, once.
    ///
    /// **This is the only place `enabled` is read.** The flag is decided here,
    /// when the engine is built, and a rule that is not in one of these three
    /// vectors is never dispatched; each rule's per-transaction config read
    /// used to ask the same question again on every dispatch and discard the
    /// answer.
    ///
    /// Construction runs [`crate::rules::validate_rules`] itself, so an engine
    /// cannot exist over a config whose rule tables were never checked. This
    /// used to be a caller obligation that nothing enforced: a library caller
    /// that skipped it got rules silently filtered out (`is_enabled` reads a
    /// missing `enabled` as `false`) instead of the error naming the malformed
    /// table. A config that fails validation now fails here, before anything
    /// is dispatched.
    pub fn new(cfg: &Config) -> anyhow::Result<Self> {
        crate::rules::validate_rules(cfg)?;
        let prepare_enabled = |rules: &[&'static dyn Rule]| {
            rules
                .iter()
                .filter(|r| cfg.is_enabled(r.id()))
                .map(|&rule| {
                    Ok(PreparedRule {
                        rule,
                        query: crate::rules::query_type_for(rule.id()),
                        resolved: rule.prepare(cfg)?,
                    })
                })
                .collect::<anyhow::Result<_>>()
        };
        Ok(Self {
            enabled_full: prepare_enabled(&crate::rules::RULES)?,
            enabled_request_only: prepare_enabled(&crate::rules::REQUEST_ONLY_RULES)?,
            enabled_protocol: crate::rules::PROTOCOL_RULES
                .iter()
                .copied()
                .filter(|r| cfg.is_enabled(r.id()))
                .map(|rule| {
                    Ok(PreparedProtocolRule {
                        rule,
                        resolved: rule.prepare(cfg)?,
                    })
                })
                .collect::<anyhow::Result<_>>()?,
        })
    }

    /// Lint an entire `HttpTransaction` against the enabled rule set. No
    /// config parameter: everything config-derived was resolved when the
    /// engine was built.
    pub fn lint_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
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
        let mut history_by_connection: Option<crate::transaction_history::TransactionHistory> =
            None;
        // Rules that don't read history (the vast majority) are dispatched
        // against this shared empty history instead of an unused per-resource
        // query.
        let empty_history = crate::transaction_history::TransactionHistory::empty();

        // Cache origin extraction since it's used by any rule requiring ByOrigin
        let origin = crate::helpers::uri::extract_origin_if_absolute(&tx.request.uri);

        // Enabled rules only — disabled rules were filtered out at construction.
        // `Server` rules are excluded when the response isn't collected yet
        // (mirrors `crate::rules::rules_for_scope`, see `Rule::scope`).
        let scoped = if tx.response.is_some() {
            &self.enabled_full
        } else {
            &self.enabled_request_only
        };
        for prepared in scoped {
            let rule = prepared.rule;
            let history = match prepared.query {
                Some(crate::queries::QueryType::ByResource) => history_by_resource
                    .get_or_insert_with(|| {
                        crate::queries::by_resource::by_resource(state, &tx.client, &tx.request.uri)
                    }),
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

            let ctx = crate::rules::RuleContext::new(&prepared.resolved);
            out.extend(rule.findings(tx, history, &ctx));
        }

        out
    }
}

/// Lint an entire `HttpTransaction`. Convenience one-shot: builds a
/// [`PreparedEngine`] for `cfg` and dispatches once. Hot paths (the proxy
/// pipeline, the offline `lint` subcommand) build a `PreparedEngine` once and
/// reuse it; this wrapper is for tests and one-off callers.
///
/// # Panics
///
/// Panics when `cfg` fails rule validation. A one-shot caller has no startup
/// phase to surface the error in, and a rule table that is malformed must not
/// degrade into that rule silently not running — callers that need to handle
/// the error build a [`PreparedEngine`] themselves.
pub fn lint_transaction(
    tx: &crate::http_transaction::HttpTransaction,
    cfg: &Config,
    state: &crate::state::StateStore,
) -> Vec<Violation> {
    PreparedEngine::new(cfg)
        .expect("config failed rule validation")
        .lint_transaction(tx, state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::test_helpers::{disable_rule, make_test_config_with_enabled_rules};

    #[test]
    fn prepared_engine_keeps_only_enabled_rules() {
        // Enable two Server-scoped rules and one Client-scoped rule. The full
        // set keeps all three; the request-only set keeps just the Client rule —
        // exercising both the enabled filter and the Server-scope exclusion.
        let cfg = make_test_config_with_enabled_rules(&[
            "cache_control_present",         // Server
            "etag_or_last_modified_present", // Server
            "user_agent_present",            // Client (survives into request-only)
        ]);
        let engine = PreparedEngine::new(&cfg).unwrap();

        assert_eq!(engine.enabled_full.len(), 3);
        assert!(engine
            .enabled_full
            .iter()
            .all(|p| cfg.is_enabled(p.rule.id())));
        // Only the non-Server rule survives into the request-only set; the
        // assertion is non-vacuous because that set is non-empty here.
        assert_eq!(engine.enabled_request_only.len(), 1);
        assert!(engine
            .enabled_request_only
            .iter()
            .all(|p| !matches!(p.rule.scope(), crate::rules::RuleScope::Server)));

        // An empty config enables nothing.
        let empty = PreparedEngine::new(&Config::default()).unwrap();
        assert_eq!(empty.enabled_full.len(), 0);
        assert_eq!(empty.enabled_protocol.len(), 0);
    }

    /// Every registered rule, dispatched once — a response-bearing and a
    /// request-only transaction through the transaction rules, one event
    /// through the protocol rules. Keeps every rule's dispatch path exercised
    /// through the engine itself (not only through the per-rule tests'
    /// helper), so a rule whose `findings` panics on ordinary traffic fails
    /// here by name.
    #[test]
    fn every_registered_rule_dispatches_cleanly() -> anyhow::Result<()> {
        let toml_src = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../config_example.toml"),
        )?;
        let mut cfg: Config = toml::from_str(&toml_src)?;
        for val in cfg.rules.values_mut() {
            if let toml::Value::Table(table) = val {
                table.insert("enabled".to_string(), toml::Value::Boolean(true));
            }
        }
        let engine = PreparedEngine::new(&cfg)?;
        let state = crate::state::StateStore::new(300, 10);

        let with_response = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let _ = engine.lint_transaction(&with_response, &state);

        use crate::http_transaction::{HttpTransaction, TimingInfo};
        let mut request_only = HttpTransaction::new(
            crate::test_helpers::make_test_client(),
            "GET".to_string(),
            "http://example.com/".to_string(),
        );
        request_only.timing = TimingInfo { duration_ms: 5 };
        let _ = engine.lint_transaction(&request_only, &state);

        let event_store = crate::protocol_event_store::ProtocolEventStore::new(300, 100);
        let event = crate::protocol_event::ProtocolEvent {
            timestamp: chrono::Utc::now(),
            connection_id: uuid::Uuid::new_v4(),
            kind: crate::protocol_event::ProtocolEventKind::H3StreamOpened { stream_id: 0 },
        };
        let _ = engine.lint_protocol_event(&event, &event_store);
        Ok(())
    }

    #[test]
    fn construction_rejects_malformed_enabled_rule_config() {
        // An enabled rule whose table lacks `severity` used to be a lint-time
        // silence (a per-dispatch parse ending in `.ok()?`); construction now
        // refuses the config outright.
        let mut cfg = Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        cfg.rules.insert(
            "cache_control_present".to_string(),
            toml::Value::Table(table),
        );
        let err = PreparedEngine::new(&cfg)
            .err()
            .expect("construction must fail")
            .to_string();
        assert!(err.contains("severity"), "unexpected error: {err}");
    }

    #[test]
    fn construction_rejects_unknown_rule_name() {
        let cfg = make_test_config_with_enabled_rules(&["no_such_rule_zzz"]);
        let err = PreparedEngine::new(&cfg)
            .err()
            .expect("construction must fail")
            .to_string();
        assert!(err.contains("does not exist"), "unexpected error: {err}");
    }

    #[test]
    fn prepared_and_free_dispatch_agree() {
        let state = crate::state::StateStore::new(300, 10);
        let cfg =
            make_test_config_with_enabled_rules(&["cache_control_present", "user_agent_present"]);
        let tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);

        let via_free = lint_transaction(&tx, &cfg, &state);
        let via_prepared = PreparedEngine::new(&cfg)
            .unwrap()
            .lint_transaction(&tx, &state);

        let ids = |vs: &[Violation]| {
            let mut v: Vec<_> = vs.iter().map(|x| x.rule.clone()).collect();
            v.sort();
            v
        };
        assert_eq!(ids(&via_free), ids(&via_prepared));
    }

    #[test]
    fn lint_response_rules_emit_when_enabled() {
        let state = crate::state::StateStore::new(300, 10);
        let cfg = make_test_config_with_enabled_rules(&[
            "cache_control_present",
            "etag_or_last_modified_present",
        ]);
        let tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let v = lint_transaction(&tx, &cfg, &state);

        assert!(v.iter().any(|x| x.rule == "cache_control_present"));
        assert!(v.iter().any(|x| x.rule == "etag_or_last_modified_present"));
    }

    #[test]
    fn lint_request_rules_emit_when_enabled() {
        let state = crate::state::StateStore::new(300, 10);
        let cfg =
            make_test_config_with_enabled_rules(&["user_agent_present", "accept_encoding_present"]);
        use crate::http_transaction::{HttpTransaction, TimingInfo};
        let mut tx = HttpTransaction::new(
            crate::test_helpers::make_test_client(),
            "GET".to_string(),
            "http://example/".to_string(),
        );
        tx.timing = TimingInfo { duration_ms: 5 };

        let v = lint_transaction(&tx, &cfg, &state);

        assert!(v.iter().any(|x| x.rule == "user_agent_present"));
        assert!(v.iter().any(|x| x.rule == "accept_encoding_present"));
    }

    #[test]
    fn rule_toggles_disable_rules() {
        let state = crate::state::StateStore::new(300, 10);
        let cfg_enabled = make_test_config_with_enabled_rules(&[
            "cache_control_present",
            "etag_or_last_modified_present",
        ]);
        let tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let v = lint_transaction(&tx, &cfg_enabled, &state);
        assert!(v.iter().any(|x| x.rule == "cache_control_present"));
        assert!(v.iter().any(|x| x.rule == "etag_or_last_modified_present"));

        let mut cfg_disabled = Config::default();
        disable_rule(&mut cfg_disabled, "cache_control_present");
        disable_rule(&mut cfg_disabled, "etag_or_last_modified_present");
        let v2 = lint_transaction(&tx, &cfg_disabled, &state);
        assert!(!v2.iter().any(|x| x.rule == "cache_control_present"));
        assert!(!v2.iter().any(|x| x.rule == "etag_or_last_modified_present"));
    }

    #[test]
    fn lint_transaction_handles_both_client_and_server_rules() {
        let state = crate::state::StateStore::new(300, 10);
        let cfg =
            make_test_config_with_enabled_rules(&["user_agent_present", "cache_control_present"]);
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
            .filter(|v| v.rule == "user_agent_present")
            .collect();
        let server_violations: Vec<_> = violations
            .iter()
            .filter(|v| v.rule == "cache_control_present")
            .collect();

        assert!(!client_violations.is_empty() || !server_violations.is_empty());
    }

    #[test]
    fn lint_transaction_with_connection_id() {
        // Exercises the lazy ByOrigin and general flow with a transaction
        // that has connection_id set (used by ByConnection queries).
        let state = crate::state::StateStore::new(300, 10);
        let cfg = make_test_config_with_enabled_rules(&["cache_control_present"]);
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
        assert!(violations.iter().any(|v| v.rule == "cache_control_present"));
    }

    #[test]
    fn lint_transaction_exercises_by_origin_query() {
        // Enable a ByOrigin rule to exercise the lazy ByOrigin init path
        let state = crate::state::StateStore::new(300, 10);
        let cfg = make_test_config_with_enabled_rules(&["authentication_failure_loop"]);
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
        let cfg = make_test_config_with_enabled_rules(&["private_cache_visibility"]);
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
        let cfg = make_test_config_with_enabled_rules(&["authentication_failure_loop"]);
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
        let cfg =
            make_test_config_with_enabled_rules(&["cache_control_present", "user_agent_present"]);
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
            v.iter().any(|x| x.rule == "user_agent_present"),
            "client-scoped rule should still run on request-only tx",
        );
        assert!(
            !v.iter().any(|x| x.rule == "cache_control_present"),
            "server-scoped rule must not emit on request-only tx",
        );
    }

    #[test]
    fn lint_transaction_with_no_origin() {
        // Transaction with a relative/invalid URI to exercise the ByOrigin None path
        let state = crate::state::StateStore::new(300, 10);
        let cfg = make_test_config_with_enabled_rules(&["cache_control_present"]);
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
