// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::queries::QueryType;
use linkme::distributed_slice;
use std::sync::LazyLock;

/// Standard configuration for rules
/// Used as the Config type for non-configurable rules.
#[derive(Debug, Clone)]
pub struct RuleConfig {
    pub enabled: bool,
    pub severity: crate::lint::Severity,
}

/// Parse severity from config for a given rule.
/// Returns RuleConfig with parsed severity. Fails if severity is not explicitly configured.
pub fn parse_rule_config(cfg: &crate::config::Config, rule_id: &str) -> anyhow::Result<RuleConfig> {
    let severity = get_rule_severity_required(cfg, rule_id)?;
    let enabled = get_rule_enabled_required(cfg, rule_id)?;
    Ok(RuleConfig { enabled, severity })
}

/// The `Rule` trait defines a single hook that runs on the canonical
/// `HttpTransaction`. All rules must implement `check_transaction`.
/// Scope of a rule: whether it applies to client-only traffic (requests),
/// server-only traffic (responses), or both (full transactions).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RuleScope {
    Client,
    Server,
    Both,
}

/// Whether an [`Example`] illustrates traffic the rule accepts or rejects.
/// Maps to the ✅ Good / ❌ Bad sections of `docs/rules/TEMPLATE.md`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Compliance {
    /// Traffic the rule accepts (a "✅ Good" docs example).
    Compliant,
    /// Traffic the rule flags (a "❌ Bad" docs example).
    NonCompliant,
}

/// A documentation example for a rule: a snippet of HTTP traffic tagged with
/// whether the rule accepts or rejects it. Consumed by the docs generator
/// (#11b) and `rules list` (#18c). Intrinsic to the rule, so it lives in the
/// rule crate alongside the trait rather than in downstream tooling.
#[derive(Copy, Clone, Debug)]
pub struct Example {
    pub compliance: Compliance,
    pub snippet: &'static str,
}

pub trait Rule: Send + Sync {
    fn id(&self) -> &'static str;

    /// Validate the rule's configuration section. Called once per enabled
    /// rule at startup so a malformed config fails fast rather than silently
    /// disabling the rule at lint time.
    ///
    /// The default checks the base `enabled` / `severity` fields. Rules with
    /// a custom config section override this to validate their own fields.
    fn validate(&self, cfg: &crate::config::Config) -> anyhow::Result<()> {
        parse_rule_config(cfg, self.id()).map(|_| ())
    }

    /// The scope where the rule should be executed. Default is `Both`;
    /// rules may override for better precision.
    ///
    /// The engine partitions rules by scope and dispatches accordingly:
    /// - `Client` and `Both` rules run on every transaction.
    /// - `Server` rules run only when `tx.response.is_some()`.
    ///
    /// A rule that returns `Server` may therefore assume the response is
    /// present, but existing implementations still defensively check —
    /// tightening those is left as follow-up cleanup.
    fn scope(&self) -> RuleScope {
        RuleScope::Both
    }

    /// Evaluate an `HttpTransaction` against this rule. Rules parse whatever
    /// configuration they need directly from the global `cfg: &Config`.
    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation>;

    /// Human-readable summary of what this rule checks and why it matters.
    /// Renders as the "Description" section of the generated per-rule doc.
    /// Empty by default; #11c fills these in from the existing docs/rules/ files.
    fn description(&self) -> &'static str {
        ""
    }

    /// Canonical specification reference (e.g. "RFC 9110 §5.2"), if any.
    /// Renders into the "Specifications" section of the generated doc.
    fn rfc_reference(&self) -> Option<&'static str> {
        None
    }

    /// Compliant / non-compliant traffic examples for the generated doc's
    /// "Examples" section. Empty by default.
    fn examples(&self) -> &'static [Example] {
        &[]
    }
}

/// Get rule enabled flag, failing if not explicitly configured.
/// All rules must have an explicit enabled field.
pub fn get_rule_enabled_required(cfg: &crate::config::Config, rule: &str) -> anyhow::Result<bool> {
    let Some(rule_cfg) = cfg.get_rule_config(rule) else {
        return Err(anyhow::anyhow!(
            "Rule '{}' missing configuration. Add:\n[rules.{}]\nenabled = true\nseverity = \"warn\"",
            rule, rule
        ));
    };
    let Some(table) = rule_cfg.as_table() else {
        return Err(anyhow::anyhow!(
            "Rule '{}' configuration must be a table",
            rule
        ));
    };
    let Some(enabled) = table.get("enabled").and_then(|v| v.as_bool()) else {
        return Err(anyhow::anyhow!(
            "Rule '{}' missing required 'enabled' field. Must be true or false",
            rule
        ));
    };
    Ok(enabled)
}

/// Lookup the configured severity for a rule at runtime,
/// Get rule severity, failing if not explicitly configured.
/// All enabled rules must have an explicit severity field.
pub fn get_rule_severity_required(
    cfg: &crate::config::Config,
    rule: &str,
) -> anyhow::Result<crate::lint::Severity> {
    let Some(rule_cfg) = cfg.get_rule_config(rule) else {
        return Err(anyhow::anyhow!(
            "Rule '{}' is enabled but missing configuration. Add:\n[rules.{}]\nenabled = true\nseverity = \"warn\"",
            rule, rule
        ));
    };
    let Some(table) = rule_cfg.as_table() else {
        return Err(anyhow::anyhow!(
            "Rule '{}' configuration must be a table",
            rule
        ));
    };
    let Some(s) = table.get("severity").and_then(|v| v.as_str()) else {
        return Err(anyhow::anyhow!(
            "Rule '{}' missing required 'severity' field. Must be one of: info, warn, error",
            rule
        ));
    };
    match s {
        "info" => Ok(crate::lint::Severity::Info),
        "warn" => Ok(crate::lint::Severity::Warn),
        "error" => Ok(crate::lint::Severity::Error),
        _ => Err(anyhow::anyhow!(
            "Rule '{}' has invalid severity '{}'. Must be one of: info, warn, error",
            rule,
            s
        )),
    }
}

pub fn validate_rules(config: &crate::config::Config) -> anyhow::Result<()> {
    // Ensure every rule table specifies valid `enabled` and `severity` entries.
    for (rule_name, val) in &config.rules {
        if let toml::Value::Table(table) = val {
            // Validate `enabled` field - must be present and be a boolean
            match table.get("enabled") {
                Some(toml::Value::Boolean(_)) => {}
                Some(_) => {
                    return Err(anyhow::anyhow!(
                        "Invalid 'enabled' for rule '{}': must be a boolean (true or false)",
                        rule_name
                    ));
                }
                None => {
                    return Err(anyhow::anyhow!(
                        "Missing required 'enabled' key for rule '{}'",
                        rule_name
                    ));
                }
            }

            // Validate `severity` field - must be present and be a valid string
            match table.get("severity") {
                Some(toml::Value::String(s)) => match s.as_str() {
                    "info" | "warn" | "error" => {}
                    _ => {
                        return Err(anyhow::anyhow!(
                                "Invalid severity '{}' for rule '{}': must be one of 'info', 'warn', 'error'",
                                s,
                                rule_name
                            ));
                    }
                },
                Some(_) => {
                    return Err(anyhow::anyhow!(
                        "Invalid severity for rule '{}': must be a string 'info', 'warn', or 'error'",
                        rule_name
                    ));
                }
                None => {
                    return Err(anyhow::anyhow!(
                        "Missing required 'severity' key for rule '{}'",
                        rule_name
                    ));
                }
            }
        }
    }

    // Per-rule validation: every enabled rule parses its own config section so
    // a malformed section (including custom fields) fails fast at startup.
    for rule in RULES.iter() {
        if config.is_enabled(rule.id()) {
            rule.validate(config).map_err(|e| {
                anyhow::anyhow!("Invalid configuration for rule '{}': {}", rule.id(), e)
            })?;
        }
    }
    for rule in PROTOCOL_RULES.iter() {
        if config.is_enabled(rule.id()) {
            rule.validate(config).map_err(|e| {
                anyhow::anyhow!("Invalid configuration for rule '{}': {}", rule.id(), e)
            })?;
        }
    }
    Ok(())
}

// Leaf rule modules are declared by `build.rs` (see `rule_modules.rs`),
// discovered from the `src/rules/*.rs` directory listing. Each module
// self-registers into the distributed slices below, so adding a rule is
// just creating one file here.
include!(concat!(env!("OUT_DIR"), "/rule_modules.rs"));

// ── Protocol-level rule trait ──────────────────────────────────────────
//
// `ProtocolRule` mirrors `Rule` but operates on `ProtocolEvent` instead of
// `HttpTransaction`.  It lives in the same module to share `RuleConfig`,
// severity helpers, and the config TOML infrastructure.

/// A rule that evaluates protocol-level events (WebSocket frames, HTTP/3
/// control frames, QUIC transport events) rather than HTTP transactions.
pub trait ProtocolRule: Send + Sync {
    fn id(&self) -> &'static str;

    /// Validate the rule's configuration section at startup. See
    /// [`Rule::validate`] for the contract.
    fn validate(&self, cfg: &crate::config::Config) -> anyhow::Result<()> {
        parse_rule_config(cfg, self.id()).map(|_| ())
    }

    /// Evaluate a single protocol event against this rule. Rules parse
    /// whatever configuration they need directly from `cfg: &Config`.
    fn check_event(
        &self,
        event: &crate::protocol_event::ProtocolEvent,
        history: &crate::protocol_event::ProtocolEventHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation>;

    /// Human-readable summary of what this rule checks and why it matters.
    /// Renders as the "Description" section of the generated per-rule doc.
    /// Empty by default; #11c fills these in from the existing docs/rules/ files.
    fn description(&self) -> &'static str {
        ""
    }

    /// Canonical specification reference (e.g. "RFC 9000 §18.2"), if any.
    /// Renders into the "Specifications" section of the generated doc.
    fn rfc_reference(&self) -> Option<&'static str> {
        None
    }

    /// Compliant / non-compliant traffic examples for the generated doc's
    /// "Examples" section. Empty by default.
    fn examples(&self) -> &'static [Example] {
        &[]
    }
}

/// Every transaction rule, self-registered at link time via
/// `linkme::distributed_slice`. Each rule module appends itself here (see the
/// `REGISTRATION` static at the bottom of each `src/rules/*.rs`), so adding a
/// rule requires no edit to a central list. The link order is unspecified;
/// [`RULES`] sorts a copy by id for deterministic dispatch.
#[distributed_slice]
pub static REGISTERED_RULES: [&'static dyn Rule] = [..];

/// Every protocol-event rule, self-registered at link time. See
/// [`REGISTERED_RULES`]; [`PROTOCOL_RULES`] is the sorted view used by dispatch.
#[distributed_slice]
pub static REGISTERED_PROTOCOL_RULES: [&'static dyn ProtocolRule] = [..];

/// All protocol-event rules, collected from the per-file
/// `#[distributed_slice]` registrations and sorted by id for a
/// deterministic dispatch order independent of link order.
pub static PROTOCOL_RULES: LazyLock<Vec<&'static dyn ProtocolRule>> = LazyLock::new(|| {
    let mut v: Vec<&'static dyn ProtocolRule> = REGISTERED_PROTOCOL_RULES.iter().copied().collect();
    v.sort_by_key(|r| r.id());
    v
});

/// All transaction rules, collected from the per-file `#[distributed_slice]`
/// registrations (see `REGISTERED_RULES`) and sorted by id for a
/// deterministic dispatch order independent of link order.
pub static RULES: LazyLock<Vec<&'static dyn Rule>> = LazyLock::new(|| {
    let mut v: Vec<&'static dyn Rule> = REGISTERED_RULES.iter().copied().collect();
    v.sort_by_key(|r| r.id());
    v
});

/// Rules that read cross-transaction history, each paired with the state query
/// that builds the history it needs.
///
/// A rule **absent** from this list is dispatched with an empty history (see
/// `lint::lint_transaction`). That is deliberate: it means a history-consuming
/// rule that is forgotten here receives empty history and fails its own
/// history-exercising tests *loudly*, rather than silently receiving a
/// plausible-but-wrong `ByResource` history. There is no silent default.
///
/// This registry is kept separate from `RULES` (and off the `Rule` trait) so
/// the rule library's public surface stays free of the engine's query layer —
/// see the module-level note on `QueryType`.
pub static STATEFUL_RULES: &[(&dyn Rule, QueryType)] = &[
    // ── ByOrigin: history spans an entire origin (all resources) ──
    (
        &stateful_authentication_failure_loop::StatefulAuthenticationFailureLoop,
        QueryType::ByOrigin,
    ),
    (
        &stateful_digest_auth_nonce_handling::StatefulDigestAuthNonceHandling,
        QueryType::ByOrigin,
    ),
    (
        &stateful_cookie_lifecycle::StatefulCookieLifecycle,
        QueryType::ByOrigin,
    ),
    (
        &stateful_cookie_same_site_enforcement::StatefulCookieSameSiteEnforcement,
        QueryType::ByOrigin,
    ),
    // ── ByResourceAll: history for a resource across all clients ──
    (
        &stateful_private_cache_visibility::StatefulPrivateCacheVisibility,
        QueryType::ByResourceAll,
    ),
    // ── ByConnection: history for a single TCP connection ──
    (
        &stateful_101_switching_protocols::Stateful101SwitchingProtocols,
        QueryType::ByConnection,
    ),
    // ── ByResource: per-client history for one resource (the common case) ──
    (
        &client_accept_ranges_on_partial_content::ClientAcceptRangesOnPartialContent,
        QueryType::ByResource,
    ),
    (
        &client_cache_respect::ClientCacheRespect,
        QueryType::ByResource,
    ),
    (
        &client_patch_method_content_type_match::ClientPatchMethodContentTypeMatch,
        QueryType::ByResource,
    ),
    (
        &semantic_cache_coherence::SemanticCacheCoherence,
        QueryType::ByResource,
    ),
    (
        &semantic_head_response_headers_match_get::SemanticHeadResponseHeadersMatchGet,
        QueryType::ByResource,
    ),
    (
        &stateful_cookie_domain_matching::StatefulCookieDomainMatching,
        QueryType::ByResource,
    ),
    (
        &stateful_103_early_hints_before_final::Stateful103EarlyHintsBeforeFinal,
        QueryType::ByResource,
    ),
    (
        &stateful_cache_validation_chain::StatefulCacheValidationChain,
        QueryType::ByResource,
    ),
    (
        &stateful_conditional_request_handling::StatefulConditionalRequestHandling,
        QueryType::ByResource,
    ),
    (
        &stateful_immutable_cache_never_stale::StatefulImmutableCacheNeverStale,
        QueryType::ByResource,
    ),
    (
        &stateful_max_age_directive_validity::StatefulMaxAgeDirectiveValidity,
        QueryType::ByResource,
    ),
    (
        &stateful_must_revalidate_enforcement::StatefulMustRevalidateEnforcement,
        QueryType::ByResource,
    ),
    (
        &stateful_no_cache_revalidation::StatefulNoCacheRevalidation,
        QueryType::ByResource,
    ),
    (
        &stateful_no_store_enforcement::StatefulNoStoreEnforcement,
        QueryType::ByResource,
    ),
    (
        &stateful_oauth2_code_flow::StatefulOauth2CodeFlow,
        QueryType::ByResource,
    ),
    (
        &stateful_range_request_and_caching::StatefulRangeRequestAndCaching,
        QueryType::ByResource,
    ),
    (
        &stateful_redirect_chain_validity::StatefulRedirectChainValidity,
        QueryType::ByResource,
    ),
    (
        &stateful_s_max_age_enforcement::StatefulSMaxAgeEnforcement,
        QueryType::ByResource,
    ),
    (
        &stateful_vary_header_cache_validity::StatefulVaryHeaderCacheValidity,
        QueryType::ByResource,
    ),
];

/// Lookup map from rule id to its required `QueryType`, built once from
/// [`STATEFUL_RULES`].
static STATEFUL_QUERY_TYPES: LazyLock<std::collections::HashMap<&'static str, QueryType>> =
    LazyLock::new(|| STATEFUL_RULES.iter().map(|(r, q)| (r.id(), *q)).collect());

/// The state query a rule needs to build its history, or `None` if the rule
/// does not read history (the engine then dispatches it with an empty
/// history). Replaces the former `queries::mapping` table and its silent
/// `ByResource` default.
pub fn query_type_for(rule_id: &str) -> Option<QueryType> {
    STATEFUL_QUERY_TYPES.get(rule_id).copied()
}

/// `RULES` filtered to those whose scope allows execution on a request-only
/// transaction (`Client` and `Both`). Built once on first access and preserves
/// the (id-sorted) order of `RULES`, so dispatch order is stable across the
/// has-response / no-response cases.
///
/// Implementation detail of [`rules_for_scope`]; not part of the public API.
pub(crate) static REQUEST_ONLY_RULES: LazyLock<Vec<&'static dyn Rule>> = LazyLock::new(|| {
    RULES
        .iter()
        .copied()
        .filter(|r| !matches!(r.scope(), RuleScope::Server))
        .collect()
});

/// Returns the rule slice the engine should iterate for a transaction with
/// the given response presence. `Server` rules are excluded when there is no
/// response; `Client` and `Both` rules run on every transaction. The returned
/// slice preserves the (id-sorted) order of `RULES`.
pub fn rules_for_scope(has_response: bool) -> &'static [&'static dyn Rule] {
    if has_response {
        RULES.as_slice()
    } else {
        &REQUEST_ONLY_RULES
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{enable_rule, enable_rule_with_paths};

    #[test]
    fn linkme_collects_full_catalogue() {
        // Every rule self-registers via `distributed_slice`; a linkme/linker
        // failure on this platform would silently drop registrations, which
        // this test turns into a hard failure.
        assert!(
            !REGISTERED_RULES.is_empty(),
            "no transaction rules were collected by linkme",
        );
        assert!(
            !REGISTERED_PROTOCOL_RULES.is_empty(),
            "no protocol rules were collected by linkme",
        );
        // The sorted views must contain exactly what was registered.
        assert_eq!(RULES.len(), REGISTERED_RULES.len());
        assert_eq!(PROTOCOL_RULES.len(), REGISTERED_PROTOCOL_RULES.len());
        assert!(RULES.iter().any(|r| r.id() == "client_host_header"));
        assert!(PROTOCOL_RULES
            .iter()
            .any(|r| r.id() == "server_quic_transport_parameters"));
    }

    #[test]
    fn rules_and_protocol_rules_sorted_by_id() {
        // Dispatch order must be deterministic regardless of link order.
        let ids: Vec<&str> = RULES.iter().map(|r| r.id()).collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        assert_eq!(ids, sorted, "RULES must be sorted by id");

        let pids: Vec<&str> = PROTOCOL_RULES.iter().map(|r| r.id()).collect();
        let mut psorted = pids.clone();
        psorted.sort_unstable();
        assert_eq!(pids, psorted, "PROTOCOL_RULES must be sorted by id");
    }

    #[test]
    fn metadata_accessors_dispatch_with_empty_defaults() {
        // #11a only adds the metadata surface; no rule overrides it yet, so
        // every collected rule must report the empty defaults. This proves the
        // three accessors exist and dispatch through `&dyn Rule` /
        // `&dyn ProtocolRule`. #11c will fill in real content per rule.
        for r in RULES.iter() {
            assert_eq!(r.description(), "", "{} description default", r.id());
            assert_eq!(r.rfc_reference(), None, "{} rfc default", r.id());
            assert!(r.examples().is_empty(), "{} examples default", r.id());
        }
        for r in PROTOCOL_RULES.iter() {
            assert_eq!(r.description(), "", "{} description default", r.id());
            assert_eq!(r.rfc_reference(), None, "{} rfc default", r.id());
            assert!(r.examples().is_empty(), "{} examples default", r.id());
        }
    }

    #[test]
    fn every_rule_file_is_registered() {
        // Deleting the hand-maintained `RULES` const removed the single place
        // that enumerated every rule. linkme self-registration has no
        // compile-time guarantee that a rule file actually registers: a file
        // that exists but forgets its `REGISTRATION` static — or a stray
        // non-rule `.rs` dropped into `src/rules/` — would be silently excluded
        // from (or unaccounted for in) the catalogue. This restores that
        // safety net: every `src/rules/*.rs` file must self-register exactly
        // one rule, so the file count equals the collected catalogue size.
        let file_count = std::fs::read_dir("src/rules")
            .expect("cannot read src/rules")
            .filter_map(|e| e.ok())
            .filter(|e| {
                let p = e.path();
                p.extension().and_then(|x| x.to_str()) == Some("rs")
                    && p.file_stem().and_then(|s| s.to_str()) != Some("mod")
            })
            .count();
        assert_eq!(
            RULES.len() + PROTOCOL_RULES.len(),
            file_count,
            "every src/rules/*.rs file must self-register exactly one rule \
             (catalogue has {} transaction + {} protocol rules, but {} rule \
             files exist) — a file is unregistered or a non-rule file is present",
            RULES.len(),
            PROTOCOL_RULES.len(),
            file_count,
        );
    }

    #[test]
    fn rule_ids_unique_and_non_empty() {
        let mut ids = std::collections::HashSet::new();
        for rule in RULES.iter() {
            let id = rule.id();
            assert!(!id.is_empty(), "Rule id should not be empty");
            assert!(ids.insert(id), "Duplicate rule id found: {}", id);
        }
        for rule in PROTOCOL_RULES.iter() {
            let id = rule.id();
            assert!(!id.is_empty(), "ProtocolRule id should not be empty");
            assert!(ids.insert(id), "Duplicate rule id found: {}", id);
        }
    }

    #[test]
    fn request_only_rules_excludes_server_scope_and_preserves_order() {
        let server_count = RULES
            .iter()
            .filter(|r| matches!(r.scope(), RuleScope::Server))
            .count();
        assert_eq!(
            REQUEST_ONLY_RULES.len(),
            RULES.len() - server_count,
            "request-only slice should equal RULES minus the {} server-scoped rules",
            server_count,
        );

        // Every rule in REQUEST_ONLY_RULES is non-Server.
        for rule in REQUEST_ONLY_RULES.iter() {
            assert_ne!(
                rule.scope(),
                RuleScope::Server,
                "server-scoped rule {} leaked into request-only slice",
                rule.id(),
            );
        }

        // Order preservation: walking RULES and skipping Server entries must
        // match REQUEST_ONLY_RULES element-for-element.
        let expected: Vec<&'static str> = RULES
            .iter()
            .filter(|r| !matches!(r.scope(), RuleScope::Server))
            .map(|r| r.id())
            .collect();
        let actual: Vec<&'static str> = REQUEST_ONLY_RULES.iter().map(|r| r.id()).collect();
        assert_eq!(
            actual, expected,
            "request-only slice must preserve source order of RULES",
        );
    }

    #[test]
    fn rules_for_scope_returns_full_rules_when_response_present() {
        // The has-response path must yield the same id sequence as `RULES` —
        // dispatch order on the production proxy path is unchanged from
        // pre-partitioning iteration.
        let with_response: Vec<&'static str> =
            rules_for_scope(true).iter().map(|r| r.id()).collect();
        let expected: Vec<&'static str> = RULES.iter().map(|r| r.id()).collect();
        assert_eq!(with_response, expected);
    }

    #[test]
    fn rules_for_scope_skips_server_when_no_response() {
        let without_response = rules_for_scope(false);
        for rule in RULES.iter() {
            let present = without_response.iter().any(|r| r.id() == rule.id());
            let is_server = matches!(rule.scope(), RuleScope::Server);
            assert_eq!(
                present,
                !is_server,
                "rule {} (scope {:?}): expected presence in request-only dispatch = {}",
                rule.id(),
                rule.scope(),
                !is_server,
            );
        }
    }

    #[test]
    fn validate_rules_ok_when_enabled_rule_has_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        // server_cache_control_present doesn't require config; enabling should pass
        enable_rule(&mut cfg, "server_cache_control_present");
        // server_clear_site_data requires paths; enable with valid paths too
        enable_rule_with_paths(&mut cfg, "server_clear_site_data", &["/logout"]);
        validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn stateful_rules_registry_is_consistent() {
        let rule_ids: std::collections::HashSet<&str> = RULES.iter().map(|r| r.id()).collect();
        let mut seen = std::collections::HashSet::new();
        for (rule, _query) in STATEFUL_RULES {
            let id = rule.id();
            // Every entry must correspond to a registered transaction rule, so
            // a typo or a rule dropped from RULES can't leave a dangling entry.
            assert!(
                rule_ids.contains(id),
                "STATEFUL_RULES entry '{}' is not present in RULES",
                id,
            );
            assert!(seen.insert(id), "duplicate id '{}' in STATEFUL_RULES", id,);
            // The lookup must resolve every registered entry.
            assert!(
                query_type_for(id).is_some(),
                "query_type_for('{}') returned None for a registered stateful rule",
                id,
            );
        }
    }

    // Note: there is intentionally no "every `stateful_`-prefixed rule must be
    // registered" test. The prefix is not a reliable signal for whether a rule
    // reads history — `stateful_websocket_handshake_validity` is prefixed but
    // ignores history, while several `client_*` / `semantic_*` rules read it.
    // The real guard is per-rule: a history consumer omitted from
    // STATEFUL_RULES is dispatched with an empty history and fails its own
    // history-exercising tests loudly.

    #[test]
    fn config_example_includes_all_rules() -> anyhow::Result<()> {
        let s = std::fs::read_to_string("config_example.toml")?;

        for rule in RULES.iter() {
            let id = rule.id();
            let marker = format!("[rules.{}]", id);
            assert!(
                s.contains(&marker),
                "config_example.toml missing example for rule '{}'",
                id
            );
        }
        for rule in PROTOCOL_RULES.iter() {
            let id = rule.id();
            let marker = format!("[rules.{}]", id);
            assert!(
                s.contains(&marker),
                "config_example.toml missing example for protocol rule '{}'",
                id
            );
        }

        Ok(())
    }

    #[test]
    fn validate_rules_errors_on_invalid_rule_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        // Enable server_clear_site_data but with invalid empty paths
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("paths".to_string(), toml::Value::Array(vec![]));
        cfg.rules.insert(
            "server_clear_site_data".to_string(),
            toml::Value::Table(table),
        );

        let res = validate_rules(&cfg);
        assert!(res.is_err());
        let msg = res.unwrap_err().to_string();
        assert!(msg.contains("server_clear_site_data"));
        Ok(())
    }

    #[test]
    fn test_validate_rules_invalid_severity() {
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert(
            "severity".to_string(),
            toml::Value::String("critical".into()),
        );
        cfg.rules
            .insert("test_rule".into(), toml::Value::Table(table));

        let res = validate_rules(&cfg);
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("Invalid severity"));
    }

    #[test]
    fn get_rule_enabled_required_not_table_errors() {
        let mut cfg = crate::config::Config::default();
        // Put a non-table value for the rule
        cfg.rules
            .insert("test_rule_nt".into(), toml::Value::String("oops".into()));

        let res = get_rule_enabled_required(&cfg, "test_rule_nt");
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .to_string()
            .contains("configuration must be a table"));
    }

    #[test]
    fn get_rule_severity_required_missing_or_not_string_errors() {
        let mut cfg = crate::config::Config::default();

        // Missing severity
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        cfg.rules
            .insert("test_rule_no_sev".into(), toml::Value::Table(table.clone()));

        let res = get_rule_severity_required(&cfg, "test_rule_no_sev");
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .to_string()
            .contains("missing required 'severity'"));

        // Severity present but not a string
        let mut table2 = table;
        table2.insert("severity".to_string(), toml::Value::Integer(1));
        cfg.rules
            .insert("test_rule_bad_sev".into(), toml::Value::Table(table2));

        let res2 = get_rule_severity_required(&cfg, "test_rule_bad_sev");
        assert!(res2.is_err());
        assert!(res2
            .unwrap_err()
            .to_string()
            .contains("missing required 'severity'"));
    }

    #[test]
    fn validate_rules_enabled_not_bool_errors() {
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Integer(1));
        table.insert("severity".to_string(), toml::Value::String("warn".into()));
        cfg.rules
            .insert("r_enabled_bad".into(), toml::Value::Table(table));

        let res = validate_rules(&cfg);
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("Invalid 'enabled'"));
    }

    #[test]
    fn validate_rules_missing_enabled_key_errors() {
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("severity".to_string(), toml::Value::String("warn".into()));
        cfg.rules
            .insert("r_missing_enabled".into(), toml::Value::Table(table));

        let res = validate_rules(&cfg);
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .to_string()
            .contains("Missing required 'enabled' key"));
    }

    #[test]
    fn validate_rules_severity_not_string_errors() {
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("severity".to_string(), toml::Value::Integer(1));
        cfg.rules
            .insert("r_sev_not_string".into(), toml::Value::Table(table));

        let res = validate_rules(&cfg);
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("must be a string"));
    }

    #[test]
    fn validate_rules_missing_severity_key_errors() {
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        cfg.rules
            .insert("r_missing_sev".into(), toml::Value::Table(table));

        let res = validate_rules(&cfg);
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .to_string()
            .contains("Missing required 'severity' key"));
    }
    #[test]
    fn default_rule_scope_is_both() {
        struct DummyRule;
        impl Rule for DummyRule {
            fn id(&self) -> &'static str {
                "dummy_rule"
            }

            fn check_transaction(
                &self,
                _tx: &crate::http_transaction::HttpTransaction,
                _history: &crate::transaction_history::TransactionHistory,
                _cfg: &crate::config::Config,
            ) -> Option<Violation> {
                None
            }
        }

        let r = DummyRule;
        assert_eq!(crate::rules::Rule::scope(&r), RuleScope::Both);

        // Also verify through a trait object (now object-safe).
        let v: &dyn Rule = &r;
        assert_eq!(v.scope(), RuleScope::Both);
    }

    #[test]
    fn parse_rule_config_success() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("severity".to_string(), toml::Value::String("warn".into()));
        cfg.rules.insert(
            "server_cache_control_present".into(),
            toml::Value::Table(table),
        );

        let rc = parse_rule_config(&cfg, "server_cache_control_present")?;
        assert!(rc.enabled);
        assert_eq!(rc.severity, crate::lint::Severity::Warn);
        Ok(())
    }

    #[test]
    fn get_rule_enabled_and_severity_required_success() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("severity".to_string(), toml::Value::String("warn".into()));
        cfg.rules
            .insert("test_rule".into(), toml::Value::Table(table));

        let enabled = get_rule_enabled_required(&cfg, "test_rule")?;
        assert!(enabled);

        let sev = get_rule_severity_required(&cfg, "test_rule")?;
        assert_eq!(sev, crate::lint::Severity::Warn);
        Ok(())
    }

    #[test]
    fn get_rule_severity_required_invalid_string_errors() {
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert(
            "severity".to_string(),
            toml::Value::String("critical".into()),
        );
        cfg.rules
            .insert("test_rule_invalid".into(), toml::Value::Table(table));

        let res = get_rule_severity_required(&cfg, "test_rule_invalid");
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("invalid severity"));
    }

    #[test]
    fn get_rule_enabled_required_missing_config_errors() {
        let cfg = crate::config::Config::default();
        let res = get_rule_enabled_required(&cfg, "nope");
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .to_string()
            .contains("missing configuration"));
    }
}
