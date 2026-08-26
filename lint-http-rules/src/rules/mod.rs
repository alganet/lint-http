// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::queries::QueryType;
use linkme::distributed_slice;
use std::sync::LazyLock;

/// What a rule reads from its configuration **at lint time**, which is its
/// severity and nothing else.
///
/// It carried an `enabled: bool` beside the severity, and no rule ever read it
/// back: `PreparedEngine` partitions the catalogue with `Config::is_enabled`
/// when it is built, so a disabled rule is never dispatched and the flag was
/// discarded at all 174 `check_transaction` / `check_event` call sites. The
/// question is answered before the rule runs, and asking it again cost a second
/// hash of the rule id and a second table probe on the hottest path in the
/// crate.
///
/// The *presence* of `enabled` is still required, and [`validate_rule_table`] is
/// where that is asked — at startup, once per rule, rather than once per
/// transaction per rule.
#[derive(Debug, Clone)]
pub struct RuleConfig {
    pub severity: crate::lint::Severity,
}

/// Parse severity from config for a given rule.
/// Returns RuleConfig with parsed severity. Fails if severity is not explicitly configured.
///
/// **What it costs, exactly.** One lookup of the rule id:
/// [`get_rule_severity_required`] hashes `rule_id` against `Config::rules`,
/// takes the value as a table and probes that table for `severity`. Thirteen
/// rules that read this after their gates say why in the comment placing the
/// call, and word it "several map probes plus a hash over the rule id"; **it
/// used to be two hashes and is now one**, because the `enabled` lookup beside
/// it was answering a question already decided. The call still belongs **after**
/// whatever gate ends the rule: a version comparison or an event-kind
/// discriminant is a few instructions against even one hash.
///
/// **Why the second lookup went, and where it went to.** Nothing at lint time
/// read the flag — `PreparedEngine` partitions the catalogue with
/// `Config::is_enabled` when it is built, so a disabled rule is never dispatched
/// — and the only thing that lookup did on this path was make a rule whose table
/// lacks `enabled` silent. That is a *validation* answer given at lint time, and
/// [`validate_rule_table`] is where it belongs: the two `validate` defaults call
/// it, `validate_rules` runs them at startup, and every binary entry point goes
/// through `load_validated_config` first.
///
/// **The consequence, stated plainly, and it is narrower than it looks.** A rule
/// whose table has a `severity` and no `enabled` used to be silent here and now
/// returns its severity. Through `PreparedEngine` that changes nothing at all:
/// `Config::is_enabled` reads a missing `enabled` as `false`, so such a rule is
/// filtered out when the engine is built and this function is never reached for
/// it — the lookup was dead *twice over* on that path. What changes is the
/// answer for a caller invoking `check_transaction` directly, which is what the
/// test suite does, and there the honest answer is the severity: whether the
/// rule runs was that caller's decision, not this function's.
pub fn parse_rule_config(cfg: &crate::config::Config, rule_id: &str) -> anyhow::Result<RuleConfig> {
    let severity = get_rule_severity_required(cfg, rule_id)?;
    Ok(RuleConfig { severity })
}

/// Both keys a rule's table must carry, checked once at startup.
///
/// This is the reading [`parse_rule_config`] used to perform on every
/// transaction: `enabled` must be present and a boolean, and `severity` present
/// and one of the three names. It is the default body of `Rule::validate` and
/// `ProtocolRule::validate`, so a rule that overrides `validate` to check its own
/// options is the one place the pair can be forgotten — which is why
/// `validate_rules` also walks `Config::rules` itself before it calls any of
/// them.
pub fn validate_rule_table(cfg: &crate::config::Config, rule_id: &str) -> anyhow::Result<()> {
    get_rule_severity_required(cfg, rule_id)?;
    get_rule_enabled_required(cfg, rule_id)?;
    Ok(())
}

/// Everything a rule derives from its configuration, resolved once when the
/// engine is built. What [`Rule::prepare`] returns.
///
/// `state` is the rule's own resolved shape — an allowed-list, a set of
/// header names — behind `dyn Any` so the trait stays object-safe (the
/// catalogue is dispatched through `&'static dyn Rule`, which rules out an
/// associated type). Rules that read only their severity return `Box::new(())`.
pub struct ResolvedRule {
    pub severity: crate::lint::Severity,
    pub state: Box<dyn std::any::Any + Send + Sync>,
}

/// One rule's resolved configuration, borrowed for one dispatch.
///
/// This is what replaces `cfg: &Config` at the check sites: two words on the
/// stack, no hashing, no TOML, no allocation. The severity is read directly;
/// rule-specific state comes back out through [`RuleContext::state`], typed
/// by the rule that put it in.
pub struct RuleContext<'a> {
    pub severity: crate::lint::Severity,
    state: &'a (dyn std::any::Any + Send + Sync),
}

impl<'a> RuleContext<'a> {
    /// Borrow a prepared rule's resolved configuration for one dispatch.
    pub fn new(resolved: &'a ResolvedRule) -> Self {
        Self {
            severity: resolved.severity,
            state: &*resolved.state,
        }
    }

    /// The rule-specific state this rule's own `prepare` returned.
    ///
    /// # Panics
    ///
    /// Panics on a type mismatch. The engine builds each context from the
    /// same rule's [`ResolvedRule`], so a mismatch means a rule asked for a
    /// type its `prepare` does not produce — a wiring bug, not a config one.
    pub fn state<T: 'static>(&self) -> &T {
        self.state.downcast_ref().expect("rule state wiring")
    }
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
/// Serializes as `"compliant"` / `"non_compliant"` for
/// `rules list --format json`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
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
#[derive(Copy, Clone, Debug, serde::Serialize)]
pub struct Example {
    pub compliance: Compliance,
    /// Optional heading suffix, rendered after `Good`/`Bad` in the doc
    /// subheading (e.g. `Some("Response")` → `### ✅ Good Response`,
    /// `Some("(invalid percent-encoding)")` → `### ❌ Bad (invalid
    /// percent-encoding)`). `None` renders a bare `### ✅ Good` / `### ❌ Bad`.
    pub label: Option<&'static str>,
    pub snippet: &'static str,
}

/// A reference to the specification text a rule enforces.
///
/// This used to be a free-form markdown bullet — a display string, not data —
/// and five spellings of it had grown up side by side, across three spellings of
/// the same host. Nothing could be checked, because there was nothing to check:
/// no field held the URL, so no tool could fetch it.
///
/// `spec` names the document in **exactly the vocabulary `specs/sources.yaml`
/// uses**. That is the point of it: a `SpecRef` and a `// cite` comment name one
/// source the same way, so the rule's metadata and the verified quote inside its
/// code cannot drift into describing different documents.
///
/// What is deliberately absent is the quoted sentence. A rule emits violations
/// from several branches, and a quote on the *rule* cannot say which branch
/// implements which normative sentence. Quotes live at the statement that
/// enforces them, as a `// cite` comment.
#[derive(Copy, Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct SpecRef {
    /// The document: `"RFC 9110"`, `"Fetch"`, `"MDN Origin"`.
    pub spec: &'static str,
    /// The section within it: `"7.2"`. `None` when the reference names the
    /// document as a whole (a registry, an explainer).
    pub section: Option<&'static str>,
    /// Where to read it. Canonical: one host per document, always.
    pub url: &'static str,
    /// What this reference contributes to *this* rule. May be empty when the
    /// section title already says it.
    pub note: &'static str,
}

impl std::fmt::Display for SpecRef {
    /// The markdown bullet body the docs render. One spelling now, derived —
    /// which is what retires the format drift rather than merely tidying it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.section {
            Some(section) => write!(f, "[{} §{}]({})", self.spec, section, self.url)?,
            None => write!(f, "[{}]({})", self.spec, self.url)?,
        }
        if !self.note.is_empty() {
            write!(f, ": {}", self.note)?;
        }
        Ok(())
    }
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
        validate_rule_table(cfg, self.id())
    }

    /// Resolve this rule's configuration once, when the engine is built.
    ///
    /// Validation *is* successful preparation: what `validate` answers with
    /// `Ok(())`, this answers with the resolved values themselves, so the
    /// same parse cannot run again — typed or untyped — on the lint path.
    /// The default resolves what every rule needs (the table's two required
    /// keys, of which severity is the one carried forward); a rule with a
    /// custom config section overrides this to parse it into its own `state`.
    fn prepare(&self, cfg: &crate::config::Config) -> anyhow::Result<ResolvedRule> {
        validate_rule_table(cfg, self.id())?;
        Ok(ResolvedRule {
            severity: get_rule_severity_required(cfg, self.id())?,
            state: Box::new(()),
        })
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

    /// Build one of this rule's findings.
    ///
    /// `Violation.rule` is the rule id, so a constructor for it needs `self.id()`
    /// — which is why seven rules had each written this out privately, where
    /// `id()` already was in scope. Four were byte-identical, one differed only
    /// in argument order, and two took a whole config struct in order to read
    /// `severity` off it. That is the argument for the extraction and not merely
    /// its occasion: seven copies of one four-line body had already grown three
    /// signatures.
    ///
    /// The parameters follow the struct's own field order: `rule` comes from
    /// `self`, then `severity`, then `message`. A rule whose severity lives in a
    /// custom config section passes `config.severity`; nothing here reads a
    /// config, because the trait cannot know the shape of one.
    ///
    /// Not generic over the message, so the trait stays object-safe — the engine
    /// dispatches every rule through `&'static dyn Rule`.
    ///
    /// An inherent method of this name on a rule would shadow this one silently,
    /// which is why `structured_headers_valid`'s private finding
    /// builder is named for its failure rather than for what it returns.
    fn violation(&self, severity: crate::lint::Severity, message: String) -> Violation {
        Violation {
            rule: self.id().into(),
            severity,
            message,
        }
    }

    /// Evaluate an `HttpTransaction` against this rule. Rules parse whatever
    /// configuration they need directly from the global `cfg: &Config`.
    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation>;

    /// Doc title override (the `# ` heading of the generated per-rule doc).
    /// Defaults to `None`, which makes the generator derive the title from the
    /// rule id. Rules override this only when the desired title differs from
    /// the derived form (e.g. to preserve header casing like `Accept-Encoding`).
    fn title(&self) -> Option<&'static str> {
        None
    }

    /// Human-readable summary of what this rule checks and why it matters.
    /// Renders as the "Description" section of the generated per-rule doc.
    /// Empty by default; rules override it with content sourced from
    /// `docs/rules/`.
    fn description(&self) -> &'static str {
        ""
    }

    /// The specification text this rule enforces. Renders into the
    /// "Specifications" section of the generated doc; empty by default.
    fn specifications(&self) -> &'static [SpecRef] {
        &[]
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

    // A configured name that matches no registered rule fails, loudly. A
    // section under an unknown name used to validate fine and configure
    // nothing — which is a rule the operator believes is on and is not. Both
    // ways of arriving here deserve the error: a typo, and a configuration
    // written against ids this catalogue no longer uses. Renames here are
    // breaking by decision, never aliased, so this is the only place a
    // configuration hears about one.
    //
    // The message names `docs/rules.md` rather than any particular old id. It
    // used to carry the most recent rename as a worked example, which is a
    // shape that only survives while renames arrive one at a time; every id in
    // the catalogue was rewritten at once, and a hint listing 193 pairs is a
    // document, not an error message.
    for rule_name in config.rules.keys() {
        let known = RULES.iter().any(|r| r.id() == rule_name)
            || PROTOCOL_RULES.iter().any(|r| r.id() == rule_name);
        if !known {
            return Err(anyhow::anyhow!(
                "Configuration names a rule '{}' that does not exist. Every rule id is listed \
                 in docs/rules.md",
                rule_name
            ));
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
        validate_rule_table(cfg, self.id())
    }

    /// Resolve this rule's configuration once, when the engine is built. See
    /// [`Rule::prepare`] for the contract.
    fn prepare(&self, cfg: &crate::config::Config) -> anyhow::Result<ResolvedRule> {
        validate_rule_table(cfg, self.id())?;
        Ok(ResolvedRule {
            severity: get_rule_severity_required(cfg, self.id())?,
            state: Box::new(()),
        })
    }

    /// Evaluate a single protocol event against this rule. Rules parse
    /// whatever configuration they need directly from `cfg: &Config`.
    fn check_event(
        &self,
        event: &crate::protocol_event::ProtocolEvent,
        history: &crate::protocol_event::ProtocolEventHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation>;

    /// Doc title override (the `# ` heading of the generated per-rule doc).
    /// See [`Rule::title`] for the contract.
    fn title(&self) -> Option<&'static str> {
        None
    }

    /// Human-readable summary of what this rule checks and why it matters.
    /// Renders as the "Description" section of the generated per-rule doc.
    /// Empty by default; rules override it with content sourced from
    /// `docs/rules/`.
    fn description(&self) -> &'static str {
        ""
    }

    /// The specification text this rule enforces. Renders into the
    /// "Specifications" section of the generated doc; empty by default.
    fn specifications(&self) -> &'static [SpecRef] {
        &[]
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
        &authentication_failure_loop::AuthenticationFailureLoop,
        QueryType::ByOrigin,
    ),
    (
        &digest_auth_nonce_handling::DigestAuthNonceHandling,
        QueryType::ByOrigin,
    ),
    (&cookie_lifecycle::CookieLifecycle, QueryType::ByOrigin),
    (
        &cookie_same_site_enforced::CookieSameSiteEnforced,
        QueryType::ByOrigin,
    ),
    // ── ByResourceAll: history for a resource across all clients ──
    (
        &private_cache_visibility::PrivateCacheVisibility,
        QueryType::ByResourceAll,
    ),
    // ── ByConnection: history for a single TCP connection ──
    (
        &status_101_switching_protocols::Status101SwitchingProtocols,
        QueryType::ByConnection,
    ),
    // ── ByResource: per-client history for one resource (the common case) ──
    (
        &accept_ranges_on_partial_content::AcceptRangesOnPartialContent,
        QueryType::ByResource,
    ),
    (
        &cached_validators_reused::CachedValidatorsReused,
        QueryType::ByResource,
    ),
    (
        &expect_header_valid::ExpectHeaderValid,
        QueryType::ByResource,
    ),
    (
        &patch_method_content_type_match::PatchMethodContentTypeMatch,
        QueryType::ByResource,
    ),
    (&cache_coherence::CacheCoherence, QueryType::ByResource),
    (
        &head_response_headers_match_get::HeadResponseHeadersMatchGet,
        QueryType::ByResource,
    ),
    (
        &cookie_domain_matching::CookieDomainMatching,
        QueryType::ByResource,
    ),
    // `status_103_early_hints_before_final` was here. Its requirement relates
    // two responses to one request, which a history entry — a different request
    // — cannot supply, so it reads no history and would have paid for one built
    // for nothing.
    (
        &cache_validation_chain::CacheValidationChain,
        QueryType::ByResource,
    ),
    (
        &conditional_request_handling::ConditionalRequestHandling,
        QueryType::ByResource,
    ),
    (
        &immutable_cache_never_stale::ImmutableCacheNeverStale,
        QueryType::ByResource,
    ),
    (
        &max_age_directive_valid::MaxAgeDirectiveValid,
        QueryType::ByResource,
    ),
    (
        &must_revalidate_enforced::MustRevalidateEnforced,
        QueryType::ByResource,
    ),
    (
        &no_cache_revalidation::NoCacheRevalidation,
        QueryType::ByResource,
    ),
    (&no_store_enforced::NoStoreEnforced, QueryType::ByResource),
    (&oauth2_code_flow::Oauth2CodeFlow, QueryType::ByResource),
    (
        &range_request_and_caching::RangeRequestAndCaching,
        QueryType::ByResource,
    ),
    (&s_max_age_enforced::SMaxAgeEnforced, QueryType::ByResource),
    (
        &vary_header_cache_valid::VaryHeaderCacheValid,
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
    use rstest::rstest;

    // Per-rule config validation lives here, not in `Config::load_from_path`
    // (which only parses). These cases load a structurally-valid config and
    // assert `validate_rules` rejects it — the compose path callers run.
    #[rstest]
    #[case(
        r#"[general]
listen = "127.0.0.1:3000"
captures = "captures.jsonl"

[tls]
enabled = false

[rules.clear_site_data_present]
enabled = true
severity = "warn"
paths = []  # Invalid: empty array
"#,
        "clear_site_data_present",
        "cannot be empty"
    )]
    #[case(
        r#"[general]
listen = "127.0.0.1:3000"
captures = "captures.jsonl"

[tls]
enabled = false

[rules.clear_site_data_present]
enabled = true
severity = "warn"
paths = ["/logout", 42, "/signout"]  # Invalid: contains non-string
"#,
        "clear_site_data_present",
        "not a string"
    )]
    #[case(
        r#"[general]
listen = "127.0.0.1:3000"
captures = "captures.jsonl"

[tls]
enabled = false

[rules.clear_site_data_present]
enabled = true
severity = "warn"
# Missing "paths" field entirely
other_field = "value"
"#,
        "clear_site_data_present",
        "'paths' field"
    )]
    #[case(
        r#"[general]
listen = "127.0.0.1:3000"
captures = "captures.jsonl"

[tls]
enabled = false

[rules.some_rule]
enabled = true
# Missing severity key
"#,
        "some_rule",
        "Missing required 'severity'"
    )]
    #[case(
        r#"[general]
listen = "127.0.0.1:3000"
captures = "captures.jsonl"

[tls]
enabled = false

[rules.some_rule]
enabled = true
severity = "critical"
"#,
        "some_rule",
        "must be one of"
    )]
    #[case(
        r#"[general]
listen = "127.0.0.1:3000"
captures = "captures.jsonl"

[tls]
enabled = false

[rules.some_rule]
severity = "warn"
"#,
        "some_rule",
        "Missing required 'enabled'"
    )]
    #[case(
        r#"[general]
listen = "127.0.0.1:3000"
captures = "captures.jsonl"

[tls]
enabled = false

[rules.some_rule]
enabled = "true"
severity = "warn"
"#,
        "some_rule",
        "Invalid 'enabled' for rule"
    )]
    #[tokio::test]
    async fn validate_rejects_invalid_rule_config_cases(
        #[case] toml: &str,
        #[case] rule: &str,
        #[case] expected_substring: &str,
    ) -> anyhow::Result<()> {
        let tmp_toml = std::env::temp_dir().join(format!(
            "lint-http_cfg_invalid_{}.toml",
            uuid::Uuid::new_v4()
        ));
        tokio::fs::write(&tmp_toml, toml).await?;

        // Structural load succeeds; rule validation is the gate.
        let cfg = crate::config::Config::load_from_path(&tmp_toml).await?;
        let res = validate_rules(&cfg);

        assert!(res.is_err());
        let err_msg = res.unwrap_err().to_string();
        assert!(err_msg.contains(rule));
        assert!(err_msg.contains(expected_substring));

        tokio::fs::remove_file(&tmp_toml).await?;
        Ok(())
    }

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
        assert!(RULES.iter().any(|r| r.id() == "host_header"));
        assert!(PROTOCOL_RULES
            .iter()
            .any(|r| r.id() == "quic_transport_parameters_valid"));
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
    fn metadata_accessors_are_populated_and_dispatch() {
        // #11c fills real per-rule metadata sourced from `docs/rules/`. Every
        // rule must now report a non-empty description and a specification
        // reference, dispatched through `&dyn Rule` / `&dyn ProtocolRule`. This
        // doubles as a completeness gate: a future rule added without metadata
        // fails here. Examples are exercised for dispatch only — a handful of
        // docs carry no `http` snippet, so emptiness is not asserted.
        for r in RULES.iter() {
            assert!(
                !r.description().trim().is_empty(),
                "{} missing description",
                r.id()
            );
            assert!(
                !r.specifications().is_empty(),
                "{} missing specifications",
                r.id()
            );
            let _ = r.examples();
            let _ = r.title();
        }
        for r in PROTOCOL_RULES.iter() {
            assert!(
                !r.description().trim().is_empty(),
                "{} missing description",
                r.id()
            );
            assert!(
                !r.specifications().is_empty(),
                "{} missing specifications",
                r.id()
            );
            let _ = r.examples();
            let _ = r.title();
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
        let rules_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/rules");
        let file_count = std::fs::read_dir(&rules_dir)
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

    /// A configured name matching no registered rule fails validation, so a
    /// deployment carrying a stale section hears about it at startup rather
    /// than running with the rule silently unconfigured. Renames in this
    /// catalogue are breaking by decision and never aliased, which is what
    /// makes this the load-bearing check rather than a courtesy.
    ///
    /// Both ids below are invented. The test used to assert on a real id the
    /// catalogue had just retired, and on the error naming its replacement —
    /// which tied it to one rename and made it a record of catalogue history.
    /// What is being tested is that an unregistered name fails, and a name that
    /// never existed says that without dating the test.
    #[test]
    fn validate_rules_rejects_a_rule_id_that_does_not_exist() {
        let mut cfg = crate::config::Config::default();
        enable_rule(&mut cfg, "no_such_rule_was_ever_registered");
        let err = validate_rules(&cfg).expect_err("an unknown rule id must fail validation");
        let msg = err.to_string();
        assert!(msg.contains("does not exist"), "{msg}");
        assert!(msg.contains("no_such_rule_was_ever_registered"), "{msg}");
        assert!(msg.contains("docs/rules.md"), "{msg}");

        // A typo in a real id is the same failure.
        let mut cfg = crate::config::Config::default();
        enable_rule(&mut cfg, "cache_control_presnet");
        assert!(validate_rules(&cfg).is_err());
    }

    #[test]
    fn validate_rules_ok_when_enabled_rule_has_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        // cache_control_present doesn't require config; enabling should pass
        enable_rule(&mut cfg, "cache_control_present");
        // clear_site_data_present requires paths; enable with valid paths too
        enable_rule_with_paths(&mut cfg, "clear_site_data_present", &["/logout"]);
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

    // Note: there is intentionally no test deriving this table's membership from
    // the catalogue. It used to be phrased against a `stateful_` id prefix, which
    // never answered the question anyway — `websocket_handshake_valid` carried
    // the prefix and read no history, while rules that carried `client_` and
    // `semantic_` did — and now there is no prefix left to phrase it against.
    // Nothing about an id says whether a rule reads history. The real guard is
    // per-rule: a history consumer omitted from STATEFUL_RULES is dispatched with
    // an empty history and fails its own history-exercising tests loudly.

    #[test]
    fn config_example_includes_all_rules() -> anyhow::Result<()> {
        let s = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../config_example.toml"),
        )?;

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
        // Enable clear_site_data_present but with invalid empty paths
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("paths".to_string(), toml::Value::Array(vec![]));
        cfg.rules.insert(
            "clear_site_data_present".to_string(),
            toml::Value::Table(table),
        );

        let res = validate_rules(&cfg);
        assert!(res.is_err());
        let msg = res.unwrap_err().to_string();
        assert!(msg.contains("clear_site_data_present"));
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
    fn default_prepare_resolves_severity_and_unit_state() -> anyhow::Result<()> {
        let cfg = crate::test_helpers::make_test_config_with_severity("host_header", "error");
        let rule = RULES
            .iter()
            .find(|r| r.id() == "host_header")
            .expect("host_header registered");
        let resolved = rule.prepare(&cfg)?;
        assert_eq!(resolved.severity, crate::lint::Severity::Error);
        let ctx = RuleContext::new(&resolved);
        assert_eq!(ctx.severity, crate::lint::Severity::Error);
        // The default prepare carries no rule-specific state.
        let _: &() = ctx.state::<()>();
        Ok(())
    }

    #[test]
    fn default_prepare_rejects_missing_severity() {
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        cfg.rules
            .insert("host_header".to_string(), toml::Value::Table(table));
        let rule = RULES
            .iter()
            .find(|r| r.id() == "host_header")
            .expect("host_header registered");
        assert!(rule.prepare(&cfg).is_err());
    }

    #[test]
    fn rule_context_state_roundtrips_the_prepared_type() {
        let resolved = ResolvedRule {
            severity: crate::lint::Severity::Info,
            state: Box::new(vec!["utf-8".to_string()]),
        };
        let ctx = RuleContext::new(&resolved);
        assert_eq!(ctx.state::<Vec<String>>(), &vec!["utf-8".to_string()]);
    }

    #[test]
    #[should_panic(expected = "rule state wiring")]
    fn rule_context_state_mismatch_panics() {
        let resolved = ResolvedRule {
            severity: crate::lint::Severity::Warn,
            state: Box::new(()),
        };
        let ctx = RuleContext::new(&resolved);
        let _ = ctx.state::<Vec<String>>();
    }

    #[test]
    fn protocol_rule_default_prepare_resolves_severity() -> anyhow::Result<()> {
        let cfg =
            crate::test_helpers::make_test_config_with_severity("websocket_frame_masking", "warn");
        let rule = PROTOCOL_RULES
            .iter()
            .find(|r| r.id() == "websocket_frame_masking")
            .expect("websocket_frame_masking registered");
        let resolved = rule.prepare(&cfg)?;
        assert_eq!(resolved.severity, crate::lint::Severity::Warn);
        Ok(())
    }

    #[test]
    fn parse_rule_config_success() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("severity".to_string(), toml::Value::String("warn".into()));
        cfg.rules
            .insert("cache_control_present".into(), toml::Value::Table(table));

        let rc = parse_rule_config(&cfg, "cache_control_present")?;
        assert_eq!(rc.severity, crate::lint::Severity::Warn);

        // The reading is the severity's, and the `enabled` key beside it is not
        // read: a table carrying a severity and no `enabled` is a config a rule
        // can be run under, and one `validate_rule_table` refuses.
        let mut severity_only = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("severity".to_string(), toml::Value::String("error".into()));
        severity_only
            .rules
            .insert("cache_control_present".into(), toml::Value::Table(table));
        assert_eq!(
            parse_rule_config(&severity_only, "cache_control_present")?.severity,
            crate::lint::Severity::Error
        );
        assert!(validate_rule_table(&severity_only, "cache_control_present").is_err());

        // And a table with neither is refused by both, because the severity is
        // the reading lint time cannot do without.
        let empty = crate::config::Config::default();
        assert!(parse_rule_config(&empty, "cache_control_present").is_err());
        assert!(validate_rule_table(&empty, "cache_control_present").is_err());

        // And the reason dropping the flag is not an engine-visible change:
        // `is_enabled` reads a missing `enabled` as `false`, so the rule whose
        // severity is now readable is one `PreparedEngine` never dispatches. The
        // lookup was dead twice over on that path.
        assert!(!severity_only.is_enabled("cache_control_present"));
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
