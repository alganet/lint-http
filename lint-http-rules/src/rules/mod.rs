// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::queries::QueryType;
use linkme::distributed_slice;
use std::sync::LazyLock;

/// Both keys a rule's table must carry, checked once at startup.
///
/// `enabled` must be present and a boolean, and `severity` present and one of
/// the three names. The two `prepare` defaults ask it, and every custom
/// `prepare` is expected to ask it after its own options — which is the one
/// place the pair could be forgotten, and why `validate_rules` also walks
/// `Config::rules` itself before it calls any of them.
pub fn validate_rule_table(cfg: &crate::config::Config, rule_id: &str) -> anyhow::Result<()> {
    get_rule_severity_required(cfg, rule_id)?;
    get_rule_enabled_required(cfg, rule_id)?;
    Ok(())
}

/// Everything a rule derives from its configuration, resolved once when the
/// engine is built. What [`RuleMeta::prepare`] returns.
///
/// `state` is the rule's own resolved shape — an allowed-list, a set of
/// header names — behind `dyn Any` so the trait stays object-safe (the
/// catalogue is dispatched through `&'static dyn Rule`, which rules out an
/// associated type). Rules that read only their severity return `Box::new(())`.
pub struct ResolvedRule {
    pub severity: crate::lint::Severity,
    pub state: Box<dyn std::any::Any + Send + Sync>,
}

impl std::fmt::Debug for ResolvedRule {
    /// `state` is `dyn Any`, so only the severity can say anything; tests
    /// `expect_err` on `prepare` results, which needs the Ok side printable.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedRule")
            .field("severity", &self.severity)
            .finish_non_exhaustive()
    }
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

/// Scope of a rule: whether it applies to client-only traffic (requests),
/// server-only traffic (responses), or both (full transactions).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RuleScope {
    Client,
    Server,
    Both,
}

/// Whether an [`Example`] illustrates traffic the rule accepts or rejects.
/// Maps to the ✅ Good / ❌ Bad sections of the generated `docs/rules/<id>.md`.
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

impl SpecRef {
    /// This reference as an owned, serializable [`crate::lint::SpecCitation`]
    /// — what a finding carries. The `note` stays behind: it is rule-scoped
    /// prose for the docs, not part of locating the text.
    pub fn citation(&self) -> crate::lint::SpecCitation {
        crate::lint::SpecCitation {
            spec: self.spec.to_string(),
            section: self.section.map(str::to_string),
            url: self.url.to_string(),
        }
    }
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

/// Everything a rule says about itself, whatever subject it examines.
///
/// [`Rule`] and [`ProtocolRule`] are handed different subjects — a transaction,
/// a protocol event — and agreed on everything else. That agreement was written
/// out twice, with a comment on the second copy saying it matched the first,
/// and the three bodies the copies shared were extracted into free functions
/// called from both. A reader who has to be told two declarations agree is
/// reading one declaration too many: the nine members live here once, each
/// trait keeps only the hook that takes its own subject, and the three
/// go-betweens are gone because there is no longer a second caller to reach
/// them from.
///
/// The upcast is the other half of what this buys. `&dyn Rule` and
/// `&dyn ProtocolRule` both coerce to `&dyn RuleMeta`, so a check that reads
/// only metadata runs once over [`all_rules`] instead of once over `RULES` and
/// again over `PROTOCOL_RULES` — which is what a dozen gates were doing, each
/// carrying a second loop free to fall out of step with the first.
pub trait RuleMeta: Send + Sync {
    /// This rule's id: the `[rules.<id>]` section that configures it, the
    /// `Violation.rule` its findings carry, and the `docs/rules/<id>.md` page
    /// that documents it.
    fn id(&self) -> &'static str;

    /// The body of this rule's `[rules.<id>]` section, as it appears in the
    /// generated `config_example.toml` and in the generated doc page's
    /// Configuration block. The `[rules.<id>]` header itself is rendered from
    /// [`id`](RuleMeta::id), so the two cannot name different rules; what a
    /// rule writes here is everything under that header — the two required
    /// keys, its own options, and any comment explaining them.
    ///
    /// Required rather than defaulted, for the reason §6 of
    /// `docs/development.md` gives for options: an example nobody chose is
    /// still an example someone will copy. A default would silently answer
    /// `enabled = true` / `severity = "warn"` for a rule whose author never
    /// considered either, and 40 of the catalogue's 193 rules write something
    /// else.
    ///
    /// A comment belongs *below* the key it explains. Sections are rendered
    /// one after another with a blank line between them, so a comment written
    /// above a key reads as introducing everything under it — including, at
    /// the top of a body, the whole rule.
    fn config_example(&self) -> &'static str;

    /// Resolve this rule's configuration once, when the engine is built —
    /// which is also when it is validated: a malformed section fails fast at
    /// startup rather than silently disabling the rule at lint time.
    ///
    /// Validation *is* successful preparation: what a separate `validate`
    /// hook would answer with `Ok(())`, this answers with the resolved values
    /// themselves, so the same parse cannot run again — typed or untyped —
    /// on the lint path. The default resolves what every rule needs (the
    /// table's two required keys, of which severity is the one carried
    /// forward); a rule with a custom config section overrides this to parse
    /// it into its own `state`.
    fn prepare(&self, cfg: &crate::config::Config) -> anyhow::Result<ResolvedRule> {
        validate_rule_table(cfg, self.id())?;
        Ok(ResolvedRule {
            severity: get_rule_severity_required(cfg, self.id())?,
            state: Box::new(()),
        })
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
            cite: None,
        }
    }

    /// Build one of this rule's findings, carrying the specification text it
    /// enforces. `spec` must be one of the rule's own
    /// [`specifications`](RuleMeta::specifications) — a finding may only cite a
    /// reference its rule declares, which also keeps the docs' Specifications
    /// section covering every citable target. Checked in debug builds, so the
    /// whole test suite enforces it.
    ///
    /// Attachment is per violation site and opt-in, never derived from the
    /// rule: the median rule declares several references, and a wrong
    /// citation is worse than none. The `// cite` comment beside the call is
    /// the reviewer's oracle that the right one was named.
    fn cited(&self, spec: &SpecRef, severity: crate::lint::Severity, message: String) -> Violation {
        debug_assert!(
            self.specifications().contains(spec),
            "{}: a finding may only cite a spec the rule declares",
            self.id()
        );
        Violation {
            cite: Some(spec.citation()),
            ..self.violation(severity, message)
        }
    }

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

/// A rule that reads one canonical `HttpTransaction`. Everything it says about
/// itself comes from [`RuleMeta`]; what it adds is the subject it examines and
/// the half of the transaction it needs to see.
pub trait Rule: RuleMeta {
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

    /// Every finding this rule has about the transaction; empty means clean.
    /// Everything the rule derived from its configuration arrives resolved in
    /// `ctx` — its own `prepare` ran when the engine was built, so nothing
    /// here reads TOML.
    ///
    /// `Vec`, deliberately: a field with three defects is three findings, and
    /// the previous `Option` return capped every rule at one per message —
    /// ten rules were string-joining defects into a single message to get
    /// around it. `Vec::new()` does not allocate, so the clean path — nearly
    /// every message — still costs nothing. A single-finding rule keeps its
    /// `?`-shaped body behind a private `Option` adapter and collects it.
    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        history: &crate::transaction_history::TransactionHistory,
        ctx: &RuleContext<'_>,
    ) -> Vec<Violation>;
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
        if !all_rules().any(|r| r.id() == rule_name) {
            return Err(anyhow::anyhow!(
                "Configuration names a rule '{}' that does not exist. Every rule id is listed \
                 in docs/rules.md",
                rule_name
            ));
        }
    }

    // Per-rule validation: every enabled rule parses its own config section so
    // a malformed section (including custom fields) fails fast at startup.
    for rule in all_rules() {
        if config.is_enabled(rule.id()) {
            rule.prepare(config).map_err(|e| {
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
// `HttpTransaction`.  It lives in the same module to share `ResolvedRule`,
// the severity helpers, and the config TOML infrastructure.

/// A rule that evaluates protocol-level events (WebSocket frames, HTTP/3
/// control frames, QUIC transport events) rather than HTTP transactions.
///
/// It says the same things about itself a transaction rule does — that is
/// [`RuleMeta`] — and differs in the one member below, which is the whole of
/// what "protocol-level" means here. Scope is absent because it partitions a
/// transaction into its request and response halves, and an event has neither.
pub trait ProtocolRule: RuleMeta {
    /// Every finding this rule has about the event; empty means clean. See
    /// [`Rule::findings`] for the contract — everything config-derived
    /// arrives resolved in `ctx`, and the `Vec` return is what lets one
    /// event carry more than one defect.
    fn findings(
        &self,
        event: &crate::protocol_event::ProtocolEvent,
        history: &crate::protocol_event::ProtocolEventHistory,
        ctx: &RuleContext<'_>,
    ) -> Vec<Violation>;
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

/// The whole catalogue — every transaction rule, then every protocol rule — as
/// the metadata face the two kinds share.
///
/// Nothing here is a third catalogue: it chains the two sorted views through
/// the [`RuleMeta`] upcast, so it cannot disagree with them about membership or
/// order. What it retires is the doubled loop. A check phrased against metadata
/// has no reason to know which trait a rule implements, and every such check
/// used to say so twice — a `for` over `RULES` and a second `for` over
/// `PROTOCOL_RULES`, the second free to drift, or to be forgotten entirely when
/// the check was written. Reach for the individual views only when the
/// difference matters: dispatch, `scope`, and the docs index, which groups
/// transaction rules by a scope protocol rules do not have.
pub fn all_rules() -> impl Iterator<Item = &'static dyn RuleMeta> {
    RULES
        .iter()
        .map(|r| *r as &'static dyn RuleMeta)
        .chain(PROTOCOL_RULES.iter().map(|r| *r as &'static dyn RuleMeta))
}

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
        // reference, dispatched through `&dyn RuleMeta`. This doubles as a
        // completeness gate: a future rule added without metadata fails here.
        // Examples are exercised for dispatch only — a handful of docs carry no
        // `http` snippet, so emptiness is not asserted.
        for r in all_rules() {
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

    /// A rule builds findings through the `violation` helper (and, later, its
    /// cited sibling), never a struct literal: the helper is what guarantees
    /// `Violation.rule` is the rule's own id, and it is the one place a new
    /// field on `Violation` gets a default instead of 600 compile errors.
    /// Enforced by scanning the sources because privatizing the struct's
    /// fields would break every legitimate read downstream.
    #[test]
    fn no_rule_constructs_a_violation_literal() -> anyhow::Result<()> {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/rules");
        for entry in std::fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.extension().is_none_or(|e| e != "rs")
                || path.file_name().is_some_and(|n| n == "mod.rs")
            {
                continue;
            }
            let src = std::fs::read_to_string(&path)?;
            for (i, line) in src.lines().enumerate() {
                if let Some(pos) = line.find("Violation {") {
                    assert!(
                        line[..pos].ends_with("-> "),
                        "{}:{}: findings are built with the violation() helper, not a struct literal",
                        path.display(),
                        i + 1
                    );
                }
            }
        }
        Ok(())
    }

    /// A ratchet on citation coverage, not a target: `cite` is optional by
    /// design, and a finding whose sentence nobody has read yet is meant to
    /// carry none rather than a guess. What this pins is the direction —
    /// attaching a citation is progress that cannot be undone by accident, and
    /// the number tells whoever reads the catalogue next how much is left.
    ///
    /// Raise the floor when a batch lands. If this fails downward, a `cited()`
    /// site became a `violation()` one: say why in the commit or put it back.
    ///
    /// **Two finding sites merging into one lowers this number without losing a
    /// citation**, and that is the only reason it has ever moved down. Twice so
    /// far: the `Date` field's request and response readings were two copies of
    /// the same two findings and now share one function, and `Secure` and
    /// `HttpOnly` — one sentence each, the same defect, the same wording — are
    /// now one site over both names. Each still cites what it cited; the count
    /// of *sites* is not the count of sentences read, so when a duplicate
    /// disappears, lower the floor and say which one.
    #[test]
    fn citation_coverage_does_not_regress() {
        /// Finding sites that name the specification sentence they enforce, out
        /// of 578. The rest are the per-rule reading that has not happened yet.
        const FLOOR: usize = 171;

        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/rules");
        let mut cited = 0;
        let mut uncited = 0;
        for entry in std::fs::read_dir(&dir).expect("cannot read src/rules") {
            let path = entry.expect("a directory entry").path();
            if path.extension().is_none_or(|e| e != "rs")
                || path.file_name().is_some_and(|n| n == "mod.rs")
            {
                continue;
            }
            let src = std::fs::read_to_string(&path).expect("a rule file");
            // Before the test module: a fixture is not a finding site.
            let body = src.split("#[cfg(test)]").next().unwrap_or(&src);
            cited += body.matches("self.cited(").count();
            uncited += body.matches("self.violation(").count();
        }
        assert!(
            cited >= FLOOR,
            "citation coverage fell to {cited}/{} findings, below the floor of {FLOOR}",
            cited + uncited
        );
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
        for rule in all_rules() {
            let id = rule.id();
            assert!(!id.is_empty(), "Rule id should not be empty");
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

    /// The shipped file has a section for every rule.
    ///
    /// `config_example_matches_generated` in `xtask` says something stronger,
    /// and this is not therefore redundant: that gate needs the generator, and
    /// this crate is the one a `cargo test -p lint-http-rules` runs. It is also
    /// the half that survives a hand-edit of the file, which is the only way
    /// the two can now disagree.
    #[test]
    fn config_example_includes_all_rules() -> anyhow::Result<()> {
        let s = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../config_example.toml"),
        )?;

        for rule in all_rules() {
            let id = rule.id();
            let marker = format!("[rules.{}]", id);
            assert!(
                s.contains(&marker),
                "config_example.toml missing example for rule '{}'",
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
        impl RuleMeta for DummyRule {
            fn id(&self) -> &'static str {
                "dummy_rule"
            }

            fn config_example(&self) -> &'static str {
                r#"enabled = true
severity = "warn"
"#
            }
        }
        impl Rule for DummyRule {
            fn findings(
                &self,
                _tx: &crate::http_transaction::HttpTransaction,
                _history: &crate::transaction_history::TransactionHistory,
                _ctx: &crate::rules::RuleContext<'_>,
            ) -> Vec<Violation> {
                Vec::new()
            }
        }

        let r = DummyRule;
        assert_eq!(crate::rules::Rule::scope(&r), RuleScope::Both);

        // Also verify through a trait object (now object-safe).
        let v: &dyn Rule = &r;
        assert_eq!(v.scope(), RuleScope::Both);
    }

    /// Every registered rule prepares successfully under the shipped example
    /// config. This is the startup-time replacement for the coverage the
    /// per-transaction `.ok()?` parses used to get incidentally: a rule whose
    /// `prepare` cannot digest its own shipped `[rules.*]` section fails here
    /// by name, and no per-rule test has to remember to ask.
    #[test]
    fn every_rule_prepares_under_the_example_config() -> anyhow::Result<()> {
        let toml_src = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../config_example.toml"),
        )?;
        let cfg: crate::config::Config = toml::from_str(&toml_src)?;
        for rule in all_rules() {
            rule.prepare(&cfg)
                .map_err(|e| anyhow::anyhow!("rule '{}' failed to prepare: {e}", rule.id()))?;
        }
        Ok(())
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
    fn cited_attaches_a_declared_spec() {
        let rule = RULES
            .iter()
            .find(|r| r.id() == "host_header")
            .expect("host_header registered");
        let spec = &rule.specifications()[0];
        let v = rule.cited(spec, crate::lint::Severity::Warn, "m".to_string());
        let cite = v.cite.expect("citation attached");
        assert_eq!(cite.spec, spec.spec);
        assert_eq!(cite.section.as_deref(), spec.section);
        assert_eq!(cite.url, spec.url);
        assert_eq!(v.rule, "host_header");
    }

    #[test]
    #[should_panic(expected = "may only cite a spec the rule declares")]
    fn cited_refuses_a_spec_the_rule_does_not_declare() {
        let rule = RULES
            .iter()
            .find(|r| r.id() == "host_header")
            .expect("host_header registered");
        let foreign = SpecRef {
            spec: "RFC 0000",
            section: None,
            url: "https://example.com/",
            note: "",
        };
        let _ = rule.cited(&foreign, crate::lint::Severity::Warn, "m".to_string());
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
    fn a_severity_only_table_is_refused_and_never_dispatched() {
        // A table carrying a severity and no `enabled` fails validation, and
        // `is_enabled` reads the missing flag as `false` — so the rule is one
        // `PreparedEngine` refuses to build over, and would never dispatch
        // even if it did.
        let mut severity_only = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("severity".to_string(), toml::Value::String("error".into()));
        severity_only
            .rules
            .insert("cache_control_present".into(), toml::Value::Table(table));
        assert!(validate_rule_table(&severity_only, "cache_control_present").is_err());
        assert!(!severity_only.is_enabled("cache_control_present"));

        // A table with neither key is refused too, because the severity is the
        // reading dispatch cannot do without.
        let empty = crate::config::Config::default();
        assert!(validate_rule_table(&empty, "cache_control_present").is_err());
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
