// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::queries::QueryType;
use crate::violations::ViolationDef;
use linkme::distributed_slice;
use std::sync::LazyLock;

/// The one key a rule's table must carry, checked once at startup.
///
/// `enabled` must be present and a boolean. **It used to be two**: a rule table
/// also had to name a `severity`, which every finding then reported at — one
/// scalar for everything a rule said. Severity is a violation's now, so the key
/// is gone and this asks for what is left. The two `prepare` defaults ask it,
/// and every custom `prepare` is expected to ask it after its own options —
/// which is the one place it could be forgotten, and why `validate_rules` also
/// walks `Config::rules` itself before it calls any of them.
pub fn validate_rule_table(cfg: &crate::config::Config, rule_id: &str) -> anyhow::Result<()> {
    get_rule_enabled_required(cfg, rule_id)?;
    Ok(())
}

/// Everything a rule derives from its configuration, resolved once when the
/// engine is built. What [`RuleMeta::prepare`] returns.
///
/// `state` is the rule's own resolved shape — an allowed-list, a set of
/// header names — behind `dyn Any` so the trait stays object-safe (the
/// catalogue is dispatched through `&'static dyn Rule`, which rules out an
/// associated type). A rule with nothing to resolve returns `Box::new(())`,
/// which is most of them: the severity that used to sit beside `state` was the
/// only thing the other 176 had here.
pub struct ResolvedRule {
    pub state: Box<dyn std::any::Any + Send + Sync>,
}

impl std::fmt::Debug for ResolvedRule {
    /// `state` is `dyn Any` and there is nothing else, so this prints the name
    /// alone; tests `expect_err` on `prepare` results, which needs the Ok side
    /// printable.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedRule").finish_non_exhaustive()
    }
}

/// One rule's resolved configuration, borrowed for one dispatch.
///
/// This is what replaces `cfg: &Config` at the check sites: no hashing, no
/// TOML, no allocation. Rule-specific state comes back out through
/// [`RuleContext::state`], typed by the rule that put it in.
///
/// It is also where a finding is built from the catalogue. **It used to carry a
/// `severity` too** — one scalar for the whole rule, which is what made a rule
/// that says four different things say them all at the same level. The defects
/// a rule declares each carry their own, [`report`](RuleContext::report) reads
/// the one for the defect being reported, and the scalar went when the last
/// finding stopped asking for it.
pub struct RuleContext<'a> {
    state: &'a (dyn std::any::Any + Send + Sync),
    /// The reporting rule's id, for the `Violation.rule` a report carries. A
    /// context has to be told, because `report` is a method on the context and
    /// not on the rule.
    rule_id: &'static str,
    /// The defects this rule may report — [`RuleMeta::violations`], carried
    /// here so a report can be resolved without dispatching back through the
    /// rule.
    declared: &'static [&'static ViolationDef],
    /// The severity each entry of `declared` reports at, same order, same
    /// length. Resolved once when the engine is built; see [`severities_for`].
    severities: &'a [crate::lint::Severity],
}

impl<'a> RuleContext<'a> {
    /// Borrow a prepared rule's resolved configuration for one dispatch.
    ///
    /// The context this builds declares no defects, which is what an empty
    /// `declared` list says: reporting one through it is a wiring error and
    /// says so in debug. Every dispatch path names the rule and its catalogue
    /// through [`with_violations`](RuleContext::with_violations); this is the
    /// half that carries only what `prepare` resolved.
    pub fn new(resolved: &'a ResolvedRule) -> Self {
        Self {
            state: &*resolved.state,
            rule_id: "",
            declared: &[],
            severities: &[],
        }
    }

    /// Name the reporting rule and hand it the defects it declares, with the
    /// severity each of them reports at: `severities[i]` configures
    /// `declared[i]`, which is what lets [`report`](RuleContext::report)
    /// resolve a severity by index instead of hashing an id on every finding.
    ///
    /// Separate from [`new`](RuleContext::new) because the two halves are
    /// resolved by different things. A [`ResolvedRule`] is what the rule's own
    /// `prepare` made of its `[rules.<id>]` section, and 17 rules build one
    /// themselves; the severity table is read from the catalogue and the
    /// configuration together, alongside that result rather than inside it, so
    /// neither the trait nor those rules have to know it exists.
    pub fn with_violations(
        self,
        rule: &dyn RuleMeta,
        severities: &'a [crate::lint::Severity],
    ) -> Self {
        Self {
            rule_id: rule.id(),
            declared: rule.violations(),
            severities,
            ..self
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

    /// Report one of this rule's declared defects, at the severity configured
    /// for it.
    ///
    /// The def carries the wording and the sentence it enforces, so naming the
    /// defect names both. That was the difference from the two methods this
    /// replaced — `RuleMeta::violation` and its cited sibling, deleted with the
    /// last site that called them — where the message was written out at the
    /// site and the citation was a second argument beside it: there, two sites
    /// reporting the same defect agreed only by having been written the same
    /// way, and an operator had no name for what they shared.
    ///
    /// # Panics
    ///
    /// In debug builds: if `def` is not one of this rule's declared defects,
    /// or if it holds no message of its own — a parameterised def is reported
    /// through [`report_with`](RuleContext::report_with), and reporting it
    /// here would emit an empty message. The suite runs debug, so any test
    /// reaching the site catches both.
    pub fn report(&self, def: &'static ViolationDef) -> Violation {
        debug_assert!(
            !def.message.is_empty(),
            "{}: {} holds no message of its own; report_with formats one",
            self.rule_id,
            def.id,
        );
        self.finding(def, def.message.to_string())
    }

    /// Report one of this rule's declared defects with a message formatted
    /// here — the shape for a defect whose wording names the value that caused
    /// it. Such a def carries an empty `message`, because the format arguments
    /// are at the site and the catalogue cannot hold them.
    ///
    /// # Panics
    ///
    /// In debug builds, on an undeclared def, or on one that holds its own
    /// whole message: reporting that through here would let the site say
    /// something the catalogue does not.
    pub fn report_with(&self, def: &'static ViolationDef, message: String) -> Violation {
        debug_assert!(
            def.message.is_empty(),
            "{}: {} holds its own message; report emits it",
            self.rule_id,
            def.id,
        );
        self.finding(def, message)
    }

    /// The common half: everything but the message comes from the def and the
    /// context, so the two entry points differ only in where the message came
    /// from.
    ///
    /// A finding is cited when its def names exactly one sentence. A def
    /// naming several names them because no one of them governs — the
    /// requirement is written once per protocol version — and picking one here
    /// would put an HTTP/2 reference on an HTTP/3 finding half the time. Such a
    /// finding says which section governs it in its own message, which is what
    /// it did while the entry carried no reference at all; the references are
    /// on the def for the catalogue and the docs to read.
    fn finding(&self, def: &'static ViolationDef, message: String) -> Violation {
        Violation {
            rule: self.rule_id.into(),
            violation: def.id.into(),
            severity: self.severity_for(def),
            message,
            cite: match def.spec {
                [only] => Some(only.citation()),
                _ => None,
            },
        }
    }

    /// The severity `def` reports at, found by identity: the defs are
    /// `static`, so the address is the name and nothing on the finding path
    /// compares a string. A rule declares a handful, and this runs only when
    /// there is something to report.
    ///
    /// An undeclared def is the same wiring error [`RuleMeta::cited`] refuses
    /// an undeclared spec for, and is caught the same way. Falling back to the
    /// def's own default in release keeps a release build reporting the defect
    /// rather than dropping it — what cannot be honoured is the configuration
    /// for something the rule never said it reports.
    fn severity_for(&self, def: &'static ViolationDef) -> crate::lint::Severity {
        let index = self.declared.iter().position(|d| std::ptr::eq(*d, def));
        debug_assert!(
            index.is_some(),
            "{}: a finding may only report a violation the rule declares, and {} is not in its list",
            self.rule_id,
            def.id,
        );
        index
            .and_then(|i| self.severities.get(i).copied())
            .unwrap_or(def.default_severity)
    }
}

/// The severity each of `rule`'s declared defects reports at: one entry per
/// [`RuleMeta::violations`] entry, in that order — the table
/// [`RuleContext::with_violations`] hands to dispatch.
///
/// An entry is its def's `default_severity` unless `[violations.<id>]` says
/// otherwise. The defaults live in code, unlike a rule's *options*: an option
/// is policy about the traffic and has to be chosen, a severity is a
/// preference, and a catalogue of this many defects cannot be answered entry by
/// entry before it can run at all. So the override is the exception an operator
/// writes, and the whole table resolves without one.
pub fn severities_for(
    rule: &dyn RuleMeta,
    cfg: &crate::config::Config,
) -> Vec<crate::lint::Severity> {
    rule.violations()
        .iter()
        .map(|def| violation_severity(cfg, def))
        .collect()
}

/// The severity `def` reports at under `cfg` — its `[violations.<id>]`
/// override, or the default on the def.
///
/// Infallible where [`get_rule_severity_required`] is not, and for a reason
/// that only holds because of where it runs: [`validate_rules`] has already
/// refused a malformed `[violations.*]` table by the time an engine prepares
/// anything, so an unreadable value here is not a configuration this code can
/// reach. Reading it as "no override" rather than as an error is also the
/// safe half of being wrong — the defect is still reported, at the severity
/// its author chose.
fn violation_severity(cfg: &crate::config::Config, def: &ViolationDef) -> crate::lint::Severity {
    cfg.get_violation_config(def.id)
        .and_then(toml::Value::as_table)
        .and_then(|table| table.get("severity"))
        .and_then(toml::Value::as_str)
        .and_then(crate::lint::Severity::from_name)
        .unwrap_or(def.default_severity)
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
    /// on the lint path. The default validates the table's one required key and
    /// resolves nothing, which is the true statement about 176 of the rules; a
    /// rule with a custom config section overrides this to parse it into its
    /// own `state`.
    fn prepare(&self, cfg: &crate::config::Config) -> anyhow::Result<ResolvedRule> {
        validate_rule_table(cfg, self.id())?;
        Ok(ResolvedRule {
            state: Box::new(()),
        })
    }

    /// The defects this rule may report, and the only ones it may:
    /// [`RuleContext::report`] resolves a def against this list by identity
    /// and reads the severity at the same index, so a def missing here has no
    /// configured severity and says so in debug.
    ///
    /// Hand-declared, and a named `static DECLARED` per rule rather than an
    /// inline `&[…]` — an array of references to statics is not
    /// const-promotable, so the inline form does not typecheck as `'static`.
    /// The defs it names are themselves `static` for the identity lookup's
    /// sake; see [`ViolationDef`].
    ///
    /// **Required, with no default.** The default was `&[]` while the two ways
    /// of reporting coexisted — a true statement about a rule whose defects had
    /// not been read out of its body yet — and it is what let them coexist one
    /// rule at a time instead of all 193 at once. The last site converted, so
    /// the default went with it: a rule that declares nothing can now report
    /// nothing, and the compiler says so at the rule rather than a gate saying
    /// it at the catalogue.
    fn violations(&self) -> &'static [&'static ViolationDef];

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
            "Rule '{}' missing configuration. Add:\n[rules.{}]\nenabled = true",
            rule,
            rule
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

/// Check the whole lint configuration: the `[rules.*]` tables this is named
/// for, and the `[violations.*]` overrides beside them.
///
/// One entry point rather than two, because a second function is a second
/// thing every caller has to remember — the proxy, the offline `lint`
/// subcommand and [`crate::engine::PreparedEngine::new`] each call this once
/// and get everything. A caller that validated only half would start under a
/// configuration naming a defect that does not exist.
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

            // A `severity` under `[rules.*]` is refused rather than ignored.
            // The key was required until severity became a violation's, and a
            // configuration that still carries one is asking for something this
            // engine no longer does: every finding reports at the level its
            // defect names. Accepting it silently would leave an operator
            // believing a rule had been turned down. This tree refuses a
            // configured name that matches no rule for the same reason, in the
            // same words — breaking by decision, never aliased.
            if table.contains_key("severity") {
                return Err(anyhow::anyhow!(
                    "Rule '{}' carries a 'severity' key, which no longer exists: severity is configured per violation. Remove the key, and use [violations.<id>] severity = \"...\" for the defects this rule reports — `docs/rules/{}.md` lists them",
                    rule_name,
                    rule_name
                ));
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

    validate_violation_overrides(config)?;

    // Per-rule validation: every enabled rule parses its own config section so
    // a malformed section (including custom fields) fails fast at startup.
    // Last, because it is the only part that runs rule code.
    for rule in all_rules() {
        if config.is_enabled(rule.id()) {
            rule.prepare(config).map_err(|e| {
                anyhow::anyhow!("Invalid configuration for rule '{}': {}", rule.id(), e)
            })?;
        }
    }
    Ok(())
}

/// Check every `[violations.<id>]` table: it sets a severity, it sets nothing
/// else, and it names a defect in the catalogue.
///
/// Stricter than the rule tables in the one way that matters here. A rule's
/// table is required and carries the rule's own options, so an unknown key is
/// the rule's business and its `prepare` judges it; a violation's table is
/// optional, exists only to disagree with a default, and has exactly one key.
/// An unrecognised key in it is therefore always a mistake — and one mistake
/// in particular, `enabled = false`, would otherwise look like it worked.
fn validate_violation_overrides(config: &crate::config::Config) -> anyhow::Result<()> {
    for (id, value) in &config.violations {
        let Some(table) = value.as_table() else {
            return Err(anyhow::anyhow!(
                "Violation '{}' configuration must be a table",
                id
            ));
        };
        // First, because the key most likely to be here is one that will never
        // be: `[violations.<id>] enabled = false`. Judged before the severity
        // is missed, so that section hears why it cannot work rather than that
        // it forgot a key it never meant to write.
        for key in table.keys() {
            if key != "severity" {
                return Err(anyhow::anyhow!(
                    "Unknown key '{}' for violation '{}': a violation table configures \
                     'severity' only. A single defect cannot be switched off — most rules \
                     report their first finding and stop, so silencing one would silence \
                     whatever the same branch would have said next. Set severity = \"info\" \
                     and report with --min-severity warn instead",
                    key,
                    id
                ));
            }
        }
        match table.get("severity") {
            Some(toml::Value::String(s)) if crate::lint::Severity::from_name(s).is_some() => {}
            Some(toml::Value::String(s)) => {
                return Err(anyhow::anyhow!(
                    "Invalid severity '{}' for violation '{}': must be one of 'info', 'warn', \
                     'error'",
                    s,
                    id
                ));
            }
            Some(_) => {
                return Err(anyhow::anyhow!(
                    "Invalid severity for violation '{}': must be a string 'info', 'warn', or \
                     'error'",
                    id
                ));
            }
            // Required *within* a table that was written, though the table
            // itself is optional: the only thing it can say is a severity, so
            // one that says nothing is a section its author expected to do
            // something.
            None => {
                return Err(anyhow::anyhow!(
                    "Missing required 'severity' key for violation '{}'. A violation table \
                     overrides the default severity on its catalogue entry, and has nothing \
                     else to say",
                    id
                ));
            }
        }
        // Last, so that a well-formed section naming nothing is the error an
        // operator hears about a typo — and a malformed one is judged on its
        // shape whichever name it carries. Same order the rule tables are
        // checked in, for the same reason.
        if !crate::violations::VIOLATIONS.iter().any(|def| def.id == id) {
            return Err(anyhow::anyhow!(
                "Configuration names a violation '{}' that does not exist. A violation is one \
                 defect a rule reports, not the rule itself; every violation id is listed in \
                 config_example.toml",
                id
            ));
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

[rules.host_header]
enabled = true
severity = "warn"
"#,
        "host_header",
        "severity is configured per violation"
    )]
    #[case(
        r#"[general]
listen = "127.0.0.1:3000"
captures = "captures.jsonl"

[tls]
enabled = false

[rules.some_rule]
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
            // A rule that declares no defect reports none: every finding goes
            // through `report`/`report_with`, and both resolve against this
            // list. The trait has no default for it any more, so this catches
            // the one shape the compiler cannot — an explicit `&[]`.
            assert!(
                !r.violations().is_empty(),
                "{} declares no violation",
                r.id()
            );
            let _ = r.examples();
            let _ = r.title();
        }
    }

    /// A rule builds findings through [`RuleContext::report`] and
    /// [`report_with`](RuleContext::report_with), never a struct literal.
    ///
    /// **What the helper guarantees has grown since this test was written.** It
    /// used to be that `Violation.rule` is the rule's own id, and that a new
    /// field on `Violation` gets a default in one place instead of 600 compile
    /// errors. Now it is also that every finding *names a defect* — the id, the
    /// configured severity and the citation all come off the def, and a literal
    /// would be a finding with none of them.
    ///
    /// Enforced by scanning the sources because privatizing the struct's
    /// fields would break every legitimate read downstream. `-> Violation {` is
    /// a return type and not a literal, which is the one shape the scan
    /// permits.
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
                        "{}:{}: findings are built with ctx.report/report_with, not a struct literal",
                        path.display(),
                        i + 1
                    );
                }
            }
        }
        Ok(())
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

    /// Every way a `[violations.<id>]` section can be wrong, in the order they
    /// are judged: a table that is not one, a section that says nothing, a
    /// severity that is not a string or not a name, and last a name the
    /// catalogue does not have.
    #[test]
    fn validate_rules_rejects_a_malformed_violation_table() {
        let section = |value: toml::Value| {
            let mut cfg = crate::config::Config::default();
            cfg.violations.insert("some_defect".to_string(), value);
            validate_rules(&cfg)
                .expect_err("a malformed violation table must fail validation")
                .to_string()
        };

        let msg = section(toml::Value::String("error".into()));
        assert!(msg.contains("must be a table"), "{msg}");

        let mut table = toml::map::Map::new();
        let msg = section(toml::Value::Table(table.clone()));
        assert!(msg.contains("Missing required 'severity'"), "{msg}");

        table.insert("severity".to_string(), toml::Value::Boolean(true));
        let msg = section(toml::Value::Table(table.clone()));
        assert!(msg.contains("must be a string"), "{msg}");

        table.insert(
            "severity".to_string(),
            toml::Value::String("shouting".into()),
        );
        let msg = section(toml::Value::Table(table.clone()));
        assert!(msg.contains("Invalid severity 'shouting'"), "{msg}");

        table.insert("severity".to_string(), toml::Value::String("error".into()));
        let msg = section(toml::Value::Table(table));
        assert!(msg.contains("does not exist"), "{msg}");
        assert!(msg.contains("some_defect"), "{msg}");
    }

    /// The unknown-key arm exists for one key in particular: a defect cannot be
    /// switched off on its own, and `enabled = false` is what someone reaches
    /// for first. Accepting and ignoring it would leave the defect reporting
    /// under a configuration that says it does not.
    ///
    /// Written alone, which is how it would actually be written, so this also
    /// pins the arm's position: judged before the missing severity, or the
    /// section hears that it forgot a key it never meant to write.
    #[test]
    fn validate_rules_rejects_switching_one_violation_off() {
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(false));
        let mut cfg = crate::config::Config::default();
        cfg.violations
            .insert("some_defect".to_string(), toml::Value::Table(table));
        let err = validate_rules(&cfg).expect_err("a violation has no enabled flag");
        let msg = err.to_string();
        assert!(msg.contains("Unknown key 'enabled'"), "{msg}");
        assert!(msg.contains("--min-severity"), "{msg}");
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
    fn validate_rules_enabled_not_bool_errors() {
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Integer(1));
        cfg.rules
            .insert("r_enabled_bad".into(), toml::Value::Table(table));

        let res = validate_rules(&cfg);
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("Invalid 'enabled'"));
    }

    #[test]
    fn validate_rules_missing_enabled_key_errors() {
        let mut cfg = crate::config::Config::default();
        cfg.rules.insert(
            "r_missing_enabled".into(),
            toml::Value::Table(toml::map::Map::new()),
        );

        let res = validate_rules(&cfg);
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .to_string()
            .contains("Missing required 'enabled' key"));
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
"#
            }

            // Required of every rule since the flag day, and a fixture is no
            // exception: this one reports nothing, and says so.
            fn violations(&self) -> &'static [&'static ViolationDef] {
                &[]
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

    /// The default `prepare` resolves nothing at all now, which is the whole
    /// of what it has to say: it validated a severity and carried it forward
    /// until severity became a violation's, and what is left is the `enabled`
    /// check and a unit state.
    #[test]
    fn default_prepare_resolves_unit_state() -> anyhow::Result<()> {
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&["host_header"]);
        let rule = RULES
            .iter()
            .find(|r| r.id() == "host_header")
            .expect("host_header registered");
        let resolved = rule.prepare(&cfg)?;
        let ctx = RuleContext::new(&resolved);
        let _: &() = ctx.state::<()>();
        Ok(())
    }

    /// A rule table with no `enabled` is the one thing the default `prepare`
    /// still refuses. A missing `severity` used to be the other, and a table
    /// carrying one now fails earlier, in `validate_rules`.
    #[test]
    fn default_prepare_rejects_a_table_without_enabled() {
        let mut cfg = crate::config::Config::default();
        cfg.rules.insert(
            "host_header".to_string(),
            toml::Value::Table(toml::map::Map::new()),
        );
        let rule = RULES
            .iter()
            .find(|r| r.id() == "host_header")
            .expect("host_header registered");
        assert!(rule.prepare(&cfg).is_err());
    }

    /// A defect that always reads the same way, and cites the sentence it
    /// enforces. `static`, like every def: the address is what
    /// `RuleContext::report` resolves against.
    static FIXED: ViolationDef = ViolationDef {
        id: "test_fixture_defect_fixed",
        title: "A defect with one wording",
        message: "the fixture is malformed",
        default_severity: crate::lint::Severity::Warn,
        spec: &[SpecRef {
            spec: "RFC 0000",
            section: Some("1"),
            url: "https://example.com/",
            note: "",
        }],
    };

    /// A defect whose wording names what caused it, so the message is formatted
    /// at the site and the def holds none.
    static PARAMETERISED: ViolationDef = ViolationDef {
        id: "test_fixture_defect_parameterised",
        title: "A defect that names its value",
        message: "",
        default_severity: crate::lint::Severity::Error,
        spec: &[],
    };

    /// What a rule's `violations()` returns: a named `static`, because an
    /// array of references to statics is not const-promotable and the inline
    /// form would not typecheck as `'static`.
    static DECLARED: &[&ViolationDef] = &[&FIXED, &PARAMETERISED];

    /// A rule that declares the two above. Nothing in the catalogue declares
    /// any defect yet, and these two are deliberately not registered: what is
    /// under test is the reporting path, not the catalogue's contents.
    struct ReportingRule;

    impl RuleMeta for ReportingRule {
        fn id(&self) -> &'static str {
            "test_fixture_reporting_rule"
        }

        fn config_example(&self) -> &'static str {
            "enabled = true\n"
        }

        fn violations(&self) -> &'static [&'static ViolationDef] {
            DECLARED
        }
    }

    /// Build the context a dispatch would hand `ReportingRule`, with the
    /// severity table the caller wants to prove was consulted.
    fn reporting_context<'a>(
        resolved: &'a ResolvedRule,
        severities: &'a [crate::lint::Severity],
    ) -> RuleContext<'a> {
        RuleContext::new(resolved).with_violations(&ReportingRule, severities)
    }

    fn unit_resolved() -> ResolvedRule {
        ResolvedRule {
            state: Box::new(()),
        }
    }

    /// A report takes its wording, its citation and its rule from the def and
    /// the context — and its severity from the table, not from the def's
    /// default and not from the rule-wide `ctx.severity`. Those three are
    /// deliberately different values here, which is the whole point of the
    /// split: one rule, one dispatch, two defects at two levels.
    #[test]
    fn report_builds_a_finding_from_the_declared_def() {
        let resolved = unit_resolved();
        let severities = [crate::lint::Severity::Error, crate::lint::Severity::Info];
        let ctx = reporting_context(&resolved, &severities);

        let v = ctx.report(&FIXED);
        assert_eq!(v.rule, "test_fixture_reporting_rule");
        assert_eq!(v.message, "the fixture is malformed");
        assert_eq!(v.severity, crate::lint::Severity::Error);
        let cite = v.cite.expect("the def's spec is carried onto the finding");
        assert_eq!(cite.spec, "RFC 0000");
        assert_eq!(cite.section.as_deref(), Some("1"));

        let other = ctx.report_with(&PARAMETERISED, "the fixture said 42".to_string());
        assert_eq!(other.message, "the fixture said 42");
        assert_eq!(other.severity, crate::lint::Severity::Info);
        assert!(other.cite.is_none(), "an unread sentence is carried absent");
    }

    /// The identity lookup, from the other side: a def the rule does not
    /// declare has no configured severity, so reporting it is a wiring error
    /// rather than a finding at a guessed level.
    #[test]
    #[should_panic(expected = "may only report a violation the rule declares")]
    fn report_refuses_a_violation_the_rule_does_not_declare() {
        static FOREIGN: ViolationDef = ViolationDef {
            id: "test_fixture_defect_foreign",
            title: "A defect belonging to some other rule",
            message: "not this rule's to report",
            default_severity: crate::lint::Severity::Warn,
            spec: &[],
        };
        let resolved = unit_resolved();
        let severities = [crate::lint::Severity::Warn, crate::lint::Severity::Warn];
        let _ = reporting_context(&resolved, &severities).report(&FOREIGN);
    }

    /// A context built without a catalogue declares nothing, which is what
    /// makes the same wiring error out of reporting through one.
    #[test]
    #[should_panic(expected = "may only report a violation the rule declares")]
    fn a_context_without_violations_declares_none() {
        let resolved = unit_resolved();
        let _ = RuleContext::new(&resolved).report(&FIXED);
    }

    /// Emitting a parameterised def through `report` would emit its empty
    /// message — a finding that says nothing, at the right severity, which is
    /// the failure most likely to survive a test that only counts findings.
    #[test]
    #[should_panic(expected = "holds no message of its own")]
    fn report_refuses_a_def_whose_message_is_formatted_at_the_site() {
        let resolved = unit_resolved();
        let severities = [crate::lint::Severity::Warn, crate::lint::Severity::Warn];
        let _ = reporting_context(&resolved, &severities).report(&PARAMETERISED);
    }

    /// And the inverse: a def that holds its whole message is not one a site
    /// may reword, or the catalogue no longer says what the operator reads.
    #[test]
    #[should_panic(expected = "holds its own message")]
    fn report_with_refuses_a_def_that_holds_its_own_message() {
        let resolved = unit_resolved();
        let severities = [crate::lint::Severity::Warn, crate::lint::Severity::Warn];
        let _ = reporting_context(&resolved, &severities).report_with(&FIXED, "reworded".into());
    }

    /// The table is the defs' own defaults, in declaration order — the order
    /// the index lookup depends on. A configuration that names no violation
    /// resolves the whole catalogue, which is what the defaults are for.
    #[test]
    fn severities_default_to_the_catalogue_in_declaration_order() {
        assert_eq!(
            severities_for(&ReportingRule, &crate::config::Config::default()),
            vec![crate::lint::Severity::Warn, crate::lint::Severity::Error],
        );
    }

    /// One defect of a rule reconfigured, the other left alone — the split the
    /// catalogue exists for. Under the rule-wide severity these two could only
    /// ever have said the same thing.
    #[test]
    fn a_violation_table_overrides_that_defects_default_alone() {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::override_violation_severity(
            &mut cfg,
            "test_fixture_defect_fixed",
            "info",
        );
        assert_eq!(
            severities_for(&ReportingRule, &cfg),
            vec![crate::lint::Severity::Info, crate::lint::Severity::Error],
        );

        let resolved = unit_resolved();
        let severities = severities_for(&ReportingRule, &cfg);
        let v = reporting_context(&resolved, &severities).report(&FIXED);
        assert_eq!(v.severity, crate::lint::Severity::Info);
        assert_eq!(
            v.violation, "test_fixture_defect_fixed",
            "a report names the defect it reports, and that is the name the table used",
        );
    }

    /// A section naming a defect this rule does not declare changes nothing
    /// about it. Resolution is per violation id, not per rule, so the two
    /// rules that report one defect are configured together and a rule that
    /// does not report it is untouched.
    #[test]
    fn a_section_for_a_defect_the_rule_never_declared_changes_nothing() {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::override_violation_severity(
            &mut cfg,
            "test_fixture_defect_foreign",
            "info",
        );
        assert_eq!(
            severities_for(&ReportingRule, &cfg),
            vec![crate::lint::Severity::Warn, crate::lint::Severity::Error],
        );
    }

    /// Validation refuses a malformed table before an engine exists, so the
    /// resolver never sees one — and if it somehow did, the defect is still
    /// reported at its author's level rather than dropped or guessed.
    #[test]
    fn an_unreadable_override_falls_back_to_the_defs_default() {
        let mut cfg = crate::config::Config::default();
        cfg.violations.insert(
            "test_fixture_defect_fixed".to_string(),
            toml::Value::Boolean(true),
        );
        crate::test_helpers::override_violation_severity(
            &mut cfg,
            "test_fixture_defect_parameterised",
            "shouting",
        );
        assert_eq!(
            severities_for(&ReportingRule, &cfg),
            vec![crate::lint::Severity::Warn, crate::lint::Severity::Error],
        );
    }

    /// A rule may not list the same defect twice. The lookup answers with the
    /// *first* matching index, so a repeat would be a def whose configured
    /// severity is unreachable — the entry is there, the operator's setting
    /// for it is read, and the finding comes out at the other copy's level.
    /// Nothing else would notice.
    ///
    /// Both halves are checked because they fail differently: two entries
    /// pointing at one `static` is the copy-paste, and two defs sharing an id
    /// is the rename that half-landed. The catalogue is empty, so this asserts
    /// nothing yet and starts asserting the moment a rule declares anything.
    #[test]
    fn a_rule_declares_each_violation_once() {
        for rule in all_rules() {
            let declared = rule.violations();
            let mut ids = std::collections::HashSet::new();
            for (i, def) in declared.iter().enumerate() {
                assert!(
                    !declared[..i].iter().any(|d| std::ptr::eq(*d, *def)),
                    "{} declares {} twice",
                    rule.id(),
                    def.id,
                );
                assert!(
                    ids.insert(def.id),
                    "{} declares two violations named {}",
                    rule.id(),
                    def.id,
                );
            }
        }
    }

    /// The defects more than one rule reports, counted and named.
    ///
    /// This is the overlap the split was opened against, measured from the far
    /// side of it. Before the catalogue it could only be counted as *message
    /// templates* — 14 exact strings emitted by two or more rules over 70
    /// sites, one non-UTF-8 `Authorization` header drawing five byte-identical
    /// findings under five rule ids, and nothing in the type system able to say
    /// they were one defect. They share an id now, so the question has an
    /// answer that survives a reworded message, and the answer is **109**:
    /// seven and a half times what the template count could see.
    ///
    /// **The difference is not overlap that appeared; it is overlap that
    /// became visible.** A template count compares strings, so it sees two
    /// rules as duplicating only where they duplicate down to the wording.
    /// Most of these 109 are a *shared reader*: `token_character_forbidden` is
    /// declared by 42 rules because 42 rules parse a token, and each of them
    /// formatted its own sentence about it. That is the split working — one
    /// defect, one id, one severity to tune it with — and those 42 rules read
    /// 42 different fields and will never merge.
    ///
    /// So this is a ceiling and not a countdown. It falls when a merge lands.
    /// It rises only for a rule that reaches for a reader an existing rule
    /// already uses, which is a commit that should have to say so — the number
    /// here is the count of defects an operator can be shown twice for one
    /// seam, and Phase 5's dedup is sized by it.
    #[test]
    fn no_violation_is_emitted_by_two_rules() {
        /// Read from what the assertion prints, never incremented.
        const CEILING: usize = 109;

        let mut declarers: std::collections::BTreeMap<&str, Vec<&str>> =
            std::collections::BTreeMap::new();
        for rule in all_rules() {
            for def in rule.violations() {
                declarers.entry(def.id).or_default().push(rule.id());
            }
        }
        let shared: Vec<String> = declarers
            .iter()
            .filter(|(_, rules)| rules.len() > 1)
            .map(|(id, rules)| format!("  {id}: {}", rules.join(", ")))
            .collect();
        assert!(
            shared.len() <= CEILING,
            "{} defects are reported by more than one rule, above the ceiling of {CEILING}:\n{}",
            shared.len(),
            shared.join("\n"),
        );
    }

    /// Two rules that declare the *same set* of defects — the narrowest
    /// reading of overlap this catalogue can take, and the closest thing to a
    /// merge signal that is a measurement rather than a judgment.
    ///
    /// The gate above cannot be that signal: by its number every pair of rules
    /// that parses a token overlaps. Neither can a subset relation — a rule
    /// reporting nothing but token defects is a subset of all 42 that read one,
    /// which is 164 pairs of noise. Equality is what is left, and it says
    /// something the other two do not: everything one rule reports, the other
    /// reports, so nothing an operator can *tune* tells the two apart.
    ///
    /// **It read five pairs when it was written and only two of them were
    /// merges, which was the finding.** The two were the ones already first in
    /// the merge order — the `If-Match`/`If-None-Match` pair, now merged into
    /// `conditional_etag_syntax`, and the two conditional-date rules — where
    /// the fields are a request pair with one grammar between them, so one rule
    /// reads both. The other three read *different* fields with the
    /// same reader: `Allow` and `Vary` are both token lists,
    /// `Cache-Control` and `Pragma` both directive lists, `Server` and
    /// `User-Agent` both product assemblies. Merging either of those would put
    /// two fields under one rule id and one `enabled` flag, for no reason
    /// except that the reader they share has nothing further to say about
    /// them. *What distinguishes them is the field the message names, and a
    /// field is a parameter of the message rather than a property of the
    /// defect* — which is why the equality is exact and the conclusion still
    /// is not.
    ///
    /// So this is a ceiling too, and its floor is three rather than zero. What
    /// the number is for is the review: a sixth pair is either a merge waiting
    /// or a rule written by copying one that already reported everything it
    /// reports, and both want reading before they land.
    #[test]
    fn no_two_rules_declare_the_same_defects() {
        /// Lowered by each merge, of which one is left. Read from what the
        /// assertion prints, never incremented.
        const CEILING: usize = 4;

        let declared: std::collections::BTreeMap<&str, std::collections::BTreeSet<&str>> =
            all_rules()
                .map(|rule| (rule.id(), rule.violations().iter().map(|d| d.id).collect()))
                .collect();
        let rules: Vec<&str> = declared.keys().copied().collect();
        let twins: Vec<String> = rules
            .iter()
            .enumerate()
            .flat_map(|(i, a)| {
                rules[i + 1..]
                    .iter()
                    .filter(|b| declared[a] == declared[**b])
                    .map(move |b| format!("  {a} and {b} declare the same defects"))
            })
            .collect();
        assert!(
            twins.len() <= CEILING,
            "{} rule pairs declare the same defects, above the ceiling of {CEILING}:\n{}",
            twins.len(),
            twins.join("\n"),
        );
    }

    #[test]
    fn rule_context_state_roundtrips_the_prepared_type() {
        let resolved = ResolvedRule {
            state: Box::new(vec!["utf-8".to_string()]),
        };
        let ctx = RuleContext::new(&resolved);
        assert_eq!(ctx.state::<Vec<String>>(), &vec!["utf-8".to_string()]);
    }

    #[test]
    #[should_panic(expected = "rule state wiring")]
    fn rule_context_state_mismatch_panics() {
        let resolved = ResolvedRule {
            state: Box::new(()),
        };
        let ctx = RuleContext::new(&resolved);
        let _ = ctx.state::<Vec<String>>();
    }

    #[test]
    fn protocol_rule_default_prepare_succeeds() -> anyhow::Result<()> {
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["websocket_frame_masking"]);
        let rule = PROTOCOL_RULES
            .iter()
            .find(|r| r.id() == "websocket_frame_masking")
            .expect("websocket_frame_masking registered");
        rule.prepare(&cfg)?;
        Ok(())
    }

    /// A rule table with no `enabled` is refused, and `is_enabled` reads the
    /// missing flag as `false` — so the rule is one `PreparedEngine` refuses to
    /// build over, and would never dispatch even if it did. The test is named
    /// for the table it was written about, which carried a `severity` and
    /// nothing else; that key is refused on sight now, so what is left to be
    /// short of is the flag.
    #[test]
    fn a_table_without_enabled_is_refused_and_never_dispatched() {
        let mut without_enabled = crate::config::Config::default();
        without_enabled.rules.insert(
            "cache_control_present".into(),
            toml::Value::Table(toml::map::Map::new()),
        );
        assert!(validate_rule_table(&without_enabled, "cache_control_present").is_err());
        assert!(!without_enabled.is_enabled("cache_control_present"));

        // A configuration with no table for the rule at all is refused too.
        let empty = crate::config::Config::default();
        assert!(validate_rule_table(&empty, "cache_control_present").is_err());
    }

    #[test]
    fn get_rule_enabled_required_success() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        cfg.rules
            .insert("test_rule".into(), toml::Value::Table(table));

        assert!(get_rule_enabled_required(&cfg, "test_rule")?);
        Ok(())
    }

    /// A retired key is refused rather than ignored, and the error says where
    /// severity went. An operator whose file still carries one is asking for a
    /// rule to be turned down, and silence would let them believe it was.
    #[test]
    fn a_rule_table_carrying_a_severity_is_refused() {
        // Whatever the value is: the key itself is what no longer exists, so
        // there is nothing left for a type check to be a better error than.
        for value in [
            toml::Value::String("warn".into()),
            toml::Value::String("shouting".into()),
            toml::Value::Integer(1),
        ] {
            let mut cfg = crate::config::Config::default();
            let mut table = toml::map::Map::new();
            table.insert("enabled".to_string(), toml::Value::Boolean(true));
            table.insert("severity".to_string(), value);
            cfg.rules
                .insert("host_header".into(), toml::Value::Table(table));

            let msg = validate_rules(&cfg)
                .expect_err("a retired key must fail validation")
                .to_string();
            assert!(msg.contains("host_header"), "{msg}");
            assert!(
                msg.contains("severity is configured per violation"),
                "{msg}"
            );
            assert!(msg.contains("[violations."), "{msg}");
        }
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
