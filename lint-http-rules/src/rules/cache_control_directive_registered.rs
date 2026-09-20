// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::helpers::headers::combined_field_value_as_written;
use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::cache_control::{
    CACHE_CONTROL_DIRECTIVE_UNREGISTERED, RFC_9111_5_2, RFC_9111_5_2_3, RFC_9111_5_2_4,
};
use crate::violations::ViolationDef;

pub struct CacheControlDirectiveRegistered;

/// One entry, and it is the only thing this rule can say.
///
/// Everything about the *shape* of a member — an empty list element, a name
/// that is no `token`, an argument the directive does not take — belongs to
/// `cache_control_directive_valid` and `cache_control_token_valid`, which read
/// the same list under the same scope. What is left over is the one question
/// neither of them asks: whether the name identifies a directive at all.
static DECLARED: &[&ViolationDef] = &[&CACHE_CONTROL_DIRECTIVE_UNREGISTERED];

/// What the rule reads out of its configuration.
///
/// Directive names, held folded to lowercase because § 5.2 compares them that
/// way. The fold happens once here rather than at every comparison below, and
/// the entries are stored rather than borrowed because the config outlives no
/// particular walk.
#[derive(Debug, Clone)]
pub struct CacheControlDirectiveConfig {
    pub allowed: Vec<String>,
}

/// The list is required and the shipped default is the registry as it stood
/// when this was written.
///
/// **The namespace is closed in a way the linter's other registry lists are
/// not.** RFC 7301 § 6 hands the ALPN registry to a designated expert, so
/// `alt_svc_protocol_registered` cannot ship a list and asks an operator what
/// the deployment serves instead. § 5.2.4 puts this namespace under IETF
/// Review, which means a new directive arrives with an RFC and not between
/// two of them — so a snapshot is defensible here, and the shipped list is the
/// whole registry rather than a guess at one deployment.
///
/// It stays configuration all the same, for the case the registry exists to
/// permit: a deployment running a private extension its own caches implement.
/// Adding the name says those caches recognise it, which is exactly the claim
/// the finding rests on.
// cite(RFC 9111 § 5.2.4): "Values to be added to this namespace require IETF Review (see [RFC8126], Section 4.8)."
fn parse_allowed_config(
    config: &crate::config::Config,
    rule_id: &str,
) -> anyhow::Result<CacheControlDirectiveConfig> {
    let rule_cfg = config
        .get_rule_config(rule_id)
        .expect("internal error: rule config missing after validation");
    let table = rule_cfg
        .as_table()
        .ok_or_else(|| anyhow::anyhow!("Configuration for rule '{}' must be a table", rule_id))?;

    let allowed_val = table.get("allowed").ok_or_else(|| {
        anyhow::anyhow!(
            "Rule '{}' requires an 'allowed' array listing the Cache-Control directive names caches on this path implement (e.g., ['max-age','no-store'])",
            rule_id
        )
    })?;

    let arr = allowed_val.as_array().ok_or_else(|| {
        anyhow::anyhow!("'allowed' must be an array of strings (e.g., ['max-age','no-store'])")
    })?;

    if arr.is_empty() {
        return Err(anyhow::anyhow!("'allowed' array cannot be empty"));
    }

    let mut out = Vec::new();
    for (i, item) in arr.iter().enumerate() {
        let s = item.as_str().ok_or_else(|| {
            anyhow::anyhow!("'allowed' array item at index {} must be a string", i)
        })?;
        // A directive is named by a `token`, and `token` is `1*tchar`: the
        // empty string names none. Rejected at configuration time rather than
        // silently never matching, because an empty entry in this list is a
        // typo that would otherwise widen nothing and say nothing.
        // cite(RFC 9111 § 5.2): "cache-directive = token [ "=" ( token / quoted-string ) ]"
        if s.is_empty() {
            return Err(anyhow::anyhow!(
                "'allowed' array item at index {} is the empty string, which names no directive: a cache directive is identified by a `token`",
                i
            ));
        }
        if let Some(c) = crate::helpers::token::find_invalid_token_char(s) {
            return Err(anyhow::anyhow!(
                "'allowed' array item at index {} is '{}', which holds {:?} — a cache directive is identified by a `token` and no field could ever carry this name",
                i,
                s,
                c
            ));
        }
        // Folded once, here. § 5.2 compares directive names case-insensitively,
        // so `NO-STORE` on the wire is `no-store`, and a list written in any
        // case means the same thing.
        // cite(RFC 9111 § 5.2): "Cache directives are identified by a token, to be compared case-insensitively"
        out.push(s.to_ascii_lowercase());
    }

    Ok(CacheControlDirectiveConfig { allowed: out })
}

impl RuleMeta for CacheControlDirectiveRegistered {
    fn id(&self) -> &'static str {
        "cache_control_directive_registered"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
# The "Hypertext Transfer Protocol (HTTP) Cache Directive Registry", which RFC
# 9111 § 5.2.4 says defines the namespace for cache directives. A name outside
# it is one every cache MUST ignore, so what the sender asked for does not
# happen — `s-max-age=150` beside `max-age=300` gives shared caches 300.
#
# Unlike the ALPN list next door, this one ships complete: § 5.2.4 puts the
# namespace under IETF Review, so a directive arrives with an RFC rather than
# between two of them. The 16 below are the whole registry — RFC 9111's
# fourteen, RFC 5861's two — plus RFC 8246's `immutable`.
#
# Extend it where a deployment runs a private directive its own caches
# implement. Adding a name here is the claim that something on this path acts
# on it, which is the claim the finding rests on.
allowed = [
    "max-age",
    "max-stale",
    "min-fresh",
    "must-revalidate",
    "must-understand",
    "no-cache",
    "no-store",
    "no-transform",
    "only-if-cached",
    "private",
    "proxy-revalidate",
    "public",
    "s-maxage",
    "immutable",
    "stale-if-error",
    "stale-while-revalidate",
]
"#
    }

    fn prepare(&self, cfg: &crate::config::Config) -> anyhow::Result<crate::rules::ResolvedRule> {
        let config = parse_allowed_config(cfg, self.id())?;
        // The two standard keys, **after** this rule's own options, so a config
        // naming a bad option still fails on that option.
        crate::rules::validate_rule_table(cfg, self.id())?;
        Ok(crate::rules::ResolvedRule {
            state: Box::new(config),
        })
    }

    fn title(&self) -> Option<&'static str> {
        Some("Cache-Control Directive IANA-Registered")
    }

    fn description(&self) -> &'static str {
        "Read each `Cache-Control` directive name and ask whether it identifies a directive any cache implements.\n\n**A cache MUST ignore what it does not recognise**, which is what makes this worth reporting rather than tolerating. RFC 9111 §5.2.3 says *\"A cache MUST ignore unrecognized cache directives\"*, so an unregistered name is not a weaker instruction — it is no instruction at all, and every cache on the path behaves as though the sender had written nothing. `Cache-Control: public, max-age=300, s-max-age=150` asks shared caches for 150 seconds and gets 300, because `s-maxage` is the registered name and `s-max-age` is one hyphen away from it.\n\n**The list ships complete, and stays configuration anyway.** RFC 9111 §5.2.4 puts the *\"Hypertext Transfer Protocol (HTTP) Cache Directive Registry\"* under IETF Review, so a new directive arrives with an RFC rather than between two of them — which is why the default is the whole registry, where `alt_svc_protocol_registered` next door can only ask an operator what its deployment serves. A deployment running a private extension its own caches implement adds the name, and that addition is exactly the claim the finding rests on.\n\n**The comparison folds case and nothing else.** §5.2 says directives are *\"identified by a token, to be compared case-insensitively\"*, so `NO-STORE` is `no-store` here as it is in every cache. The argument is not read at all: whether `max-age` carries digits is the directive's own syntax and `cache_control_directive_valid`'s question.\n\n**What this rule declines.** Everything that is the field's grammar rather than its namespace: an empty list element, a directive name that is no `token`, a name holding whitespace or a control character. `cache_control_directive_valid` and `cache_control_token_valid` read the same list under the same scope and report all three, so a member this rule cannot name a directive from is passed over rather than reported twice. Both sides of the exchange are read, because §5.2 lists directives for caches along the request/response chain and a client writing `only-if-cachd` has made the same mistake an origin does."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_9111_5_2, RFC_9111_5_2_3, RFC_9111_5_2_4]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::PerSite
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "Cache-Control: public, max-age=300, s-maxage=150",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(the registry is not RFC 9111 alone)"),
                snippet: "Cache-Control: max-age=600, immutable, stale-while-revalidate=30",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(names are compared case-insensitively)"),
                snippet: "Cache-Control: NO-STORE",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— `s-maxage` is the name; shared caches use max-age=300 instead"),
                snippet: "Cache-Control: public, max-age=300, s-max-age=150",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— two directives no cache has ever implemented"),
                snippet: "Cache-Control: no-cache, post-check=0, pre-check=0",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— a request directive is a directive too"),
                snippet: "GET / HTTP/1.1\nHost: example.com\nCache-Control: only-if-cachd",
            },
        ]
    }
}

impl Rule for CacheControlDirectiveRegistered {
    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // One finding per section. Both halves of the exchange carry this field
        // and neither is evidence about the other: a client that misspells a
        // request directive and an origin that misspells a response one have
        // made two mistakes, in two messages, with two senders to tell.
        // cite(RFC 9111 § 5.2): "The "Cache-Control" header field is used to list directives for caches along the request/response chain."
        let mut out = self.unregistered_in(
            &tx.request.headers,
            "request",
            crate::lint::Party::Client,
            ctx,
        );
        if let Some(resp) = &tx.response {
            out.extend(self.unregistered_in(
                &resp.headers,
                "response",
                crate::lint::Party::Server,
                ctx,
            ));
        }
        out
    }
}

impl CacheControlDirectiveRegistered {
    /// Every directive in one section that names nothing a cache implements.
    ///
    /// **One finding per directive, not per field.** `Cache-Control:
    /// #cache-directive` puts each name beside the others, so a value carrying
    /// `post-check=0, pre-check=0` is two names to take out and an operator who
    /// removed one would still be sending the other.
    // cite(RFC 9111 § 5.2): "Cache-Control   = #cache-directive"
    fn unregistered_in(
        &self,
        headers: &hyper::HeaderMap,
        side: &str,
        party: crate::lint::Party,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // Read as octets and over the whole section. A directive name holding an
        // octet outside visible US-ASCII is a `token` defect the rules beside
        // this one report, and `to_str` would fold the whole field into "no such
        // field here" — dropping every well-formed directive next to the
        // offending one along with it.
        // cite(RFC 9110 § 5.3): "A recipient MAY combine multiple field lines within a field section that have the same field name into one field line, without changing the semantics of the message, by appending each subsequent field line value to the initial field line value in order, separated by a comma (",") and optional whitespace (OWS, defined in Section 5.6.3)."
        let Some(value) = combined_field_value_as_written(headers, "cache-control") else {
            return Vec::new();
        };
        let config: &CacheControlDirectiveConfig = ctx.state();

        let mut out = Vec::new();
        for member in crate::helpers::cache_control::members_of(&value) {
            // The strict reader, so that a member this rule cannot name a
            // directive from is *declined* rather than guessed at. Its three
            // defects — an empty element, an empty name, a name holding a
            // character no `tchar` admits — are the list's and the `token`'s,
            // and the two syntax rules reading this field report every one of
            // them. A name nobody could parse is not a name nobody registered.
            let Ok(directive) = crate::helpers::cache_control::read_member(member) else {
                continue;
            };

            // cite(RFC 9111 § 5.2): "Cache directives are identified by a token, to be compared case-insensitively"
            let name = directive.name.to_ascii_lowercase();
            if config.allowed.contains(&name) {
                continue;
            }

            out.push(ctx.by(party).report_with(
                &CACHE_CONTROL_DIRECTIVE_UNREGISTERED,
                format!(
                    "Cache-Control directive '{}' in {} is in no cache's vocabulary: it names nothing in the HTTP Cache Directive Registry and nothing this deployment lists as implemented, so every cache on the path ignores it and whatever it was meant to ask for does not happen",
                    crate::helpers::shown::shown_in_finding(directive.name),
                    side
                ),
            ));
        }
        out
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &CacheControlDirectiveRegistered;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// The shipped list, which is the registry. Written out here rather than
    /// read off `config_example` so that a test asserting the registry's
    /// contents fails when the example drifts from it, instead of agreeing with
    /// whatever the example happens to say.
    const REGISTERED: &[&str] = &[
        "max-age",
        "max-stale",
        "min-fresh",
        "must-revalidate",
        "must-understand",
        "no-cache",
        "no-store",
        "no-transform",
        "only-if-cached",
        "private",
        "proxy-revalidate",
        "public",
        "s-maxage",
        "immutable",
        "stale-if-error",
        "stale-while-revalidate",
    ];

    fn registry_config() -> crate::config::Config {
        let mut cfg = crate::config::Config::default();
        cfg.rules.insert(
            "cache_control_directive_registered".into(),
            toml::Value::Table({
                let mut t = toml::value::Table::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(
                        REGISTERED
                            .iter()
                            .map(|s| toml::Value::String((*s).into()))
                            .collect(),
                    ),
                );
                t
            }),
        );
        cfg
    }

    fn findings_for(headers: &[(&str, &str)], response: bool) -> Vec<Violation> {
        use crate::test_helpers::{make_test_transaction, make_test_transaction_with_response};
        let tx = if response {
            make_test_transaction_with_response(200, headers)
        } else {
            let mut tx = make_test_transaction();
            tx.request.headers = crate::test_helpers::make_headers_from_pairs(headers);
            tx
        };
        crate::test_helpers::run_rule_all(
            &CacheControlDirectiveRegistered,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &registry_config(),
        )
    }

    fn ids(headers: &[(&str, &str)], response: bool) -> Vec<String> {
        findings_for(headers, response)
            .iter()
            .map(|v| v.violation.clone())
            .collect()
    }

    /// Every name in the registry is silent, and the three that are not RFC
    /// 9111's are in that list for a reason: the registry is the namespace, and
    /// the document is not.
    ///
    /// Without this, a list mistakenly written from RFC 9111's own §5.2
    /// subsections alone would pass every other test in this file while
    /// reporting `immutable`, `stale-if-error` and `stale-while-revalidate` on
    /// traffic that is entirely conforming — and those three are ordinary on
    /// the web, not exotic.
    #[test]
    fn no_registered_directive_is_reported() {
        for name in REGISTERED {
            let value = format!("{name}=0");
            assert!(
                ids(&[("cache-control", &value)], true).is_empty(),
                "registered directive '{name}' was reported"
            );
            assert!(
                ids(&[("cache-control", name)], true).is_empty(),
                "registered directive '{name}' was reported in its bare form"
            );
        }
    }

    /// The registry has sixteen entries and this rule's default list is all of
    /// them. A census is a claim, so it is asserted rather than described: a
    /// name dropped from the shipped list would otherwise only show up as a
    /// finding nobody expected on real traffic.
    #[test]
    fn the_shipped_list_is_the_registry() {
        let cfg = parse_allowed_config(&registry_config(), "cache_control_directive_registered")
            .expect("the shipped list parses");
        assert_eq!(cfg.allowed.len(), 16, "{:?}", cfg.allowed);

        // And `config_example` ships exactly it — the list an operator gets is
        // the list this file's tests are about.
        let example = CacheControlDirectiveRegistered.config_example();
        for name in REGISTERED {
            assert!(
                example.contains(&format!("\"{name}\"")),
                "config_example does not ship '{name}'"
            );
        }
    }

    /// The finding this entry exists for: a name one hyphen from a registered
    /// one, beside the directive it was meant to override.
    #[test]
    fn a_misspelled_directive_is_one_no_cache_implements() {
        let found = findings_for(
            &[("cache-control", "public, max-age=300, s-max-age=150")],
            true,
        );
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].violation, "cache_control_directive_unregistered");
        assert_eq!(found[0].severity, crate::lint::Severity::Warn);
        // The sentence names the value, not just the production: an operator
        // reading it has to be able to find the octets to change.
        assert!(
            found[0].message.contains("s-max-age"),
            "{}",
            found[0].message
        );
        assert!(
            found[0].message.contains("response"),
            "{}",
            found[0].message
        );
    }

    /// Each unregistered directive is its own finding, because each is its own
    /// edit. A walk that answered once per field would tell an operator to
    /// remove `post-check` and leave `pre-check` in place.
    #[test]
    fn every_unregistered_directive_in_the_value_is_named() {
        let found = findings_for(
            &[(
                "cache-control",
                "private, max-age=0, no-store, no-cache, must-revalidate, post-check=0, pre-check=0",
            )],
            true,
        );
        assert_eq!(found.len(), 2, "{found:?}");
        assert!(
            found[0].message.contains("post-check"),
            "{}",
            found[0].message
        );
        assert!(
            found[1].message.contains("pre-check"),
            "{}",
            found[1].message
        );
        assert_ne!(found[0].message, found[1].message);
    }

    /// Both halves of the exchange, and the finding says which. A request
    /// directive is a directive.
    #[test]
    fn a_request_directive_is_read_and_attributed_to_the_client() {
        let found = findings_for(&[("cache-control", "only-if-cachd")], false);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].party, Some(crate::lint::Party::Client));
        assert!(found[0].message.contains("request"), "{}", found[0].message);

        let found = findings_for(&[("cache-control", "post-check=0")], true);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].party, Some(crate::lint::Party::Server));
        assert!(
            found[0].message.contains("response"),
            "{}",
            found[0].message
        );
    }

    /// § 5.2 compares names case-insensitively, so the fold runs on both sides
    /// of the comparison and a shouted registered name is silent.
    #[rstest]
    #[case("NO-STORE")]
    #[case("No-Cache")]
    #[case("S-MaxAge=60")]
    #[case("IMMUTABLE")]
    fn a_registered_name_is_silent_in_any_case(#[case] value: &str) {
        assert!(ids(&[("cache-control", value)], true).is_empty(), "{value}");
    }

    /// And the fold does not manufacture a match either: an unregistered name
    /// stays unregistered however it is written.
    #[rstest]
    #[case("POST-CHECK=0")]
    #[case("S-Max-Age=150")]
    fn an_unregistered_name_is_reported_in_any_case(#[case] value: &str) {
        assert_eq!(
            ids(&[("cache-control", value)], true),
            ["cache_control_directive_unregistered"],
            "{value}"
        );
    }

    /// What this rule declines, and the reason it must: a member the grammar
    /// refuses is not a name anyone failed to register.
    ///
    /// The three cases are the three `read_member` refuses on — an empty list
    /// element, an `=` with no name before it, and a name holding a character
    /// no `tchar` admits. Each is reported by `cache_control_directive_valid`
    /// and `cache_control_token_valid` under the list's and the token's own
    /// ids, so reporting here would draw one edit twice under a sentence that
    /// names the wrong thing to fix.
    #[rstest]
    #[case("max-age=60,,no-store")]
    #[case("=60")]
    #[case("max age=60")]
    fn a_member_the_grammar_refuses_is_not_this_rules_finding(#[case] value: &str) {
        let found = findings_for(&[("cache-control", value)], true);
        assert!(found.is_empty(), "{value}: {found:?}");
    }

    /// An empty `Cache-Control`, and no `Cache-Control` at all. `#element`
    /// admits the zero-element list, so neither is a directive of any kind.
    #[rstest]
    #[case(Some(""))]
    #[case(None)]
    fn nothing_to_read_is_no_finding(#[case] value: Option<&str>) {
        let headers: Vec<(&str, &str)> = match value {
            Some(v) => vec![("cache-control", v)],
            None => vec![],
        };
        assert!(ids(&headers, true).is_empty(), "{value:?}");
    }

    /// The argument is not this rule's business at all. A registered directive
    /// whose argument is nonsense stays silent here and is reported by the
    /// reader that owns the directive's own syntax.
    #[test]
    fn the_argument_is_never_read() {
        assert!(ids(&[("cache-control", "max-age=abc")], true).is_empty());
        assert!(ids(&[("cache-control", "max-age=\"60\"")], true).is_empty());
    }

    /// A deployment that runs a private extension says so, and the finding
    /// goes. This is the whole reason the list is configuration and not a
    /// table: adding the name is the claim that something on this path
    /// implements it.
    #[test]
    fn a_configured_extension_is_implemented_and_so_is_silent() {
        let mut cfg = crate::config::Config::default();
        cfg.rules.insert(
            "cache_control_directive_registered".into(),
            toml::Value::Table({
                let mut t = toml::value::Table::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![
                        toml::Value::String("max-age".into()),
                        toml::Value::String("community".into()),
                    ]),
                );
                t
            }),
        );
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("cache-control", "max-age=60, community=\"UCI\"")],
        );
        let found = crate::test_helpers::run_rule_all(
            &CacheControlDirectiveRegistered,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(found.is_empty(), "{found:?}");
    }

    /// The list is required, and each way of writing it wrongly says which.
    #[rstest]
    #[case(None, "requires an 'allowed' array")]
    #[case(Some(toml::Value::String("max-age".into())), "must be an array")]
    #[case(Some(toml::Value::Array(vec![])), "cannot be empty")]
    #[case(Some(toml::Value::Array(vec![toml::Value::Integer(1)])), "must be a string")]
    #[case(Some(toml::Value::Array(vec![toml::Value::String(String::new())])), "names no directive")]
    #[case(Some(toml::Value::Array(vec![toml::Value::String("max age".into())])), "no field could ever carry this name")]
    fn a_list_that_cannot_be_read_says_why(
        #[case] allowed: Option<toml::Value>,
        #[case] expected: &str,
    ) {
        let mut cfg = crate::config::Config::default();
        cfg.rules.insert(
            "cache_control_directive_registered".into(),
            toml::Value::Table({
                let mut t = toml::value::Table::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                if let Some(v) = allowed {
                    t.insert("allowed".into(), v);
                }
                t
            }),
        );
        let err = parse_allowed_config(&cfg, "cache_control_directive_registered")
            .expect_err("expected a configuration error");
        assert!(err.to_string().contains(expected), "{err}");
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let cfg = registry_config();
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
