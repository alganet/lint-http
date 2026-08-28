// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ContentTypeRegistered;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9110_8_3_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("8.3.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3.1",
    note: "`media-type` syntax, the case-insensitivity of its tokens, and the \"ought to be registered with IANA\" guidance that motivates this rule — guidance, not a requirement, and not something this rule verifies",
};
const RFC_6838_4_2_8: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 6838",
    section: Some("4.2.8"),
    url: "https://www.rfc-editor.org/rfc/rfc6838.html#section-4.2.8",
    note: "Structured syntax suffixes — a suffix is appended to a base subtype after a `+`, which is what a `+json` allowlist entry matches",
};
const IANA_MEDIA_TYPES: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "IANA Media Types",
    section: None,
    url: "https://www.iana.org/assignments/media-types/media-types.xhtml",
    note: "The registry this rule is named after but does not read; the configured `allowed` array stands in for it",
};

impl Rule for ContentTypeRegistered {
    fn id(&self) -> &'static str {
        "content_type_registered"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn prepare(&self, cfg: &crate::config::Config) -> anyhow::Result<crate::rules::ResolvedRule> {
        let severity = crate::rules::get_rule_severity_required(cfg, self.id())?;
        let allowed = crate::helpers::rule_config::parse_lowercased_list(
            cfg,
            self.id(),
            "allowed",
            "acceptable media-types or patterns",
            "['text/plain','application/json','image/*','+json']",
        )?;
        // The two standard keys, **after** this rule's own options, so a config
        // naming a bad option still fails on that option.
        crate::rules::validate_rule_table(cfg, self.id())?;
        Ok(crate::rules::ResolvedRule {
            severity,
            state: Box::new(crate::helpers::rule_config::AllowedList { allowed }),
        })
    }

    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // Single-finding body behind an Option: `?` ends it early, and the
        // one finding (or none) becomes the vector.
        let finding = || -> Option<Violation> {
            let config: &crate::helpers::rule_config::AllowedList = ctx.state();
            let check_media_type =
                |hdr_name: &str, val: &str, allowed: &Vec<String>| -> Option<Violation> {
                    // Parse media-type; if it fails, let other rules (well-formed) report it.
                    let parsed = match crate::helpers::headers::parse_media_type(val) {
                        Ok(p) => p,
                        Err(_) => return None,
                    };
                    // Folded to lowercase before every comparison below because the
                    // grammar's tokens are case-insensitive, so `TEXT/PLAIN` and
                    // `text/plain` must reach the same verdict. (The config values are
                    // lowercased at parse time for the same reason.)
                    // cite(RFC 9110 § 8.3.1): "The type and subtype tokens are case-insensitive."
                    let t = parsed.type_.to_ascii_lowercase();
                    let s = parsed.subtype.to_ascii_lowercase();
                    let full = format!("{}/{}", t, s);

                    // What follows is an *allowlist* match, not a registry lookup, and the
                    // rule's name oversells it. The sentence below is why such a rule is
                    // wanted — registration is the thing worth encouraging — but it is an
                    // "ought to", it is addressed to people defining media types, and
                    // nothing here consults the IANA registry. An operator's list stands in
                    // for it: entries can be exact (`text/plain`), a type wildcard
                    // (`image/*`), `*/*`, or a structured-syntax suffix (`+json`). The
                    // wildcard and suffix forms are configuration conveniences with no
                    // basis in any specification.
                    // cite(RFC 9110 § 8.3.1): "Media types ought to be registered with IANA according to the procedures defined in [BCP13]."

                    for pat in allowed {
                        if pat == "*/*" || pat == &full {
                            return None;
                        }
                        if pat.ends_with("/*") {
                            // type/* form
                            if let Some(idx) = pat.find('/') {
                                let ptype = &pat[..idx];
                                if ptype == t {
                                    return None;
                                }
                            }
                        }
                        if let Some(suff) = pat.strip_prefix('+') {
                            // `+suffix` form. This means the *structured syntax suffix* —
                            // the part after a literal `+` appended to a base subtype —
                            // so it is matched with the helper that owns that concept
                            // rather than by a bare `ends_with`, which would also admit
                            // any subtype whose name happens to end in those letters
                            // (`text/notjson` against `+json`) and any base subtype of
                            // the same name (`application/json`), neither of which uses
                            // the suffix convention at all.
                            // cite(RFC 6838 § 4.2.8): "it specified a suffix (in that case, "+xml") to be appended to the base subtype name."
                            if crate::helpers::headers::media_type_subtype_suffix(&s) == Some(suff)
                            {
                                return None;
                            }
                        }
                    }

                    Some(self.violation(
                        ctx.severity,
                        format!("Unrecognized media type '{}' in {} header", full, hdr_name),
                    ))
                };

            // Check request Content-Type
            if let Some(val) =
                crate::helpers::headers::get_header_str(&tx.request.headers, "content-type")
            {
                if let Some(v) = check_media_type("Content-Type", val, &config.allowed) {
                    return Some(v);
                }
            }

            // Check response Content-Type
            if let Some(resp) = &tx.response {
                if let Some(val) =
                    crate::helpers::headers::get_header_str(&resp.headers, "content-type")
                {
                    if let Some(v) = check_media_type("Content-Type", val, &config.allowed) {
                        return Some(v);
                    }
                }
            }

            None
        };
        Vec::from_iter(finding())
    }

    fn title(&self) -> Option<&'static str> {
        Some("Message Content-Type IANA Registered")
    }

    fn description(&self) -> &'static str {
        "This rule checks that `Content-Type` media types (in both requests and responses) appear in an allowlist you configure. It helps flag unregistered or accidental vendor types that may cause interoperability problems.\n\n**It does not consult the IANA registry**, despite the rule's name: there is no lookup, and a media type is \"registered\" as far as this rule is concerned exactly when your `allowed` array covers it. RFC 9110 says media types *ought to* be registered, which is the motivation for the rule, but the check itself is your policy.\n\nEntries may be exact (`text/plain`), a type wildcard (`image/*`), `*/*`, or a structured syntax suffix (`+json`, matching `application/vnd.example+json` but not `application/json` or `text/notjson`). The wildcard and suffix forms are conveniences of this configuration, not media-type syntax. Comparisons are case-insensitive."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_9110_8_3_1, RFC_6838_4_2_8, IANA_MEDIA_TYPES]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "Content-Type: text/plain\nContent-Type: application/json; charset=utf-8\nContent-Type: application/ld+json\nContent-Type: image/png",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "Content-Type: application/vnd.unknown\nContent-Type: text/x-custom",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ContentTypeRegistered;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn make_cfg() -> crate::config::Config {
        let mut cfg = crate::config::Config::default();
        cfg.rules.insert(
            "content_type_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![
                        toml::Value::String("text/plain".into()),
                        toml::Value::String("application/json".into()),
                        toml::Value::String("image/*".into()),
                        toml::Value::String("+json".into()),
                    ]),
                );
                t
            }),
        );
        cfg
    }

    #[rstest]
    #[case(Some("text/plain"), false)]
    #[case(Some("application/json; charset=utf-8"), false)]
    #[case(Some("application/ld+json"), false)]
    #[case(Some("image/png"), false)]
    #[case(Some("application/vnd.example"), true)]
    #[case(Some("text/x-custom"), true)]
    // A `+json` allowlist entry means the *structured syntax suffix*, so it must
    // not admit a subtype that merely happens to end in those letters.
    #[case(Some("text/notjson"), true)]
    #[case(Some("application/xjson"), true)]
    #[case(Some("application/vnd.example+json"), false)]
    #[case(None, false)]
    fn check_response_cases(
        #[case] ct: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = ContentTypeRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        if let Some(v) = ct {
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[("content-type", v)]);
        }

        let violation = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(violation.is_some());
        } else {
            assert!(violation.is_none());
        }
        Ok(())
    }

    #[rstest]
    #[case(Some("text/plain"), false)]
    #[case(Some("application/vnd.custom+json; foo=bar"), false)]
    #[case(Some("application/x-cms"), true)]
    #[case(None, false)]
    fn check_request_cases(
        #[case] ct: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = ContentTypeRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(v) = ct {
            tx.request.headers =
                crate::test_helpers::make_headers_from_pairs(&[("content-type", v)]);
        }

        let violation = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(violation.is_some());
        } else {
            assert!(violation.is_none());
        }
        Ok(())
    }

    #[test]
    fn malformed_content_type_is_ignored() {
        let rule = ContentTypeRegistered;
        let cfg = make_cfg();
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-type", "text")]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn wildcard_allowed_accepts_any() {
        let rule = ContentTypeRegistered;
        let mut cfg = crate::config::Config::default();
        cfg.rules.insert(
            "content_type_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![toml::Value::String("*/*".into())]),
                );
                t
            }),
        );
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-type",
            "application/vnd.unknown",
        )]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn case_insensitive_allowed_is_parsed() -> anyhow::Result<()> {
        let mut cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["content_type_registered"]);
        cfg.rules.insert(
            "content_type_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![toml::Value::String("IMAGE/*".into())]),
                );
                t
            }),
        );
        let parsed = ContentTypeRegistered.prepare(&cfg)?;
        let parsed: &crate::helpers::rule_config::AllowedList =
            parsed.state.downcast_ref().expect("allowed list state");
        assert!(parsed.allowed.contains(&"image/*".to_string()));
        Ok(())
    }

    #[test]
    fn suffix_matches_json_variants() {
        let rule = ContentTypeRegistered;
        let cfg = make_cfg();

        let mut tx1 = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx1.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-type", "application/json")]);
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx1,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .is_none());

        let mut tx2 = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx2.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-type",
            "application/ld+json",
        )]);
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx2,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .is_none());
    }

    #[test]
    fn violation_message_is_meaningful() {
        let rule = ContentTypeRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-type", "text/x-custom")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let v = v.unwrap();
        assert_eq!(v.rule, "content_type_registered");
        assert!(v.message.contains("Content-Type"));
        assert!(v.message.contains("text/x-custom"));
    }

    #[test]
    fn config_parse_allows_custom_list() -> anyhow::Result<()> {
        let mut cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["content_type_registered"]);
        cfg.rules.insert(
            "content_type_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![toml::Value::String("x-custom/type".into())]),
                );
                t
            }),
        );

        let parsed = ContentTypeRegistered.prepare(&cfg)?;
        let parsed: &crate::helpers::rule_config::AllowedList =
            parsed.state.downcast_ref().expect("allowed list state");
        assert!(parsed.allowed.contains(&"x-custom/type".to_string()));
        Ok(())
    }

    #[test]
    fn parse_config_rejects_empty_allowed_array() {
        let mut cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["content_type_registered"]);
        cfg.rules.insert(
            "content_type_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert("allowed".into(), toml::Value::Array(vec![]));
                t
            }),
        );

        let res = ContentTypeRegistered.prepare(&cfg);
        assert!(res.is_err());
    }

    #[test]
    fn parse_config_rejects_non_string_allowed_item() {
        let mut cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["content_type_registered"]);
        cfg.rules.insert(
            "content_type_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![toml::Value::Integer(1)]),
                );
                t
            }),
        );

        let res = ContentTypeRegistered.prepare(&cfg);
        assert!(res.is_err());
    }

    #[test]
    fn validate_parses_config() -> anyhow::Result<()> {
        let mut full_cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["content_type_registered"]);
        full_cfg.rules.insert(
            "content_type_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![toml::Value::String("text/plain".into())]),
                );
                t
            }),
        );

        let arc = ContentTypeRegistered.prepare(&full_cfg)?;
        let arc: &crate::helpers::rule_config::AllowedList =
            arc.state.downcast_ref().expect("allowed list state");
        assert!(arc.allowed.contains(&"text/plain".to_string()));
        Ok(())
    }

    #[test]
    fn non_utf8_header_values_are_ignored() {
        let rule = ContentTypeRegistered;
        let cfg = make_cfg();

        // Non-utf8 response header value should be ignored and produce no violation
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = hyper::HeaderMap::new();
        hm.insert(
            "content-type",
            hyper::header::HeaderValue::from_bytes(b"\xff").unwrap(),
        );
        tx.response.as_mut().unwrap().headers = hm;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());

        // Non-utf8 request header value should be ignored
        let mut tx2 = crate::test_helpers::make_test_transaction();
        let mut hm2 = hyper::HeaderMap::new();
        hm2.insert(
            "content-type",
            hyper::header::HeaderValue::from_bytes(b"\xff").unwrap(),
        );
        tx2.request.headers = hm2;
        let v2 = crate::test_helpers::run_rule(
            &rule,
            &tx2,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v2.is_none());
    }

    #[test]
    fn scope_is_both() {
        let rule = ContentTypeRegistered;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }
}
