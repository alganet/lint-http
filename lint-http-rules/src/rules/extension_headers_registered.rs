// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ExtensionHeadersRegistered;

impl Rule for ExtensionHeadersRegistered {
    fn id(&self) -> &'static str {
        "extension_headers_registered"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        // The sentence that asks for registration is about field names, and names no
        // direction and no section, so every field the transaction carries is in scope.
        // cite(RFC 9110 § 5): "Fields are sent and received within the header and trailer sections of messages"
        crate::rules::RuleScope::Both
    }

    fn prepare(&self, cfg: &crate::config::Config) -> anyhow::Result<crate::rules::ResolvedRule> {
        let severity = crate::rules::get_rule_severity_required(cfg, self.id())?;
        // What the array lists is field names, and a field name means the same
        // thing however it is spelled, so the configured spelling is folded at
        // prepare time -- once per array rather than once per field of every message.
        // cite(RFC 9110 § 5.1): "Field names are case-insensitive and ought to be registered within the "Hypertext Transfer Protocol (HTTP) Field Name Registry""
        let allowed = crate::helpers::rule_config::parse_lowercased_list(
            cfg,
            self.id(),
            "allowed",
            "the field names this deployment expects, in header and trailer sections alike",
            "['host','content-type']",
        )?;
        // The two standard keys, **after** this rule's own options, so a config
        // naming a bad option still fails on that option.
        crate::rules::validate_rule_table(cfg, self.id())?;
        Ok(crate::rules::ResolvedRule {
            severity,
            state: Box::new(crate::helpers::rule_config::AllowedList { allowed }),
        })
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Option<Violation> {
        let config: &crate::helpers::rule_config::AllowedList = ctx.state();

        // All four, in wire order, from the shared walk. A trailer field name is
        // a field name, so the allowlist reaches it on the same terms; a
        // transaction the upstream never answered has no response half; and
        // which sections exist at all is the framing's answer, not this rule's.
        // cite(RFC 9110 § 6.5): "Fields (Section 5) that are located within a "trailer section" are referred to as "trailer fields""
        for (section, headers) in crate::helpers::headers::transaction_field_sections(tx) {
            if let Some(v) = check_section(section, headers, config, ctx.severity) {
                return Some(v);
            }
        }

        None
    }

    fn description(&self) -> &'static str {
        "Reports field names this deployment has not listed in the rule's `allowed` array. All four field sections a transaction can carry are walked — the request and response header sections, and their trailer sections when the message framing carried one — and names are compared case-insensitively, which is what RFC 9110 §5.1 says a field name is.\n\n**The `allowed` array is the rule's only authority.** It does not consult the IANA HTTP Field Name Registry: a permanently registered field is reported exactly like a typo when the array omits it, and registering a name with IANA changes nothing about what this rule says. Neither is a finding a protocol error. RFC 9110 §5.1 asks only that field names \"ought to be\" registered — weaker than SHOULD — and the same paragraph requires a proxy to forward unrecognized header fields and tells other recipients they SHOULD ignore them. A finding means \"this deployment did not expect this field\", which is worth a look for typos, forgotten debug headers and injected fields, and is not a claim that the sender did anything wrong.\n\nBecause the array has to name every field the deployment sees, no useful list is deployment-independent and `config_example.toml` ships the rule disabled with an illustrative one. For a private field prefer a short name scoped to its use and no `X-` prefix: RFC 9110 §16.3.2.1 says field names ought not be prefixed with `X-`."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("5.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.1",
                note: "Field Names (case-insensitive, and registration is an \"ought to\"; the same paragraph makes a proxy forward what it does not recognize)",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("6.5"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-6.5",
                note: "Trailer Fields (a trailer field name is a field name, so the array reaches it)",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("16.3.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-16.3.1",
                note: "Field Name Registry (what registration is; this rule does not consult it)",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("16.3.2.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-16.3.2.1",
                note: "Considerations for New Field Names (no \"X-\" prefix)",
            },
            crate::rules::SpecRef {
                spec: "IANA HTTP Field Name Registry",
                section: None,
                url: "https://www.iana.org/assignments/http-fields/http-fields.xhtml",
                note: "The registry § 5.1 points at, for deciding what belongs in the array",
            },
        ]
    }

    // Judged against the `allowed` array `config_example.toml` ships, so the
    // snippets mean what a reader with the documented configuration would see.
    // The private field is named without a prefix the spec advises against.
    // cite(RFC 9110 § 16.3.2.1): "Field names ought not be prefixed with "X-""
    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "Host: example.com\nAccept: text/plain\nAcme-Request-Id: 7c1f2b",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("A typo is a field name of its own"),
                snippet: "Host: example.com\nAcme-Request-Idd: 7c1f2b",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("Registered with IANA and still reported: the array does not name it"),
                snippet: "Host: example.com\nContent-Language: en",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("Trailer section, walked on the same terms"),
                snippet: "Acme-Checksum: 9f2a",
            },
        ]
    }
}

/// Walk one field section, reporting the first field name the deployment has not
/// listed.
//
// The report is a deployment-policy signal and not a conformance verdict, which is
// as much as the licensing sentence's `ought to` will carry. The paragraph it sits
// in settles the rest: an unrecognized field is something HTTP expects to travel
// through and be ignored, so a name absent from the array is worth a look and is
// never a claim that the sender got something wrong.
// cite(RFC 9110 § 5.1): "A proxy MUST forward unrecognized header fields unless the field name is listed in the Connection header field"
// cite(RFC 9110 § 5.1): "Other recipients SHOULD ignore unrecognized header and trailer fields"
// cite(RFC 9110 § 16.3): "Most fields are designed with the expectation that a recipient can safely ignore (but forward downstream) any field not recognized"
fn check_section(
    section: &str,
    fields: &hyper::HeaderMap,
    config: &crate::helpers::rule_config::AllowedList,
    severity: crate::lint::Severity,
) -> Option<Violation> {
    // `keys()` rather than `iter()`: what is being judged is the name, and a field
    // repeated across lines is one name that would otherwise be judged once per line.
    for name in fields.keys() {
        // `as_str()` is already lowercase whatever the wire spelling was -- the HTTP/1
        // parser folds case on the way in and the HTTP/2 and HTTP/3 decoders reject an
        // uppercase name outright -- so the configured side, folded once at parse time,
        // is the only one that needs folding.
        // cite(RFC 9114 § 4.2): "A request or response containing uppercase characters in field names MUST be treated as malformed"
        if config
            .allowed
            .iter()
            .any(|allowed| allowed == name.as_str())
        {
            continue;
        }
        // cite(RFC 9110 § 5.1): "Field names are case-insensitive and ought to be registered within the "Hypertext Transfer Protocol (HTTP) Field Name Registry""
        return Some(Violation {
            rule: ExtensionHeadersRegistered.id().into(),
            severity,
            message: format!(
                "Field name '{}' in the {} is not in the 'allowed' list for '{}'. That list is the rule's only authority: add the name to it if this deployment expects the field",
                name.as_str(),
                section,
                ExtensionHeadersRegistered.id()
            ),
        });
    }
    None
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ExtensionHeadersRegistered;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn make_cfg_with_allowed(allowed: Vec<&str>) -> crate::config::Config {
        let mut cfg = crate::config::Config::default();
        cfg.rules.insert(
            "extension_headers_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(
                        allowed
                            .into_iter()
                            .map(|s| toml::Value::String(s.to_string()))
                            .collect(),
                    ),
                );
                t
            }),
        );
        cfg
    }

    #[rstest]
    #[case(vec![("host", "example")], false)]
    #[case(vec![("x-custom", "v")], false)]
    #[case(vec![("x-other", "v")], true)]
    fn check_request_cases(
        #[case] header_pairs: Vec<(&str, &str)>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = ExtensionHeadersRegistered;
        let cfg = make_cfg_with_allowed(vec!["host", "x-custom"]);

        // If header name cannot be parsed into HeaderName, treat as violation by test harness
        for (k, _) in &header_pairs {
            if hyper::header::HeaderName::from_bytes(k.as_bytes()).is_err() {
                assert!(
                    expect_violation,
                    "header '{}' invalid but test expected no violation",
                    k
                );
                return Ok(());
            }
        }

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&header_pairs);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(v.is_some());
        } else {
            assert!(v.is_none());
        }
        Ok(())
    }

    #[rstest]
    #[case(vec![("content-type", "text/plain")], false)]
    #[case(vec![("x-evil", "v")], true)]
    fn check_response_cases(
        #[case] header_pairs: Vec<(&str, &str)>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = ExtensionHeadersRegistered;
        // make sure default request header 'user-agent' is permitted in this config
        let cfg = make_cfg_with_allowed(vec!["content-type", "server", "user-agent"]);

        let tx =
            crate::test_helpers::make_test_transaction_with_response(200, header_pairs.as_slice());

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(v.is_some());
        } else {
            assert!(v.is_none());
        }
        Ok(())
    }

    #[test]
    fn parse_config_requires_allowed_array() {
        let cfg = crate::config::Config::default();
        let res = ExtensionHeadersRegistered.prepare(&cfg);
        assert!(res.is_err());
    }

    #[test]
    fn parse_config_rejects_empty_allowed_array() {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "extension_headers_registered",
        ]);
        cfg.rules.insert(
            "extension_headers_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert("allowed".into(), toml::Value::Array(vec![]));
                t
            }),
        );

        let res = ExtensionHeadersRegistered.prepare(&cfg);
        assert!(res.is_err());
    }

    #[test]
    fn parse_config_rejects_non_string_allowed_item() {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "extension_headers_registered",
        ]);
        cfg.rules.insert(
            "extension_headers_registered".into(),
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

        let res = ExtensionHeadersRegistered.prepare(&cfg);
        assert!(res.is_err());
    }

    #[test]
    fn parse_config_rejects_allowed_not_array() {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "extension_headers_registered",
        ]);
        cfg.rules.insert(
            "extension_headers_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert("allowed".into(), toml::Value::String("host".into()));
                t
            }),
        );

        let res = ExtensionHeadersRegistered.prepare(&cfg);
        assert!(res.is_err());
    }

    #[test]
    fn parse_config_rejects_non_table_rule_cfg() {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "extension_headers_registered",
        ]);
        cfg.rules.insert(
            "extension_headers_registered".into(),
            toml::Value::String("not a table".into()),
        );

        let res = ExtensionHeadersRegistered.prepare(&cfg);
        assert!(res.is_err());
    }

    #[test]
    fn unrecognized_header_reports_violation_with_name() -> anyhow::Result<()> {
        let rule = ExtensionHeadersRegistered;
        // allow default request 'user-agent' so response header is the one that triggers the violation
        let cfg = make_cfg_with_allowed(vec!["host", "user-agent"]);

        let tx =
            crate::test_helpers::make_test_transaction_with_response(200, &[("x-unknown", "v")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let v = v.unwrap();
        assert_eq!(v.rule, "extension_headers_registered");
        assert!(v.message.contains("x-unknown"));
        Ok(())
    }

    #[test]
    fn validate_parses_config() -> anyhow::Result<()> {
        let mut full_cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "extension_headers_registered",
        ]);
        full_cfg.rules.insert(
            "extension_headers_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![toml::Value::String("host".into())]),
                );
                t
            }),
        );

        let arc = ExtensionHeadersRegistered.prepare(&full_cfg)?;
        let arc: &crate::helpers::rule_config::AllowedList =
            arc.state.downcast_ref().expect("allowed list state");
        assert!(arc.allowed.contains(&"host".to_string()));
        Ok(())
    }

    /// What this pins is where the folding happens, which is not in the rule: the
    /// configured spelling is folded at parse time and `HeaderName` has folded the
    /// wire spelling before any rule sees it. Both halves have to hold for a
    /// deployment to be able to write `X-Custom` in its config and mean it.
    #[test]
    fn header_name_matching_is_case_insensitive() -> anyhow::Result<()> {
        let rule = ExtensionHeadersRegistered;
        let cfg = make_cfg_with_allowed(vec!["x-custom"]);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[("X-CUSTOM", "1")]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn multiple_unrecognized_headers_reports_first() -> anyhow::Result<()> {
        let rule = ExtensionHeadersRegistered;
        let cfg = make_cfg_with_allowed(vec!["host"]);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("x-a", "1"), ("x-b", "2")]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let v = v.unwrap();
        assert!(v.message.contains("x-a"));
        Ok(())
    }

    #[test]
    fn parse_config_lowercases_allowed_items() -> anyhow::Result<()> {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "extension_headers_registered",
        ]);
        cfg.rules.insert(
            "extension_headers_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![toml::Value::String("X-Custom".into())]),
                );
                t
            }),
        );

        let parsed = ExtensionHeadersRegistered.prepare(&cfg)?;
        let parsed: &crate::helpers::rule_config::AllowedList =
            parsed.state.downcast_ref().expect("allowed list state");
        assert!(parsed.allowed.contains(&"x-custom".to_string()));
        Ok(())
    }

    /// The allowlist reaches every section a transaction can carry, and the
    /// violation says which one it came from -- it could stay silent about that
    /// while only two of the four were walked.
    #[rstest]
    #[case("request trailer section")]
    #[case("response trailer section")]
    fn unlisted_trailer_field_name_is_reported(#[case] section: &str) -> anyhow::Result<()> {
        let rule = ExtensionHeadersRegistered;
        let cfg = make_cfg_with_allowed(vec!["host", "user-agent"]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let trailers = crate::test_helpers::make_headers_from_pairs(&[("checksum", "abc123")]);
        if section.starts_with("request") {
            tx.request.trailers = Some(trailers);
        } else {
            tx.response.as_mut().unwrap().trailers = Some(trailers);
        }

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .expect("a trailer field name the deployment did not list must be reported");
        assert!(v.message.contains("checksum"));
        assert!(
            v.message.contains(section),
            "violation should name the section it came from, got: {}",
            v.message
        );
        Ok(())
    }

    /// A listed name is listed wherever it appears; the trailer walks are not a
    /// second, stricter allowlist.
    #[test]
    fn listed_trailer_field_name_is_accepted() -> anyhow::Result<()> {
        let rule = ExtensionHeadersRegistered;
        let cfg = make_cfg_with_allowed(vec!["host", "user-agent", "checksum"]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().trailers = Some(
            crate::test_helpers::make_headers_from_pairs(&[("checksum", "abc123")]),
        );

        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .is_none());
        Ok(())
    }

    /// Every published snippet is run through the rule, against the array
    /// `config_example.toml` ships -- the docs print that block right beside the
    /// examples, so it is the configuration a reader judges them with, and a
    /// config built by `make_test_config_with_enabled_rules` would carry no
    /// `allowed` key at all and make this guard pass by never running.
    ///
    /// The shipped block says `enabled = false`; the engine is what honours that,
    /// so a direct `check_transaction` still exercises the rule.
    #[test]
    fn published_examples_are_judged_the_way_they_are_labelled() {
        use crate::rules::{Compliance, Rule as _};
        let rule = ExtensionHeadersRegistered;
        let toml_src = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../config_example.toml"),
        )
        .expect("config_example.toml must be readable");
        let cfg: crate::config::Config =
            toml::from_str(&toml_src).expect("config_example.toml must parse");

        let mut saw_a_finding = false;
        for ex in rule.examples() {
            assert!(
                !ex.snippet.contains('#'),
                "example carries a comment no HTTP message has: {:?}",
                ex.snippet
            );
            let pairs: Vec<(&str, &str)> = ex
                .snippet
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(|l| {
                    l.split_once(": ")
                        .unwrap_or_else(|| panic!("not a field line: {l:?}"))
                })
                .collect();
            let section = crate::test_helpers::make_headers_from_pairs(&pairs);

            let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
            if ex.label.is_some_and(|l| l.starts_with("Trailer section")) {
                tx.response.as_mut().unwrap().trailers = Some(section);
            } else {
                tx.request.headers = section;
            }

            let found = crate::test_helpers::run_rule(
                &rule,
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            );
            match ex.compliance {
                Compliance::Compliant => assert!(
                    found.is_none(),
                    "rule reports its Compliant example {:?}: {found:?}",
                    ex.snippet
                ),
                Compliance::NonCompliant => {
                    assert!(
                        found.is_some(),
                        "rule accepts its NonCompliant example {:?}",
                        ex.snippet
                    );
                    saw_a_finding = true;
                }
            }
        }
        assert!(saw_a_finding, "no example produced a finding");
    }

    #[test]
    fn scope_is_both() {
        let rule = ExtensionHeadersRegistered;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "extension_headers_registered");
        // Provide minimal allowed array so validation succeeds
        cfg.rules.insert(
            "extension_headers_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![toml::Value::String("host".into())]),
                );
                t
            }),
        );
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
