// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

#[derive(Debug, Clone)]
pub struct ContentEncodingConfig {
    pub severity: crate::lint::Severity,
    pub allowed: Vec<String>,
}

fn parse_allowed_config(
    config: &crate::config::Config,
    rule_id: &str,
) -> anyhow::Result<ContentEncodingConfig> {
    // Base required fields (enabled + severity)
    let severity = crate::rules::get_rule_severity_required(config, rule_id)?;

    // Allowed list is REQUIRED for this rule. It must be an array of strings.
    let rule_cfg = config.get_rule_config(rule_id).ok_or_else(|| {
        anyhow::anyhow!(
            "rule '{}' requires configuration and a named 'allowed' array listing acceptable content-codings. Example in config_example.toml",
            rule_id
        )
    })?;
    let table = rule_cfg
        .as_table()
        .ok_or_else(|| anyhow::anyhow!("Configuration for rule '{}' must be a table", rule_id))?;

    let allowed_val = table.get("allowed").ok_or_else(|| {
        anyhow::anyhow!(
            "Rule '{}' requires an 'allowed' array listing allowed content-coding tokens (e.g., ['gzip','br','deflate'])",
            rule_id
        )
    })?;

    let arr = allowed_val.as_array().ok_or_else(|| {
        anyhow::anyhow!("'allowed' must be an array of strings (e.g., ['gzip','br'])")
    })?;

    if arr.is_empty() {
        return Err(anyhow::anyhow!("'allowed' array cannot be empty"));
    }

    let mut out = Vec::new();
    for (i, item) in arr.iter().enumerate() {
        let s = item.as_str().ok_or_else(|| {
            anyhow::anyhow!("'allowed' array item at index {} must be a string", i)
        })?;
        out.push(s.to_ascii_lowercase());
    }

    Ok(ContentEncodingConfig {
        severity,
        allowed: out,
    })
}

pub struct ContentEncodingRegistered;

impl Rule for ContentEncodingRegistered {
    fn id(&self) -> &'static str {
        "content_encoding_registered"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn prepare(&self, cfg: &crate::config::Config) -> anyhow::Result<crate::rules::ResolvedRule> {
        let config = parse_allowed_config(cfg, self.id())?;
        // The two standard keys, **after** this rule's own options, so a config
        // naming a bad option still fails on that option.
        crate::rules::validate_rule_table(cfg, self.id())?;
        Ok(crate::rules::ResolvedRule {
            severity: config.severity,
            state: Box::new(config),
        })
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Option<Violation> {
        let config: &ContentEncodingConfig = ctx.state();
        // Helper to check a single header value against allowed list
        // `is_accept` distinguishes the two grammars. They are not the same vocabulary:
        // Content-Encoding is a list of plain content-codings, while Accept-Encoding
        // adds two alternatives of its own, and letting those leak into
        // Content-Encoding is what this parameter exists to prevent.
        // cite(RFC 9110 § 8.4): "Content-Encoding = #content-coding"
        // cite(RFC 9110 § 12.5.3): "codings = content-coding / "identity" / "*""
        let check_value = |hdr_name: &str,
                           val: &str,
                           allowed: &Vec<String>,
                           is_accept: bool|
         -> Option<Violation> {
            for part in crate::helpers::headers::list_members(val) {
                // Split off any parameters (e.g., gzip;q=0.8)
                let token = part.split(';').next().unwrap().trim();
                if token == "*" {
                    // A wildcard is a preference, so it means something only where
                    // preferences are expressed. In Content-Encoding there is
                    // nothing for it to match: that field states what was actually
                    // applied.
                    // cite(RFC 9110 § 12.5.3): "The asterisk "*" symbol in an Accept-Encoding field matches any available content coding not explicitly listed in the field."
                    if is_accept {
                        continue;
                    }
                    return Some(Violation {
                            rule: "content_encoding_registered".into(),
                            severity: config.severity,
                            message: format!(
                                "'*' is not a content-coding and is only meaningful in Accept-Encoding, not in {}",
                                hdr_name
                            ),
                        });
                }
                // `identity` is likewise Accept-Encoding vocabulary — the way to say
                // "no encoding". Naming it in Content-Encoding claims a transformation
                // that by definition does nothing, so the spec reserves it away.
                // cite(RFC 9110 § 8.4): "Note that the coding named "identity" is reserved for its special role in Accept-Encoding and thus SHOULD NOT be included."
                if !is_accept && token.eq_ignore_ascii_case("identity") {
                    return Some(Violation {
                            rule: "content_encoding_registered".into(),
                            severity: config.severity,
                            message: format!(
                                "'identity' is reserved for Accept-Encoding and SHOULD NOT be sent in {}",
                                hdr_name
                            ),
                        });
                }
                // cite(RFC 9110 § 8.4.1): "content-coding = token"
                if let Some(c) = crate::helpers::token::find_invalid_token_char(token) {
                    return Some(Violation {
                        rule: "content_encoding_registered".into(),
                        severity: config.severity,
                        message: format!("Invalid token '{}' in {} header", c, hdr_name),
                    });
                }
                // Folded to lowercase because the codings are case-insensitive. As
                // in the media-type sibling, "registered" here means "in the
                // operator's list": nothing consults the registry the rule is named
                // after, and the sentence below is an "ought to" in any case.
                // cite(RFC 9110 § 8.4.1): "All content codings are case-insensitive and ought to be registered within the "HTTP Content Coding Registry","
                if !allowed.contains(&token.to_ascii_lowercase()) {
                    return Some(Violation {
                        rule: "content_encoding_registered".into(),
                        severity: config.severity,
                        message: format!(
                            "Unrecognized content-coding '{}' in {} header",
                            token, hdr_name
                        ),
                    });
                }
            }
            None
        };

        // Check response Content-Encoding
        if let Some(resp) = &tx.response {
            if let Some(val) =
                crate::helpers::headers::get_header_str(&resp.headers, "content-encoding")
            {
                if let Some(v) = check_value("Content-Encoding", val, &config.allowed, false) {
                    return Some(v);
                }
            }
        }

        // Check request Accept-Encoding
        if let Some(val) =
            crate::helpers::headers::get_header_str(&tx.request.headers, "accept-encoding")
        {
            if let Some(v) = check_value("Accept-Encoding", val, &config.allowed, true) {
                return Some(v);
            }
        }

        None
    }

    fn description(&self) -> &'static str {
        "Validate `Content-Encoding` and `Accept-Encoding` header values: each content-coding must be a valid `token` and must appear in the `allowed` array you configure.\n\n**It does not consult the IANA registry**, despite the rule's name. RFC 9110 says content codings *ought to* be registered, which is the motivation, but a coding is recognised here exactly when your `allowed` array covers it. Comparisons are case-insensitive.\n\nThe two headers do not share a vocabulary. `Accept-Encoding` additionally admits `*` (matching any coding not listed) and `identity` (meaning no encoding); both are preference vocabulary and neither is a content-coding, so in `Content-Encoding` they are flagged — `identity` explicitly so, since RFC 9110 §8.4 reserves it for its Accept-Encoding role and says it SHOULD NOT be included."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("8.4"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.4",
                note: "`Content-Encoding = #content-coding`, and the reservation of `identity` for Accept-Encoding — the reason it is flagged here",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("8.4.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.4.1",
                note: "`content-coding = token`, case-insensitive, and the \"ought to be registered\" guidance that motivates the rule without being what it checks",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("12.5.3"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.3",
                note: "The wider Accept-Encoding grammar (`codings = content-coding / \"identity\" / \"*\"`), which is why the two headers are checked against different vocabularies",
            },
            crate::rules::SpecRef {
                spec: "IANA HTTP Parameters",
                section: None,
                url: "https://www.iana.org/assignments/http-parameters/http-parameters.xhtml#content-coding",
                note: "The registry this rule is named after but does not read; the configured `allowed` array stands in for it",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "Content-Encoding: gzip\nContent-Encoding: gzip, br\nAccept-Encoding: gzip;q=0.8, br;q=1.0\nAccept-Encoding: *",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "Content-Encoding: x-custom\nAccept-Encoding: x-custom;q=0.5\nAccept-Encoding: x!bad  # invalid token character '!'",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ContentEncodingRegistered;

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;
    use rstest::rstest;

    fn make_cfg() -> crate::config::Config {
        let mut cfg = crate::config::Config::default();
        cfg.rules.insert(
            "content_encoding_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![
                        toml::Value::String("gzip".into()),
                        toml::Value::String("br".into()),
                        toml::Value::String("deflate".into()),
                        toml::Value::String("zstd".into()),
                    ]),
                );
                t
            }),
        );
        cfg
    }

    #[rstest]
    #[case(Some("gzip"), false)]
    #[case(Some("br"), false)]
    #[case(Some("gZiP"), false)]
    #[case(Some("x-custom"), true)]
    #[case(Some("gzip, x-custom"), true)]
    #[case(Some("gzip;q=0.8"), false)]
    // `*` and `identity` belong to Accept-Encoding, not Content-Encoding.
    #[case(Some("*"), true)]
    #[case(Some("identity"), true)]
    #[case(Some("gzip, identity"), true)]
    #[case(None, false)]
    fn check_response_cases(
        #[case] ce: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = ContentEncodingRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        if let Some(v) = ce {
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[("content-encoding", v)]);
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
    #[case(Some("gzip"), false)]
    #[case(Some("br;q=1.0"), false)]
    #[case(Some("x-custom;q=0.1"), true)]
    #[case(Some("*, gzip"), false)]
    #[case(Some("x!bad"), true)]
    #[case(None, false)]
    fn check_request_cases(
        #[case] ae: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = ContentEncodingRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(v) = ae {
            tx.request.headers =
                crate::test_helpers::make_headers_from_pairs(&[("accept-encoding", v)]);
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
    fn config_parse_allows_custom_list() -> anyhow::Result<()> {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "content_encoding_registered",
        ]);
        cfg.rules.insert(
            "content_encoding_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![toml::Value::String("x-custom".into())]),
                );
                t
            }),
        );

        let parsed = parse_allowed_config(&cfg, "content_encoding_registered")?;
        assert_eq!(parsed.allowed, vec!["x-custom".to_string()]);
        Ok(())
    }

    #[test]
    fn parse_config_rejects_empty_allowed_array() {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "content_encoding_registered",
        ]);
        cfg.rules.insert(
            "content_encoding_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert("allowed".into(), toml::Value::Array(vec![]));
                t
            }),
        );

        let res = parse_allowed_config(&cfg, "content_encoding_registered");
        assert!(res.is_err());
    }

    #[test]
    fn parse_config_rejects_non_string_allowed_item() {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "content_encoding_registered",
        ]);
        cfg.rules.insert(
            "content_encoding_registered".into(),
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

        let res = parse_allowed_config(&cfg, "content_encoding_registered");
        assert!(res.is_err());
    }

    #[test]
    fn parse_config_requires_allowed_array() {
        // When the rule is enabled but 'allowed' key missing, parsing should fail
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "content_encoding_registered",
        ]);
        let res = parse_allowed_config(&cfg, "content_encoding_registered");
        assert!(res.is_err());
    }

    #[test]
    fn parse_allowed_config_missing_rule_errors() {
        // If the entire rule is not present in the config, parsing should fail
        let cfg = crate::config::Config::default();
        let res = parse_allowed_config(&cfg, "content_encoding_registered");
        assert!(res.is_err());
        let msg = res.unwrap_err().to_string();
        // Different helper functions compose different error strings; accept either form.
        assert!(
            msg.contains("requires configuration")
                || msg.contains("missing configuration")
                || msg.contains("missing")
        );
    }

    #[test]
    fn validate_fails_when_allowed_missing() {
        let rule = ContentEncodingRegistered;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "content_encoding_registered",
        ]);
        let res = rule.prepare(&cfg);
        assert!(res.is_err());
    }

    #[test]
    fn parse_config_rejects_non_table_rule_cfg() {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "content_encoding_registered",
        ]);
        cfg.rules.insert(
            "content_encoding_registered".into(),
            toml::Value::String("not-a-table".into()),
        );
        let res = parse_allowed_config(&cfg, "content_encoding_registered");
        assert!(res.is_err());
    }

    #[test]
    fn parse_config_rejects_allowed_not_array() {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "content_encoding_registered",
        ]);
        cfg.rules.insert(
            "content_encoding_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                // 'allowed' present but not an array
                t.insert("allowed".into(), toml::Value::String("gzip".into()));
                t
            }),
        );
        let res = parse_allowed_config(&cfg, "content_encoding_registered");
        assert!(res.is_err());
        let msg = res.unwrap_err().to_string();
        assert!(msg.contains("'allowed' must be an array"));
    }

    #[test]
    fn validate_parses_config() -> anyhow::Result<()> {
        let rule = ContentEncodingRegistered;
        let mut full_cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "content_encoding_registered",
        ]);
        full_cfg.rules.insert(
            "content_encoding_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![toml::Value::String("gzip".into())]),
                );
                t
            }),
        );

        let arc = parse_allowed_config(&full_cfg, rule.id())?;
        assert!(arc.allowed.contains(&"gzip".to_string()));
        Ok(())
    }

    #[test]
    fn scope_is_both() {
        let rule = ContentEncodingRegistered;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }

    #[test]
    fn invalid_token_in_content_encoding_is_reported() -> anyhow::Result<()> {
        let rule = ContentEncodingRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-encoding", "x!bad")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let v = v.unwrap();
        assert_eq!(v.rule, "content_encoding_registered");
        // Message should indicate either an invalid token or an unrecognized coding
        assert!(
            v.message.contains("Invalid token")
                || v.message.contains("Unrecognized content-coding")
        );
        Ok(())
    }

    #[test]
    fn non_utf8_header_values_are_ignored() {
        let rule = ContentEncodingRegistered;
        let cfg = make_cfg();

        // Non-utf8 response header value should be ignored and produce no violation
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = hyper::HeaderMap::new();
        hm.insert(
            "content-encoding",
            HeaderValue::from_bytes(b"\xff").unwrap(),
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
        hm2.insert("accept-encoding", HeaderValue::from_bytes(b"\xff").unwrap());
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
    fn request_custom_allowed_is_accepted() -> anyhow::Result<()> {
        let rule = ContentEncodingRegistered;
        let mut full_cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "content_encoding_registered",
        ]);
        full_cfg.rules.insert(
            "content_encoding_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![toml::Value::String("x-custom".into())]),
                );
                t
            }),
        );

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("accept-encoding", "x-custom;q=0.5")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &full_cfg,
        );
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn response_custom_allowed_is_accepted() -> anyhow::Result<()> {
        let rule = ContentEncodingRegistered;
        let mut full_cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "content_encoding_registered",
        ]);
        full_cfg.rules.insert(
            "content_encoding_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![toml::Value::String("x-custom".into())]),
                );
                t
            }),
        );

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-encoding", "x-custom")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &full_cfg,
        );
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn trailing_commas_and_whitespace_are_ignored() -> anyhow::Result<()> {
        let rule = ContentEncodingRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-encoding", "gzip, ")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());

        let mut tx2 = crate::test_helpers::make_test_transaction();
        tx2.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("accept-encoding", "gzip, ")]);
        let v2 = crate::test_helpers::run_rule(
            &rule,
            &tx2,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v2.is_none());
        Ok(())
    }

    #[test]
    fn content_encoding_with_parameters_is_supported() -> anyhow::Result<()> {
        let rule = ContentEncodingRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-encoding", "gzip; param=1")]);

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
    fn iana_registry_entries_are_accepted() -> anyhow::Result<()> {
        let rule = ContentEncodingRegistered;
        let codings: Vec<String> = vec![
            "aes128gcm",
            "br",
            "compress",
            "dcb",
            "dcz",
            "deflate",
            "exi",
            "gzip",
            "identity",
            "pack200-gzip",
            "x-compress",
            "x-gzip",
            "zstd",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let mut cfg = crate::config::Config::default();
        cfg.rules.insert(
            "content_encoding_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(
                        codings
                            .iter()
                            .map(|s| toml::Value::String(s.clone()))
                            .collect(),
                    ),
                );
                t
            }),
        );

        for coding in &codings {
            // `identity` is in the registry but reserved for Accept-Encoding, so it
            // is exercised only on the request side below.
            if coding == "identity" {
                continue;
            }
            // response
            let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
            tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(
                &[("content-encoding", coding.as_str())],
            );
            let v = crate::test_helpers::run_rule(
                &rule,
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            );
            assert!(
                v.is_none(),
                "coding {} produced violation in response",
                coding
            );

            // request
            let mut tx2 = crate::test_helpers::make_test_transaction();
            tx2.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
                "accept-encoding",
                coding.as_str(),
            )]);
            let v2 = crate::test_helpers::run_rule(
                &rule,
                &tx2,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            );
            assert!(
                v2.is_none(),
                "coding {} produced violation in request",
                coding
            );
        }
        Ok(())
    }

    #[test]
    fn parse_config_accepts_uppercase_allowed_entries() -> anyhow::Result<()> {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "content_encoding_registered",
        ]);
        cfg.rules.insert(
            "content_encoding_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![toml::Value::String("GZIP".into())]),
                );
                t
            }),
        );

        let parsed = parse_allowed_config(&cfg, "content_encoding_registered")?;
        assert_eq!(parsed.allowed, vec!["gzip".to_string()]);
        Ok(())
    }

    #[test]
    fn unrecognized_content_coding_message_and_severity() -> anyhow::Result<()> {
        let rule = ContentEncodingRegistered;
        let mut cfg = crate::config::Config::default();
        cfg.rules.insert(
            "content_encoding_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("error".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![toml::Value::String("gzip".into())]),
                );
                t
            }),
        );

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-encoding", "x-foo")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let v = v.unwrap();
        assert_eq!(v.severity, crate::lint::Severity::Error);
        assert_eq!(
            v.message,
            "Unrecognized content-coding 'x-foo' in Content-Encoding header"
        );
        Ok(())
    }

    #[test]
    fn invalid_token_message_exact() -> anyhow::Result<()> {
        let rule = ContentEncodingRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        // use '@' which is not a tchar to trigger the invalid-token branch
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-encoding", "x@bad")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let v = v.unwrap();
        assert_eq!(v.message, "Invalid token '@' in Content-Encoding header");
        Ok(())
    }
}
