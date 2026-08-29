// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct XContentTypeOptionsPresent;

#[derive(Debug, Clone)]
pub struct XContentTypeOptionsConfig {
    pub severity: crate::lint::Severity,
    pub content_types: Vec<String>,
}

fn parse_x_content_type_options_config(
    config: &crate::config::Config,
    rule_id: &str,
) -> anyhow::Result<XContentTypeOptionsConfig> {
    let Some(rule_config) = config.get_rule_config(rule_id) else {
        return Err(anyhow::anyhow!(
            "rule 'x_content_type_options_present' requires configuration to be enabled. Example:\n[rules.x_content_type_options_present]\nenabled = true\ncontent_types = [\"text/html\", \"application/json\"]"
        ));
    };

    let table = rule_config.as_table().ok_or_else(|| {
        anyhow::anyhow!(
            "Configuration for rule 'x_content_type_options_present' must be a TOML table with 'content_types' array"
        )
    })?;

    let value = table.get("content_types").ok_or_else(|| {
        anyhow::anyhow!("'content_types' field is required and must be an array of strings")
    })?;

    let arr = value
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("'content_types' must be an array"))?;
    if arr.is_empty() {
        return Err(anyhow::anyhow!("'content_types' array cannot be empty"));
    }

    let mut content_types = Vec::new();
    for (idx, item) in arr.iter().enumerate() {
        let s = item.as_str().ok_or_else(|| {
            anyhow::anyhow!("'content_types' item at index {} is not a string", idx)
        })?;
        content_types.push(s.to_ascii_lowercase());
    }

    let severity = crate::rules::get_rule_severity_required(config, rule_id)?;

    Ok(XContentTypeOptionsConfig {
        content_types,
        severity,
    })
}

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const FETCH_3_6: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "Fetch",
    section: Some("3.6"),
    url: "https://fetch.spec.whatwg.org/#x-content-type-options-header",
    note: "`X-Content-Type-Options`: the conformance value ABNF (`\"nosniff\" ; case-insensitive`) and the determine-nosniff algorithm",
};
const MDN_X_CONTENT_TYPE_OPTIONS: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "MDN X-Content-Type-Options",
    section: None,
    url:
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Content-Type-Options",
    note: "Web Docs: X-Content-Type-Options",
};

impl Rule for XContentTypeOptionsPresent {
    fn id(&self) -> &'static str {
        "x_content_type_options_present"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn prepare(&self, cfg: &crate::config::Config) -> anyhow::Result<crate::rules::ResolvedRule> {
        let config = parse_x_content_type_options_config(cfg, self.id())?;
        // The two standard keys, **after** this rule's own options, so a config
        // naming a bad option still fails on that option.
        crate::rules::validate_rule_table(cfg, self.id())?;
        Ok(crate::rules::ResolvedRule {
            severity: config.severity,
            state: Box::new(config),
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
            let config: &XContentTypeOptionsConfig = ctx.state();
            let Some(resp) = &tx.response else {
                return None;
            };

            // A present header must actually enable the protection: browsers read the
            // first list element case-insensitively, so anything else means sniffing
            // stays on while the sender believes otherwise. A conforming extra element
            // after a valid first one is tolerated (the processing model ignores it).
            // cite(Fetch § 3.6): "X-Content-Type-Options = "nosniff" ; case-insensitive"
            // cite(Fetch § 3.6): "If values[0] is an ASCII case-insensitive match for "nosniff", then return true."
            if let Some(xcto) =
                crate::helpers::headers::get_header_str(&resp.headers, "x-content-type-options")
            {
                let first = xcto.split(',').next().unwrap_or("").trim();
                if !first.eq_ignore_ascii_case("nosniff") {
                    return Some(self.cited(&FETCH_3_6, config.severity, format!(
                            "X-Content-Type-Options value '{}' does not enable nosniff (the value must be `nosniff`, case-insensitive)",
                            xcto.trim()
                        )));
                }
            }

            // Get the response's content-type (without parameters)
            let content_type_header =
                crate::helpers::headers::get_header_str(&resp.headers, "content-type").and_then(
                    |s| {
                        crate::helpers::list::parse_semicolon_list(s)
                            .next()
                            .map(|v| v.to_ascii_lowercase())
                    },
                );

            if let Some(content_type) = content_type_header {
                // cite(Fetch § 3.6): "The `X-Content-Type-Options` response header can be used to require checking of a response’s `Content-Type` header against the destination of a request."
                // The 2xx gate is the rule's own tolerance (no sentence scopes the header
                // to successful responses). The configured content-type list stands in for
                // the request destination, which a proxy cannot know: the spec only blocks
                // for script-like and style destinations, so the config names the types a
                // deployment serves to those destinations.
                // cite(Fetch § 3.6.1): "Only request destinations that are script-like or "style" are considered as any exploits pertain to them."
                if (200..300).contains(&resp.status)
                    && config.content_types.contains(&content_type)
                    && !resp.headers.contains_key("x-content-type-options")
                {
                    return Some(self.violation(
                        config.severity,
                        "Missing X-Content-Type-Options: nosniff header".into(),
                    ));
                }
            }
            None
        };
        Vec::from_iter(finding())
    }

    fn title(&self) -> Option<&'static str> {
        Some("Server X-Content-Type-Options")
    }

    fn description(&self) -> &'static str {
        "This rule checks if responses include the `X-Content-Type-Options: nosniff` header.\n\nThis security header prevents browsers from \"MIME-sniffing\" a response away from the declared `Content-Type`. This reduces exposure to drive-by download attacks and cross-site scripting (XSS) vulnerabilities where a browser might execute a file as HTML/JavaScript even if the server served it as an image or text.\n\nA header that is present but whose first value is not `nosniff` (matched case-insensitively, per the Fetch standard's determine-nosniff algorithm) is also flagged: it does not enable the protection."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[FETCH_3_6, MDN_X_CONTENT_TYPE_OPTIONS]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("Response"),
                snippet: "HTTP/1.1 200 OK\nContent-Type: text/javascript\nX-Content-Type-Options: nosniff",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("Response"),
                snippet: "HTTP/1.1 200 OK\nContent-Type: text/javascript\n# Missing X-Content-Type-Options header",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &XContentTypeOptionsPresent;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::enable_rule;
    use rstest::rstest;

    #[rstest]
    #[case(200, vec![("content-type", "text/html")], vec!["text/html"], true, Some("Missing X-Content-Type-Options: nosniff header"))]
    #[case(200, vec![("content-type", "text/javascript"), ("x-content-type-options", "nosniff")], vec!["text/javascript"], false, None)]
    #[case(404, vec![("content-type", "text/html")], vec!["text/html"], false, None)]
    #[case(101, vec![("content-type", "text/html")], vec!["text/html"], false, None)]
    #[case(200, vec![("content-type", "image/png")], vec!["text/html"], false, None)]
    #[case(200, vec![("content-type", "text/html; charset=utf-8")], vec!["text/html"], true, Some("Missing X-Content-Type-Options: nosniff header"))]
    // A present header must enable the protection: the first value is matched
    // ASCII case-insensitively against `nosniff`.
    #[case(200, vec![("content-type", "text/html"), ("x-content-type-options", "foobar")], vec!["text/html"], true, Some("X-Content-Type-Options value 'foobar' does not enable nosniff (the value must be `nosniff`, case-insensitive)"))]
    #[case(200, vec![("content-type", "text/html"), ("x-content-type-options", "NOSNIFF")], vec!["text/html"], false, None)]
    #[case(200, vec![("content-type", "text/html"), ("x-content-type-options", "nosniff, extra")], vec!["text/html"], false, None)]
    // The value check is independent of status and configured types: a malformed
    // security header is wrong wherever it is sent.
    #[case(404, vec![("content-type", "text/html"), ("x-content-type-options", "sniff")], vec!["text/html"], true, Some("X-Content-Type-Options value 'sniff' does not enable nosniff (the value must be `nosniff`, case-insensitive)"))]
    fn check_response_cases(
        #[case] status: u16,
        #[case] header_pairs: Vec<(&str, &str)>,
        #[case] content_types: Vec<&str>,
        #[case] expect_violation: bool,
        #[case] expected_message: Option<&str>,
    ) -> anyhow::Result<()> {
        let rule = XContentTypeOptionsPresent;

        let mut config = crate::config::Config::default();
        config.rules.insert(
            "x_content_type_options_present".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "content_types".into(),
                    toml::Value::Array(
                        content_types
                            .iter()
                            .map(|s| toml::Value::String(s.to_string()))
                            .collect(),
                    ),
                );
                t
            }),
        );

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(header_pairs.as_slice()),

            body_length: None,
            trailers: None,
        });

        let violation = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        );

        if expect_violation {
            assert!(violation.is_some());
            assert_eq!(
                violation.map(|v| v.message),
                expected_message.map(|s| s.to_string())
            );
        } else {
            assert!(violation.is_none());
        }
        Ok(())
    }

    #[rstest]
    #[case("missing_table", true, None)]
    #[case("non_table", true, Some("must be a TOML table"))]
    #[case("missing_field", true, None)]
    #[case("non_array", true, None)]
    #[case("non_string_item", true, Some("not a string"))]
    #[case("empty_array", true, Some("cannot be empty"))]
    #[case("valid", false, None)]
    fn validate_config_cases(
        #[case] scenario: &str,
        #[case] expect_error: bool,
        #[case] expected_substring: Option<&str>,
    ) -> anyhow::Result<()> {
        let rule = XContentTypeOptionsPresent;
        let mut cfg = crate::config::Config::default();

        match scenario {
            "missing_table" => {
                // No rule table at all
            }
            "non_table" => {
                cfg.rules.insert(
                    "x_content_type_options_present".to_string(),
                    toml::Value::String("not a table".to_string()),
                );
            }
            "missing_field" => {
                enable_rule(&mut cfg, "x_content_type_options_present");
            }
            "non_array" => {
                let mut table = toml::map::Map::new();
                table.insert("enabled".to_string(), toml::Value::Boolean(true));
                table.insert(
                    "content_types".to_string(),
                    toml::Value::String("text/html".to_string()),
                );
                cfg.rules.insert(
                    "x_content_type_options_present".to_string(),
                    toml::Value::Table(table),
                );
            }
            "non_string_item" => {
                let mut table = toml::map::Map::new();
                table.insert("enabled".to_string(), toml::Value::Boolean(true));
                table.insert(
                    "content_types".to_string(),
                    toml::Value::Array(vec![toml::Value::Integer(5)]),
                );
                cfg.rules.insert(
                    "x_content_type_options_present".to_string(),
                    toml::Value::Table(table),
                );
            }
            "empty_array" => {
                let mut table = toml::map::Map::new();
                table.insert("enabled".to_string(), toml::Value::Boolean(true));
                table.insert("content_types".to_string(), toml::Value::Array(vec![]));
                cfg.rules.insert(
                    "x_content_type_options_present".to_string(),
                    toml::Value::Table(table),
                );
            }
            "valid" => {
                let mut table = toml::map::Map::new();
                table.insert("enabled".to_string(), toml::Value::Boolean(true));
                table.insert(
                    "severity".to_string(),
                    toml::Value::String("warn".to_string()),
                );
                table.insert(
                    "content_types".to_string(),
                    toml::Value::Array(vec![toml::Value::String("text/html".to_string())]),
                );
                cfg.rules.insert(
                    "x_content_type_options_present".to_string(),
                    toml::Value::Table(table),
                );
            }
            _ => panic!("unknown scenario"),
        }

        let res = rule.prepare(&cfg);
        if expect_error {
            assert!(res.is_err());
            if let Some(sub) = expected_substring {
                assert!(res.unwrap_err().to_string().contains(sub));
            }
        } else {
            res?;
            let parsed = super::parse_x_content_type_options_config(&cfg, rule.id())?;
            assert_eq!(parsed.content_types, vec!["text/html".to_string()]);
        }
        Ok(())
    }

    #[test]
    fn check_response_with_parameters_matches() -> anyhow::Result<()> {
        let rule = XContentTypeOptionsPresent;

        let status = 200;
        let mut config = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert(
            "severity".to_string(),
            toml::Value::String("warn".to_string()),
        );
        table.insert(
            "content_types".to_string(),
            toml::Value::Array(vec![toml::Value::String("text/html".to_string())]),
        );
        config.rules.insert(
            "x_content_type_options_present".to_string(),
            toml::Value::Table(table),
        );

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[(
                "content-type",
                "text/html; charset=utf-8",
            )]),

            body_length: None,
            trailers: None,
        });

        let violation = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        );
        assert!(violation.is_some());
        Ok(())
    }

    #[test]
    fn check_missing_response() {
        let rule = XContentTypeOptionsPresent;
        let tx = crate::test_helpers::make_test_transaction();
        let mut config = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert(
            "severity".to_string(),
            toml::Value::String("warn".to_string()),
        );
        table.insert(
            "content_types".to_string(),
            toml::Value::Array(vec![toml::Value::String("text/html".to_string())]),
        );
        config.rules.insert(
            "x_content_type_options_present".to_string(),
            toml::Value::Table(table),
        );
        let violation = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        );
        assert!(violation.is_none());
    }

    #[test]
    fn id_and_scope_are_expected() {
        let rule = XContentTypeOptionsPresent;
        assert_eq!(rule.id(), "x_content_type_options_present");
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }
}
