// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageRangeAndContentRangeConsistency;

pub struct RangeConsistencyConfig {
    pub enabled: bool,
    pub severity: crate::lint::Severity,
    /// Range units whose positions this rule may read as octet offsets.
    pub units: Vec<String>,
}

fn parse_units_config(
    config: &crate::config::Config,
    rule_id: &str,
) -> anyhow::Result<RangeConsistencyConfig> {
    let severity = crate::rules::get_rule_severity_required(config, rule_id)?;
    let enabled = crate::rules::get_rule_enabled_required(config, rule_id)?;

    let rule_cfg = config.get_rule_config(rule_id).ok_or_else(|| {
        anyhow::anyhow!(
            "rule '{}' requires configuration and a named 'units' array listing the range units whose lengths may be checked against Content-Length. Example in config_example.toml",
            rule_id
        )
    })?;
    let table = rule_cfg
        .as_table()
        .ok_or_else(|| anyhow::anyhow!("Configuration for rule '{}' must be a table", rule_id))?;

    let units_val = table.get("units").ok_or_else(|| {
        anyhow::anyhow!(
            "Rule '{}' requires a 'units' array listing range units to check (e.g., ['bytes'])",
            rule_id
        )
    })?;

    let arr = units_val
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("'units' must be an array of strings (e.g., ['bytes'])"))?;

    if arr.is_empty() {
        return Err(anyhow::anyhow!("'units' array cannot be empty"));
    }

    let mut out = Vec::new();
    for (i, item) in arr.iter().enumerate() {
        let s = item
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("'units' array item at index {} must be a string", i))?;
        // Unit names are case-insensitive, so the configured names are folded once
        // here and compared against an already-folded parse result.
        out.push(s.to_ascii_lowercase());
    }

    Ok(RangeConsistencyConfig {
        enabled,
        severity,
        units: out,
    })
}

impl Rule for MessageRangeAndContentRangeConsistency {
    fn id(&self) -> &'static str {
        "message_range_and_content_range_consistency"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn validate(&self, config: &crate::config::Config) -> anyhow::Result<()> {
        parse_units_config(config, self.id())?;
        Ok(())
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = parse_units_config(cfg, self.id()).ok()?;
        let resp = tx.response.as_ref()?;

        let status = resp.status;
        let has_range_request = tx.request.headers.get("range").is_some();

        // 206 Partial Content rules
        // cite(RFC 9110 § 14.4): "The "Content-Range" header field is sent in a single part 206 (Partial Content) response"
        if status == 206 {
            // 206 MUST include a valid Content-Range
            let cr = crate::helpers::headers::get_header_str(&resp.headers, "content-range");
            if cr.is_none() {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "206 Partial Content response missing Content-Range header".into(),
                });
            }
            let cr = cr.unwrap();
            match crate::helpers::content_range::parse_content_range(cr) {
                Ok(crate::helpers::content_range::ContentRange::Satisfied {
                    ref unit,
                    first,
                    last,
                    ..
                }) => {
                    // If no Range was present in the request, 206 is unexpected
                    if !has_range_request {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: "206 Partial Content response received but request did not include a Range header".into(),
                        });
                    }

                    // Everything above holds whatever the unit is. What follows does not:
                    // first-pos and last-pos count units, Content-Length counts octets, and
                    // the two are the same number only for `bytes`. For any other unit this
                    // is not a violation we are declining to report -- it is an equation we
                    // have no basis to write down.
                    //
                    // cite(RFC 9110 § 14.4): "If a 206 (Partial Content) response contains a Content-Range header field with a range unit (Section 14.1) that the recipient does not understand, the recipient MUST NOT attempt to recombine it with a stored representation."
                    if !config.units.iter().any(|u| u == unit) {
                        return None;
                    }

                    // If Content-Length is present, it must equal last-first+1
                    if let Some(cl) =
                        crate::helpers::headers::get_header_str(&resp.headers, "content-length")
                    {
                        if let Ok(cl_v) = cl.trim().parse::<u128>() {
                            let expected = (last - first) + 1;
                            if cl_v != expected {
                                return Some(Violation {
                                    rule: self.id().into(),
                                    severity: config.severity,
                                    message: format!("Content-Length ({}) does not match Content-Range length ({})", cl_v, expected),
                                });
                            }
                        } else {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: format!("Invalid Content-Length value: {}", cl),
                            });
                        }
                    }
                }
                Ok(crate::helpers::content_range::ContentRange::Unsatisfiable { .. }) => {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "206 response must not use '*' byte-range-resp-spec (use 416 for unsatisfiable ranges)".into(),
                    });
                }
                Err(e) => {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!("Invalid Content-Range header '{}': {}", cr, e),
                    });
                }
            }
        }

        // 416 Range Not Satisfiable rules
        if status == 416 {
            // 416 MUST include a Content-Range with "*" response and instance-length
            let cr = crate::helpers::headers::get_header_str(&resp.headers, "content-range");
            if cr.is_none() {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "416 Range Not Satisfiable response missing Content-Range header"
                        .into(),
                });
            }
            let cr = cr.unwrap();
            match crate::helpers::content_range::parse_content_range(cr) {
                Ok(crate::helpers::content_range::ContentRange::Unsatisfiable { .. }) => {
                    // ok
                }
                Ok(crate::helpers::content_range::ContentRange::Satisfied { .. }) => {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "416 response must use '*' byte-range-resp-spec in Content-Range"
                            .into(),
                    });
                }
                Err(e) => {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!("Invalid Content-Range header '{}': {}", cr, e),
                    });
                }
            }
        }

        None
    }

    fn description(&self) -> &'static str {
        "Validate the semantics and syntax of `Range` (request) and `Content-Range` (response) interactions.\nThis rule enforces that 206 (Partial Content) responses include a valid `Content-Range` describing the enclosed byte range, that 416 (Range Not Satisfiable) responses include an unsatisfiable `Content-Range` (`bytes */<length>`), and that `Content-Length` (when present) matches the indicated range length."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("15.3.7"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.7",
                note: "206 Partial Content: single-part 206 responses MUST include a `Content-Range` header describing the enclosed range",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("14.4"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-14.4",
                note: "Content-Range: syntax of `Content-Range` and the semantics for satisfied and unsatisfiable ranges",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("15.5.17"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5.17",
                note: "416 Range Not Satisfiable: server SHOULD include `Content-Range: bytes */<complete-length>` in 416 responses",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "GET /resource HTTP/1.1\nHost: example.com\nRange: bytes=0-499\n\nHTTP/1.1 206 Partial Content\nContent-Range: bytes 0-499/1234\nContent-Length: 500\nContent-Type: application/octet-stream\n\n...500 bytes...",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "GET /resource HTTP/1.1\nHost: example.com\nRange: bytes=0-499\n\nHTTP/1.1 206 Partial Content\nContent-Length: 500\n\n...500 bytes but missing Content-Range in headers...",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "GET /resource HTTP/1.1\nHost: example.com\n\nHTTP/1.1 206 Partial Content\nContent-Range: bytes 0-1/10\n\n# 206 must not be sent if the request did not include a Range header",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 416 Range Not Satisfiable\nContent-Range: bytes 0-1/10\n\n# 416 must use a \"*/length\" unsatisfied-range form",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &MessageRangeAndContentRangeConsistency;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// The rule's config with an explicit `units` list. `["bytes"]` is what
    /// `config_example.toml` ships; a test wanting another unit says so.
    fn cfg_with_units(units: &[&str]) -> crate::config::Config {
        let mut cfg = crate::config::Config::default();
        let mut t = toml::map::Map::new();
        t.insert("enabled".into(), toml::Value::Boolean(true));
        t.insert("severity".into(), toml::Value::String("warn".into()));
        t.insert(
            "units".into(),
            toml::Value::Array(
                units
                    .iter()
                    .map(|s| toml::Value::String(s.to_string()))
                    .collect(),
            ),
        );
        cfg.rules.insert(
            "message_range_and_content_range_consistency".into(),
            toml::Value::Table(t),
        );
        cfg
    }

    #[rstest]
    fn valid_206_with_matching_length() {
        let tx = crate::test_helpers::make_test_transaction_with_response(
            206,
            &[
                ("content-range", "bytes 0-499/1234"),
                ("content-length", "500"),
            ],
        );
        // add Range header to request to make 206 valid
        let mut tx = tx;
        tx.request
            .headers
            .insert("range", "bytes=0-499".parse().unwrap());

        let rule = MessageRangeAndContentRangeConsistency;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg_with_units(&["bytes"]),
        );
        assert!(v.is_none());
    }

    #[rstest]
    fn test_206_missing_content_range_reports_violation() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(206, &[]);
        tx.request
            .headers
            .insert("range", "bytes=0-1".parse().unwrap());
        let rule = MessageRangeAndContentRangeConsistency;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg_with_units(&["bytes"]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("missing Content-Range"));
    }

    #[rstest]
    fn test_206_with_invalid_content_range_reports_violation() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            206,
            &[("content-range", "bytes 5-3/10")],
        );
        tx.request
            .headers
            .insert("range", "bytes=5-3".parse().unwrap());
        let rule = MessageRangeAndContentRangeConsistency;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg_with_units(&["bytes"]),
        );
        assert!(v.is_some());
    }

    #[rstest]
    fn test_206_without_range_in_request_reports_violation() {
        let tx = crate::test_helpers::make_test_transaction_with_response(
            206,
            &[("content-range", "bytes 0-1/10")],
        );
        let rule = MessageRangeAndContentRangeConsistency;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg_with_units(&["bytes"]),
        );
        assert!(v.is_some());
        assert!(v
            .unwrap()
            .message
            .contains("request did not include a Range"));
    }

    #[rstest]
    fn content_length_mismatch_reports_violation() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            206,
            &[
                ("content-range", "bytes 0-499/1234"),
                ("content-length", "400"),
            ],
        );
        tx.request
            .headers
            .insert("range", "bytes=0-499".parse().unwrap());
        let rule = MessageRangeAndContentRangeConsistency;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg_with_units(&["bytes"]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Content-Length"));
    }

    #[rstest]
    fn test_416_requires_unsatisfiable_content_range() {
        let tx_ok = crate::test_helpers::make_test_transaction_with_response(
            416,
            &[("content-range", "bytes */1234")],
        );
        let rule = MessageRangeAndContentRangeConsistency;
        let v = rule.check_transaction(
            &tx_ok,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg_with_units(&["bytes"]),
        );
        assert!(v.is_none());

        let tx_bad = crate::test_helpers::make_test_transaction_with_response(
            416,
            &[("content-range", "bytes 0-0/1234")],
        );
        let v2 = rule.check_transaction(
            &tx_bad,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg_with_units(&["bytes"]),
        );
        assert!(v2.is_some());

        let tx_missing = crate::test_helpers::make_test_transaction_with_response(416, &[]);
        let v3 = rule.check_transaction(
            &tx_missing,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg_with_units(&["bytes"]),
        );
        assert!(v3.is_some());
    }

    #[rstest]
    fn test_206_with_unsatisfiable_content_range_reports_violation() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            206,
            &[("content-range", "bytes */1234")],
        );
        tx.request
            .headers
            .insert("range", "bytes=0-1".parse().unwrap());
        let rule = MessageRangeAndContentRangeConsistency;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg_with_units(&["bytes"]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("must not use '*'"));
    }

    #[rstest]
    fn test_206_with_non_numeric_content_length_reports_violation() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            206,
            &[("content-range", "bytes 0-1/10"), ("content-length", "abc")],
        );
        tx.request
            .headers
            .insert("range", "bytes=0-1".parse().unwrap());
        let rule = MessageRangeAndContentRangeConsistency;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg_with_units(&["bytes"]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Invalid Content-Length"));
    }

    #[test]
    fn scope_is_both() {
        let rule = MessageRangeAndContentRangeConsistency;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        crate::rules::validate_rules(&cfg_with_units(&["bytes"]))?;
        Ok(())
    }

    fn tx_206_with_unit(cr: &str, range: &str) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            206,
            &[("content-range", cr), ("content-length", "2")],
        );
        tx.request.headers.insert("range", range.parse().unwrap());
        tx
    }

    /// A unit outside the configured list is legal and unmodelled, not invalid.
    /// `items 0-1/3` describes 2 items; `content-length: 2` is 2 octets, and the
    /// agreement between those numbers is a coincidence we must not read.
    #[rstest]
    fn unconfigured_unit_is_not_reported() {
        let rule = MessageRangeAndContentRangeConsistency;
        let v = rule.check_transaction(
            &tx_206_with_unit("items 0-1/3", "items=0-1"),
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg_with_units(&["bytes"]),
        );
        assert!(v.is_none(), "legal unmodelled unit reported: {:?}", v);
    }

    /// ...and the same traffic is checked once the unit is configured, which is
    /// what shows the skip is the config's doing and not a blanket exemption.
    #[rstest]
    fn configured_unit_is_checked() {
        let rule = MessageRangeAndContentRangeConsistency;
        let v = rule.check_transaction(
            &tx_206_with_unit("items 0-5/9", "items=0-5"),
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg_with_units(&["bytes", "items"]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("does not match"));
    }

    /// A malformed unit is still a malformed Content-Range.
    #[rstest]
    fn non_token_unit_is_reported() {
        let rule = MessageRangeAndContentRangeConsistency;
        let v = rule.check_transaction(
            &tx_206_with_unit("by(tes 0-1/3", "bytes=0-1"),
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg_with_units(&["bytes"]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("invalid range-unit"));
    }
}
