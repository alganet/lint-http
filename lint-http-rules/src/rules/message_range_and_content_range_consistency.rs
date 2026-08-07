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

/// Whether the response declares the media type § 15.3.7.2 requires of a 206
/// that carries multiple parts. Only the first `Content-Type` field line is
/// read; a message carrying more than one is `message_content_type_well_formed`'s
/// finding, and the parameters (the boundary among them) belong to
/// `message_multipart_boundary_syntax`.
///
/// The comparison is case-insensitive because the production says so, not
/// because it is being kind: `multipart/byteranges` and `Multipart/ByteRanges`
/// are one media type.
// cite(RFC 9110 § 8.3.1): "The type and subtype tokens are case-insensitive."
fn response_is_multipart_byteranges(headers: &hyper::HeaderMap) -> bool {
    let Some(ct) = crate::helpers::headers::get_header_str(headers, "content-type") else {
        return false;
    };
    match crate::helpers::headers::parse_media_type(ct) {
        Ok(mt) => {
            mt.type_.eq_ignore_ascii_case("multipart")
                && mt.subtype.eq_ignore_ascii_case("byteranges")
        }
        Err(_) => false,
    }
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
        // What the request asked for, read from its first `Range` field line: the
        // unit it named and the range-set it named it over. A value that is not a
        // `ranges-specifier` at all is `client_range_header_syntax_valid`'s
        // finding, and leaves this rule knowing less rather than guessing.
        let requested = crate::helpers::headers::get_header_str(&tx.request.headers, "range")
            .and_then(crate::helpers::content_range::split_ranges_specifier);

        // A 206 is *defined* as the answer to a range request, so one returned to a
        // request that asked for no range contradicts its own status code. No MUST
        // states this, and none is needed: the sentence says what the code
        // indicates, and here it indicates something that did not happen. This
        // check used to sit two branches deeper, where only a 206 carrying a
        // well-formed satisfied Content-Range could reach it.
        // cite(RFC 9110 § 15.3.7): "The 206 (Partial Content) status code indicates that the server is successfully fulfilling a range request for the target resource by transferring one or more parts of the selected representation."
        if status == 206 && !has_range_request {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message:
                    "206 Partial Content response received but request did not include a Range header"
                        .into(),
            });
        }

        // 206 Partial Content rules
        // cite(RFC 9110 § 14.4): "The "Content-Range" header field is sent in a single part 206 (Partial Content) response to indicate the partial range of the selected representation enclosed as the message content, sent in each part of a multipart 206 response to indicate the range enclosed within each body part (Section 14.6), and sent in 416 (Range Not Satisfiable) responses to provide information about the selected representation."
        if status == 206 {
            let cr = crate::helpers::headers::get_header_str(&resp.headers, "content-range");

            // Which half of § 15.3.7 governs is decided by the response's own
            // Content-Type, and the two halves want opposite things of this header
            // section. The rule knew only the single-part half -- it required a
            // Content-Range of every 206 -- so a conforming multipart response was
            // reported for obeying a MUST NOT, and that MUST NOT went unenforced.
            // The § 15.3.7 SpecRef note has said "single-part" since the rule was
            // written; the code never had the condition.
            // cite(RFC 9110 § 15.3.7.2): "If multiple parts are being transferred, the server generating the 206 response MUST generate "multipart/byteranges" content, as defined in Section 14.6, and a Content-Type header field containing the "multipart/byteranges" media type and its required boundary parameter."
            if response_is_multipart_byteranges(&resp.headers) {
                // cite(RFC 9110 § 15.3.7.2): "To avoid confusion with single-part responses, a server MUST NOT generate a Content-Range header field in the HTTP header section of a multiple part response (this field will be sent in each part instead)."
                if cr.is_some() {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "multipart/byteranges 206 response must not carry a Content-Range header field in its header section (each body part carries its own)".into(),
                    });
                }

                // One requested range may not be answered with a multipart
                // response at all. The count is exact rather than a guess: a
                // range-set is a `#`-list, whose separator is the comma, and no
                // range-spec may contain one. Empty elements are not elements, so
                // the shared list splitter is the one that counts them -- and a
                // `Range` this rule could not split into a specifier leaves
                // `requested` empty, which reports nothing.
                // cite(RFC 9110 § 15.3.7.2): "A server MUST NOT generate a multipart response to a request for a single range, since a client that does not request multiple parts might not support multipart responses."
                // cite(RFC 9110 § 5.6.1.2): "Empty elements do not contribute to the count of elements present."
                let requested_ranges = requested
                    .as_ref()
                    .map(|(_, set)| crate::helpers::headers::parse_list_header(set).count());
                if requested_ranges == Some(1) {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message:
                            "multipart/byteranges 206 response sent to a request for a single range"
                                .into(),
                    });
                }

                // Each part's own Content-Range is in the message content, which
                // this rule does not read. The requirement below is therefore
                // neither checked nor waived here.
                // cite(RFC 9110 § 15.3.7.2): "Within the header area of each body part in the multipart content, the server MUST generate a Content-Range header field corresponding to the range being enclosed in that body part."
                return None;
            }

            // Single part: the field is required, and this is the sentence the
            // rule has been reporting all along -- with its first six words gone.
            // cite(RFC 9110 § 15.3.7.1): "If a single part is being transferred, the server generating the 206 response MUST generate a Content-Range header field, describing what range of the selected representation is enclosed, and a content consisting of the range."
            let cr = match cr {
                Some(v) => v,
                None => {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "206 Partial Content response missing Content-Range header".into(),
                    })
                }
            };
            match crate::helpers::content_range::parse_content_range(cr) {
                Ok(crate::helpers::content_range::ContentRange::Satisfied {
                    ref unit,
                    first,
                    last,
                    ..
                }) => {
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
        "Validate the semantics and syntax of `Range` (request) and `Content-Range` (response) interactions.\n\n**A 206 carrying a single part** MUST include a `Content-Range` describing the enclosed range, and `Content-Length` (when present) must equal that range's length.\n\n**A 206 carrying multiple parts** is the opposite case, and RFC 9110 §15.3.7.2 is explicit about it: the parts each carry their own `Content-Range` and the header section MUST NOT carry one. A response whose `Content-Type` is `multipart/byteranges` is therefore checked for the *presence* of the field rather than its absence — and, since a client that asked for one range may not be able to read a multipart response, for having been sent to a request that asked for more than one. What is inside the parts is message content, which this rule does not read.\n\n**A 416** (Range Not Satisfiable) must include an unsatisfiable `Content-Range` (`bytes */<length>`).\n\nA 206 whose request carried no `Range` at all contradicts the status code's own definition, and is reported whatever its `Content-Range` says.\n\n**Not this rule's finding:** a `Range` value that is not a `ranges-specifier` belongs to `client_range_header_syntax_valid`, and leaves this rule knowing less rather than guessing."
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
                section: Some("15.3.7.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.7.2",
                note: "206 Partial Content, multiple parts: the parts carry the `Content-Range` fields and the header section MUST NOT carry one; a request for a single range MUST NOT be answered with a multipart response",
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

    /// A 206 that carries its parts as `multipart/byteranges` sends each
    /// Content-Range inside a body part, and § 15.3.7.2 forbids one here. The
    /// rule used to require one of every 206, so this conforming response was
    /// reported for obeying a MUST NOT.
    #[rstest]
    fn multipart_206_without_top_level_content_range_is_accepted() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            206,
            &[
                ("content-type", "multipart/byteranges; boundary=SEP"),
                ("content-length", "1741"),
            ],
        );
        tx.request
            .headers
            .insert("range", "bytes=500-999,7000-7999".parse().unwrap());
        let rule = MessageRangeAndContentRangeConsistency;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg_with_units(&["bytes"]),
        );
        assert!(v.is_none(), "conforming multipart 206 reported: {:?}", v);
    }

    /// ...and the same message with the field present is the violation, which
    /// nothing in this rule used to be able to say.
    #[rstest]
    fn multipart_206_with_top_level_content_range_is_reported() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            206,
            &[
                ("content-type", "Multipart/ByteRanges; boundary=SEP"),
                ("content-range", "bytes 500-999/8000"),
            ],
        );
        tx.request
            .headers
            .insert("range", "bytes=500-999,7000-7999".parse().unwrap());
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
            .contains("must not carry a Content-Range"));
    }

    /// A client that asked for one range might not be able to read a multipart
    /// response, so the server may not send one.
    #[rstest]
    fn multipart_206_to_single_range_request_is_reported() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            206,
            &[("content-type", "multipart/byteranges; boundary=SEP")],
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
        assert!(v.unwrap().message.contains("single range"));
    }

    /// An empty list element is not an element, so `bytes=0-499,` asked for one
    /// range and is reported as one -- the malformed value itself is
    /// `client_range_header_syntax_valid`'s finding, not this rule's.
    #[rstest]
    fn empty_range_list_element_does_not_inflate_the_count() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            206,
            &[("content-type", "multipart/byteranges; boundary=SEP")],
        );
        tx.request
            .headers
            .insert("range", "bytes=0-499,".parse().unwrap());
        let rule = MessageRangeAndContentRangeConsistency;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg_with_units(&["bytes"]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("single range"));
    }

    /// A 206 with no Range in the request is reported whatever its
    /// Content-Range says -- the check used to be reachable only through a
    /// well-formed satisfied one.
    #[rstest]
    fn missing_request_range_is_reported_before_the_content_range_is_read() {
        let rule = MessageRangeAndContentRangeConsistency;
        for headers in [
            vec![("content-range", "bytes */1234")],
            vec![("content-range", "bytes 5-3/10")],
            vec![("content-type", "multipart/byteranges; boundary=SEP")],
        ] {
            let tx = crate::test_helpers::make_test_transaction_with_response(206, &headers);
            let v = rule.check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg_with_units(&["bytes"]),
            );
            assert!(v
                .expect("a 206 to a request with no Range is reported")
                .message
                .contains("request did not include a Range"));
        }
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
