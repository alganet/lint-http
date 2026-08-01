// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

#[derive(Debug, Clone)]
pub struct CharsetConfig {
    pub enabled: bool,
    pub severity: crate::lint::Severity,
    pub allowed: Vec<String>,
}

fn parse_allowed_config(
    config: &crate::config::Config,
    rule_id: &str,
) -> anyhow::Result<CharsetConfig> {
    let severity = crate::rules::get_rule_severity_required(config, rule_id)?;
    let enabled = crate::rules::get_rule_enabled_required(config, rule_id)?;

    let rule_cfg = config.get_rule_config(rule_id).ok_or_else(|| {
        anyhow::anyhow!(
            "rule '{}' requires configuration and a named 'allowed' array listing acceptable charset names. Example in config_example.toml",
            rule_id
        )
    })?;

    let table = rule_cfg
        .as_table()
        .ok_or_else(|| anyhow::anyhow!("Configuration for rule '{}' must be a table", rule_id))?;

    let allowed_val = table.get("allowed").ok_or_else(|| {
        anyhow::anyhow!(
            "Rule '{}' requires an 'allowed' array listing allowed character set names (e.g., ['utf-8','iso-8859-1'])",
            rule_id
        )
    })?;

    let arr = allowed_val.as_array().ok_or_else(|| {
        anyhow::anyhow!("'allowed' must be an array of strings (e.g., ['utf-8','iso-8859-1'])")
    })?;

    if arr.is_empty() {
        return Err(anyhow::anyhow!("'allowed' array cannot be empty"));
    }

    // Entries are folded once here rather than at every comparison, which is
    // sound because the matching itself is defined to ignore case.
    // cite(RFC 9110 § 8.3.2): "In both cases, charset names are matched case-insensitively."
    let mut out = Vec::new();
    for (i, item) in arr.iter().enumerate() {
        let s = item.as_str().ok_or_else(|| {
            anyhow::anyhow!("'allowed' array item at index {} must be a string", i)
        })?;
        out.push(s.to_ascii_lowercase());
    }

    Ok(CharsetConfig {
        enabled,
        severity,
        allowed: out,
    })
}

pub struct MessageCharsetIanaRegistered;

impl Rule for MessageCharsetIanaRegistered {
    fn id(&self) -> &'static str {
        "message_charset_iana_registered"
    }

    // The parameter this rule reads lives in Content-Type, which describes the
    // representation a message carries — and both directions carry one.
    // cite(RFC 9110 § 8.3.2): "HTTP uses "charset" names to indicate or negotiate the character encoding scheme ([RFC6365], Section 2) of a textual representation."
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn validate(&self, config: &crate::config::Config) -> anyhow::Result<()> {
        parse_allowed_config(config, self.id())?;
        Ok(())
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = parse_allowed_config(cfg, self.id()).ok()?;
        use crate::helpers::headers::parse_media_type;

        let check_header = |which: &str, val: &str| -> Option<Violation> {
            // A value that is not a media-type at all has no parameters to read,
            // and saying so is `message_content_type_well_formed`'s finding, not
            // this one's. The `media-type` grammar is the helper's.
            let parsed = match parse_media_type(val) {
                Ok(p) => p,
                Err(_) => return None,
            };

            if let Some(params) = parsed.params {
                // Quote-aware, because a `;` inside a quoted parameter value does
                // not separate parameters. A raw `split(';')` cut such a value in
                // half and then read the halves as parameters of their own, so a
                // boundary like `boundary="x; charset=bogus"` produced a charset
                // finding for a message that has no charset parameter at all.
                // Every other rule that walks media-type parameters already uses
                // this helper; this one was the exception.
                for raw in crate::helpers::headers::split_semicolons_respecting_quotes(params) {
                    let p = raw.trim();
                    if p.is_empty() {
                        continue;
                    }
                    if let Some(eq) = p.find('=') {
                        let (name, value) = p.split_at(eq);
                        let name = name.trim();
                        let value = value[1..].trim(); // skip '='
                                                       // cite(RFC 9110 § 5.6.6): "Parameter names are case-insensitive."
                        if name.eq_ignore_ascii_case("charset") {
                            // An unquoted value must satisfy `token`, and `token`
                            // is `1*tchar`, so nothing after the "=" is not a
                            // charset name that happens to be unregistered — it
                            // is not a parameter value at all.
                            // cite(RFC 9110 § 5.6.6): "parameter-value = ( token / quoted-string )"
                            if value.is_empty() {
                                return Some(Violation {
                                    rule: MessageCharsetIanaRegistered.id().into(),
                                    severity: config.severity,
                                    message: format!(
                                        "Invalid Content-Type in {}: empty 'charset' parameter",
                                        which
                                    ),
                                });
                            }

                            // The two alternatives of `parameter-value`, each
                            // handed to the helper that owns its grammar:
                            // `quoted-string` is unescaped and validated in one
                            // step, `token` is checked character by character.
                            // A charset name is compared after unescaping, since
                            // "the quoted and unquoted values are equivalent".
                            let mut value_owned: Option<String> = None;
                            if value.starts_with('"') {
                                match crate::helpers::headers::unescape_quoted_string(value) {
                                    Ok(u) => value_owned = Some(u),
                                    Err(e) => {
                                        return Some(Violation {
                                            rule: MessageCharsetIanaRegistered.id().into(),
                                            severity: config.severity,
                                            message: format!(
                                                "Invalid Content-Type in {}: 'charset' quoted-string invalid: {}",
                                                which, e
                                            ),
                                        })
                                    }
                                }
                            } else {
                                // Narrower than the charset production by two
                                // characters: §8.3.2 notes that `mime-charset`
                                // (RFC 2978 §2.3) admits "{" and "}", which
                                // `token` does not, while also noting that no
                                // registered charset name uses them. Since an
                                // unregistered name is reported anyway, the
                                // narrowing changes the message and not the
                                // verdict. (That note sits in a gutter-marked
                                // block, which apycite cannot quote verbatim.)
                                if let Some(c) =
                                    crate::helpers::token::find_invalid_token_char(value)
                                {
                                    return Some(Violation {
                                        rule: MessageCharsetIanaRegistered.id().into(),
                                        severity: config.severity,
                                        message: format!(
                                            "Invalid Content-Type in {}: charset contains invalid character '{}'",
                                            which, c
                                        ),
                                    });
                                }
                            }
                            let value = value_owned.as_deref().unwrap_or(value);

                            if value.is_empty() {
                                return Some(Violation {
                                    rule: MessageCharsetIanaRegistered.id().into(),
                                    severity: config.severity,
                                    message: format!(
                                        "Invalid Content-Type in {}: empty 'charset' parameter",
                                        which
                                    ),
                                });
                            }

                            // The rule's name says IANA; the code says the
                            // operator's `allowed` array. The registry is never
                            // consulted — there is no lookup — so this cite is
                            // the *motivation*, and "ought to" is why the whole
                            // rule is a policy rather than a conformance check.
                            // The fold is the matching rule, not a convenience.
                            // cite(RFC 9110 § 8.3.2): "Charset names ought to be registered in the IANA "Character Sets" registry (<https://www.iana.org/assignments/character-sets>) according to the procedures defined in Section 2 of [RFC2978]."
                            // cite(RFC 9110 § 8.3.2): "In both cases, charset names are matched case-insensitively."
                            if !config.allowed.contains(&value.to_ascii_lowercase()) {
                                return Some(Violation {
                                    rule: MessageCharsetIanaRegistered.id().into(),
                                    severity: config.severity,
                                    message: format!(
                                        "Unrecognized charset '{}' in {} header",
                                        value, which
                                    ),
                                });
                            }
                        }
                    }
                }
            }
            None
        };

        // Every Content-Type field line, not just the first. `get_header_str`
        // returns one value, and RFC 9110 §8.3 says recipients faced with a
        // duplicated Content-Type often act on the *last* syntactically valid
        // member — so an unregistered charset on a second line was invisible
        // here while being the one a recipient might use.
        //
        // That there is more than one line is `message_content_type_well_formed`'s
        // finding to report; this rule adds nothing by repeating it, and says
        // only what it owns: whether a charset it can see is recognized.
        let check_all = |which: &str, headers: &hyper::HeaderMap| -> Option<Violation> {
            for hv in headers.get_all("content-type").iter() {
                let Ok(s) = hv.to_str() else { continue };
                if let Some(v) = check_header(which, s) {
                    return Some(v);
                }
            }
            None
        };

        if let Some(v) = check_all("request", &tx.request.headers) {
            return Some(v);
        }
        if let Some(resp) = &tx.response {
            if let Some(v) = check_all("response", &resp.headers) {
                return Some(v);
            }
        }

        None
    }

    fn description(&self) -> &'static str {
        "If a `Content-Type` header carries a `charset` parameter, this rule checks the name against an allowlist you configure. It also reports an empty `charset`, a malformed quoted-string, and characters that do not belong in the name.\n\n**It does not consult the IANA registry**, despite the rule's name: there is no lookup, and a charset is \"registered\" as far as this rule is concerned exactly when your `allowed` array covers it. RFC 9110 §8.3.2 says charset names *ought to* be registered, which is the motivation for the rule, but the check itself is your policy. Matching is case-insensitive, as §8.3.2 requires, and a quoted value is compared after unescaping, since the quoted and unquoted forms are equivalent.\n\n**Known narrowing:** an unquoted name is checked against `token`, while the charset production (`mime-charset`, RFC 2978 §2.3) also admits `{` and `}`. RFC 9110 §8.3.2 notes both facts and adds that no registered charset name uses braces — and since an unrecognized name is reported anyway, this changes the wording of the finding rather than whether there is one.\n\n**Scope:** a `Content-Type` that does not parse as a `media-type` is skipped here; that is `message_content_type_well_formed`'s finding, as is the presence of more than one `Content-Type` field line. This rule reads every line and reports only on the charsets it finds."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("8.3.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3.2",
                note: "Charset: what the parameter means, that names are matched case-insensitively, and the \"ought to be registered\" guidance that motivates this rule — guidance, not a requirement, and not something this rule verifies",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("5.6.6"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.6",
                note: "Parameters: case-insensitive names, and `parameter-value = ( token / quoted-string )` — the fork this rule takes on the value",
            },
            crate::rules::SpecRef {
                spec: "RFC 2978",
                section: Some("2.3"),
                url: "https://www.rfc-editor.org/rfc/rfc2978.html#section-2.3",
                note: "`mime-charset`, the production a charset name actually follows. It admits `{` and `}`, which `token` does not; this rule checks `token`, a narrowing RFC 9110 §8.3.2 itself calls harmless",
            },
            crate::rules::SpecRef {
                spec: "IANA Character Sets",
                section: None,
                url: "https://www.iana.org/assignments/character-sets/character-sets.xhtml",
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
                snippet: "GET / HTTP/1.1\nHost: example.com\nContent-Type: text/plain; charset=utf-8",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nContent-Type: text/html; charset=\"UTF-8\"\n\n<html>...</html>",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nContent-Type: text/plain; charset=unknown-charset",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nContent-Type: text/plain; charset=\"unfinished",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &MessageCharsetIanaRegistered;

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;
    use rstest::rstest;

    fn make_cfg() -> crate::config::Config {
        let mut cfg = crate::config::Config::default();
        cfg.rules.insert(
            "message_charset_iana_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![
                        toml::Value::String("utf-8".into()),
                        toml::Value::String("iso-8859-1".into()),
                        toml::Value::String("us-ascii".into()),
                    ]),
                );
                t
            }),
        );
        cfg
    }

    #[rstest]
    #[case(Some("text/plain; charset=utf-8"), false)]
    #[case(Some("text/html; charset=ISO-8859-1"), false)]
    #[case(Some("text/plain; charset=us-ascii"), false)]
    #[case(Some("text/plain"), false)]
    #[case(Some("text/plain; charset=unknown-charset"), true)]
    #[case(Some("text/plain; charset=us!ascii"), true)]
    #[case(Some("text/plain; charset=\"UTF-8\""), false)]
    #[case(Some("text/plain; charset=\"\""), true)]
    // A ";" inside a quoted parameter value does not start a new parameter.
    // These have no charset parameter at all, so there is nothing to report.
    #[case(Some("multipart/form-data; boundary=\"x; charset=bogus\""), false)]
    #[case(Some("multipart/form-data; boundary=\"x; charset=utf-8\""), false)]
    // A real charset whose quoted value contains ";" is read whole, so the
    // verdict is "unrecognized", not "malformed quoted-string".
    #[case(Some("text/plain; charset=\"a;b\""), true)]
    // Still found when it follows a quoted value carrying a ";".
    #[case(Some("multipart/form-data; boundary=\"a;b\"; charset=utf-8"), false)]
    #[case(Some("multipart/form-data; boundary=\"a;b\"; charset=bogus"), true)]
    #[case(None, false)]
    fn check_response_cases(
        #[case] ct: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageCharsetIanaRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        if let Some(v) = ct {
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[("content-type", v)]);
        }

        let violation = rule.check_transaction(
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

    /// Every published snippet is run through this rule and, for the Compliant
    /// ones, through the other rules that read `Content-Type`. Nothing else does
    /// this, so a snippet this rule accepts but a sibling rejects would ship in
    /// the docs as the recommended spelling. Three families have now published
    /// one.
    #[test]
    fn published_examples_agree_with_every_rule_reading_this_header() {
        use crate::rules::{Compliance, Rule as _};
        let rule = MessageCharsetIanaRegistered;
        // The example config is the one the docs describe, so the allowlist the
        // examples are judged against is the one a reader would have.
        let toml_src = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../config_example.toml"),
        )
        .expect("config_example.toml must be readable");
        let cfg: crate::config::Config =
            toml::from_str(&toml_src).expect("config_example.toml must parse");
        let siblings: [(&str, &dyn Rule); 3] = [
            ("well-formed", &crate::rules::message_content_type_well_formed::MessageContentTypeWellFormed),
            ("charset presence", &crate::rules::server_charset_specification::ServerCharsetSpecification),
            ("media-type allowlist", &crate::rules::message_content_type_iana_registered::MessageContentTypeIanaRegistered),
        ];

        for ex in rule.examples() {
            let values: Vec<&str> = ex
                .snippet
                .lines()
                .filter_map(|l| l.strip_prefix("Content-Type: "))
                .collect();
            assert!(
                !values.is_empty(),
                "example has no Content-Type: {}",
                ex.snippet
            );
            let pairs: Vec<(&str, &str)> = values.iter().map(|v| ("content-type", *v)).collect();

            // Examples are written as whole messages, so honour the start-line.
            let on_response = ex.snippet.starts_with("HTTP/");
            let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
            if on_response {
                tx.response.as_mut().unwrap().headers =
                    crate::test_helpers::make_headers_from_pairs(&pairs);
            } else {
                tx.request.headers = crate::test_helpers::make_headers_from_pairs(&pairs);
            }
            let history = crate::transaction_history::TransactionHistory::empty();

            let v = rule.check_transaction(&tx, &history, &cfg);
            match ex.compliance {
                Compliance::Compliant => {
                    assert!(
                        v.is_none(),
                        "rule rejects its Compliant example {:?}: {v:?}",
                        ex.snippet
                    );
                    for (name, sibling) in siblings {
                        let other = sibling.check_transaction(&tx, &history, &cfg);
                        assert!(
                            other.is_none(),
                            "the {name} rule rejects a Compliant example {:?}: {other:?}",
                            ex.snippet
                        );
                    }
                }
                Compliance::NonCompliant => {
                    assert!(
                        v.is_some(),
                        "rule accepts its NonCompliant example {:?}",
                        ex.snippet
                    )
                }
            }
        }
    }

    #[rstest]
    #[case(&["text/plain; charset=utf-8", "text/plain; charset=bogus"], true)]
    #[case(&["text/plain; charset=bogus", "text/plain; charset=utf-8"], true)]
    #[case(&["text/plain; charset=utf-8", "text/plain; charset=us-ascii"], false)]
    fn every_field_line_is_checked(#[case] values: &[&str], #[case] expect_violation: bool) {
        // An unregistered charset on a second Content-Type line used to be
        // invisible, though RFC 9110 §8.3 says a recipient may well be the one
        // acting on it. That two lines are present is a different rule's
        // finding, so this rule stays quiet about the count.
        let rule = MessageCharsetIanaRegistered;
        let cfg = make_cfg();
        let pairs: Vec<(&str, &str)> = values.iter().map(|v| ("content-type", *v)).collect();
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&pairs);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert_eq!(v.is_some(), expect_violation, "{values:?} -> {v:?}");
        if let Some(v) = v {
            assert!(!v.message.contains("Multiple"), "{}", v.message);
        }
    }

    #[rstest]
    #[case(Some("text/plain; charset=utf-8"), false)]
    #[case(Some("text/plain; charset=unknown-charset"), true)]
    #[case(Some("text/plain; charset=us!ascii"), true)]
    #[case(Some("text/plain; charset=\"broken"), true)]
    #[case(None, false)]
    fn check_request_cases(
        #[case] ct: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageCharsetIanaRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(v) = ct {
            tx.request.headers =
                crate::test_helpers::make_headers_from_pairs(&[("content-type", v)]);
        }

        let violation = rule.check_transaction(
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
    fn parse_config_requires_allowed_array() {
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_charset_iana_registered",
        ]);
        let res = parse_allowed_config(&cfg, "message_charset_iana_registered");
        assert!(res.is_err());
    }

    #[test]
    fn parse_config_rejects_empty_allowed_array() {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_charset_iana_registered",
        ]);
        cfg.rules.insert(
            "message_charset_iana_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert("allowed".into(), toml::Value::Array(vec![]));
                t
            }),
        );

        let res = parse_allowed_config(&cfg, "message_charset_iana_registered");
        assert!(res.is_err());
    }

    #[test]
    fn parse_config_rejects_non_string_allowed_item() {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_charset_iana_registered",
        ]);
        cfg.rules.insert(
            "message_charset_iana_registered".into(),
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

        let res = parse_allowed_config(&cfg, "message_charset_iana_registered");
        assert!(res.is_err());
    }

    #[test]
    fn parse_config_rejects_allowed_not_array() {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_charset_iana_registered",
        ]);
        cfg.rules.insert(
            "message_charset_iana_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert("allowed".into(), toml::Value::String("utf-8".into()));
                t
            }),
        );
        let res = parse_allowed_config(&cfg, "message_charset_iana_registered");
        assert!(res.is_err());
    }

    #[test]
    fn parse_config_rejects_non_table_rule_cfg() {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_charset_iana_registered",
        ]);
        cfg.rules.insert(
            "message_charset_iana_registered".into(),
            toml::Value::String("not-a-table".into()),
        );
        let res = parse_allowed_config(&cfg, "message_charset_iana_registered");
        assert!(res.is_err());
    }

    #[test]
    fn malformed_content_type_is_ignored() {
        // If Content-Type fails to parse, this rule should return None (other rules handle well-formedness)
        let rule = MessageCharsetIanaRegistered;
        let cfg = make_cfg();
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-type", "text")]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn charset_name_case_and_spacing_ok() {
        let rule = MessageCharsetIanaRegistered;
        let cfg = make_cfg();
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-type",
            "text/plain; CHARSET = UTF-8",
        )]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn param_without_equals_is_ignored_response() {
        // A parameter without an '=' should be ignored, producing no violation
        let rule = MessageCharsetIanaRegistered;
        let cfg = make_cfg();
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-type",
            "text/plain; charset",
        )]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn param_without_equals_is_ignored_request() {
        // Same as response, but for requests
        let rule = MessageCharsetIanaRegistered;
        let cfg = make_cfg();
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-type",
            "text/plain; charset",
        )]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn trailing_semicolon_is_ignored() {
        // Trailing semicolons should not cause errors
        let rule = MessageCharsetIanaRegistered;
        let cfg = make_cfg();
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-type",
            "text/plain; charset=utf-8;",
        )]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn duplicate_charset_param_reports_violation() {
        let rule = MessageCharsetIanaRegistered;
        let cfg = make_cfg();
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-type",
            "text/plain; charset=utf-8; charset=unknown-charset",
        )]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn parse_allowed_config_missing_rule_errors() {
        let cfg = crate::config::Config::default();
        let res = parse_allowed_config(&cfg, "message_charset_iana_registered");
        assert!(res.is_err());
        let msg = res.unwrap_err().to_string();
        assert!(msg.contains("requires configuration") || msg.contains("missing"));
    }

    #[test]
    fn validate_parses_config() -> anyhow::Result<()> {
        let rule = MessageCharsetIanaRegistered;
        let mut full_cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_charset_iana_registered",
        ]);
        full_cfg.rules.insert(
            "message_charset_iana_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![toml::Value::String("utf-8".into())]),
                );
                t
            }),
        );

        let arc = parse_allowed_config(&full_cfg, rule.id())?;
        assert!(arc.allowed.contains(&"utf-8".to_string()));
        Ok(())
    }

    #[test]
    fn non_utf8_header_values_are_ignored() {
        let rule = MessageCharsetIanaRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let bad = HeaderValue::from_bytes(b"text/plain; charset=\xff").unwrap();
        tx.response
            .as_mut()
            .unwrap()
            .headers
            .insert("content-type", bad);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn id_and_scope_are_expected() {
        let rule = MessageCharsetIanaRegistered;
        assert_eq!(rule.id(), "message_charset_iana_registered");
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }
}
