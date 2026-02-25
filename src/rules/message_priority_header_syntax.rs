// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessagePriorityHeaderSyntax;

impl Rule for MessagePriorityHeaderSyntax {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_priority_header_syntax"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        config: &Self::Config,
    ) -> Option<Violation> {
        // Check request
        if let Some(hv) = tx.request.headers.get_all("priority").iter().next() {
            if hv.to_str().is_err() {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Priority header value is not valid UTF-8".into(),
                });
            }
            if let Ok(s) = hv.to_str() {
                if let Some(msg) = validate_priority_header(s) {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!("Invalid Priority header in request: {}", msg),
                    });
                }
            }
        }

        // Check response
        if let Some(resp) = &tx.response {
            if let Some(hv) = resp.headers.get_all("priority").iter().next() {
                if hv.to_str().is_err() {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Priority header value is not valid UTF-8".into(),
                    });
                }
                if let Ok(s) = hv.to_str() {
                    if let Some(msg) = validate_priority_header(s) {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!("Invalid Priority header in response: {}", msg),
                        });
                    }
                }
            }
        }

        None
    }
}

/// Return Some(error_msg) on parse/validation failure, None on success.
fn validate_priority_header(s: &str) -> Option<String> {
    // Split top-level members by comma
    for member in s.split(',') {
        let member = member.trim();
        if member.is_empty() {
            return Some("empty member in Priority header".into());
        }

        // Split off parameters separated by ';'
        let mut parts = member.split(';');
        let head = parts.next().unwrap().trim();
        let params: Vec<&str> = parts.map(|p| p.trim()).filter(|p| !p.is_empty()).collect();

        // Validate params keys (if present) - simple conservative checks
        for p in &params {
            // param can be key or key=value
            let mut kv = p.splitn(2, '=');
            let key = kv.next().unwrap().trim();
            if !is_valid_sf_key(key) {
                return Some(format!("invalid parameter key '{}'", key));
            }
            if let Some(val) = kv.next() {
                let val = val.trim();
                if val.is_empty() {
                    return Some(format!("empty value for parameter '{}'", key));
                }
                // conservative: reject control chars
                if val.bytes().any(|b| b < 0x20 || b == 0x7f) {
                    return Some(format!("invalid parameter value for '{}'", key));
                }
            }
        }

        // Now parse head: either key or key=value
        let mut kv = head.splitn(2, '=');
        let key = kv.next().unwrap().trim();
        if !is_valid_sf_key(key) {
            return Some(format!("invalid member key '{}'", key));
        }

        let value_opt = kv.next().map(|v| v.trim());

        match key {
            "u" => {
                // urgency MUST have an integer value in 0..=7
                let v = match value_opt {
                    Some(x) => x,
                    None => return Some("urgency 'u' missing value".into()),
                };
                // value must be an integer (no leading '+', no trailing)
                if v.starts_with('-') || v.starts_with('+') {
                    return Some(format!("urgency '{}' not in range 0..=7", v));
                }
                if !v.chars().all(|c| c.is_ascii_digit()) {
                    return Some(format!("urgency '{}' is not an integer", v));
                }
                let n: i64 = match v.parse() {
                    Ok(n) => n,
                    Err(_) => return Some(format!("urgency '{}' parse error", v)),
                };
                if !(0..=7).contains(&n) {
                    return Some(format!("urgency '{}' out of range 0..=7", v));
                }
            }
            "i" => {
                // incremental may be present without value (boolean true), or have ?1/?0
                if let Some(v) = value_opt {
                    // accept ?1 or ?0
                    if !(v == "?1" || v == "?0") {
                        return Some(format!("incremental 'i' has invalid boolean value '{}'", v));
                    }
                }
            }
            _ => {
                // Other keys: accept but conservative validation of optional value
                if let Some(v) = value_opt {
                    // ok if integer, token-like, or boolean ?1/?0
                    if v.starts_with('?') {
                        if !(v == "?1" || v == "?0") {
                            return Some(format!(
                                "invalid boolean value '{}' for key '{}'",
                                v, key
                            ));
                        }
                    } else if v.chars().all(|c| c.is_ascii_digit()) {
                        // integer OK
                    } else if is_valid_token_like(v) {
                        // token-like value OK
                    } else {
                        return Some(format!("invalid value '{}' for key '{}'", v, key));
                    }
                }
            }
        }
    }

    None
}

fn is_valid_sf_key(k: &str) -> bool {
    let mut chars = k.chars();
    let first = match chars.next() {
        Some(c) => c,
        None => return false,
    };
    if !(first.is_ascii_lowercase() || first == '*') {
        return false;
    }
    for c in chars {
        if !(c.is_ascii_lowercase()
            || c.is_ascii_digit()
            || c == '_'
            || c == '-'
            || c == '.'
            || c == '*')
        {
            return false;
        }
    }
    true
}

fn is_valid_token_like(v: &str) -> bool {
    // Accept a token-like value: first char alpha or '*' then allowed tchar/:/
    let mut chars = v.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '*' => {}
        _ => return false,
    }
    for c in chars {
        if crate::helpers::token::is_tchar(c) || c == ':' || c == '/' {
            continue;
        }
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn make_tx_with_req(hv: &str) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[("priority", hv)]);
        tx
    }

    fn make_tx_with_resp(hv: &str) -> crate::http_transaction::HttpTransaction {
        crate::test_helpers::make_test_transaction_with_response(200, &[("priority", hv)])
    }

    #[rstest]
    #[case("u=0", false)]
    #[case("u=5, i", false)]
    #[case("i", false)]
    #[case("u=7", false)]
    #[case("u=8", true)]
    #[case("u=+1", true)]
    #[case("u=3;i", false)]
    #[case("u", true)]
    #[case("u=abc", true)]
    #[case("U=3", true)]
    #[case("i=?1", false)]
    #[case("i=?2", true)]
    fn check_request_cases(
        #[case] value: &str,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessagePriorityHeaderSyntax;
        let tx = make_tx_with_req(value);
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(v.is_some(), "expected violation for '{}', got none", value);
        } else {
            assert!(
                v.is_none(),
                "did not expect violation for '{}', got some: {:?}",
                value,
                v
            );
        }
        Ok(())
    }

    #[rstest]
    #[case("u=0", false)]
    #[case("u=5, i", false)]
    #[case("u=8", true)]
    #[case("u=+1", true)]
    fn check_response_cases(
        #[case] value: &str,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessagePriorityHeaderSyntax;
        let tx = make_tx_with_resp(value);
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(
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
    fn violation_message_is_meaningful() {
        let rule = MessagePriorityHeaderSyntax;
        let tx = make_tx_with_req("u=8");
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("urgency") || msg.contains("out of range"));
    }

    #[test]
    fn params_and_edge_cases() {
        let rule = MessagePriorityHeaderSyntax;
        let cfg = crate::test_helpers::make_test_rule_config();

        // valid parameter on urgency
        let tx1 = make_tx_with_req("u=3;foo=bar");
        assert!(rule
            .check_transaction(
                &tx1,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg
            )
            .is_none());

        // empty parameter name is ignored (tolerant) per structured-field-like handling
        let tx2 = make_tx_with_req("u=3;;i");
        assert!(rule
            .check_transaction(
                &tx2,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg
            )
            .is_none());

        // empty member between commas
        let tx3 = make_tx_with_req("u=1, ,i");
        let v3 = rule.check_transaction(
            &tx3,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v3.is_some());
        assert!(v3.unwrap().message.contains("empty member"));

        // param key uppercase -> violation
        let tx4 = make_tx_with_req("u=1;X=1");
        let v4 = rule.check_transaction(
            &tx4,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v4.is_some());
        assert!(v4.unwrap().message.contains("invalid parameter key"));

        // param with empty value
        let tx5 = make_tx_with_req("u=1;foo=");
        let v5 = rule.check_transaction(
            &tx5,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v5.is_some());
        if let Some(v) = v5 {
            assert!(
                v.message.contains("empty value for parameter 'foo'")
                    || v.message.contains("invalid")
            );
        } else {
            panic!("expected violation");
        }

        // unknown key with token-like value is accepted
        let tx6 = make_tx_with_req("x=token/value");
        assert!(rule
            .check_transaction(
                &tx6,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg
            )
            .is_none());

        // i=?0 accepted
        let tx7 = make_tx_with_req("i=?0");
        assert!(rule
            .check_transaction(
                &tx7,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg
            )
            .is_none());

        // explicit boolean on unknown key accepted
        let tx8 = make_tx_with_req("y=?1");
        assert!(rule
            .check_transaction(
                &tx8,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg
            )
            .is_none());
    }

    #[test]
    fn more_edge_cases_to_increase_coverage() {
        let rule = MessagePriorityHeaderSyntax;
        let cfg = crate::test_helpers::make_test_rule_config();

        // unknown key with invalid boolean -> violation
        let tx2 = make_tx_with_req("x=?2");
        let v2 = rule.check_transaction(
            &tx2,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v2.is_some());
        assert!(v2.unwrap().message.contains("invalid boolean value"));

        // invalid member key (starts with digit)
        let tx3 = make_tx_with_req("1=3");
        let v3 = rule.check_transaction(
            &tx3,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v3.is_some());
        assert!(v3.unwrap().message.contains("invalid member key"));

        // invalid numeric with leading plus -> violation, reported as "invalid value"
        let tx4 = make_tx_with_req("x=+1");
        let v4 = rule.check_transaction(
            &tx4,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v4.is_some());
        let msg = v4.unwrap().message;
        assert!(msg.contains("invalid value"));

        // star key accepted
        let tx5 = make_tx_with_req("*=5");
        assert!(rule
            .check_transaction(
                &tx5,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg
            )
            .is_none());
    }

    #[test]
    fn non_utf8_header_value_is_reported() -> anyhow::Result<()> {
        let rule = MessagePriorityHeaderSyntax;
        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        let bad = HeaderValue::from_bytes(&[0xff])?;
        hm.append("priority", bad);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = hm;
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("not valid UTF-8"));
        Ok(())
    }

    #[test]
    fn scope_is_both() {
        let rule = MessagePriorityHeaderSyntax;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }

    #[test]
    fn helper_validations() {
        // sf key: star and mixed chars OK
        assert!(is_valid_sf_key("*"));
        assert!(is_valid_sf_key("a1_b-c.*"));
        // uppercase first char -> invalid
        assert!(!is_valid_sf_key("Abad"));

        // token-like checks
        assert!(is_valid_token_like("a:foo/bar"));
        assert!(!is_valid_token_like("1abc"));
    }

    #[test]
    fn non_utf8_header_value_in_response_is_reported() -> anyhow::Result<()> {
        let rule = MessagePriorityHeaderSyntax;
        use hyper::header::HeaderValue;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let bad = HeaderValue::from_bytes(&[0xff])?;
        tx.response
            .as_mut()
            .unwrap()
            .headers
            .append("priority", bad);
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("not valid UTF-8"));
        Ok(())
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let rule = MessagePriorityHeaderSyntax;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("severity".to_string(), toml::Value::String("warn".into()));
        cfg.rules.insert(
            "message_priority_header_syntax".into(),
            toml::Value::Table(table),
        );

        // should succeed
        let _boxed = rule.validate_and_box(&cfg)?;
        Ok(())
    }
}
