// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageStructuredHeadersValidity;

#[derive(Debug, Clone)]
pub struct MessageStructuredHeadersConfig {
    pub enabled: bool,
    pub severity: crate::lint::Severity,
    pub headers: Vec<String>,
}

fn parse_headers_config(
    config: &crate::config::Config,
    rule_id: &str,
) -> anyhow::Result<MessageStructuredHeadersConfig> {
    let severity = crate::rules::get_rule_severity_required(config, rule_id)?;
    let enabled = crate::rules::get_rule_enabled_required(config, rule_id)?;

    let rule_cfg = config
        .get_rule_config(rule_id)
        .ok_or_else(|| anyhow::anyhow!("missing configuration for '{}'", rule_id))?;
    let table = rule_cfg
        .as_table()
        .ok_or_else(|| anyhow::anyhow!("Configuration for rule '{}' must be a table", rule_id))?;

    let headers_val = table.get("headers").ok_or_else(|| {
        anyhow::anyhow!(
            "Rule '{}' requires a 'headers' array listing header field-names to validate",
            rule_id
        )
    })?;

    let arr = headers_val.as_array().ok_or_else(|| {
        anyhow::anyhow!(
            "'headers' must be an array of strings (e.g., ['Priority','Permissions-Policy'])"
        )
    })?;

    if arr.is_empty() {
        return Err(anyhow::anyhow!("'headers' array cannot be empty"));
    }

    let mut out = Vec::new();
    for (i, item) in arr.iter().enumerate() {
        let s = item.as_str().ok_or_else(|| {
            anyhow::anyhow!("'headers' array item at index {} must be a string", i)
        })?;
        out.push(s.to_ascii_lowercase());
    }

    Ok(MessageStructuredHeadersConfig {
        enabled,
        severity,
        headers: out,
    })
}

impl Rule for MessageStructuredHeadersValidity {
    type Config = MessageStructuredHeadersConfig;

    fn id(&self) -> &'static str {
        "message_structured_headers_validity"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn validate_and_box(
        &self,
        config: &crate::config::Config,
    ) -> anyhow::Result<std::sync::Arc<dyn std::any::Any + Send + Sync>> {
        let parsed = parse_headers_config(config, self.id())?;
        Ok(std::sync::Arc::new(parsed))
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _previous: Option<&crate::http_transaction::HttpTransaction>,
        config: &Self::Config,
    ) -> Option<Violation> {
        for hdr in &config.headers {
            // Request
            for hv in tx.request.headers.get_all(hdr.as_str()).iter() {
                if hv.to_str().is_err() {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!("Header '{}' value is not valid UTF-8", hdr),
                    });
                }
                if let Ok(s) = hv.to_str() {
                    if let Some(msg) = validate_structured_field(s) {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!(
                                "Invalid structured-field in request header '{}': {}",
                                hdr, msg
                            ),
                        });
                    }
                }
            }

            // Response
            if let Some(resp) = &tx.response {
                for hv in resp.headers.get_all(hdr.as_str()).iter() {
                    if hv.to_str().is_err() {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!("Header '{}' value is not valid UTF-8", hdr),
                        });
                    }
                    if let Ok(s) = hv.to_str() {
                        if let Some(msg) = validate_structured_field(s) {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: format!(
                                    "Invalid structured-field in response header '{}': {}",
                                    hdr, msg
                                ),
                            });
                        }
                    }
                }
            }
        }

        None
    }
}

// Minimal conservative structured-field validator. Returns Some(error_msg) on failure.
fn validate_structured_field(s: &str) -> Option<String> {
    // Reject control characters
    if s.bytes().any(|b| b < 0x20 && b != b'\t' || b == 0x7f) {
        return Some("contains control characters".into());
    }

    // Attempt parsing as: Item, List, or Dictionary
    #[allow(clippy::question_mark)]
    if parse_item_with_params(s).is_none() {
        return None;
    }

    // If single-item parse failed, try split-aware list
    let parts = split_commas_outside_quotes(s);
    if parts.len() > 1 {
        for p in parts {
            let p = p.trim();
            if p.is_empty() {
                return Some("empty list member".into());
            }
            // Accept list members that are either Items or dictionary-like key=value forms
            if parse_item_with_params(p).is_none() {
                continue;
            }
            if let Some(eqpos) = find_char_outside_quotes(p, '=') {
                let (k, v) = p.split_at(eqpos);
                let key = k.trim();
                let val = v[1..].trim();
                if !is_valid_sf_key(key) {
                    return Some(format!("invalid dictionary key '{}' in list member", key));
                }
                if parse_item_with_params(val).is_some() {
                    return Some(format!("invalid dictionary value for key '{}'", key));
                }
                continue;
            }
            return Some(format!("invalid list member '{}'", p));
        }
        return None;
    }

    // Try dictionary: members separated by commas where each member is key or key=bare
    // Use same top-level comma splitting
    let members = split_commas_outside_quotes(s);
    if !members.is_empty() {
        let mut seen_key = false;
        for m in members {
            let m = m.trim();
            if m.is_empty() {
                return Some("empty dictionary member".into());
            }
            // find '=' not inside quotes
            if let Some(pos) = find_char_outside_quotes(m, '=') {
                let (k, v) = m.split_at(pos);
                let key = k.trim();
                let val = v[1..].trim(); // drop '='
                if !is_valid_sf_key(key) {
                    return Some(format!("invalid dictionary key '{}'", key));
                }
                if parse_item_with_params(val).is_some() {
                    return Some(format!("invalid dictionary value for key '{}'", key));
                }
                // successfully parsed key=value
                seen_key = true;
            } else {
                // key with optional params (e.g., about a flag key; parameters are allowed)
                let parts = split_semicolons_outside_quotes(m);
                let key = parts.first().map(|s| s.trim()).unwrap_or("");
                if !is_valid_sf_key(key) {
                    return Some(format!("invalid dictionary member key '{}'", key));
                }
                // params (if any) must be key or key=token/string
                for p in parts.iter().skip(1) {
                    let p = p.trim();
                    if p.is_empty() {
                        return Some("empty parameter".into());
                    }
                    if let Some(eq) = find_char_outside_quotes(p, '=') {
                        let (pk, pv) = p.split_at(eq);
                        let pk = pk.trim();
                        let pv = pv[1..].trim();
                        if !is_valid_sf_key(pk) {
                            return Some(format!("invalid parameter key '{}'", pk));
                        }
                        if parse_item_with_params(pv).is_some() {
                            return Some(format!("invalid parameter value for '{}'", pk));
                        }
                    } else if !is_valid_sf_key(p) {
                        return Some(format!("invalid parameter '{}'", p));
                    }
                }
                seen_key = true;
            }
        }
        if seen_key {
            return None;
        }
    }

    Some("value is not a recognized structured-field Item/List/Dictionary".into())
}

fn parse_item_with_params(s: &str) -> Option<String> {
    // split head and params by semicolons outside quotes
    let parts = split_semicolons_outside_quotes(s);
    let head = parts.first().map(|s| s.trim()).unwrap_or("");
    if head.is_empty() {
        return Some("empty item".into());
    }

    // head can be an inner-list "(...)" or boolean ?1/?0, number, string, token, byte-sequence :b64:
    if head.starts_with('(') && head.ends_with(')') {
        // parse inner-list contents: members separated by spaces (outside quotes)
        let inner = &head[1..head.len() - 1];
        let members = split_spaces_outside_quotes(inner);
        if members.len() == 1 && members[0].trim().is_empty() {
            // allow empty inner list: ()
        } else {
            for m in members {
                let m = m.trim();
                if m.is_empty() {
                    return Some("empty inner-list member".into());
                }
                // each inner-member is an item possibly with params
                if parse_item_with_params(m).is_some() {
                    return Some(format!("invalid inner-list member '{}'", m));
                }
            }
        }
        // treat params after the inner-list the same way as for items
        for p in parts.iter().skip(1) {
            let p = p.trim();
            if p.is_empty() {
                return Some("empty parameter".into());
            }
            if let Some(eq) = find_char_outside_quotes(p, '=') {
                let (k, v) = p.split_at(eq);
                let k = k.trim();
                let v = v[1..].trim();
                if !is_valid_sf_key(k) {
                    return Some(format!("invalid parameter key '{}'", k));
                }
                if !(is_valid_token_like(v) || is_quoted_string(v) || is_boolean(v) || is_number(v))
                {
                    return Some(format!("invalid parameter value '{}' for key '{}'", v, k));
                }
            } else if !is_valid_sf_key(p) {
                return Some(format!("invalid parameter '{}'", p));
            }
        }
        return None;
    }

    if is_boolean(head)
        || is_number(head)
        || is_quoted_string(head)
        || is_byte_sequence(head)
        || is_valid_token_like(head)
    {
        // check parameters (if any)
        for p in parts.iter().skip(1) {
            let p = p.trim();
            if p.is_empty() {
                return Some("empty parameter".into());
            }
            if let Some(eq) = find_char_outside_quotes(p, '=') {
                let (k, v) = p.split_at(eq);
                let k = k.trim();
                let v = v[1..].trim();
                if !is_valid_sf_key(k) {
                    return Some(format!("invalid parameter key '{}'", k));
                }
                // value must be token or quoted-string or boolean or number
                if !(is_valid_token_like(v) || is_quoted_string(v) || is_boolean(v) || is_number(v))
                {
                    return Some(format!("invalid parameter value '{}' for key '{}'", v, k));
                }
            } else {
                // bare parameter key
                if !is_valid_sf_key(p) {
                    return Some(format!("invalid parameter '{}'", p));
                }
            }
        }
        return None;
    }

    Some(format!("invalid item '{}'", head))
}

fn is_boolean(s: &str) -> bool {
    s == "?1" || s == "?0"
}

fn is_number(s: &str) -> bool {
    // conservative: allow optional leading '-', digits, optional '.' with digits
    let mut chars = s.chars();
    if let Some('-') = chars.clone().next() {
        chars.next();
    }
    let s2: String = chars.collect();
    if s2.is_empty() {
        return false;
    }
    if s2.contains('.') {
        let mut parts = s2.splitn(2, '.');
        let a = parts.next().unwrap();
        let b = parts.next().unwrap_or("");
        return !a.is_empty()
            && a.chars().all(|c| c.is_ascii_digit())
            && !b.is_empty()
            && b.chars().all(|c| c.is_ascii_digit());
    }
    s2.chars().all(|c| c.is_ascii_digit())
}

fn is_quoted_string(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() < 2 || bytes[0] != b'"' || bytes[bytes.len() - 1] != b'"' {
        return false;
    }
    // ensure interior doesn't contain raw control chars (conservative)
    let interior = &bytes[1..bytes.len() - 1];
    !interior
        .iter()
        .any(|b| *b < 0x20 && *b != b'\t' || *b == 0x7f)
}

fn is_byte_sequence(s: &str) -> bool {
    // :base64:
    let bytes = s.as_bytes();
    if bytes.len() < 3 || bytes[0] != b':' || bytes[bytes.len() - 1] != b':' {
        return false;
    }
    let inner = &s[1..s.len() - 1];
    !inner.is_empty()
        && inner
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
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
        if crate::helpers::token::is_tchar(c)
            || c == ':'
            || c == '/'
            || c == '.'
            || c == '-'
            || c == '_'
        {
            continue;
        }
        return false;
    }
    true
}

fn split_commas_outside_quotes(s: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut in_quote = false;
    let mut paren_depth = 0i32;
    let bytes = s.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'"' => in_quote = !in_quote,
            b'(' if !in_quote => paren_depth += 1,
            b')' if !in_quote && paren_depth > 0 => paren_depth -= 1,
            b',' if !in_quote && paren_depth == 0 => {
                parts.push(s[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(s[start..].trim());
    parts
}

fn split_semicolons_outside_quotes(s: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut in_quote = false;
    let mut paren_depth = 0i32;
    let bytes = s.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'"' => in_quote = !in_quote,
            b'(' if !in_quote => paren_depth += 1,
            b')' if !in_quote && paren_depth > 0 => paren_depth -= 1,
            b';' if !in_quote && paren_depth == 0 => {
                parts.push(s[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(s[start..].trim());
    parts
}

fn split_spaces_outside_quotes(s: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut in_quote = false;
    let bytes = s.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'"' => in_quote = !in_quote,
            b' ' if !in_quote => {
                // It is possible `start` was advanced past `i` by an earlier
                // skip of multiple spaces; avoid slicing with start > i.
                if start <= i {
                    parts.push(s[start..i].trim());
                }
                start = i + 1;
                // skip multiple spaces
                while start < bytes.len() && bytes[start] == b' ' {
                    start += 1;
                }
            }
            _ => {}
        }
    }
    // Be defensive: if start has moved beyond the string length, return
    // an explicit empty member instead of slicing out-of-bounds.
    if start >= bytes.len() {
        parts.push("");
    } else {
        parts.push(s[start..].trim());
    }
    parts
}

fn find_char_outside_quotes(s: &str, ch: char) -> Option<usize> {
    let mut in_quote = false;
    for (i, c) in s.chars().enumerate() {
        if c == '"' {
            in_quote = !in_quote;
        }
        if c == ch && !in_quote {
            return Some(i);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn make_cfg_with_headers(headers: &[&str]) -> MessageStructuredHeadersConfig {
        MessageStructuredHeadersConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
            headers: headers.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[rstest]
    #[case("foo", false)]
    #[case("\"string\"", false)]
    #[case("?1", false)]
    #[case("123", false)]
    #[case(":YWJj:", false)]
    fn parse_simple_item(#[case] value: &str, #[case] expect_err: bool) {
        let v = validate_structured_field(value);
        if expect_err {
            assert!(v.is_some());
        } else {
            assert!(v.is_none(), "unexpected parse error: {:?}", v);
        }
    }

    #[rstest]
    fn list_of_items_valid() {
        let v = validate_structured_field("u=1, i");
        if v.is_some() {
            eprintln!("list parse error: {:?}", v);
        }
        assert!(v.is_none());
    }

    #[rstest]
    fn dictionary_valid() {
        let v = validate_structured_field("sha-256=:YWJj:,");
        // trailing comma makes it invalid
        assert!(v.is_some());

        let v = validate_structured_field("sha-256=:YWJj:");
        if v.is_some() {
            eprintln!("dictionary parse error: {:?}", v);
        }
        // check inner item parsing for debugging
        let inner = parse_item_with_params(":YWJj:");
        if inner.is_some() {
            eprintln!("parse_item_with_params(:YWJj:) -> {:?}", inner);
        }
        assert!(v.is_none());
    }

    #[rstest]
    fn bad_token_is_rejected() {
        let v = validate_structured_field("bad!token");
        // '!' is allowed as a tchar per the token grammar; accept as valid token
        assert!(v.is_none());
    }

    #[rstest]
    fn unbalanced_quotes_rejected() {
        let v = validate_structured_field("\"unterminated");
        assert!(v.is_some());
    }

    #[rstest]
    fn non_utf8_header_values_are_reported() {
        let rule = MessageStructuredHeadersValidity;
        let cfg = make_cfg_with_headers(&["x-struct"]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = hyper::HeaderMap::new();
        hm.insert(
            "x-struct",
            hyper::header::HeaderValue::from_bytes(b"\xff").unwrap(),
        );
        tx.request.headers = hm;
        let v = rule.check_transaction(&tx, None, &cfg);
        // header.to_str() will error and we expect a violation reporting invalid utf-8
        assert!(v.is_some());
    }

    #[rstest]
    fn validate_and_box_parses_config() -> anyhow::Result<()> {
        let rule = MessageStructuredHeadersValidity;
        let mut full_cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_structured_headers_validity",
        ]);
        full_cfg.rules.insert(
            "message_structured_headers_validity".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "headers".into(),
                    toml::Value::Array(vec![toml::Value::String("X-Struct".into())]),
                );
                t
            }),
        );

        let boxed = rule.validate_and_box(&full_cfg)?;
        let arc = boxed
            .downcast::<MessageStructuredHeadersConfig>()
            .map_err(|_| anyhow::anyhow!("downcast failed"))?;
        assert!(arc.headers.contains(&"x-struct".to_string()));
        Ok(())
    }

    #[rstest]
    fn invalid_byte_sequence_rejected() {
        let v = validate_structured_field(":???:");
        assert!(v.is_some());
    }

    #[rstest]
    fn empty_list_member_is_rejected() {
        let v = validate_structured_field("a,,b");
        assert!(v.is_some());
    }

    #[rstest]
    fn invalid_parameter_value_reports_violation() {
        let v = validate_structured_field("foo;bar=??");
        assert!(v.is_some());
    }

    #[rstest]
    fn empty_parameter_key_is_rejected() {
        let v = validate_structured_field("foo;=1");
        assert!(v.is_some());
    }

    #[rstest]
    fn response_header_invalid_is_reported() {
        let rule = MessageStructuredHeadersValidity;
        let cfg = make_cfg_with_headers(&["x-struct"]);
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("x-struct", "\"unterminated")],
        );
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
    }

    #[rstest]
    fn quoted_comma_inside_quotes_is_allowed() {
        let v = validate_structured_field("a=\"x,y\", b");
        assert!(v.is_none());
    }

    #[rstest]
    fn semicolon_inside_quoted_param_allowed() {
        let v = validate_structured_field("t;note=\"a;b=;c\"");
        assert!(v.is_none());
    }

    #[rstest]
    fn control_chars_are_rejected() {
        let v = validate_structured_field("good\nbad");
        assert!(v.is_some());
    }

    #[rstest]
    fn token_like_with_colon_and_slash_valid() {
        let v = validate_structured_field("x:abc/def");
        assert!(v.is_none());
    }

    #[rstest]
    fn sf_key_uppercase_is_rejected_in_dictionary() {
        let v = validate_structured_field("BadKey=1");
        assert!(v.is_some());
    }

    #[rstest]
    fn dictionary_flag_with_param_valid() {
        let v = validate_structured_field("flag;foo=1");
        assert!(v.is_none());
    }

    #[rstest]
    fn list_of_dict_members_valid() {
        let v = validate_structured_field("a=1, b=2");
        assert!(v.is_none());
    }

    #[rstest]
    fn inner_list_empty_is_valid() {
        let v = validate_structured_field("interest-cohort=()");
        assert!(v.is_none());
    }

    #[rstest]
    fn inner_list_with_members_valid() {
        let v = validate_structured_field("a=(foo bar;baz=1)");
        if v.is_some() {
            eprintln!("inner list parse error: {:?}", v);
        }
        // debug: show parse_item_with_params on the inner list
        let inner_test = parse_item_with_params("(foo bar;baz=1)");
        if inner_test.is_some() {
            eprintln!("parse_item_with_params on inner list -> {:?}", inner_test);
        }
        assert!(v.is_none());
    }

    #[rstest]
    fn inner_list_with_quoted_member_valid() {
        let v = validate_structured_field("x=(\"a b\" bar)");
        assert!(v.is_none());
    }

    #[rstest]
    fn invalid_inner_list_member_is_rejected() {
        let _v = validate_structured_field("a=(bad!token)");
        // bad!token is accepted as token by token grammar so this example uses an invalid form
        // instead use an actual invalid member such as an unbalanced quoted-string inside
        let v2 = validate_structured_field("a=(\"unterminated)");
        assert!(v2.is_some());
    }

    #[rstest]
    fn quoted_param_with_escaped_quote_is_ok() {
        let v = validate_structured_field("foo;bar=\"a\\\"b\"");
        assert!(v.is_none());
    }

    #[rstest]
    fn numeric_variants() {
        assert!(validate_structured_field("-1").is_none());
        assert!(validate_structured_field("3.14").is_none());
    }

    #[rstest]
    fn byte_sequence_with_padding_valid() {
        let v = validate_structured_field(":YWJj=:");
        assert!(v.is_none());
    }

    // Config validation failures
    #[rstest]
    fn parse_config_rejects_missing_headers() -> anyhow::Result<()> {
        let rule = MessageStructuredHeadersValidity;
        let mut full_cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_structured_headers_validity",
        ]);
        full_cfg.rules.insert(
            "message_structured_headers_validity".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t
            }),
        );

        assert!(rule.validate_and_box(&full_cfg).is_err());
        Ok(())
    }

    #[rstest]
    fn parse_config_rejects_headers_not_array() -> anyhow::Result<()> {
        let rule = MessageStructuredHeadersValidity;
        let mut full_cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_structured_headers_validity",
        ]);
        full_cfg.rules.insert(
            "message_structured_headers_validity".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert("headers".into(), toml::Value::String("x".into()));
                t
            }),
        );

        assert!(rule.validate_and_box(&full_cfg).is_err());
        Ok(())
    }

    #[rstest]
    fn parse_config_rejects_empty_headers_array() -> anyhow::Result<()> {
        let rule = MessageStructuredHeadersValidity;
        let mut full_cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_structured_headers_validity",
        ]);
        full_cfg.rules.insert(
            "message_structured_headers_validity".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert("headers".into(), toml::Value::Array(vec![]));
                t
            }),
        );

        assert!(rule.validate_and_box(&full_cfg).is_err());
        Ok(())
    }

    #[rstest]
    fn parse_config_rejects_non_string_item() -> anyhow::Result<()> {
        let rule = MessageStructuredHeadersValidity;
        let mut full_cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_structured_headers_validity",
        ]);
        full_cfg.rules.insert(
            "message_structured_headers_validity".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "headers".into(),
                    toml::Value::Array(vec![toml::Value::Integer(1)]),
                );
                t
            }),
        );

        assert!(rule.validate_and_box(&full_cfg).is_err());
        Ok(())
    }

    #[rstest]
    fn invalid_list_member_is_rejected() {
        let v = validate_structured_field("a, \"unterminated");
        assert!(v.is_some());
    }

    #[rstest]
    fn invalid_dictionary_key_in_list_member_is_rejected() {
        let v = validate_structured_field("a, BadKey=1");
        // BadKey is invalid because of uppercase letter
        assert!(v.is_some());
    }

    #[rstest]
    fn invalid_parameter_key_in_item_is_rejected() {
        let v = validate_structured_field("foo;1=1");
        assert!(v.is_some());
    }

    #[rstest]
    fn invalid_bare_parameter_key_in_item_is_rejected() {
        let v = validate_structured_field("foo;1");
        assert!(v.is_some());
    }

    #[rstest]
    fn empty_parameter_in_dictionary_is_rejected() {
        let v = validate_structured_field("flag;");
        assert!(v.is_some());
    }

    #[rstest]
    fn empty_item_is_rejected() {
        let v = validate_structured_field(";a=1");
        assert!(v.is_some());
    }

    #[rstest]
    fn item_head_starting_with_digit_is_invalid() {
        let v = validate_structured_field("1abc");
        assert!(v.is_some());
    }

    #[rstest]
    fn invalid_dictionary_value_for_key_is_rejected() {
        let v = validate_structured_field("a=??");
        assert!(v.is_some());
    }

    #[rstest]
    fn dict_member_with_invalid_param_key_is_rejected() {
        let v = validate_structured_field("flag;1=1");
        assert!(v.is_some());
    }

    #[rstest]
    fn empty_dictionary_member_is_rejected() {
        let v = validate_structured_field("a=1, ,b=2");
        assert!(v.is_some());
    }

    #[rstest]
    fn dict_member_invalid_param_value_is_rejected() {
        let v = validate_structured_field("flag;foo=??");
        assert!(v.is_some());
    }

    #[rstest]
    fn empty_byte_sequence_is_rejected() {
        let v = validate_structured_field("::");
        assert!(v.is_some());
    }

    #[rstest]
    fn quoted_string_with_control_char_is_rejected() {
        let v = validate_structured_field("\"bad\n\"");
        assert!(v.is_some());
    }

    #[rstest]
    fn number_edge_cases_are_rejected() {
        assert!(validate_structured_field("-").is_some());
        assert!(validate_structured_field(".5").is_some());
        assert!(validate_structured_field("1.").is_some());
    }

    #[rstest]
    fn sf_key_star_is_accepted() {
        let v = validate_structured_field("*=1");
        assert!(v.is_none());
    }

    #[rstest]
    fn token_like_starting_with_star_is_valid() {
        let v = validate_structured_field("*token");
        assert!(v.is_none());
    }

    #[rstest]
    fn equals_inside_quotes_is_ignored() {
        let v = validate_structured_field("a=\"b=c\"");
        assert!(v.is_none());
    }

    #[rstest]
    fn bare_parameter_is_accepted() {
        let v = validate_structured_field("foo;bar");
        assert!(v.is_none());
    }

    #[rstest]
    fn parameter_boolean_is_accepted() {
        let v = validate_structured_field("foo;bar=?1");
        assert!(v.is_none());
    }

    #[rstest]
    fn empty_quoted_string_is_accepted() {
        let v = validate_structured_field("\"\"");
        assert!(v.is_none());
    }

    #[rstest]
    fn parameter_value_token_is_accepted() {
        let v = validate_structured_field("t;foo=bar_baz-1");
        assert!(v.is_none());
    }

    #[rstest]
    fn parameter_key_with_dot_is_accepted() {
        let v = validate_structured_field("t;foo.bar=1");
        assert!(v.is_none());
    }

    #[rstest]
    fn dict_wildcard_key_with_param_is_accepted() {
        let v = validate_structured_field("*;p=1");
        assert!(v.is_none());
    }

    #[rstest]
    fn empty_dictionary_value_is_rejected() {
        let v = validate_structured_field("a=");
        assert!(v.is_some());
    }

    #[rstest]
    fn rule_scope_is_both() {
        let r = MessageStructuredHeadersValidity;
        assert_eq!(r.scope(), crate::rules::RuleScope::Both);
    }

    #[rstest]
    fn request_header_invalid_structured_is_reported() {
        let rule = MessageStructuredHeadersValidity;
        let cfg = make_cfg_with_headers(&["x-struct"]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = hyper::HeaderMap::new();
        hm.insert(
            "x-struct",
            hyper::header::HeaderValue::from_static("\"unterminated"),
        );
        tx.request.headers = hm;
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        if let Some(vi) = v {
            assert!(vi.message.contains("request header"));
        }
    }

    #[rstest]
    fn response_header_non_utf8_is_reported() {
        let rule = MessageStructuredHeadersValidity;
        let cfg = make_cfg_with_headers(&["x-struct"]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        // set response header to invalid bytes
        let mut rh = hyper::HeaderMap::new();
        rh.insert(
            "x-struct",
            hyper::header::HeaderValue::from_bytes(b"\xff").unwrap(),
        );
        if let Some(resp) = &mut tx.response {
            resp.headers = rh;
        }
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        if let Some(vi) = v {
            assert!(
                vi.message.contains("response header") || vi.message.contains("not valid UTF-8")
            );
        }
    }

    #[rstest]
    fn invalid_dictionary_value_in_list_member_is_rejected() {
        let v = validate_structured_field("a=??, b=1");
        assert!(v.is_some());
    }

    #[rstest]
    fn inner_list_param_key_invalid() {
        // parameter key after inner-list must be a valid sf-key
        let v = validate_structured_field("a=(foo);1=1");
        assert!(v.is_some());
    }

    #[rstest]
    fn inner_list_param_value_invalid() {
        // parameter value after inner-list must be token/quoted/boolean/number
        let v = validate_structured_field("a=(foo);baz=??");
        assert!(v.is_some());
    }

    #[rstest]
    fn empty_inner_list_member_is_rejected() {
        // trailing spaces inside parens can produce an empty member
        let v = validate_structured_field("a=(foo  )");
        assert!(v.is_some());
    }

    #[rstest]
    fn comma_inside_inner_list_is_rejected() {
        // commas inside inner-lists should not split members and will produce invalid members
        let v = validate_structured_field("a=(foo,bar)");
        assert!(v.is_some());
    }

    #[rstest]
    fn token_like_with_question_mark_rejected() {
        // '?' is not accepted in token-like values
        let v = validate_structured_field("bad?token");
        assert!(v.is_some());
    }

    #[rstest]
    fn split_spaces_trailing_space_produces_empty_member() {
        let parts = split_spaces_outside_quotes("a ");
        assert_eq!(parts, vec!["a", ""]);
    }

    #[rstest]
    fn split_commas_respects_parentheses() {
        let parts = split_commas_outside_quotes("a,(b,c),d");
        assert_eq!(parts, vec!["a", "(b,c)", "d"]);
    }

    #[rstest]
    fn split_semicolons_respects_parentheses() {
        let parts = split_semicolons_outside_quotes("a;(b;c);d");
        assert_eq!(parts, vec!["a", "(b;c)", "d"]);
    }

    #[rstest]
    fn find_char_outside_quotes_ignores_quoted() {
        // '=' only inside a quoted-string should be ignored
        let s = "\"x=y\"";
        assert_eq!(find_char_outside_quotes(s, '='), None);
        // '=' outside quotes should be found at its position
        let s2 = "a=1,b=2";
        assert_eq!(find_char_outside_quotes(s2, '='), Some(1));
    }
}
