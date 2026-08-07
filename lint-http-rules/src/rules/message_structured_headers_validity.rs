// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::helpers::structured_fields::*;
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

impl MessageStructuredHeadersValidity {
    /// Judge one header field across one section, from its joined value.
    ///
    /// Not one field line at a time, which is what this used to do. A List or a
    /// Dictionary is a structure over the whole field, its members may be spread
    /// across lines on purpose, and a line taken alone can fail in ways the field
    /// does not: split a String and each half is an unterminated quoted-string
    /// while the joined value is a String containing a comma. § 4.2 makes the
    /// combining a MUST and says why.
    ///
    // cite(RFC 9651 § 4.2): "When generating input_bytes, parsers MUST combine all field lines in the same section (header or trailer) that case-insensitively match the field name into one comma-separated field-value, as per Section 5.2 of [HTTP]; this assures that the entire field value is processed correctly."
    fn check_section(
        &self,
        headers: &hyper::HeaderMap,
        hdr: &str,
        section: &str,
        config: &MessageStructuredHeadersConfig,
    ) -> Option<Violation> {
        let mut lines: Vec<&str> = Vec::new();
        for hv in headers.get_all(hdr).iter() {
            // Not "not valid UTF-8", which this used to claim and is a different
            // statement: a well-formed multi-byte character fails here too.
            // Structured Fields are ASCII, and step 1 fails before any type is
            // considered.
            // cite(RFC 9651 § 4.2): "Convert input_bytes into an ASCII string input_string; if conversion fails, fail parsing."
            let Ok(v) = hv.to_str() else {
                return Some(self.violation(
                    hdr,
                    section,
                    "contains a byte outside ASCII",
                    config.severity,
                ));
            };
            lines.push(v);
        }
        if lines.is_empty() {
            return None;
        }
        let msg = validate_structured_field(&lines.join(", "))?;
        Some(self.violation(hdr, section, &msg, config.severity))
    }

    /// The finding, framed as what a recipient does about it.
    ///
    /// "Invalid" is not what either half of this costs. A parse failure takes
    /// the entire field with it -- every member, not the malformed one -- and
    /// RFC 9651 forbids field specifications from softening that, so the price
    /// of one stray character is the whole header.
    ///
    // cite(RFC 9651 § 4.2): "If parsing fails, either the entire field value MUST be ignored (i.e., treated as if the field were not present in the section), or alternatively the complete HTTP message MUST be treated as malformed."
    fn violation(
        &self,
        hdr: &str,
        section: &str,
        msg: &str,
        severity: crate::lint::Severity,
    ) -> Violation {
        Violation {
            rule: self.id().into(),
            severity,
            message: format!(
                "The {} header '{}' fails Structured Fields parsing, so a recipient discards \
                 the whole field or treats the message as malformed: {}",
                section, hdr, msg
            ),
        }
    }
}

impl Rule for MessageStructuredHeadersValidity {
    fn id(&self) -> &'static str {
        "message_structured_headers_validity"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn validate(&self, config: &crate::config::Config) -> anyhow::Result<()> {
        parse_headers_config(config, self.id())?;
        Ok(())
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = parse_headers_config(cfg, self.id()).ok()?;
        // cite(RFC 9651): "This document describes a set of data types and associated algorithms that are intended to make it easier and safer to define and handle HTTP header and trailer fields,"
        for hdr in &config.headers {
            if let Some(v) = self.check_section(&tx.request.headers, hdr, "request", &config) {
                return Some(v);
            }
            if let Some(resp) = &tx.response {
                if let Some(v) = self.check_section(&resp.headers, hdr, "response", &config) {
                    return Some(v);
                }
            }
        }

        None
    }

    fn description(&self) -> &'static str {
        "Validate that specified header fields are valid RFC 9651 Structured Field values (Item, List, or Dictionary). This rule checks for syntactic correctness (tokens, quoted-strings, numbers, booleans, byte-sequences, and simple parameters) and reports malformed header values. It is intentionally conservative and focuses on common syntactic errors."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9651",
                section: None,
                url: "https://www.rfc-editor.org/rfc/rfc9651.html",
                note: "Structured Field Values for HTTP",
            },
            crate::rules::SpecRef {
                spec: "RFC 9651",
                section: Some("3"),
                url: "https://www.rfc-editor.org/rfc/rfc9651.html#section-3",
                note: "Items, Lists, Dictionaries",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "Priority: u=3, i\nPermissions-Policy: interest-cohort=()\nAccept-Patch: application/json-patch+json\nContent-Digest: sha-256=:BASE64=",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "Priority: u=INVALID  # invalid token (structured field tokens cannot start with uppercase)\nPermissions-Policy: bad(token)  # invalid token characters: '(' and ')'\nAccept-Patch: \"unterminated  # unbalanced quoted-string\nContent-Digest: sha-256=:???=  # invalid byte-sequence",
            },
        ]
    }
}

/// Validate a joined field value as a Structured Field. `Some(msg)` on failure.
///
/// § 4.2 takes a `field_type` and this has none: nothing on the wire says
/// whether a configured header was defined as a Dictionary, a List or an Item,
/// and the config names bare field names. So all three are tried and the value
/// passes if any of them parses it. That is a real weakening -- `Priority` is a
/// Dictionary, and `Priority: "u"` is accepted here because it is a perfectly
/// good String Item -- and it is the honest limit of what a generic rule can
/// say. Where a field's own rule exists, that rule knows the type and this one
/// should not be pointed at the same header.
///
/// (The registry does now publish types, which is the shape of a fix: RFC 9651
/// § 5 added a "Structured Type" column and populated it for ten fields. It is
/// a registry table, not something a parser derives, so it is left for a rule
/// that transcribes one.)
///
// cite(RFC 9651 § 4.2): "Given an array of bytes as input_bytes that represent the chosen field's field-value (which is empty if that field is not present) and field_type (one of "dictionary", "list", or "item"), return the parsed field value."
fn validate_structured_field(s: &str) -> Option<String> {
    // cite(RFC 9651 § 4.2): "Convert input_bytes into an ASCII string input_string; if conversion fails, fail parsing."
    if !s.is_ascii() {
        return Some("contains a byte outside ASCII".into());
    }
    // HTAB survives, and it is the one control character that should: joining
    // field lines is where one appears, and § 4.2 says so in as many words.
    // Everything else has no production that admits it -- a String rejects it
    // (§ 4.2.5), a Token has no tchar for it, and the whitespace the algorithms
    // discard is SP or OWS at named points, never inside a value.
    // cite(RFC 9651 § 4.2): "The parsing algorithms for both types allow tab characters, since these might be used to combine field lines by some implementations."
    if s.bytes().any(|b| (b < 0x20 && b != b'\t') || b == 0x7f) {
        return Some("contains control characters".into());
    }

    // Step 2 discards SP, and steps 6-7 require what is left to be empty, so
    // surrounding space is not a defect. `trim` also takes HTAB, where the
    // algorithm at this outermost level would not; that leniency is deliberate,
    // for the same reason the tab check above is -- a tab here is an artifact of
    // whatever joined the lines, not of the field's author.
    // cite(RFC 9651 § 4.2): "Discard any leading SP characters from input_string."
    let s = s.trim();

    // An empty value is not a parse failure. Two of the three algorithms end by
    // returning an empty structure, so a field-type-blind check cannot call it
    // one. A field whose own definition makes it an Item is the exception, and
    // that is exactly the judgement this rule is not in a position to make.
    // cite(RFC 9651 § 4.2.1): "No structured data has been found; return members (which is empty)."
    // cite(RFC 9651 § 4.2.2): "No structured data has been found; return dictionary (which is empty)."
    if s.is_empty() {
        return None;
    }

    // cite(RFC 9651 § 4.2): "If field_type is "item", let output be the result of running Parsing an Item (Section 4.2.3) with input_string."
    let as_item = parse_item(s);
    // cite(RFC 9651 § 4.2): "If field_type is "list", let output be the result of running Parsing a List (Section 4.2.1) with input_string."
    let as_list = parse_list(s);
    // cite(RFC 9651 § 4.2): "If field_type is "dictionary", let output be the result of running Parsing a Dictionary (Section 4.2.2) with input_string."
    let as_dictionary = parse_dictionary(s);

    // No message from any one of the three means that reading consumed the
    // whole value, and one type accepting it is as much as this rule can ask.
    let (Some(as_item), Some(as_list), Some(as_dictionary)) = (as_item, as_list, as_dictionary)
    else {
        return None;
    };

    // All three readings failed, so all three are reported. Picking one would
    // be picking a field_type, and choosing the shortest complaint or the first
    // one would name a type the field may well not have -- a Dictionary told it
    // is an invalid Item has been told nothing.
    Some(format!(
        "as an Item, {}; as a List, {}; as a Dictionary, {}",
        as_item, as_list, as_dictionary
    ))
}

/// § 4.2.1 -- a comma-separated sequence of Items or Inner Lists.
fn parse_list(s: &str) -> Option<String> {
    for m in split_commas_outside_quotes(s) {
        let m = m.trim();
        // Step 2.6 names the common way to reach this: a trailing comma leaves
        // an empty string where a member was expected. A doubled comma is the
        // same shape one step earlier.
        // cite(RFC 9651 § 4.2.1): "If input_string is empty, there is a trailing comma; fail parsing."
        if m.is_empty() {
            return Some("empty list member".into());
        }
        // cite(RFC 9651 § 4.2.1): "Append the result of running Parsing an Item or Inner List (Section 4.2.1.1) with input_string to members."
        if let Some(msg) = parse_item_or_inner_list(m) {
            return Some(format!("invalid list member '{}': {}", m, msg));
        }
    }
    None
}

/// § 4.2.2 -- comma-separated `key` or `key=value` members, each parameterizable.
fn parse_dictionary(s: &str) -> Option<String> {
    for m in split_commas_outside_quotes(s) {
        let m = m.trim();
        // cite(RFC 9651 § 4.2.2): "If input_string is empty, there is a trailing comma; fail parsing."
        if m.is_empty() {
            return Some("empty dictionary member".into());
        }
        // The key is read first and the "=" has to be the character right after
        // it, which is why the head is isolated before looking for one. Reading
        // the member's first "=" instead finds the one in `flag;p=1` and blames
        // a key of `flag;p`, which is not a key and not what is wrong.
        // cite(RFC 9651 § 4.2.2): "Let this_key be the result of running Parsing a Key (Section 4.2.3.3) with input_string."
        let parts = split_semicolons_outside_quotes(m);
        let head = parts.first().map(|p| p.trim()).unwrap_or("");
        // cite(RFC 9651 § 4.2.2): "If the first character of input_string is "=":"
        let (key, value) = match find_char_outside_quotes(head, '=') {
            Some(eq) => {
                let (k, v) = head.split_at(eq);
                (k.trim(), Some(v[1..].trim()))
            }
            // cite(RFC 9651 § 4.2.2): "Let value be Boolean true."
            None => (head, None),
        };
        if !is_valid_sf_key(key) {
            return Some(format!("invalid dictionary key '{}'", key));
        }
        if let Some(value) = value {
            // cite(RFC 9651 § 4.2.2): "Let member be the result of running Parsing an Item or Inner List (Section 4.2.1.1) with input_string."
            if let Some(msg) = parse_member_value(value) {
                return Some(format!("invalid value for key '{}': {}", key, msg));
            }
        }
        if let Some(msg) = parse_parameters(&parts[1..]) {
            return Some(format!("{} on member '{}'", msg, key));
        }
    }
    None
}

/// § 4.2.1.1 -- an Item or an Inner List, either of them parameterized.
fn parse_item_or_inner_list(s: &str) -> Option<String> {
    let parts = split_semicolons_outside_quotes(s);
    let head = parts.first().map(|p| p.trim()).unwrap_or("");
    parse_member_value(head).or_else(|| parse_parameters(&parts[1..]))
}

/// The head of a § 4.2.1.1 member: a bare Item, or an Inner List.
// cite(RFC 9651 § 4.2.1.1): "If the first character of input_string is "(", return the result of running Parsing an Inner List (Section 4.2.1.2) with input_string."
fn parse_member_value(head: &str) -> Option<String> {
    if head.is_empty() {
        return Some("empty value".into());
    }
    if head.starts_with('(') {
        return parse_inner_list(head);
    }
    if !is_bare_item(head) {
        return Some(format!("invalid item '{}'", head));
    }
    None
}

/// § 4.2.1.2 -- space-separated Items between parentheses.
fn parse_inner_list(head: &str) -> Option<String> {
    // cite(RFC 9651 § 4.2.1.2): "The end of the Inner List was not found; fail parsing."
    if head.len() < 2 || !head.ends_with(')') {
        return Some(format!("unterminated inner list '{}'", head));
    }
    let inner = &head[1..head.len() - 1];

    // Space is the member separator here, but not every space separates. Where
    // one follows a ";" it belongs to the parameters of the member before it --
    // `("foo"; a=1;b=2)` is one String with two parameters, and it is the RFC's
    // own example -- so that part is rejoined rather than started as a member.
    // cite(RFC 9651 § 4.2.3.2): "Discard any leading SP characters from input_string."
    let mut members: Vec<String> = Vec::new();
    for part in split_spaces_outside_quotes(inner) {
        let part = part.trim();
        // A run of spaces, or a space before the closing paren, leaves an empty
        // string here and means nothing: the loop discards leading SP before
        // deciding whether the list has ended, so `(a  b)`, `( a)` and `(a )`
        // are all the same list. This used to report each of them.
        // cite(RFC 9651 § 4.2.1.2): "Discard any leading SP characters from input_string."
        if part.is_empty() {
            continue;
        }
        match members.last_mut() {
            Some(prev) if prev.ends_with(';') => prev.push_str(part),
            _ => members.push(part.to_string()),
        }
    }

    for m in &members {
        // An Item, not an Item-or-Inner-List: Inner Lists do not nest, and the
        // bare-item dispatch has no branch for "(".
        // cite(RFC 9651 § 4.2.1.2): "Let item be the result of running Parsing an Item (Section 4.2.3) with input_string."
        if let Some(msg) = parse_item(m) {
            return Some(format!("invalid inner-list member '{}': {}", m, msg));
        }
    }
    None
}

/// § 4.2.3 -- a bare Item and its Parameters.
fn parse_item(s: &str) -> Option<String> {
    let parts = split_semicolons_outside_quotes(s);
    let head = parts.first().map(|p| p.trim()).unwrap_or("");
    if head.is_empty() {
        return Some("empty item".into());
    }
    // cite(RFC 9651 § 4.2.3): "Let bare_item be the result of running Parsing a Bare Item (Section 4.2.3.1) with input_string."
    if !is_bare_item(head) {
        return Some(format!("invalid item '{}'", head));
    }
    // cite(RFC 9651 § 4.2.3): "Let parameters be the result of running Parsing Parameters (Section 4.2.3.2) with input_string."
    parse_parameters(&parts[1..])
}

/// § 4.2.3.2 -- `;key` or `;key=value`, where a value is any bare Item.
///
/// Every one of the seven types is admitted here, and the four that used to be
/// is the shorter list. A byte sequence was rejected outright, so `foo;bar=:YWJj:`
/// -- an ordinary parameterized token -- was reported as invalid.
///
// cite(RFC 9651 § 3.1.2): "The keys are unique within the scope of the Parameters they occur within, and the values are bare items (i.e., they themselves cannot be parameterized; see Section 3.3)."
fn parse_parameters(parts: &[&str]) -> Option<String> {
    for p in parts {
        let p = p.trim();
        if p.is_empty() {
            return Some("empty parameter".into());
        }
        match find_char_outside_quotes(p, '=') {
            Some(eq) => {
                let (k, v) = p.split_at(eq);
                let (k, v) = (k.trim(), v[1..].trim());
                // cite(RFC 9651 § 4.2.3.2): "Let param_key be the result of running Parsing a Key (Section 4.2.3.3) with input_string."
                if !is_valid_sf_key(k) {
                    return Some(format!("invalid parameter key '{}'", k));
                }
                // cite(RFC 9651 § 4.2.3.2): "Let param_value be the result of running Parsing a Bare Item (Section 4.2.3.1) with input_string."
                if !is_bare_item(v) {
                    return Some(format!("invalid parameter value '{}' for key '{}'", v, k));
                }
            }
            // A parameter with no "=" is the Boolean true, spelled the way § 3.1.2
            // requires it be spelled, so only the key is left to check.
            // cite(RFC 9651 § 4.2.3.2): "Let param_value be Boolean true."
            None => {
                if !is_valid_sf_key(p) {
                    return Some(format!("invalid parameter '{}'", p));
                }
            }
        }
    }
    None
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &MessageStructuredHeadersValidity;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn make_cfg_with_headers(headers: &[&str]) -> crate::config::Config {
        let mut cfg = crate::config::Config::default();
        cfg.rules.insert(
            "message_structured_headers_validity".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "headers".into(),
                    toml::Value::Array(
                        headers
                            .iter()
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
        assert!(v.is_none(), "unexpected parse error: {:?}", v);
    }

    #[rstest]
    fn dictionary_valid() {
        let v = validate_structured_field("sha-256=:YWJj:,");
        // trailing comma makes it invalid
        assert!(v.is_some());

        let v = validate_structured_field("sha-256=:YWJj:");
        assert!(v.is_none(), "unexpected parse error: {:?}", v);
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
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        // header.to_str() will error and we expect a violation reporting invalid utf-8
        assert!(v.is_some());
    }

    #[rstest]
    fn validate_parses_config() -> anyhow::Result<()> {
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

        let arc = parse_headers_config(&full_cfg, rule.id())?;
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
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
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
        assert!(v.is_none(), "unexpected parse error: {:?}", v);
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
    fn unrecognized_value_reports_violation() {
        // Value that is neither a valid Item, List nor Dictionary should be rejected
        let v = validate_structured_field("foo bar");
        assert!(v.is_some());
    }

    #[rstest]
    fn inner_list_param_invalid_key_is_rejected() {
        // inner-list with an invalid parameter key (digit) should be rejected
        let v = validate_structured_field("(foo);1=1");
        assert!(v.is_some());
    }

    #[rstest]
    fn inner_list_member_starting_with_digit_is_rejected() {
        // inner-list member starting with a digit is invalid as an item head
        let v = validate_structured_field("a=(1abc)");
        assert!(v.is_some());
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

        assert!(rule.validate(&full_cfg).is_err());
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

        assert!(rule.validate(&full_cfg).is_err());
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

        assert!(rule.validate(&full_cfg).is_err());
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

        assert!(rule.validate(&full_cfg).is_err());
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
    fn empty_byte_sequence_is_accepted() {
        let v = validate_structured_field("::");
        assert!(v.is_none(), "unexpected parse error: {:?}", v);
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
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
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
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
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
    #[case("a=(foo )")]
    #[case("a=( foo)")]
    #[case("a=(foo  bar)")]
    #[case("a=( )")]
    fn spaces_around_inner_list_members_are_discarded(#[case] value: &str) {
        // Section 4.2.1.2 discards leading SP before deciding whether the list
        // has ended, so a run of spaces -- or one before ")" -- is not a member.
        let v = validate_structured_field(value);
        assert!(v.is_none(), "unexpected parse error: {:?}", v);
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

    #[rstest]
    fn invalid_list_member_without_eq_is_rejected() {
        // list member that is neither an item nor a key=value should be rejected
        let v = validate_structured_field("a, ???");
        assert!(v.is_some());
        if let Some(msg) = v {
            assert!(msg.contains("invalid list member"));
        }
    }

    #[rstest]
    fn parse_item_invalid_item_reports_invalid_item_message() {
        // an unrecognized bare-item type is reported as an invalid item
        let v = parse_item("@foo");
        assert!(v.is_some());
        let msg = v.unwrap();
        assert!(msg.contains("invalid item"));
    }

    #[rstest]
    fn parse_item_empty_parameter_is_rejected() {
        // trailing semicolon after an item should be treated as an empty parameter
        let v = parse_item("foo;");
        assert!(v.is_some());
        let msg = v.unwrap();
        assert!(msg.contains("empty parameter"));
    }

    #[rstest]
    fn empty_input_is_an_empty_list_or_dictionary() {
        // Both Section 4.2.1 and Section 4.2.2 end by returning an empty
        // structure, so an empty value is only a failure for a field whose
        // definition makes it an Item -- which this rule does not know.
        let v = validate_structured_field("");
        assert!(v.is_none(), "unexpected parse error: {:?}", v);
    }

    #[rstest]
    fn single_comma_is_rejected_as_empty_list_members() {
        let v = validate_structured_field(",");
        assert!(v.is_some());
        if let Some(msg) = v {
            assert!(msg.contains("empty list member") || msg.contains("empty dictionary member"));
        }
    }

    #[rstest]
    fn item_param_with_empty_key_is_rejected() {
        // parameter name after semicolon cannot be empty when expressed as key=value
        let v = validate_structured_field("a=1;=1");
        assert!(v.is_some());
    }

    // The two types RFC 9651 added over RFC 8941. This rule names 9651 and a
    // 9651 parser is required to accept everything an 8941 one does *and* these.
    #[rstest]
    #[case("@1659578233")]
    #[case("a=@1659578233")]
    #[case("foo;when=@1659578233")]
    #[case("a=(@1 @2)")]
    #[case("%\"This is intended for display to %c3%bcsers.\"")]
    #[case("a=%\"caf%c3%a9\"")]
    #[case("foo;label=%\"caf%c3%a9\"")]
    fn dates_and_display_strings_are_accepted(#[case] value: &str) {
        let v = validate_structured_field(value);
        assert!(
            v.is_none(),
            "unexpected parse error for {:?}: {:?}",
            value,
            v
        );
    }

    #[rstest]
    #[case("@1.5")]
    #[case("%\"%C3%BC\"")]
    #[case("%\"unterminated")]
    fn malformed_dates_and_display_strings_are_rejected(#[case] value: &str) {
        assert!(validate_structured_field(value).is_some(), "{value:?}");
    }

    // Every bare-item type is a legal parameter value. Byte sequences were
    // rejected outright, which made an ordinary parameterized token a finding.
    #[rstest]
    #[case("foo;bar=:YWJj:")]
    #[case("u=3;x=:YWJj:")]
    #[case("a=(foo;h=:YWJj:)")]
    fn byte_sequence_parameter_values_are_accepted(#[case] value: &str) {
        let v = validate_structured_field(value);
        assert!(
            v.is_none(),
            "unexpected parse error for {:?}: {:?}",
            value,
            v
        );
    }

    // Every field value RFC 9651 prints as an example of a well-formed
    // Structured Field. The one that broke was `("foo"; a=1;b=2)`, where the
    // space belongs to a parameter and the member split took it as a separator.
    #[rstest]
    #[case("?1")]
    #[case(":cHJldGVuZCB0aGlzIGlzIGJpbmFyeSBjb250ZW50Lg==:")]
    #[case("@1659578233")]
    #[case("4.5")]
    #[case("a=?0, b, c; foo=bar")]
    #[case("a=(1 2), b=3, c=4;aa=bb, d=(5 6);valid")]
    #[case("en=\"Applepie\", da=:w4ZibGV0w6ZydGU=:")]
    #[case("foo=1, bar=2")]
    #[case("rating=1.5, feelings=(joy sadness)")]
    #[case("%\"This is intended for display to %c3%bcsers.\"")]
    #[case("1; a; b=?0")]
    #[case("5; foo=bar")]
    #[case("abc;a=1;b=2; cde_456, (ghi;jk=4 l);q=\"9\";r=w")]
    #[case("(\"foo\"; a=1;b=2);lvl=5, (\"bar\" \"baz\");lvl=1")]
    #[case("(\"foo\" \"bar\"), (\"baz\"), (\"bat\" \"one\"), ()")]
    #[case("sugar, tea, rum")]
    #[case("\"hello world\"")]
    #[case("foo123/456")]
    fn examples_printed_by_the_rfc_all_parse(#[case] value: &str) {
        let v = validate_structured_field(value);
        assert!(
            v.is_none(),
            "unexpected parse error for {:?}: {:?}",
            value,
            v
        );
    }

    #[rstest]
    fn a_space_before_a_parameter_semicolon_is_still_a_finding() {
        // Section 4.2.3.2 exits its loop unless the next character is ";", so
        // the space belongs to the inner list and what follows is a member
        // with no bare item in front of it.
        assert!(validate_structured_field("a=(\"foo\" ;b=2)").is_some());
    }

    #[rstest]
    fn nested_inner_lists_are_rejected() {
        // Section 4.2.1.2 parses each member as an Item, and the bare-item
        // dispatch has no branch for "(".
        assert!(validate_structured_field("a=((b))").is_some());
    }

    #[rstest]
    fn parameterized_key_is_not_read_as_a_dictionary_key() {
        // The "=" that follows a key is the one right after it; the first "="
        // anywhere in the member belongs to a parameter, and blaming a key of
        // "flag;p" describes something that is not a key.
        let v = validate_structured_field("flag;p=??");
        assert!(v.is_some());
        let msg = v.unwrap();
        assert!(!msg.contains("'flag;p'"), "{msg}");
        assert!(msg.contains("invalid parameter value"), "{msg}");
    }

    #[rstest]
    fn failure_message_names_each_reading_it_tried() {
        // No field_type is available, so a value that fails as all three has
        // three complaints; when they differ the message says which is which.
        let msg = validate_structured_field("a, ???").expect("should fail");
        assert!(msg.contains("as an Item,"), "{msg}");
        assert!(msg.contains("as a List,"), "{msg}");
        assert!(msg.contains("as a Dictionary,"), "{msg}");
    }

    #[rstest]
    fn a_dictionary_member_names_the_member_not_a_second_key() {
        let msg = validate_structured_field("u=3;q=?2").expect("should fail");
        assert!(msg.contains("for key 'q' on member 'u'"), "{msg}");
    }

    #[rstest]
    fn field_lines_are_joined_before_parsing() {
        let rule = MessageStructuredHeadersValidity;
        let cfg = make_cfg_with_headers(&["x-struct"]);

        // A String split across two lines: each line alone is an unterminated
        // quoted-string, and the joined value is a String containing a comma.
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = hyper::HeaderMap::new();
        hm.append("x-struct", hyper::header::HeaderValue::from_static("\"foo"));
        hm.append("x-struct", hyper::header::HeaderValue::from_static("bar\""));
        tx.request.headers = hm;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none(), "unexpected finding: {:?}", v);
    }

    #[rstest]
    fn a_member_split_across_field_lines_is_still_a_finding() {
        let rule = MessageStructuredHeadersValidity;
        let cfg = make_cfg_with_headers(&["x-struct"]);

        // Joined, this is `a=1, BadKey=2` -- a defect neither line shows alone,
        // because "BadKey=2" on its own is a fine List of one Token.
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = hyper::HeaderMap::new();
        hm.append("x-struct", hyper::header::HeaderValue::from_static("a=1"));
        hm.append(
            "x-struct",
            hyper::header::HeaderValue::from_static("BadKey=2"),
        );
        tx.request.headers = hm;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[rstest]
    fn finding_says_what_a_recipient_does_with_the_field() {
        let rule = MessageStructuredHeadersValidity;
        let cfg = make_cfg_with_headers(&["x-struct"]);
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("x-struct", "\"unterminated")],
        );
        let v = rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            )
            .expect("should report");
        assert!(
            v.message.contains("discards the whole field"),
            "{}",
            v.message
        );
        assert!(
            !v.message.contains("Invalid structured-field"),
            "{}",
            v.message
        );
    }

    #[rstest]
    fn non_ascii_is_not_reported_as_invalid_utf8() {
        let rule = MessageStructuredHeadersValidity;
        let cfg = make_cfg_with_headers(&["x-struct"]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = hyper::HeaderMap::new();
        // Well-formed UTF-8, and still outside the ASCII that step 1 requires.
        hm.insert(
            "x-struct",
            hyper::header::HeaderValue::from_bytes("caf\u{e9}".as_bytes()).unwrap(),
        );
        tx.request.headers = hm;
        let v = rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            )
            .expect("should report");
        assert!(v.message.contains("outside ASCII"), "{}", v.message);
        assert!(!v.message.contains("UTF-8"), "{}", v.message);
    }
}
