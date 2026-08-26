// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! The shared shape of a configured list of case-insensitive names.
//!
//! Nine rules configure themselves with a required array of strings whose
//! entries are matched case-insensitively against the wire — seven under the
//! key `allowed`, two under the key `headers` — and each had grown its own
//! copy of the same parser, differing only in the key and the noun its error
//! messages named. The parser moves here; the key and the *nouns* stay with
//! the rules (`key`/`what`/`example` below), and so do the citations that
//! justify each rule's case-fold, because which sentence licenses folding
//! `GZIP` to `gzip` is a per-registry fact, not a property of this function.
//!
//! What deliberately does **not** share this parser: `alt_svc_protocol_registered`.
//! ALPN protocol names are opaque byte strings identified by their exact
//! octets, so its list is stored as written and each entry is validated —
//! same TOML shape, different question.

use crate::config::Config;

/// A rule's resolved `allowed` list, entries folded to lowercase once at
/// prepare time so the comparison site folds only the wire value.
#[derive(Debug)]
pub struct AllowedList {
    pub allowed: Vec<String>,
}

/// A rule's resolved `headers` list — field names to check, folded once at
/// prepare time (field names are case-insensitive, RFC 9110 §5.1; the cite
/// lives with each rule that relies on it).
#[derive(Debug)]
pub struct HeaderNameList {
    pub headers: Vec<String>,
}

/// Parse the required `key` array out of `[rules.<rule_id>]`, folding each
/// entry to lowercase. `what` names the entries in error messages
/// ("acceptable charset names"); `example` shows a valid array
/// ("['utf-8','iso-8859-1']").
pub fn parse_lowercased_list(
    cfg: &Config,
    rule_id: &str,
    key: &str,
    what: &str,
    example: &str,
) -> anyhow::Result<Vec<String>> {
    let rule_cfg = cfg.get_rule_config(rule_id).ok_or_else(|| {
        anyhow::anyhow!(
            "rule '{}' requires configuration and a named '{}' array listing {}. Example in config_example.toml",
            rule_id,
            key,
            what
        )
    })?;

    let table = rule_cfg
        .as_table()
        .ok_or_else(|| anyhow::anyhow!("Configuration for rule '{}' must be a table", rule_id))?;

    let list_val = table.get(key).ok_or_else(|| {
        anyhow::anyhow!(
            "Rule '{}' requires a '{}' array listing {} (e.g., {})",
            rule_id,
            key,
            what,
            example
        )
    })?;

    let arr = list_val.as_array().ok_or_else(|| {
        anyhow::anyhow!("'{}' must be an array of strings (e.g., {})", key, example)
    })?;

    // No sentence forbids an empty array. It is refused because the rule it
    // configures would then report every message it reads, which is a broken
    // linter rather than a deployment that accepts nothing.
    if arr.is_empty() {
        return Err(anyhow::anyhow!("'{}' array cannot be empty", key));
    }

    let mut out = Vec::new();
    for (i, item) in arr.iter().enumerate() {
        let s = item.as_str().ok_or_else(|| {
            anyhow::anyhow!("'{}' array item at index {} must be a string", key, i)
        })?;
        out.push(s.to_ascii_lowercase());
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_with(rule: &str, value: toml::Value) -> Config {
        let mut cfg = Config::default();
        cfg.rules.insert(rule.to_string(), value);
        cfg
    }

    fn table_with_allowed(value: toml::Value) -> toml::Value {
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert(
            "severity".to_string(),
            toml::Value::String("warn".to_string()),
        );
        table.insert("allowed".to_string(), value);
        toml::Value::Table(table)
    }

    fn parse(cfg: &Config) -> anyhow::Result<Vec<String>> {
        parse_lowercased_list(
            cfg,
            "some_rule",
            "allowed",
            "acceptable widgets",
            "['a','b']",
        )
    }

    #[test]
    fn entries_fold_to_lowercase_once() {
        let cfg = cfg_with(
            "some_rule",
            table_with_allowed(toml::Value::Array(vec![
                toml::Value::String("UTF-8".to_string()),
                toml::Value::String("gzip".to_string()),
            ])),
        );
        let list = parse(&cfg).unwrap();
        assert_eq!(list, vec!["utf-8".to_string(), "gzip".to_string()]);
    }

    #[test]
    fn missing_rule_table_names_the_what() {
        let err = parse(&Config::default()).unwrap_err().to_string();
        assert!(err.contains("requires configuration"), "{err}");
        assert!(err.contains("acceptable widgets"), "{err}");
    }

    #[test]
    fn non_table_config_is_refused() {
        let cfg = cfg_with("some_rule", toml::Value::Boolean(true));
        let err = parse(&cfg).unwrap_err().to_string();
        assert!(err.contains("must be a table"), "{err}");
    }

    #[test]
    fn missing_key_shows_the_key_and_example() {
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        let cfg = cfg_with("some_rule", toml::Value::Table(table));
        let err = parse(&cfg).unwrap_err().to_string();
        assert!(err.contains("requires a 'allowed' array"), "{err}");
        assert!(err.contains("['a','b']"), "{err}");
    }

    #[test]
    fn a_different_key_is_read_and_named() {
        let mut table = toml::map::Map::new();
        table.insert(
            "headers".to_string(),
            toml::Value::Array(vec![toml::Value::String("ETag".to_string())]),
        );
        let cfg = cfg_with("some_rule", toml::Value::Table(table));
        let list =
            parse_lowercased_list(&cfg, "some_rule", "headers", "field names", "['etag']").unwrap();
        assert_eq!(list, vec!["etag".to_string()]);

        let err = parse_lowercased_list(&cfg, "some_rule", "allowed", "widgets", "['a']")
            .unwrap_err()
            .to_string();
        assert!(err.contains("'allowed'"), "{err}");
    }

    #[test]
    fn non_array_value_is_refused() {
        let cfg = cfg_with(
            "some_rule",
            table_with_allowed(toml::Value::String("gzip".to_string())),
        );
        let err = parse(&cfg).unwrap_err().to_string();
        assert!(err.contains("must be an array of strings"), "{err}");
    }

    #[test]
    fn empty_array_is_refused() {
        let cfg = cfg_with("some_rule", table_with_allowed(toml::Value::Array(vec![])));
        let err = parse(&cfg).unwrap_err().to_string();
        assert!(err.contains("cannot be empty"), "{err}");
    }

    #[test]
    fn non_string_item_is_refused_by_index() {
        let cfg = cfg_with(
            "some_rule",
            table_with_allowed(toml::Value::Array(vec![
                toml::Value::String("ok".to_string()),
                toml::Value::Integer(3),
            ])),
        );
        let err = parse(&cfg).unwrap_err().to_string();
        assert!(err.contains("index 1"), "{err}");
    }
}
