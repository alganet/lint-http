// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ServerPriorityAndCacheabilityConsistency;

impl Rule for ServerPriorityAndCacheabilityConsistency {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "server_priority_and_cacheability_consistency"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _previous: Option<&crate::http_transaction::HttpTransaction>,
        config: &Self::Config,
    ) -> Option<Violation> {
        let resp = match &tx.response {
            Some(r) => r,
            None => return None,
        };

        // Only consider responses that include a Priority header field.
        // Prefer the first ASCII-valid field value when multiple header fields exist.
        let mut priority_val: Option<&str> = None;
        for hv in resp.headers.get_all("priority").iter() {
            if let Ok(s) = hv.to_str() {
                let s = s.trim();
                if !s.is_empty() {
                    priority_val = Some(s);
                    break;
                }
            }
        }
        let priority = priority_val?;

        // Only check for cacheable-ish responses (2xx and 3xx); be conservative and skip 1xx, 4xx, 5xx
        if !(200..400).contains(&resp.status) {
            return None;
        }

        let has_cache_control = resp.headers.contains_key("cache-control");
        let has_vary = resp.headers.contains_key("vary");

        if !has_cache_control && !has_vary {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!(
                    "Response includes Priority header ('{}') but lacks Cache-Control or Vary to control cacheability; origin servers emitting Priority should control cacheability per RFC 9218 §5",
                    priority
                ),
            });
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;
    use rstest::rstest;

    #[rstest]
    fn priority_without_cache_control_or_vary_reports_violation() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("priority", "u=3")]);

        let rule = ServerPriorityAndCacheabilityConsistency;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Priority header"));
    }

    #[rstest]
    fn priority_with_cache_control_is_ok() {
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("priority", "u=1"), ("cache-control", "public, max-age=60")],
        );
        let rule = ServerPriorityAndCacheabilityConsistency;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
    }

    #[rstest]
    fn priority_with_vary_is_ok() {
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("priority", "u=1"), ("vary", "Accept-Encoding")],
        );
        let rule = ServerPriorityAndCacheabilityConsistency;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
    }

    #[rstest]
    fn no_priority_is_ignored() {
        let tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let rule = ServerPriorityAndCacheabilityConsistency;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
    }

    #[rstest]
    fn priority_non_utf8_is_ignored() -> anyhow::Result<()> {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = hyper::HeaderMap::new();
        hm.insert("priority", HeaderValue::from_bytes(&[0xff])?);
        tx.response.as_mut().unwrap().headers = hm;

        let rule = ServerPriorityAndCacheabilityConsistency;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
        Ok(())
    }

    #[rstest]
    fn priority_multiple_fields_prefers_ascii_value() -> anyhow::Result<()> {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = hyper::HeaderMap::new();
        // Non-UTF8 first, ASCII second
        hm.insert("priority", HeaderValue::from_bytes(&[0xff])?);
        hm.append("priority", HeaderValue::from_static("u=2"));
        tx.response.as_mut().unwrap().headers = hm;

        let rule = ServerPriorityAndCacheabilityConsistency;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        Ok(())
    }

    #[rstest]
    fn priority_on_non_cacheable_status_is_ignored() {
        let tx =
            crate::test_helpers::make_test_transaction_with_response(503, &[("priority", "u=1")]);
        let rule = ServerPriorityAndCacheabilityConsistency;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
    }

    #[rstest]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "server_priority_and_cacheability_consistency");
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn validate_rules_with_invalid_config_missing_severity() {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "server_priority_and_cacheability_consistency");
        // remove severity to simulate invalid config
        if let Some(toml::Value::Table(ref mut table)) = cfg
            .rules
            .get_mut("server_priority_and_cacheability_consistency")
        {
            table.remove("severity");
        }

        let err = crate::rules::validate_rules(&cfg).expect_err("expected validation to fail");
        assert!(err.to_string().contains("Missing required 'severity'"));
    }

    #[test]
    fn scope_is_server() {
        let rule = ServerPriorityAndCacheabilityConsistency;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }
}
