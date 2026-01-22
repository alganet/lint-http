// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageWellKnownUriFormat;

impl Rule for MessageWellKnownUriFormat {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_well_known_uri_format"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _previous: Option<&crate::http_transaction::HttpTransaction>,
        config: &Self::Config,
    ) -> Option<Violation> {
        let path = crate::helpers::uri::extract_path_from_request_target(&tx.request.uri)?;

        // Well-known URIs MUST be under the path prefix `/.well-known/` per RFC 8615.
        if path.starts_with("/.well-known/") {
            return None;
        }

        if path.starts_with("/.well-known") {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Request target uses '/.well-known' but is not a valid well-known URI; it must use '/.well-known/{name}' (RFC 8615)".to_string(),
            });
        }

        if path.contains("/.well-known") {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Request target contains '/.well-known' but not at the path root; well-known URIs MUST begin with '/.well-known/' (RFC 8615)".to_string(),
            });
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn make_tx_with_uri(uri: &str) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.uri = uri.into();
        tx
    }

    #[test]
    fn valid_well_known_paths_are_ok() {
        let rule = MessageWellKnownUriFormat;
        let mut tx = make_tx_with_uri("/.well-known/openid-configuration");
        let config = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };
        let v = rule.check_transaction(&tx, None, &config);
        assert!(v.is_none());

        tx = make_tx_with_uri("https://example.com/.well-known/security.txt");
        let v2 = rule.check_transaction(&tx, None, &config);
        assert!(v2.is_none());
    }

    #[rstest]
    #[case("/.well-known", "missing trailing slash or name")]
    #[case("/.well-known?x=1", "missing trailing slash or name")]
    fn missing_slash_reports_violation(#[case] uri: &str, #[case] _desc: &str) {
        let rule = MessageWellKnownUriFormat;
        let tx = make_tx_with_uri(uri);
        let config = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };
        let v = rule.check_transaction(&tx, None, &config);
        assert!(v.is_some());
        let v = v.unwrap();
        assert_eq!(v.rule, "message_well_known_uri_format");
    }

    #[test]
    fn not_at_root_reports_violation() {
        let rule = MessageWellKnownUriFormat;
        let tx = make_tx_with_uri("/foo/.well-known/abc");
        let config = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };
        let v = rule.check_transaction(&tx, None, &config);
        assert!(v.is_some());
        let v = v.unwrap();
        assert_eq!(v.rule, "message_well_known_uri_format");
    }

    #[test]
    fn unrelated_paths_do_not_trigger() {
        let rule = MessageWellKnownUriFormat;
        let tx = make_tx_with_uri("/foo/bar");
        let config = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };
        let v = rule.check_transaction(&tx, None, &config);
        assert!(v.is_none());
    }

    #[test]
    fn absolute_form_without_path_does_not_trigger() {
        let rule = MessageWellKnownUriFormat;
        let tx = make_tx_with_uri("https://example.com");
        let config = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };
        let v = rule.check_transaction(&tx, None, &config);
        assert!(v.is_none());
    }

    #[test]
    fn message_and_id() {
        let rule = MessageWellKnownUriFormat;
        assert_eq!(rule.id(), "message_well_known_uri_format");
        assert_eq!(rule.scope(), crate::rules::RuleScope::Client);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_well_known_uri_format",
        ]);
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
