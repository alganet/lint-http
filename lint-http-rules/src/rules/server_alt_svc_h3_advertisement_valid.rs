// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// Alt-Svc advertising `h3` must use the final protocol ID (not draft versions),
/// with a reasonable `ma` (max-age) value (RFC 9114 §3.1, RFC 7838).
pub struct ServerAltSvcH3AdvertisementValid;

/// Maximum reasonable max-age: 1 year in seconds.
const MAX_REASONABLE_MA: u64 = 365 * 24 * 3600;

impl Rule for ServerAltSvcH3AdvertisementValid {
    fn id(&self) -> &'static str {
        "server_alt_svc_h3_advertisement_valid"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
        let resp = tx.response.as_ref()?;

        // cite(RFC 7838 § 1): "This specification defines a new concept in HTTP, "Alternative Services", that allows an origin server to nominate additional means of interacting with it"
        for hv in resp.headers.get_all("alt-svc").iter() {
            let s = match hv.to_str() {
                Ok(s) => s,
                Err(_) => continue, // syntax rule handles non-UTF8
            };

            for entry in crate::helpers::headers::parse_list_header(s) {
                // split off params after first ';'
                let mut parts = entry.splitn(2, ';');
                let proto_auth = parts.next().unwrap_or("").trim();
                let params_str = parts.next().unwrap_or("");

                if proto_auth.is_empty() {
                    continue; // syntax rule handles this
                }

                // "clear" is a valid Alt-Svc directive (RFC 7838 §3)
                if proto_auth.eq_ignore_ascii_case("clear") {
                    continue;
                }

                let eq_idx = match proto_auth.find('=') {
                    Some(i) => i,
                    None => continue, // syntax rule handles missing '='
                };

                let protocol = proto_auth[..eq_idx].trim();
                if protocol.is_empty() {
                    continue;
                }

                let proto_lower = protocol.to_ascii_lowercase();

                // Draft h3 protocol IDs (h3-29, h3-Q050, etc.)
                if proto_lower.starts_with("h3-") {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!(
                            "Alt-Svc uses draft HTTP/3 protocol identifier '{}'; \
                             use the final 'h3' token instead (RFC 9114 §3.1)",
                            protocol
                        ),
                    });
                }

                // Only validate parameters for actual h3 entries
                if proto_lower != "h3" {
                    continue;
                }

                // Parse parameters looking for `ma`
                if let Some(v) = check_h3_ma_param(self.id(), &config, params_str) {
                    return Some(v);
                }
            }
        }

        None
    }

    fn title(&self) -> Option<&'static str> {
        Some("Server Alt-Svc H3 Advertisement Valid")
    }

    fn description(&self) -> &'static str {
        "Validates `Alt-Svc` entries that advertise HTTP/3. Servers must use the final ALPN protocol identifier `h3`, not draft-era tokens such as `h3-29` or `h3-Q050`. When the `ma` (max-age) parameter is present on an `h3` entry, its value must be a positive integer within reasonable bounds (at most 1 year / 31 536 000 seconds); `ma=0` immediately invalidates the advertisement and is flagged as likely misconfiguration.\n\nThis rule complements `server_alt_svc_header_syntax` (general syntax) and `server_alt_svc_protocol_iana_registered` (allowlist check) by adding HTTP/3-specific semantic validation."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9114",
                section: Some("3.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9114.html#section-3.1",
                note: "HTTP/3 alternative service discovery",
            },
            crate::rules::SpecRef {
                spec: "RFC 7838",
                section: Some("3"),
                url: "https://www.rfc-editor.org/rfc/rfc7838.html#section-3",
                note: "Alt-Svc header field syntax and `ma` parameter semantics",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "Alt-Svc: h3=\":443\"; ma=2592000\nAlt-Svc: h3=example.com:443; ma=86400\nAlt-Svc: h2=\":443\", h3=\":443\"; ma=3600",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "Alt-Svc: h3-29=\":443\"              # draft protocol identifier\nAlt-Svc: h3=\":443\"; ma=0           # immediately invalidates entry\nAlt-Svc: h3=\":443\"; ma=99999999    # exceeds 1 year\nAlt-Svc: h3=\":443\"; ma=abc         # non-numeric max-age",
            },
        ]
    }
}

/// Validate the `ma` (max-age) parameter on an h3 Alt-Svc entry.
fn check_h3_ma_param(
    rule_id: &str,
    config: &crate::rules::RuleConfig,
    params_str: &str,
) -> Option<Violation> {
    for param in crate::helpers::headers::split_semicolons_respecting_quotes(params_str) {
        if param.is_empty() {
            continue;
        }
        let mut kv = param.splitn(2, '=');
        let key = kv.next().unwrap_or("").trim();
        let raw_val = kv.next().unwrap_or("").trim();

        if !key.eq_ignore_ascii_case("ma") {
            continue;
        }

        if raw_val.is_empty() {
            return Some(Violation {
                rule: rule_id.into(),
                severity: config.severity,
                message: "Alt-Svc h3 entry has 'ma' parameter with no value".into(),
            });
        }

        // Strip quotes if present (RFC 7838 allows quoted-string)
        let val = if raw_val.starts_with('"') && raw_val.ends_with('"') && raw_val.len() >= 2 {
            &raw_val[1..raw_val.len() - 1]
        } else {
            raw_val
        };

        match val.parse::<u64>() {
            Ok(0) => {
                return Some(Violation {
                    rule: rule_id.into(),
                    severity: config.severity,
                    message: "Alt-Svc h3 entry has 'ma=0' which immediately invalidates \
                         the advertisement (RFC 7838 §3)"
                        .into(),
                });
            }
            Ok(n) if n > MAX_REASONABLE_MA => {
                return Some(Violation {
                    rule: rule_id.into(),
                    severity: config.severity,
                    message: format!(
                        "Alt-Svc h3 entry has unreasonably large 'ma={}' \
                         (exceeds 1 year / {} seconds)",
                        n, MAX_REASONABLE_MA
                    ),
                });
            }
            Ok(_) => {}
            Err(_) => {
                return Some(Violation {
                    rule: rule_id.into(),
                    severity: config.severity,
                    message: format!("Alt-Svc h3 entry has non-numeric 'ma' value: '{}'", val),
                });
            }
        }
    }

    None
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ServerAltSvcH3AdvertisementValid;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    // No violation cases
    #[case(None, false)]
    #[case(Some("h3=\":443\"; ma=2592000"), false)]
    #[case(Some("h3=\":443\""), false)]
    #[case(Some("h3=example.com:443; ma=86400"), false)]
    #[case(Some("h2=\":443\", h3=\":443\"; ma=3600"), false)]
    #[case(Some("h3=\":443\"; ma=\"86400\""), false)]
    #[case(Some("h2=\":443\""), false)]
    #[case(Some("clear"), false)]
    #[case(Some("h3=\":443\"; ma=31536000"), false)]
    // Draft version violations
    #[case(Some("h3-29=\":443\""), true)]
    #[case(Some("h3-Q050=\":443\""), true)]
    #[case(Some("h3-27=\":443\"; ma=3600"), true)]
    #[case(Some("h2=\":443\", h3-29=\":443\""), true)]
    // ma=0 violation
    #[case(Some("h3=\":443\"; ma=0"), true)]
    #[case(Some("h3=\":443\"; ma=\"0\""), true)]
    // Unreasonably large ma
    #[case(Some("h3=\":443\"; ma=99999999"), true)]
    #[case(Some("h3=\":443\"; ma=31536001"), true)]
    // Non-numeric ma
    #[case(Some("h3=\":443\"; ma=abc"), true)]
    // Empty ma value
    #[case(Some("h3=\":443\"; ma="), true)]
    // Case-insensitive protocol
    #[case(Some("H3=\":443\"; ma=86400"), false)]
    // Case-insensitive ma key
    #[case(Some("h3=\":443\"; MA=86400"), false)]
    // Persist param without ma (valid, defaults to 24h)
    #[case(Some("h3=\":443\"; persist=1"), false)]
    // Multiple params including valid ma
    #[case(Some("h3=\":443\"; persist=1; ma=86400"), false)]
    // Boundary: ma=1 is valid (positive)
    #[case(Some("h3=\":443\"; ma=1"), false)]
    // Negative ma value (non-numeric)
    #[case(Some("h3=\":443\"; ma=-1"), true)]
    // CLEAR directive (case-insensitive)
    #[case(Some("CLEAR"), false)]
    // Draft with numeric suffix only
    #[case(Some("h3-14=\":443\""), true)]
    // h3 mixed with clear
    #[case(Some("clear, h3=\":443\"; ma=86400"), false)]
    // Quoted parameter value containing semicolon should not mis-split
    #[case(Some("h3=\":443\"; foo=\"a;b\"; ma=86400"), false)]
    fn check_cases(#[case] header: Option<&str>, #[case] expect_violation: bool) {
        let rule = ServerAltSvcH3AdvertisementValid;
        let tx = match header {
            Some(h) => {
                crate::test_helpers::make_test_transaction_with_response(200, &[("alt-svc", h)])
            }
            None => crate::test_helpers::make_test_transaction_with_response(200, &[]),
        };

        let config = crate::test_helpers::make_test_config_with_severity(
            "server_alt_svc_h3_advertisement_valid",
            "warn",
        );

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        );
        if expect_violation {
            assert!(v.is_some(), "expected violation for header={:?}", header);
        } else {
            assert!(
                v.is_none(),
                "unexpected violation for header={:?}: {:?}",
                header,
                v
            );
        }
    }

    #[test]
    fn draft_version_message_includes_protocol() {
        let rule = ServerAltSvcH3AdvertisementValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("alt-svc", "h3-29=\":443\"")],
        );
        let config = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let v = rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &config,
            )
            .unwrap();
        assert!(v.message.contains("h3-29"));
        assert!(v.message.contains("draft"));
    }

    #[test]
    fn ma_zero_message_mentions_invalidation() {
        let rule = ServerAltSvcH3AdvertisementValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("alt-svc", "h3=\":443\"; ma=0")],
        );
        let config = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let v = rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &config,
            )
            .unwrap();
        assert!(v.message.contains("ma=0"));
    }

    #[test]
    fn large_ma_message_mentions_exceeds() {
        let rule = ServerAltSvcH3AdvertisementValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("alt-svc", "h3=\":443\"; ma=99999999")],
        );
        let config = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let v = rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &config,
            )
            .unwrap();
        assert!(v.message.contains("unreasonably large"));
    }

    #[test]
    fn non_numeric_ma_message_mentions_value() {
        let rule = ServerAltSvcH3AdvertisementValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("alt-svc", "h3=\":443\"; ma=abc")],
        );
        let config = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let v = rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &config,
            )
            .unwrap();
        assert!(v.message.contains("non-numeric"));
        assert!(v.message.contains("abc"));
    }

    #[test]
    fn missing_response_returns_none() {
        let rule = ServerAltSvcH3AdvertisementValid;
        let tx = crate::test_helpers::make_test_transaction();
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn multiple_header_values_checks_all() {
        let rule = ServerAltSvcH3AdvertisementValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("alt-svc", "h2=\":443\""), ("alt-svc", "h3-29=\":443\"")],
        );
        let config = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        );
        assert!(v.is_some());
    }

    #[test]
    fn h2_with_bad_ma_is_not_flagged() {
        let rule = ServerAltSvcH3AdvertisementValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("alt-svc", "h2=\":443\"; ma=0")],
        );
        let config = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        );
        assert!(v.is_none());
    }

    #[test]
    fn empty_ma_message_mentions_no_value() {
        let rule = ServerAltSvcH3AdvertisementValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("alt-svc", "h3=\":443\"; ma=")],
        );
        let config = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let v = rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &config,
            )
            .unwrap();
        assert!(v.message.contains("no value"));
    }

    #[test]
    fn non_utf8_header_value_is_skipped() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;
        let rule = ServerAltSvcH3AdvertisementValid;

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        let bad = HeaderValue::from_bytes(&[0xff]).expect("should construct non-utf8 header");
        hm.insert("alt-svc", bad);
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,
            body_length: None,
            trailers: None,
        });

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(
            v.is_none(),
            "non-UTF8 should be skipped (syntax rule handles it)"
        );
        Ok(())
    }

    #[test]
    fn syntax_errors_are_skipped() {
        let rule = ServerAltSvcH3AdvertisementValid;
        // Missing '=' - syntax rule handles this, our rule should skip
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("alt-svc", "h3example.com:443")],
        );
        let config = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        );
        assert!(v.is_none());
    }

    #[test]
    fn empty_protocol_is_skipped() {
        let rule = ServerAltSvcH3AdvertisementValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("alt-svc", "=\":443\"")],
        );
        let config = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        );
        assert!(v.is_none());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "server_alt_svc_h3_advertisement_valid");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn scope_is_server() {
        let rule = ServerAltSvcH3AdvertisementValid;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }
}
