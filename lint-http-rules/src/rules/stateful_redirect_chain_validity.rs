// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// Stateful checks for redirect chains and obvious redirect loops.
///
/// - Detects immediate circular redirects where `Location` points back to the
///   same request target (absolute or relative).
/// - Flags repeated redirects for the same client+resource that point to the
///   same `Location` as the previous observed response (possible loop/misconfig).
///
/// Note: full multi-resource redirect-chain graph analysis is out of scope for
/// the current `StateStore` shape (which only caches the previous transaction
/// per client+resource). This rule implements conservative, high‑value checks
/// that are stateless-within-a-resource or rely on the `previous` transaction.
pub struct StatefulRedirectChainValidity;

impl Rule for StatefulRedirectChainValidity {
    fn id(&self) -> &'static str {
        "stateful_redirect_chain_validity"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
        let resp = tx.response.as_ref()?;

        let status = resp.status;
        // Consider redirection/creation status codes that may include Location
        if !matches!(status, 300 | 301 | 302 | 303 | 307 | 308 | 201) {
            return None;
        }

        // No Location -> nothing to validate here (other rules handle presence)
        let mut loc_iter = resp.headers.get_all("location").iter();
        let first_loc = match loc_iter.next()?.to_str() {
            Ok(s) => s.trim().to_string(),
            Err(_) => {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Location header value is not valid UTF-8".into(),
                })
            }
        };

        // Helper: compare request-target path+query (if present) with a Location
        let req_pathq =
            crate::helpers::uri::extract_path_and_query_from_request_target(&tx.request.uri);
        let loc_pathq = crate::helpers::uri::extract_path_and_query_from_request_target(&first_loc);

        // 1) Immediate circular redirect: Location equals request target
        if let (Some(rpq), Some(lpq)) = (req_pathq.as_ref(), loc_pathq.as_ref()) {
            if rpq == lpq {
                // If both are absolute, ensure origins match or treat path-equality as circular
                let req_origin = crate::helpers::uri::extract_origin_if_absolute(&tx.request.uri);
                let loc_origin = crate::helpers::uri::extract_origin_if_absolute(&first_loc);
                let same_origin = match (req_origin, loc_origin) {
                    (Some(a), Some(b)) => a.eq_ignore_ascii_case(&b),
                    // if either side isn't absolute, treat path-equality as circular
                    _ => true,
                };

                if same_origin {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!(
                            "Redirect Location '{}' equals request target '{}' — circular redirect",
                            first_loc, tx.request.uri
                        ),
                    });
                }
            }
        }

        // 2) Repeated redirect to same Location for the same client+resource
        if let Some(prev) = history.previous() {
            if let Some(prev_resp) = &prev.response {
                if matches!(prev_resp.status, 300 | 301 | 302 | 303 | 307 | 308 | 201) {
                    if let Some(phv) = prev_resp.headers.get_all("location").iter().next() {
                        if let Ok(prev_loc) = phv.to_str() {
                            if prev_loc.trim() == first_loc {
                                return Some(Violation {
                                    rule: self.id().into(),
                                    severity: config.severity,
                                    message: format!(
                                        "Repeated redirect for '{}' to the same Location '{}' observed previously; possible redirect loop",
                                        tx.request.uri, first_loc
                                    ),
                                });
                            }
                        }
                    }
                }
            }
        }

        None
    }

    fn description(&self) -> &'static str {
        "Detects obvious redirect loops and repeated redirect targets for the same client+resource. The rule flags:\n\n- Immediate circular redirects where the `Location` header points back to the same request target (absolute or relative).\n- Repeated redirects for the same client+resource that point to the same `Location` as a previous response (likely misconfiguration or loop).\n\nThis is a conservative, high‑value stateful check — full multi-resource chain graph analysis is out of scope for the current per-resource state store."
    }

    fn rfc_references(&self) -> &'static [&'static str] {
        &[
            "[RFC 9110 §6.4 — Redirection](https://www.rfc-editor.org/rfc/rfc9110.html#section-6.4)",
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "> GET /resource HTTP/1.1\n\n< 301 Moved Permanently  HTTP/1.1\n< Location: /other",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— Location equals request target (circular)"),
                snippet: "> GET /resource HTTP/1.1\n\n< 301 Moved Permanently  HTTP/1.1\n< Location: /resource",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— same resource repeatedly redirects to same Location"),
                snippet: "// previous transaction for client requested /r -> 302 Location: /x\n\n> GET /r HTTP/1.1\n\n< 302 Found  HTTP/1.1\n< Location: /x",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &StatefulRedirectChainValidity;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn make_tx_with_req(uri: &str) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.uri = uri.to_string();
        tx
    }

    fn make_resp_tx(
        uri: &str,
        status: u16,
        loc: Option<&str>,
    ) -> crate::http_transaction::HttpTransaction {
        let mut tx = make_tx_with_req(uri);
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status,
            version: "HTTP/1.1".into(),
            headers: match loc {
                Some(l) => crate::test_helpers::make_headers_from_pairs(&[("location", l)]),
                None => crate::test_helpers::make_headers_from_pairs(&[]),
            },
            body_length: None,
            trailers: None,
        });
        tx
    }

    #[rstest]
    #[case("/a", "/a")]
    #[case("http://example.com/a", "/a")]
    #[case("http://example.com/a?x=1", "/a?x=1")]
    #[case("http://example.com/a", "http://example.com/a")]
    fn detects_circular_redirect_for_equal_path(#[case] req: &str, #[case] loc: &str) {
        let rule = StatefulRedirectChainValidity;
        let tx = make_resp_tx(req, 301, Some(loc));
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "stateful_redirect_chain_validity",
            ]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("circular redirect"));
    }

    #[test]
    fn does_not_flag_different_origin_same_path() {
        let rule = StatefulRedirectChainValidity;
        // different host should NOT be considered circular
        let tx = make_resp_tx("http://example.com/a", 301, Some("http://other/a"));
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "stateful_redirect_chain_validity",
            ]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn repeated_redirect_to_same_location_is_flagged() {
        let rule = StatefulRedirectChainValidity;

        let mut prev = make_resp_tx("/r", 302, Some("/x"));
        prev.client = crate::test_helpers::make_test_client();

        let mut tx = make_resp_tx("/r", 302, Some("/x"));
        tx.client = crate::test_helpers::make_test_client();

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::from_transactions(vec![prev.clone()]),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "stateful_redirect_chain_validity",
            ]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Repeated redirect"));
    }

    #[test]
    fn non_utf8_location_is_reported() {
        use hyper::header::HeaderName;
        use hyper::header::HeaderValue;

        let rule = StatefulRedirectChainValidity;
        let mut tx = make_tx_with_req("/r");
        let mut headers = crate::test_helpers::make_headers_from_pairs(&[]);
        // insert non-UTF8 Location value
        headers.insert(
            HeaderName::from_static("location"),
            HeaderValue::from_bytes(&[0xff]).unwrap(),
        );
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 301,
            version: "HTTP/1.1".into(),
            headers,
            body_length: None,
            trailers: None,
        });

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "stateful_redirect_chain_validity",
            ]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("not valid UTF-8"));
    }

    #[test]
    fn non_redirect_status_with_location_is_ignored() {
        let rule = StatefulRedirectChainValidity;
        let tx = make_resp_tx("/r", 200, Some("/x"));
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "stateful_redirect_chain_validity",
            ]),
        );
        // This rule only inspects redirect/creation status codes — ignore otherwise
        assert!(v.is_none());
    }

    #[test]
    fn previous_non_redirect_location_is_ignored_for_repeated_check() {
        let rule = StatefulRedirectChainValidity;

        let mut prev = make_resp_tx("/r", 200, Some("/x"));
        prev.client = crate::test_helpers::make_test_client();

        let mut tx = make_resp_tx("/r", 302, Some("/x"));
        tx.client = crate::test_helpers::make_test_client();

        // previous had non-redirect status -> should NOT trigger repeated-redirect violation
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::from_transactions(vec![prev.clone()]),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "stateful_redirect_chain_validity",
            ]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn no_location_is_ignored() {
        let rule = StatefulRedirectChainValidity;
        let tx = make_resp_tx("/r", 302, None);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "stateful_redirect_chain_validity",
            ]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "stateful_redirect_chain_validity");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
