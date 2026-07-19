// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ServerRedirectStatusAndLocationValidity;

impl Rule for ServerRedirectStatusAndLocationValidity {
    fn id(&self) -> &'static str {
        "server_redirect_status_and_location_validity"
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
        // If response has a Location header but the status code is not one
        // that normally indicates a redirect or created resource, report it.
        if let Some(resp) = &tx.response {
            let status = resp.status;
            // These statuses allow or SHOULD include Location when appropriate
            let allowed_with_location = matches!(status, 201 | 300 | 301 | 302 | 303 | 307 | 308);

            if !allowed_with_location && resp.headers.get_all("location").iter().next().is_some() {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!(
                        "Location header present on non-redirect response with status {} (RFC 9110 §10.2.2)",
                        status
                    ),
                });
            }
        }
        None
    }

    fn description(&self) -> &'static str {
        "Responses that indicate a resource has moved or been created (3xx redirections and 201 Created) commonly use the `Location` header to point to the target resource. A `Location` header appearing on responses that are not redirects or creations may indicate a misconfiguration or misuse; this rule flags `Location` header presence on non-redirect responses."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("10.2.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.2",
                note: "`Location = URI-reference` and semantics for redirection responses (3xx)",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("15.4"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4",
                note: "`201 Created` responses SHOULD include a `Location` header when a new resource is created",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nContent-Type: text/plain\n\nHello",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(redirect)"),
                snippet: "HTTP/1.1 302 Found\nLocation: /new",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nLocation: /unexpected",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ServerRedirectStatusAndLocationValidity;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    // Negative/positive cases: status, optional Location value, expect violation
    #[case(200, Some("/ok"), true)]
    #[case(200, None, false)]
    #[case(200, Some(""), true)]
    #[case(100, Some("/info"), true)]
    #[case(204, Some("/no-content-location"), true)]
    #[case(201, Some("/created"), false)]
    #[case(201, None, false)]
    #[case(301, Some("/moved"), false)]
    #[case(301, None, false)]
    #[case(404, Some("/notfound"), true)]
    fn check_location_presence(
        #[case] status: u16,
        #[case] loc: Option<&str>,
        #[case] expect_violation: bool,
    ) {
        let rule = ServerRedirectStatusAndLocationValidity;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(status, &[]);
        if let Some(l) = loc {
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[("location", l)]);
        }

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(
                v.is_some(),
                "expected violation for {} with loc {:?}",
                status,
                loc
            );
        } else {
            assert!(
                v.is_none(),
                "did not expect violation for {} with loc {:?}: got {:?}",
                status,
                loc,
                v
            );
        }
    }

    #[test]
    fn no_response_is_ignored() {
        let rule = ServerRedirectStatusAndLocationValidity;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);

        let tx = crate::test_helpers::make_test_transaction();
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn id_and_scope() {
        let rule = ServerRedirectStatusAndLocationValidity;
        assert_eq!(rule.id(), "server_redirect_status_and_location_validity");
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "server_redirect_status_and_location_validity");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
