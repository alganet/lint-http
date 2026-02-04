// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ServerRedirectStatusAndLocationValidity;

impl Rule for ServerRedirectStatusAndLocationValidity {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "server_redirect_status_and_location_validity"
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
}

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
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(status, &[]);
        if let Some(l) = loc {
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[("location", l)]);
        }

        let v = rule.check_transaction(&tx, None, &cfg);
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
        let cfg = crate::test_helpers::make_test_rule_config();

        let tx = crate::test_helpers::make_test_transaction();
        let v = rule.check_transaction(&tx, None, &cfg);
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
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
