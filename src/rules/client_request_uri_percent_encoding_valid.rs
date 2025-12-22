// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ClientRequestUriPercentEncodingValid;

impl Rule for ClientRequestUriPercentEncodingValid {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "client_request_uri_percent_encoding_valid"
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
        let s = tx.request.uri.as_str();
        if let Some(msg) = crate::uri::check_percent_encoding(s) {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!("{} in request-target", msg),
            });
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("/path/to/resource", false)]
    #[case("/path%20with%20spaces", false)]
    #[case("/path%2Fwith%2Fslashes", false)]
    #[case("/%41BC", false)]
    #[case("/mix%2fCase%2F", false)]
    #[case("/incomplete%2", true)]
    #[case("/endswith%", true)]
    #[case("/bad%2Gchar", true)]
    #[case("/bad%zz", true)]
    fn check_percent_encoding(#[case] uri: &str, #[case] expect_violation: bool) {
        let rule = ClientRequestUriPercentEncodingValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.uri = uri.to_string();

        let config = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Error,
        };

        let violation = rule.check_transaction(&tx, None, &config);

        if expect_violation {
            assert!(violation.is_some());
            let v = violation.unwrap();
            assert_eq!(v.rule, "client_request_uri_percent_encoding_valid");
            assert!(
                v.message.contains('%')
                    || v.message.contains("Percent-encoding")
                    || v.message.contains("Invalid")
            );
        } else {
            assert!(violation.is_none());
        }
    }

    #[test]
    fn scope_is_client() {
        let rule = ClientRequestUriPercentEncodingValid;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Client);
    }
}
