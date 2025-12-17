// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ServerCharsetSpecification;

impl Rule for ServerCharsetSpecification {
    fn id(&self) -> &'static str {
        "server_charset_specification"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _previous: Option<&crate::http_transaction::HttpTransaction>,
        _config: &crate::config::Config,
    ) -> Option<Violation> {
        let Some(resp) = &tx.response else {
            return None;
        };
        if let Some(content_type) = resp.headers.get(hyper::header::CONTENT_TYPE.as_str()) {
            if let Ok(ct_str) = content_type.to_str() {
                let ct_lower = ct_str.to_lowercase();
                if ct_lower.starts_with("text/")
                    && !ct_lower.contains(";charset=")
                    && !ct_lower.contains("; charset=")
                {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: crate::rules::get_rule_severity(_config, self.id()),
                        message: "Text-based Content-Type header missing charset parameter.".into(),
                    });
                }
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
    #[case("text/html; charset=utf-8", false, None)]
    #[case("text/html;charset=utf-8", false, None)]
    #[case("TEXT/HTML;CHARSET=UTF-8", false, None)]
    #[case(
        "text/html",
        true,
        Some("Text-based Content-Type header missing charset parameter.")
    )]
    #[case("application/json", false, None)]
    #[case("", false, None)]
    fn check_response_cases(
        #[case] content_type: &str,
        #[case] expect_violation: bool,
        #[case] expected_message: Option<&str>,
    ) -> anyhow::Result<()> {
        let rule = ServerCharsetSpecification;

        let mut tx = crate::test_helpers::make_test_transaction();
        if !content_type.is_empty() {
            tx.response = Some(crate::http_transaction::ResponseInfo {
                status: 200,
                headers: crate::test_helpers::make_headers_from_pairs(&[(
                    "content-type",
                    content_type,
                )]),
            });
        }

        let violation = rule.check_transaction(&tx, None, &crate::config::Config::default());

        if expect_violation {
            assert!(violation.is_some());
            assert_eq!(
                violation.map(|v| v.message),
                expected_message.map(|s| s.to_string())
            );
        } else {
            assert!(violation.is_none());
        }
        Ok(())
    }
}
