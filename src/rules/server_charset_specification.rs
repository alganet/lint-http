// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ServerCharsetSpecification;

impl Rule for ServerCharsetSpecification {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "server_charset_specification"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        config: &Self::Config,
    ) -> Option<Violation> {
        let Some(resp) = &tx.response else {
            return None;
        };

        if let Some(ct_str) = crate::helpers::headers::get_header_str(&resp.headers, "content-type")
        {
            // Parse content-type to inspect type and parameters reliably
            if let Ok(parsed) = crate::helpers::headers::parse_media_type(ct_str) {
                if parsed.type_.eq_ignore_ascii_case("text") {
                    let has_charset = parsed.params.unwrap_or("").split(';').any(|p| {
                        let p = p.trim();
                        p.split_once('=')
                            .map(|(k, _)| k.trim().eq_ignore_ascii_case("charset"))
                            .unwrap_or(false)
                    });

                    if !has_charset {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: "Text-based Content-Type header missing charset parameter."
                                .into(),
                        });
                    }
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
                version: "HTTP/1.1".into(),
                headers: crate::test_helpers::make_headers_from_pairs(&[(
                    "content-type",
                    content_type,
                )]),

                body_length: None,
            });
        }

        let violation = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );

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
