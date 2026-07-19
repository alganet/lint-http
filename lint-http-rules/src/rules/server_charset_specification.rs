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
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
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

    fn description(&self) -> &'static str {
        "This rule checks if `Content-Type` headers for text-based resources (starting with `text/`) include a `charset` parameter.\n\nSpecifying the character encoding is crucial for security and correct rendering. If the charset is not explicitly defined, browsers may attempt to guess the encoding (MIME sniffing), which can lead to Cross-Site Scripting (XSS) vulnerabilities or incorrect display of characters."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("8.3"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3",
                note: "Content-Type header",
            },
            crate::rules::SpecRef {
                spec: "MDN Content-Type",
                section: None,
                url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Type",
                note: "Content-Type",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("Response"),
                snippet: "HTTP/1.1 200 OK\nContent-Type: text/html; charset=utf-8",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("Response"),
                snippet: "HTTP/1.1 200 OK\nContent-Type: text/html\n# Missing charset parameter",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ServerCharsetSpecification;

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
                trailers: None,
            });
        }

        let violation = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
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
