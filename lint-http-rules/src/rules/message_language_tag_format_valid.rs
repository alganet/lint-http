// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageLanguageTagFormatValid;

impl Rule for MessageLanguageTagFormatValid {
    fn id(&self) -> &'static str {
        "message_language_tag_format_valid"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
        // Helper to validate language-tag tokens according to helpers::language
        let check_tag = |hdr: &str, tag: &str| -> Option<Violation> {
            // cite(RFC 9110 § 8.5.1): "A language tag, as defined in [RFC5646], identifies a natural language spoken, written, or otherwise conveyed by human beings for communication of information to other human beings."
            if let Err(e) = crate::helpers::language::validate_language_tag(tag) {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!("Invalid language tag '{}' in {}: {}", tag, hdr, e),
                });
            }
            None
        };

        // Both fields are lists, so a sender may spread their members over
        // several field lines and a recipient recombines them. Reading only the
        // first — `get_header_str` returns one value — left every later line
        // unchecked, and `message_accept_language_weight_validity` defers the
        // range's syntax to this rule, so for those lines the deferral pointed
        // at nobody.
        //
        // Each line is walked on its own rather than joined first, which for a
        // per-member syntax check is the same answer either way and keeps a
        // malformed line from being described in terms of its neighbour.
        let content_language = |headers: &hyper::HeaderMap| -> Option<Violation> {
            for hv in headers.get_all("content-language").iter() {
                let Ok(val) = hv.to_str() else { continue };
                for token in crate::helpers::headers::parse_list_header(val) {
                    if let Some(v) = check_tag("Content-Language", token) {
                        return Some(v);
                    }
                }
            }
            None
        };

        let accept_language = |headers: &hyper::HeaderMap| -> Option<Violation> {
            for hv in headers.get_all("accept-language").iter() {
                let Ok(val) = hv.to_str() else { continue };
                for member in crate::helpers::headers::parse_list_header(val) {
                    let lang = member.split(';').next().unwrap().trim();
                    if lang == "*" {
                        continue; // wildcard allowed
                    }
                    if let Some(v) = check_tag("Accept-Language", lang) {
                        return Some(v);
                    }
                }
            }
            None
        };

        if let Some(resp) = &tx.response {
            if let Some(v) = content_language(&resp.headers) {
                return Some(v);
            }
        }
        if let Some(v) = content_language(&tx.request.headers) {
            return Some(v);
        }
        if let Some(v) = accept_language(&tx.request.headers) {
            return Some(v);
        }
        if let Some(resp) = &tx.response {
            if let Some(v) = accept_language(&resp.headers) {
                return Some(v);
            }
        }

        None
    }

    fn description(&self) -> &'static str {
        "Validate that any language tag appearing in HTTP headers such as `Content-Language` and `Accept-Language` follows a well-formed BCP 47-style syntax (RFC 5646). This check is conservative: it rejects obvious syntax problems (invalid characters, empty subtags, consecutive hyphens, or overly long subtags) while accepting common valid forms such as `en`, `en-US`, `zh-Hant`, `sr-Latn-RS`, and private-use tags like `x-custom`."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 5646",
                section: None,
                url: "https://www.rfc-editor.org/rfc/rfc5646.html",
                note: "BCP 47 language tag syntax",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("12.5.4"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.4",
                note: "Accept-Language — Accept-Language uses language-tags from RFC 5646",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("8.5"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.5",
                note: "Content-Language — Content-Language uses language-tags from RFC 5646",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "Accept-Language: en, fr-CA;q=0.8\nContent-Language: en-US",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "Accept-Language: en_US\nContent-Language: en-TooLongSubtag123",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &MessageLanguageTagFormatValid;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(Some("en"), false)]
    #[case(Some("en-US"), false)]
    #[case(Some("zh-Hant, en;q=0.8"), false)]
    #[case(Some("*"), false)]
    #[case(Some("en_US"), true)]
    #[case(Some("en-TooLongSubtag123"), true)]
    #[case(None, false)]
    fn check_accept_language_request(
        #[case] cl: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageLanguageTagFormatValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_language_tag_format_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(v) = cl {
            tx.request.headers =
                crate::test_helpers::make_headers_from_pairs(&[("accept-language", v)]);
        }

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(v.is_some());
        } else {
            assert!(v.is_none());
        }
        Ok(())
    }

    #[rstest]
    #[case(Some("en, fr-CA"), false)]
    #[case(Some("en, en_US"), true)]
    fn check_content_language_response(
        #[case] cl: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageLanguageTagFormatValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_language_tag_format_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        if let Some(v) = cl {
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[("content-language", v)]);
        }

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(v.is_some());
        } else {
            assert!(v.is_none());
        }
        Ok(())
    }

    #[test]
    fn message_and_id() {
        let rule = MessageLanguageTagFormatValid;
        assert_eq!(rule.id(), "message_language_tag_format_valid");
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }

    /// Both fields are lists whose members may be spread over several field
    /// lines. Only the first was read, so a malformed tag on a later line was
    /// reported by nobody — and `message_accept_language_weight_validity`
    /// defers the range's syntax to this rule, so that deferral was false for
    /// exactly those lines.
    #[rstest]
    #[case("accept-language", &["en", "e n"], true)]
    #[case("accept-language", &["e n", "en"], true)]
    #[case("accept-language", &["en", "fr;q=0.5"], false)]
    #[case("content-language", &["en", "e n"], true)]
    #[case("content-language", &["en", "fr"], false)]
    fn every_field_line_is_read(
        #[case] header: &str,
        #[case] values: &[&str],
        #[case] expect_violation: bool,
    ) {
        let rule = MessageLanguageTagFormatValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let mut tx = crate::test_helpers::make_test_transaction();
        let pairs: Vec<(&str, &str)> = values.iter().map(|v| (header, *v)).collect();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&pairs);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert_eq!(
            v.is_some(),
            expect_violation,
            "{header} {values:?} -> {v:?}"
        );
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_language_tag_format_valid",
        ]);
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[rstest]
    #[case(Some("en, *;q=0.5"), false)]
    #[case(Some("en, en_US"), true)]
    fn check_accept_language_in_response(
        #[case] al: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageLanguageTagFormatValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_language_tag_format_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        if let Some(v) = al {
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[("accept-language", v)]);
        }

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(v.is_some());
        } else {
            assert!(v.is_none());
        }
        Ok(())
    }

    #[test]
    fn check_content_language_in_request() -> anyhow::Result<()> {
        let rule = MessageLanguageTagFormatValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_language_tag_format_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-language", "en, fr")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
        Ok(())
    }
}
