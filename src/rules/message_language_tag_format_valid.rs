// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageLanguageTagFormatValid;

impl Rule for MessageLanguageTagFormatValid {
    type Config = crate::rules::RuleConfig;

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
        config: &Self::Config,
    ) -> Option<Violation> {
        // Helper to validate language-tag tokens according to helpers::language
        let check_tag = |hdr: &str, tag: &str| -> Option<Violation> {
            if let Err(e) = crate::helpers::language::validate_language_tag(tag) {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!("Invalid language tag '{}' in {}: {}", tag, hdr, e),
                });
            }
            None
        };

        // Check Content-Language (response or request)
        if let Some(resp) = &tx.response {
            if let Some(val) =
                crate::helpers::headers::get_header_str(&resp.headers, "content-language")
            {
                for token in crate::helpers::headers::parse_list_header(val) {
                    if let Some(v) = check_tag("Content-Language", token) {
                        return Some(v);
                    }
                }
            }
        }

        if let Some(val) =
            crate::helpers::headers::get_header_str(&tx.request.headers, "content-language")
        {
            for token in crate::helpers::headers::parse_list_header(val) {
                if let Some(v) = check_tag("Content-Language", token) {
                    return Some(v);
                }
            }
        }

        // Check Accept-Language: members may include parameters (e.g., q=0.8)
        if let Some(val) =
            crate::helpers::headers::get_header_str(&tx.request.headers, "accept-language")
        {
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

        // Check Accept-Language in response (some servers may echo it back; be conservative)
        if let Some(resp) = &tx.response {
            if let Some(val) =
                crate::helpers::headers::get_header_str(&resp.headers, "accept-language")
            {
                for member in crate::helpers::headers::parse_list_header(val) {
                    let lang = member.split(';').next().unwrap().trim();
                    if lang == "*" {
                        continue;
                    }
                    if let Some(v) = check_tag("Accept-Language", lang) {
                        return Some(v);
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
        let cfg = crate::test_helpers::make_test_rule_config();

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
        let cfg = crate::test_helpers::make_test_rule_config();

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

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_language_tag_format_valid",
        ]);
        let _engine = crate::rules::validate_rules(&cfg)?;
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
        let cfg = crate::test_helpers::make_test_rule_config();

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
        let cfg = crate::test_helpers::make_test_rule_config();

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
