// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageContentMd5VsDigestPreference;

impl Rule for MessageContentMd5VsDigestPreference {
    fn id(&self) -> &'static str {
        "message_content_md5_vs_digest_preference"
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
        // Helper to check a header map for both Content-Digest and Content-MD5
        let check_map = |which: &str, headers: &hyper::HeaderMap| -> Option<Violation> {
            let has_new = headers.get_all("content-digest").iter().next().is_some();
            let has_md5 = headers.get_all("content-md5").iter().next().is_some();

            if has_new && has_md5 {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!("Both Content-Digest and Content-MD5 present in {}; prefer validating with Content-Digest; Content-MD5 is deprecated (RFC 9530)", which),
                });
            }
            None
        };

        // Check request
        if let Some(v) = check_map("request", &tx.request.headers) {
            return Some(v);
        }

        // Check response
        if let Some(resp) = &tx.response {
            if let Some(v) = check_map("response", &resp.headers) {
                return Some(v);
            }
        }

        None
    }

    fn description(&self) -> &'static str {
        "If both legacy `Content-MD5` and modern `Content-Digest` are present in the same message, prefer validating and using `Content-Digest`. `Content-MD5` is deprecated by newer specifications (see RFC 9530) and may not carry the same algorithm flexibility or security guarantees.\n\nThis rule flags messages (requests or responses) that include both `Content-Digest` (RFC 9530 structured digest) and the legacy `Content-MD5` header. When both are present, `Content-Digest` should be preferred for integrity validation and `Content-MD5` should be avoided because it is deprecated."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9530",
                section: Some("2"),
                url: "https://www.rfc-editor.org/rfc/rfc9530.html#section-2",
                note: "Content-Digest and related structured fields",
            },
            crate::rules::SpecRef {
                spec: "RFC 7231",
                section: Some("3.3.2"),
                url: "https://www.rfc-editor.org/rfc/rfc7231.html#section-3.3.2",
                note: "Content-MD5 (historical reference)",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "Content-Digest: sha-256=\":dGVzdA==:\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "Content-Digest: sha-256=\":dGVzdA==:\"\nContent-MD5: dGVzdA==",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &MessageContentMd5VsDigestPreference;

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;

    #[test]
    fn both_headers_in_request_reports_violation() {
        let rule = MessageContentMd5VsDigestPreference;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_content_md5_vs_digest_preference",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("content-digest", "sha-256=:\tdGVzdA==:"),
            ("content-md5", "dGVzdA=="),
        ]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let v = v.unwrap();
        assert_eq!(v.rule, "message_content_md5_vs_digest_preference");
        assert!(v.message.contains("prefer validating with Content-Digest"));
    }

    #[test]
    fn both_headers_in_response_reports_violation() {
        let rule = MessageContentMd5VsDigestPreference;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_content_md5_vs_digest_preference",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            ("content-digest", "sha-256=:\tdGVzdA==:"),
            ("content-md5", "dGVzdA=="),
        ]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn only_content_digest_is_ok() {
        let rule = MessageContentMd5VsDigestPreference;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_content_md5_vs_digest_preference",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-digest",
            "sha-256=:\tdGVzdA==:",
        )]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn only_content_md5_is_ok_for_this_specific_rule() {
        // Content-MD5 alone is handled by the digest header syntax rule for deprecation. This rule only flags when both are present.
        let rule = MessageContentMd5VsDigestPreference;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_content_md5_vs_digest_preference",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-md5", "dGVzdA==")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn non_utf8_content_md5_but_content_digest_present_reports_violation() {
        let rule = MessageContentMd5VsDigestPreference;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_content_md5_vs_digest_preference",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        // Insert non-utf8 for content-md5
        let bad = hyper::header::HeaderValue::from_bytes(b"\xff").unwrap();
        tx.response
            .as_mut()
            .unwrap()
            .headers
            .insert("content-md5", bad);
        // But also have content-digest present as normal
        tx.response.as_mut().unwrap().headers.append(
            "content-digest",
            HeaderValue::from_static("sha-256=:\tdGVzdA==:"),
        );

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn id_and_scope_are_expected() {
        let rule = MessageContentMd5VsDigestPreference;
        assert_eq!(rule.id(), "message_content_md5_vs_digest_preference");
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }

    #[test]
    fn request_precedence_over_response() {
        let rule = MessageContentMd5VsDigestPreference;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_content_md5_vs_digest_preference",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("content-digest", "sha-256=:\tdGVzdA==:"),
            ("content-md5", "dGVzdA=="),
        ]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            ("content-digest", "sha-256=:\tdGVzdA==:"),
            ("content-md5", "dGVzdA=="),
        ]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let v = v.unwrap();
        // Ensure the message refers to the request (i.e., the rule returned early on request)
        assert!(v.message.contains("request"));
    }

    #[test]
    fn validate_parses_rule_config() -> anyhow::Result<()> {
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_content_md5_vs_digest_preference",
        ]);
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
