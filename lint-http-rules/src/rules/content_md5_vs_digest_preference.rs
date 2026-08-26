// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ContentMd5VsDigestPreference;

impl Rule for ContentMd5VsDigestPreference {
    fn id(&self) -> &'static str {
        "content_md5_vs_digest_preference"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Option<Violation> {
        // Helper to check a header map for both Content-Digest and Content-MD5.
        // The same check runs over the request and the response below, which is
        // what this sentence licenses — Content-Digest is defined for both
        // directions, so neither side is out of scope.
        // cite(RFC 9530 § 2): "The Content-Digest HTTP field can be used in requests and responses"
        let check_map = |which: &str, headers: &hyper::HeaderMap| -> Option<Violation> {
            let has_new = headers.get_all("content-digest").iter().next().is_some();
            let has_md5 = headers.get_all("content-md5").iter().next().is_some();

            // No sentence anywhere says "prefer Content-Digest over Content-MD5":
            // RFC 9530 never mentions Content-MD5, so it cannot rank them. What is
            // citable is that Content-MD5 is not part of HTTP at all — removed by
            // RFC 7231, years before RFC 9530 existed. The preference is this
            // linter's judgement resting on that fact.
            //
            // The distinct hazard here, and the reason this rule earns its keep
            // beside `digest_header_syntax` (which reports a lone
            // Content-MD5 already), is *disagreement*: two integrity values over
            // the same content, computed by different algorithms, with nothing
            // saying which a recipient validates. The message names that rather
            // than repeating the sibling's obsolescence report.
            // cite(RFC 7231): "The Content-MD5 header field has been removed because it was inconsistently implemented with respect to partial responses."
            if has_new && has_md5 {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: ctx.severity,
                    message: format!(
                        "Both Content-Digest and Content-MD5 present in {}; they are independent integrity values that can disagree, and nothing specifies which a recipient validates. Content-MD5 was removed from HTTP by RFC 7231 — send only Content-Digest",
                        which
                    ),
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
        "This rule flags messages (requests or responses) that carry both `Content-Digest` (the RFC 9530 structured field) and the legacy `Content-MD5` header.\n\nCarrying both is a hazard in its own right: they are independent integrity values over the same content, computed by different algorithms, and no specification says which one a recipient validates — so a mismatch between them has no defined resolution.\n\n`Content-MD5` should simply be dropped. It is not merely discouraged but absent from HTTP: RFC 7231 removed it, for being inconsistently implemented with respect to partial responses. (RFC 9530, which defines `Content-Digest`, does not mention `Content-MD5` at all and so is not the document that retired it.)"
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9530",
                section: Some("2"),
                url: "https://www.rfc-editor.org/rfc/rfc9530.html#section-2",
                note: "`Content-Digest`, the field to keep — defined for both requests and responses, which is why both are checked. Note it does not mention `Content-MD5`, so it is not what retired it",
            },
            crate::rules::SpecRef {
                spec: "RFC 7231",
                section: Some("Appendix B"),
                url: "https://www.rfc-editor.org/rfc/rfc7231.html#appendix-B",
                note: "Where `Content-MD5` was removed from HTTP, and the reason: inconsistent implementation with respect to partial responses",
            },
            crate::rules::SpecRef {
                spec: "RFC 2616",
                section: Some("14.15"),
                url: "https://www.rfc-editor.org/rfc/rfc2616.html#section-14.15",
                note: "`Content-MD5`, where it was defined — and from where RFC 7231 removed it. This reference said RFC 7231 §3.3.2, a section that does not exist in RFC 7231",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "Content-Digest: sha-256=:dGVzdA==:",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "Content-Digest: sha-256=:dGVzdA==:\nContent-MD5: dGVzdA==",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ContentMd5VsDigestPreference;

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;

    /// `gendocs` publishes `examples()` to users, but nothing runs a rule's own
    /// snippets through the rules, so a malformed one can survive there
    /// indefinitely — and this rule's did. Both examples carried
    /// `Content-Digest: sha-256=":dGVzdA==:"`, whose quotes make the value a
    /// structured-field String rather than the Byte Sequence the field requires;
    /// the rule that owns that syntax rejects it. This rule checks only header
    /// presence, so it could never have caught its own bad example.
    #[test]
    fn published_content_digest_examples_are_valid_syntax() {
        use crate::rules::digest_header_syntax::DigestHeaderSyntax;

        let syntax_rule = DigestHeaderSyntax;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[syntax_rule.id()]);

        for example in ContentMd5VsDigestPreference.examples() {
            for line in example.snippet.lines() {
                let Some(value) = line.strip_prefix("Content-Digest: ") else {
                    continue;
                };
                let tx = crate::test_helpers::make_test_transaction_with_response(
                    200,
                    &[("content-digest", value)],
                );
                let v = crate::test_helpers::run_rule(
                    &syntax_rule,
                    &tx,
                    &crate::transaction_history::TransactionHistory::empty(),
                    &cfg,
                );
                assert!(
                    v.is_none(),
                    "published example carries a Content-Digest the syntax rule rejects: \
                     {value:?} -> {v:?}"
                );
            }
        }
    }

    #[test]
    fn both_headers_in_request_reports_violation() {
        let rule = ContentMd5VsDigestPreference;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "content_md5_vs_digest_preference",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("content-digest", "sha-256=:\tdGVzdA==:"),
            ("content-md5", "dGVzdA=="),
        ]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let v = v.unwrap();
        assert_eq!(v.rule, "content_md5_vs_digest_preference");
        assert!(v.message.contains("send only Content-Digest"));
        assert!(v.message.contains("can disagree"));
        // The obsolescence is attributed to the document that actually removed
        // the field, not to RFC 9530, which never mentions it.
        assert!(v.message.contains("RFC 7231"));
        assert!(!v.message.contains("deprecated (RFC 9530)"));
    }

    #[test]
    fn both_headers_in_response_reports_violation() {
        let rule = ContentMd5VsDigestPreference;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "content_md5_vs_digest_preference",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            ("content-digest", "sha-256=:\tdGVzdA==:"),
            ("content-md5", "dGVzdA=="),
        ]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn only_content_digest_is_ok() {
        let rule = ContentMd5VsDigestPreference;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "content_md5_vs_digest_preference",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-digest",
            "sha-256=:\tdGVzdA==:",
        )]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn only_content_md5_is_ok_for_this_specific_rule() {
        // Content-MD5 alone is handled by the digest header syntax rule for deprecation. This rule only flags when both are present.
        let rule = ContentMd5VsDigestPreference;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "content_md5_vs_digest_preference",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-md5", "dGVzdA==")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn non_utf8_content_md5_but_content_digest_present_reports_violation() {
        let rule = ContentMd5VsDigestPreference;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "content_md5_vs_digest_preference",
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

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn id_and_scope_are_expected() {
        let rule = ContentMd5VsDigestPreference;
        assert_eq!(rule.id(), "content_md5_vs_digest_preference");
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }

    #[test]
    fn request_precedence_over_response() {
        let rule = ContentMd5VsDigestPreference;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "content_md5_vs_digest_preference",
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

        let v = crate::test_helpers::run_rule(
            &rule,
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
            "content_md5_vs_digest_preference",
        ]);
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
