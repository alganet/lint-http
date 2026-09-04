// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};

/// Validate `ETag` header values: must be a single entity-tag (strong or weak quoted-string)
/// per RFC 9110 §8.8.3. Also flags invalid UTF-8 and multiple header fields.
pub struct EtagSyntax;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9110_8_8_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("8.8.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8.3",
    note: "`ETag` header field, the `ETag = entity-tag` field production, and the `entity-tag` grammar",
};
const RFC_9110_5_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("5.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.3",
    note: "Field Order: a non-list field (such as `ETag = entity-tag`) must not appear as multiple field lines",
};

impl RuleMeta for EtagSyntax {
    fn id(&self) -> &'static str {
        "etag_syntax"
    }

    fn title(&self) -> Option<&'static str> {
        Some("Message ETag Syntax")
    }

    fn description(&self) -> &'static str {
        "Validate that the `ETag` response header contains a single, syntactically valid entity-tag (strong or weak) as defined by RFC 9110. This rule flags non-UTF-8 header values, the use of the special `*` value (which is only meaningful in conditional request headers), and the presence of multiple `ETag` header fields."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_9110_8_8_3, RFC_9110_5_3]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("(strong ETag)"),
                snippet: "HTTP/1.1 200 OK\nETag: \"33a64df551425fcc55e4d42a148795d9f25f89d4\"",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(weak ETag)"),
                snippet: "HTTP/1.1 200 OK\nETag: W/\"67ab43\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(`*` used in response)"),
                snippet: "HTTP/1.1 200 OK\nETag: *",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(missing quotes)"),
                snippet: "HTTP/1.1 200 OK\nETag: abc",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(multiple header fields)"),
                snippet: "HTTP/1.1 200 OK\nETag: \"a\"\nETag: \"b\"",
            },
        ]
    }
}

impl Rule for EtagSyntax {
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // Single-finding body behind an Option: `?` ends it early, and the
        // one finding (or none) becomes the vector.
        let finding = || -> Option<Violation> {
            // ETag is a response field, which is why this rule is Server-scoped and only
            // inspects the response.
            // cite(RFC 9110 § 8.8.3): "The "ETag" field in a response provides the current entity tag for the selected representation, as determined at the conclusion of handling the request."
            let Some(resp) = &tx.response else {
                return None;
            };

            let mut count = 0usize;
            for hv in resp.headers.get_all("etag").iter() {
                count += 1;
                let Ok(s) = hv.to_str() else {
                    return Some(
                        self.violation(ctx.severity, "ETag header value is not valid UTF-8".into()),
                    );
                };

                let t = s.trim();
                // The `*` kept its own branch, and the reason changed. It stood here
                // because `validate_entity_tag` admitted a `*` -- which no
                // `entity-tag` generates, and the helper refuses now -- so the branch
                // is no longer a correction of the helper. It stays because this
                // finding is worth more than the helper's: `*` is the one non-tag an
                // `ETag` plausibly holds, written by a server copying the shape of
                // the conditional fields that do take it.
                // cite(RFC 9110 § 8.8.3): "An entity tag consists of an opaque quoted string, possibly prefixed by a weakness indicator."
                if t == "*" {
                    return Some(self.cited(&RFC_9110_8_8_3, ctx.severity, "ETag header value '*' is invalid for responses; ETag must be an entity-tag"
                                .into()));
                }

                // The entity-tag grammar itself (§8.8.3) is owned by `validate_entity_tag`.
                if let Err(msg) = crate::helpers::validator::validate_entity_tag(t) {
                    return Some(
                        self.violation(ctx.severity, format!("ETag header invalid: {}", msg)),
                    );
                }
            }

            // `ETag = entity-tag` is a single value, not a list (`#entity-tag`), so ETag is
            // not a field whose lines may be recombined as a comma-separated list — the §5.3
            // exception does not apply, and a sender must emit at most one ETag field line.
            // cite(RFC 9110 § 5.3): "a sender MUST NOT generate multiple field lines with the same name in a message (whether in the headers or trailers) or append a field line when a field line of the same name already exists in the message, unless that field's definition allows multiple field line values to be recombined as a comma-separated list"
            if count > 1 {
                return Some(self.cited(&RFC_9110_5_3, ctx.severity, format!(
                        "Multiple ETag header fields present ({}); ETag must be a single entity-tag",
                        count
                    )));
            }

            None
        };
        Vec::from_iter(finding())
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &EtagSyntax;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(Some("\"abc\""), false)]
    #[case(Some("W/\"abc\""), false)]
    #[case(Some("*"), true)]
    #[case(Some("abc"), true)]
    #[case(None, false)]
    fn etag_cases(#[case] value: Option<&str>, #[case] expect_violation: bool) {
        let rule = EtagSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(v) = value {
            tx.response = Some(crate::http_transaction::ResponseInfo {
                status: 200,
                version: "HTTP/1.1".into(),
                headers: crate::test_helpers::make_headers_from_pairs(&[("etag", v)]),

                body_length: None,
                trailers: None,
            });
        }

        let cfg = crate::test_helpers::make_test_config_with_severity(rule.id(), "warn");

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(v.is_some(), "expected violation for value={:?}", value);
        } else {
            assert!(
                v.is_none(),
                "unexpected violation for value={:?}: {:?}",
                value,
                v
            );
        }
    }

    #[test]
    fn non_utf8_is_violation() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;
        let rule = EtagSyntax;

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        let bad = HeaderValue::from_bytes(&[0xff])?;
        hm.insert("etag", bad);
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,

            body_length: None,
            trailers: None,
        });

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn multiple_etag_headers_reported() {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;
        let rule = EtagSyntax;

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        hm.append("etag", HeaderValue::from_static("\"a\""));
        hm.append("etag", HeaderValue::from_static("\"b\""));
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,

            body_length: None,
            trailers: None,
        });

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "etag_syntax");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn id_and_scope_are_expected() {
        let r = EtagSyntax;
        assert_eq!(r.id(), "etag_syntax");
        assert_eq!(r.scope(), crate::rules::RuleScope::Server);
    }
}
