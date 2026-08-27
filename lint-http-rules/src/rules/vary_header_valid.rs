// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// Validate the `Vary` response header against RFC 9110 §12.5.5:
/// `Vary = #( "*" / field-name )`. Each field-name must conform to the `token`
/// grammar (tchar). Because it is a `#`-list, an empty value is a legal
/// zero-element list; `*` is an ordinary list member and may appear alongside
/// field-names (RFC 7231's `"*" / 1#field-name` exclusivity was dropped).
pub struct VaryHeaderValid;

impl Rule for VaryHeaderValid {
    fn id(&self) -> &'static str {
        "vary_header_valid"
    }

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
            // Vary is a response header field; the rule inspects responses only.
            // cite(RFC 9110 § 12.5.5): "The "Vary" header field in a response describes what parts of a request message, aside from the method and target URI, might have influenced the origin server's process for selecting the content of this response."
            let resp = tx.response.as_ref()?;

            // The whole check transcribes the field grammar: a comma list whose members
            // are each "*" or a field-name.
            // cite(RFC 9110 § 12.5.5): "Vary = #( "*" / field-name )"
            for hv in resp.headers.get_all("vary").iter() {
                let s = match hv.to_str() {
                    Ok(s) => s,
                    Err(_) => {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: ctx.severity,
                            message: "Vary header contains non-UTF8 value".into(),
                        })
                    }
                };

                // Vary is a `#`-list, so an entirely empty value is a legal zero-element
                // list (the degenerate "does not vary" case), not a malformed header.
                // Distinct from an empty *element* within a non-empty list, flagged below.
                if s.trim().is_empty() {
                    continue;
                }

                // An empty element within the list (trailing/leading/consecutive commas)
                // is forbidden, unlike the empty whole value skipped above.
                // cite(RFC 9110 § 5.6.1.1): "In any production that uses the list construct, a sender MUST NOT generate empty list elements."
                for raw in s.split(',') {
                    if raw.trim().is_empty() {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: ctx.severity,
                            message: "Vary header contains empty token (e.g., trailing or consecutive commas)".into(),
                        });
                    }
                }

                for token in crate::helpers::headers::list_members(s) {
                    // "*" is a valid list member. Under RFC 9110 it may appear alongside
                    // field-names (RFC 7231's "*"-or-a-list exclusivity was dropped), so
                    // no combination check is made — only field-name tokens are validated.
                    //
                    // §12.5.5's one MUST on "*" — "A proxy MUST NOT generate "*" in a Vary
                    // field value." — is deliberately not enforced, and not merely because
                    // the sender's role is unknown. It forbids *generating*, not carrying:
                    // an intermediary that forwards an origin's `Vary: *` is compliant, and
                    // an origin may send it freely. So even a definite "a proxy handled
                    // this" signal (a `Via` field) would not identify who authored the
                    // header, and no field records authorship. The check is undecidable
                    // from an observed response rather than merely unimplemented, so the
                    // sentence stays uncited here: the code does not enforce it.
                    if token == "*" {
                        continue;
                    }

                    // Every other member is a field-name, i.e. a token.
                    if let Some(c) = crate::helpers::token::find_invalid_token_char(token) {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: ctx.severity,
                            message: format!(
                                "Vary header contains invalid field-name token character: '{}'",
                                c
                            ),
                        });
                    }
                }
            }

            None
        };
        Vec::from_iter(finding())
    }

    fn description(&self) -> &'static str {
        "Validate the `Vary` response header against its grammar `Vary = #( \"*\" / field-name )` (RFC 9110 §12.5.5). This rule enforces that:\n\n- Each field-name conforms to the `token` grammar (RFC `tchar`).\n- The list contains no empty elements (a stray, leading, or trailing comma).\n\nBecause `Vary` is a comma-separated (`#`) list, an entirely empty value is a legal zero-element list and is not flagged. The wildcard `*` is an ordinary list member: under RFC 9110 it may appear alongside field-names, so the combination is not reported (RFC 7231's `\"*\" / 1#field-name` exclusivity no longer applies)."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[crate::rules::SpecRef {
            spec: "RFC 9110",
            section: Some("12.5.5"),
            url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.5",
            note: "Vary = #( \"*\" / field-name ) — a comma-separated list; \"*\" is an ordinary member (RFC 7231's \"*\"-or-a-list form is obsolete). Not checked: the same section's \"A proxy MUST NOT generate \\\"*\\\"\", since a forwarded \"*\" is indistinguishable from a generated one in an observed response",
        }]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "Vary: Accept-Encoding\nVary: User-Agent",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "Vary: Accept-Encoding, User-Agent",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "Vary: *",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("— '*' may accompany field-names under RFC 9110"),
                snippet: "Vary: *, Accept-Encoding",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "Vary: x@bad                # invalid token characters in field-name\nVary: Accept-Encoding,     # empty element (trailing comma) is invalid",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &VaryHeaderValid;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(None, false)]
    #[case(Some("*"), false)]
    #[case(Some("accept-encoding"), false)]
    #[case(Some("Accept-Encoding, User-Agent"), false)]
    // '*' alongside field-names is valid under RFC 9110's #-list grammar.
    #[case(Some("accept-encoding, *"), false)]
    #[case(Some("*, accept-encoding"), false)]
    // Empty value / whitespace-only is a legal zero-element list.
    #[case(Some(""), false)]
    #[case(Some("   "), false)]
    #[case(Some("x@bad"), true)]
    // Empty *elements* within a non-empty list remain violations.
    #[case(Some("Accept-Encoding,"), true)]
    #[case(Some(",Accept-Encoding"), true)]
    #[case(Some("Accept-Encoding,,User-Agent"), true)]
    #[case(Some(","), true)]
    #[case(Some("\"Accept-Encoding\""), true)]
    fn vary_cases(#[case] header: Option<&str>, #[case] expect_violation: bool) {
        let rule = VaryHeaderValid;
        let tx = match header {
            Some(h) => {
                crate::test_helpers::make_test_transaction_with_response(200, &[("vary", h)])
            }
            None => crate::test_helpers::make_test_transaction_with_response(200, &[]),
        };

        let config = crate::test_helpers::make_test_config_with_severity(rule.id(), "warn");

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        );
        if expect_violation {
            assert!(v.is_some(), "expected violation for header={:?}", header);
        } else {
            assert!(
                v.is_none(),
                "unexpected violation for header={:?}: {:?}",
                header,
                v
            );
        }
    }

    #[test]
    fn multiple_header_fields_merged() {
        let rule = VaryHeaderValid;

        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("vary", "Accept-Encoding"), ("vary", "User-Agent")],
        );

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn star_combined_across_header_fields_is_allowed() {
        // RFC 9110's `#( "*" / field-name )` permits '*' alongside field-names,
        // including when split across multiple Vary field lines.
        let rule = VaryHeaderValid;

        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("vary", "*"), ("vary", "Accept-Encoding")],
        );

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn non_utf8_header_value_is_violation() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;
        let rule = VaryHeaderValid;

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        let bad = HeaderValue::from_bytes(&[0xff]).expect("should construct non-utf8 header");
        hm.insert("vary", bad);
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
        let msg = v.unwrap().message;
        assert!(msg.contains("non-UTF8"));
        Ok(())
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "vary_header_valid");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn scope_is_server() {
        let rule = VaryHeaderValid;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }

    #[test]
    fn no_response_returns_none() {
        let rule = VaryHeaderValid;
        let tx = crate::test_helpers::make_test_transaction(); // request-only, no response
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }
}
