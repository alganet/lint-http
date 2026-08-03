// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageAcceptAndContentTypeNegotiation;

impl Rule for MessageAcceptAndContentTypeNegotiation {
    fn id(&self) -> &'static str {
        "message_accept_and_content_type_negotiation"
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
        // Only check when request has Accept and response has Content-Type
        // The whole Accept field, not its first line. `Accept` is a list field,
        // so a sender may spread its members over several field lines and a
        // recipient recombines them into one comma-separated list — reading
        // only the first announced that a response was unacceptable to a client
        // that had listed it on the second.
        let accept = crate::helpers::headers::get_all_header_values(&tx.request.headers, "accept");
        let accept = accept.as_deref();
        let resp = tx.response.as_ref()?;

        // One Content-Type, or no opinion. With two field lines there is no
        // single media type the response sent: RFC 9110 §8.3 says recipients
        // differ over which member of a duplicated Content-Type they act on, so
        // whether the client got something it asked for depends on which one it
        // reads. Judging the first would be a guess dressed as a finding. The
        // duplication itself is `message_content_type_well_formed`'s to report.
        let mut cts = resp.headers.get_all("content-type").iter();
        let content_type = cts.next()?.to_str().ok()?;
        if cts.next().is_some() {
            return None;
        }

        // If server already returned 406 Not Acceptable, don't flag
        // cite(RFC 9110 § 15.5.7): "The 406 (Not Acceptable) status code indicates that the target resource does not have a current representation that would be acceptable to the user agent"
        if resp.status == 406 {
            return None;
        }

        let accept = accept?;

        // Parse response Content-Type media-type
        let parsed_ct = match crate::helpers::headers::parse_media_type(content_type) {
            Ok(p) => p,
            Err(_) => return None, // content-type parsing is handled by other rules
        };

        // Iterate Accept members and see if any non-zero-q member matches the response Content-Type
        let mut matched = false;
        // Whether the header expressed a preference this rule could read at
        // all. A finding here says the response is not among the media types
        // the client asked for, and that is a claim about what the client
        // asked for — so it needs at least one member that is a `media-range`.
        let mut readable_preference = false;
        // Quote-aware, because a comma inside a quoted parameter value is not a
        // list separator. A raw `split(',')` cut such a value apart and read the
        // pieces as members of their own, so `text/plain;foo="a,image/png,b"` —
        // which accepts `text/plain` and nothing else — was read as accepting
        // `image/png` too, and a response nobody asked for went unreported.
        for member in crate::helpers::headers::split_commas_respecting_quotes(accept) {
            let member = member.trim();
            if member.is_empty() {
                continue;
            }
            // Quote-aware for the same reason the comma split is: a `;` inside
            // a quoted parameter value does not start a parameter. A raw
            // `split(';')` read the pieces as parameters, so a `q=0` sitting
            // inside some other value — `foo="a;q=0;b=1"` — was taken for a
            // weight and the member declared unacceptable, when the member has
            // no weight at all and accepts everything it names.
            let mut parts =
                crate::helpers::headers::split_semicolons_respecting_quotes(member).into_iter();
            let media = match parts.next() {
                Some(m) => m,
                None => continue,
            };
            // `media-range` is one of three shapes, and a bare `*` is none of
            // them: the asterisk groups media *types* into ranges, so it stands
            // for a whole type or a whole subtype, never for the pair. A
            // wildcard type with a concrete subtype — `*/json` — is not a range
            // either, though it parses as a media-type.
            let range = match crate::helpers::headers::parse_media_type(media) {
                Ok(mr) if mr.type_ != "*" || mr.subtype == "*" => mr,
                _ => continue,
            };
            readable_preference = true;

            // find q param if present
            let mut qval: Option<&str> = None;
            for p in parts {
                let p = p.trim();
                let mut kv = p.splitn(2, '=');
                let k = kv.next().unwrap().trim();
                if k.eq_ignore_ascii_case("q") {
                    if let Some(v) = kv.next() {
                        qval = Some(v.trim());
                    }
                }
            }

            // A weight of zero is a refusal, and that is the one thing a weight
            // tells this rule. But it says so only when it *is* a weight: the
            // meaning belongs to `qvalue`, and `q=-1` is not one. A raw
            // `parse::<f32>()` read that as less than zero and refused the
            // member on the strength of a value the grammar does not admit,
            // which turned a malformed Accept into a finding about the
            // response. Anything that is not a qvalue leaves the member at its
            // default weight of 1, which is also what a member with no `q` gets.
            if let Some(q) = qval {
                if crate::helpers::headers::valid_qvalue(q)
                    && q.parse::<f32>().is_ok_and(|n| n == 0.0)
                {
                    continue;
                }
            }

            // The three shapes, matched by what each one ranges over: `*/*`
            // covers every media type, `type/*` every subtype of its type, and
            // `type/subtype` only itself. The asterisks are compared literally
            // because they are literals; the type and subtype tokens are
            // compared without regard to case because they are case-insensitive.
            let type_matches =
                range.type_ == "*" || range.type_.eq_ignore_ascii_case(parsed_ct.type_);
            let subtype_matches =
                range.subtype == "*" || range.subtype.eq_ignore_ascii_case(parsed_ct.subtype);
            if type_matches && subtype_matches {
                matched = true;
                break;
            }
        }

        // No member was a media-range, so the header states no preference this
        // rule can read — `Accept: *`, `Accept: not-a-media-range`, or an empty
        // value. Saying the response "does not match" such a header would be a
        // claim about a preference nobody expressed, and it would name the
        // response for a defect that is in the request.
        // `message_accept_header_media_type_syntax` reports the malformed
        // header; this rule declines.
        if !readable_preference {
            return None;
        }

        if !matched {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!(
                    "Response Content-Type '{}' does not match request Accept header '{}', consider returning 406 Not Acceptable",
                    content_type, accept
                ),
            });
        }

        None
    }

    fn description(&self) -> &'static str {
        "Validate that a server response's `Content-Type` matches the client's `Accept` header when present. If the request provides an `Accept` header that does not allow the response media type (for example `Accept: application/json` but response `Content-Type: text/html`), the server should consider returning `406 Not Acceptable` or use a matching representation."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("12.5.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.1",
                note: "Accept (media ranges and q-values)",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("12.4.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-12.4.2",
                note: "Quality values (q parameter)",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("15.5.7"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5.7",
                note: "406 Not Acceptable",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "GET /resource HTTP/1.1\nAccept: application/json\n\nHTTP/1.1 200 OK\nContent-Type: application/json; charset=utf-8",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "GET /resource HTTP/1.1\nAccept: application/json\n\nHTTP/1.1 200 OK\nContent-Type: text/html; charset=utf-8",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &MessageAcceptAndContentTypeNegotiation;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(Some("application/json"), Some("application/json"), 200, false)]
    #[case(Some("application/json"), Some("text/html"), 200, true)]
    #[case(Some("text/*"), Some("text/html; charset=utf-8"), 200, false)]
    #[case(Some("*/*"), Some("image/png"), 200, false)]
    #[case(Some("application/json;q=0"), Some("application/json"), 200, true)]
    #[case(Some("application/json;q=0"), Some("application/json"), 406, false)]
    #[case(None, Some("application/json"), 200, false)]
    #[case(Some("application/json, text/html;q=0"), Some("text/html"), 200, true)]
    // A comma inside a quoted parameter value is not a list separator. This
    // header accepts `text/plain` and nothing else; reading the fragments as
    // members made it look like it accepted `image/png`.
    #[case(Some("text/plain;foo=\"a,image/png,b\""), Some("image/png"), 200, true)]
    // The real list is still split on the commas that are separators.
    #[case(
        Some("text/plain;foo=\"a,b\", image/png"),
        Some("image/png"),
        200,
        false
    )]
    // A `;` inside a quoted value does not start a parameter, so the `q=0` in
    // this member's `foo` value is not a weight and the member is acceptable.
    #[case(Some("text/html;foo=\"a;q=0;b=1\""), Some("text/html"), 200, false)]
    // A real weight of zero after a quoted value carrying one is still found.
    #[case(Some("text/html;foo=\"a;q=1\";q=0"), Some("text/html"), 200, true)]
    // The forms `qvalue` admits, at both ends of the range.
    #[case(Some("text/html;q=0"), Some("text/html"), 200, true)]
    #[case(Some("text/html;q=0.000"), Some("text/html"), 200, true)]
    #[case(Some("text/html;q=0.001"), Some("text/html"), 200, false)]
    #[case(Some("text/html;q=1"), Some("text/html"), 200, false)]
    // Not a `qvalue`, so not a weight. Refusing the member on the strength of
    // these would turn a malformed Accept into a finding about the response;
    // the member keeps the default weight of 1 instead.
    #[case(Some("text/html;q=-1"), Some("text/html"), 200, false)]
    #[case(Some("text/html;q=0.0001"), Some("text/html"), 200, false)]
    #[case(Some("text/html;q=1e-9"), Some("text/html"), 200, false)]
    #[case(Some("text/html;q=00"), Some("text/html"), 200, false)]
    fn negotiation_cases(
        #[case] accept: Option<&str>,
        #[case] content_type: Option<&str>,
        #[case] status: u16,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageAcceptAndContentTypeNegotiation;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_accept_and_content_type_negotiation",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(status, &[]);
        if let Some(a) = accept {
            tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[("accept", a)]);
        }
        if let Some(ct) = content_type {
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[("content-type", ct)]);
        }

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(
                v.is_some(),
                "expected violation for accept={:?} ct={:?}",
                accept,
                content_type
            );
        } else {
            assert!(v.is_none());
        }
        Ok(())
    }

    /// `Accept` is a list field, so its members may be spread over several
    /// field lines and are recombined into one list. Reading only the first
    /// announced that a response was unacceptable to a client that had asked
    /// for it on the second.
    #[rstest]
    #[case(&["application/json", "text/html"], "text/html", false)]
    #[case(&["application/json", "text/html"], "application/json", false)]
    #[case(&["application/json", "text/html"], "image/png", true)]
    fn every_accept_field_line_is_read(
        #[case] accepts: &[&str],
        #[case] content_type: &str,
        #[case] expect_violation: bool,
    ) {
        let rule = MessageAcceptAndContentTypeNegotiation;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let pairs: Vec<(&str, &str)> = accepts.iter().map(|a| ("accept", *a)).collect();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&pairs);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-type", content_type)]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert_eq!(
            v.is_some(),
            expect_violation,
            "{accepts:?} vs {content_type} -> {v:?}"
        );
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_accept_and_content_type_negotiation",
        ]);
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn message_and_id() {
        let rule = MessageAcceptAndContentTypeNegotiation;
        assert_eq!(rule.id(), "message_accept_and_content_type_negotiation");
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }

    #[test]
    fn invalid_response_content_type_parsing_is_ignored() {
        // If the response Content-Type cannot be parsed, the rule conservatively does nothing
        let rule = MessageAcceptAndContentTypeNegotiation;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_accept_and_content_type_negotiation",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("accept", "text/plain")]);
        // invalid content-type (no slash) -> parse_media_type should fail
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-type", "text")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    /// A finding here says the response is not among the media types the client
    /// asked for. When no member of Accept is a `media-range`, nobody asked for
    /// anything this rule can read, and the header — not the response — is the
    /// malformed thing. These used to be reported, under test names recording
    /// it as intended: an unreadable Accept produced a finding against a
    /// response that had done nothing wrong.
    #[rstest]
    #[case("not-a-media-range")]
    // A bare asterisk is not a `media-range`: the asterisk stands for a whole
    // type or a whole subtype, never for the pair.
    #[case("*")]
    // A wildcard type with a concrete subtype is not one either, though it
    // parses as a media-type.
    #[case("*/json")]
    // A zero-element list expresses no preference at all.
    #[case("")]
    #[case(",  ,")]
    fn an_unreadable_accept_is_not_a_finding_about_the_response(#[case] accept: &str) {
        let rule = MessageAcceptAndContentTypeNegotiation;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[("accept", accept)]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-type", "text/plain")]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none(), "Accept {accept:?} states no preference: {v:?}");
    }

    /// One readable member is enough to make the question meaningful, and the
    /// unreadable ones alongside it change nothing.
    #[test]
    fn a_readable_member_beside_an_unreadable_one_is_still_judged() {
        let rule = MessageAcceptAndContentTypeNegotiation;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "accept",
            "not-a-media-range, application/json",
        )]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-type", "text/plain")]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some(), "application/json is a real preference: {v:?}");
    }

    /// With two Content-Type lines there is no single media type the response
    /// sent — recipients differ over which one they act on — so whether the
    /// client got what it asked for depends on which it reads. The rule judged
    /// the first and reported, though the second is one the client accepts.
    #[test]
    fn two_content_type_lines_leave_the_question_unanswerable() {
        let rule = MessageAcceptAndContentTypeNegotiation;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("accept", "application/json")]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            ("content-type", "text/html"),
            ("content-type", "application/json"),
        ]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none(), "which media type applies is unknown: {v:?}");
    }

    #[test]
    fn invalid_q_value_is_ignored_and_does_not_make_member_unacceptable() {
        // If q value is malformed, we conservatively treat the member as acceptable unless q parses to 0
        let rule = MessageAcceptAndContentTypeNegotiation;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_accept_and_content_type_negotiation",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("accept", "text/plain;q=notnum")]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-type", "text/plain")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn empty_q_value_is_ignored_and_member_is_accepted() {
        // q= with empty RHS should not make member unacceptable
        let rule = MessageAcceptAndContentTypeNegotiation;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_accept_and_content_type_negotiation",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("accept", "application/json;q=")]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-type", "application/json")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn no_response_is_ignored() {
        let rule = MessageAcceptAndContentTypeNegotiation;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_accept_and_content_type_negotiation",
        ]);

        let tx = crate::test_helpers::make_test_transaction();
        // tx.response is None
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }
}
