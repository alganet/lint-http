// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::content_coding::{
    CONTENT_CODING_REDUNDANT, CONTENT_CODING_WILDCARD_FORBIDDEN, RFC_9110_12_5_3, RFC_9110_8_4,
};
use crate::violations::token::{
    token_character, RFC_9110_5_6_2, TOKEN_CHARACTER_FORBIDDEN, TOKEN_EMPTY,
    TOKEN_WHITESPACE_OR_CONTROL_FORBIDDEN,
};
use crate::violations::ViolationDef;

pub struct ContentEncodingAndTypeConsistent;

/// The `token` pair, and it is the same field
/// [`content_encoding_registered`](crate::rules::content_encoding_registered)
/// reads, asked a different question.
///
/// That rule takes `Content-Encoding` and `Accept-Encoding` for which coding
/// *names* exist; this takes them for which were applied twice, and the octet
/// no `tchar` admits comes out with the same id from both. The two even say it
/// in the same words — one message written twice in two files that share no
/// code — so here the id retires a duplication the prose still carries.
///
/// **Nothing this rule is named for changed.** A coding repeated, a `*` where
/// none is defined, a member whose coding half is missing, and the field on a
/// response with no content are all statements about what a *well-formed* list
/// means, and they keep the rule's severity because no production is broken by
/// any of them.
static DECLARED: &[&ViolationDef] = &[
    &TOKEN_CHARACTER_FORBIDDEN,
    &TOKEN_WHITESPACE_OR_CONTROL_FORBIDDEN,
    &TOKEN_EMPTY,
    &CONTENT_CODING_WILDCARD_FORBIDDEN,
    &CONTENT_CODING_REDUNDANT,
];

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9110_15_4_5: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("15.4.5"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.5",
    note: "Why a 304 should not carry Content-Encoding: a sender SHOULD NOT include representation metadata beyond the listed fields. (This reference previously pointed at §8.3, which is Content-Type, not message-body rules.) The 1xx and 204 cases have no such sentence and are inferred",
};

impl RuleMeta for ContentEncodingAndTypeConsistent {
    fn id(&self) -> &'static str {
        "content_encoding_and_type_consistent"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
severity = "warn"
"#
    }

    fn description(&self) -> &'static str {
        "Validate `Content-Encoding` header members for common correctness issues: members must be valid `token`s, a wildcard `*` is rejected (it belongs to `Accept-Encoding`), and a coding repeated within the field is flagged.\n\nResponses that carry no content (1xx, 204, 304) are flagged for sending `Content-Encoding` at all. For 304 this follows RFC 9110 §15.4.5, which tells a sender not to include representation metadata beyond a listed set; for 1xx and 204 it is this rule's inference that a coding describing absent content is a misconfiguration.\n\nRepeating a coding is likewise a judgement call rather than a conformance failure — `gzip, gzip` legitimately expresses gzip applied twice — but in practice it usually means two layers each added the header.\n\n**Note:** despite the rule's name, no `Content-Type` consistency check is performed; the rule inspects `Content-Encoding` only.\n\n**The value is read as octets and over the whole field section.** Every character of a `token` is visible US-ASCII, so an `obs-text` octet in a coding name is reported for what it is — a character the production does not admit, named as the byte it is — rather than as a verdict about the field's encoding. It used to be the second: a value the string reader refused was reported as *not valid UTF-8*, which is a claim about the whole value where the defect is one character of one member. The lines of a section are joined first, because `#content-coding` makes them one list."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_9110_8_4,
            RFC_9110_12_5_3,
            RFC_9110_15_4_5,
            RFC_9110_5_6_2,
        ]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nContent-Encoding: gzip, br\nContent-Type: application/json; charset=utf-8\n\n...compressed JSON body...",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(duplicate coding)"),
                snippet: "HTTP/1.1 200 OK\nContent-Encoding: gzip, gzip\nContent-Type: application/json\n\n...compressed JSON body...",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(Content-Encoding on no-body response)"),
                snippet: "HTTP/1.1 204 No Content\nContent-Encoding: gzip",
            },
        ]
    }
}

impl Rule for ContentEncodingAndTypeConsistent {
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
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
            // Helper to validate a Content-Encoding-like header value (comma-separated members).
            // This helper validates members in `val` and updates `seen` with found codings so duplicates
            // across multiple header fields can be detected when `seen` is shared between calls.
            let check_encoding_header = |hdr_name: &str,
                                         val: &str,
                                         seen: &mut std::collections::HashSet<String>|
             -> Option<Violation> {
                // cite(RFC 9110 § 8.4): "Content-Encoding = #content-coding"
                for part in crate::helpers::list::list_members(val) {
                    // Strip parameters (not expected for Content-Encoding but be forgiving)
                    let token = part.split(';').next().unwrap().trim();
                    // **Not `list_member_empty`, though the message says
                    // "member".** The walk above drops the list's empty members
                    // before this sees them, so what reaches here is a member
                    // that is *present* and whose coding half is missing --
                    // `;q=1` and the like. `content-coding = token` and `1*tchar`
                    // has a floor, so the name that is not there is the token's
                    // own defect: the mirror rule on `Transfer-Encoding` reached
                    // the same id from the same member shape.
                    if token.is_empty() {
                        return Some(ctx.report_with(
                            &TOKEN_EMPTY,
                            format!("{} header contains empty member", hdr_name),
                        ));
                    }
                    if token == "*" && hdr_name.eq_ignore_ascii_case("Content-Encoding") {
                        return Some(ctx.report_with(
                            &CONTENT_CODING_WILDCARD_FORBIDDEN,
                            format!("Wildcard '*' is not valid in {} header", hdr_name),
                        ));
                    }
                    if let Some(c) = crate::helpers::token::find_invalid_token_char(token) {
                        // Rendered rather than written through: the value is
                        // read as octets, so what stopped the scan may be an
                        // `obs-text` byte a recipient is told to treat as
                        // opaque -- and `0xE9` is what that byte is, where `é`
                        // is a reading of it.
                        return Some(ctx.report_with(
                            token_character(c),
                            format!(
                                "Invalid token {} in {} header",
                                crate::helpers::shown::describe_char(c),
                                hdr_name
                            ),
                        ));
                    }
                    // Repeating a coding is not forbidden anywhere: §8.4 has the sender list
                    // the codings "in the order in which they were applied", which makes
                    // `gzip, gzip` a well-formed way to say gzip was applied twice. Flagging
                    // it is this rule's judgement that a repeat is far more often a
                    // configuration accident (two layers each adding the header) than a
                    // deliberate double-encoding -- and the document's own aside about a
                    // coding listed a second time is what the entry quotes.
                    let key = token.to_ascii_lowercase();
                    if !seen.insert(key.clone()) {
                        return Some(ctx.report_with(
                            &CONTENT_CODING_REDUNDANT,
                            format!("Duplicate content-coding '{}' in {} header", key, hdr_name),
                        ));
                    }
                }
                None
            };

            // The lines of a section are one list, read as octets. `to_str`
            // refuses everything outside visible US-ASCII, which folded an
            // `obs-text` octet in a coding name into a verdict about the
            // field's encoding -- a claim about the whole value where the
            // defect is one character of one member, and one this rule already
            // had an id for. Reading the octets is what lets that id answer.
            {
                let mut seen = std::collections::HashSet::new();
                if let Some(val) = crate::helpers::headers::combined_field_value_as_written(
                    &tx.request.headers,
                    "content-encoding",
                ) {
                    if let Some(v) = check_encoding_header("Content-Encoding", &val, &mut seen) {
                        return Some(v);
                    }
                }
            }

            // Check response Content-Encoding header(s)
            if let Some(resp) = &tx.response {
                // No-body statuses should not carry Content-Encoding
                let status = resp.status;
                // These three statuses reach the same verdict by different routes, and only
                // one of them is a stated requirement.
                //
                // 304 is the grounded case: Content-Encoding is representation metadata,
                // it is not among the fields a 304 is told to send, and it does not guide
                // cache updates — so the sentence below covers it directly (a SHOULD NOT,
                // which is why the message says "should not").
                // cite(RFC 9110 § 15.4.5): "a sender SHOULD NOT generate representation metadata other than the above listed fields unless said metadata exists for the purpose of guiding cache updates"
                //
                // 1xx and 204 are the linter's inference: those responses carry no content,
                // so a coding describing how the content was encoded has nothing to
                // describe. No sentence says this, and for 204 the spec arguably leans the
                // other way — §15.3.5 has metadata "refer to the target resource and its
                // selected representation", which would make representation metadata
                // meaningful even with no content to send. Kept because a Content-Encoding
                // on a bodyless response is far more often a misconfiguration than a
                // deliberate description of a representation the client is not receiving;
                // recorded as the possible false positive it is.
                let is_no_body_status =
                    (100..200).contains(&status) || status == 204 || status == 304;
                if is_no_body_status && resp.headers.contains_key("content-encoding") {
                    return Some(self.cited(&RFC_9110_15_4_5, ctx.severity, format!(
                            "Response {} carries no content, so it should not send Content-Encoding",
                            status
                        )));
                }

                let mut seen = std::collections::HashSet::new();
                if let Some(val) = crate::helpers::headers::combined_field_value_as_written(
                    &resp.headers,
                    "content-encoding",
                ) {
                    if let Some(v) = check_encoding_header("Content-Encoding", &val, &mut seen) {
                        return Some(v);
                    }
                }
            }

            None
        };
        Vec::from_iter(finding())
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ContentEncodingAndTypeConsistent;

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;
    use rstest::rstest;

    /// The six fields spelling `content-coding = token` now answer for it with
    /// one pair of ids, and the last two arrive from the rules that ask the
    /// fields a *different* question. Asserted against the registry rule, which
    /// reads the same field for which names exist and shares no code with this
    /// one.
    #[test]
    fn a_coding_name_is_a_token_whatever_the_rule_is_asking() {
        let judge = |rule: &dyn crate::rules::Rule,
                     cfg: &crate::config::Config,
                     value: &str|
         -> Violation {
            let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[("content-encoding", value)]);
            crate::test_helpers::run_rule(
                rule,
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                cfg,
            )
            .unwrap_or_else(|| panic!("{}: {value}", rule.id()))
        };

        // The neighbour reads an operator's list of names, so it needs one; the
        // octet below is refused before any name is looked up.
        let mut registered_cfg = crate::config::Config::default();
        registered_cfg.rules.insert(
            "content_encoding_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![toml::Value::String("gzip".into())]),
                );
                t
            }),
        );

        let here = judge(
            &ContentEncodingAndTypeConsistent,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "content_encoding_and_type_consistent",
            ]),
            "x@bad",
        );
        let registered = judge(
            &crate::rules::content_encoding_registered::ContentEncodingRegistered,
            &registered_cfg,
            "x@bad",
        );
        assert_eq!(here.violation, "token_character_forbidden");
        assert_eq!(registered.violation, "token_character_forbidden");
        // And the sentence is *the same one*, written twice in two files that
        // share no code -- retired by the id and left as two strings for a
        // later dedup pass to collapse.
        assert_eq!(here.message, registered.message);
    }

    /// Every finding here names the production the failing part is written in.
    /// A coding repeated and a wildcard where none is defined are both
    /// well-formed tokens in a well-formed list, so their ids are the
    /// `content_coding` subject's rather than this field's — and a member that
    /// is nothing but a parameter has no name at all, which is the `token`
    /// floor and the id the mirror rule reaches from the same shape.
    #[rstest]
    #[case::duplicate("gzip, gzip", "content_coding_redundant")]
    #[case::wildcard("*", "content_coding_wildcard_forbidden")]
    #[case::no_coding("gzip, ;q=1", "token_empty")]
    #[case::bad_octet("x@bad", "token_character_forbidden")]
    #[case::space_inside("g zip", "token_whitespace_or_control_forbidden")]
    fn the_grammars_defects_are_the_grammars(#[case] value: &str, #[case] violation: &str) {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-encoding", value)]);
        let finding = crate::test_helpers::run_rule(
            &ContentEncodingAndTypeConsistent,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "content_encoding_and_type_consistent",
            ]),
        )
        .unwrap_or_else(|| panic!("expected a finding for {value:?}"));
        assert_eq!(finding.violation, violation, "for {value:?}");
    }

    #[rstest]
    #[case(Some("gzip"), 200, false)]
    #[case(Some("gzip, br"), 200, false)]
    #[case(Some("gzip, gzip"), 200, true)]
    #[case(Some("x@bad"), 200, true)]
    #[case(Some("gzip"), 204, true)]
    #[case(Some("gzip, "), 200, false)]
    #[case(None, 200, false)]
    fn response_cases(
        #[case] ce: Option<&str>,
        #[case] status: u16,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = ContentEncodingAndTypeConsistent;

        let mut tx = crate::test_helpers::make_test_transaction_with_response(status, &[]);
        if let Some(v) = ce {
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[("content-encoding", v)]);
        }

        let violation = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        if expect_violation {
            assert!(violation.is_some());
        } else {
            assert!(violation.is_none());
        }
        Ok(())
    }

    #[rstest]
    #[case(Some("gzip, gzip"), true)]
    #[case(Some("x@bad"), true)]
    #[case(Some("gzip"), false)]
    #[case(None, false)]
    fn request_cases(
        #[case] ce: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = ContentEncodingAndTypeConsistent;

        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(v) = ce {
            tx.request.headers =
                crate::test_helpers::make_headers_from_pairs(&[("content-encoding", v)]);
        }

        let violation = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        if expect_violation {
            assert!(violation.is_some());
        } else {
            assert!(violation.is_none());
        }
        Ok(())
    }

    #[test]
    fn an_obs_text_octet_is_a_token_defect_not_an_encoding_verdict() {
        let rule = ContentEncodingAndTypeConsistent;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[]),

            body_length: None,
            trailers: None,
        });
        tx.response.as_mut().unwrap().headers.append(
            "content-encoding",
            HeaderValue::from_bytes(&[0xff]).unwrap(),
        );

        let violation = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        let v = violation.expect("a finding");
        assert_eq!(v.violation, "token_character_forbidden");
        assert_eq!(v.message, "Invalid token 0xFF in Content-Encoding header");
    }
    #[test]
    fn request_trailing_comma_accepted() {
        let rule = ContentEncodingAndTypeConsistent;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-encoding", "gzip, ")]);
        let violation = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(violation.is_none());
    }
    #[test]
    fn content_encoding_wildcard_reports_violation() -> anyhow::Result<()> {
        let rule = ContentEncodingAndTypeConsistent;

        // request header with '*'
        let mut tx1 = crate::test_helpers::make_test_transaction();
        tx1.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-encoding", "*")]);
        let v1 = crate::test_helpers::run_rule(
            &rule,
            &tx1,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v1.is_some());

        // response header with '*'
        let mut tx2 = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx2.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-encoding", "*")]);
        let v2 = crate::test_helpers::run_rule(
            &rule,
            &tx2,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v2.is_some());

        Ok(())
    }

    #[test]
    fn duplicate_across_multiple_header_fields_reports_violation_response() -> anyhow::Result<()> {
        let rule = ContentEncodingAndTypeConsistent;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        // Two header fields both mentioning 'gzip' should be treated as duplicate
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[("content-encoding", "gzip")]);
        hm.append("content-encoding", HeaderValue::from_static("gzip"));
        tx.response.as_mut().unwrap().headers = hm;

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
    fn duplicate_across_multiple_header_fields_reports_violation_request() -> anyhow::Result<()> {
        let rule = ContentEncodingAndTypeConsistent;
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[("content-encoding", "gzip")]);
        hm.append("content-encoding", HeaderValue::from_static("gzip"));
        tx.request.headers = hm;

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
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "content_encoding_and_type_consistent",
        ]);
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn scope_is_both() {
        let rule = ContentEncodingAndTypeConsistent;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }

    #[test]
    fn empty_list_member_reports_violation() -> anyhow::Result<()> {
        let rule = ContentEncodingAndTypeConsistent;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        // include a semicolon-only member (";") between commas which will leave a non-empty
        // part but its token before the ';' is empty -> triggers the rule
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-encoding", "gzip,;,br")]);
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
    fn a_requests_obs_text_octet_is_the_same_token_defect() -> anyhow::Result<()> {
        let rule = ContentEncodingAndTypeConsistent;
        let mut tx = crate::test_helpers::make_test_transaction();
        use hyper::header::HeaderValue;
        tx.request
            .headers
            .append("content-encoding", HeaderValue::from_bytes(&[0xff])?);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        let v = v.expect("a finding");
        assert_eq!(v.violation, "token_character_forbidden");
        assert_eq!(v.message, "Invalid token 0xFF in Content-Encoding header");
        Ok(())
    }

    #[test]
    fn response_no_body_status_with_encoding_reports_violation() -> anyhow::Result<()> {
        let rule = ContentEncodingAndTypeConsistent;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(100, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-encoding", "gzip")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        let v = v.unwrap();
        assert!(v.message.contains("should not send Content-Encoding"));
        Ok(())
    }
}
