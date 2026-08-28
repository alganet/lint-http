// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct UserAgentTokenValid;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9110_10_1_5: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("10.1.5"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1.5",
    note: "`User-Agent = product *( RWS ( product / comment ) )`, a request context field; `product = token [\"/\" product-version]` is defined here once and `Server` shares it. The section's further requirements — no advertising or nonessential information in a product identifier, no needlessly fine-grained detail — are about intent and are not decidable from a field value",
};
const RFC_9110_5_6_5: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("5.6.5"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.5",
    note: "`comment = \"(\" *( ctext / quoted-pair / comment ) \")\"` — comments nest, and `ctext` admits `obs-text` but not the parentheses or the backslash",
};

impl Rule for UserAgentTokenValid {
    fn id(&self) -> &'static str {
        "user_agent_token_valid"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        // `User-Agent` is defined for requests only -- it lives under §10.1,
        // "Request Context Fields", and the field's own first sentence says
        // whose request it describes. A response carrying one is not this
        // rule's subject: there is no sentence giving the field a meaning in
        // that direction, so there is nothing for a grammar finding to mean.
        // This is the mirror of the argument `Server` carries next door, where
        // the same production is response-only.
        // cite(RFC 9110 § 10.1.5): "The "User-Agent" header field contains information about the user agent originating the request"
        crate::rules::RuleScope::Client
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
            // `User-Agent` and `Server` are one production, and RFC 9110 defines
            // `product` once — under this field — for both. The grammar walk lives
            // in the shared helper so the two fields cannot be validated by two
            // readings of the same sentence.
            // cite(RFC 9110 § 10.1.5): "The User-Agent field value consists of one or more product identifiers, each followed by zero or more comments (Section 5.6.5), which together identify the user agent software and its significant subproducts."
            //
            // What §10.1.5 asks of a product identifier beyond its grammar, it asks
            // about intent, and the octets do not carry that: whether a token is
            // "advertising or other nonessential information", whether the string
            // after the slash is a version, whether the detail is "needlessly"
            // fine-grained. The first of the three is a MUST NOT and is undecidable
            // all the same, so none of them is approximated here with a length
            // limit or a vocabulary -- the rule enforces the production and says in
            // its description that the rest is out of reach.
            // cite(RFC 9110 § 10.1.5): "A sender SHOULD limit generated product identifiers to what is necessary to identify the product; a sender MUST NOT generate advertising or other nonessential information within the product identifier."
            // cite(RFC 9110 § 10.1.5): "A sender SHOULD NOT generate information in product-version that is not a version identifier"
            // cite(RFC 9110 § 10.1.5): "A user agent SHOULD NOT generate a User-Agent header field containing needlessly fine-grained detail and SHOULD limit the addition of subproducts by third parties."
            //
            // The request trailer section is deliberately not walked. §10.1.5 puts
            // the field in a request and says nothing about trailers, which makes a
            // `User-Agent` trailer a violation of the sentence below rather than a
            // value for this rule to grammar-check; the trailer rules own it.
            // cite(RFC 9110 § 6.5.1): "A sender MUST NOT generate a trailer field unless the sender knows the corresponding header field name's definition permits the field to be sent in trailers."
            //
            // Each field line is parsed on its own, and deliberately not joined
            // first. No alternative of `User-Agent` is a comma-separated list, so
            // the recombination the note in §5.5 assumes does not apply here and the
            // comma a recipient would insert is not a `tchar` -- joining would turn
            // a second field line into a grammar finding, which blames the wrong
            // sentence. The second line is a violation of §5.3 as a whole message,
            // which `singleton_fields_not_repeated` owns and reports.
            // cite(RFC 9110 § 5.3): "a sender MUST NOT generate multiple field lines with the same name in a message (whether in the headers or trailers)"
            for hv in tx.request.headers.get_all("user-agent").iter() {
                // The raw octets, not `to_str()`: `ctext` admits `obs-text`, so a
                // conforming value need not be visible US-ASCII and the decode would
                // reject the field before the grammar could accept it.
                // cite(RFC 9110 § 5.5): "A recipient SHOULD treat other allowed octets in field content (i.e., obs-text) as opaque data."
                if let Err(e) = crate::helpers::product::validate_product_list(hv.as_bytes()) {
                    return Some(
                        self.violation(ctx.severity, format!("Invalid User-Agent header: {}", e)),
                    );
                }
            }

            None
        };
        Vec::from_iter(finding())
    }

    fn description(&self) -> &'static str {
        "Validate a `User-Agent` request header against `User-Agent = product *( RWS ( product / comment ) )`. Each product is a `token` with an optional `/`-separated version token; parenthesized comments may nest and may hold a `quoted-pair`, but a comment can only follow a product, so a value that opens with one — or holds nothing else — does not match the grammar. Required whitespace between elements is enforced, and `obs-text` is accepted inside a comment, where `ctext` allows it, and nowhere else. What §10.1.5 asks beyond the grammar — that a product identifier carry no advertising or other nonessential information, and no needlessly fine-grained detail — is a question about intent that the octets cannot answer, and is not checked."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_9110_10_1_5, RFC_9110_5_6_5]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "GET / HTTP/1.1\nHost: example.org\nUser-Agent: curl/7.68.0",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("the example RFC 9110 prints for the field"),
                snippet: "GET / HTTP/1.1\nHost: example.org\nUser-Agent: CERN-LineMode/2.15 libwww/2.17b3",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("comments following a product"),
                snippet: "GET / HTTP/1.1\nHost: example.org\nUser-Agent: Mozilla/5.0 (compatible; Bot/1.0; +http://example.com)",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("no leading product identifier"),
                snippet: "GET / HTTP/1.1\nHost: example.org\nUser-Agent: /1.0",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("a comment before the first product"),
                snippet: "GET / HTTP/1.1\nHost: example.org\nUser-Agent: (compatible; Bot/1.0) Mozilla/5.0",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("illegal character in the product token"),
                snippet: "GET / HTTP/1.1\nHost: example.org\nUser-Agent: Bad@UA/1.0",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("no whitespace between the product and the comment"),
                snippet: "GET / HTTP/1.1\nHost: example.org\nUser-Agent: Mozilla/5.0(Windows)",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("unterminated comment"),
                snippet: "GET / HTTP/1.1\nHost: example.org\nUser-Agent: Mozilla/5.0 (unbalanced comment",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &UserAgentTokenValid;

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;
    use rstest::rstest;

    #[rstest]
    #[case(Some("curl/7.68.0"), false)]
    #[case(Some("gzip"), false)]
    #[case(Some("Mozilla/5.0 (compatible; Bot/1.0; +http://example.com)"), false)]
    #[case(Some("Agent/1.0 AnotherOne/2.0"), false)]
    // `!` is a `tchar`, so this is two products separated by RWS and it
    // conforms. It was published as a Bad example on the strength of reading
    // like one, three lines below this case saying it is not.
    #[case(Some("Bad UA!"), false)]
    #[case(Some("/1.0"), true)]
    #[case(Some("Agent/"), true)]
    #[case(Some("Agent/1.0/extra"), true)]
    #[case(None, false)]
    fn check_user_agent_request(
        #[case] ua: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = UserAgentTokenValid;
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["user_agent_token_valid"]);

        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(v) = ua {
            tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[("user-agent", v)]);
        }

        let v = crate::test_helpers::run_rule(
            &rule,
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
    fn user_agent_product_and_version_invalid_chars_are_reported() -> anyhow::Result<()> {
        let rule = UserAgentTokenValid;
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["user_agent_token_valid"]);

        // invalid character in product
        let mut tx1 = crate::test_helpers::make_test_transaction();
        tx1.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("user-agent", "A@gen/1.0")]);
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx1,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .is_some());

        // invalid character in version
        let mut tx2 = crate::test_helpers::make_test_transaction();
        tx2.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("user-agent", "Agent/1@0")]);
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx2,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .is_some());

        Ok(())
    }

    #[test]
    fn multiple_user_agent_fields_are_checked() -> anyhow::Result<()> {
        let rule = UserAgentTokenValid;
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["user_agent_token_valid"]);

        // one good and one bad header -> violation
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[("user-agent", "curl/7.68.0")]);
        hm.append("user-agent", HeaderValue::from_static("Bad@UA/1.0"));
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = hm;
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .is_some());

        Ok(())
    }

    /// An `obs-text` octet is reported for where it sits, not for failing to
    /// decode: `ctext` admits %x80-FF and `tchar` does not, so the finding has
    /// to name the production, not the encoding.
    #[test]
    fn obs_text_outside_a_comment_is_reported_as_a_grammar_fault() -> anyhow::Result<()> {
        let rule = UserAgentTokenValid;
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["user_agent_token_valid"]);

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        hm.insert("user-agent", HeaderValue::from_bytes(b"\xff").unwrap());
        tx.request.headers = hm;

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        let violation = v.expect("0xFF is not a tchar");
        assert!(
            violation
                .message
                .contains("does not begin with a product identifier"),
            "{}",
            violation.message
        );
        Ok(())
    }

    /// The same octet inside a comment is `ctext`, and the value conforms.
    #[test]
    fn obs_text_inside_a_comment_is_accepted() -> anyhow::Result<()> {
        let rule = UserAgentTokenValid;
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["user_agent_token_valid"]);

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        hm.insert(
            "user-agent",
            HeaderValue::from_bytes(b"Mozilla/5.0 (U\xdcnix)").unwrap(),
        );
        tx.request.headers = hm;

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none(), "{v:?}");
        Ok(())
    }

    /// `User-Agent` is a request context field, so a response carrying one is
    /// not this rule's subject however malformed the value is. The request in
    /// this transaction is deliberately left without the field, so the only
    /// thing that could produce a finding is the response.
    #[test]
    fn a_response_user_agent_is_not_this_rules_subject() -> anyhow::Result<()> {
        let rule = UserAgentTokenValid;
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["user_agent_token_valid"]);

        for value in ["/1.0", "(compatible)", "Bad@UA/1.0"] {
            let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
            tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[]);
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[("user-agent", value)]);

            let v = crate::test_helpers::run_rule(
                &rule,
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            );
            assert!(v.is_none(), "{value}: {v:?}");
        }
        Ok(())
    }

    /// RWS separates elements, and what follows it has to be a product or a
    /// comment; a `/` there begins neither.
    #[test]
    fn a_slash_where_an_element_is_due_is_reported() -> anyhow::Result<()> {
        let rule = UserAgentTokenValid;
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["user_agent_token_valid"]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("user-agent", "Agent  /1.0")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        if let Some(violation) = v {
            assert!(
                violation
                    .message
                    .contains("expected a product identifier, found '/'"),
                "{}",
                violation.message
            );
        }
        Ok(())
    }

    #[test]
    fn invalid_char_messages_include_char() -> anyhow::Result<()> {
        let rule = UserAgentTokenValid;
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["user_agent_token_valid"]);

        let mut tx1 = crate::test_helpers::make_test_transaction();
        tx1.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("user-agent", "A@gen/1.0")]);
        let v1 = crate::test_helpers::run_rule(
            &rule,
            &tx1,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v1.is_some());
        if let Some(violation) = v1 {
            assert!(violation.message.contains("@"));
        }

        let mut tx2 = crate::test_helpers::make_test_transaction();
        tx2.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("user-agent", "Agent/1@0")]);
        let v2 = crate::test_helpers::run_rule(
            &rule,
            &tx2,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v2.is_some());
        if let Some(violation) = v2 {
            assert!(violation.message.contains("@"));
        }
        Ok(())
    }

    #[test]
    fn user_agent_only_comments_is_reported() -> anyhow::Result<()> {
        let rule = UserAgentTokenValid;
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["user_agent_token_valid"]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "user-agent",
            "(compatible; something)",
        )]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        if let Some(violation) = v {
            assert!(
                violation
                    .message
                    .contains("does not begin with a product identifier"),
                "{}",
                violation.message
            );
        }
        Ok(())
    }

    #[test]
    fn user_agent_unmatched_parentheses_is_reported() -> anyhow::Result<()> {
        let rule = UserAgentTokenValid;
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["user_agent_token_valid"]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("user-agent", "Agent (unclosed")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        let violation = v.expect("an unterminated comment does not match the grammar");
        assert!(
            violation
                .message
                .contains("unterminated parenthesized comment"),
            "{}",
            violation.message
        );
        Ok(())
    }

    /// §5.6.4 gives the backslash its meaning inside a `quoted-string` or a
    /// `comment` and nowhere else, so outside one it is an ordinary octet that
    /// is not a `tchar` — and it does not open a comment on the way past. The
    /// finding names the product token, not an unbalanced parenthesis.
    #[test]
    fn user_agent_escaped_parentheses_do_not_become_comments() -> anyhow::Result<()> {
        let rule = UserAgentTokenValid;
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["user_agent_token_valid"]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("user-agent", "Agent\\(1.0\\)")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        let violation = v.expect("a backslash is not a tchar");
        assert!(
            violation
                .message
                .contains("product token contains invalid character: '\\'"),
            "{}",
            violation.message
        );
        Ok(())
    }

    #[test]
    fn message_and_id() {
        let rule = UserAgentTokenValid;
        assert_eq!(rule.id(), "user_agent_token_valid");
        assert_eq!(rule.scope(), crate::rules::RuleScope::Client);
    }

    #[test]
    fn published_examples_are_judged_the_way_they_are_labelled() {
        use crate::rules::{Compliance, Rule as _};
        let rule = UserAgentTokenValid;
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["user_agent_token_valid"]);

        let mut saw_a_finding = false;
        for ex in rule.examples() {
            let mut lines = ex.snippet.lines();
            let start = lines.next().expect("an example has a start line");
            // The rule is request-scoped, so every example is a request and the
            // headers below go on the request. Were a response snippet ever
            // added, discarding its status line would file the fields on the
            // request instead and the guard would pass on a value the rule
            // never sees.
            assert!(
                !start.starts_with("HTTP/"),
                "a response-shaped example cannot be checked by this guard: {start:?}"
            );

            let pairs: Vec<(&str, &str)> = lines
                .filter(|l| !l.trim().is_empty())
                .map(|l| {
                    l.split_once(": ")
                        .unwrap_or_else(|| panic!("not a header line: {l:?}"))
                })
                .collect();

            let mut tx = crate::test_helpers::make_test_transaction();
            tx.request.headers = crate::test_helpers::make_headers_from_pairs(&pairs);
            let found = crate::test_helpers::run_rule(
                &rule,
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            );

            match ex.compliance {
                Compliance::Compliant => assert!(
                    found.is_none(),
                    "rule rejects its Compliant example {:?}: {found:?}",
                    ex.snippet
                ),
                Compliance::NonCompliant => {
                    found.unwrap_or_else(|| {
                        panic!("rule accepts its NonCompliant example {:?}", ex.snippet)
                    });
                    saw_a_finding = true;
                }
            }
        }
        assert!(saw_a_finding, "no published example produced a finding");
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["user_agent_token_valid"]);
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
