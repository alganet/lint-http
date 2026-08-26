// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct HeaderFieldNamesTokenValid;

impl Rule for HeaderFieldNamesTokenValid {
    fn id(&self) -> &'static str {
        "header_field_names_token_valid"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        // The grammar is stated for fields, with no clause naming a direction or a
        // section, so every field the transaction carries is in scope.
        // cite(RFC 9110 § 5): "Fields are sent and received within the header and trailer sections of messages"
        crate::rules::RuleScope::Both
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;

        // All four, in wire order, from the shared walk. A trailer field name is
        // a field name, so the same grammar reaches it; a transaction the
        // upstream never answered has no response half; and which sections exist
        // at all is the framing's answer, not this rule's.
        // cite(RFC 9110 § 6.5): "Fields (Section 5) that are located within a "trailer section" are referred to as "trailer fields""
        for (section, headers) in crate::helpers::headers::transaction_field_sections(tx) {
            if let Some(v) = check_section(section, headers, &config) {
                return Some(v);
            }
        }

        None
    }

    fn description(&self) -> &'static str {
        "This rule validates that **field names** conform to the `token` grammar. Field names containing control characters, spaces, or other separator characters are invalid and can indicate protocol violations or injection attempts.\n\nThe rule flags field names that contain characters outside the allowed `tchar` set (letters, digits, and the following characters: ``! # $ % & ' * + - . ^ _ ` | ~``). One grammar governs every field section, so the request and response header sections are checked and so are their trailer sections when the message framing carried one.\n\nAn HTTP/1.1 field name that is not a `token` is rejected by the message parser before the linter sees it, so this check has teeth on HTTP/2 and HTTP/3: their field-name encodings can convey a `\"`, which the `token` grammar does not allow, and RFC 9113 §8.2.1 asks a recipient to validate the name against RFC 9110 §5.1 and treat a message carrying a prohibited character as malformed."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("5.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.1",
                note: "Field Names (field-name = token)",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("5.6.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.2",
                note: "Tokens (the tchar set the production expands to)",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("6.5"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-6.5",
                note: "Trailer Fields",
            },
            crate::rules::SpecRef {
                spec: "RFC 9113",
                section: Some("8.2.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9113.html#section-8.2.1",
                note: "Field Validity (HTTP/2 recipients validate names against §5.1)",
            },
            crate::rules::SpecRef {
                spec: "RFC 9114",
                section: Some("4.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9114.html#section-4.2",
                note: "HTTP Fields (HTTP/3 defers field-name properties to §5.1)",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "Host: example.com\nContent-Type: text/plain\nX-Custom-Header: v",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("HTTP/2 or HTTP/3, where the field-name encoding conveys a DQUOTE"),
                snippet: "x\"bad: v",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("Trailer section, governed by the same grammar"),
                snippet: "x\"checksum: abc123",
            },
        ]
    }
}

/// Walk one field section, reporting the first field name that is not a `token`.
fn check_section(
    section: &str,
    fields: &hyper::HeaderMap,
    config: &crate::rules::RuleConfig,
) -> Option<Violation> {
    for (k, _v) in fields.iter() {
        // The one check a § 5.1 validator still owes -- that the name is not
        // uppercase -- is not observable from this representation, and so is enforced
        // nowhere in this rule: the HTTP/1 parser folds case on the way in, and the
        // HTTP/2 and HTTP/3 decoders reject an uppercase name outright, so `as_str()`
        // has already been made lowercase by the time any rule reads it.
        // cite(RFC 9114 § 4.2): "A request or response containing uppercase characters in field names MUST be treated as malformed"
        if let Some(v) = check_header_name(section, k.as_str(), config) {
            return Some(v);
        }
    }
    None
}

// Extracted helper to make the message/violation formatting testable without needing
// to construct a `HeaderName` the HTTP/1 parser would reject.
//
// The check has teeth on the HTTP/2 and HTTP/3 legs. Their minimal field-name
// validation prohibits control characters, SP, uppercase and COLON, which leaves
// DQUOTE to the RFC 9110 § 5.1 check both specs ask a recipient to also perform.
// cite(RFC 9113 § 8.2.1): "HTTP/2 implementations SHOULD validate field names and values according to their definitions in Sections 5.1 and 5.5 of [HTTP], respectively, and treat messages that contain prohibited characters as malformed"
// cite(RFC 9114 § 4.2): "Properties of HTTP field names and values are discussed in more detail in Section 5.1 of [HTTP]"
fn check_header_name(
    section: &str,
    name: &str,
    config: &crate::rules::RuleConfig,
) -> Option<Violation> {
    // The production is defined in § 5.1; the quote is the collected grammar's copy,
    // where it sits beside a neighbour rather than alone between two paragraphs, so
    // there is enough of it to stand as evidence. The `tchar` set it expands to is
    // transcribed once, in the shared helper, and read from there.
    // cite(RFC 9110 § A): "field-name = token field-value = *field-content"
    if let Some(c) = crate::helpers::token::find_invalid_token_char(name) {
        return Some(Violation {
            rule: HeaderFieldNamesTokenValid.id().into(),
            severity: config.severity,
            message: format!(
                "Field name '{}' in the {} contains invalid character: '{}'",
                name, section, c
            ),
        });
    }
    None
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &HeaderFieldNamesTokenValid;

#[cfg(test)]
mod tests {
    use super::*;

    use hyper::header::{HeaderName, HeaderValue};
    use rstest::rstest;

    /// A field section holding one name that `HeaderName`'s HTTP/1 parser would
    /// reject: `from_lowercase` is the constructor the HTTP/2 and HTTP/3 decoders
    /// use, and its table admits DQUOTE.
    fn section_with(name: &str, value: &str) -> hyper::HeaderMap {
        let mut hm = hyper::HeaderMap::new();
        hm.append(
            HeaderName::from_lowercase(name.as_bytes()).expect("h2/h3 decoders accept this name"),
            HeaderValue::from_str(value).expect("valid field value"),
        );
        hm
    }

    #[rstest]
    #[case(vec![("host", "example")], false)]
    #[case(vec![("content-type", "text/plain")], false)]
    #[case(vec![("x-custom-header", "v")], false)]
    fn check_request_cases(
        #[case] header_pairs: Vec<(&str, &str)>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = HeaderFieldNamesTokenValid;

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(header_pairs.as_slice());

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
    #[case(vec![("etag", "\"abc\"")], false)]
    fn check_response_cases(
        #[case] header_pairs: Vec<(&str, &str)>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = HeaderFieldNamesTokenValid;

        let tx =
            crate::test_helpers::make_test_transaction_with_response(200, header_pairs.as_slice());

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

    /// The domain the rule actually polices. The HTTP/1 field-name parser is the
    /// `token` grammar exactly, so a name it accepts can never violate this rule;
    /// the HTTP/2 and HTTP/3 decoders admit one character the grammar does not.
    #[rstest]
    #[case("x@bad")]
    #[case("bad header")]
    #[case("header:with:colon")]
    fn names_the_http1_parser_rejects_never_reach_the_rule(#[case] name: &str) {
        assert!(
            HeaderName::from_bytes(name.as_bytes()).is_err(),
            "'{}' would reach a HeaderMap, so the rule must be tested on it",
            name
        );
    }

    #[test]
    fn dquote_name_is_the_reachable_violation() {
        assert!(
            HeaderName::from_bytes(b"x\"bad").is_err(),
            "the HTTP/1 parser must keep DQUOTE out"
        );
        let name = HeaderName::from_lowercase(b"x\"bad").expect("h2/h3 decoders convey DQUOTE");
        assert_eq!(name.as_str(), "x\"bad");
    }

    #[rstest]
    #[case("host", false, None)]
    #[case("x\"bad", true, Some('"'))]
    fn check_header_name_helper_cases(
        #[case] name: &str,
        #[case] expect_violation: bool,
        #[case] expected_char: Option<char>,
    ) -> anyhow::Result<()> {
        let cfg = &crate::test_helpers::make_test_rule_config();
        let res = super::check_header_name("request header section", name, cfg);

        if expect_violation {
            assert!(res.is_some(), "expected violation for '{}'", name);
            let v = res.unwrap();
            assert!(v.message.contains(name));
            assert!(v.message.contains("request header section"));
            if let Some(c) = expected_char {
                assert!(v.message.contains(&c.to_string()));
            }
        } else {
            assert!(res.is_none(), "expected no violation for '{}'", name);
        }
        Ok(())
    }

    /// Every field section of the transaction is walked, and the violation names
    /// the one the field came from.
    #[rstest]
    #[case::request_headers("request header section")]
    #[case::request_trailers("request trailer section")]
    #[case::response_headers("response header section")]
    #[case::response_trailers("response trailer section")]
    fn dquote_field_name_is_flagged_in_every_section(#[case] section: &str) {
        let rule = HeaderFieldNamesTokenValid;
        let bad = section_with("x\"bad", "v");

        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "text/plain")],
        );
        match section {
            "request header section" => tx.request.headers = bad,
            "request trailer section" => tx.request.trailers = Some(bad),
            "response header section" => tx.response.as_mut().unwrap().headers = bad,
            "response trailer section" => tx.response.as_mut().unwrap().trailers = Some(bad),
            other => panic!("unknown section {}", other),
        }

        let violation = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );

        let v = violation.expect("DQUOTE field name must be flagged");
        assert!(
            v.message.contains(section),
            "violation should name the section it came from, got: {}",
            v.message
        );
        assert!(v.message.contains("x\"bad"));
    }

    /// A NonCompliant snippet the rule cannot flag documents a detection that
    /// does not exist, and a field name neither constructor accepts is a snippet
    /// no message can carry. `from_bytes` folds case the way an HTTP/1 parser
    /// does; `from_lowercase` is the HTTP/2 and HTTP/3 path.
    #[test]
    fn published_examples_are_judged_the_way_they_are_labelled() {
        use crate::rules::{Compliance, Rule as _};
        let rule = HeaderFieldNamesTokenValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);

        let mut saw_a_finding = false;
        for ex in rule.examples() {
            let mut section = hyper::HeaderMap::new();
            for line in ex.snippet.lines().filter(|l| !l.trim().is_empty()) {
                let (raw, value) = line
                    .split_once(": ")
                    .unwrap_or_else(|| panic!("not a field line: {line:?}"));
                let name = HeaderName::from_bytes(raw.as_bytes())
                    .or_else(|_| HeaderName::from_lowercase(raw.to_ascii_lowercase().as_bytes()))
                    .unwrap_or_else(|_| {
                        panic!(
                            "no HTTP version can carry the field name {raw:?}, \
                             so no message can carry this example"
                        )
                    });
                section.append(
                    name,
                    HeaderValue::from_str(value).expect("valid field value"),
                );
            }

            let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
            if ex.label.is_some_and(|l| l.starts_with("Trailer section")) {
                tx.response.as_mut().unwrap().trailers = Some(section);
            } else {
                tx.response.as_mut().unwrap().headers = section;
            }

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
        assert!(saw_a_finding, "the guard never produced a finding");
    }

    #[test]
    fn valid_trailer_field_names_are_not_flagged() {
        let rule = HeaderFieldNamesTokenValid;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("trailer", "x-checksum")],
        );
        tx.request.trailers = Some(crate::test_helpers::make_headers_from_pairs(&[(
            "x-request-checksum",
            "abc",
        )]));
        tx.response.as_mut().unwrap().trailers = Some(
            crate::test_helpers::make_headers_from_pairs(&[("x-checksum", "abc123")]),
        );

        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .is_none());
    }

    #[test]
    fn scope_is_both() {
        let rule = HeaderFieldNamesTokenValid;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }
}
