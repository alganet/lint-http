// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageContentTypeWellFormed;

impl Rule for MessageContentTypeWellFormed {
    fn id(&self) -> &'static str {
        "message_content_type_well_formed"
    }

    // The field describes the representation a message carries, and both
    // directions carry one, so both are in scope. Nothing narrows this to
    // responses the way RFC 6266 narrows Content-Disposition.
    // cite(RFC 9110 § 8.3): "The "Content-Type" header field indicates the media type of the associated representation: either the representation enclosed in the message content or the selected representation, as determined by the message semantics."
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

        let check_message = |which: &str,
                             headers: &hyper::HeaderMap,
                             trailers: Option<&hyper::HeaderMap>|
         -> Option<Violation> {
            // Every field line, not just the first. `HeaderMap::get` returns one
            // value, and RFC 9110 §8.3 says recipients often resolve a duplicated
            // Content-Type by taking the *last* syntactically valid member — so
            // checking only the first validated a value the recipient may never
            // act on. Both field sections of the message are counted, since
            // §5.3's prohibition spans them.
            let vals: Vec<_> = headers
                .get_all("content-type")
                .iter()
                .chain(
                    trailers
                        .into_iter()
                        .flat_map(|t| t.get_all("content-type").iter()),
                )
                .collect();

            // `Content-Type = media-type` is a single media-type with no list
            // form, and RFC 9110 does not leave the consequences to inference:
            // it names the duplication, names the recipient behaviour it
            // provokes, and names the security risk. This is the one field whose
            // own section spells out why a second line matters.
            // cite(RFC 9110 § 8.3): "Content-Type = media-type"
            // cite(RFC 9110 § 8.3): "Although Content-Type is defined as a singleton field, it is sometimes incorrectly generated multiple times, resulting in a combined field value that appears to be a list."
            // cite(RFC 9110 § 8.3): "Recipients often attempt to handle this error by using the last syntactically valid member of the list, leading to potential interoperability and security issues if different implementations have different error handling behaviors."
            // cite(RFC 9110 § 5.3): "a sender MUST NOT generate multiple field lines with the same name in a message (whether in the headers or trailers) or append a field line when a field line of the same name already exists in the message, unless that field's definition allows multiple field line values to be recombined as a comma-separated list"
            if vals.len() > 1 {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!(
                        "Multiple Content-Type header fields in the {}; Content-Type is a singleton field (RFC 9110 §8.3) and recipients differ over which member wins, so the media type the peer acts on is not the one this message states",
                        which
                    ),
                });
            }

            for hv in vals {
                // A value carrying octets outside visible US-ASCII was skipped
                // in silence, so the rule that exists to say "this media type is
                // unparseable" said nothing about the least parseable value it
                // could be handed. Every construct in `media-type` is a `token`
                // or a `quoted-string`, neither of which reaches past US-ASCII.
                // cite(RFC 9110 § 5.5): "Field values are usually constrained to the range of US-ASCII characters [USASCII]."
                let Ok(s) = hv.to_str() else {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!(
                            "Content-Type header in the {} contains octets outside visible US-ASCII, so no media type can be read from it",
                            which
                        ),
                    });
                };
                if let Some(v) = check_content_type(which, s, &config) {
                    return Some(v);
                }
            }

            None
        };

        if let Some(v) = check_message("request", &tx.request.headers, tx.request.trailers.as_ref())
        {
            return Some(v);
        }

        if let Some(resp) = &tx.response {
            if let Some(v) = check_message("response", &resp.headers, resp.trailers.as_ref()) {
                return Some(v);
            }
        }

        None
    }

    fn title(&self) -> Option<&'static str> {
        Some("Message Content-Type Well-Formed")
    }

    fn description(&self) -> &'static str {
        "Check that a `Content-Type` header — in a request or a response — reads as a valid `media-type`: a non-empty `type` and `subtype`, each a `token`, separated by `/`, followed by well-formed parameters if any are present. A parameter is a `name=value` pair whose name is a `token` and whose value is a `token` or a `quoted-string`; a trailing `;` with nothing after it is fine, since the grammar brackets each parameter as optional.\n\n**More than one `Content-Type` field line is reported.** RFC 9110 §8.3 calls Content-Type a singleton and says duplicated ones are handled by recipients \"using the last syntactically valid member of the list, leading to potential interoperability and security issues if different implementations have different error handling behaviors\" — so the media type a peer acts on is not the one the message states. Header and trailer sections are counted together.\n\n**A wildcard is reported**, though `*` is a legal `token` and `*/plain` parses. The asterisk belongs to `media-range`, the Accept-side production for naming a *set* of media types; a Content-Type saying `*/*` identifies no representation. This is the rule's judgement rather than a grammar violation.\n\n**Known leniency:** RFC 9110 §5.6.6 forbids whitespace around a parameter's `=`, and this rule trims it, so `charset =utf-8` is accepted. It never causes a false report, only a missed one."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("8.3"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3",
                note: "Content-Type: `Content-Type = media-type`, and the paragraph naming duplicated field lines as an error whose recipient handling differs between implementations",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("8.3.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3.1",
                note: "Media Type: `media-type = type \"/\" subtype parameters`, both halves `token`, both case-insensitive",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("5.6.6"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.6",
                note: "Parameters: the `name=value` grammar, and the bracketing that makes a trailing `;` conforming. Its prohibition on whitespace around `=` is NOT enforced here",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("12.5.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.1",
                note: "Accept: where `*` belongs — `media-range`, which names a set of media types. Cited to explain why a wildcard is reported in Content-Type, which carries a `media-type`",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("5.3"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.3",
                note: "Field Order: a sender MUST NOT emit multiple field lines for a field with no comma-separated-list alternative",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        // One media type per example. These used to be two blocks of stacked
        // `Content-Type:` lines meaning "any of these" — a reading the rule now
        // contradicts, since stacked Content-Type lines in one message are
        // themselves the defect the last example illustrates.
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "Content-Type: text/plain",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(token parameter)"),
                snippet: "Content-Type: application/json; charset=utf-8",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(quoted-string parameter, and a trailing `;` is conforming)"),
                snippet: "Content-Type: image/vnd.example+json; foo=\"bar\"; charset=utf-8;",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(no subtype)"),
                snippet: "Content-Type: text",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(empty subtype)"),
                snippet: "Content-Type: text/",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(wildcard belongs to Accept, not Content-Type)"),
                snippet: "Content-Type: */plain",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(parameter without a value)"),
                snippet: "Content-Type: text/plain; badparam",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(unterminated quoted-string)"),
                snippet: "Content-Type: text/plain; charset=\"unclosed",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(two field lines in one message — Content-Type is a singleton)"),
                snippet:
                    "HTTP/1.1 200 OK\nContent-Type: text/plain\nContent-Type: application/json",
            },
        ]
    }
}

fn check_content_type(
    _which: &str,
    val: &str,
    config: &crate::rules::RuleConfig,
) -> Option<Violation> {
    use crate::helpers::headers::parse_media_type;

    // `media-type = type "/" subtype parameters` is transcribed at
    // `parse_media_type`, which owns it; a second copy here would be the same
    // production stated twice. What the helper reports back is the split and the
    // two "this is not a media-type at all" shapes: no "/", or an empty half.
    let parsed = match parse_media_type(val) {
        Ok(p) => p,
        Err(msg) => {
            let message = if msg == "Empty media-type" {
                "Empty Content-Type header".into()
            } else {
                msg.replace("media-type", "Content-Type")
            };
            return Some(Violation {
                rule: MessageContentTypeWellFormed.id().into(),
                severity: config.severity,
                message,
            });
        }
    };

    // `*` is a perfectly good `tchar`, so this check is not the grammar
    // speaking — `*/plain` parses as a `media-type`. It is the two sentences
    // below read together: Content-Type states *the* media type of the
    // representation, while the asterisk exists to name a *range* of them, and
    // ranges belong to the `media-range` production Accept uses. A wildcard
    // here identifies nothing, so the field says nothing.
    // cite(RFC 9110 § 12.5.1): "The asterisk "*" character is used to group media types into ranges, with "*/*" indicating all media types and "type/*" indicating all subtypes of that type."
    if parsed.type_ == "*" || parsed.subtype == "*" {
        return Some(Violation {
            rule: MessageContentTypeWellFormed.id().into(),
            severity: config.severity,
            message: format!(
                "Invalid Content-Type '{}': wildcard '*' not allowed in type/subtype",
                val
            ),
        });
    }

    // The helper split on "/" and rejected an empty half; what each half must
    // *be* is these two productions, and `token` itself is the token helper's.
    // Case is not checked because there is nothing to check: both are
    // case-insensitive, so no spelling is wrong.
    // cite(RFC 9110 § 8.3.1): "type       = token subtype    = token"
    // cite(RFC 9110 § 8.3.1): "The type and subtype tokens are case-insensitive."
    if let Some(c) = crate::helpers::token::find_invalid_token_char(parsed.type_) {
        return Some(Violation {
            rule: MessageContentTypeWellFormed.id().into(),
            severity: config.severity,
            message: format!(
                "Invalid Content-Type '{}': invalid character '{}' in type",
                val, c
            ),
        });
    }

    // Same production, other half; the quote above covers both lines of it.
    if let Some(c) = crate::helpers::token::find_invalid_token_char(parsed.subtype) {
        return Some(Violation {
            rule: MessageContentTypeWellFormed.id().into(),
            severity: config.severity,
            message: format!(
                "Invalid Content-Type '{}': invalid character '{}' in subtype",
                val, c
            ),
        });
    }

    // Parameters are optional after the type/subtype, and each one is a
    // name/value pair; the two productions below carry the whole check.
    // cite(RFC 9110 § 8.3.1): "The type/subtype MAY be followed by semicolon-delimited parameters (Section 5.6.6) in the form of name/value pairs."
    if let Some(params) = parsed.params {
        for p_raw in crate::helpers::headers::split_semicolons_respecting_quotes(params) {
            let p = p_raw.trim();
            // `[ parameter ]` is bracketed, so a semicolon with nothing after it
            // is a conforming zero-parameter repetition rather than a defect --
            // `text/plain; charset=utf-8;` is well formed. This is the same
            // empty-element shape that produced four false positives in the
            // caching family; here the code already had it right.
            // cite(RFC 9110 § 5.6.6): "parameters      = *( OWS ";" OWS [ parameter ] )"
            if p.is_empty() {
                continue;
            }
            if let Some(eq) = p.find('=') {
                let (name, value) = p.split_at(eq);
                let name = name.trim();
                let value = value[1..].trim(); // skip '='
                if name.is_empty() {
                    return Some(Violation {
                        rule: MessageContentTypeWellFormed.id().into(),
                        severity: config.severity,
                        message: format!("Invalid Content-Type '{}': empty parameter name", val),
                    });
                }
                // cite(RFC 9110 § 5.6.6): "parameter-name  = token"
                if let Some(c) = crate::helpers::token::find_invalid_token_char(name) {
                    return Some(Violation {
                        rule: MessageContentTypeWellFormed.id().into(),
                        severity: config.severity,
                        message: format!("Invalid Content-Type '{}': invalid character '{}' in parameter name '{}'", val, c, name),
                    });
                }
                if value.starts_with('"') {
                    // The `quoted-string` production belongs to the shared
                    // helper, which walks the interior. The check that stood here
                    // was a second, weaker copy: it asked only that the value
                    // start and end with DQUOTE, so a value whose closing quote
                    // was itself escaped — `foo="a\"` — looked terminated, as did
                    // `foo="a"b"` with an unescaped quote in the middle.
                    if let Err(e) = crate::helpers::headers::validate_quoted_string(value) {
                        return Some(Violation {
                            rule: MessageContentTypeWellFormed.id().into(),
                            severity: config.severity,
                            message: format!(
                                "Invalid Content-Type '{}': parameter '{}' has invalid quoted-string: {}",
                                val, name, e
                            ),
                        });
                    }
                } else {
                    // The alternation is exclusive: a value that does not open
                    // with DQUOTE has to satisfy `token`, which is why an
                    // unquoted `utf 8` is a defect rather than a curiosity.
                    // cite(RFC 9110 § 5.6.6): "parameter-value = ( token / quoted-string )"
                    if let Some(c) = crate::helpers::token::find_invalid_token_char(value) {
                        return Some(Violation {
                            rule: MessageContentTypeWellFormed.id().into(),
                            severity: config.severity,
                            message: format!("Invalid Content-Type '{}': invalid character '{}' in parameter value '{}'", val, c, value),
                        });
                    }
                }
            } else {
                // The "=" is not optional inside `parameter`, so a bare token
                // among the parameters is not a valueless flag.
                // cite(RFC 9110 § 5.6.6): "parameter       = parameter-name "=" parameter-value"
                return Some(Violation {
                    rule: MessageContentTypeWellFormed.id().into(),
                    severity: config.severity,
                    message: format!(
                        "Invalid Content-Type '{}': parameter '{}' missing '='",
                        val, p
                    ),
                });
            }
        }
    }

    None
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &MessageContentTypeWellFormed;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("text/plain", false)]
    #[case("application/json", false)]
    #[case("application/json; charset=utf-8", false)]
    #[case("text/html; charset=\"utf-8\"", false)]
    #[case("text/plain; foo=\"a;b\"", false)]
    #[case("image/vnd.example+json; charset=utf-8; foo=bar", false)]
    #[case("text", true)]
    #[case("text/", true)]
    #[case("/plain", true)]
    #[case("*/plain", true)]
    #[case("text/*", true)]
    #[case("text/plain; badparam", true)]
    #[case("text/plain;=value", true)]
    #[case("text/plain; charset=utf 8", true)]
    #[case("text/plain; charset=\"unclosed", true)]
    fn content_type_parsing_cases(#[case] val: &str, #[case] expect_violation: bool) {
        let cfg = crate::test_helpers::make_test_rule_config();
        let res = super::check_content_type("test", val, &cfg);
        if expect_violation {
            assert!(res.is_some(), "expected violation for '{}'", val);
        } else {
            assert!(
                res.is_none(),
                "unexpected violation for '{}': {:?}",
                val,
                res
            );
        }
    }

    #[rstest]
    #[case("te@xt/plain", true)]
    #[case("text/pl@in", true)]
    #[case("text/plain; bad@=v", true)]
    #[case("", true)]
    #[case("text/plain; charset=utf-8;", false)]
    #[case("text/plain; foo=bar baz", true)]
    // The closing DQUOTE is escaped, so the string is not terminated.
    #[case("text/plain; foo=\"a\\\"", true)]
    // An unescaped DQUOTE inside the string.
    #[case("text/plain; foo=\"a\"b\"", true)]
    // A control character inside the string.
    #[case("text/plain; foo=\"a\u{1}b\"", true)]
    // Still accepted: a properly escaped quote, and an empty quoted-string.
    #[case("text/plain; foo=\"a\\\"b\"", false)]
    #[case("text/plain; foo=\"\"", false)]
    fn extra_content_type_cases(#[case] val: &str, #[case] expect_violation: bool) {
        let cfg = crate::test_helpers::make_test_rule_config();
        let res = super::check_content_type("test", val, &cfg);
        if expect_violation {
            assert!(res.is_some(), "expected violation for '{}'", val);
        } else {
            assert!(
                res.is_none(),
                "unexpected violation for '{}': {:?}",
                val,
                res
            );
        }
    }

    #[rstest]
    // Both individually valid: only the count can see this.
    #[case(&["text/plain", "application/json"], true)]
    // The second line is the malformed one, and §8.3 says recipients often take
    // the last valid member — checking only the first missed it entirely.
    #[case(&["text/plain", "text/"], true)]
    #[case(&["text/plain"], false)]
    fn multiple_content_type_field_lines_report_violation(
        #[case] values: &[&str],
        #[case] expect_violation: bool,
    ) {
        let rule = MessageContentTypeWellFormed;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_content_type_well_formed",
        ]);
        let pairs: Vec<(&str, &str)> = values.iter().map(|v| ("content-type", *v)).collect();
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&pairs);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert_eq!(v.is_some(), expect_violation, "{values:?} -> {v:?}");
    }

    #[test]
    fn a_header_line_and_a_trailer_line_are_still_two_field_lines() {
        let rule = MessageContentTypeWellFormed;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_content_type_well_formed",
        ]);
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        {
            let resp = tx.response.as_mut().unwrap();
            resp.headers =
                crate::test_helpers::make_headers_from_pairs(&[("content-type", "text/plain")]);
            resp.trailers = Some(crate::test_helpers::make_headers_from_pairs(&[(
                "content-type",
                "application/json",
            )]));
        }
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.expect("must be reported").message.contains("Multiple"));
    }

    #[rstest]
    #[case(true)]
    #[case(false)]
    fn undecodable_value_is_reported_not_skipped(#[case] on_response: bool) {
        // The whole point of this rule is to say when a media type cannot be
        // read; a value it cannot even decode used to be passed over in silence.
        use hyper::header::HeaderValue;
        let rule = MessageContentTypeWellFormed;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_content_type_well_formed",
        ]);
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        hm.insert("content-type", HeaderValue::from_bytes(&[0xff]).unwrap());
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        if on_response {
            tx.response.as_mut().unwrap().headers = hm;
        } else {
            tx.request.headers = hm;
        }
        let msg = rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            )
            .expect("must be reported")
            .message;
        assert!(msg.contains("US-ASCII"), "{msg}");
        assert!(
            msg.contains(if on_response { "response" } else { "request" }),
            "{msg}"
        );
    }

    #[test]
    fn a_malformed_second_request_line_is_reached() {
        // Before the loop read every line, `HeaderMap::get` stopped at the first.
        let rule = MessageContentTypeWellFormed;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_content_type_well_formed",
        ]);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("content-type", "text/plain"),
            ("content-type", "*/plain"),
        ]);
        let msg = rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            )
            .expect("must be reported")
            .message;
        assert!(msg.contains("request"), "{msg}");
    }

    /// Every published snippet is run through the rule. Nothing else does this,
    /// so a `Compliant` example the rule rejects — or a `NonCompliant` one it
    /// accepts — would ship in the docs unchallenged. This family has published
    /// a wrong example twice already.
    #[test]
    fn published_examples_match_the_rules_verdict() {
        use crate::rules::Compliance;
        let rule = MessageContentTypeWellFormed;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_content_type_well_formed",
        ]);

        for ex in rule.examples() {
            let mut values: Vec<&str> = Vec::new();
            for line in ex.snippet.lines() {
                if line.starts_with("HTTP/") {
                    continue;
                }
                let v = line.strip_prefix("Content-Type: ").unwrap_or_else(|| {
                    panic!("example line is neither a start-line nor a Content-Type field line: {line:?}")
                });
                values.push(v);
            }
            assert!(
                !values.is_empty(),
                "example has no field lines: {}",
                ex.snippet
            );

            let pairs: Vec<(&str, &str)> = values.iter().map(|v| ("content-type", *v)).collect();
            let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&pairs);
            let v = rule.check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            );
            match ex.compliance {
                Compliance::Compliant => {
                    assert!(
                        v.is_none(),
                        "rule rejects its Compliant example {:?}: {v:?}",
                        ex.snippet
                    )
                }
                Compliance::NonCompliant => {
                    assert!(
                        v.is_some(),
                        "rule accepts its NonCompliant example {:?}",
                        ex.snippet
                    )
                }
            }
        }
    }

    #[rstest]
    fn request_and_response_integration() -> anyhow::Result<()> {
        let rule = MessageContentTypeWellFormed;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_content_type_well_formed",
        ]);

        // request invalid
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-type", "text")]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());

        // response invalid
        let tx2 = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "text")],
        );
        let v2 = rule.check_transaction(
            &tx2,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v2.is_some());

        // both valid
        let mut tx3 = crate::test_helpers::make_test_transaction();
        tx3.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-type",
            "text/plain; charset=utf-8",
        )]);
        let tx4 = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "application/json")],
        );
        let v3 = rule.check_transaction(
            &tx3,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        let v4 = rule.check_transaction(
            &tx4,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v3.is_none());
        assert!(v4.is_none());

        Ok(())
    }

    #[test]
    fn scope_is_both() {
        let rule = MessageContentTypeWellFormed;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }
}
