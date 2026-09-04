// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};

pub struct ContentDispositionTokenValid;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_6266_4_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 6266",
    section: Some("4.1"),
    url: "https://www.rfc-editor.org/rfc/rfc6266.html#section-4.1",
    note: "Grammar: a mandatory `disposition-type` followed by optional `;`-separated parameters, with `disp-ext-type = token`. Whitespace around the separators is implied rather than written",
};
const RFC_6266_4_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 6266",
    section: Some("4.2"),
    url: "https://www.rfc-editor.org/rfc/rfc6266.html#section-4.2",
    note: "Disposition Type: an unknown type is conforming and has defined handling (treat as `attachment`), which is why this rule validates the value's shape and not its membership in any list",
};
const RFC_6266_4: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 6266",
    section: Some("4"),
    url: "https://www.rfc-editor.org/rfc/rfc6266.html#section-4",
    note: "Defines Content-Disposition as a *response* header field — the request half of this rule is a deliberate extension beyond the document, since upload APIs do send one",
};
const RFC_9110_5_6_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("5.6.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.2",
    note: "`token = 1*tchar` — where the production actually lives now. RFC 6266 §4.1 imports `token` from the obsolete RFC 2616; the character set is unchanged",
};
const RFC_9110_5_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("5.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.3",
    note: "Field Order: a sender MUST NOT emit multiple field lines for a field whose definition has no comma-separated-list alternative",
};

impl RuleMeta for ContentDispositionTokenValid {
    fn id(&self) -> &'static str {
        "content_disposition_token_valid"
    }

    fn title(&self) -> Option<&'static str> {
        Some("Message Content-Disposition Disposition-Type Token Valid")
    }

    fn description(&self) -> &'static str {
        "Validate that the `Content-Disposition` header's `disposition-type` is present and is a valid `token`. The `disposition-type` is everything before the first `;` (e.g. `attachment` in `attachment; filename=\"a.txt\"`); `inline` and `attachment` are the two named types, and any other value must satisfy `disp-ext-type = token` — no whitespace, controls, or separator characters.\n\nAn unrecognized type is **not** an error: RFC 6266 §4.2 says recipients should treat unknown types like `attachment`, so this rule checks the shape of the value and never compares it against a list of known types.\n\nSince the grammar has no comma-separated-list alternative, a message section carries at most one `Content-Disposition` field line (RFC 9110 §5.3). Two lines are reported: recipients that recombine them get `attachment; filename=\"a\", inline` and disagree about where the parameter value ends, which is a real source of filename-handling divergence in downloads.\n\n**Scope:** RFC 6266 defines a *response* header field. This rule also inspects requests, where the field is used in practice by upload APIs but is not defined by RFC 6266. `Content-Disposition` inside multipart body *parts* is a different thing governed by RFC 7578 §4.2; this linter reads message header fields, not parsed body parts.\n\n**Note on `token`:** RFC 6266 §4.1 imports `token` from RFC 2616, which is obsolete. The production is the same set of characters as RFC 9110 §5.6.2's `token = 1*tchar`, which is what this rule enforces."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_6266_4_1,
            RFC_6266_4_2,
            RFC_6266_4,
            RFC_9110_5_6_2,
            RFC_9110_5_3,
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "Content-Disposition: attachment; filename=\"example.txt\"",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "Content-Disposition: inline",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "Content-Disposition: ; filename=\"example.txt\"",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(an unrecognized type is conforming)"),
                snippet: "Content-Disposition: preview; filename=\"a.txt\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "Content-Disposition: bad@type; filename=\"a\"",
            },
            // Framed as a response, not two bare field lines: a sibling rule
            // publishes a multi-line block meaning "any of these spellings", and
            // without the start-line the two constructs look identical while
            // meaning opposite things.
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(two field lines in one message — Content-Disposition is a singleton)"),
                snippet: "HTTP/1.1 200 OK\nContent-Disposition: attachment; filename=\"a.txt\"\nContent-Disposition: inline",
            },
        ]
    }
}

impl Rule for ContentDispositionTokenValid {
    // RFC 6266 defines a *response* header field, so the request half of this
    // rule is outside the document it cites. Kept, because a request
    // Content-Disposition does occur (upload APIs put one on the message) and a
    // malformed disposition-type is worth reporting wherever it appears — but no
    // sentence licenses looking there, and the previous rationale ("multipart/
    // form-data parts") was wrong twice over: those are *part* headers inside the
    // body, which this linter does not parse, and their grammar is RFC 7578's —
    // and RFC 6266 says so itself rather than merely implying it.
    // cite(RFC 6266 § 4): "The Content-Disposition response header field is used to convey additional information about how to process the response payload, and also can be used to attach additional metadata, such as the filename to use when saving the response payload locally."
    // cite(RFC 6266 § 1): "This document does not apply to Content-Disposition header fields appearing in payload bodies transmitted over HTTP, such as when using the media type "multipart/form-data" ([RFC2388])."
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
            // Helper to validate a single Content-Disposition header value
            let check_value = |hdr_name: &str, val: &str| -> Option<Violation> {
                // Trim whitespace and split off parameters
                // The disposition-type is mandatory and the parameters are not, so an
                // empty field value satisfies no part of the production.
                // cite(RFC 6266 § 4.1): "content-disposition = "Content-Disposition" ":" disposition-type *( ";" disposition-parm )"
                let s = val.trim();
                if s.is_empty() {
                    return Some(self.cited(
                        &RFC_6266_4_1,
                        ctx.severity,
                        format!("{} header value must not be empty", hdr_name),
                    ));
                }

                // Everything before the first ";" is the disposition-type. Trimming
                // is not tidiness: the grammar's whitespace is implied rather than
                // written, so `attachment ; filename=…` is a conforming spelling.
                // cite(RFC 6266 § 4.1): "Note that due to the rules for implied linear whitespace (Section 2.1 of [RFC2616]), OPTIONAL whitespace can appear between words (token or quoted-string) and separator characters."
                let dispo = s.split(';').next().unwrap().trim();
                // cite(RFC 6266 § 4.1): "disposition-type = "inline" | "attachment" | disp-ext-type"
                if dispo.is_empty() {
                    return Some(self.cited(
                        &RFC_6266_4_1,
                        ctx.severity,
                        format!("{} header disposition-type must not be empty", hdr_name),
                    ));
                }

                // The rule's whole purpose, and it had been uncited. Only the third
                // alternative constrains characters, and it is what a value other
                // than "inline"/"attachment" must satisfy; `token` itself is the
                // shared helper's to define. Nothing checks the value against a list
                // of known types, because there is no such list to check against —
                // an unrecognized type is conforming and has defined handling.
                // cite(RFC 6266 § 4.1): "disp-ext-type       = token"
                // cite(RFC 6266 § 4.2): "Unknown or unhandled disposition types SHOULD be handled by recipients the same way as "attachment" (see also [RFC2183], Section 2.8)."
                if let Some(c) = crate::helpers::token::find_invalid_token_char(dispo) {
                    return Some(self.violation(
                        ctx.severity,
                        format!(
                            "{} disposition-type contains invalid token character: '{}'",
                            hdr_name, c
                        ),
                    ));
                }

                None
            };

            // One message's worth of Content-Disposition field lines. The §5.3
            // prohibition is scoped to a message and spans both of its field
            // sections, so the header and trailer sections are counted together: one
            // line in each is the same defect as two in either.
            let check_message = |kind: &str,
                                 headers: &hyper::HeaderMap,
                                 trailers: Option<&hyper::HeaderMap>|
             -> Option<Violation> {
                let vals: Vec<_> = headers
                    .get_all("content-disposition")
                    .iter()
                    .chain(
                        trailers
                            .into_iter()
                            .flat_map(|t| t.get_all("content-disposition").iter()),
                    )
                    .collect();

                // The grammar is a disposition-type followed by parameters, with no
                // `#(...)` alternative anywhere in it, so §5.3's exception does not
                // apply and a message carries at most one field line.
                // Combining two is worse here than the arithmetic suggests: the
                // recombined value is "attachment; filename="a", inline", which
                // different recipients truncate at different points, so the filename
                // a download is saved under depends on whose parser read it.
                //
                // **Not `helpers::headers::singleton_field_preamble`, and the reason
                // is one line above: `vals` counts the header section and the trailer
                // section together.** That is what §5.3 asks for -- its MUST NOT is
                // about the message and says *"whether in the headers or trailers"* --
                // and it is exactly what the shared preamble may not claim, because
                // the recombining clause in it is §5.2's and §5.2 recombines *within a
                // section*. Two lines in two sections are two values, not one. The
                // five callers of that preamble each read one section; this rule is
                // out of it by a reason rather than by omission, and it was missed by
                // both of the hand-maintained copy lists that P3 was written from.
                // cite(RFC 6266 § 4.1): "content-disposition = "Content-Disposition" ":" disposition-type *( ";" disposition-parm )"
                // cite(RFC 9110 § 5.5): "Fields that only anticipate a single member as the field value are referred to as "singleton fields"."
                // cite(RFC 9110 § 5.3): "a sender MUST NOT generate multiple field lines with the same name in a message (whether in the headers or trailers) or append a field line when a field line of the same name already exists in the message, unless that field's definition allows multiple field line values to be recombined as a comma-separated list"
                if vals.len() > 1 {
                    // The singleton conclusion is drawn from RFC 6266's grammar, so
                    // only a response — the message RFC 6266 governs — may be told
                    // that. A request Content-Disposition is outside that document,
                    // and the §5.3 requirement stands on its own for it.
                    let basis = if kind == "response" {
                        "the grammar has no comma-separated-list alternative (RFC 6266 §4.1), so at most one field line may be sent (RFC 9110 §5.3)"
                    } else {
                        "no definition of this field gives it a comma-separated-list form, so at most one field line may be sent (RFC 9110 §5.3)"
                    };
                    return Some(self.violation(
                        ctx.severity,
                        format!(
                            "Multiple Content-Disposition header fields in the {}; {}",
                            kind, basis
                        ),
                    ));
                }

                for hv in vals {
                    // Not a UTF-8 question: `to_str` accepts only visible US-ASCII,
                    // which is the range field values are held to. A raw non-ASCII
                    // filename is well-formed UTF-8 and still wrong here — RFC 6266
                    // §4.3 has `filename*` for exactly that.
                    // cite(RFC 9110 § 5.5): "Field values are usually constrained to the range of US-ASCII characters [USASCII]."
                    let Ok(s) = hv.to_str() else {
                        return Some(self.violation(ctx.severity, "Content-Disposition header value contains octets outside visible US-ASCII; non-ASCII filenames belong in a `filename*` parameter (RFC 6266 §4.3)".into()));
                    };
                    if let Some(v) = check_value("Content-Disposition", s) {
                        return Some(v);
                    }
                }

                None
            };

            if let Some(resp) = &tx.response {
                if let Some(v) = check_message("response", &resp.headers, resp.trailers.as_ref()) {
                    return Some(v);
                }
            }

            if let Some(v) =
                check_message("request", &tx.request.headers, tx.request.trailers.as_ref())
            {
                return Some(v);
            }

            None
        };
        Vec::from_iter(finding())
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ContentDispositionTokenValid;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(Some("attachment; filename=\"a.txt\""), false)]
    #[case(Some("inline"), false)]
    #[case(Some("form-data; name=\"field\"; filename=\"a.png\""), false)]
    #[case(Some("x-custom"), false)]
    #[case(Some(""), true)]
    #[case(Some("; filename=\"a\""), true)]
    #[case(Some("bad@type; filename=\"a\""), true)]
    #[case(None, false)]
    fn response_cases(#[case] value: Option<&str>, #[case] expect_violation: bool) {
        let rule = ContentDispositionTokenValid;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        if let Some(v) = value {
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[("content-disposition", v)]);
        }

        let config = crate::test_helpers::make_test_config_with_severity(
            "content_disposition_token_valid",
            "warn",
        );

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        );
        if expect_violation {
            assert!(v.is_some(), "expected violation for '{:?}'", value);
        } else {
            assert!(v.is_none(), "did not expect violation for '{:?}'", value);
        }
    }

    #[test]
    fn request_header_checked() {
        let rule = ContentDispositionTokenValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-disposition",
            "form-data; name=\"x\"",
        )]);
        let config = crate::test_helpers::make_test_config_with_severity(
            "content_disposition_token_valid",
            "warn",
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        );
        assert!(v.is_none());
    }

    #[test]
    fn non_utf8_header_is_violation() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        let rule = ContentDispositionTokenValid;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        hm.insert("content-disposition", HeaderValue::from_bytes(&[0xff])?);
        tx.response.as_mut().unwrap().headers = hm;

        let config = crate::test_helpers::make_test_config_with_severity(
            "content_disposition_token_valid",
            "warn",
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn request_non_utf8_header_is_violation() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        let rule = ContentDispositionTokenValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        hm.insert("content-disposition", HeaderValue::from_bytes(&[0xff])?);
        tx.request.headers = hm;

        let config = crate::test_helpers::make_test_config_with_severity(
            "content_disposition_token_valid",
            "warn",
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        );
        assert!(v.is_some());
        Ok(())
    }

    #[rstest]
    // Two individually valid lines: nothing in the per-value checks can see this.
    #[case("inline", "attachment")]
    #[case("inline", "bad@type")]
    fn multiple_header_fields_report_violation(#[case] first: &str, #[case] second: &str) {
        let rule = ContentDispositionTokenValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[
                ("content-disposition", first),
                ("content-disposition", second),
            ]),
            body_length: None,
            trailers: None,
        });

        let config = crate::test_helpers::make_test_config_with_severity(
            "content_disposition_token_valid",
            "warn",
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        );
        let msg = v.expect("two field lines must be reported").message;
        assert!(msg.contains("Multiple Content-Disposition"), "{msg}");
        assert!(msg.contains("response"), "{msg}");
    }

    #[test]
    fn a_header_line_and_a_trailer_line_are_still_two_field_lines() {
        // §5.3 forbids multiple field lines "whether in the headers or
        // trailers" — one in each section is the same defect as two in either.
        let rule = ContentDispositionTokenValid;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        {
            let resp = tx.response.as_mut().unwrap();
            resp.headers = crate::test_helpers::make_headers_from_pairs(&[(
                "content-disposition",
                "attachment; filename=\"a.txt\"",
            )]);
            resp.trailers = Some(crate::test_helpers::make_headers_from_pairs(&[(
                "content-disposition",
                "inline",
            )]));
        }
        let config = crate::test_helpers::make_test_config_with_severity(
            "content_disposition_token_valid",
            "warn",
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        );
        assert!(v.expect("must be reported").message.contains("Multiple"));
    }

    #[test]
    fn request_message_does_not_claim_rfc_6266_as_its_authority() {
        // RFC 6266 defines a response header field, so a request-side finding
        // must not cite its grammar as the reason.
        let rule = ContentDispositionTokenValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("content-disposition", "inline"),
            ("content-disposition", "attachment"),
        ]);
        let config = crate::test_helpers::make_test_config_with_severity(
            "content_disposition_token_valid",
            "warn",
        );
        let msg = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        )
        .expect("must be reported")
        .message;
        assert!(!msg.contains("RFC 6266"), "{msg}");
        assert!(msg.contains("RFC 9110 §5.3"), "{msg}");
    }

    #[test]
    fn non_ascii_value_message_does_not_blame_utf8() {
        // A raw non-ASCII filename is perfectly good UTF-8; what it violates is
        // the US-ASCII range field values are held to.
        use hyper::header::HeaderValue;
        let rule = ContentDispositionTokenValid;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        hm.insert(
            "content-disposition",
            HeaderValue::from_bytes("attachment; filename=\"café.txt\"".as_bytes()).unwrap(),
        );
        tx.response.as_mut().unwrap().headers = hm;
        let config = crate::test_helpers::make_test_config_with_severity(
            "content_disposition_token_valid",
            "warn",
        );
        let msg = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        )
        .expect("must be reported")
        .message;
        assert!(!msg.contains("UTF-8"), "{msg}");
        assert!(msg.contains("US-ASCII"), "{msg}");
    }

    #[test]
    fn multiple_request_field_lines_report_violation() {
        let rule = ContentDispositionTokenValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("content-disposition", "form-data; name=\"a\""),
            ("content-disposition", "form-data; name=\"b\""),
        ]);
        let config = crate::test_helpers::make_test_config_with_severity(
            "content_disposition_token_valid",
            "warn",
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        );
        let msg = v.expect("two field lines must be reported").message;
        assert!(msg.contains("request"), "{msg}");
    }

    #[test]
    fn request_value_is_validated() {
        let rule = ContentDispositionTokenValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-disposition", "bad@type")]);
        let config = crate::test_helpers::make_test_config_with_severity(
            "content_disposition_token_valid",
            "warn",
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        );
        assert!(v.unwrap().message.contains("invalid token character"));
    }

    #[test]
    fn whitespace_only_is_violation() {
        let rule = ContentDispositionTokenValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-disposition", "   ")],
        );
        let config = crate::test_helpers::make_test_config_with_severity(
            "content_disposition_token_valid",
            "warn",
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        );
        assert!(v.is_some());
    }

    /// Published examples must survive every rule that reads this header, not
    /// just this one. Nothing runs a rule's own `examples()` through the engine,
    /// so a snippet this rule accepts but a sibling rejects would ship in the
    /// docs as the recommended spelling. That has already happened twice in this
    /// family. Three rules read `Content-Disposition`; all three are checked.
    #[test]
    fn published_examples_agree_with_every_rule_reading_this_header() {
        use crate::rules::Compliance;
        let rule = ContentDispositionTokenValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "content_disposition_token_valid",
            "content_disposition_parameter_valid",
            "form_data_content_disposition_valid",
        ]);
        let siblings: [(&str, &dyn crate::rules::Rule); 2] = [
            ("parameter validity", &crate::rules::content_disposition_parameter_valid::ContentDispositionParameterValid),
            ("form-data validity", &crate::rules::form_data_content_disposition_valid::FormDataContentDispositionValid),
        ];

        for ex in rule.examples() {
            // Every line must be accounted for: a start-line, or a field line
            // this test knows how to feed in. A line silently dropped here is a
            // line `gendocs` publishes unchecked.
            let mut values: Vec<&str> = Vec::new();
            for line in ex.snippet.lines() {
                if line.starts_with("HTTP/") {
                    continue;
                }
                let v = line.strip_prefix("Content-Disposition: ").unwrap_or_else(|| {
                    panic!("example line is neither a start-line nor a Content-Disposition field line: {line:?}")
                });
                values.push(v);
            }
            assert!(
                !values.is_empty(),
                "example has no field lines: {}",
                ex.snippet
            );

            let pairs: Vec<(&str, &str)> =
                values.iter().map(|v| ("content-disposition", *v)).collect();
            let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&pairs);
            let history = crate::transaction_history::TransactionHistory::empty();

            let own = crate::test_helpers::run_rule(&rule, &tx, &history, &cfg);
            match ex.compliance {
                Compliance::Compliant => {
                    assert!(
                        own.is_none(),
                        "own rule rejects its Compliant example {:?}: {own:?}",
                        ex.snippet
                    );
                    for (name, sibling) in siblings {
                        let other = crate::test_helpers::run_rule(sibling, &tx, &history, &cfg);
                        assert!(
                            other.is_none(),
                            "the {name} rule rejects a Compliant example {:?}: {other:?}",
                            ex.snippet
                        );
                    }
                }
                Compliance::NonCompliant => {
                    assert!(
                        own.is_some(),
                        "own rule accepts its NonCompliant example {:?}",
                        ex.snippet
                    );
                }
            }
        }
    }

    #[test]
    fn scope_is_both() {
        let rule = ContentDispositionTokenValid;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }
}
