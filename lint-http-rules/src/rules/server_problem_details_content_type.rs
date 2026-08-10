// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ServerProblemDetailsContentType;

impl Rule for ServerProblemDetailsContentType {
    fn id(&self) -> &'static str {
        "server_problem_details_content_type"
    }

    // No sentence scopes this rule to responses on its own. What does is the
    // status gate below: the question the rule asks is about a status code and
    // the representation sent with it, and only a response has either. The cite
    // lives there, at its narrowest site, rather than being repeated here.
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
        let resp = tx.response.as_ref()?;

        // The permission is unconditional and the fit is not, so the gate is the
        // second half of the sentence: nothing is wrong with problem details on
        // a 200, and there is nothing to advise about one either.
        // cite(RFC 9457 § 1): "Problem details can be used with any HTTP status code, but they most naturally fit the semantics of 4xx and 5xx responses."
        if resp.status < 400 {
            return None;
        }

        // A response with no `Content-Type` is `server_content_type_present`'s
        // finding, and a value that is not a media type is
        // `message_content_type_well_formed`'s. Neither is answered here.
        let ct_str = crate::helpers::headers::get_header_str(&resp.headers, "content-type")?;
        let parsed = crate::helpers::headers::parse_media_type(ct_str).ok()?;

        // Folded once, here, rather than at each comparison below.
        // cite(RFC 9110 § 8.3.1): "The type and subtype tokens are case-insensitive."
        let t = parsed.type_.to_ascii_lowercase();
        let sub = parsed.subtype.to_ascii_lowercase();

        // The response already carries problem details. The JSON serialization
        // is named in the body of the document and the XML one only in an
        // appendix, so the two halves of this test come from two places.
        // cite(RFC 9457 § 3): "When serialized in a JSON document, that format is identified with the "application/problem+json" media type."
        // cite(RFC 9457 § B): "The media type for this format is "application/problem+xml"."
        if t == "application" && (sub == "problem+json" || sub == "problem+xml") {
            return None;
        }

        // Only the three media types that name a syntax and no format on top of
        // it: `application/json` is the media type for JSON text, and RFC 7303
        // names its two XML counterparts in the same breath as "a more specific
        // media type", which is the distinction this table draws.
        // cite(RFC 8259 § 11): "The media type for JSON text is application/json."
        // cite(RFC 7303 § 4.1): "The media types application/xml or text/xml, or a more specific media type (see Section 9.6), SHOULD be used."
        //
        // A `+json` or `+xml` subtype is a sender naming a format it already
        // has, which is the case the document twice says to leave alone.
        // cite(RFC 9457 § 1): "If the response is still a representation of a resource, for example, it's often preferable to describe the relevant details in that application's format."
        // cite(RFC 9457 § 4): "Problem details are intended to avoid the necessity of establishing new "fault" or "error" document formats, not to replace existing domain-specific formats."
        if !matches!(
            (t.as_str(), sub.as_str()),
            ("application", "json") | ("application", "xml") | ("text", "xml")
        ) {
            return None;
        }

        // No sentence in RFC 9457 is violated by any of this: what is left once
        // the document's own exemptions are honoured is the case it was written
        // for, an application with no error format of its own. So the finding is
        // advice and the message says so.
        // cite(RFC 9457 § 1): "This specification's aim is to define common error formats for applications that need one so that they aren't required to define their own or, worse, tempted to redefine the semantics of existing HTTP status codes."
        Some(Violation {
            rule: self.id().into(),
            severity: config.severity,
            message: format!(
                "Error response carries the generic media type '{}'; problem details (RFC 9457) would describe the error in a machine-readable form, as 'application/problem+json' or 'application/problem+xml'. Advisory: no RFC requires them, and an application that already has an error format of its own should keep using it",
                ct_str
            ),
        })
    }

    fn description(&self) -> &'static str {
        "Reports an error response (4xx or 5xx) whose `Content-Type` is one of the three **generic** JSON or XML media types — `application/json`, `application/xml`, `text/xml` — as a candidate for problem details, the format RFC 9457 defines to carry machine-readable details of an error as `application/problem+json` or `application/problem+xml`. RFC 9457 obsoletes RFC 7807.\n\n**The finding is advisory: no RFC requires problem details.** RFC 9457 says they \"can be used with any HTTP status code, but they most naturally fit the semantics of 4xx and 5xx responses\", which is where this rule looks, and it twice says that a sender with a format of its own should keep it: §1 notes that where the response is still a representation of a resource \"it's often preferable to describe the relevant details in that application's format\", and §4 that problem details are \"intended to avoid the necessity of establishing new 'fault' or 'error' document formats, not to replace existing domain-specific formats\". A finding means this error response carries no error format at all, not that its sender did anything wrong.\n\nThat is why the reported set stops at the three generic media types. A subtype ending in `+json` or `+xml` (`application/hal+json`, `application/vnd.api+json`) names a specific format, so the sender has the one RFC 9457 prefers and the rule says nothing. It also says nothing about a `Content-Type` it cannot parse, which is `message_content_type_well_formed`'s finding, nor about a response carrying no `Content-Type` at all, which is `server_content_type_present`'s."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9457",
                section: Some("1"),
                url: "https://www.rfc-editor.org/rfc/rfc9457.html#section-1",
                note: "Which status codes problem details suit, and the two sentences saying an application-specific format is often the better answer — between them the reason this rule's finding is advice and not a defect",
            },
            crate::rules::SpecRef {
                spec: "RFC 9457",
                section: Some("3"),
                url: "https://www.rfc-editor.org/rfc/rfc9457.html#section-3",
                note: "The problem details JSON object, and the media type that identifies it: `application/problem+json`",
            },
            crate::rules::SpecRef {
                spec: "RFC 9457",
                section: Some("B"),
                url: "https://www.rfc-editor.org/rfc/rfc9457.html#appendix-B",
                note: "The equivalent XML format and its media type, `application/problem+xml` — the second value this rule accepts is defined in an appendix, not in the body of the document",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("problem details, in the media type that names them"),
                snippet: "HTTP/1.1 400 Bad Request\nContent-Type: application/problem+json\n\n{\"type\":\"https://example.com/probs/out-of-credit\",\"title\":\"You do not have enough credit\",\"status\":400}",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("an application's own error format — RFC 9457 §4 says to keep it"),
                snippet: "HTTP/1.1 422 Unprocessable Content\nContent-Type: application/vnd.api+json\n\n{\"errors\":[{\"status\":\"422\",\"title\":\"must be a positive integer\"}]}",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("the content is problem details; the media type does not say so"),
                snippet: "HTTP/1.1 500 Internal Server Error\nContent-Type: application/json\n\n{\"type\":\"https://example.com/probs/internal\",\"title\":\"Internal error\",\"status\":500}",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ServerProblemDetailsContentType;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(400, Some("application/problem+json"), false)]
    #[case(400, Some("application/PROBLEM+JSON"), false)]
    #[case(400, Some("application/problem+JSON"), false)]
    #[case(500, Some("application/problem+xml"), false)]
    #[case(500, Some("application/json"), true)]
    #[case(500, Some("APPLICATION/JSON"), true)]
    #[case(404, Some("application/json; charset=utf-8"), true)]
    #[case(500, Some("application/xml"), true)]
    #[case(500, Some("text/xml"), true)]
    // A `+json` / `+xml` subtype names a format the sender already has, which is
    // the case RFC 9457 §1 and §4 say is often the better answer. Each of these
    // was reported before the premise was audited.
    #[case(500, Some("application/hal+json"), false)]
    #[case(500, Some("application/vnd.api+json"), false)]
    #[case(500, Some("application/soap+xml"), false)]
    // Not a registered media type at all, so the rule has nothing to say.
    #[case(500, Some("text/problem+json"), false)]
    #[case(500, Some("text/json"), false)]
    #[case(500, Some("application/problem+xml; charset=utf-8"), false)]
    #[case(500, Some("text/html"), false)]
    #[case(500, Some("not-a-media"), false)]
    #[case(200, Some("application/json"), false)]
    #[case(399, Some("application/json"), false)]
    #[case(404, None, false)]
    fn check_cases(
        #[case] status: u16,
        #[case] content_type: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = ServerProblemDetailsContentType;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(
                &content_type
                    .map(|v| ("content-type", v))
                    .into_iter()
                    .collect::<Vec<_>>(),
            ),

            body_length: None,
            trailers: None,
        });

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        if expect_violation {
            assert!(v.is_some(), "expected a finding for {content_type:?}");
            let msg = v.unwrap().message;
            // Keyed on the clause that distinguishes this finding, not on the
            // wording of the advice around it.
            assert!(msg.contains("generic media type"), "{msg}");
            assert!(msg.contains(content_type.unwrap()), "{msg}");
        } else {
            assert!(
                v.is_none(),
                "unexpected finding for {content_type:?}: {v:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn scope_is_server() {
        let rule = ServerProblemDetailsContentType;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }

    /// Each published snippet, judged by this rule, must reach the verdict its
    /// label carries -- and at least one of them must actually produce the
    /// finding, so the guard cannot pass by never firing.
    #[test]
    fn published_examples_are_judged_by_this_rule() {
        use crate::rules::{Compliance, Rule as _};
        let rule = ServerProblemDetailsContentType;
        let mut saw_a_finding = false;

        for ex in rule.examples() {
            let mut lines = ex.snippet.lines();
            let status = lines
                .next()
                .and_then(|line| line.strip_prefix("HTTP/1.1 "))
                .and_then(|rest| rest.split_whitespace().next())
                .and_then(|code| code.parse::<u16>().ok())
                .unwrap_or_else(|| {
                    panic!(
                        "the first line of an example is its status line: {:?}",
                        ex.snippet
                    )
                });
            let headers: Vec<(&str, &str)> = lines
                .take_while(|l| !l.trim().is_empty())
                .map(|l| {
                    l.split_once(": ")
                        .unwrap_or_else(|| panic!("not a field line: {l:?}"))
                })
                .collect();

            let tx = crate::test_helpers::make_test_transaction_with_response(status, &headers);
            let v = rule.check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
            );
            match ex.compliance {
                Compliance::Compliant => assert!(v.is_none(), "{}: {v:?}", ex.snippet),
                Compliance::NonCompliant => {
                    assert!(v.is_some(), "{}", ex.snippet);
                    saw_a_finding = true;
                }
            }
        }
        assert!(saw_a_finding, "no published example reaches the finding");
    }
}
