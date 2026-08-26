// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ContextFieldsDirection;

/// RFC 9110 § 10.1's five request context fields, each with the subject its
/// own section gives it — the clause the finding prints, so the report says
/// what the field is *for* rather than merely where it may not go.
//
// cite(RFC 9110 § 10.1): "The request header fields below provide additional information about the request context, including information about the user, user agent, and resource behind the request."
// cite(RFC 9110 § 10.1.1): "The "Expect" header field in a request indicates a certain set of behaviors (expectations) that need to be supported by the server in order to properly handle this request."
// cite(RFC 9110 § 10.1.2): "The "From" header field contains an Internet email address for a human user who controls the requesting user agent."
// cite(RFC 9110 § 10.1.3): "The "Referer" [sic] header field allows the user agent to specify a URI reference for the resource from which the target URI was obtained (i.e., the "referrer", though the field name is misspelled)."
// cite(RFC 9110 § 10.1.4): "The "TE" header field describes capabilities of the client with regard to transfer codings and trailer sections."
// cite(RFC 9110 § 10.1.5): "The "User-Agent" header field contains information about the user agent originating the request"
const REQUEST_CONTEXT_FIELDS: &[(&str, &str)] = &[
    (
        "expect",
        "behaviors the server must support to handle this request (§10.1.1)",
    ),
    (
        "from",
        "an email address for the human controlling the requesting user agent (§10.1.2)",
    ),
    (
        "referer",
        "the resource from which the request's target URI was obtained (§10.1.3)",
    ),
    (
        "te",
        "the client's capabilities regarding transfer codings and trailer sections (§10.1.4)",
    ),
    (
        "user-agent",
        "information about the user agent originating the request (§10.1.5)",
    ),
];

/// § 10.2's four response context fields, same shape.
//
// cite(RFC 9110 § 10.2): "The response header fields below provide additional information about the response, beyond what is implied by the status code, including information about the server, about the target resource, or about related resources."
// cite(RFC 9110 § 10.2.1): "The "Allow" header field lists the set of methods advertised as supported by the target resource."
// cite(RFC 9110 § 10.2.2): "The "Location" header field is used in some responses to refer to a specific resource in relation to the response."
// cite(RFC 9110 § 10.2.3): "Servers send the "Retry-After" header field to indicate how long the user agent ought to wait before making a follow-up request."
// cite(RFC 9110 § 10.2.4): "The "Server" header field contains information about the software used by the origin server to handle the request"
const RESPONSE_CONTEXT_FIELDS: &[(&str, &str)] = &[
    (
        "allow",
        "the set of methods supported by the target resource (§10.2.1)",
    ),
    (
        "location",
        "a specific resource in relation to the response (§10.2.2)",
    ),
    (
        "retry-after",
        "how long the user agent ought to wait before a follow-up request (§10.2.3)",
    ),
    (
        "server",
        "the software the origin server handled the request with (§10.2.4)",
    ),
];

impl Rule for ContextFieldsDirection {
    fn id(&self) -> &'static str {
        "context_fields_direction"
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

        // A response context field in a request, then a request context field
        // in a response. Each table is probed against the *other* direction
        // only — in its own direction the field is what its section says it
        // is, and its value is its own rule's question.
        let message = misdirected(
            &tx.request.headers,
            RESPONSE_CONTEXT_FIELDS,
            "Request",
            "response context field",
            "a request",
        )
        .or_else(|| {
            tx.response.as_ref().and_then(|resp| {
                misdirected(
                    &resp.headers,
                    REQUEST_CONTEXT_FIELDS,
                    "Response",
                    "request context field",
                    "a response",
                )
            })
        })?;

        Some(Violation {
            rule: self.id().into(),
            severity: config.severity,
            message,
        })
    }

    fn description(&self) -> &'static str {
        "Reports a message context field arriving in the direction it is not defined for: one of \
         RFC 9110 §10.1's five request context fields (`Expect`, `From`, `Referer`, `TE`, \
         `User-Agent`) in a response, or one of §10.2's four response context fields (`Allow`, \
         `Location`, `Retry-After`, `Server`) in a request.\
         \n\n\
         **The finding is advice, and its message says so.** §10 attaches no BCP 14 keyword to \
         the arrival — the split into *Request Context Fields* and *Response Context Fields* is \
         how the document says what each field is about, not a stated prohibition — so the \
         report is that the field states nothing where it was sent: each section's subject is a \
         fact about the other direction (`Server` is *\"information about the software used by \
         the origin server to handle the request\"*; `From` is the human controlling *\"the \
         requesting user agent\"*), and no definition gives the field a meaning elsewhere. The \
         finding names the field's own subject rather than inventing a modal, and the shipped \
         severity is `info`.\
         \n\n\
         **This is the placement question, not the value question.** Each of the nine fields has \
         a rule reading its value in the direction it is defined for, and each of those rules \
         correctly declines the other direction — there is no sentence to measure the value \
         against there. That decline is what left the arrival itself unreported: a `Server` \
         field in a request was walked past by every rule in the catalogue.\
         \n\n\
         **`TE` is also a connection-specific field**, so over HTTP/2 and HTTP/3 \
         `message_no_connection_specific_fields` reports its presence in either direction under \
         a different and stronger sentence (RFC 9113 §8.2.2). The two findings answer different \
         questions — that one is about hop-by-hop fields surviving into a multiplexed protocol, \
         this one is about a field defined for the other direction — and only this one exists \
         over HTTP/1.1.\
         \n\n\
         **Only header sections are read.** A context field in a *trailer* section is a \
         different fault with its own sentences, and `message_trailer_fields_validity` owns \
         them.\
         \n\n\
         **Fields defined for both directions are not here.** `Content-Location` is defined in \
         both (§8.7 gives the request side its own meaning), and the general representation \
         fields travel with content in either direction, so nothing about them is a placement \
         fault."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("10.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1",
                note: "Request Context Fields — the five fields whose subjects are the user, \
                       user agent and resource behind a request; the section split this rule \
                       reads the direction from",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("10.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2",
                note: "Response Context Fields — the four whose subjects are the server, the \
                       target resource and related resources. No sentence in either section \
                       forbids the misdirection, which is why the finding is advice",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "GET / HTTP/1.1\nHost: example.com\nUser-Agent: curl/8.0\n\nHTTP/1.1 200 OK\nServer: httpd/2.4\nAllow: GET, HEAD",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(Server is response context — it says nothing in a request)"),
                snippet: "GET / HTTP/1.1\nHost: example.com\nServer: httpd/2.4",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(User-Agent is request context — it says nothing in a response)"),
                snippet: "HTTP/1.1 200 OK\nUser-Agent: curl/8.0",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ContextFieldsDirection;

/// The first table field present in this section, reported with its own
/// section's subject.
///
/// The wording invents no modal on purpose: §10 states none about the
/// arrival, and the defect this rule exists to report is a field that says
/// nothing where it was sent — so the message says what the field is *for*
/// and where it arrived, and calls itself advice.
fn misdirected(
    headers: &hyper::HeaderMap,
    table: &[(&str, &str)],
    side: &str,
    class: &str,
    wrong_home: &str,
) -> Option<String> {
    for (name, subject) in table {
        if headers.contains_key(*name) {
            return Some(format!(
                "{side} carries '{name}', a {class}: its subject is {subject}, and no \
                 definition gives the field a meaning in {wrong_home}. RFC 9110 §10 states no \
                 requirement about the arrival, so this is advice — the field states nothing \
                 where it was sent"
            ));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn cfg() -> crate::config::Config {
        crate::test_helpers::make_test_config_with_enabled_rules(&["context_fields_direction"])
    }

    fn run(tx: &crate::http_transaction::HttpTransaction) -> Option<String> {
        ContextFieldsDirection
            .check_transaction(
                tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg(),
            )
            .map(|v| v.message)
    }

    /// Each field in its own direction draws nothing — that is the direction
    /// its value rule reads it in.
    #[test]
    fn fields_in_their_own_direction_draw_nothing() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("host", "example.com"),
            ("user-agent", "curl/8.0"),
            ("from", "a@example.com"),
            ("referer", "https://example.com/"),
            ("te", "trailers"),
            ("expect", "100-continue"),
        ]);
        tx.response.as_mut().expect("a response").headers =
            crate::test_helpers::make_headers_from_pairs(&[
                ("server", "httpd/2.4"),
                ("allow", "GET, HEAD"),
                ("retry-after", "120"),
                ("location", "/other"),
            ]);
        assert_eq!(run(&tx), None);
    }

    /// Exact message once: the side, the class, the field's own subject, and
    /// the sentence calling itself advice.
    #[test]
    fn a_server_field_in_a_request_is_reported_as_advice() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("host", "example.com"),
            ("server", "httpd/2.4"),
        ]);
        assert_eq!(
            run(&tx).expect("reported"),
            "Request carries 'server', a response context field: its subject is the software \
             the origin server handled the request with (§10.2.4), and no definition gives the \
             field a meaning in a request. RFC 9110 §10 states no requirement about the \
             arrival, so this is advice — the field states nothing where it was sent"
        );
    }

    /// Every table row fires in the wrong direction — the table is data, and
    /// a row that never fired is a row a typo can disable.
    #[rstest]
    #[case("allow", "GET")]
    #[case("location", "/x")]
    #[case("retry-after", "120")]
    #[case("server", "a")]
    fn every_response_context_row_fires_in_a_request(#[case] name: &str, #[case] value: &str) {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("host", "example.com"), (name, value)]);
        let msg = run(&tx).unwrap_or_else(|| panic!("{name} not reported"));
        assert!(
            msg.starts_with(&format!("Request carries '{name}'")),
            "{msg}"
        );
    }

    #[rstest]
    #[case("expect", "100-continue")]
    #[case("from", "a@example.com")]
    #[case("referer", "/a")]
    #[case("te", "trailers")]
    #[case("user-agent", "curl/8.0")]
    fn every_request_context_row_fires_in_a_response(#[case] name: &str, #[case] value: &str) {
        let mut tx =
            crate::test_helpers::make_test_transaction_with_response(200, &[(name, value)]);
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("host", "example.com")]);
        let msg = run(&tx).unwrap_or_else(|| panic!("{name} not reported"));
        assert!(
            msg.starts_with(&format!("Response carries '{name}'")),
            "{msg}"
        );
    }

    /// The rule's own hazard, asserted the `proxy_connection_discouraged`
    /// way: §10 states no BCP 14 keyword about the arrival, so the message must
    /// not invent one.
    #[test]
    fn the_finding_invents_no_modal() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("host", "example.com"),
            ("server", "a"),
        ]);
        let msg = run(&tx).expect("reported");
        for modal in ["MUST", "SHOULD", "REQUIRED", "SHALL", "RECOMMENDED"] {
            assert!(!msg.contains(modal), "{modal} invented in: {msg}");
        }
        assert!(msg.contains("advice"), "{msg}");
    }

    #[test]
    fn shipped_severity_is_advisory() {
        let s = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../config_example.toml"),
        )
        .expect("config_example.toml must be readable");
        let section = s
            .split("[rules.context_fields_direction]")
            .nth(1)
            .expect("rule must appear in config_example.toml");
        let shipped = section
            .lines()
            .take_while(|l| !l.starts_with('['))
            .find_map(|l| l.strip_prefix("severity = "))
            .expect("rule must ship a severity");
        assert_eq!(shipped.trim(), "\"info\"");
    }

    #[test]
    fn scope_is_both() {
        assert_eq!(
            ContextFieldsDirection.scope(),
            crate::rules::RuleScope::Both
        );
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "context_fields_direction");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
