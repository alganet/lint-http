// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct SemanticPostCreatesResource;

impl Rule for SemanticPostCreatesResource {
    fn id(&self) -> &'static str {
        "semantic_post_creates_resource"
    }

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

        // The sentence this rule enforces is in the POST method's own section, so the
        // method is the first gate. It is compared exactly: a request whose method is
        // `post` is a request with an unrecognized method, and §9.3.3 says nothing
        // about it. `client_request_method_token_valid` is the rule that reports it.
        // cite(RFC 9110 § 9.1): "The method token is case-sensitive because it might be used as a gateway to object-based systems with case-sensitive method names."
        if tx.request.method != "POST" {
            return None;
        }

        // What a POST did is stated by the status code the origin server chose, so
        // there is nothing for this rule to read until a response has arrived — which
        // is what `RuleScope::Server` declares.
        // cite(RFC 9110 § 9.3.3): "An origin server indicates response semantics by choosing an appropriate status code depending on the result of processing the POST request; almost all of the status codes defined by this specification could be received in a response to POST (the exceptions being 206 (Partial Content), 304 (Not Modified), and 416 (Range Not Satisfiable))."
        let resp = tx.response.as_ref()?;

        // §9.3.3's SHOULD opens on a condition nothing in a message states directly —
        // *"If one or more resources has been created on the origin server"*. The 201
        // is what makes it observable: the status's own definition says that is what
        // it indicates, so a server that chose it has asserted the condition holds.
        // No other status is read here. A 200 or a 204 answering a POST asserts no
        // creation, and §9.3.3 asks nothing of it — including when it carries a
        // `Location`, which is `server_redirect_status_and_location_validity`'s
        // finding on every status rather than this rule's on the 2xx ones.
        // cite(RFC 9110 § 15.3.2): "The 201 (Created) status code indicates that the request has been fulfilled and has resulted in one or more new resources being created."
        if resp.status != 201 {
            return None;
        }

        // Presence is the whole test, and the field's own status definition is what
        // makes presence the right question: the sentence below distinguishes exactly
        // the two states, received and not received. A value this rule cannot decode
        // is still a field the message carries, so nothing here reads the value —
        // whether it is a usable `URI-reference` is `server_location_header_uri_valid`'s
        // question. The lowercase key is the field name as §5.1 defines names.
        // cite(RFC 9110 § 5.1): "Field names are case-insensitive and ought to be registered within the "Hypertext Transfer Protocol (HTTP) Field Name Registry"; see Section 16.3.1."
        // cite(RFC 9110 § 15.3.2): "The primary resource created by the request is identified by either a Location header field in the response or, if no Location header field is received, by the target URI."
        //
        // Only the header section is read. §10.2.2 defines `Location` without
        // permitting it in trailers, and a sender may only generate a trailer field
        // where the field's own definition permits it — so a `Location` written after
        // the content is not the field §9.3.3 asks for.
        // cite(RFC 9110 § 6.5.1): "A sender MUST NOT generate a trailer field unless the sender knows the corresponding header field name's definition permits the field to be sent in trailers."
        if resp.headers.contains_key("location") {
            return None;
        }

        // The SHOULD, quoted whole so the identifier it asks for travels with the
        // condition that asks for it.
        // cite(RFC 9110 § 9.3.3): "If one or more resources has been created on the origin server as a result of successfully processing a POST request, the origin server SHOULD send a 201 (Created) response containing a Location header field that provides an identifier for the primary resource created (Section 10.2.2) and a representation that describes the status of the request while referring to the new resource(s)."
        // cite(RFC 9110 § 10.2.2): "For 201 (Created) responses, the Location value refers to the primary resource created by the request."
        //
        // §15.3.2's fallback is the *target URI*, and `tx.request.uri` is the
        // **request-target** — the same string only when the request-target is in
        // absolute-form. Over HTTP/1.1 it arrives in origin-form, where it is the
        // target URI's path and query and nothing more: the authority comes from
        // `Host` and the scheme from whether the connection was secured, which no
        // part of the message records. So the message names the request-target as
        // the request-target and says what §15.3.2 does with it, rather than
        // printing a path under the words "the target URI".
        // cite(RFC 9112 § 3.3): "The target URI is the request-target when the request-target is in absolute-form."
        // cite(RFC 9112 § 3.3): "Otherwise, the target URI's combined path and query component is the request-target."
        Some(Violation {
            rule: self.id().into(),
            severity: config.severity,
            message: format!(
                "201 Created response to a POST request carries no Location header field. \
                 RFC 9110 §9.3.3 asks an origin server that has created one or more resources \
                 to answer with a 201 containing a Location field that provides an identifier \
                 for the primary resource created, with a SHOULD. Nothing is malformed without \
                 it — RFC 9110 §15.3.2 says the primary resource created is then identified by \
                 the target URI, which this request addressed as '{}' — so what is missing is \
                 the identifier being stated rather than left to be inferred",
                tx.request.uri
            ),
        })
    }

    fn title(&self) -> Option<&'static str> {
        Some("A 201 that does not say what it created")
    }

    fn description(&self) -> &'static str {
        "RFC 9110 §9.3.3 asks an origin server that has created one or more resources while processing a `POST` request to send a `201 Created` response containing a `Location` header field that provides an identifier for the primary resource created. This rule reports a `201` answering a `POST` that carries no `Location`.\n\n**The status is the evidence for the SHOULD's condition.** The sentence opens *\"If one or more resources has been created on the origin server\"*, which nothing in a message states directly — but §15.3.2 defines the `201` as indicating exactly that, so a server that chose the status has already asserted the condition holds. No other status is read: a `200` or a `204` answering a `POST` asserts no creation, and §9.3.3 asks nothing of it.\n\n**Nothing is malformed without the field.** §15.3.2 says the primary resource created is identified *\"by either a Location header field in the response or, if no Location header field is received, by the target URI\"* — so a `201` with no `Location` does name the created resource, just not explicitly. The finding is that the identifier is left to be inferred, which is what the SHOULD buys.\n\n**The finding names the request-target, not the target URI.** The two are the same string only when the request-target is in absolute-form (RFC 9112 §3.3). Over HTTP/1.1 it arrives in origin-form, where it is the target URI's combined path and query and nothing more — the authority comes from `Host` and the scheme from whether the connection was secured, which no part of the message records. So the message prints what the request addressed and leaves the reconstruction to the reader who knows the connection.\n\n**The sentence is addressed to the origin server.** A capture taken between a client and a proxy cannot tell an origin server's `201` from one a gateway produced on its behalf, and nothing on the wire records which component chose the status. Read the finding as being about whichever one did.\n\n**Only presence is read.** Field names are case-insensitive (§5.1), so the field is found however it was written, and a value that cannot be decoded still counts as present — the message on the wire carries the field. Whether the value is a usable `URI-reference`, whether it is empty, and whether several field lines were sent are `server_location_header_uri_valid`'s questions. A `Location` in a trailer section is not counted: §6.5.1 permits a trailer field only where the field's own definition permits it, and §10.2.2 does not — so a `201` that writes its `Location` after the content is reported here for not carrying one, and by `message_trailer_fields_validity` for the `MUST NOT` it broke getting there.\n\n**Not reported: a `Location` on a `POST` response that is not a `201`.** This rule previously reported every other 2xx carrying the field, advising the sender to \"use 201 Created when a new resource is created\" — a claim about what the sender did that no sentence licenses, and one §10.2.2 declines to make by leaving the field's relationship to the response to *\"the combination of request method and status code semantics\"*. `server_redirect_status_and_location_validity` owns that finding, reports it as advice, and reports it on every status rather than only on the 2xx ones; its description names the `202 Accepted` carrying a status-monitor `Location` as the case that shows why it is advice and not a violation.\n\n**Not reported: a `PUT` that created a resource.** §9.3.4 requires the `201` there with a MUST and asks nothing about `Location`, because the target URI of a `PUT` is already the identifier of what it creates. The method is compared exactly, since §9.1 says the method token is case-sensitive: a request whose method is `post` is not a `POST` request, and `client_request_method_token_valid` is the rule that reports it."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("9.3.3"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.3",
                note: "POST: the SHOULD this rule enforces — an origin server that created one or more resources sends a 201 containing a Location field that provides an identifier for the primary resource created",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("15.3.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.2",
                note: "201 Created: the status indicates one or more new resources were created, which is what makes §9.3.3's condition observable, and the primary resource is identified by the Location field or, if none is received, by the target URI",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("10.2.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.2",
                note: "Location: on a 201 (Created) response the value refers to the primary resource created by the request. The field's relationship to any other status is left to \"the combination of request method and status code semantics\", which is why a Location on a non-201 is not reported here",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("9.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-9.1",
                note: "The method token is case-sensitive, which is why `POST` is matched exactly and a lowercase `post` is not a POST",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "POST /widgets HTTP/1.1\nHost: example.com\nContent-Type: application/json\nContent-Length: 17\n\n{\"name\":\"fidget\"}\n\nHTTP/1.1 201 Created\nLocation: /widgets/123\nContent-Type: application/json\n\n{\"id\":123}",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(no creation is claimed, so §9.3.3 asks for nothing)"),
                snippet: "POST /widgets HTTP/1.1\nHost: example.com\nContent-Type: application/json\nContent-Length: 17\n\n{\"name\":\"fidget\"}\n\nHTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"status\":\"ok\"}",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(the created resource is identified by the target URI, but not stated)"),
                snippet: "POST /widgets HTTP/1.1\nHost: example.com\nContent-Type: application/json\nContent-Length: 17\n\n{\"name\":\"fidget\"}\n\nHTTP/1.1 201 Created\nContent-Type: application/json\n\n{\"id\":123}",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &SemanticPostCreatesResource;

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tx(
        status: u16,
        headers: Vec<(&str, &str)>,
    ) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(status, &[]);
        tx.request.method = "POST".to_string();
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&headers);
        tx
    }

    fn run(tx: &crate::http_transaction::HttpTransaction) -> Option<Violation> {
        let rule = SemanticPostCreatesResource;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        rule.check_transaction(
            tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
    }

    #[test]
    fn id_and_scope() {
        let r = SemanticPostCreatesResource;
        assert_eq!(r.id(), "semantic_post_creates_resource");
        assert_eq!(r.scope(), crate::rules::RuleScope::Server);
    }

    #[rstest::rstest]
    #[case(201, vec![], true)]
    #[case(201, vec![("location", "/new")], false)]
    // A `Location` on a status that is not a 201 rests on no sentence in §9.3.3, and
    // `server_redirect_status_and_location_validity` reports it on every status.
    #[case(200, vec![("location", "/new")], false)]
    #[case(202, vec![("location", "/new")], false)]
    #[case(204, vec![("location", "/new")], false)]
    #[case(303, vec![("location", "/new")], false)]
    #[case(200, vec![], false)]
    #[case(204, vec![], false)]
    fn post_creation_cases(
        #[case] status: u16,
        #[case] headers: Vec<(&str, &str)>,
        #[case] expect_violation: bool,
    ) {
        let v = run(&make_tx(status, headers));
        assert_eq!(
            v.is_some(),
            expect_violation,
            "status {} produced {:?}",
            status,
            v
        );
    }

    #[test]
    fn location_header_is_found_however_it_is_written() {
        assert!(run(&make_tx(201, vec![("Location", "/new")])).is_none());
    }

    #[test]
    fn undecodable_location_value_counts_as_presence() {
        let mut tx = make_tx(201, vec![]);
        let mut hm = hyper::HeaderMap::new();
        hm.insert(
            "location",
            hyper::header::HeaderValue::from_bytes(&[0xff]).unwrap(),
        );
        tx.response.as_mut().unwrap().headers = hm;
        assert!(
            run(&tx).is_none(),
            "a value this rule cannot decode is still a field the message carries"
        );
    }

    #[test]
    fn several_location_field_lines_count_as_presence() {
        assert!(run(&make_tx(201, vec![("location", "/a"), ("location", "/b")])).is_none());
    }

    #[test]
    fn location_in_a_trailer_section_is_not_counted() {
        let mut tx = make_tx(201, vec![]);
        tx.response.as_mut().unwrap().trailers = Some(
            crate::test_helpers::make_headers_from_pairs(&[("location", "/widgets/123")]),
        );
        assert!(
            run(&tx).is_some(),
            "RFC 9110 §6.5.1 permits a trailer field only where the field's definition does"
        );
    }

    #[test]
    fn lowercase_post_is_not_a_post() {
        let mut tx = make_tx(201, vec![]);
        tx.request.method = "post".to_string();
        assert!(
            run(&tx).is_none(),
            "RFC 9110 §9.1: the method token is case-sensitive"
        );
    }

    #[test]
    fn non_post_requests_are_ignored() {
        let mut tx = make_tx(201, vec![]);
        tx.request.method = "PUT".to_string();
        assert!(run(&tx).is_none());
    }

    #[test]
    fn a_request_with_no_response_is_out_of_scope() {
        let mut tx = make_tx(201, vec![]);
        tx.response = None;
        assert!(run(&tx).is_none());
    }

    #[test]
    fn the_message_names_the_request_target_the_created_resource_falls_back_to() {
        let v = run(&make_tx(201, vec![])).expect("a 201 with no Location is the finding");
        assert!(
            v.message.contains("http://example/"),
            "message should name the request-target: {}",
            v.message
        );
    }

    /// Over HTTP/1.1 the request-target arrives in origin-form, and it is then the
    /// target URI's combined path and query rather than the target URI (RFC 9112
    /// §3.3). The message says "addressed as" for that reason; the default fixture
    /// carries an absolute-form target, so it does not exercise this on its own.
    #[test]
    fn an_origin_form_request_target_is_not_called_the_target_uri() {
        let mut tx = make_tx(201, vec![]);
        tx.request.uri = "/widgets".to_string();
        let v = run(&tx).expect("a 201 with no Location is the finding");
        assert!(
            v.message.contains("addressed as '/widgets'"),
            "message should name the request-target as addressed: {}",
            v.message
        );
        assert!(
            !v.message.contains("target URI ('/widgets')")
                && !v.message.contains("target URI (/widgets)"),
            "an origin-form request-target is not the target URI: {}",
            v.message
        );
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "semantic_post_creates_resource");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
