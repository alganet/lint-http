// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::helpers::headers::{combined_field_value_as_written, shown_in_finding, trim_ows};
use crate::helpers::websocket::version_production_defect;
use crate::lint::Violation;
use crate::rules::Rule;

pub struct SecWebsocketVersionAdvertised;

impl SecWebsocketVersionAdvertised {
    /// The versions this response advertises, in the order it wrote them, with
    /// the null elements RFC 2616's list construct permits already dropped.
    ///
    /// § 4.3 imports that notation by name for this whole grammar, so
    /// `Sec-WebSocket-Version: 13,,8` advertises two versions and conforms —
    /// where RFC 9110 § 5.6.1.1 would make the empty member a sender's defect.
    /// The `1#` floor is what a value of only commas fails, and the caller
    /// reports that separately.
    ///
    /// cite(RFC 6455 § 4.3): "This section is using ABNF syntax/rules from Section 2.1 of [RFC2616], including the "implied *LWS rule"."
    /// cite(RFC 2616 § 2.1): "Wherever this construct is used, null elements are allowed, but do not contribute to the count of elements present."
    fn advertised(value: &str) -> Vec<&str> {
        value
            .split(',')
            .map(trim_ows)
            .filter(|member| !member.is_empty())
            .collect()
    }

    /// What is wrong with the response's field, if anything.
    ///
    /// The value is read as the server wrote it, all of the section's lines
    /// joined — which § 4.4 illustrates in as many words, printing the same
    /// advertisement as one line and as two.
    ///
    /// cite(RFC 6455 § 4.3, label: Sec-WebSocket-Version-Server): "Sec-WebSocket-Version-Server = 1#version"
    /// cite(RFC 6455 § 4.4): "If the server doesn't support the requested version, it MUST respond with a |Sec-WebSocket-Version| header field (or multiple |Sec-WebSocket-Version| header fields) containing all versions it is willing to use."
    fn defect(resp_headers: &hyper::HeaderMap, requested: Option<&str>) -> Option<String> {
        let value = combined_field_value_as_written(resp_headers, "sec-websocket-version")?;
        let advertised = Self::advertised(&value);

        // `1#version` needs one element that is not null, which is the one place
        // RFC 2616's list construct is stricter than it first reads.
        //
        // cite(RFC 2616 § 2.1): "Therefore, where at least one element is required, at least one non-null element MUST be present."
        if advertised.is_empty() {
            return Some(format!(
                "advertises no version: '{}'. The field is `1#version` in a response, and the list \
                 construct this grammar uses allows null elements but requires at least one that \
                 is not",
                shown_in_finding(&value)
            ));
        }

        for member in &advertised {
            if let Some(defect) = version_production_defect(member) {
                return Some(format!(
                    "advertises '{}', which derives from no `version`: {defect}",
                    shown_in_finding(member)
                ));
            }
        }

        // The field is in the response *because* the requested version was not
        // one the server understood, and § 11.3.5 says so in the sentence that
        // defines when a server sends it at all. So a list holding the requested
        // version says both things about one handshake: that the server did not
        // understand it, and that it will speak it. The comparison is exact —
        // both sides derive from `version`, which is DIGITs, so there is no case
        // to fold and no leading zero to normalise away.
        //
        // cite(RFC 6455 § 11.3.5): "The |Sec-WebSocket-Version| header field is also sent from the server to the client on WebSocket handshake error, when the version received from the client does not match a version understood by the server."
        // cite(RFC 6455 § 11.3.5): "In such a case, the header field includes the protocol version(s) supported by the server."
        if let Some(requested) = requested {
            if advertised.contains(&requested) {
                return Some(format!(
                    "advertises '{}', which includes the version the request asked for ('{}'): the \
                     field is in a response because the version received from the client did not \
                     match one the server understood, so listing it says both that the server does \
                     not speak it and that it does",
                    shown_in_finding(&value),
                    shown_in_finding(requested)
                ));
            }
        }

        None
    }
}

impl Rule for SecWebsocketVersionAdvertised {
    fn id(&self) -> &'static str {
        "sec_websocket_version_advertised"
    }

    /// The `-Server` suffix is the document's own scoping, and § 4.3 states what
    /// it means: the production is used in responses only. The evidence is a
    /// field the server wrote, so a capture whose upstream never answered has
    /// nothing to measure.
    ///
    /// cite(RFC 6455 § 4.3): "ABNF rules with the "-Client" suffix in the name are only used in requests sent by the client to the server; ABNF rules with the "-Server" suffix in the name are only used in responses sent by the server to the client."
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let resp = tx.response.as_ref()?;

        // Only an opening handshake's answer is measured, and the shared reader
        // is what decides that a request is one — the same gate the two rules
        // reading the rest of this handshake use, so a message that is a
        // handshake to them and not to this rule is not a gap anyone has to
        // find. Above HTTP/1.x the handshake is an extended CONNECT and this
        // field is not part of it.
        crate::helpers::websocket::opening_handshake_version(&tx.request)?;

        // The request's version is read as one value: `Sec-WebSocket-Version-Client
        // = version` is a single `version`, not a list, so a request carrying
        // two field lines has written something this grammar does not derive —
        // and `sec_websocket_headers_consistent` is the rule that says
        // so. Here the joined value simply matches no member, which leaves the
        // contradiction finding unstated rather than falsely stated.
        let requested =
            combined_field_value_as_written(&tx.request.headers, "sec-websocket-version")
                .map(|raw| trim_ows(&raw).to_string());

        let message = Self::defect(&resp.headers, requested.as_deref())?;

        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
        Some(self.violation(
            config.severity,
            format!("The response to a WebSocket opening handshake {message}"),
        ))
    }

    fn description(&self) -> &'static str {
        "Reads the `Sec-WebSocket-Version` a **response** carries — the versions a server advertises when it will not speak the one the client asked for.\n\n**Two fields share a name and neither shares a production.** RFC 6455 §4.3 prints `Sec-WebSocket-Version-Client = version` for the request and `Sec-WebSocket-Version-Server = 1#version` for the response, and says what the suffixes mean: *ABNF rules with the \"-Client\" suffix in the name are only used in requests sent by the client to the server; ABNF rules with the \"-Server\" suffix in the name are only used in responses sent by the server to the client.* So the response's field is a **list** where the request's is one value, and `sec_websocket_headers_consistent` — which reads the request — measures the other production.\n\n**The notation is RFC 2616's, which §4.3 imports by name.** A null list element therefore conforms: `Sec-WebSocket-Version: 13,,8` advertises two versions, where RFC 9110 §5.6.1.1 would make the empty member a sender's defect. What `1#` requires is *at least one non-null element*, so a value that is only commas advertises nothing and is the finding instead. Several field lines in one section are one list — §4.4 prints the same advertisement both ways and calls them the same response.\n\n**The second finding is the field's own reason for existing.** §11.3.5: the field *is also sent from the server to the client on WebSocket handshake error, when the version received from the client does not match a version understood by the server*, and *In such a case, the header field includes the protocol version(s) supported by the server.* A response advertising a list that **contains the version the request asked for** says both things about one handshake: that the server did not understand that version, and that it will speak it. The comparison is exact, because both sides derive from `version`, which is DIGITs — no case to fold, no leading zero to normalise, since the production admits none.\n\n**Not reported: that the field is missing.** §4.4's MUST is conditional — *If the server doesn't support the requested version, it MUST respond with a |Sec-WebSocket-Version| header field … containing all versions it is willing to use* — and its antecedent is a fact about the server, not about the message. A non-101 answer to a handshake can be a refusal for any of the reasons §4.2.2 lists (a 401, a 3xx, a 403, a 404, a 426), and no field in the exchange says which. Reporting every one of them for a missing advertisement would be reading the antecedent off the consequent.\n\n**Not reported: which versions the list should hold, or a `101` that carries one.** The set a server is *willing to use* is the server's own; nothing in the capture disagrees with it. And §11.3.5 describes when the field is sent rather than forbidding it elsewhere, so a `101` carrying it is odd and not a violation — `websocket_handshake_valid` declines the version question on a `101` for its own reason, which is that §4.2.2 aborts a handshake only for a version *that does not match a version understood by the server*, a fact a `101` is that server asserting.\n\nScope: this rule reads a response's header section, and only where the request was RFC 6455's opening handshake — the same shared gate the other two handshake rules use. Above HTTP/1.x the handshake is an extended CONNECT (RFC 8441, RFC 9220) and this field is not part of it. A value carrying an octet outside US-ASCII is measured rather than skipped: it reaches the production that excludes it and is reported there."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 6455",
                section: Some("4.3"),
                url: "https://www.rfc-editor.org/rfc/rfc6455.html#section-4.3",
                note: "Collected ABNF — `Sec-WebSocket-Version-Server = 1#version`, the `version` \
                       production under it, the suffix convention that makes this field the \
                       response's, and the note that the notation is RFC 2616's",
            },
            crate::rules::SpecRef {
                spec: "RFC 2616",
                section: Some("2.1"),
                url: "https://www.rfc-editor.org/rfc/rfc2616.html#section-2.1",
                note: "Augmented BNF — the `#rule` §4.3 imports: null elements are allowed (RFC \
                       9110 §5.6.1.1 forbids them) and `1#` requires one that is not. Obsolete \
                       and correct: the current document is what sends the reader here",
            },
            crate::rules::SpecRef {
                spec: "RFC 6455",
                section: Some("4.4"),
                url: "https://www.rfc-editor.org/rfc/rfc6455.html#section-4.4",
                note:
                    "Supporting Multiple Versions — the conditional MUST whose antecedent is the \
                       server's own state, and the worked example printing one advertisement as \
                       one field line and as two",
            },
            crate::rules::SpecRef {
                spec: "RFC 6455",
                section: Some("11.3.5"),
                url: "https://www.rfc-editor.org/rfc/rfc6455.html#section-11.3.5",
                note: "The field's registration — when a server sends it, and that it holds the \
                       versions the server supports, which is what a list holding the requested \
                       one contradicts",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("§4.4's own worked exchange"),
                snippet: "GET /chat HTTP/1.1\nHost: server.example.com\nUpgrade: websocket\nConnection: Upgrade\nSec-WebSocket-Version: 25\n\nHTTP/1.1 400 Bad Request\nSec-WebSocket-Version: 13, 8, 7",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("The same advertisement on two field lines, which §4.4 also prints"),
                snippet: "GET /chat HTTP/1.1\nHost: server.example.com\nUpgrade: websocket\nConnection: Upgrade\nSec-WebSocket-Version: 25\n\nHTTP/1.1 400 Bad Request\nSec-WebSocket-Version: 13\nSec-WebSocket-Version: 8, 7",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("A member deriving from no `version` — the production admits no leading zero"),
                snippet: "GET /chat HTTP/1.1\nHost: server.example.com\nUpgrade: websocket\nConnection: Upgrade\nSec-WebSocket-Version: 25\n\nHTTP/1.1 400 Bad Request\nSec-WebSocket-Version: 013",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("The advertisement holds the version the request asked for"),
                snippet: "GET /chat HTTP/1.1\nHost: server.example.com\nUpgrade: websocket\nConnection: Upgrade\nSec-WebSocket-Version: 25\n\nHTTP/1.1 400 Bad Request\nSec-WebSocket-Version: 13, 25",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &SecWebsocketVersionAdvertised;

#[cfg(test)]
mod tests {
    use super::*;

    use hyper::header::{HeaderName, HeaderValue};
    use rstest::rstest;

    /// A handshake request carrying `requested`, answered by `status` with the
    /// given `Sec-WebSocket-Version` response lines.
    fn exchange(requested: Option<&str>, status: u16, lines: &[&[u8]]) -> Option<Violation> {
        let rule = SecWebsocketVersionAdvertised;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(status, &[]);
        tx.request.method = "GET".into();
        tx.request.version = "HTTP/1.1".into();
        let mut req = crate::test_helpers::make_headers_from_pairs(&[
            ("upgrade", "websocket"),
            ("connection", "Upgrade"),
        ]);
        if let Some(requested) = requested {
            req.append(
                HeaderName::from_static("sec-websocket-version"),
                HeaderValue::from_str(requested).expect("field value"),
            );
        }
        tx.request.headers = req;

        let mut hm = hyper::HeaderMap::new();
        for line in lines {
            hm.append(
                HeaderName::from_static("sec-websocket-version"),
                HeaderValue::from_bytes(line).expect("field value"),
            );
        }
        tx.response.as_mut().expect("response").headers = hm;

        rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
    }

    /// §4.4's own worked exchange, in both spellings it prints.
    #[test]
    fn the_sections_own_exchange_is_clean_however_many_lines_carry_it() {
        assert!(exchange(Some("25"), 400, &[b"13, 8, 7"]).is_none());
        assert!(exchange(Some("25"), 400, &[b"13" as &[u8], b"8, 7"]).is_none());
    }

    /// The null elements RFC 2616's list construct allows.
    #[rstest]
    #[case(b"13,,8")]
    #[case(b",13")]
    #[case(b"13,")]
    #[case(b"13, , 8")]
    fn a_null_element_is_allowed_where_this_grammar_is_rfc_2616s(#[case] value: &[u8]) {
        let v = exchange(Some("25"), 400, &[value]);
        assert!(v.is_none(), "{value:?}: {v:?}");
    }

    /// And `1#` is what a value of only null elements fails.
    #[rstest]
    #[case(b"")]
    #[case(b",")]
    #[case(b" , ")]
    fn a_list_of_only_null_elements_advertises_nothing(#[case] value: &[u8]) {
        let v = exchange(Some("25"), 400, &[value]).expect("violation");
        assert!(v.message.contains("advertises no version"), "{}", v.message);
    }

    /// Each member is a `version`, and the finding names the member rather than
    /// the list, since that is the one an operator has to go and look at.
    #[rstest]
    #[case(b"013", "leading zero")]
    #[case(b"256", "above 255")]
    #[case(b"13, 8x", "DIGITs alone")]
    #[case(b"1234", "no alternative of `version` is longer than three digits")]
    #[case(b"13, \xe9", "DIGITs alone")]
    fn a_member_deriving_from_no_version_is_reported(#[case] value: &[u8], #[case] expected: &str) {
        let v = exchange(Some("25"), 400, &[value]).expect("violation");
        assert!(
            v.message.contains("derives from no `version`"),
            "{}",
            v.message
        );
        assert!(v.message.contains(expected), "{}", v.message);
    }

    /// The field is in the response because the requested version was not
    /// understood, so a list holding it contradicts the reason it is there.
    #[rstest]
    #[case("25", b"13, 25")]
    #[case("13", b"13")]
    #[case("8", b"13, 8, 7")]
    fn advertising_the_requested_version_contradicts_the_field(
        #[case] requested: &str,
        #[case] advertised: &[u8],
    ) {
        let v = exchange(Some(requested), 400, &[advertised]).expect("violation");
        assert!(
            v.message
                .contains("includes the version the request asked for"),
            "{}",
            v.message
        );
    }

    /// A request with no version of its own leaves that comparison unstated
    /// rather than falsely stated — there is nothing for the list to contradict.
    #[test]
    fn a_request_naming_no_version_is_not_compared_against() {
        assert!(exchange(None, 400, &[b"13, 8, 7"]).is_none());
    }

    /// §4.4's MUST is conditional on a fact about the server, so a refusal
    /// carrying no advertisement is not this rule's finding.
    #[rstest]
    #[case(400)]
    #[case(426)]
    #[case(101)]
    fn a_response_with_no_such_field_is_not_measured(#[case] status: u16) {
        assert!(exchange(Some("25"), status, &[]).is_none());
    }

    /// Only an opening handshake's answer is measured, and the shared gate is
    /// what decides that. A `POST` carrying the same fields is some other
    /// exchange, and the field in its response is not this production's.
    #[test]
    fn a_response_to_something_that_is_not_a_handshake_is_not_measured() {
        let rule = SecWebsocketVersionAdvertised;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(400, &[]);
        tx.request.method = "POST".into();
        tx.request.version = "HTTP/1.1".into();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("upgrade", "websocket"),
            ("connection", "Upgrade"),
            ("sec-websocket-version", "25"),
        ]);
        tx.response.as_mut().expect("response").headers =
            crate::test_helpers::make_headers_from_pairs(&[("sec-websocket-version", "013")]);
        assert!(rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
            )
            .is_none());
    }

    /// Every published snippet, run as the exchange it prints.
    #[test]
    fn published_examples_agree_with_the_rule() {
        use crate::rules::{Compliance, Rule as _};
        let rule = SecWebsocketVersionAdvertised;
        for ex in rule.examples() {
            let (request, response) = ex
                .snippet
                .split_once("\n\n")
                .expect("every example writes both halves of the exchange");
            let requested = request
                .lines()
                .find_map(|l| l.strip_prefix("Sec-WebSocket-Version: "));
            let lines: Vec<&[u8]> = response
                .lines()
                .filter_map(|l| l.strip_prefix("Sec-WebSocket-Version:"))
                .map(|v| v.strip_prefix(' ').unwrap_or(v).as_bytes())
                .collect();
            let status: u16 = response
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|s| s.parse().ok())
                .expect("a status line names a status code");

            let v = exchange(requested, status, &lines);
            match ex.compliance {
                Compliance::Compliant => assert!(v.is_none(), "{}: {v:?}", ex.snippet),
                Compliance::NonCompliant => assert!(v.is_some(), "{}", ex.snippet),
            }
        }
    }

    #[test]
    fn scope_is_server() {
        use crate::rules::Rule as _;
        assert_eq!(
            SecWebsocketVersionAdvertised.scope(),
            crate::rules::RuleScope::Server
        );
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "sec_websocket_version_advertised");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
