// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::helpers::headers::{
    combined_field_value_as_written, describe_octet, is_nominated_by_connection,
    sender_list_members, shown_in_finding, trim_ows,
};
use crate::helpers::websocket::{sec_websocket_key_defect, version_production_defect};
use crate::lint::Violation;
use crate::rules::Rule;

pub struct SecWebsocketHeadersConsistent;

impl SecWebsocketHeadersConsistent {
    /// The `Connection` half of the handshake: the field has to be there and it has
    /// to name `Upgrade`.
    ///
    /// The nomination question is `Connection`'s own, asked here of the one field
    /// name every `Upgrade` request has to name; the shared predicate is what knows
    /// that a `connection-option` is a field name and therefore compared without
    /// case. The lines are joined before it looks, because `Connection` is one list
    /// however many lines carry it.
    // cite(RFC 6455 § 4.1): "The request MUST contain a |Connection| header field whose value MUST include the "Upgrade" token."
    // cite(RFC 6455 § 4.2.1): "A |Connection| header field that includes the token "Upgrade", treated as an ASCII case-insensitive value."
    fn connection_defect(headers: &hyper::HeaderMap) -> Option<String> {
        let Some(value) = combined_field_value_as_written(headers, "connection") else {
            return Some(
                "the request carries no Connection header field, so it names no connection-option \
                 at all"
                    .into(),
            );
        };
        if is_nominated_by_connection("upgrade", Some(&value)) {
            return None;
        }
        Some(format!(
            "its Connection header field is `{}`, which does not include the Upgrade token",
            shown_in_finding(&value)
        ))
    }

    /// The `Sec-WebSocket-Version` half.
    ///
    /// Two questions in one place because the second only makes sense after the
    /// first: whether the value derives from `version`, and then whether the version
    /// it names is the one this document defines.
    // cite(RFC 6455 § 4.1): "The request MUST include a header field with the name |Sec-WebSocket-Version|.  The value of this header field MUST be 13."
    fn version_defect(headers: &hyper::HeaderMap) -> Option<String> {
        // The lines are joined before the value is read, and joining them is what
        // makes a second one visible: the client's field is one `version` and the
        // list form belongs to the server, which is how a server answers with the
        // versions it will speak. Two `Sec-WebSocket-Version` lines in a request
        // therefore derive from nothing, and reading only the first would call the
        // message clean.
        // cite(RFC 6455 § 4.3, label: Sec-WebSocket-Version-Server): "Sec-WebSocket-Version-Server = 1#version"
        let Some(raw) = combined_field_value_as_written(headers, "sec-websocket-version") else {
            return Some("the request carries no Sec-WebSocket-Version header field".into());
        };
        let value = trim_ows(&raw);
        if let Some(defect) = version_production_defect(value) {
            return Some(format!(
                "its Sec-WebSocket-Version is `{}`, which derives from no `version`: {}",
                shown_in_finding(value),
                defect
            ));
        }
        if value == "13" {
            return None;
        }
        // Not "invalid", because § 4.4 prints a request exactly like this one as its
        // illustration of version advertisement -- `Sec-WebSocket-Version: 25`, answered
        // with a 400 listing what the server will speak. What the value settles is
        // which protocol this handshake is for, and this document defines one of them.
        // cite(RFC 6455 § 4.4): "a client can initially request the version of the WebSocket Protocol that it prefers (which doesn't necessarily have to be the latest supported by the client)"
        // cite(RFC 6455 § 4.4): "If the server doesn't support the requested version, it MUST respond with a |Sec-WebSocket-Version| header field (or multiple |Sec-WebSocket-Version| header fields) containing all versions it is willing to use."
        Some(format!(
            "its Sec-WebSocket-Version is `{}`, so it is not a handshake for the version this \
             document defines; RFC 6455 § 4.4 makes that a version advertisement, and the \
             answer it asks a server for is a 400 carrying the versions the server will speak",
            shown_in_finding(value)
        ))
    }

    /// The `Sec-WebSocket-Key` half.
    ///
    /// What is wrong with the value is asked of the production's owner, which is
    /// also what `Sec-WebSocket-Accept` is derived through -- so the handshake is
    /// judged from one reading of the key rather than two.
    // cite(RFC 6455 § 4.1): "The request MUST include a header field with the name |Sec-WebSocket-Key|."
    fn key_defect(headers: &hyper::HeaderMap) -> Option<String> {
        let Some(raw) = combined_field_value_as_written(headers, "sec-websocket-key") else {
            return Some("the request carries no Sec-WebSocket-Key header field".into());
        };
        let defect = sec_websocket_key_defect(&raw)?;
        Some(format!(
            "its Sec-WebSocket-Key is `{}`, which is not the nonce the field is defined as: {}",
            shown_in_finding(trim_ows(&raw)),
            defect
        ))
    }

    /// The optional `Sec-WebSocket-Protocol`, which is two MUSTs about its members
    /// rather than one about the field.
    ///
    /// The members are walked without the empty-element filter every other list in
    /// this rule gets, and that is the point: `1#token` has a floor, the sentence
    /// beside it says each element is a non-empty string, and a filter that drops
    /// empty members answers both questions before they are asked. The alphabet the
    /// sentence spells out -- U+0021 to U+007E less the separators -- is `token`,
    /// which is what the ABNF it hands off to says in one word.
    ///
    /// `[RFC2616]` inside the quote is the document's own wording and stays byte
    /// exact; the definition it resolves to today is cited beside it.
    // cite(RFC 6455 § 4.1): "The elements that comprise this value MUST be non-empty strings with characters in the range U+0021 to U+007E not including separator characters as defined in [RFC2616] and MUST all be unique strings."
    // cite(RFC 6455 § 4.1): "The ABNF for the value of this header field is 1#token, where the definitions of constructs and rules are as given in [RFC2616]."
    // cite(RFC 6455 § 4.3, label: Sec-WebSocket-Protocol): "Sec-WebSocket-Protocol-Client = 1#token"
    // cite(RFC 9110 § 5.6.2): "token = 1*tchar tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA"
    fn subprotocol_defect(headers: &hyper::HeaderMap) -> Option<String> {
        let raw = combined_field_value_as_written(headers, "sec-websocket-protocol")?;
        let members: Vec<&str> = sender_list_members(&raw).collect();

        // The floor, which a field carrying only separators reaches without being
        // empty: `1#token` needs one element and `,` supplies none.
        // cite(RFC 9110 § 5.6.1.2): "In contrast, the following values would be invalid, since at least one non-empty element is required by the example-list production"
        if members.iter().all(|m| m.is_empty()) {
            return Some(format!(
                "its Sec-WebSocket-Protocol is `{}`, and `1#token` needs one subprotocol name",
                shown_in_finding(trim_ows(&raw))
            ));
        }
        for member in &members {
            if member.is_empty() {
                return Some(format!(
                    "its Sec-WebSocket-Protocol is `{}`, which has an empty element, and every \
                     element of this list is required to be a non-empty string",
                    shown_in_finding(trim_ows(&raw))
                ));
            }
            if let Some(c) = crate::helpers::token::find_invalid_token_char(member) {
                return Some(format!(
                    "its Sec-WebSocket-Protocol names the subprotocol `{}`, which holds {} — \
                     outside the characters this field's elements are spelled from",
                    shown_in_finding(member),
                    describe_octet(c as u8)
                ));
            }
        }
        // "unique strings", and the sentence says nothing about case: two spellings
        // of one name are two strings, so the comparison is of what was written.
        for (i, member) in members.iter().enumerate() {
            if members[..i].contains(member) {
                return Some(format!(
                    "its Sec-WebSocket-Protocol names the subprotocol `{}` more than once, and \
                     the elements of this list are required to be unique",
                    shown_in_finding(member)
                ));
            }
        }
        None
    }
}

impl Rule for SecWebsocketHeadersConsistent {
    fn id(&self) -> &'static str {
        "sec_websocket_headers_consistent"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Option<Violation> {
        let req = &tx.request;

        // Which captured messages are this document's opening handshake — the
        // method, the `Upgrade` keyword and the messaging syntax — is asked of the
        // shared gate, because `websocket_handshake_valid` measures the
        // server's half of the same exchange and the two rules have to agree on
        // which exchanges those are. The version it returns is read below: the
        // second half of the sentence the method comes from is a finding, and it is
        // this rule's.
        let version = crate::helpers::websocket::opening_handshake_version(req)?;

        // Every gate above ends the rule, and reading the configuration is several
        // map probes and a hash of the id -- so only a request about to be measured
        // pays for it.
        let violation = |message: String| {
            Some(Violation {
                rule: self.id().into(),
                severity: ctx.severity,
                message,
            })
        };

        // The other half of the sentence the method gate quotes, and the half nobody
        // in this catalogue was reading. The section describing how a server reads
        // this handshake opens its list with the same requirement, and a server that
        // finds the description unmatched is told to stop and answer with an error
        // status -- so a `GET / HTTP/1.0` carrying `Upgrade: websocket` is a
        // handshake that cannot succeed.
        // cite(RFC 6455 § 4.2.1): "An HTTP/1.1 or higher GET request"
        // cite(RFC 6455 § 4.2.1): "the server MUST stop processing the client's handshake and return an HTTP response with an appropriate error code (such as 400 Bad Request)"
        if (version.major, version.minor) < (1, 1) {
            return violation(format!(
                "This WebSocket opening handshake is sent over {version}, and RFC 6455 § 4.1 \
                 requires the request's HTTP version to be at least 1.1"
            ));
        }

        // The four remaining requirements, in the order § 4.1's list states them --
        // items 6, 7, 9 and 10, with the `Origin` of item 8 declined above. One
        // message carries one finding, so the first defect is the one reported, and
        // taking the document's order rather than a convenient one means the finding
        // an operator sees first is the one the list reaches first.
        let defect = [
            Self::connection_defect(&req.headers),
            Self::key_defect(&req.headers),
            Self::version_defect(&req.headers),
            Self::subprotocol_defect(&req.headers),
        ]
        .into_iter()
        .flatten()
        .next()?;

        violation(format!(
            "This request asks to be upgraded to the WebSocket Protocol, but {defect}"
        ))
    }

    fn description(&self) -> &'static str {
        "Measures a WebSocket opening handshake — a `GET` whose `Upgrade` field names `websocket` — against the requirements RFC 6455 § 4.1 lists for it:\n\n- The request's HTTP version is at least `1.1`.\n- `Connection` names the `Upgrade` connection-option.\n- `Sec-WebSocket-Version` derives from the `version` production and names version `13`. A value that derives from the production but names another version is RFC 6455 § 4.4's version advertisement: it is reported as a handshake for a protocol this document does not define, and the answer it asks a server for is a `400` listing the versions the server speaks — which `sec_websocket_version_advertised` is the rule that reads.\n- `Sec-WebSocket-Key` is a base64-encoded sixteen-octet nonce. Whether that nonce was *chosen* randomly, which the same sentence also requires, is not something one captured message states.\n- `Sec-WebSocket-Protocol`, when present, is a list of at least one subprotocol name, each a non-empty `token`, and no name written twice.\n\nOnly HTTP/1.x messages are measured. Over HTTP/2 and HTTP/3 the opening handshake is an extended CONNECT carrying a `:protocol` pseudo-header field (RFC 8441, RFC 9220), the `Connection` and `Upgrade` fields this rule reads are forbidden outright, and `Sec-WebSocket-Key` is not processed — so demanding them there would be advice a sender must not follow.\n\n`Host` is asked for by the same list and reported by `host_header`; the server's half of the handshake is `websocket_handshake_valid`'s. RFC 6455 § 4.1 also requires an `Origin` field from a browser client, and nothing in a capture says whether a client is one — § 4.2.1 says as much, telling a server not to read a missing `Origin` as evidence either way — so no rule here reports its absence."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 6455",
                section: Some("4.1"),
                url: "https://www.rfc-editor.org/rfc/rfc6455.html#section-4.1",
                note: "Client Requirements — the numbered list this rule measures: GET, HTTP version at least 1.1, `Upgrade: websocket`, the `Upgrade` connection-option, the `Sec-WebSocket-Key` nonce, `Sec-WebSocket-Version: 13`, and `Sec-WebSocket-Protocol`'s non-empty unique `token` members",
            },
            crate::rules::SpecRef {
                spec: "RFC 6455",
                section: Some("4.2.1"),
                url: "https://www.rfc-editor.org/rfc/rfc6455.html#section-4.2.1",
                note: "Reading the Client's Opening Handshake — the same list from the server's side, which is where the two case-insensitive comparisons and the `Origin` decline are stated",
            },
            crate::rules::SpecRef {
                spec: "RFC 6455",
                section: Some("4.3"),
                url: "https://www.rfc-editor.org/rfc/rfc6455.html#section-4.3",
                note: "Collected ABNF — `Sec-WebSocket-Key = base64-value-non-empty`, `Sec-WebSocket-Version-Client = version`, `Sec-WebSocket-Protocol-Client = 1#token`; the client's version field is one `version` and only the server's is a list",
            },
            crate::rules::SpecRef {
                spec: "RFC 6455",
                section: Some("4.4"),
                url: "https://www.rfc-editor.org/rfc/rfc6455.html#section-4.4",
                note: "Supporting Multiple Versions — why a `Sec-WebSocket-Version` other than 13 is a version advertisement rather than a malformed value, and what a server owes it",
            },
            crate::rules::SpecRef {
                spec: "RFC 8441",
                section: Some("5"),
                url: "https://www.rfc-editor.org/rfc/rfc8441.html#section-5",
                note: "Updates RFC 6455: over HTTP/2 the handshake is an extended CONNECT, `Connection` and `Upgrade` MUST NOT be included, and `Sec-WebSocket-Key` is not processed — the sentences behind this rule's version gate",
            },
            crate::rules::SpecRef {
                spec: "RFC 9220",
                section: Some("3"),
                url: "https://www.rfc-editor.org/rfc/rfc9220.html#section-3",
                note: "Carries RFC 8441's mechanism to HTTP/3 with identical semantics",
            },
            crate::rules::SpecRef {
                spec: "RFC 4648",
                section: Some("3.3"),
                url: "https://www.rfc-editor.org/rfc/rfc4648.html#section-3.3",
                note: "The instruction to reject encoded data holding a character outside the base alphabet, which is what makes a malformed `Sec-WebSocket-Key` reportable rather than merely unusual",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "GET /chat HTTP/1.1\nHost: server.example.com\nUpgrade: websocket\nConnection: Upgrade\nSec-WebSocket-Version: 13\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— missing Sec-WebSocket-Key"),
                snippet: "GET /chat HTTP/1.1\nHost: server.example.com\nUpgrade: websocket\nConnection: Upgrade\nSec-WebSocket-Version: 13",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— HTTP/1.0, where the Upgrade mechanism this handshake needs does not reach"),
                snippet: "GET /chat HTTP/1.0\nHost: server.example.com\nUpgrade: websocket\nConnection: Upgrade\nSec-WebSocket-Version: 13\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— a version advertisement, which RFC 6455 § 4.4 prints as this exact request"),
                snippet: "GET /chat HTTP/1.1\nHost: server.example.com\nUpgrade: websocket\nConnection: Upgrade\nSec-WebSocket-Version: 25\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— the same subprotocol name twice"),
                snippet: "GET /chat HTTP/1.1\nHost: server.example.com\nUpgrade: websocket\nConnection: Upgrade\nSec-WebSocket-Version: 13\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\nSec-WebSocket-Protocol: chat, superchat, chat",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &SecWebsocketHeadersConsistent;

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;
    use rstest::rstest;

    fn make_ws_request(headers: Vec<(&str, &str)>) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "GET".into();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&headers);
        tx
    }

    fn run(tx: &crate::http_transaction::HttpTransaction) -> Option<Violation> {
        let rule = SecWebsocketHeadersConsistent;
        let cfg = crate::test_helpers::make_test_config_with_severity(rule.id(), "error");
        crate::test_helpers::run_rule(
            &rule,
            tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
    }

    /// The four fields of a handshake this document has no complaint about.
    fn conforming() -> Vec<(&'static str, &'static str)> {
        vec![
            ("upgrade", "websocket"),
            ("connection", "Upgrade"),
            ("sec-websocket-version", "13"),
            ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="),
        ]
    }

    #[rstest]
    #[case(conforming(), false)]
    #[case(vec![ // missing sec-websocket-key
        ("upgrade", "websocket"),
        ("connection", "Upgrade"),
        ("sec-websocket-version", "13")
    ], true)]
    #[case(vec![ // invalid base64
        ("upgrade", "websocket"),
        ("connection", "Upgrade"),
        ("sec-websocket-version", "13"),
        ("sec-websocket-key", "!!!notbase64!!!")
    ], true)]
    #[case(vec![ // key decodes to non-16 bytes (e.g., 'a')
        ("upgrade", "websocket"),
        ("connection", "Upgrade"),
        ("sec-websocket-version", "13"),
        ("sec-websocket-key", "YQ==")
    ], true)]
    #[case(vec![ // wrong version
        ("upgrade", "websocket"),
        ("connection", "Upgrade"),
        ("sec-websocket-version", "8"),
        ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
    ], true)]
    #[case(vec![ // missing Connection header
        ("upgrade", "websocket"),
        ("sec-websocket-version", "13"),
        ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
    ], true)]
    fn websocket_handshake_cases(
        #[case] headers: Vec<(&str, &str)>,
        #[case] expect_violation: bool,
    ) {
        assert_eq!(run(&make_ws_request(headers)).is_some(), expect_violation);
    }

    #[test]
    fn non_get_request_is_ignored() {
        let mut tx = make_ws_request(conforming());
        tx.request.method = "POST".into();
        assert!(run(&tx).is_none());
    }

    #[test]
    fn non_websocket_upgrade_is_ignored() {
        // Upgrade: h2
        let tx = make_ws_request(vec![("upgrade", "h2"), ("connection", "Upgrade")]);
        assert!(run(&tx).is_none());
    }

    #[test]
    fn connection_without_upgrade_token_reports_violation() {
        let tx = make_ws_request(vec![
            ("upgrade", "websocket"),
            ("connection", "keep-alive"),
            ("sec-websocket-version", "13"),
            ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="),
        ]);
        let v = run(&tx).expect("a Connection naming no Upgrade option is a finding");
        assert!(v.message.contains("Upgrade token"));
    }

    #[test]
    fn missing_sec_websocket_version_reports_violation() {
        let tx = make_ws_request(vec![
            ("upgrade", "websocket"),
            ("connection", "Upgrade"),
            ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="),
        ]);
        let v = run(&tx).expect("an absent Sec-WebSocket-Version is a finding");
        assert!(v.message.contains("no Sec-WebSocket-Version"));
    }

    #[test]
    fn whitespace_around_values_handled() {
        // The OWS the productions print between list members, and the OWS a field
        // value does not include, are both trimmed off before anything is compared.
        let tx = make_ws_request(vec![
            ("upgrade", " websocket  , other"),
            ("connection", " keep-alive, Upgrade "),
            ("sec-websocket-version", " 13 "),
            ("sec-websocket-key", " dGhlIHNhbXBsZSBub25jZQ== "),
        ]);
        assert!(run(&tx).is_none());
    }

    #[test]
    fn id_and_scope_are_correct() {
        let rule = SecWebsocketHeadersConsistent;
        assert_eq!(rule.id(), "sec_websocket_headers_consistent");
        assert_eq!(
            crate::rules::Rule::scope(&rule),
            crate::rules::RuleScope::Client
        );
    }

    /// A field carrying an octet no production admits is present, and saying it is
    /// missing is a claim about the message rather than about the value that is
    /// wrong. The octet gets named.
    #[test]
    fn an_obs_text_key_is_a_malformed_key_and_not_an_absent_one() {
        let mut tx = make_ws_request(conforming());
        let mut hm = tx.request.headers.clone();
        hm.insert(
            "sec-websocket-key",
            HeaderValue::from_bytes(b"dGhlIHNhbXBsZSBub25jZ\xe9=").unwrap(),
        );
        tx.request.headers = hm;

        let v = run(&tx).expect("a key holding obs-text is a finding");
        assert!(
            !v.message.contains("carries no Sec-WebSocket-Key"),
            "reported a present field as absent: {}",
            v.message
        );
        assert!(v.message.contains("0xE9"), "{}", v.message);
    }

    /// The same, for the field the gate reads: a value carrying `obs-text` still
    /// names `websocket`, and dropping the whole field line would take the handshake
    /// out of this rule's sight entirely.
    #[test]
    fn an_obs_text_upgrade_still_names_the_protocol() {
        let mut tx = make_ws_request(conforming());
        let mut hm = tx.request.headers.clone();
        hm.insert(
            "upgrade",
            HeaderValue::from_bytes(b"websocket, \xe9foo").unwrap(),
        );
        tx.request.headers = hm;
        // Nothing else is wrong with this handshake, so the rule reaches the end.
        assert!(run(&tx).is_none());
    }

    /// The sentence the method gate quotes has two clauses and the second one is a
    /// finding of its own.
    #[rstest]
    #[case("HTTP/1.1", false)]
    #[case("HTTP/1.9", false)]
    #[case("HTTP/1.0", true)]
    #[case("HTTP/0.9", true)]
    fn the_handshake_needs_http_1_1_or_higher(#[case] version: &str, #[case] reported: bool) {
        let mut tx = make_ws_request(conforming());
        tx.request.version = version.into();
        assert_eq!(run(&tx).is_some(), reported, "{version}");
    }

    /// Over HTTP/2 and HTTP/3 this handshake does not exist, and the two fields the
    /// rule reads are ones those versions forbid — so demanding them would be
    /// telling a sender to break a different document.
    #[rstest]
    #[case("HTTP/2.0")]
    #[case("HTTP/3.0")]
    fn the_extended_connect_versions_are_not_measured(#[case] version: &str) {
        let mut tx = make_ws_request(vec![("upgrade", "websocket")]);
        tx.request.version = version.into();
        assert!(run(&tx).is_none());
    }

    /// A version value that derives from no `HTTP-version` names no version, so
    /// there is nothing to compare; the rule that reports the value owns it.
    #[test]
    fn a_version_deriving_from_no_production_stops_the_rule() {
        let mut tx = make_ws_request(vec![("upgrade", "websocket")]);
        tx.request.version = "HTTP/3".into();
        assert!(run(&tx).is_none());
    }

    /// Six ways to write a `Sec-WebSocket-Version` the production does not generate,
    /// each with its own sentence — none of them "expected 13".
    #[rstest]
    #[case("", "at least one DIGIT")]
    #[case("013", "leading zero")]
    #[case("1e", "DIGITs alone")]
    #[case("1234", "longer than three")]
    #[case("256", "above 255")]
    #[case("13, 8", "DIGITs alone")]
    fn a_version_value_is_measured_against_its_production(
        #[case] value: &str,
        #[case] expected: &str,
    ) {
        let mut headers = conforming();
        headers.retain(|(n, _)| *n != "sec-websocket-version");
        headers.push(("sec-websocket-version", value));
        let v = run(&make_ws_request(headers)).expect("a value deriving from no `version`");
        assert!(v.message.contains("derives from no `version`"), "{v:?}");
        assert!(v.message.contains(expected), "{}", v.message);
    }

    /// The client's field is one `version`; two lines of it join into a value no
    /// production generates, and reading only the first line would call it clean.
    #[test]
    fn two_version_lines_are_one_value_and_derive_from_nothing() {
        let mut tx = make_ws_request(conforming());
        let mut hm = tx.request.headers.clone();
        hm.append("sec-websocket-version", HeaderValue::from_static("8"));
        tx.request.headers = hm;
        let v = run(&tx).expect("a second field line is a second version");
        assert!(v.message.contains("derives from no `version`"), "{v:?}");
    }

    /// § 4.4's own worked example, which is a conforming client asking for a version
    /// this document does not define. It is a finding, and the finding does not call
    /// the value invalid.
    #[test]
    fn the_documents_own_version_advertisement_is_named_as_one() {
        let mut headers = conforming();
        headers.retain(|(n, _)| *n != "sec-websocket-version");
        headers.push(("sec-websocket-version", "25"));
        let v = run(&make_ws_request(headers)).expect("a handshake for another version");
        assert!(!v.message.contains("derives from no"), "{}", v.message);
        assert!(v.message.contains("§ 4.4"), "{}", v.message);
    }

    /// The two MUSTs about `Sec-WebSocket-Protocol`'s members, and the values that
    /// satisfy them.
    #[rstest]
    #[case("chat", false)]
    #[case("chat, superchat", false)]
    #[case("chat, Chat", false)]
    #[case("chat, superchat, chat", true)]
    #[case("chat,, superchat", true)]
    #[case(",", true)]
    #[case("", true)]
    #[case("chat/1", true)]
    fn subprotocol_members_are_non_empty_unique_tokens(
        #[case] value: &str,
        #[case] reported: bool,
    ) {
        let mut headers = conforming();
        headers.push(("sec-websocket-protocol", value));
        assert_eq!(
            run(&make_ws_request(headers)).is_some(),
            reported,
            "{value}"
        );
    }

    /// A subprotocol list written across two field lines is one list, so a name
    /// repeated between the lines is a name repeated.
    #[test]
    fn subprotocol_lines_are_joined_before_the_names_are_counted() {
        let mut tx = make_ws_request(conforming());
        let mut hm = tx.request.headers.clone();
        hm.append("sec-websocket-protocol", HeaderValue::from_static("chat"));
        hm.append("sec-websocket-protocol", HeaderValue::from_static("chat"));
        tx.request.headers = hm;
        let v = run(&tx).expect("one name on two lines is one name twice");
        assert!(v.message.contains("more than once"), "{}", v.message);
    }

    /// A `Connection` member padded with an octet that renders like a space is not
    /// the `Upgrade` connection-option, and the walk that trims `OWS` is what keeps
    /// that visible.
    #[test]
    fn an_obs_text_padded_connection_member_does_not_name_the_option() {
        let mut tx = make_ws_request(conforming());
        let mut hm = tx.request.headers.clone();
        hm.insert(
            "connection",
            HeaderValue::from_bytes(b"\xa0Upgrade").unwrap(),
        );
        tx.request.headers = hm;
        let v = run(&tx).expect("a member that is not the token is not the token");
        assert!(v.message.contains("Upgrade token"), "{}", v.message);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "sec_websocket_headers_consistent");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
