// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ServerHttp3StatusCodeValidity;

impl Rule for ServerHttp3StatusCodeValidity {
    fn id(&self) -> &'static str {
        "server_http3_status_code_validity"
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
        // Only applies to HTTP/3 connections. Scoping, not a normative check — no cite.
        // Both gates read the major digit rather than a string: neither direction
        // of this version carries a version field, so both values are ones a
        // writer chose. `helpers::version` owns the production.
        if !crate::helpers::version::is_major(&tx.request.version, 3) {
            return None;
        }

        let resp = tx.response.as_ref()?;

        // Only check responses that are themselves HTTP/3. In a reverse-proxy
        // setup the upstream response may be HTTP/1.1 (where 101 is valid).
        if !crate::helpers::version::is_major(&resp.version, 3) {
            return None;
        }

        // § 4.5 is the only place RFC 9114 mentions 101 at all.
        // cite(RFC 9114 § 4.5): "HTTP/3 does not support the HTTP Upgrade mechanism (Section 7.8 of [HTTP]) or the 101 (Switching Protocols) informational status code (Section 15.2.2 of [HTTP])."
        if resp.status == 101 {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message:
                    "HTTP/3 does not support 101 (Switching Protocols); use extended CONNECT instead"
                        .into(),
            });
        }

        // Three checks used to follow -- a `Content-Length` on a 1xx, captured
        // content octets on a 1xx, a trailer section on a 1xx -- and all three
        // were governed by one sentence, quoted here because this is where the
        // rule stops rather than where it acts:
        // cite(RFC 9110 § 15.2): "A 1xx response is terminated by the end of the header section; it cannot contain content or trailers."
        //
        // That sentence is RFC 9110's, not RFC 9114's. It is not about HTTP/3, and this
        // rule's own SpecRef for it said no more than "Informational 1xx". So a
        // version-independent requirement was being enforced behind a gate that
        // gives up unless *both* the request and the response are HTTP/3: the
        // same 100 (Continue) carrying the same `Content-Length` over HTTP/1.1
        // was never reported, and the HTTP/3 one was reported twice once a rule
        // named for the requirement started reading the same three inputs.
        //
        // `server_no_body_for_1xx_204_304` is that rule and now owns all three,
        // for 1xx, 204 and 304 alike and on every version -- so this is a strict
        // widening, not a handover of coverage. What stays here is the check that
        // is genuinely HTTP/3's: § 4.5 above, which is a sentence about this
        // protocol and nothing else.
        //
        // The empty-trailer-section case is worth naming, because deleting a test
        // is the easiest way to lose a decision: a `#[test]` here asserted that a
        // trailer section carrying no fields is still a violation. It survives, in
        // the rule that took the check, for the reason recorded there -- § 6.3
        // forbids the *section*.
        None
    }

    fn title(&self) -> Option<&'static str> {
        Some("HTTP/3 Status Code Validity")
    }

    fn description(&self) -> &'static str {
        "HTTP/3 does not support the `101 (Switching Protocols)` informational status code. The protocol upgrade mechanism used in HTTP/1.1 has no equivalent in HTTP/3; applications that require protocol switching should use extended CONNECT (RFC 9220) instead.\n\nThis rule applies when the request version is `HTTP/3`. The response is checked only when its own version is also `HTTP/3`; in a reverse-proxy setup the upstream response may arrive via HTTP/1.1, where `101` is legitimate.\n\n**One status code, and only what HTTP/3 says about it.** This rule also used to report a `Content-Length`, a message body, or a trailer section on a `1xx` response. Those rest on RFC 9110 §15.2 — *\"A 1xx response is terminated by the end of the header section; it cannot contain content or trailers\"* — which is not a sentence about HTTP/3, so enforcing it here meant the same defect over HTTP/1.1 or HTTP/2 went unreported. `server_no_body_for_1xx_204_304` enforces it on every version, and for `204` and `304` as well as `1xx`."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9114",
                section: Some("4.5"),
                url: "https://www.rfc-editor.org/rfc/rfc9114.html#section-4.5",
                note: "HTTP Upgrade",
            },
            crate::rules::SpecRef {
                spec: "RFC 9114",
                section: Some("4.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9114.html#section-4.1",
                note: "HTTP Message Framing, where interim and final responses are described. This note said HTTP Message Exchanges, which is not a section RFC 9114 has",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("15.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.2",
                note: "Informational 1xx — where 101 is defined, and where the rule 101 breaks is written. Its sentence forbidding content and trailers on a 1xx is version-independent and is enforced by server_no_body_for_1xx_204_304, not here",
            },
            crate::rules::SpecRef {
                spec: "RFC 9220",
                section: None,
                url: "https://www.rfc-editor.org/rfc/rfc9220.html",
                note: "Bootstrapping WebSockets with HTTP/3",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/3 100 Continue",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/3 103 Early Hints\nLink: </style.css>; rel=preload; as=style",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/3 200 OK\nContent-Type: text/html",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/3 101 Switching Protocols\nUpgrade: websocket",
            },
            // A `100 Continue` carrying a `Content-Length` used to be published
            // here as NonCompliant. Relabelling it Compliant would have been worse
            // than removing it: this rule does accept it now, and it is still a
            // violation of § 8.6 that `server_no_body_for_1xx_204_304` reports --
            // so the page would have shown an operator a defective message under a
            // Compliant heading. The description names the rule that owns it.
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ServerHttp3StatusCodeValidity;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn make_h3_transaction_with_response(
        status: u16,
        resp_headers: &[(&str, &str)],
    ) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(status, resp_headers);
        tx.request.version = "HTTP/3.0".into();
        if let Some(ref mut resp) = tx.response {
            resp.version = "HTTP/3.0".into();
        }
        tx
    }

    // --- 101 Switching Protocols is forbidden ---

    #[test]
    fn status_101_is_violation() {
        let rule = ServerHttp3StatusCodeValidity;
        let tx = make_h3_transaction_with_response(101, &[("upgrade", "websocket")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        let v = v.expect("should be a violation");
        assert_eq!(v.rule, "server_http3_status_code_validity");
        assert_eq!(v.severity, crate::lint::Severity::Warn);
        assert!(v.message.contains("101"));
    }

    #[test]
    fn status_101_bare_is_violation() {
        // 101 without any extra headers is still a violation
        let rule = ServerHttp3StatusCodeValidity;
        let tx = make_h3_transaction_with_response(101, &[]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("101"));
    }

    // --- Valid 1xx informational responses ---

    #[rstest]
    #[case(100, &[])]
    #[case(102, &[])]
    #[case(103, &[("link", "</style.css>; rel=preload; as=style")])]
    fn valid_1xx_is_ok(#[case] status: u16, #[case] headers: &[(&str, &str)]) {
        let rule = ServerHttp3StatusCodeValidity;
        let tx = make_h3_transaction_with_response(status, headers);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    // --- What a 1xx carries is § 15.2's question, and § 15.2 is not HTTP/3's ---

    /// The three checks this rule used to make now belong to the rule named for
    /// the requirement, and the handover is checked by *running* that rule rather
    /// than by trusting a comment: it must report every case, including the empty
    /// trailer section a `#[test]` here used to pin.
    #[rstest]
    #[case(100, &[("content-length", "0")][..], None, None)]
    #[case(103, &[("content-length", "42")][..], None, None)]
    #[case(199, &[("content-length", "0")][..], None, None)]
    #[case(100, &[][..], Some(10), None)]
    #[case(102, &[][..], Some(5), None)]
    #[case(100, &[("content-length", "10")][..], Some(10), None)]
    #[case(100, &[][..], None, Some(&[("x-checksum", "abc")][..]))]
    #[case(103, &[][..], None, Some(&[("x-timing", "50ms")][..]))]
    #[case(100, &[][..], None, Some(&[][..]))]
    fn what_a_1xx_carries_is_reported_by_the_owner_and_not_here(
        #[case] status: u16,
        #[case] headers: &[(&str, &str)],
        #[case] body_length: Option<u64>,
        #[case] trailer_pairs: Option<&[(&str, &str)]>,
    ) {
        let rule = ServerHttp3StatusCodeValidity;
        let mut tx = make_h3_transaction_with_response(status, headers);
        if let Some(ref mut resp) = tx.response {
            resp.body_length = body_length;
            resp.trailers = trailer_pairs.map(crate::test_helpers::make_headers_from_pairs);
        }

        assert!(
            rule.check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
            )
            .is_none(),
            "§ 15.2 is not this rule's sentence"
        );

        let owner = crate::rules::REGISTERED_RULES
            .iter()
            .find(|r| r.id() == "server_no_body_for_1xx_204_304")
            .expect("the owning rule is registered");
        assert!(
            owner
                .check_transaction(
                    &tx,
                    &crate::transaction_history::TransactionHistory::empty(),
                    &crate::test_helpers::make_test_config_with_enabled_rules(&[owner.id()]),
                )
                .is_some(),
            "nothing reported a {status} carrying headers {headers:?} \
             body {body_length:?} trailers {trailer_pairs:?}"
        );
    }

    #[test]
    fn informational_with_zero_body_length_is_ok() {
        let rule = ServerHttp3StatusCodeValidity;
        let mut tx = make_h3_transaction_with_response(100, &[]);
        if let Some(ref mut resp) = tx.response {
            resp.body_length = Some(0);
        }

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    // --- Non-informational statuses are ok ---

    #[rstest]
    #[case(200)]
    #[case(204)]
    #[case(301)]
    #[case(304)]
    #[case(404)]
    #[case(500)]
    fn non_informational_status_is_ok(#[case] status: u16) {
        let rule = ServerHttp3StatusCodeValidity;
        let tx = make_h3_transaction_with_response(status, &[]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    // --- HTTP version gating ---

    #[test]
    fn http11_101_is_not_checked() {
        let rule = ServerHttp3StatusCodeValidity;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            101,
            &[("upgrade", "websocket")],
        );

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn h3_request_non_h3_response_101_is_not_checked() {
        // Reverse-proxy scenario: client is HTTP/3 but upstream is HTTP/1.1
        let rule = ServerHttp3StatusCodeValidity;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            101,
            &[("upgrade", "websocket")],
        );
        tx.request.version = "HTTP/3.0".into();
        // response.version stays HTTP/1.1

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    // --- No response case ---

    #[test]
    fn no_response_is_ok() {
        let rule = ServerHttp3StatusCodeValidity;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.version = "HTTP/3.0".into();

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    // --- Edge cases: 1xx boundary ---

    #[test]
    fn status_200_with_content_length_is_ok() {
        // 200 is not informational; Content-Length is allowed
        let rule = ServerHttp3StatusCodeValidity;
        let tx = make_h3_transaction_with_response(200, &[("content-length", "42")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    // --- Edge cases: non-informational with body/trailers are ok ---

    #[test]
    fn non_informational_with_body_is_ok() {
        let rule = ServerHttp3StatusCodeValidity;
        let mut tx = make_h3_transaction_with_response(200, &[]);
        if let Some(ref mut resp) = tx.response {
            resp.body_length = Some(100);
        }

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn non_informational_with_trailers_is_ok() {
        let rule = ServerHttp3StatusCodeValidity;
        let mut tx = make_h3_transaction_with_response(200, &[]);
        if let Some(ref mut resp) = tx.response {
            resp.trailers = Some(crate::test_helpers::make_headers_from_pairs(&[(
                "x-checksum",
                "abc",
            )]));
        }

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    // --- The one finding, whatever else the message carries ---

    #[test]
    fn a_101_is_reported_as_a_101_whatever_it_carries() {
        // The status is the whole finding: what the response advertises or sends
        // is § 15.2's question and another rule's.
        let rule = ServerHttp3StatusCodeValidity;
        let mut tx = make_h3_transaction_with_response(101, &[("content-length", "0")]);
        if let Some(ref mut resp) = tx.response {
            resp.body_length = Some(10);
        }

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("101"));
    }

    // --- Edge cases: informational with no body_length (None) ---

    #[test]
    fn informational_with_no_body_length_is_ok() {
        let rule = ServerHttp3StatusCodeValidity;
        let mut tx = make_h3_transaction_with_response(100, &[]);
        if let Some(ref mut resp) = tx.response {
            resp.body_length = None;
        }

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    // --- Edge case: HTTP/2 request with version gating ---

    #[test]
    fn http2_request_is_not_checked() {
        let rule = ServerHttp3StatusCodeValidity;
        let mut tx =
            crate::test_helpers::make_test_transaction_with_response(101, &[("upgrade", "h2c")]);
        tx.request.version = "HTTP/2.0".into();

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    // --- Edge case: 102 Processing with body ---

    // --- Scope and config validation ---

    #[test]
    fn scope_is_server() {
        let rule = ServerHttp3StatusCodeValidity;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "server_http3_status_code_validity");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
