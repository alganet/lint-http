// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ClientAcceptEncodingPresent;

impl Rule for ClientAcceptEncodingPresent {
    fn id(&self) -> &'static str {
        "client_accept_encoding_present"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;

        // Nothing requires a client to send this field, so the rule is advice
        // throughout. What the advice *was* is the problem: the comment here
        // said the absence means "identity only" by default. § 12.5.3 says the
        // opposite, in the first of the three rules a server tests against.
        // cite(RFC 9110 § 12.5.3): "When sent by a user agent in a request, Accept-Encoding indicates the content codings acceptable in a response."
        // cite(RFC 9110 § 12.5.3): "If no Accept-Encoding header field is in the request, any content coding is considered acceptable by the user agent."
        // cite(RFC 9110 § 12.5.3): "Accept-Encoding = #( codings [ weight ] )"
        //
        // Absence is the *most permissive* state there is -- every coding is
        // acceptable, and a server that compresses anyway conforms. The
        // "identity only" reading belongs to a different value entirely: the
        // field present and empty.
        // cite(RFC 9110 § 12.5.3): "An Accept-Encoding header field with a field value that is empty implies that the user agent does not want any content coding in response."
        //
        // So the rule reported the permissive case on a rationale that
        // described the refusing one, and passed the refusing one in silence.
        // Both are reported now, and they are not the same finding.
        //
        // A member that is empty is not an element, so a value of `,` lists no
        // codings and reads the same way as one with nothing in it at all.
        // cite(RFC 9110 § 5.6.1.2): "Empty elements do not contribute to the count of elements present."
        let mut present = false;
        let mut any_coding = false;
        for hv in tx.request.headers.get_all("accept-encoding").iter() {
            present = true;
            let val = String::from_utf8_lossy(hv.as_bytes());
            if crate::helpers::headers::parse_list_header(&val)
                .next()
                .is_some()
            {
                any_coding = true;
            }
        }

        if !present {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Request expresses no content-coding preference (no Accept-Encoding \
                          header); any coding is acceptable, but most servers will not compress \
                          without an explicit signal"
                    .into(),
            });
        }

        if !any_coding {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Request declines all content codings (empty Accept-Encoding header)"
                    .into(),
            });
        }

        None
    }

    fn title(&self) -> Option<&'static str> {
        Some("Client Accept-Encoding Present")
    }

    fn description(&self) -> &'static str {
        "This rule checks if the client sends an `Accept-Encoding` header in the request.\n\nModern HTTP clients should support compression (gzip, brotli, etc.) to reduce bandwidth usage and improve performance. Omitting this header usually implies the client does not support compression, or it was manually disabled."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[crate::rules::SpecRef {
            spec: "RFC 9110",
            section: Some("12.5.3"),
            url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.3",
            note: "Accept-Encoding header",
        }]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("Request"),
                snippet:
                    "GET /resource HTTP/1.1\nHost: example.com\nAccept-Encoding: gzip, deflate, br",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("Request"),
                snippet: "GET /resource HTTP/1.1\nHost: example.com\nUser-Agent: my-script/1.0",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ClientAcceptEncodingPresent;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn req(headers: &[(&str, &str)]) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(headers);
        tx
    }

    fn run(tx: &crate::http_transaction::HttpTransaction) -> Option<crate::lint::Violation> {
        let rule = ClientAcceptEncodingPresent;
        rule.check_transaction(
            tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
    }

    #[rstest]
    #[case(vec![("accept-encoding", "gzip")], None)]
    #[case(vec![("accept-encoding", "gzip, br")], None)]
    #[case(vec![("accept-encoding", "*")], None)]
    #[case(vec![("accept-encoding", "identity")], None)]
    #[case(vec![], Some("expresses no content-coding preference"))]
    #[case(vec![("user-agent", "my-script/1.0")], Some("expresses no content-coding preference"))]
    fn presence_and_absence(#[case] headers: Vec<(&str, &str)>, #[case] expected: Option<&str>) {
        let v = run(&req(&headers));
        match expected {
            None => assert!(v.is_none(), "{headers:?}: {v:?}"),
            Some(fragment) => assert!(
                v.is_some_and(|v| v.message.contains(fragment)),
                "{headers:?} should mention {fragment:?}"
            ),
        }
    }

    /// `identity` is a coding name, not an absence -- § 12.5.3 calls it "a
    /// synonym for 'no encoding'", which is a stated preference and exactly
    /// what this field is for.
    #[test]
    fn identity_is_a_preference_not_a_silence() {
        assert!(run(&req(&[("accept-encoding", "identity")])).is_none());
    }

    /// The empty field is the one that means what the rule's description used
    /// to claim absence meant. It used to pass in silence.
    #[rstest]
    #[case("")]
    #[case("   ")]
    // No member of this list is an element, so it lists no codings.
    #[case(",")]
    #[case(" , ")]
    fn an_empty_field_declines_every_coding(#[case] value: &str) {
        let v = run(&req(&[("accept-encoding", value)]));
        assert!(
            v.is_some_and(|v| v.message.contains("declines all content codings")),
            "{value:?} lists no codings"
        );
    }

    /// The two findings are distinct, because the states are.
    #[test]
    fn absence_and_refusal_are_different_findings() {
        let absent = run(&req(&[])).unwrap().message;
        let empty = run(&req(&[("accept-encoding", "")])).unwrap().message;
        assert_ne!(absent, empty);
        assert!(absent.contains("any coding is acceptable"));
        assert!(empty.contains("declines"));
    }

    #[test]
    fn scope_is_client() {
        let rule = ClientAcceptEncodingPresent;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Client);
    }
}
