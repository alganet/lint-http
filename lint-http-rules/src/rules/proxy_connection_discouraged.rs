// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::helpers::headers::combined_field_value_as_written;
use crate::lint::Violation;
use crate::rules::Rule;

pub struct ProxyConnectionDiscouraged;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9112_C_2_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9112",
    section: Some("C.2.2"),
    // An appendix anchors as `appendix-C.2.2`, not `section-c.2.2`,
    // and the letter is case-sensitive -- the `section-` prefix
    // every other `SpecRef` in the tree uses scrolls nowhere here.
    url: "https://www.rfc-editor.org/rfc/rfc9112.html#appendix-C.2.2",
    note: "Keep-Alive Connections — the only description of the field in either core \
           document, and it states no requirement: the section carries no BCP 14 \
           keyword",
};
const RFC_9110_7_6_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("7.6.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6.1",
    note: "Connection — lists the field among those intermediaries are asked to \
           remove before forwarding, and names Appendix C.2.2 as its definition",
};

impl Rule for ProxyConnectionDiscouraged {
    fn id(&self) -> &'static str {
        "proxy_connection_discouraged"
    }

    /// **The sentence this rule rests on** takes a client as its subject and
    /// names the direction itself — *"in any requests"* — so the evidence is a
    /// field in a request and the party blamed is the one that sent it. A proxy
    /// forwarding a request is a client of its next hop, so the finding reaches
    /// whoever wrote the field whether or not that party is the user agent.
    ///
    /// Not *every* sentence in the section is about a client: two are about what
    /// HTTP/1.0 connections and HTTP/1.0 proxy servers do, and one names
    /// *"clients and servers"* together. They are the section's narrative rather
    /// than its advice, and none of them asks anything of a responder — which is
    /// why the scope is `Client` and not `Both`.
    ///
    /// cite(RFC 9112 § C.2.2): "As a result, clients are encouraged not to send the Proxy-Connection header field in any requests."
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
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
            // The versions that have a `Connection` field are the versions this
            // advice is about: `Proxy-Connection` was invented for HTTP/1.0 proxies
            // that mishandled `Connection`, and over HTTP/2 and HTTP/3 the field is
            // not discouraged but forbidden, which
            // `no_connection_specific_fields` reports with those versions'
            // own sentences. Reporting it here as well would be two findings for one
            // field, and the weaker of the two would be this advisory one.
            //
            // The test is *"not one of the two that forbid it"* rather than *"is
            // HTTP/1.x"*, so a version deriving from no production falls through and
            // is measured: the field is on the wire either way, and the advice does
            // not turn on which digit the sender wrote. `http_version_syntax`
            // is what reports the version itself. This is the same gate the sibling
            // rules use, and the same answer for the same reason.
            //
            // cite(RFC 9110 § 7.6.1): "Note that some versions of HTTP prohibit the use of fields for such information, and therefore do not allow the Connection field."
            if matches!(crate::http_version::major(&tx.request.version), Some(2 | 3)) {
                return None;
            }

            // Presence is what the sentence is about — *"not to send the
            // Proxy-Connection header field in any requests"* names the field and
            // not a value it might hold. The value is read anyway and printed,
            // because it is what tells an operator which persistence the client was
            // reaching for, and a hung connection is the symptom the section
            // describes. It is read as the sender wrote it, one `char` per octet:
            // `to_str` would turn a value carrying `obs-text` into a request with no
            // such field, and the advice would go with it.
            //
            // cite(RFC 9110 § 5.2): "When a field name is repeated within a section, its combined field value consists of the list of corresponding field line values within that section, concatenated in order, with each field line value separated by a comma."
            let value = combined_field_value_as_written(&tx.request.headers, "proxy-connection")?;

            // The section states no requirement, and the finding says so in its own
            // words. There is no BCP 14 keyword anywhere in it — the modals are
            // *"might wish"*, *"are encouraged"*, *"ought to"* and *"ought not"* —
            // so a message written in the imperative would invent one. What makes
            // the advice worth reporting at all is the reason the section gives:
            // the field was a fix for one layer of proxy and proxies come in
            // several, so it reproduces the problem it was meant to solve.
            //
            // cite(RFC 9112 § C.2.2): "One attempted solution was the introduction of a Proxy-Connection header field, targeted specifically at proxies.  In practice, this was also unworkable, because proxies are often deployed in multiple layers, bringing about the same problem discussed above."
            Some(self.cited(&RFC_9112_C_2_2,
                ctx.severity,
                format!(
                    "Request carries a Proxy-Connection header field: '{}'. RFC 9112 Appendix C.2.2 \
                     encourages clients not to send it in any request — it was an attempted fix for \
                     HTTP/1.0 proxies that did not understand Connection, and is unworkable because \
                     proxies are often deployed in multiple layers, which brings the same hung \
                     connection back. The section states this as advice and not as a requirement",
                    value.escape_debug()
                ),
            ))
        };
        Vec::from_iter(finding())
    }

    fn description(&self) -> &'static str {
        "Reports a request carrying a `Proxy-Connection` header field.\n\n**This is advice, and the finding says so.** RFC 9112 Appendix C.2.2 is the only place in either core document that describes the field, and it contains **no BCP 14 keyword at all** — its modals are *might wish*, *are encouraged*, *ought to* and *ought not*. So no sentence makes sending `Proxy-Connection` a violation, and this rule's message is worded as the recommendation it is. What the section does supply is the reason: the field *was an attempted solution … targeted specifically at proxies*, introduced because some HTTP/1.0 proxies forwarded `Connection` they did not understand and hung the connection — and it *was also unworkable, because proxies are often deployed in multiple layers, bringing about the same problem discussed above*. A field invented to fix one layer of proxy reproduces the fault as soon as there are two.\n\n**The field is connection-specific, and RFC 9110 §7.6.1 is where that is settled.** Its list of fields intermediaries are asked to remove before forwarding names `Proxy-Connection` and points at Appendix C.2.2 for the definition — so the current specification names the older text rather than replacing it, which is what makes citing an appendix titled *Changes from Previous RFCs* the right thing rather than a stale pointer.\n\n**The two versions with a prohibition of their own are left to the rule that carries it.** Over HTTP/2 and HTTP/3 the field is not discouraged but forbidden outright, and any message carrying it is malformed — `no_connection_specific_fields` reports that with each version's own sentence, which is the stronger of the two readings. Reporting it here as well would be two findings for one field. The gate asks *is this one of those two*, not *is this HTTP/1.x*, so a request whose version derives from no production is still measured: the field is on the wire either way, and the advice does not turn on which digit the sender wrote.\n\n**Two things this rule does not report, each because the sentence does not reach them.**\n\n- **A response carrying `Proxy-Connection`.** The sentence this rule rests on takes a *client* as its subject and names the direction itself — *in any requests* — and nothing in the section asks anything of a responder. (Not every sentence there is about a client: two describe what HTTP/1.0 connections and HTTP/1.0 proxy servers do, and one names *clients and servers* together; those are the section's narrative rather than its advice.) §7.6.1's removal sentence is a SHOULD addressed to *intermediaries*, and it is about forwarding rather than about generating — a captured response holding the field could have been written by the origin or forwarded by a hop that did not strip it, and no field in the capture records which. So the direction is left alone rather than guessed at.\n- **Whether the value is a well-formed connection-option list.** `Proxy-Connection` was written to be read the way `Connection` is, but no document gives it a grammar; there is nothing to measure a value against. It is printed in the finding rather than parsed, because what an operator diagnosing a hung connection wants to know is which persistence the client was reaching for.\n\nScope: this rule reads a request's header section. Where the field appears on several lines they are read as one value (§5.2), and a value carrying an octet outside US-ASCII is measured rather than skipped — reading it back through a UTF-8 decoder would turn a field the sender wrote into a request that has none. **Whether `Proxy-Connection` may appear in a *trailer* section is §6.5.1's question, and `trailer_fields_valid` answers it on the merits**: its table names the field among its connection-specific entries, so a `Proxy-Connection` trailer is reported there whatever this message's own `Connection` or `Trailer` fields say. (The field's absence from that table was recorded here when this rule was written, and repaired in its own iteration — RULECITES P46.)"
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_9112_C_2_2, RFC_9110_7_6_1]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("The option the field was trying to imitate, written where it belongs"),
                snippet: "GET / HTTP/1.1\nHost: example.com\nConnection: keep-alive",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "GET / HTTP/1.1\nHost: example.com\nProxy-Connection: keep-alive",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("Beside the field it was meant to stand in for"),
                snippet: "GET / HTTP/1.1\nHost: example.com\nConnection: keep-alive\nProxy-Connection: keep-alive",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ProxyConnectionDiscouraged;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    const RULE: ProxyConnectionDiscouraged = ProxyConnectionDiscouraged;

    fn cfg() -> crate::config::Config {
        crate::test_helpers::make_test_config_with_enabled_rules(&["proxy_connection_discouraged"])
    }

    fn request(version: &str, headers: &[(&str, &str)]) -> Option<Violation> {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.version = version.to_string();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(headers);
        crate::test_helpers::run_rule(
            &RULE,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg(),
        )
    }

    #[rstest]
    #[case("HTTP/1.1")]
    #[case("HTTP/1.0")]
    fn the_field_is_reported_on_the_versions_that_have_a_connection_field(#[case] version: &str) {
        let v = request(version, &[("proxy-connection", "keep-alive")]).expect("violation");
        assert!(
            v.message
                .contains("Proxy-Connection header field: 'keep-alive'"),
            "{}",
            v.message
        );
    }

    /// The section states no requirement, so the finding must not read as one.
    /// A message in the imperative would invent a keyword the section does not
    /// have — which is the defect this rule was written to avoid, not one it may
    /// commit.
    #[test]
    fn the_finding_is_worded_as_advice_and_not_as_a_requirement() {
        let v = request("HTTP/1.1", &[("proxy-connection", "keep-alive")]).expect("violation");
        assert!(
            v.message.contains("advice and not as a requirement"),
            "{}",
            v.message
        );
        for keyword in ["MUST", "SHOULD", "MAY NOT", "is forbidden", "is invalid"] {
            assert!(
                !v.message.contains(keyword),
                "the finding invented {keyword}: {}",
                v.message
            );
        }
    }

    /// Over these versions the field is forbidden rather than discouraged, and
    /// `no_connection_specific_fields` carries that sentence. Two rules
    /// reporting one field is what this gate exists to prevent.
    #[rstest]
    #[case("HTTP/2.0")]
    #[case("HTTP/3.0")]
    fn the_versions_with_their_own_prohibition_are_left_to_that_rule(#[case] version: &str) {
        assert!(request(version, &[("proxy-connection", "keep-alive")]).is_none());
    }

    #[test]
    fn a_request_without_the_field_is_not_a_finding() {
        assert!(request("HTTP/1.1", &[("connection", "keep-alive")]).is_none());
    }

    /// The field is one value however many lines carry it, and an `obs-text`
    /// octet is an octet the sender wrote. Read through `to_str` this request
    /// would have had no `Proxy-Connection` at all.
    #[test]
    fn the_lines_are_one_value_and_an_obs_text_octet_survives_the_read() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.version = "HTTP/1.1".into();
        tx.request.headers.append(
            "proxy-connection",
            hyper::header::HeaderValue::from_static("keep-alive"),
        );
        tx.request.headers.append(
            "proxy-connection",
            hyper::header::HeaderValue::from_bytes(&[0xff]).expect("obs-text is a field-content"),
        );

        let v = crate::test_helpers::run_rule(
            &RULE,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg(),
        )
        .expect("violation");
        // The comma is § 5.2's join, and the `char` after it is the octet %xFF
        // standing for itself — `escape_debug` leaves a printable one alone,
        // which is how every as-written value in the tree is spelled.
        assert!(v.message.contains("'keep-alive,\u{ff}'"), "{}", v.message);
    }

    /// A response carrying the field draws nothing: every sentence of the
    /// section takes a client as its subject.
    #[test]
    fn a_response_carrying_the_field_is_not_this_rules_finding() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("proxy-connection", "keep-alive")],
        );
        tx.request.version = "HTTP/1.1".into();
        let v = crate::test_helpers::run_rule(
            &RULE,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg(),
        );
        assert!(v.is_none(), "{v:?}");
    }

    #[test]
    fn scope_is_client() {
        assert_eq!(RULE.scope(), crate::rules::RuleScope::Client);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "proxy_connection_discouraged");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
