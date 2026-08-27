// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::helpers::headers::{
    combined_field_value_as_written, is_nominated_by_connection, shown_in_finding,
};
use crate::lint::Violation;
use crate::rules::Rule;

pub struct UpgradeAndConnectionConsistent;

impl UpgradeAndConnectionConsistent {
    /// One field section, measured against the sentence that pairs the two fields.
    ///
    /// The implication runs from the field to the option and not the other way. A
    /// sender that writes `Upgrade` has to name it in `Connection`, because that is
    /// what stops the next intermediary from relaying a field that applies to one hop;
    /// a `Connection` naming `upgrade` with no `Upgrade` beside it is a different
    /// message and § 7.6.1 says in as many words that it is allowed. Reading the
    /// implication backwards is what this rule did until its audit, and the sentence
    /// it needed was two files away, enforced for `TE` by
    /// `te_header_valid` in exactly this shape — and once more one
    /// protocol wide, since RFC 6455 § 4.1 restates it for a WebSocket handshake and
    /// `sec_websocket_headers_consistent` measures that. The special cases
    /// were enforced and the sentence they specialize was not.
    ///
    /// § 7.6.1 states the general obligation for any field carrying control
    /// information about the connection, and § 7.8 states it for this field by name;
    /// both are the requirement, and the second is the one whose finding can name a
    /// field.
    ///
    /// The presence of the field is the antecedent, not the presence of a protocol
    /// name in it: the production's outer brackets make a list of no protocols a list
    /// the sender generated, and the intermediary it has to be hidden from is the same
    /// one. What that value may hold is
    /// `upgrade_header_syntax`'s question. The
    /// grammar is quoted from the collected ABNF rather than from § 7.8, where
    /// `Upgrade = #protocol` stands alone at nineteen characters — below the floor a
    /// quotation needs to be evidence of anything.
    ///
    /// cite(RFC 9110 § 7.6.1): "When a field aside from Connection is used to supply control information for or about the current connection, the sender MUST list the corresponding field name within the Connection header field."
    /// cite(RFC 9110 § 7.8): "A sender of Upgrade MUST also send an "Upgrade" connection option in the Connection header field (Section 7.6.1) to inform intermediaries not to forward this field."
    /// cite(RFC 9110 § A, label: Upgrade grammar, sender-expanded): "Upgrade = [ protocol *( OWS "," OWS protocol ) ]"
    fn defect(headers: &hyper::HeaderMap, version: &str, direction: &str) -> Option<String> {
        // The major digit decides whether this version has a `Connection` field to
        // carry the option; `http_version` owns the production that reads it. The MUST
        // is unconditional in its own sentence and its condition is one section away:
        // the two versions that convey connection-specific metadata by other means
        // forbid both of these fields outright, so asking for the option there would
        // be telling an operator to add a field whose presence makes the message
        // malformed. A value deriving from no `HTTP-version` names no wire format and
        // is measured, which is the answer the sibling rule enforcing this same
        // sentence gives: the field is in the message whatever the start-line says.
        //
        // Neither MUST NOT names a field, so neither is the whole reason on its own:
        // RFC 9113 enumerates in its next sentence and RFC 9114 enumerates nowhere,
        // deferring to § 7.6.1's list — which is where both of these fields are found.
        //
        // cite(RFC 9110 § 7.6.1): "Note that some versions of HTTP prohibit the use of fields for such information, and therefore do not allow the Connection field."
        // cite(RFC 9110 § 7.6.1): "Furthermore, intermediaries SHOULD remove or replace fields that are known to require removal before forwarding, whether or not they appear as a connection-option, after applying those fields' semantics."
        // cite(RFC 9113 § 8.2.2): "An endpoint MUST NOT generate an HTTP/2 message containing connection-specific header fields."
        // cite(RFC 9113 § 8.2.2): "This includes the Connection header field and those listed as having connection-specific semantics in Section 7.6.1 of [HTTP] (that is, Proxy-Connection, Keep-Alive, Transfer-Encoding, and Upgrade)."
        // cite(RFC 9114 § 4.2): "An endpoint MUST NOT generate an HTTP/3 field section containing connection-specific fields; any message containing connection-specific fields MUST be treated as malformed."
        if matches!(crate::http_version::major(version), Some(2 | 3)) {
            return None;
        }

        // Presence of the field, read as the sender wrote it. `to_str` would fold a
        // value carrying `obs-text` into "this message has no `Upgrade` field" — a
        // claim about the message, where the sender did write the field and does owe
        // the option for it.
        combined_field_value_as_written(headers, "upgrade")?;

        // Whether the sender listed the option, which is the *recipient's* reading of
        // a list, so the shared list reader answers it — lines joined first, since an
        // option written on a second `Connection` line is listed. Whether the
        // `Connection` value is itself well formed is
        // `connection_header_tokens_valid`'s question.
        let connection = combined_field_value_as_written(headers, "connection");
        if is_nominated_by_connection("upgrade", connection.as_deref()) {
            return None;
        }

        // Two messages, because they send an operator to two different places: a
        // `Connection` that is there and names other options is a sender that knows
        // about the field, and an absent one is a sender that does not.
        //
        // The consequence is what § 7.6.1 spends its own sentence on, and it is not
        // only that an intermediary forwards the field: the recipient of a forwarded
        // one is told to ignore it, so the upgrade this message asks for is lost in
        // both directions.
        //
        // cite(RFC 9110 § 7.6.1): "In contrast, a connection-specific field received without a corresponding connection option usually indicates that the field has been improperly forwarded by an intermediary and ought to be ignored by the recipient."
        let names = match connection.as_deref() {
            Some(value) => format!("its Connection field names `{}`", shown_in_finding(value)),
            None => "the message carries no Connection field".to_string(),
        };
        Some(format!(
            "{direction} carries an Upgrade header field without an 'upgrade' connection option \
             in Connection ({names}); Upgrade applies to the immediate connection only, the \
             option is what stops an intermediary from forwarding it, and a recipient that \
             receives it forwarded is told to ignore it (RFC 9110 §7.8)"
        ))
    }
}

impl Rule for UpgradeAndConnectionConsistent {
    fn id(&self) -> &'static str {
        "upgrade_and_connection_consistent"
    }

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
            // Each half is measured against its own version. In a reverse-proxy capture
            // the request may have arrived over HTTP/3 while the response came back from
            // the origin over HTTP/1.1, and the sender the sentence is about is the one
            // that wrote the section being read.
            let message = Self::defect(&tx.request.headers, &tx.request.version, "Request")
                .or_else(|| {
                    let resp = tx.response.as_ref()?;
                    Self::defect(&resp.headers, &resp.version, "Response")
                })?;

            // Read last: every gate above ends the rule, so only a message about to be
            // reported pays for the map probes and the hash over the rule id.
            Some(self.violation(ctx.severity, message))
        };
        Vec::from_iter(finding())
    }

    fn description(&self) -> &'static str {
        "Reports a message that carries an `Upgrade` header field without naming the `upgrade` connection-option in `Connection`.\n\nRFC 9110 §7.8 states the pairing in one direction: *A sender of Upgrade MUST also send an \"Upgrade\" connection option in the Connection header field (Section 7.6.1) to inform intermediaries not to forward this field.* §7.6.1 states the same obligation in general, for any field supplying control information about the current connection. The option is the only thing that makes the field hop-by-hop: without it an intermediary relays a field meant for one connection, and the recipient of a relayed one is told to ignore it — so the upgrade is lost in both directions rather than merely mis-declared.\n\n**The converse is not reported, and this rule used to report only the converse.** A `Connection: upgrade` with no `Upgrade` field beside it is not a defect: §7.6.1 says that connection options do not always correspond to a field present in the message, since a connection-specific field might not be needed when there are no parameters associated with the option. No sentence in RFC 9110 or RFC 9112 makes the missing field a violation. A `101` response that omits `Upgrade` **is** one, by §15.2.2, and `status_101_switching_protocols` is the rule that reports it, and `status_426_upgrade_valid` reports the same obligation on a `426 (Upgrade Required)` response.\n\n**One protocol already had this requirement, and only in one direction of one method.** RFC 6455 §4.1 asks a WebSocket opening handshake for a `Connection` header field whose value includes the `Upgrade` token, and `sec_websocket_headers_consistent` measures that alongside the rest of §4.1's list — so a `GET` whose `Upgrade` names `websocket` is reported by both rules, each from its own document. Everything else the general sentence covers was reported by neither: `Upgrade: h2c`, a `POST` offering `websocket`, and any response carrying the field at all.\n\nThe field's presence is what the sentence turns on, not what it holds. `Upgrade` is `#protocol`, so `Upgrade:` with no protocol named is still a field the sender generated and still owes the option. Whether the value derives from `protocol = protocol-name [\"/\" protocol-version]` is `upgrade_header_syntax`'s question, in both directions and on every version; `status_101_switching_protocols` reads the names in a `101` exchange only, to compare what was offered against what was chosen.\n\n**Only the versions that have a `Connection` field are measured.** HTTP/2 and HTTP/3 convey connection-specific metadata by other means and an endpoint MUST NOT generate a message carrying either of these fields (RFC 9113 §8.2.2, RFC 9114 §4.2), so demanding the option there would be advice a sender must not follow. That those fields are present at all is reported by `no_connection_specific_fields`, on both versions and with each field section measured against the version that carried *it* — so an HTTP/3 response to an HTTP/1.1 request is read there even though this rule declines it.\n\nScope: this rule reads header sections — a request's and a response's, each against its own protocol version, since a reverse proxy may have received the two over different ones. Where either field appears on several lines in one section they are one value (§5.2), so an `upgrade` option written on a second `Connection` line is listed. A value carrying an octet outside US-ASCII is measured rather than skipped: reading it back through a UTF-8 decoder would turn a field the sender wrote into a message that has no such field, and the obligation would go with it. Whether `Upgrade` may appear in a *trailer* section is §6.5.1's question and `trailer_fields_valid`'s, which holds the table `Upgrade` is listed in."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("7.8"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-7.8",
                note: "Upgrade — the sender's obligation to name the field as a connection-option \
                       beside it, and the `#protocol` grammar that makes the field's presence the \
                       thing the obligation turns on",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("7.6.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6.1",
                note: "Connection — the same obligation stated generally, what a recipient does \
                       with a connection-specific field that arrives without its option, the \
                       sentence permitting an option that names no present field, and the note \
                       that some versions do not allow the field at all",
            },
            crate::rules::SpecRef {
                spec: "RFC 9113",
                section: Some("8.2.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9113.html#section-8.2.2",
                note: "Connection-specific header fields — why an HTTP/2 message is not asked \
                       for an option it must not send",
            },
            crate::rules::SpecRef {
                spec: "RFC 9114",
                section: Some("4.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9114.html#section-4.2",
                note: "HTTP fields — the same prohibition for HTTP/3",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "Connection: upgrade\nUpgrade: websocket",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(an option needs no field)"),
                snippet: "Connection: upgrade",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "Connection: keep-alive\nUpgrade: websocket",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &UpgradeAndConnectionConsistent;

#[cfg(test)]
mod tests {
    use super::*;

    use crate::test_helpers::{
        make_headers_from_octet_pairs, make_headers_from_pairs,
        make_test_config_with_enabled_rules, make_test_transaction,
        make_test_transaction_with_response,
    };
    use rstest::rstest;

    fn run(tx: &crate::http_transaction::HttpTransaction) -> Option<Violation> {
        let rule = UpgradeAndConnectionConsistent;
        crate::test_helpers::run_rule(
            &rule,
            tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &make_test_config_with_enabled_rules(&[rule.id()]),
        )
    }

    /// A request whose `Upgrade` is named in `Connection`, and one whose is not.
    #[rstest]
    // The RFC's own hypothetical request, minus the fields this rule does not read.
    #[case(vec![("connection", "upgrade"), ("upgrade", "websocket, IRC/6.9, RTA/x11")], false)]
    // A connection-option is a field name, and those are case-insensitive.
    #[case(vec![("connection", "keep-alive, Upgrade"), ("upgrade", "websocket")], false)]
    // The field with no option beside it, the two ways it happens.
    #[case(vec![("upgrade", "websocket")], true)]
    #[case(vec![("connection", "keep-alive"), ("upgrade", "websocket")], true)]
    // The direction this rule used to report, and the sentence that permits it.
    #[case(vec![("connection", "upgrade")], false)]
    #[case(vec![("connection", "keep-alive")], false)]
    #[case(vec![], false)]
    // `Upgrade = #protocol`: a value naming no protocol is still a field the sender
    // wrote, and the intermediary it has to be hidden from is the same one.
    #[case(vec![("upgrade", "")], true)]
    #[case(vec![("connection", "upgrade"), ("upgrade", "")], false)]
    fn request_cases(#[case] header_pairs: Vec<(&str, &str)>, #[case] expect_violation: bool) {
        let mut tx = make_test_transaction();
        tx.request.headers = make_headers_from_pairs(header_pairs.as_slice());
        assert_eq!(run(&tx).is_some(), expect_violation);
    }

    /// The option written on a second `Connection` line is listed: one field name
    /// repeated in one section is one value.
    #[test]
    fn an_option_on_a_second_connection_line_is_listed() {
        let mut tx = make_test_transaction();
        tx.request.headers = make_headers_from_pairs(&[
            ("connection", "keep-alive"),
            ("connection", "upgrade"),
            ("upgrade", "websocket"),
        ]);
        assert!(run(&tx).is_none());
    }

    /// An `obs-text` octet elsewhere in the value does not hide the option beside it.
    /// Read back through a UTF-8 decoder this `Connection` is no `Connection` at all,
    /// and a conforming message would be reported for the option it did send.
    #[test]
    fn an_obs_text_octet_does_not_hide_the_option() {
        let mut tx = make_test_transaction();
        tx.request.headers = make_headers_from_octet_pairs(&[
            ("connection", b"upgrade, x\xE9y"),
            ("upgrade", b"websocket"),
        ]);
        assert!(run(&tx).is_none());
    }

    /// The same octet in the `Upgrade` value does not stand the obligation down: the
    /// sender wrote the field, whatever it wrote in it.
    #[test]
    fn an_obs_text_upgrade_value_still_owes_the_option() {
        let mut tx = make_test_transaction();
        tx.request.headers = make_headers_from_octet_pairs(&[("upgrade", b"websock\xE9t")]);
        let violation = run(&tx).expect("a field without its option");
        assert!(
            violation.message.contains("no Connection field"),
            "{}",
            violation.message
        );
    }

    /// The finding names what `Connection` did say, so an operator can tell a sender
    /// that omitted the option from one that omitted the field.
    #[test]
    fn the_finding_names_the_connection_value() {
        let mut tx = make_test_transaction();
        tx.request.headers =
            make_headers_from_pairs(&[("connection", "keep-alive"), ("upgrade", "websocket")]);
        let violation = run(&tx).expect("a field without its option");
        assert!(
            violation.message.contains("names `keep-alive`"),
            "{}",
            violation.message
        );
    }

    /// The version gate, over the fixture the rule *does* report. Only the version
    /// changes between the case that fires and the two that do not, so neither gate
    /// half can be deleted with the test still green.
    #[rstest]
    #[case("HTTP/1.1", true)]
    #[case("HTTP/1.0", true)]
    #[case("HTTP/2.0", false)]
    #[case("HTTP/3.0", false)]
    fn the_request_version_decides(#[case] version: &str, #[case] expect_violation: bool) {
        let mut tx = make_test_transaction();
        tx.request.headers = make_headers_from_pairs(&[("upgrade", "websocket")]);
        tx.request.version = version.into();
        assert_eq!(run(&tx).is_some(), expect_violation);
    }

    /// A response is measured the same way, and against its own version: a reverse
    /// proxy may have taken an HTTP/3 request and answered it from an HTTP/1.1 origin.
    #[rstest]
    #[case(vec![("upgrade", "websocket")], true)]
    #[case(vec![("connection", "upgrade"), ("upgrade", "websocket")], false)]
    #[case(vec![("connection", "upgrade")], false)]
    fn response_cases(#[case] header_pairs: Vec<(&str, &str)>, #[case] expect_violation: bool) {
        let mut tx = make_test_transaction_with_response(101, &header_pairs);
        tx.request.version = "HTTP/3.0".into();
        if let Some(resp) = tx.response.as_mut() {
            resp.version = "HTTP/1.1".into();
        }
        assert_eq!(run(&tx).is_some(), expect_violation);
    }

    /// And the response's own version stands it down, where the request's does not.
    #[test]
    fn an_http2_response_is_not_asked_for_the_option() {
        let mut tx = make_test_transaction_with_response(200, &[("upgrade", "websocket")]);
        tx.request.version = "HTTP/1.1".into();
        if let Some(resp) = tx.response.as_mut() {
            resp.version = "HTTP/2.0".into();
        }
        assert!(run(&tx).is_none());
    }

    #[test]
    fn scope_is_both() {
        let rule = UpgradeAndConnectionConsistent;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }
}
