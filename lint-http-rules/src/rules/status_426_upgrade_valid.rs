// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::helpers::headers::{combined_field_value_as_written, trim_ows};
use crate::lint::Violation;
use crate::rules::Rule;

pub struct Status426UpgradeValid;

impl Rule for Status426UpgradeValid {
    fn id(&self) -> &'static str {
        "status_426_upgrade_valid"
    }

    /// The requirement's subject is the server and its evidence is a response, so
    /// a capture whose upstream never answered has nothing to measure and this is
    /// the scope that skips exactly those.
    ///
    /// cite(RFC 9110 § 15.5.22): "The server MUST send an Upgrade header field in a 426 response to indicate the required protocol(s) (Section 7.8)."
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

        // The status is the whole antecedent. On every other response the field is
        // a MAY -- a server advertising what it would upgrade to for some future
        // request -- so its absence there says nothing.
        //
        // cite(RFC 9110 § 7.8): "A server MAY send an Upgrade header field in any other response to advertise that it implements support for upgrading to the listed protocols, in order of descending preference, when appropriate for a future request."
        if resp.status != 426 {
            return None;
        }

        // **The version that carried the response is the version that decides
        // whether this MUST can be obeyed at all**, and over two of them it cannot:
        // `Upgrade` is a connection-specific field an HTTP/2 endpoint MUST NOT
        // generate, and HTTP/3 does not have the mechanism the field belongs to.
        // Asking for the field there would be telling a server to write one whose
        // presence makes its own message malformed -- the shape
        // `sec_websocket_headers_consistent` was reported for, one document
        // over. A 426 that does carry the field on those versions is reported by
        // `no_connection_specific_fields`, which is the sentence that
        // applies to it.
        //
        // The response's own version, not the request's: a reverse proxy may have
        // taken the request over one version and answered it from an origin
        // speaking another, and the section that would have carried the field is
        // the one this response wrote. The test is *"not one of the two that
        // forbid it"* rather than *"is HTTP/1.x"*, so a version deriving from no
        // production is measured -- the status is on the wire either way.
        //
        // cite(RFC 9113 § 8.2.2): "An endpoint MUST NOT generate an HTTP/2 message containing connection-specific header fields."
        // cite(RFC 9114 § 4.5): "HTTP/3 does not support the HTTP Upgrade mechanism (Section 7.8 of [HTTP]) or the 101 (Switching Protocols) informational status code (Section 15.2.2 of [HTTP])."
        if matches!(crate::http_version::major(&resp.version), Some(2 | 3)) {
            return None;
        }

        // Read after both gates: only a response this rule could report pays for
        // the map probes and the two lookups of the rule id.
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;

        // One field section is one value however many lines carry it, and the join
        // is over the octets as written: reading them back through a UTF-8 decoder
        // would turn a value carrying `obs-text` into a response with no `Upgrade`
        // at all, and this rule would report a server that did send the field.
        // Whether what it sent derives from `protocol` is
        // `upgrade_header_syntax`'s question.
        //
        // cite(RFC 9110 § 5.2): "When a field name is repeated within a section, its combined field value consists of the list of corresponding field line values within that section, concatenated in order, with each field line value separated by a comma."
        let value = combined_field_value_as_written(&resp.headers, "upgrade");

        let Some(value) = value else {
            // A trailer field does not answer it. The requirement names a header
            // field, and § 6.5.1 forbids a trailer field unless the field's own
            // definition permits one, which § 7.8 does not -- a server that wrote
            // it there has a different thing to fix from one that wrote nothing,
            // so the finding says which. That the placement is itself a defect is
            // `trailer_fields_valid`'s finding, whose § 6.5.1 table
            // names this field.
            //
            // cite(RFC 9110 § 6.5.1): "A sender MUST NOT generate a trailer field unless the sender knows the corresponding header field name's definition permits the field to be sent in trailers."
            let in_trailer_section = resp
                .trailers
                .as_ref()
                .is_some_and(|trailers| trailers.contains_key("upgrade"));

            return Some(self.violation(
                config.severity,
                format!(
                    "426 Upgrade Required with no Upgrade header field. The status says the server \
                     refuses the request under the current protocol but might comply after the \
                     client upgrades, and the field is what names the protocol to upgrade *to*; \
                     without it the response asks for a change it does not describe (RFC 9110 \
                     §15.5.22){}",
                    if in_trailer_section {
                        ". This response's trailer section carries an Upgrade, and a trailer field \
                         does not answer a requirement on the header section"
                    } else {
                        ""
                    }
                ),
            ));
        };

        // **The MUST does not stop at the field's name**, and both sentences that
        // state it say so in their object clause: the field is sent *to indicate
        // the required protocol(s)* / *the acceptable protocols*. `Upgrade` is
        // `#protocol`, so a value naming none is a well-formed list -- reported
        // here not as a grammar defect but as a field that does not do the one
        // thing this status sends it for. On any other response the same value is
        // nobody's finding, which is what makes this the status's requirement
        // rather than the field's.
        //
        // The trim is § 5.5's: a value that is only whitespace is the empty value.
        //
        // cite(RFC 9110 § 7.8): "A server that sends a 426 (Upgrade Required) response MUST send an Upgrade header field to indicate the acceptable protocols, in order of descending preference."
        // cite(RFC 9110 § 15.5.22): "The 426 (Upgrade Required) status code indicates that the server refuses to perform the request using the current protocol but might be willing to do so after the client upgrades to a different protocol."
        // cite(RFC 9110 § 5.5): "A field value does not include leading or trailing whitespace.  When a specific version of HTTP allows such whitespace to appear in a message, a field parsing implementation MUST exclude such whitespace prior to evaluating the field value."
        if trim_ows(&value).is_empty() {
            return Some(self.violation(
                config.severity,
                "426 Upgrade Required whose Upgrade header field names no protocol. The field is \
                 `#protocol`, so an empty value is a well-formed list of none — but the requirement \
                 is to send the field *to indicate the required protocol(s)*, and a client reading \
                 this response has nothing to upgrade to (RFC 9110 §15.5.22, §7.8)"
                    .to_string(),
            ));
        }

        None
    }

    fn description(&self) -> &'static str {
        "Reports a `426 (Upgrade Required)` response that carries no `Upgrade` header field, and one whose `Upgrade` names no protocol.\n\n**The requirement is stated twice, in the two sections that own the halves of it.** RFC 9110 §15.5.22: *The server MUST send an Upgrade header field in a 426 response to indicate the required protocol(s) (Section 7.8).* And §7.8, from the field's side: *A server that sends a 426 (Upgrade Required) response MUST send an Upgrade header field to indicate the acceptable protocols, in order of descending preference.* The status itself is what makes the field load-bearing — it says the server *refuses to perform the request using the current protocol but might be willing to do so after the client upgrades to a different protocol*, so a 426 with no `Upgrade` asks for a change it does not describe.\n\n**The second finding is the clause after \"to indicate\".** `Upgrade` is `#protocol`, so `Upgrade:` is a well-formed list of no protocols and no grammar rule reports it — `upgrade_header_syntax` says so explicitly. What this rule reports is not the grammar but the purpose: on a 426 the field is sent to name what to upgrade to, and a list of none names nothing. On every other response that same value draws nothing from anybody, which is what makes this the *status's* requirement rather than the field's. (Contrast `Allow` on a 405, where §10.2.1 gives the empty value a documented meaning — *the resource allows no methods* — and `status_405_allow_valid` therefore accepts it.)\n\n**Two versions are declined, and each has its own sentence.** Over HTTP/2 an endpoint MUST NOT generate a message containing connection-specific header fields (RFC 9113 §8.2.2), and over HTTP/3 the Upgrade mechanism does not exist at all (RFC 9114 §4.5) — so on those versions this MUST cannot be obeyed, and asking for the field would be advice a server must not follow. That is the defect `sec_websocket_headers_consistent` was once reported for: a rule demanding a field on versions that forbid it. A 426 that *does* carry `Upgrade` there is reported by `no_connection_specific_fields`, with the version's own sentence, so nothing is unreported by this decline. The **response's** version decides it, not the request's: a reverse proxy may have taken the request over one version and answered from an origin speaking another, and the field would have been written in the section this response carries. The test is *not one of the two that forbid it* rather than *is this HTTP/1.x*, so a version deriving from no `HTTP-version` production is still measured.\n\n**A trailer does not answer it.** The requirement names a header field, and §6.5.1 forbids a trailer field unless the field's own definition permits one, which §7.8 does not. A 426 carrying `Upgrade` only in its trailer section is reported here as carrying none, and the finding says the trailer was seen; that the placement is itself a defect is `trailer_fields_valid`'s finding, whose §6.5.1 table names this field.\n\n**Not reported: the order.** §7.8 asks for the protocols *in order of descending preference*, which is what a sender meant by the order it wrote — no field records a preference for the order to disagree with. Nor is any name checked against the Upgrade Token Registry: §16.7's policy is First Come First Served and §7.8's *ought to be registered* is not a requirement.\n\n**What the neighbours own.** Whether the value derives from `protocol = protocol-name [\"/\" protocol-version]` is `upgrade_header_syntax`'s. Whether the field is named by an `upgrade` connection option — which §7.8 asks of every sender of `Upgrade`, including this one — is `upgrade_and_connection_consistent`'s. The mirror requirement on a `101` response, and the rule that the chosen protocol was one the client offered, is `status_101_switching_protocols`'s.\n\nScope: this rule reads a response's header section, and its subject is *the server* — whatever answered, which for a capture taken at a proxy is the party that wrote this response. Where the field appears on several lines they are one value (§5.2), and the value is read as written rather than through a UTF-8 decode, so a field carrying `obs-text` counts as a field that is there."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("15.5.22"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5.22",
                note: "426 Upgrade Required — the MUST, its object clause (to indicate the \
                       required protocol(s)), and what the status itself says the server is \
                       asking the client to do",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("7.8"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-7.8",
                note: "Upgrade — the same MUST from the field's side, worded with the ordering \
                       clause; also the MAY that licenses the field's absence on every other \
                       response",
            },
            crate::rules::SpecRef {
                spec: "RFC 9113",
                section: Some("8.2.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9113.html#section-8.2.2",
                note: "Connection-Specific Header Fields — why an HTTP/2 response is not asked \
                       for a field it must not generate",
            },
            crate::rules::SpecRef {
                spec: "RFC 9114",
                section: Some("4.5"),
                url: "https://www.rfc-editor.org/rfc/rfc9114.html#section-4.5",
                note: "HTTP Upgrade — HTTP/3 does not have the mechanism this field belongs to, \
                       which is a stronger reason than the field being forbidden",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("5.5"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.5",
                note: "A field value excludes the whitespace around it, so a value that is only \
                       whitespace is the empty value",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("5.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.2",
                note: "Several `Upgrade` lines in one field section are one field value, so the \
                       field is there if any line carries it",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("6.5.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-6.5.1",
                note: "Why an `Upgrade` in the trailer section does not answer this requirement — \
                       a trailer field needs its own definition's permission, and §7.8 gives none",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("§15.5.22's own worked example"),
                snippet: "GET /resource HTTP/1.1\nHost: example.com\n\nHTTP/1.1 426 Upgrade Required\nUpgrade: HTTP/3.0\nConnection: Upgrade\nContent-Type: text/plain",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("Every other response MAY carry the field, so its absence says nothing"),
                snippet: "GET /resource HTTP/1.1\nHost: example.com\n\nHTTP/1.1 200 OK\nContent-Type: text/plain",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("The MUST's own subject — a 426 carrying no Upgrade at all"),
                snippet: "GET /resource HTTP/1.1\nHost: example.com\n\nHTTP/1.1 426 Upgrade Required\nContent-Type: text/plain",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("The clause after \"to indicate\" — a list of no protocols names none"),
                snippet: "GET /resource HTTP/1.1\nHost: example.com\n\nHTTP/1.1 426 Upgrade Required\nUpgrade:\nConnection: Upgrade",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &Status426UpgradeValid;

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;
    use hyper::HeaderMap;
    use rstest::rstest;

    const RULE: Status426UpgradeValid = Status426UpgradeValid;

    /// Run the rule over a response of `status` carried by `version`, with the
    /// given header field lines and trailer field names.
    ///
    /// The lines are appended rather than inserted, because several field lines in
    /// one section are one value and a single-line helper cannot reach that case;
    /// they go in as octets, because a value carrying `obs-text` is not a string
    /// any Rust source file can stand in for.
    fn check(
        version: &str,
        status: u16,
        lines: &[(&str, &[u8])],
        trailers: &[&str],
    ) -> Option<Violation> {
        let tx = transaction(version, status, lines, trailers);
        crate::test_helpers::run_rule(
            &RULE,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[RULE.id()]),
        )
    }

    /// The fixture behind [`check`], separate so the published examples can be
    /// handed to the neighbouring rules as well as to this one.
    fn transaction(
        version: &str,
        status: u16,
        lines: &[(&str, &[u8])],
        trailers: &[&str],
    ) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(status, &[]);
        let resp = tx.response.as_mut().expect("response");
        resp.version = version.to_string();
        let mut hm = HeaderMap::new();
        for (name, value) in lines {
            hm.append(
                hyper::header::HeaderName::from_bytes(name.as_bytes()).expect("field name"),
                HeaderValue::from_bytes(value).expect("field value"),
            );
        }
        resp.headers = hm;
        if !trailers.is_empty() {
            let mut t = HeaderMap::new();
            for name in trailers {
                t.append(
                    hyper::header::HeaderName::from_bytes(name.as_bytes()).expect("field name"),
                    HeaderValue::from_static("websocket"),
                );
            }
            resp.trailers = Some(t);
        }
        tx
    }

    #[test]
    fn a_426_naming_a_protocol_answers_the_must() {
        let v = check("HTTP/1.1", 426, &[("upgrade", b"HTTP/3.0")], &[]);
        assert!(v.is_none(), "{v:?}");
    }

    /// The field is one value however many lines carry it, so a second line
    /// naming the protocol answers the requirement as well as a first would.
    #[test]
    fn the_lines_of_one_section_are_one_value() {
        let v = check(
            "HTTP/1.1",
            426,
            &[("upgrade", b"" as &[u8]), ("upgrade", b"HTTP/3.0")],
            &[],
        );
        assert!(v.is_none(), "{v:?}");
    }

    #[test]
    fn a_426_with_no_upgrade_field_is_the_must_unmet() {
        let v = check("HTTP/1.1", 426, &[("content-type", b"text/plain")], &[])
            .expect("the MUST is unmet");
        assert!(
            v.message.contains("no Upgrade header field"),
            "{}",
            v.message
        );
        assert!(
            !v.message.contains("trailer section carries"),
            "{}",
            v.message
        );
    }

    /// A trailer does not answer a requirement on the header section, and the
    /// finding says the trailer was seen so the two mistakes are told apart.
    #[test]
    fn an_upgrade_in_the_trailer_section_does_not_answer_it() {
        let v = check("HTTP/1.1", 426, &[], &["upgrade"]).expect("the MUST is unmet");
        assert!(
            v.message.contains("trailer section carries an Upgrade"),
            "{}",
            v.message
        );
    }

    /// The value is read as the sender wrote it: an `obs-text` octet does not
    /// turn a response that sent the field into one that did not.
    #[test]
    fn an_obs_text_value_is_a_field_that_is_there() {
        let v = check("HTTP/1.1", 426, &[("upgrade", b"HTTP/3.\xff")], &[]);
        assert!(v.is_none(), "{v:?}");
    }

    /// `#protocol` makes an empty value a well-formed list, so no grammar rule
    /// reports it — and the MUST's object clause is what does.
    #[rstest]
    #[case(b"")]
    #[case(b" ")]
    #[case(b"\t")]
    fn a_426_whose_upgrade_names_no_protocol_is_the_object_clause_unmet(#[case] value: &[u8]) {
        let v = check("HTTP/1.1", 426, &[("upgrade", value)], &[]).expect("the MUST is unmet");
        assert!(v.message.contains("names no protocol"), "{}", v.message);
    }

    /// Every other status carries the field under a MAY, so its absence there is
    /// a server taking the licence rather than a defect. `426` is the only
    /// value that changes between these cases and the ones above it.
    #[rstest]
    #[case(200)]
    #[case(101)]
    #[case(400)]
    #[case(427)]
    #[case(425)]
    fn no_other_status_is_asked_for_the_field(#[case] status: u16) {
        let v = check("HTTP/1.1", status, &[("content-type", b"text/plain")], &[]);
        assert!(v.is_none(), "{status}: {v:?}");
    }

    /// Over these two versions the MUST cannot be obeyed: the field is forbidden
    /// (RFC 9113 §8.2.2) and the mechanism does not exist (RFC 9114 §4.5).
    /// Asking for it would be advice a server must not follow.
    #[rstest]
    #[case("HTTP/2.0", false)]
    #[case("HTTP/3.0", false)]
    #[case("HTTP/1.1", true)]
    #[case("HTTP/1.0", true)]
    // A value deriving from no `HTTP-version` names no major version, so it falls
    // through to the measurement rather than out of it.
    #[case("HTTP/2", true)]
    #[case("", true)]
    fn the_responses_own_version_decides(#[case] version: &str, #[case] expect_violation: bool) {
        let v = check(version, 426, &[("content-type", b"text/plain")], &[]);
        assert_eq!(v.is_some(), expect_violation, "{version}: {v:?}");
    }

    /// The request's version does not decide it: a reverse proxy may have taken
    /// an HTTP/3 request and answered it from an HTTP/1.1 origin, and the field
    /// would have been written in the section this response carries.
    #[test]
    fn the_requests_version_does_not_stand_the_requirement_down() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(426, &[]);
        tx.request.version = "HTTP/3.0".into();
        tx.response.as_mut().expect("response").version = "HTTP/1.1".into();
        let v = crate::test_helpers::run_rule(
            &RULE,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[RULE.id()]),
        )
        .expect("the MUST is unmet");
        assert!(
            v.message.contains("no Upgrade header field"),
            "{}",
            v.message
        );
    }

    #[test]
    fn a_transaction_with_no_response_is_not_measured() {
        let tx = crate::test_helpers::make_test_transaction();
        let v = crate::test_helpers::run_rule(
            &RULE,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[RULE.id()]),
        );
        assert!(v.is_none(), "{v:?}");
    }

    /// Every published snippet is run through the rule, response version and all
    /// — and then through the two neighbours that read the same field, because a
    /// snippet this rule calls clean while another page reports it is one
    /// changeset disagreeing with itself.
    #[test]
    fn published_examples_agree_with_the_rule_and_with_the_neighbours() {
        use crate::rules::{Compliance, Rule as _};

        let mut asserted_a_finding = false;
        let neighbours: [(&dyn crate::rules::Rule, &str); 2] = [
            (
                &crate::rules::upgrade_and_connection_consistent::UpgradeAndConnectionConsistent,
                "upgrade_and_connection_consistent",
            ),
            (
                &crate::rules::upgrade_header_syntax::UpgradeHeaderSyntax,
                "upgrade_header_syntax",
            ),
        ];

        for example in RULE.examples() {
            let (_, response) = example
                .snippet
                .split_once("\n\n")
                .expect("every example writes both halves of the exchange");

            let mut lines = response.lines();
            let status_line = lines.next().expect("a status line");
            let mut parts = status_line.split_whitespace();
            let version = parts.next().expect("a status line names a version");
            let status: u16 = parts
                .next()
                .and_then(|s| s.parse().ok())
                .expect("a status line names a status code");

            // Split on the colon rather than on `": "`, or the field line written
            // with an empty value — the one the second finding is about — is
            // dropped and that example silently becomes a response with no
            // `Upgrade` at all, which the other finding would report anyway.
            let fields: Vec<(String, Vec<u8>)> = lines
                .filter_map(|l| l.split_once(':'))
                .map(|(n, v)| {
                    (
                        n.to_ascii_lowercase(),
                        v.strip_prefix(' ').unwrap_or(v).as_bytes().to_vec(),
                    )
                })
                .collect();
            let borrowed: Vec<(&str, &[u8])> = fields
                .iter()
                .map(|(n, v)| (n.as_str(), v.as_slice()))
                .collect();

            let tx = transaction(version, status, &borrowed, &[]);
            for (neighbour, id) in neighbours {
                let v = crate::test_helpers::run_rule(
                    neighbour,
                    &tx,
                    &crate::transaction_history::TransactionHistory::empty(),
                    &crate::test_helpers::make_test_config_with_severity(id, "warn"),
                );
                assert!(
                    v.is_none(),
                    "a published example is reported by {id}: {v:?}\n{}",
                    example.snippet
                );
            }

            let violation = check(version, status, &borrowed, &[]);
            match example.compliance {
                Compliance::Compliant => assert!(
                    violation.is_none(),
                    "compliant example reported: {} -> {violation:?}",
                    example.snippet
                ),
                Compliance::NonCompliant => {
                    assert!(
                        violation.is_some(),
                        "non-compliant example not reported: {}",
                        example.snippet
                    );
                    asserted_a_finding = true;
                }
            }
        }

        assert!(asserted_a_finding, "no example exercised a finding");
    }

    #[test]
    fn scope_is_server() {
        assert_eq!(RULE.scope(), crate::rules::RuleScope::Server);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "status_426_upgrade_valid");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
