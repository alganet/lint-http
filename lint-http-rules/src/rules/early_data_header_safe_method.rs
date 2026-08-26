// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// The field name, in the lowercase spelling a `HeaderMap` indexes by.
const FIELD: &str = "early-data";

#[derive(Debug, Clone)]
pub struct EarlyDataConfig {
    pub severity: crate::lint::Severity,
    pub safe_methods: Vec<String>,
}

/// Reads the `safe_methods` array this rule cannot supply for itself.
///
/// Safety is a property of a method, not a property of the four methods RFC 9110
/// happens to define — it is a required field of every entry in an IANA registry that
/// grows by IETF Review, and nine of its entries carry `Safe: yes` today. A list
/// compiled in here would be a snapshot of that registry pretending to be the grammar.
/// The array is also where a deployment says what it knows about its own methods,
/// which is the state the licensing sentence in § 4 opens with: *"Absent other
/// information"*.
// cite(RFC 9110 § 16.1.1): "The "Hypertext Transfer Protocol (HTTP) Method Registry", maintained by IANA at <https://www.iana.org/assignments/http-methods>, registers method names."
// cite(RFC 9110 § 16.1.1): "HTTP method registrations MUST include the following fields:"
// cite(RFC 9110 § 16.1.1): "Safe ("yes" or "no", see Section 9.2.1)"
// cite(RFC 9110 § 16.1.1): "Values to be added to this namespace require IETF Review"
fn parse_early_data_config(
    config: &crate::config::Config,
    rule_id: &str,
) -> anyhow::Result<EarlyDataConfig> {
    let severity = crate::rules::get_rule_severity_required(config, rule_id)?;

    let rule_cfg = config.get_rule_config(rule_id).ok_or_else(|| {
        anyhow::anyhow!(
            "rule '{}' requires configuration and a named 'safe_methods' array listing the methods this deployment knows to be safe. Example in config_example.toml",
            rule_id
        )
    })?;
    let table = rule_cfg
        .as_table()
        .ok_or_else(|| anyhow::anyhow!("Configuration for rule '{}' must be a table", rule_id))?;

    let value = table.get("safe_methods").ok_or_else(|| {
        anyhow::anyhow!(
            "Rule '{}' requires a 'safe_methods' array listing the methods this deployment knows to be safe (e.g., ['GET','HEAD','OPTIONS','TRACE'])",
            rule_id
        )
    })?;

    let arr = value.as_array().ok_or_else(|| {
        anyhow::anyhow!("'safe_methods' must be an array of strings (e.g., ['GET','HEAD'])")
    })?;

    // No sentence forbids an empty array. It is refused because the rule it configures
    // would then report every request that reached a server through early data, which
    // reads as a broken linter rather than as a deployment that knows no method to be
    // safe.
    if arr.is_empty() {
        return Err(anyhow::anyhow!("'safe_methods' array cannot be empty"));
    }

    let mut safe_methods = Vec::new();
    for (i, item) in arr.iter().enumerate() {
        let s = item.as_str().ok_or_else(|| {
            anyhow::anyhow!("'safe_methods' array item at index {} must be a string", i)
        })?;
        // Kept as written, and the contrast with the configured field-name arrays is
        // the point: a field name means the same thing however it is spelled and is
        // folded once per array, while a method does not. `get` is not `GET`; it is a
        // method this specification does not define, so its safety is not known.
        // cite(RFC 9110 § 9.1): "The method token is case-sensitive because it might be used as a gateway to object-based systems with case-sensitive method names."
        safe_methods.push(s.to_string());
    }

    Ok(EarlyDataConfig {
        severity,
        safe_methods,
    })
}

pub struct EarlyDataHeaderSafeMethod;

impl EarlyDataHeaderSafeMethod {
    /// Whether this section's `Connection` field names `early-data`.
    ///
    /// The field lines are joined first: `Connection = #connection-option`, so a member
    /// may be written on a line of its own, and the shared reader is the one that knows
    /// what a message's connection-options are.
    fn connection_names_early_data(
        &self,
        config: &EarlyDataConfig,
        section: &str,
        headers: &hyper::HeaderMap,
    ) -> Option<Violation> {
        let connection =
            crate::helpers::headers::combined_field_value_as_written(headers, "connection")?;
        if !crate::helpers::headers::is_nominated_by_connection(FIELD, Some(&connection)) {
            return None;
        }
        Some(self.violation(
            config.severity,
            format!(
                "The {section} names Early-Data as a connection-option in its Connection header field, so every intermediary removes the field before forwarding — which is what RFC 8470 §5.1 forbids an intermediary to do to it"
            ),
        ))
    }
}

impl Rule for EarlyDataHeaderSafeMethod {
    fn id(&self) -> &'static str {
        "early_data_header_safe_method"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        // The field is a request header field, and one of the sentences that govern it
        // names a response as a place it MUST NOT be — so the response half of a
        // transaction is read too, and `Server` would have skipped every capture whose
        // upstream never answered.
        // cite(RFC 8470 § 5.1): "An Early-Data header field MUST NOT be included in responses or request trailers."
        crate::rules::RuleScope::Both
    }

    fn prepare(&self, cfg: &crate::config::Config) -> anyhow::Result<crate::rules::ResolvedRule> {
        let config = parse_early_data_config(cfg, self.id())?;
        // The two standard keys, **after** this rule's own options, so a config
        // naming a bad option still fails on that option.
        crate::rules::validate_rule_table(cfg, self.id())?;
        Ok(crate::rules::ResolvedRule {
            severity: config.severity,
            state: Box::new(config),
        })
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Option<Violation> {
        let config: &EarlyDataConfig = ctx.state();

        // A count, not a value: the field is a singleton whose whole grammar is one
        // literal, so several field lines is a defect of its own rather than a longer
        // value — and the sentence that says so also says what a recipient does with
        // them.
        // cite(RFC 8470 § 5.1): "The Early-Data header field carries a single bit of information, and clients MUST include at most one instance."
        let instances = tx.request.headers.get_all(FIELD).iter().count();

        if instances > 0 {
            // The finding rests on the field being *there*, not on it saying "1". A
            // server MUST read any number of instances carrying anything as one
            // instance saying 1, so `Early-Data: 0` is a request a server treats as
            // having come through early data — which is what the next sentence says
            // such a request is.
            // cite(RFC 8470 § 5.1): "Multiple or invalid instances of the header field MUST be treated as equivalent to a single instance with a value of 1 by a server."
            // cite(RFC 8470 § 5.1): "A request that is marked with Early-Data was sent in early data on a previous hop."
            // cite(RFC 8470 § 5.1): "The Early-Data request header field indicates that the request has been conveyed in early data and that a client understands the 425 (Too Early) status code."
            //
            // The method is compared as it was written, and nothing is trimmed off it:
            // `method = token`, a `token` is `1*tchar`, and there is no whitespace in
            // that production for a trim to find.
            // cite(RFC 9110 § 9.1): "The method token is case-sensitive because it might be used as a gateway to object-based systems with case-sensitive method names."
            //
            // The parenthesis is the half that decides an unrecognized method: a method
            // this deployment does not list is not thereby unsafe, it is a method whose
            // safety is not known, and the sentence names that case beside the unsafe
            // one.
            // cite(RFC 8470 § 4): "Absent other information, clients MAY send requests with safe HTTP methods ([RFC7231], Section 4.2.1) in early data when it is available and MUST NOT send unsafe methods (or methods whose safety is not known) in early data."
            // cite(RFC 9110 § 9.2.1): "Request methods are considered "safe" if their defined semantics are essentially read-only; i.e., the client does not request, and does not expect, any state change on the origin server as a result of applying a safe method to a target resource."
            if !config.safe_methods.iter().any(|m| m == &tx.request.method) {
                return Some(self.violation(
                    config.severity,
                    format!(
                        "Request carrying an Early-Data header field was conveyed in TLS early data on a previous hop (RFC 8470 §5.1), and its method '{}' is not one this deployment lists as safe; RFC 8470 §4 has a client send only safe methods in early data, because a replayed unsafe request takes effect twice",
                        tx.request.method
                    ),
                ));
            }

            // Where a second line comes from is in the parenthesis of the sentence that
            // has an intermediary write the field: it adds one only where there is none.
            // cite(RFC 8470 § 5.1): "An intermediary that forwards a request prior to the completion of the TLS handshake with its client MUST send it with the Early-Data header field set to "1" (i.e., it adds it if not present in the request)."
            if instances > 1 {
                return Some(self.violation(
                    config.severity,
                    format!(
                        "Request carries {instances} Early-Data header field lines, and a client may send at most one — the field holds a single bit. A server reads them as one instance with the value 1, so the extra lines change nothing about the request; an intermediary marking early data adds the field only when it is not already there"
                    ),
                ));
            }

            // Exactly one line here, so the value is that line's octets, and the `else`
            // is unreachable rather than a judgement. Compared as octets, because the
            // only question asked of them is whether they are this one literal — and
            // equality of two field values is equality of two octet strings, which no
            // decode is needed to answer.
            // cite(RFC 8470 § 5.1): "It has just one valid value: "1"."
            if let Some(hv) = tx.request.headers.get(FIELD) {
                let written = hv.as_bytes();
                if written != b"1" {
                    return Some(self.violation(
                        config.severity,
                        format!(
                            "Early-Data header field carries {}, and the field has exactly one valid value, \"1\". A server treats an invalid instance as though it said 1, so the request is marked as early data all the same — the value is simply wrong",
                            describe_value(written)
                        ),
                    ));
                }
            }
        }

        // The prohibition is on what a `Connection` field says, in either direction and
        // whether or not `Early-Data` is present — so it is asked of both sections at
        // the sentence's own width. The request is the case it exists for: naming the
        // field as a connection-option has every intermediary strip it before
        // forwarding, which is the one thing the field must survive, and the sentence
        // before this one forbids removing it.
        // cite(RFC 8470 § 5.1): "An intermediary MUST NOT remove this header field if it is present in a request."
        // cite(RFC 8470 § 5.1): "Early-Data MUST NOT appear in a Connection header field."
        if let Some(v) = self.connection_names_early_data(config, "request", &tx.request.headers) {
            return Some(v);
        }

        if let Some(resp) = &tx.response {
            // cite(RFC 8470 § 5.1): "An Early-Data header field MUST NOT be included in responses or request trailers."
            if resp.headers.contains_key(FIELD) {
                return Some(self.violation(
                    config.severity,
                    "Response carries an Early-Data header field. The field is a request header field: it tells a server that a request reached it through early data, and a response has nothing to mark".to_string(),
                ));
            }
            if let Some(v) = self.connection_names_early_data(config, "response", &resp.headers) {
                return Some(v);
            }
        }

        None
    }

    fn description(&self) -> &'static str {
        "Reports a request that was conveyed in TLS early data — a request carrying an `Early-Data` header field — under a method this deployment does not list as safe. RFC 8470 §4: \"Absent other information, clients MAY send requests with safe HTTP methods … in early data when it is available and MUST NOT send unsafe methods (or methods whose safety is not known) in early data.\" Early data can be captured and replayed by an attacker, so a request that changes state may take effect more than once.\n\n**The field's presence is the signal, not its value.** RFC 8470 §5.1 gives the field one valid value, `1`, and then says what a server does with anything else: \"Multiple or invalid instances of the header field MUST be treated as equivalent to a single instance with a value of 1 by a server.\" So `Early-Data: 0`, an empty value, a value that is not US-ASCII, and two field lines all describe the same request — one a server must treat as having arrived through early data. The value and the line count are each reported separately, as what they are.\n\n**The sender of the message is usually not the party that broke the requirement.** §5.1: \"A request that is marked with Early-Data was sent in early data on a previous hop\", and the field \"is not intended for use by user agents (that is, the original initiator of a request)\" — an intermediary forwarding a request before its TLS handshake completed MUST add it. So a finding here says an unsafe method entered early data somewhere along the chain; which hop put it there is not in the message.\n\n**`safe_methods` is required, and the reason is that safety is a registry field.** RFC 9110 §16.1.1 makes `Safe (\"yes\" or \"no\")` a mandatory part of every method registration, and entries are added by IETF Review — `GET`, `HEAD`, `OPTIONS` and `TRACE` are only the ones RFC 9110 itself defines, while `PRI`, `PROPFIND`, `QUERY`, `REPORT` and `SEARCH` are registered safe by other documents. A list compiled into this rule would be a snapshot of that registry presented as though it were the grammar. The array is also where a deployment records what it knows about its own methods, which is the state §4's sentence opens with — \"Absent other information\".\n\nMethods are matched exactly. RFC 9110 §9.1: \"The method token is case-sensitive\", so `get` is not `GET` but a method this specification does not define, and §4's parenthetical — \"or methods whose safety is not known\" — is what covers it. A method absent from the array is reported for that reason, not for being unsafe.\n\n**Three further sentences of §5.1 are enforced here, because this rule is the field's only reader.** A client may send at most one instance. The field MUST NOT appear in a response. And it MUST NOT be named as a connection-option in a `Connection` header field, which would have every intermediary strip the one field §5.1 forbids removing. The remaining placement — the field arriving in a trailer section — is `trailer_fields_valid`'s finding, since that is where RFC 9110 §6.5.1 is applied.\n\n**Not checked here.** Whether a request was in fact sent in early data when no field marks it: a user agent that sends its own request in early data \"does not need to include the Early-Data header field\", so an unmarked early-data request is invisible to any observer of the message. Whether a server answered a request it could not safely process with 425 (Too Early), which turns on the origin's own judgement of replay risk for a resource. And whether \"other information\" existed: an out-of-band agreement that a particular resource tolerates replay leaves no trace in the message, which is why the deployment's array is the place to record it."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 8470",
                section: Some("4"),
                url: "https://www.rfc-editor.org/rfc/rfc8470.html#section-4",
                note: "Using Early Data in HTTP Clients — the MUST NOT that licenses this rule, and it covers two sets: unsafe methods, and methods whose safety is not known. It opens \"Absent other information\", an out-of-band state no message records",
            },
            crate::rules::SpecRef {
                spec: "RFC 8470",
                section: Some("5.1"),
                url: "https://www.rfc-editor.org/rfc/rfc8470.html#section-5.1",
                note: "The Early-Data Header Field — one valid value, at most one instance, invalid or repeated instances read as a single \"1\", added by an intermediary rather than by the user agent, and forbidden in a Connection field, in a response, and in a request's trailer section",
            },
            crate::rules::SpecRef {
                spec: "RFC 8470",
                section: Some("5.2"),
                url: "https://www.rfc-editor.org/rfc/rfc8470.html#section-5.2",
                note: "The 425 (Too Early) Status Code — what a server sends instead of processing a marked request it judges too risky. Nothing here reads it: whether a given resource tolerates replay is knowledge only the origin has",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("9.2.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-9.2.1",
                note: "Safe Methods — the property RFC 8470 §4 names. GET, HEAD, OPTIONS and TRACE are the safe methods this document defines, which is a smaller set than the safe methods there are",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("16.1.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-16.1.1",
                note: "Method Registry — every registration MUST carry a Safe field, and entries are added by IETF Review. This is why the safe set is configured rather than compiled in",
            },
            crate::rules::SpecRef {
                spec: "IANA HTTP Method Registry",
                section: None,
                url: "https://www.iana.org/assignments/http-methods/http-methods.xhtml",
                note: "The registry itself. Its Safe column held GET, HEAD, OPTIONS, PRI, PROPFIND, QUERY, REPORT, SEARCH and TRACE when config_example.toml's array was written",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("RFC 8470 §5.1's own example of the field"),
                snippet: "GET /resource HTTP/1.0\nHost: example.com\nEarly-Data: 1",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("an unsafe method conveyed in early data"),
                snippet: "POST /submit HTTP/1.1\nHost: example.com\nEarly-Data: 1",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some(
                    "a value a server still reads as \"1\", so the request is early data all the same",
                ),
                snippet: "DELETE /item/7 HTTP/1.1\nHost: example.com\nEarly-Data: 0",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some(
                    "naming the field as a connection-option has every intermediary strip it",
                ),
                snippet: "GET /resource HTTP/1.1\nHost: example.com\nConnection: early-data\nEarly-Data: 1",
            },
        ]
    }
}

/// How to name a field value that is not `1`, without claiming it is text.
///
/// A value carrying an octet outside US-ASCII is a value, not a decode failure: the
/// production is a single literal, so such octets are reported for not being it.
fn describe_value(written: &[u8]) -> String {
    if written.is_empty() {
        return "no value".to_string();
    }
    match std::str::from_utf8(written) {
        Ok(s) if s.chars().all(|c| c.is_ascii_graphic() || c == ' ') => format!("'{s}'"),
        _ => format!("{} octets, not all of them visible US-ASCII", written.len()),
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &EarlyDataHeaderSafeMethod;

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;
    use rstest::rstest;

    /// The registry's `Safe: yes` entries, which is what `config_example.toml` ships.
    const REGISTERED_SAFE: &[&str] = &[
        "GET", "HEAD", "OPTIONS", "PRI", "PROPFIND", "QUERY", "REPORT", "SEARCH", "TRACE",
    ];

    fn make_cfg_with(safe: &[&str]) -> crate::config::Config {
        let mut cfg = crate::config::Config::default();
        cfg.rules.insert(
            "early_data_header_safe_method".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "safe_methods".into(),
                    toml::Value::Array(
                        safe.iter()
                            .map(|s| toml::Value::String((*s).to_string()))
                            .collect(),
                    ),
                );
                t
            }),
        );
        cfg
    }

    fn make_cfg() -> crate::config::Config {
        make_cfg_with(REGISTERED_SAFE)
    }

    fn check(tx: &crate::http_transaction::HttpTransaction) -> Option<Violation> {
        crate::test_helpers::run_rule(
            &EarlyDataHeaderSafeMethod,
            tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &make_cfg(),
        )
    }

    fn make_tx(method: &str, headers: &[(&str, &str)]) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = method.to_string();
        let mut hm = hyper::HeaderMap::new();
        for (n, v) in headers {
            hm.append(
                hyper::header::HeaderName::from_bytes(n.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        tx.request.headers = hm;
        tx
    }

    #[rstest]
    #[case("GET", false)]
    #[case("HEAD", false)]
    #[case("OPTIONS", false)]
    #[case("TRACE", false)]
    #[case("POST", true)]
    #[case("PUT", true)]
    #[case("DELETE", true)]
    fn rfc9110s_four_safe_methods_and_three_unsafe_ones(
        #[case] method: &str,
        #[case] expect: bool,
    ) {
        assert_eq!(
            check(&make_tx(method, &[("early-data", "1")])).is_some(),
            expect
        );
    }

    /// The safe set is the registry's `Safe` column, not RFC 9110's four. Each of these
    /// is registered safe by another document and was reported before this iteration.
    #[rstest]
    #[case("PRI")]
    #[case("PROPFIND")]
    #[case("QUERY")]
    #[case("REPORT")]
    #[case("SEARCH")]
    fn a_method_registered_safe_elsewhere_is_safe(#[case] method: &str) {
        assert!(check(&make_tx(method, &[("early-data", "1")])).is_none());
    }

    /// §9.1: the method token is case-sensitive. `get` is not `GET`; it is a method
    /// whose safety is not known, which is the other half of §4's MUST NOT. Folding the
    /// token used to exempt it.
    #[rstest]
    #[case("get")]
    #[case("Get")]
    #[case("head")]
    fn a_lowercase_method_is_not_the_safe_method_it_resembles(#[case] method: &str) {
        let v = check(&make_tx(method, &[("early-data", "1")])).expect("reported");
        assert!(v
            .message
            .contains("is not one this deployment lists as safe"));
    }

    /// A method nobody registered has no known safety, so §4's parenthetical covers it.
    #[test]
    fn an_unregistered_method_is_reported() {
        assert!(check(&make_tx("FROB", &[("early-data", "1")])).is_some());
    }

    /// §5.1: a server MUST read an invalid instance as a single instance saying "1", so
    /// the request was still conveyed in early data. `Early-Data: 0` on a POST used to
    /// be `#[case]`-asserted as clean.
    #[rstest]
    #[case("0")]
    #[case("")]
    #[case("yes")]
    #[case("2")]
    fn an_invalid_value_still_marks_the_request(#[case] value: &str) {
        let v = check(&make_tx("POST", &[("early-data", value)])).expect("reported");
        assert!(v.message.contains("conveyed in TLS early data"));
    }

    /// And on a safe method the same value is reported for what it is.
    #[rstest]
    #[case("0", "'0'")]
    #[case("", "no value")]
    #[case("yes", "'yes'")]
    fn an_invalid_value_on_a_safe_method_is_reported_as_a_value(
        #[case] value: &str,
        #[case] shown: &str,
    ) {
        let v = check(&make_tx("GET", &[("early-data", value)])).expect("reported");
        assert!(v.message.contains("exactly one valid value"), "{v:?}");
        assert!(v.message.contains(shown), "{v:?}");
    }

    /// The rule asks only whether the value equals one literal, and equality of two
    /// field values is equality of two octet strings. A `#[test]` used to assert that a
    /// value `to_str` refused was ignored entirely.
    #[test]
    fn a_value_outside_us_ascii_is_measured_rather_than_skipped() {
        let mut tx = make_tx("POST", &[]);
        let mut hm = hyper::HeaderMap::new();
        hm.append("early-data", HeaderValue::from_bytes(&[0xff]).unwrap());
        tx.request.headers = hm;
        let v = check(&tx).expect("reported");
        assert!(v.message.contains("conveyed in TLS early data"));

        let mut tx = make_tx("GET", &[]);
        let mut hm = hyper::HeaderMap::new();
        hm.append("early-data", HeaderValue::from_bytes(&[0xff]).unwrap());
        tx.request.headers = hm;
        let v = check(&tx).expect("reported");
        assert!(
            v.message
                .contains("1 octets, not all of them visible US-ASCII"),
            "{v:?}"
        );
    }

    /// §5.1: "clients MUST include at most one instance". Reported by nobody before.
    #[test]
    fn two_field_lines_are_reported() {
        let v =
            check(&make_tx("GET", &[("early-data", "1"), ("early-data", "1")])).expect("reported");
        assert!(
            v.message.contains("2 Early-Data header field lines"),
            "{v:?}"
        );
    }

    /// The method question comes first: two lines under an unsafe method is still, and
    /// mainly, an unsafe method in early data.
    #[test]
    fn the_method_finding_outranks_the_multiplicity_one() {
        let v = check(&make_tx(
            "POST",
            &[("early-data", "1"), ("early-data", "1")],
        ))
        .expect("reported");
        assert!(v.message.contains("conveyed in TLS early data"));
    }

    /// §5.1: "Early-Data MUST NOT appear in a Connection header field." Reported by
    /// nobody before; the field it strips is the one §5.1 forbids removing.
    #[test]
    fn naming_the_field_as_a_connection_option_is_reported() {
        let v = check(&make_tx(
            "GET",
            &[("connection", "early-data"), ("early-data", "1")],
        ))
        .expect("reported");
        assert!(v.message.contains("connection-option"), "{v:?}");
    }

    /// `Connection = #connection-option`, so a member may arrive on a line of its own.
    #[test]
    fn a_connection_option_written_on_a_second_line_is_found() {
        let v = check(&make_tx(
            "GET",
            &[("connection", "keep-alive"), ("connection", "early-data")],
        ))
        .expect("reported");
        assert!(v.message.contains("connection-option"), "{v:?}");
    }

    /// The prohibition is on the `Connection` value, so it does not need the field to
    /// be present.
    #[test]
    fn the_connection_finding_does_not_need_the_field_present() {
        let v = check(&make_tx("GET", &[("connection", "early-data")])).expect("reported");
        assert!(v.message.contains("connection-option"), "{v:?}");
    }

    /// §5.1: "An Early-Data header field MUST NOT be included in responses". The rule
    /// used to read the request section only.
    #[test]
    fn the_field_on_a_response_is_reported() {
        let mut tx = make_tx("GET", &[]);
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[("early-data", "1")]),
            body_length: Some(0),
            trailers: None,
        });
        let v = check(&tx).expect("reported");
        assert!(
            v.message.contains("Response carries an Early-Data"),
            "{v:?}"
        );
    }

    /// A request with no field at all measures nothing.
    #[test]
    fn a_request_without_the_field_is_not_reported() {
        assert!(check(&make_tx("POST", &[])).is_none());
    }

    /// The trailer half of the same sentence belongs to the rule that applies §6.5.1,
    /// and this asserts the handover by running it rather than by describing it.
    #[test]
    fn the_trailer_half_is_the_neighbours_finding() {
        let mut tx = make_tx("POST", &[]);
        tx.request.trailers = Some(crate::test_helpers::make_headers_from_pairs(&[(
            "early-data",
            "1",
        )]));
        assert!(check(&tx).is_none());

        let neighbour = crate::rules::REGISTERED_RULES
            .iter()
            .find(|r| r.id() == "trailer_fields_valid")
            .expect("the neighbour is registered");
        assert!(crate::test_helpers::run_rule(
            *neighbour,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[neighbour.id()]),
        )
        .is_some());
    }

    #[test]
    fn scope_is_both() {
        assert_eq!(
            EarlyDataHeaderSafeMethod.scope(),
            crate::rules::RuleScope::Both
        );
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        EarlyDataHeaderSafeMethod.prepare(&make_cfg())?;
        Ok(())
    }

    /// A `safe_methods` array is required, and the rule says so rather than passing.
    #[test]
    fn a_config_without_the_array_is_refused() {
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "early_data_header_safe_method",
        ]);
        let err = EarlyDataHeaderSafeMethod
            .prepare(&cfg)
            .expect_err("refused");
        assert!(err.to_string().contains("safe_methods"), "{err}");
    }

    #[test]
    fn an_empty_array_is_refused() {
        assert!(EarlyDataHeaderSafeMethod
            .prepare(&make_cfg_with(&[]))
            .is_err());
    }

    /// Every published snippet is run through the rule, with the shipped array.
    #[test]
    fn published_examples_are_judged_by_this_rule() {
        use crate::rules::{Compliance, Rule as _};
        let rule = EarlyDataHeaderSafeMethod;
        let mut saw_non_compliant = false;
        for ex in rule.examples() {
            let mut lines = ex.snippet.lines();
            let request_line = lines.next().expect("a request line");
            let method = request_line
                .split_whitespace()
                .next()
                .expect("a method token");
            let mut hm = hyper::HeaderMap::new();
            for line in lines {
                let (n, v) = line.split_once(": ").expect("a field line");
                hm.append(
                    hyper::header::HeaderName::from_bytes(n.as_bytes()).unwrap(),
                    HeaderValue::from_str(v).unwrap(),
                );
            }
            let mut tx = crate::test_helpers::make_test_transaction();
            tx.request.method = method.to_string();
            tx.request.headers = hm;
            let v = check(&tx);
            match ex.compliance {
                Compliance::Compliant => assert!(v.is_none(), "{}: {:?}", ex.snippet, v),
                Compliance::NonCompliant => {
                    saw_non_compliant = true;
                    assert!(v.is_some(), "{}", ex.snippet);
                }
            }
        }
        assert!(saw_non_compliant, "the guard ran");
    }
}
