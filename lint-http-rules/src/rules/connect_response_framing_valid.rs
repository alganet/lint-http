// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::method::{METHOD_CONNECT_FRAMING_FORBIDDEN, RFC_9110_9_3_6};
use crate::violations::ViolationDef;

/// One entry, one sentence, and two fields it names for one reason.
static DECLARED: &[&ViolationDef] = &[&METHOD_CONNECT_FRAMING_FORBIDDEN];

/// The two fields § 9.3.6 forbids, in the order the sentence writes them.
///
/// A list rather than two branches because the finding is the same claim about
/// either: a `2xx` to CONNECT is followed by the tunnel, so neither field can
/// be framing anything. Reported once per field present, because a response
/// carrying both is two lines to delete and one sentence naming only the first
/// would leave the second behind.
const FRAMING_FIELDS: &[&str] = &["transfer-encoding", "content-length"];

pub struct ConnectResponseFramingValid;

/// The other document's copy of the recipient half, quoted where this rule
/// declines to measure rather than where it reports.
const RFC_9112_6_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9112",
    section: Some("6.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3",
    note: "Message body length, item 2 — a successful response to CONNECT is followed by the tunnel, so its body length is not determined by either framing field",
};

impl RuleMeta for ConnectResponseFramingValid {
    fn id(&self) -> &'static str {
        "connect_response_framing_valid"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
# Nothing to configure. The sentence names the two fields and the status class,
# and neither is a deployment's choice.
"#
    }

    fn description(&self) -> &'static str {
        "Reports a `2xx` response to a `CONNECT` request that carries `Transfer-Encoding` or `Content-Length`.\n\n**RFC 9110 §9.3.6 states it as a MUST NOT on the server**: *\"A server MUST NOT send any Transfer-Encoding or Content-Length header fields in a 2xx (Successful) response to CONNECT.\"* What the fields would be framing is the tunnel — a successful CONNECT response ends at its header section and everything after it belongs to the tunnelled connection — so a recipient that honours a `Content-Length` here reads that many octets of another protocol as content, and whatever follows as the start of a new message. The prohibition is on presence and not on a wrong value: there is no length the number could correctly state.\n\n**The next sentence is the repair, not a licence.** §9.3.6 goes on to have a client *ignore* either field received in a successful response to CONNECT, and RFC 9112 §6.3 says the same in its own list of ways a message body length is determined. That is why a length disagreement on this shape is unmeasurable, and why `response_body_length_accuracy` declines on exactly it — a recipient told to ignore something is not a sender permitted to send it, and the sender's sentence is the one this rule reports.\n\n**`2xx` is the whole of the antecedent.** A CONNECT refused with a `4xx` or a `5xx` establishes no tunnel, so its framing is ordinary and the content explaining the refusal needs a length like any other. The sentence says `2xx` and the reading stops there.\n\n**One finding per field.** A response carrying both has two lines to delete, and the message names which field it saw; the entry is one because the sentence is one, where the bodyless statuses' `Content-Length` and `Transfer-Encoding` entries are two because they rest on two sentences in two documents.\n\n**The request half of the same section is a different rule's.** §9.3.6 also says a CONNECT request message does not have content, which `request_version_method_valid` reports as `method_connect_content_forbidden` — that finding is the client's and this one is the server's, which is why they are not one rule.\n\nScope: this rule reads a response's header section, and it reads it whatever protocol version carried the exchange. §9.3.6 states the requirement once for HTTP as a whole and each version document points back at it; over HTTP/2 and HTTP/3 a `Transfer-Encoding` is additionally forbidden outright by those versions' own sentences, which `no_connection_specific_fields` reports. Presence is the whole test, so no value is parsed here and the field's own syntax stays `content_length_valid`'s and `transfer_encoding_valid`'s."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_9110_9_3_6, RFC_9112_6_3]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    /// **The server, and the sentence names it.** § 9.3.6's subject is *a
    /// server* and the evidence is a field in the response it generated, so the
    /// party answerable is the one that sent the message in front of the rule.
    /// The request's method is read as the antecedent and never as evidence:
    /// the client wrote `CONNECT`, which is not what is wrong here.
    ///
    /// One answer for the whole rule rather than one per site, because there is
    /// one sentence and one direction. The neighbouring sentence in the same
    /// section binds a client — to *ignore* these fields — and that is a
    /// recipient's obligation about its own behaviour, which no capture
    /// records and no finding of this rule is about.
    ///
    /// cite(RFC 9110 § 9.3.6): "A server MUST NOT send any Transfer-Encoding or Content-Length header fields in a 2xx (Successful) response to CONNECT."
    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::Presumed(crate::lint::Party::Server)
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("A tunnel established, and nothing claiming to frame it"),
                snippet: "CONNECT example.com:443 HTTP/1.1\nHost: example.com:443\n\nHTTP/1.1 200 Connection Established",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("The zero is not an exception: the field is what is forbidden"),
                snippet: "CONNECT example.com:443 HTTP/1.1\nHost: example.com:443\n\nHTTP/1.1 200 Connection Established\nContent-Length: 0",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("Both fields are two lines to remove, and draw the entry twice"),
                snippet: "CONNECT example.com:443 HTTP/1.1\nHost: example.com:443\n\nHTTP/1.1 200 Connection Established\nTransfer-Encoding: chunked\nContent-Length: 5",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("A refused CONNECT establishes no tunnel, so its content is framed like any other"),
                snippet: "CONNECT example.com:443 HTTP/1.1\nHost: example.com:443\n\nHTTP/1.1 403 Forbidden\nContent-Length: 9\n\nno tunnel",
            },
        ]
    }
}

impl Rule for ConnectResponseFramingValid {
    /// A response is the evidence, so a transaction without one has nothing for
    /// this rule to read.
    fn needs_response(&self) -> bool {
        true
    }

    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        let Some(resp) = tx.response.as_ref() else {
            return Vec::new();
        };

        // The method is the antecedent and is compared case-sensitively,
        // because `method = token` and a token is matched by its exact octets:
        // `Connect` names no registered method, and what to say about it is
        // `request_version_method_valid`'s question rather than this one's.
        // cite(RFC 9110 § 9.1): "The method token is case-sensitive because it might be used as a gateway to object-based systems with case-sensitive method names."
        if tx.request.method != "CONNECT" {
            return Vec::new();
        }

        // The status class is the rest of it, written as the sentence writes
        // it. A CONNECT refused with any other class establishes no tunnel, so
        // its content is framed like any other message's and the fields below
        // are doing their ordinary job.
        // cite(RFC 9110 § 9.3.6): "Any 2xx (Successful) response indicates that the sender (and all inbound proxies) will switch to tunnel mode immediately after the response header section; data received after that header section is from the server identified by the request target."
        if !(200..300).contains(&resp.status) {
            return Vec::new();
        }

        // Presence, once per field, and no value is read. There is no length
        // the number could correctly state — what follows the header section is
        // the tunnel's traffic — so the finding is about the line being there
        // and the message says which line it is.
        //
        // A field written on several lines is one field and one finding: § 5.3
        // makes the lines one value, and what an operator has to remove is the
        // field, however many lines it took.
        // cite(RFC 9110 § 5.3): "A recipient MAY combine multiple field lines within a field section that have the same field name into one field line, without changing the semantics of the message, by appending each subsequent field line value to the initial field line value in order, separated by a comma"
        FRAMING_FIELDS
            .iter()
            .filter(|name| resp.headers.contains_key(**name))
            .map(|name| {
                ctx.report_with(
                    &METHOD_CONNECT_FRAMING_FORBIDDEN,
                    format!(
                        "A {} response to CONNECT carries {}, and what follows its header \
                         section is the tunnel rather than content: a recipient that framed \
                         a body from this field would read the tunnelled protocol's first \
                         octets as content and the rest as a new message",
                        resp.status,
                        canonical(name)
                    ),
                )
            })
            .collect()
    }
}

/// The field name as its own definition spells it, for the message alone.
///
/// The lookup above folds case because a field name is case-insensitive; the
/// sentence an operator is being pointed at writes these two spellings, and a
/// finding that echoed the map's lowercase key would name something § 9.3.6
/// does not.
fn canonical(name: &str) -> &'static str {
    match name {
        "transfer-encoding" => "Transfer-Encoding",
        _ => "Content-Length",
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ConnectResponseFramingValid;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    const RULE: ConnectResponseFramingValid = ConnectResponseFramingValid;

    fn cfg() -> crate::config::Config {
        crate::test_helpers::make_test_config_with_enabled_rules(&[
            "connect_response_framing_valid",
        ])
    }

    fn exchange(method: &str, status: u16, headers: &[(&str, &str)]) -> Vec<Violation> {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(status, headers);
        tx.request.method = method.to_string();
        crate::test_helpers::run_rule_all(
            &RULE,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg(),
        )
    }

    /// Both fields the sentence names, and the zero that is not an exception:
    /// what is forbidden is the field, because there is no length it could
    /// state correctly.
    #[rstest]
    #[case::content_length("content-length", "5", "Content-Length")]
    #[case::content_length_zero("content-length", "0", "Content-Length")]
    #[case::transfer_encoding("transfer-encoding", "chunked", "Transfer-Encoding")]
    fn a_framing_field_on_a_successful_connect_is_reported(
        #[case] name: &str,
        #[case] value: &str,
        #[case] shown: &str,
    ) {
        let v = exchange("CONNECT", 200, &[(name, value)]);
        assert_eq!(v.len(), 1, "one field is one finding: {v:?}");
        assert_eq!(v[0].violation, "method_connect_framing_forbidden");
        assert_eq!(v[0].severity, crate::lint::Severity::Error);
        // The message names the field as § 9.3.6 spells it, not as the
        // case-folded key the lookup used.
        assert!(v[0].message.contains(shown), "{}", v[0].message);
    }

    /// Two lines to delete are two findings. A single finding here would name
    /// one field and leave the other in place, which is the whole reason the
    /// reading walks the pair instead of asking whether either is present.
    #[test]
    fn both_fields_are_two_findings_naming_one_field_each() {
        let v = exchange(
            "CONNECT",
            200,
            &[("transfer-encoding", "chunked"), ("content-length", "5")],
        );
        assert_eq!(v.len(), 2, "{v:?}");
        assert!(v
            .iter()
            .all(|f| f.violation == "method_connect_framing_forbidden"));
        assert!(
            v[0].message.contains("Transfer-Encoding"),
            "{}",
            v[0].message
        );
        assert!(v[1].message.contains("Content-Length"), "{}", v[1].message);
    }

    /// The whole of the antecedent, in both of its terms. A refused CONNECT
    /// establishes no tunnel, so its content is framed like any other message's
    /// — and a framing field on a method that is not CONNECT is the ordinary
    /// case this rule must never reach.
    #[rstest]
    #[case::refused_connect("CONNECT", 403)]
    #[case::redirected_connect("CONNECT", 301)]
    #[case::server_error_connect("CONNECT", 502)]
    #[case::a_get("GET", 200)]
    #[case::a_post("POST", 200)]
    fn nothing_outside_a_successful_connect_is_reported(#[case] method: &str, #[case] status: u16) {
        assert!(
            exchange(method, status, &[("content-length", "9")]).is_empty(),
            "{method} {status} is outside the sentence"
        );
    }

    /// `method = token` is matched by its exact octets, so a lowercase spelling
    /// names no method and this rule's antecedent is unreached. What to say
    /// about that spelling is `request_version_method_valid`'s.
    #[test]
    fn the_method_is_compared_as_the_token_it_is() {
        assert!(exchange("Connect", 200, &[("content-length", "5")]).is_empty());
    }

    /// The tunnel established and nothing claiming to frame it, which is the
    /// shape every conforming CONNECT exchange has.
    #[test]
    fn a_tunnel_with_no_framing_field_draws_nothing() {
        assert!(exchange("CONNECT", 200, &[("via", "1.1 proxy")]).is_empty());
    }

    /// The full 2xx class and not the one status deployments write. § 9.3.6
    /// says *2xx*, and a proxy answering `204` or `299` has switched to tunnel
    /// mode just as one answering `200` has.
    #[rstest]
    #[case(200)]
    #[case(204)]
    #[case(299)]
    fn the_class_is_read_and_not_the_one_status(#[case] status: u16) {
        assert_eq!(
            exchange("CONNECT", status, &[("content-length", "0")]).len(),
            1,
            "{status} is in the class the sentence names"
        );
    }
}
