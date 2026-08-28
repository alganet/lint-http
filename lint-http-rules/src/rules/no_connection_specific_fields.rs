// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::helpers::headers::combined_field_value_as_written;
use crate::lint::Violation;
use crate::rules::Rule;

/// The connection-specific field names, as the two governing documents reach
/// them.
///
/// **The same five names are the whole of one requirement and part of the
/// other.** RFC 9113 § 8.2.2 closes its list by name in the sentence after its
/// MUST NOT — the `Connection` field itself plus the four it prints in a
/// parenthetical — and that sentence is exactly this array. RFC 9114 § 4.2
/// enumerates nothing: it says *"connection-specific fields"* and leaves the
/// reader to § 7.6.1, whose own list opens *"This includes but is not limited
/// to"* and is a SHOULD addressed to intermediaries rather than a closed set.
/// So a name's absence from these findings is a verdict over HTTP/2 and is not
/// one over HTTP/3, which `description()` says.
///
/// **Which sentence supplies the names, for the version that does not print
/// them.** § 7.6.1's own list is five bullets under *"This includes but is not
/// limited to:"*, and a bullet is four words long and unreachable under a
/// section label — `apysource` resolves it to a document-wide `html` targetter,
/// which is the hazard § 1 of the tracker names. So the names are carried here
/// the way the documents themselves carry them: § 7.6.1 states that such a list
/// exists and that it is open, and **RFC 9113 § 8.2.2's parenthetical is a
/// published reading of that same list** — *"those listed as having
/// connection-specific semantics in Section 7.6.1 of [HTTP] (that is, …)"*. One
/// document enumerating the other's bullets is why a single array serves both
/// versions, and why it is a closed set for only one of them.
///
/// `TE` is § 7.6.1's third bullet and is deliberately not here: both documents
/// spend their next sentence restoring it to a *request*, so it is measured in
/// [`check_te`] instead, where the direction it arrived in decides. It is also
/// the bullet RFC 9113's parenthetical drops, for that reason.
///
/// cite(RFC 9113 § 8.2.2): "This includes the Connection header field and those listed as having connection-specific semantics in Section 7.6.1 of [HTTP] (that is, Proxy-Connection, Keep-Alive, Transfer-Encoding, and Upgrade)."
/// cite(RFC 9110 § 7.6.1): "Furthermore, intermediaries SHOULD remove or replace fields that are known to require removal before forwarding, whether or not they appear as a connection-option, after applying those fields' semantics."
/// cite(RFC 9110 § 7.6.1): "This includes but is not limited to:"
const CONNECTION_SPECIFIC_FIELDS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
];

/// A version that conveys connection-specific metadata by other means, together
/// with the section of its own document that says so.
///
/// Both documents state the same four sentences in the same order, and neither
/// is the other's copy: the finding is worded from whichever one governs the
/// version the field section arrived on, so `section` travels with `version`
/// rather than being chosen once per transaction.
///
/// cite(RFC 9113 § 8.2.2): "HTTP/2 does not use the Connection header field (Section 7.6.1 of [HTTP]) to indicate connection-specific header fields; in this protocol, connection-specific metadata is conveyed by other means."
/// cite(RFC 9114 § 4.2): "HTTP/3 does not use the Connection header field to indicate connection-specific fields; in this protocol, connection-specific metadata is conveyed by other means."
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct ConnectionlessVersion {
    /// How a finding names the version.
    version: &'static str,
    /// The section stating the prohibition, for the finding to point at.
    section: &'static str,
}

impl ConnectionlessVersion {
    /// The version that carried this field section, when it is one whose own
    /// document forbids these fields.
    ///
    /// The major digit is the whole question and `http_version` owns the
    /// production that reads it. A value naming no messaging syntax comes back
    /// `None` and is `http_version_syntax`'s finding rather than
    /// this rule's.
    ///
    /// cite(RFC 9110 § 2.5): "The first digit (major version) indicates the messaging syntax"
    fn of(version: &str) -> Option<Self> {
        match crate::http_version::major(version) {
            Some(2) => Some(Self {
                version: "HTTP/2",
                section: "RFC 9113 §8.2.2",
            }),
            Some(3) => Some(Self {
                version: "HTTP/3",
                section: "RFC 9114 §4.2",
            }),
            _ => None,
        }
    }
}

/// Which direction a field section was written in.
///
/// The `TE` exception is the only thing that turns on this, and it turns on it
/// entirely: both documents restore the field to *"an HTTP/2 request"* /
/// *"an HTTP/3 request header"*, so a response gets no exception and a `TE`
/// there is an ordinary connection-specific field. Nothing else in this rule
/// reads it except the noun a finding prints.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Direction {
    Request,
    Response,
}

impl Direction {
    fn noun(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Response => "response",
        }
    }
}

pub struct NoConnectionSpecificFields;

impl NoConnectionSpecificFields {
    /// One field section, measured against the document that governs the
    /// version **that section** arrived on.
    ///
    /// The gate is per section rather than per transaction, and the difference
    /// is a whole class of message: a reverse proxy may have received the
    /// request over one version and the response over another, so the request's
    /// version decides nothing about the response's fields. Reading both
    /// against the request's — which is what this rule did — let every HTTP/3
    /// response to an HTTP/1.1 request through untouched.
    ///
    /// The fourth sentence of each section is what makes that the right cut,
    /// and it is quoted here rather than on the array: an intermediary rewriting
    /// an HTTP/1.x message into one of these versions MUST strip these fields,
    /// so a section that arrived on one of them is measured whatever the other
    /// half of the exchange was carried by — the transforming intermediary is
    /// exactly the party this proxy stands next to.
    ///
    /// cite(RFC 9113 § 8.2.2): "An intermediary transforming an HTTP/1.x message to HTTP/2 MUST remove connection-specific header fields as discussed in Section 7.6.1 of [HTTP], or their messages will be treated by other HTTP/2 endpoints as malformed (Section 8.1.1)."
    /// cite(RFC 9114 § 4.2): "An intermediary transforming an HTTP/1.x message to HTTP/3 MUST remove connection-specific header fields as discussed in Section 7.6.1 of [HTTP], or their messages will be treated by other HTTP/3 endpoints as malformed."
    fn check_field_section(
        &self,
        governing: ConnectionlessVersion,
        direction: Direction,
        headers: &hyper::HeaderMap,
        severity: crate::lint::Severity,
    ) -> Option<Violation> {
        // Presence is the whole defect, so the value is never read: what both
        // documents forbid is generating a message that *contains* the field.
        // Whether the value derives from the field's own production is the
        // question of the rule that owns that field, and it is a question about
        // a message this one has already called malformed.
        //
        // cite(RFC 9113 § 8.2.2): "An endpoint MUST NOT generate an HTTP/2 message containing connection-specific header fields."
        // cite(RFC 9113 § 8.2.2): "Any message containing connection-specific header fields MUST be treated as malformed (Section 8.1.1)."
        // cite(RFC 9114 § 4.2): "An endpoint MUST NOT generate an HTTP/3 field section containing connection-specific fields; any message containing connection-specific fields MUST be treated as malformed."
        for &name in CONNECTION_SPECIFIC_FIELDS {
            if headers.contains_key(name) {
                return Some(self.violation(
                    severity,
                    format!(
                        "{} {} carries the connection-specific header field '{}'; \
                         {} makes such a message malformed",
                        governing.version,
                        direction.noun(),
                        name,
                        governing.section
                    ),
                ));
            }
        }

        self.check_te(governing, direction, headers, severity)
    }

    /// The one field both documents take back out of the set, and only for one
    /// direction.
    ///
    /// cite(RFC 9113 § 8.2.2): "The only exception to this is the TE header field, which MAY be present in an HTTP/2 request; when it is, it MUST NOT contain any value other than "trailers"."
    /// cite(RFC 9114 § 4.2): "The only exception to this is the TE header field, which MAY be present in an HTTP/3 request header; when it is, it MUST NOT contain any value other than "trailers"."
    fn check_te(
        &self,
        governing: ConnectionlessVersion,
        direction: Direction,
        headers: &hyper::HeaderMap,
        severity: crate::lint::Severity,
    ) -> Option<Violation> {
        // A response is not the request the exception is written for, so the
        // field is connection-specific there like the five above it and the
        // value is beside the point. § 10.1.4 is what makes that reading the
        // ordinary one rather than a strict construction of the exception: the
        // field describes the *client's* capabilities, so a server writing one
        // has said nothing a recipient can use.
        //
        // cite(RFC 9110 § 10.1.4): "The "TE" header field describes capabilities of the client with regard to transfer codings and trailer sections."
        if direction == Direction::Response {
            if headers.contains_key("te") {
                return Some(self.violation(
                    severity,
                    format!(
                        "{} response carries a TE header field; the exception {} makes is \
                         for a request, so in a response TE is a connection-specific field \
                         like any other and the message is malformed",
                        governing.version, governing.section
                    ),
                ));
            }
            return None;
        }

        // Read as the sender wrote it: every `TE` line of this section joined
        // into the one list it is, one `char` per octet. Reading the first line
        // only made `TE: trailers` / `TE: gzip` a conforming request, and
        // `to_str` turned a value carrying `obs-text` into the claim that the
        // message has no `TE` field — where what is wrong with it is that it
        // holds a value other than "trailers", which is exactly what the
        // sentence above forbids.
        //
        // cite(RFC 9110 § 5.2): "When a field name is repeated within a section, its combined field value consists of the list of corresponding field line values within that section, concatenated in order, with each field line value separated by a comma."
        let value = combined_field_value_as_written(headers, "te")?;

        // The quote-aware walk, because `t-codings` puts a `quoted-string` inside
        // its own element: a `transfer-parameter`'s value may be one, and a
        // `quoted-string` may hold a comma. The naive split cut
        // `TE: gzip;ext="a,b"` — one member carrying one parameter — into
        // `gzip;ext="a` and `b"`, and while both are still values other than
        // "trailers", the finding then **named** a member no sender wrote.
        // `te_header_valid` owns this field's grammar and had
        // already written the same trap down at its own walk.
        //
        // Empty elements are dropped here rather than reported: an empty element
        // is not a value, so it is not a value other than "trailers". That one
        // was generated at all is § 5.6.1.1's MUST NOT, and that rule's finding.
        // An empty *field* falls out of the same walk for the same reason —
        // `TE:` contains no value, and RFC 9112 § 7.4 prints it as one of its
        // three worked examples of the field in use.
        //
        // The comparison folds case because `t-codings` writes `"trailers"` as
        // an ABNF string, and an ABNF string is case-insensitive — the sentence
        // is RFC 5234's rather than either version's document, which is why it
        // is quoted here and not paraphrased from § 8.2.2's prose.
        //
        // cite(RFC 9110 § A, label: t-codings): "t-codings = "trailers" / ( transfer-coding [ weight ] )"
        // cite(RFC 9110 § A): "transfer-parameter = token BWS "=" BWS ( token / quoted-string )"
        // cite(RFC 5234 § 2.3): "ABNF strings are case insensitive and the character set for these strings is US-ASCII."
        let member = crate::helpers::headers::list_members_as_written(&value)
            .into_iter()
            .filter(|member| !member.is_empty())
            .find(|member| !member.eq_ignore_ascii_case("trailers"))?;

        Some(self.violation(
            severity,
            format!(
                "{} request's TE header field holds '{}'; the only value {} permits it \
                 to contain is 'trailers'",
                governing.version,
                member.escape_debug(),
                governing.section
            ),
        ))
    }
}

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9113_8_2_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9113",
    section: Some("8.2.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9113.html#section-8.2.2",
    note: "Connection-Specific Header Fields — HTTP/2's prohibition, and the one \
           sentence of the two that closes the list of names",
};
const RFC_9114_4_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9114",
    section: Some("4.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9114.html#section-4.2",
    note: "HTTP Fields — HTTP/3's prohibition, which enumerates nothing and defers \
           to RFC 9110 §7.6.1",
};
const RFC_9110_7_6_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("7.6.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6.1",
    note: "Connection — the field itself, and the open list of those that carry \
           connection-specific semantics",
};
const RFC_9110_10_1_4: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("10.1.4"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1.4",
    note: "TE — the capabilities of the client, which is why a response carrying \
           the field gets no part of the exception",
};
const RFC_5234_2_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 5234",
    section: Some("2.3"),
    url: "https://www.rfc-editor.org/rfc/rfc5234.html#section-2.3",
    note: "Terminal Values — an ABNF string is case-insensitive, which is what \
           licenses matching `trailers` without regard to case",
};

impl Rule for NoConnectionSpecificFields {
    fn id(&self) -> &'static str {
        "no_connection_specific_fields"
    }

    /// Both documents address the endpoint that *generates* the message, and
    /// either party generates one.
    ///
    /// cite(RFC 9113 § 8.2.2): "An endpoint MUST NOT generate an HTTP/2 message containing connection-specific header fields."
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
            // Each section's own version, decided before anything else is read.
            let request = ConnectionlessVersion::of(&tx.request.version);
            let response = tx.response.as_ref().and_then(|resp| {
                ConnectionlessVersion::of(&resp.version).map(|governing| (governing, resp))
            });

            // A transaction neither half of which was carried by one of these
            // versions ends here.
            if request.is_none() && response.is_none() {
                return None;
            }

            if let Some(governing) = request {
                if let Some(violation) = self.check_field_section(
                    governing,
                    Direction::Request,
                    &tx.request.headers,
                    ctx.severity,
                ) {
                    return Some(violation);
                }
            }

            if let Some((governing, resp)) = response {
                if let Some(violation) = self.check_field_section(
                    governing,
                    Direction::Response,
                    &resp.headers,
                    ctx.severity,
                ) {
                    return Some(violation);
                }
            }

            None
        };
        Vec::from_iter(finding())
    }

    fn description(&self) -> &'static str {
        "Reports a connection-specific header field in a message carried by a version of HTTP that has none.\n\n`Connection`, `Keep-Alive`, `Proxy-Connection`, `Transfer-Encoding` and `Upgrade` supply control information about one hop, and HTTP/2 and HTTP/3 convey that metadata by other means. Both documents say so in the same four sentences: the version does not use the `Connection` field, an endpoint MUST NOT generate a message containing connection-specific fields, any such message MUST be treated as malformed, and an intermediary transforming an HTTP/1.x message MUST remove them or its output will be treated as malformed by other endpoints. **Presence is the whole finding** — no value is read, because a message this rule reports has already been called malformed, and whether the value derives from its field's own production is that field's rule's question.\n\n**The two documents are not copies of each other, and the difference is what the finding may claim.** RFC 9113 §8.2.2 closes the list by name in the sentence after its MUST NOT — *that is, Proxy-Connection, Keep-Alive, Transfer-Encoding, and Upgrade* — so over HTTP/2 these five names are the entire requirement and a name's absence from these findings is a verdict. RFC 9114 §4.2 enumerates nothing at all, deferring to RFC 9110 §7.6.1, whose list opens *This includes but is not limited to* and is a SHOULD addressed to intermediaries. So over HTTP/3 the same five names are a **subset**, and a field this rule passes is not a field it has cleared.\n\n**`TE` is the one exception, and it is an exception for one direction.** Both sections restore it to *an HTTP/2 request* / *an HTTP/3 request header*, and say that when it is present it MUST NOT contain any value other than `trailers`. So in a request the field is permitted and its members are measured; in a **response** no exception applies, and the field is connection-specific like the five above it — RFC 9110 §10.1.4 defines it as describing the capabilities of the *client*, so a server writing one has said nothing a recipient can use. The comparison against `trailers` folds case, and the sentence licensing that is RFC 5234 §2.3's — `t-codings = \"trailers\" / ( transfer-coding [ weight ] )` writes the keyword as an ABNF string, and ABNF strings are case-insensitive — rather than anything in either version's own document. An empty list element is not a value and is not reported here; that it was generated is §5.6.1.1's MUST NOT and `te_header_valid`'s finding. An empty field value is likewise not reported: `TE:` contains no value, and RFC 9112 §7.4 prints it as one of its three worked examples.\n\n**Each field section is measured against the version that carried it.** A reverse proxy may have received the request over one version and the response over another, so the request's version decides nothing about the response's fields — reading both against the request's, which this rule used to do, let every HTTP/3 response to an HTTP/1.1 request through untouched, and it was the version gate rather than any branch that did it.\n\n**What the transports do to these findings before the linter sees them, and it differs by version.** Over HTTP/3 the `h3` crate this proxy uses filters nothing, so every finding here is live on traffic the proxy captured itself. Over HTTP/2 `h2` 0.4.14 refuses all five names on **both** its paths — on receive in `src/frame/headers.rs`, which fails the HEADERS block as a malformed message before the fields reach hyper, and on send in `src/proto/streams/send.rs` — so those findings are reachable only through `lint` over captures written elsewhere. This is a claim about a dependency and it is deliberately not pinned by a test: `h2` puts its frame layer behind an `unstable` feature, so the check would cost a build flag on a transitive crate. The version is the one in `Cargo.lock`, and a reader wanting to confirm it has the two file names.\n\nThe one HTTP/2 finding that survives the library is the **`TE` in a response**: `h2`'s filter tests the field's value and never its direction, so `te: trailers` in a response passes it and reaches the capture. That same filter is byte-exact where the grammar is not, which means `h2` resets a `te: Trailers` that RFC 5234 §2.3 says derives from the production — a deployed reading that **disagrees** with this rule rather than corroborating it, recorded here because a reader comparing the two should not conclude the rule is wrong.\n\nScope: this rule reads header sections. The word both documents use is *field section*, which includes a trailer section — that half is `trailer_fields_valid`'s, whose §6.5.1 table holds `Connection`, `Keep-Alive`, `Upgrade`, `Transfer-Encoding` and `TE`, for every version rather than only these two. **It does not hold `Proxy-Connection`**, so that one field arriving in a trailer section is reported by neither rule: this one does not read trailers, and the other's table omits it. The omission is that rule's to answer and is recorded rather than fixed here, because widening its table changes the verdicts of a rule whose own audit is closed. What a `Connection` value may itself contain is `connection_header_tokens_valid`'s and what an `Upgrade` value may is `upgrade_header_syntax`'s — both measure their field on every version, because this rule reads no value; whether an `Upgrade` field is backed by an `upgrade` connection option is `upgrade_and_connection_consistent`'s; the rest of what a `TE` value may hold in a request is `te_header_valid`'s."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_9113_8_2_2,
            RFC_9114_4_2,
            RFC_9110_7_6_1,
            RFC_9110_10_1_4,
            RFC_5234_2_3,
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "GET /resource HTTP/3\nHost: example.com\nAccept: text/html",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("The exception, in the direction it is written for"),
                snippet: "GET /resource HTTP/2\nHost: example.com\nTE: trailers",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "GET /resource HTTP/2\nHost: example.com\nConnection: keep-alive",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "POST /data HTTP/3\nHost: example.com\nTransfer-Encoding: chunked",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "GET /resource HTTP/3\nHost: example.com\nUpgrade: websocket",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "GET /resource HTTP/2\nHost: example.com\nTE: gzip, trailers",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("The exception is for a request; a response gets none of it"),
                snippet: "HTTP/2 200 OK\nContent-Type: text/html\nTE: trailers",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &NoConnectionSpecificFields;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    const RULE: NoConnectionSpecificFields = NoConnectionSpecificFields;

    fn cfg() -> crate::config::Config {
        crate::test_helpers::make_test_config_with_enabled_rules(&["no_connection_specific_fields"])
    }

    /// One request section, at a named version. The version is named at every
    /// call site rather than defaulted, because it is the thing under test.
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

    /// A transaction whose two sections carry their own versions, which is the
    /// pair this rule reads and the pair the old gate collapsed into one.
    fn exchange(
        request_version: &str,
        response_version: &str,
        response_headers: &[(&str, &str)],
    ) -> Option<Violation> {
        let mut tx =
            crate::test_helpers::make_test_transaction_with_response(200, response_headers);
        tx.request.version = request_version.to_string();
        if let Some(resp) = tx.response.as_mut() {
            resp.version = response_version.to_string();
        }
        crate::test_helpers::run_rule(
            &RULE,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg(),
        )
    }

    // --- The five names, on each version that forbids them ---

    #[rstest]
    #[case("HTTP/2.0", "connection", "keep-alive")]
    #[case("HTTP/2.0", "keep-alive", "timeout=5")]
    #[case("HTTP/2.0", "proxy-connection", "keep-alive")]
    #[case("HTTP/2.0", "transfer-encoding", "chunked")]
    #[case("HTTP/2.0", "upgrade", "websocket")]
    #[case("HTTP/3.0", "connection", "keep-alive")]
    #[case("HTTP/3.0", "keep-alive", "timeout=5")]
    #[case("HTTP/3.0", "proxy-connection", "keep-alive")]
    #[case("HTTP/3.0", "transfer-encoding", "chunked")]
    #[case("HTTP/3.0", "upgrade", "websocket")]
    fn a_connection_specific_field_is_reported_on_both_versions(
        #[case] version: &str,
        #[case] name: &str,
        #[case] value: &str,
    ) {
        let v = request(version, &[(name, value)]).expect("violation");
        // Quoted, because every message of this rule holds the unquoted word
        // "connection" inside "connection-specific header field" — so a bare
        // `contains(name)` asserts nothing at all for two of these ten cases.
        assert!(v.message.contains(&format!("'{name}'")), "{}", v.message);
    }

    /// The same five names in the other direction. The request section is read
    /// first and returns on its first finding, so without a clean request these
    /// cases would be measuring the request branch again.
    #[rstest]
    #[case("connection")]
    #[case("keep-alive")]
    #[case("proxy-connection")]
    #[case("transfer-encoding")]
    #[case("upgrade")]
    fn the_same_five_names_are_read_in_a_response_section(#[case] name: &str) {
        let v = exchange("HTTP/2.0", "HTTP/2.0", &[(name, "x")]).expect("violation");
        assert_eq!(
            v.message,
            format!(
                "HTTP/2 response carries the connection-specific header field \
                 '{name}'; RFC 9113 §8.2.2 makes such a message malformed"
            )
        );
    }

    /// The finding is worded from the document that governs the version it was
    /// found on — the two sections are not interchangeable, so a message naming
    /// the wrong one is a citation defect a reader cannot see from the code.
    #[rstest]
    #[case("HTTP/2.0", "HTTP/2", "RFC 9113 §8.2.2")]
    #[case("HTTP/3.0", "HTTP/3", "RFC 9114 §4.2")]
    fn the_finding_names_the_document_that_governs_the_version(
        #[case] version: &str,
        #[case] named_version: &str,
        #[case] section: &str,
    ) {
        let v = request(version, &[("connection", "keep-alive")]).expect("violation");
        assert_eq!(
            v.message,
            format!(
                "{named_version} request carries the connection-specific header field \
                 'connection'; {section} makes such a message malformed"
            )
        );
    }

    // --- The versions that have a Connection field are not measured ---

    #[rstest]
    #[case("HTTP/1.1")]
    #[case("HTTP/1.0")]
    #[case("HTTP/0.9")]
    fn a_version_that_has_the_field_is_not_reported_for_carrying_it(#[case] version: &str) {
        assert!(request(version, &[("connection", "keep-alive")]).is_none());
    }

    /// A value deriving from no `HTTP-version` names no messaging syntax, so it
    /// selects no document. `http_version_syntax` reports it.
    #[rstest]
    #[case("HTTP/2")]
    #[case("2.0")]
    #[case("")]
    fn a_version_that_names_no_syntax_selects_no_document(#[case] version: &str) {
        assert!(request(version, &[("connection", "keep-alive")]).is_none());
    }

    // --- The per-section gate: P26's class ---

    /// The whole rule used to sit under the *request's* version, so an HTTP/3
    /// response to an HTTP/1.1 request was read by nobody — not by this rule and
    /// not by any other. The response section is measured against its own.
    #[rstest]
    #[case("HTTP/1.1", "HTTP/3.0", "HTTP/3", "RFC 9114 §4.2")]
    #[case("HTTP/1.1", "HTTP/2.0", "HTTP/2", "RFC 9113 §8.2.2")]
    fn a_response_is_measured_against_its_own_version_not_the_requests(
        #[case] request_version: &str,
        #[case] response_version: &str,
        #[case] named_version: &str,
        #[case] section: &str,
    ) {
        let v = exchange(
            request_version,
            response_version,
            &[("connection", "close")],
        )
        .expect("violation");
        assert_eq!(
            v.message,
            format!(
                "{named_version} response carries the connection-specific header field \
                 'connection'; {section} makes such a message malformed"
            )
        );
    }

    /// The converse, and the reason the gate cannot simply be widened to the
    /// transaction: a reverse proxy's upstream leg may be HTTP/1.1, where these
    /// fields are how the protocol works.
    #[rstest]
    #[case("HTTP/2.0")]
    #[case("HTTP/3.0")]
    fn an_http1_response_to_a_request_on_these_versions_is_not_reported(
        #[case] request_version: &str,
    ) {
        assert!(exchange(
            request_version,
            "HTTP/1.1",
            &[
                ("connection", "keep-alive"),
                ("transfer-encoding", "chunked")
            ],
        )
        .is_none());
    }

    // --- TE: the exception, and its direction ---

    #[rstest]
    #[case("HTTP/2.0", "trailers")]
    #[case("HTTP/3.0", "trailers")]
    #[case("HTTP/2.0", "Trailers")]
    #[case("HTTP/3.0", "TRAILERS")]
    fn the_keyword_is_an_abnf_string_and_derives_in_any_case(
        #[case] version: &str,
        #[case] value: &str,
    ) {
        assert!(request(version, &[("te", value)]).is_none());
    }

    #[rstest]
    #[case("HTTP/2.0", "gzip", "gzip")]
    #[case("HTTP/3.0", "gzip", "gzip")]
    #[case("HTTP/2.0", "trailers, gzip", "gzip")]
    #[case("HTTP/3.0", "deflate, trailers", "deflate")]
    #[case("HTTP/2.0", "trailers;q=0.5", "trailers;q=0.5")]
    fn a_te_member_other_than_the_keyword_is_reported_and_named(
        #[case] version: &str,
        #[case] value: &str,
        #[case] reported: &str,
    ) {
        let v = request(version, &[("te", value)]).expect("violation");
        assert!(
            v.message.contains(&format!("holds '{reported}'")),
            "{}",
            v.message
        );
    }

    /// A `transfer-parameter`'s value may be a `quoted-string`, and a
    /// `quoted-string` may hold a comma — so the member boundary is not every
    /// comma. Both readings report this value; only one of them names a member
    /// the sender actually wrote, which an `is_some()` assertion cannot see.
    #[rstest]
    #[case("HTTP/2.0")]
    #[case("HTTP/3.0")]
    fn a_comma_inside_a_quoted_parameter_does_not_end_the_member(#[case] version: &str) {
        let v = request(version, &[("te", "gzip;ext=\"a,b\"")]).expect("violation");
        assert!(
            v.message.contains(r#"holds 'gzip;ext=\"a,b\"'"#),
            "{}",
            v.message
        );
    }

    /// `TE:` contains no value, so it contains no value other than `trailers`.
    /// RFC 9112 §7.4 prints it as one of its three worked examples.
    #[rstest]
    #[case("HTTP/2.0", "")]
    #[case("HTTP/3.0", "")]
    #[case("HTTP/2.0", "trailers,,")]
    fn an_empty_value_and_an_empty_member_are_not_values(
        #[case] version: &str,
        #[case] value: &str,
    ) {
        assert!(request(version, &[("te", value)]).is_none());
    }

    /// The field is one list however many lines carry it (§5.2). Reading the
    /// first line only made this request conforming.
    #[rstest]
    #[case("HTTP/2.0")]
    #[case("HTTP/3.0")]
    fn te_written_on_a_second_line_is_part_of_the_same_value(#[case] version: &str) {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.version = version.to_string();
        tx.request
            .headers
            .append("te", hyper::header::HeaderValue::from_static("trailers"));
        tx.request
            .headers
            .append("te", hyper::header::HeaderValue::from_static("gzip"));

        let v = crate::test_helpers::run_rule(
            &RULE,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg(),
        )
        .expect("violation");
        assert!(v.message.contains("holds 'gzip'"), "{}", v.message);
    }

    /// An `obs-text` octet is a value other than `trailers`, and that is what is
    /// wrong with it. Read through `to_str` the field disappeared and the
    /// finding became a claim about the message's encoding.
    #[rstest]
    #[case("HTTP/2.0")]
    #[case("HTTP/3.0")]
    fn an_obs_text_octet_is_a_value_other_than_the_keyword(#[case] version: &str) {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.version = version.to_string();
        tx.request.headers.insert(
            "te",
            hyper::header::HeaderValue::from_bytes(&[0xff]).expect("obs-text is a field-content"),
        );

        let v = crate::test_helpers::run_rule(
            &RULE,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg(),
        )
        .expect("violation");
        assert!(v.message.contains("TE header field holds"), "{}", v.message);
        assert!(!v.message.contains("UTF-8"), "{}", v.message);
    }

    /// The exception is for a request. This is also the one HTTP/2 finding the
    /// `h2` crate does not erase before the capture: its filter tests the
    /// value and never the direction.
    #[rstest]
    #[case("HTTP/2.0", "HTTP/2", "RFC 9113 §8.2.2")]
    #[case("HTTP/3.0", "HTTP/3", "RFC 9114 §4.2")]
    fn a_response_carrying_te_gets_no_part_of_the_exception(
        #[case] version: &str,
        #[case] named_version: &str,
        #[case] section: &str,
    ) {
        let v = exchange(version, version, &[("te", "trailers")]).expect("violation");
        assert_eq!(
            v.message,
            format!(
                "{named_version} response carries a TE header field; the exception \
                 {section} makes is for a request, so in a response TE is a \
                 connection-specific field like any other and the message is malformed"
            )
        );
    }

    // --- Order, scope, config ---

    /// The five names are read before the exception, so a request carrying both
    /// is reported for the field that has no exception at all.
    #[test]
    fn a_connection_specific_field_is_reported_before_the_te_value() {
        let v = request("HTTP/2.0", &[("connection", "keep-alive"), ("te", "gzip")])
            .expect("violation");
        assert!(v.message.contains("'connection'"), "{}", v.message);
    }

    #[test]
    fn a_clean_exchange_on_these_versions_draws_nothing() {
        assert!(request("HTTP/2.0", &[("accept", "*/*")]).is_none());
        assert!(exchange("HTTP/3.0", "HTTP/3.0", &[("content-type", "text/html")]).is_none());
    }

    #[test]
    fn scope_is_both() {
        assert_eq!(RULE.scope(), crate::rules::RuleScope::Both);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "no_connection_specific_fields");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
