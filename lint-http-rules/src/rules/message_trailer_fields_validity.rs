// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// The fields that actually arrive after the content, and whether they may.
///
/// This rule reads the *trailer section*; `message_trailer_headers_valid` reads the
/// `Trailer` declaration in the header section. Announcing a field and sending one
/// are two acts, and §6.5.1's MUST NOT binds the second.
///
/// The framing precondition below is not checked and cannot be: a trailer section
/// reaches this rule only because the framing that carries it delivered one, so
/// there is no message here in which the sentence is false.
///
/// cite(RFC 9110 § 6.5.1): "A trailer section is only possible when supported by the version of HTTP in use and enabled by an explicit framing mechanism."
pub struct MessageTrailerFieldsValidity;

impl Rule for MessageTrailerFieldsValidity {
    fn id(&self) -> &'static str {
        "message_trailer_fields_validity"
    }

    /// A trailer section is a sender's, and either party is a sender. The
    /// requirement names no direction, and a request's trailer section is reachable
    /// here — HTTP/1.1 chunked framing runs both ways.
    ///
    /// cite(RFC 9110 § 6.5.1): "A sender MUST NOT generate a trailer field unless the sender knows the corresponding header field name's definition permits the field to be sent in trailers."
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;

        // Each trailer section is measured against the header section of its own
        // message. A request's `Trailer` announces what that request will send and
        // its `Connection` names options for that message, so neither says anything
        // about what the response may put after its content.
        if let Some(ref trailers) = tx.request.trailers {
            if let Some(v) = check_trailers(self.id(), &config, trailers, &tx.request.headers) {
                return Some(v);
            }
        }

        if let Some(ref resp) = tx.response {
            if let Some(ref trailers) = resp.trailers {
                if let Some(v) = check_trailers(self.id(), &config, trailers, &resp.headers) {
                    return Some(v);
                }
            }
        }

        None
    }

    fn title(&self) -> Option<&'static str> {
        Some("Trailer Fields Validity")
    }

    fn description(&self) -> &'static str {
        "Validates the fields that actually arrive in a message's trailer section — the fields sent after the content, in a request or a response.\n\nA field is reported for one of three reasons:\n\n- **Its own definition does not permit the usage.** RFC 9110 §6.5.1: a sender MUST NOT generate a trailer field unless it knows the corresponding field definition permits it. Reported for the fields whose definitions this linter holds and which do not: message framing (`Content-Length`, `Transfer-Encoding`), routing (`Host`, `Forwarded`), request modifiers (`Cache-Control`, `Expect`, `Max-Forwards`, `Pragma`, `Range`, `TE`, and the five `If-*` conditionals), authentication (`Authorization`, `WWW-Authenticate`, `Proxy-Authenticate`, `Proxy-Authorization`), response controls (`Age`, `Date`, `Expires`, `Location`, `Retry-After`, `Vary`, `Warning`), content format (`Content-Encoding`, `Content-Range`, `Content-Type`), the connection-specific `Connection`, `Keep-Alive` and `Upgrade`, and `Trailer` itself, which would announce a section the recipient has finished reading.\n- **This message's own `Connection` names it.** A field listed as a connection-option carries control information for the current connection, and RFC 9110 §7.6.1 has every intermediary remove such a field from the trailer section before forwarding. The `Connection` consulted is the one in the same message as the trailer section, across all of its field lines.\n- **The `Trailer` declaration did not indicate it.** Where a message carries a `Trailer` header field, RFC 9110 §6.6.2's SHOULD asks it to indicate which fields might appear in the trailers, so a field that arrives unannounced is reported. `Trailer:` carrying nothing is a legal, empty declaration that announces no field at all — it is read, not treated as missing.\n\n**Scope limit, and it is the requirement's shape rather than an omission.** §6.5.1 is deny-by-default — RFC 9110 §16.3.2 says a new field is not allowable in trailers unless its definition says so — while the first check above is a list of names, which answers the opposite question. It cannot be inverted here: for a field this linter holds no definition of (`X-Checksum`, `Grpc-Status`), only the sender knows whether its definition permits the usage, and reporting all of them would report the senders that read their own specification. So a field absent from the list passes, and its passing is not a verdict. For the same reason, `Authentication-Info` and `Proxy-Authentication-Info` are *not* reported: RFC 9110 §11.6.3 and §11.7.3 permit both in a trailer section when the authentication scheme allows it, and the scheme is not visible here.\n\nTwo further sentences of §6.5.1 are left alone deliberately: that a trailer section is only possible where the framing enables one (a trailer section reaches this rule only because framing delivered it), and that a server SHOULD NOT send trailer fields it *believes* the user agent needs to receive (a belief, which no capture records).\n\nThis rule complements `message_trailer_headers_valid`, which reads the `Trailer` declaration's own syntax. Announcing a field and sending one are two acts; this rule judges the second."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("6.5"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-6.5",
                note: "Trailer fields: what a trailer section is, and why what it carries cannot unmake a routing or processing choice already made from the header section",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("6.5.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-6.5.1",
                note: "The MUST NOT behind the first finding, and it is deny-by-default: a trailer field is permitted only where the field's own definition says so. This rule reports the subset it can name; a field it does not recognise is not thereby approved",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("6.6.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-6.6.2",
                note: "The `Trailer` field, whose SHOULD asks a sender to indicate which fields might appear — the sentence behind the undeclared-field finding, which said §6.5 in the finding text",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("7.6.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6.1",
                note: "`Connection`: naming a field as a connection-option makes its value control information for this connection, and every intermediary removes it from the trailer section before forwarding",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("11.6.3"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-11.6.3",
                note: "`Authentication-Info` may be sent as a trailer field when the authentication scheme allows it — a field §6.5.1's authentication category would forbid, permitted by name in its own definition. §11.7.3 says the same of `Proxy-Authentication-Info`. Neither is reported",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("16.3.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-16.3.2",
                note: "The registry's advice to authors of new fields, and the sentence that makes §6.5.1 deny-by-default: a field is not allowable in trailers unless its definition says it is",
            },
            crate::rules::SpecRef {
                spec: "RFC 9112",
                section: Some("7.1.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-7.1.2",
                note: "The chunked transfer coding's trailer section — HTTP/1.1's framing mechanism for the section this rule reads, and the reason the framing precondition in §6.5.1 needs no check here",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("Announced before the content, sent after it"),
                snippet: "HTTP/1.1 200 OK\nTrailer: X-Checksum\nTransfer-Encoding: chunked\n\n<chunked body>\nX-Checksum: abc123",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some(
                    "A field §6.5.1's categories would forbid and its own definition permits",
                ),
                snippet: "HTTP/1.1 200 OK\nTrailer: Authentication-Info\nTransfer-Encoding: chunked\n\n<chunked body>\nAuthentication-Info: nextnonce=\"a1b2c3\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("Message framing, which the recipient needed before the content"),
                snippet: "HTTP/1.1 200 OK\nTransfer-Encoding: chunked\n\n<chunked body>\nContent-Length: 42",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("Control information for this connection, by the sender's own account"),
                snippet: "HTTP/1.1 200 OK\nConnection: keep-alive, X-Hop-State\nTransfer-Encoding: chunked\n\n<chunked body>\nX-Hop-State: value",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("Sent after the content, and the declaration did not indicate it"),
                snippet: "HTTP/1.1 200 OK\nTrailer: X-Checksum\nTransfer-Encoding: chunked\n\n<chunked body>\nX-Signature: sig-value",
            },
        ]
    }
}

/// The field names one field section's `Trailer` announces, lowercased, or `None`
/// where that section carries no `Trailer` field at all.
///
/// The two are different inputs and the caller acts on the difference: a message
/// that announced nothing is not a message that announced an empty list, and only
/// the second has a declaration to fall short of. `Some(vec![])` is the empty list —
/// `Trailer:` is a legal value, so it is read, not repaired.
///
/// The lines are joined before the members are counted, because the field is one
/// list however many lines carry it, and the value is carried octet for octet: a
/// member outside US-ASCII is not a `field-name` and will match no arriving field,
/// which is the same answer as dropping it and is one the caller can see.
///
/// From here the declaration is read the way a recipient reads it, which is the
/// party this rule stands in for: empty elements are ignored, and the sender is
/// answered for writing one by `message_trailer_headers_valid`.
///
/// cite(RFC 9110 § 5.1): "Field names are case-insensitive and ought to be registered within the "Hypertext Transfer Protocol (HTTP) Field Name Registry"; see Section 16.3.1."
/// cite(RFC 9110 § 5.6.1.2): "A recipient MUST parse and ignore a reasonable number of empty list elements:"
fn collect_declared_trailers(headers: &hyper::HeaderMap) -> Option<Vec<String>> {
    let value = crate::helpers::headers::combined_field_value_as_written(headers, "trailer")?;
    Some(
        crate::helpers::headers::parse_list_header(&value)
            .map(|member| member.to_ascii_lowercase())
            .collect(),
    )
}

/// Validate one message's trailer section against its own header section.
fn check_trailers(
    rule_id: &str,
    config: &crate::rules::RuleConfig,
    trailers: &hyper::HeaderMap,
    headers: &hyper::HeaderMap,
) -> Option<Violation> {
    let declared = collect_declared_trailers(headers);
    // The `Connection` consulted is this message's, all of its lines: the options
    // are one list however many lines carry them, and reading the first line only
    // made every option after the first invisible.
    //
    // cite(RFC 9110 § 7.6.1): "The "Connection" header field allows the sender to list desired control options for the current connection."
    let connection_val =
        crate::helpers::headers::combined_field_value_as_written(headers, "connection");

    for key in trailers.keys() {
        // hyper normalises header names to lowercase, which is the comparison the
        // field-name production asks for anyway.
        //
        // cite(RFC 9110 § 5.1): "Field names are case-insensitive and ought to be registered within the "Hypertext Transfer Protocol (HTTP) Field Name Registry"; see Section 16.3.1."
        let name = key.as_str();

        // The half that depends on what the field is. The table is a subset of the
        // cited requirement and says so; what it holds are the field definitions
        // this crate carries that do not permit the usage.
        //
        // cite(RFC 9110 § 6.5.1): "A sender MUST NOT generate a trailer field unless the sender knows the corresponding header field name's definition permits the field to be sent in trailers."
        if crate::helpers::headers::is_prohibited_trailer_field(name) {
            return Some(Violation {
                rule: rule_id.to_string(),
                severity: config.severity,
                message: format!(
                    "Trailer section contains prohibited field '{}'; \
                     trailers must not include fields used for message framing, \
                     routing, request modifiers, authentication, response control \
                     data, or payload processing (RFC 9110 §6.5.1)",
                    name
                ),
            });
        }

        // The other half, and the one that depends on this message rather than on
        // what the field is — and the one case where the general question above is
        // decidable for a field nobody defined, because the sender answered it
        // itself: naming a field as a connection-option says its value is control
        // information for this connection, which is information the recipient needs
        // before the content, and every intermediary strips it from the trailer
        // section on the way. The sentence that reaches into that section is cited
        // on the helper.
        //
        // cite(RFC 9110 § 7.6.1): "When a field aside from Connection is used to supply control information for or about the current connection, the sender MUST list the corresponding field name within the Connection header field."
        if crate::helpers::headers::is_nominated_by_connection(name, connection_val.as_deref()) {
            return Some(Violation {
                rule: rule_id.to_string(),
                severity: config.severity,
                message: format!(
                    "Trailer field '{}' is named as a connection-option in this \
                     message's Connection header, so it is control information for \
                     this connection and every intermediary removes it from the \
                     trailer section before forwarding (RFC 9110 §7.6.1)",
                    name
                ),
            });
        }

        // Undeclared trailer field — asked only of a message that carries a
        // `Trailer` field, because it is the declaration that creates the
        // expectation to fall short of. An empty declaration is still a
        // declaration: `Trailer:` announces a list of no field names, so every
        // field that then arrives is one it did not indicate.
        //
        // cite(RFC 9110 § 6.6.2): "A sender that intends to generate one or more trailer fields in a message SHOULD generate a Trailer header field in the header section of that message to indicate which fields might be present in the trailers."
        if let Some(ref declared) = declared {
            if !declared.iter().any(|d| d == name) {
                return Some(Violation {
                    rule: rule_id.to_string(),
                    severity: config.severity,
                    message: format!(
                        "Trailer field '{}' was not declared in the Trailer header; \
                         senders should list the fields that might appear in the \
                         trailers before the message body (RFC 9110 §6.6.2)",
                        name
                    ),
                });
            }
        }
    }
    None
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &MessageTrailerFieldsValidity;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{
        make_headers_from_pairs, make_test_transaction, make_test_transaction_with_response,
    };
    use crate::transaction_history::TransactionHistory;
    use rstest::rstest;

    fn cfg() -> crate::config::Config {
        crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_trailer_fields_validity",
        ])
    }

    fn empty_history() -> TransactionHistory {
        TransactionHistory::empty()
    }

    // ---- Prohibited trailer fields (response) ----

    #[rstest]
    #[case("content-length")]
    #[case("transfer-encoding")]
    #[case("host")]
    #[case("cache-control")]
    #[case("expect")]
    #[case("max-forwards")]
    #[case("pragma")]
    #[case("range")]
    #[case("te")]
    #[case("if-match")]
    #[case("if-modified-since")]
    #[case("if-none-match")]
    #[case("if-range")]
    #[case("if-unmodified-since")]
    #[case("authorization")]
    #[case("proxy-authenticate")]
    #[case("proxy-authorization")]
    #[case("www-authenticate")]
    #[case("age")]
    #[case("date")]
    #[case("expires")]
    #[case("location")]
    #[case("retry-after")]
    #[case("vary")]
    #[case("warning")]
    #[case("content-encoding")]
    #[case("content-range")]
    #[case("content-type")]
    #[case("trailer")]
    #[case("connection")]
    #[case("keep-alive")]
    #[case("upgrade")]
    fn response_prohibited_trailer_field_is_violation(#[case] field: &str) {
        let rule = MessageTrailerFieldsValidity;
        let mut tx = make_test_transaction_with_response(200, &[]);
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert(
            field.parse::<hyper::header::HeaderName>().unwrap(),
            "some-value".parse().unwrap(),
        );
        tx.response.as_mut().unwrap().trailers = Some(trailers);

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(
            v.is_some(),
            "expected violation for prohibited trailer '{field}'"
        );
        assert!(v.unwrap().message.contains(field));
    }

    // ---- Prohibited trailer fields (request) ----

    #[rstest]
    #[case("content-length")]
    #[case("transfer-encoding")]
    #[case("host")]
    #[case("authorization")]
    #[case("content-type")]
    #[case("trailer")]
    fn request_prohibited_trailer_field_is_violation(#[case] field: &str) {
        let rule = MessageTrailerFieldsValidity;
        let mut tx = make_test_transaction();
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert(
            field.parse::<hyper::header::HeaderName>().unwrap(),
            "some-value".parse().unwrap(),
        );
        tx.request.trailers = Some(trailers);

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(
            v.is_some(),
            "expected violation for prohibited request trailer '{field}'"
        );
        assert!(v.unwrap().message.contains(field));
    }

    // ---- Valid trailer fields ----

    #[test]
    fn response_valid_trailer_field_no_violation() {
        let rule = MessageTrailerFieldsValidity;
        let mut tx = make_test_transaction_with_response(200, &[]);
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("x-checksum", "abc123".parse().unwrap());
        tx.response.as_mut().unwrap().trailers = Some(trailers);

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_none());
    }

    #[test]
    fn request_valid_trailer_field_no_violation() {
        let rule = MessageTrailerFieldsValidity;
        let mut tx = make_test_transaction();
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("x-checksum", "abc123".parse().unwrap());
        tx.request.trailers = Some(trailers);

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_none());
    }

    // ---- No trailers at all — no violation ----

    #[test]
    fn no_trailers_no_violation() {
        let rule = MessageTrailerFieldsValidity;
        let tx = make_test_transaction_with_response(200, &[]);
        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_none());
    }

    #[test]
    fn request_only_no_trailers_no_violation() {
        let rule = MessageTrailerFieldsValidity;
        let tx = make_test_transaction();
        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_none());
    }

    // ---- Undeclared trailer fields ----

    #[test]
    fn response_trailer_not_declared_in_trailer_header_is_violation() {
        let rule = MessageTrailerFieldsValidity;
        let mut tx = make_test_transaction_with_response(200, &[("trailer", "x-checksum")]);
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("x-signature", "sig-value".parse().unwrap());
        tx.response.as_mut().unwrap().trailers = Some(trailers);

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("not declared"));
    }

    #[test]
    fn request_trailer_not_declared_in_trailer_header_is_violation() {
        let rule = MessageTrailerFieldsValidity;
        let mut tx = make_test_transaction();
        tx.request.headers = make_headers_from_pairs(&[("trailer", "x-checksum")]);
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("x-signature", "sig-value".parse().unwrap());
        tx.request.trailers = Some(trailers);

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("not declared"));
    }

    #[test]
    fn response_trailer_declared_and_matching_no_violation() {
        let rule = MessageTrailerFieldsValidity;
        let mut tx = make_test_transaction_with_response(200, &[("trailer", "X-Checksum")]);
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("x-checksum", "abc123".parse().unwrap());
        tx.response.as_mut().unwrap().trailers = Some(trailers);

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_none());
    }

    #[test]
    fn response_trailer_declared_case_insensitive_match() {
        let rule = MessageTrailerFieldsValidity;
        let mut tx = make_test_transaction_with_response(200, &[("trailer", "X-CHECKSUM")]);
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("x-checksum", "abc123".parse().unwrap());
        tx.response.as_mut().unwrap().trailers = Some(trailers);

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_none());
    }

    #[test]
    fn response_trailer_multiple_declared_fields() {
        let rule = MessageTrailerFieldsValidity;
        let mut tx =
            make_test_transaction_with_response(200, &[("trailer", "X-Checksum, X-Signature")]);
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("x-checksum", "abc123".parse().unwrap());
        trailers.insert("x-signature", "sig-value".parse().unwrap());
        tx.response.as_mut().unwrap().trailers = Some(trailers);

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_none());
    }

    // ---- No Trailer header but trailers present — no undeclared violation ----

    #[test]
    fn response_trailers_present_without_trailer_header_no_undeclared_violation() {
        let rule = MessageTrailerFieldsValidity;
        let mut tx = make_test_transaction_with_response(200, &[]);
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("x-checksum", "abc123".parse().unwrap());
        tx.response.as_mut().unwrap().trailers = Some(trailers);

        // No Trailer header → declared is empty → undeclared check skipped
        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_none());
    }

    // ---- Prohibited takes priority over undeclared ----

    #[test]
    fn prohibited_field_takes_priority_over_undeclared() {
        let rule = MessageTrailerFieldsValidity;
        let mut tx = make_test_transaction_with_response(200, &[("trailer", "x-checksum")]);
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("content-length", "42".parse().unwrap());
        tx.response.as_mut().unwrap().trailers = Some(trailers);

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("prohibited"));
    }

    // ---- Connection-nominated hop-by-hop trailer fields ----

    #[test]
    fn response_connection_nominated_trailer_is_violation() {
        let rule = MessageTrailerFieldsValidity;
        let mut tx = make_test_transaction_with_response(200, &[("connection", "X-Custom-Hop")]);
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("x-custom-hop", "value".parse().unwrap());
        tx.response.as_mut().unwrap().trailers = Some(trailers);

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("connection-option"));
    }

    #[test]
    fn request_connection_nominated_trailer_is_violation() {
        let rule = MessageTrailerFieldsValidity;
        let mut tx = make_test_transaction();
        tx.request.headers = make_headers_from_pairs(&[("connection", "X-Req-Hop")]);
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("x-req-hop", "value".parse().unwrap());
        tx.request.trailers = Some(trailers);

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("connection-option"));
    }

    #[test]
    fn connection_nominated_case_insensitive_match() {
        let rule = MessageTrailerFieldsValidity;
        let mut tx = make_test_transaction_with_response(200, &[("connection", "X-CUSTOM-HOP")]);
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("x-custom-hop", "value".parse().unwrap());
        tx.response.as_mut().unwrap().trailers = Some(trailers);

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("connection-option"));
    }

    /// The connection options are one list however many `Connection` lines carry
    /// them. Reading the first line only made every option after the first
    /// invisible — and `Connection: keep-alive` in front of the interesting one is
    /// the ordinary shape of a message, not a contrived one.
    #[test]
    fn connection_option_on_a_later_line_is_still_a_connection_option() {
        let rule = MessageTrailerFieldsValidity;
        let mut tx = make_test_transaction_with_response(200, &[]);
        let mut hm = hyper::HeaderMap::new();
        hm.append("connection", "keep-alive".parse().unwrap());
        hm.append("connection", "X-Custom-Hop".parse().unwrap());
        tx.response.as_mut().unwrap().headers = hm;

        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("x-custom-hop", "value".parse().unwrap());
        tx.response.as_mut().unwrap().trailers = Some(trailers);

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_some(), "second Connection line was not read");
        assert!(v.unwrap().message.contains("connection-option"));
    }

    /// A request's connection options are that request's, and a response's trailer
    /// section is measured against the response's own header section.
    #[test]
    fn request_connection_option_does_not_reach_the_response_trailers() {
        let rule = MessageTrailerFieldsValidity;
        let mut tx = make_test_transaction_with_response(200, &[]);
        tx.request.headers = make_headers_from_pairs(&[("connection", "X-Custom-Hop")]);

        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("x-custom-hop", "value".parse().unwrap());
        tx.response.as_mut().unwrap().trailers = Some(trailers);

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_none(), "{v:?}");
    }

    #[test]
    fn trailer_not_in_connection_is_ok() {
        let rule = MessageTrailerFieldsValidity;
        let mut tx = make_test_transaction_with_response(200, &[("connection", "X-Custom-Hop")]);
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("x-other", "value".parse().unwrap());
        tx.response.as_mut().unwrap().trailers = Some(trailers);

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_none());
    }

    #[test]
    fn prohibited_takes_priority_over_connection_nominated() {
        // A statically prohibited field is caught before the dynamic check.
        let rule = MessageTrailerFieldsValidity;
        let mut tx =
            make_test_transaction_with_response(200, &[("connection", "transfer-encoding")]);
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("transfer-encoding", "chunked".parse().unwrap());
        tx.response.as_mut().unwrap().trailers = Some(trailers);

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_some());
        // Should say "prohibited", not "hop-by-hop", since static check runs first.
        assert!(v.unwrap().message.contains("prohibited"));
    }

    // ---- Request trailers checked before response trailers ----

    #[test]
    fn request_trailers_checked_first() {
        let rule = MessageTrailerFieldsValidity;
        let mut tx = make_test_transaction_with_response(200, &[]);

        // Add prohibited field to request trailers
        let mut req_trailers = hyper::HeaderMap::new();
        req_trailers.insert("host", "example.com".parse().unwrap());
        tx.request.trailers = Some(req_trailers);

        // Add valid field to response trailers
        let mut resp_trailers = hyper::HeaderMap::new();
        resp_trailers.insert("x-checksum", "abc".parse().unwrap());
        tx.response.as_mut().unwrap().trailers = Some(resp_trailers);

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("host"));
    }

    // ---- Multiple Trailer header fields ----

    #[test]
    fn multiple_trailer_header_fields_collected() {
        let rule = MessageTrailerFieldsValidity;
        let mut tx = make_test_transaction_with_response(200, &[]);
        let mut hm = hyper::HeaderMap::new();
        hm.append(
            "trailer",
            "X-Checksum".parse::<hyper::header::HeaderValue>().unwrap(),
        );
        hm.append(
            "trailer",
            "X-Signature".parse::<hyper::header::HeaderValue>().unwrap(),
        );
        tx.response.as_mut().unwrap().headers = hm;

        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("x-checksum", "abc".parse().unwrap());
        trailers.insert("x-signature", "sig".parse().unwrap());
        tx.response.as_mut().unwrap().trailers = Some(trailers);

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_none());
    }

    // ---- Empty trailers HeaderMap — no violation ----

    #[test]
    fn empty_trailers_headermap_no_violation() {
        let rule = MessageTrailerFieldsValidity;
        let mut tx = make_test_transaction_with_response(200, &[("trailer", "x-checksum")]);
        tx.response.as_mut().unwrap().trailers = Some(hyper::HeaderMap::new());

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_none());
    }

    // ---- An empty declaration is a declaration ----

    #[test]
    fn whitespace_only_trailer_header_with_actual_trailers_flags_undeclared() {
        // `Trailer:` is a legal value — the field is `#field-name`, so a list of no
        // field names is a list — and it announces nothing. A field that then
        // arrives is a field the declaration did not indicate, which is what the
        // finding says. The rule used to reach the same verdict by calling the
        // value invalid and standing a sentinel field-name in its place.
        let rule = MessageTrailerFieldsValidity;
        let mut tx = make_test_transaction_with_response(200, &[("trailer", "  ")]);
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("x-checksum", "abc".parse().unwrap());
        tx.response.as_mut().unwrap().trailers = Some(trailers);

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("not declared"));
    }

    // ---- RFC edge cases ----

    #[test]
    fn common_valid_trailer_etag_passes() {
        // RFC 9110 §8.8.3 explicitly allows ETag as a trailer field.
        let rule = MessageTrailerFieldsValidity;
        let mut tx = make_test_transaction_with_response(200, &[("trailer", "ETag")]);
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("etag", "\"abc\"".parse().unwrap());
        tx.response.as_mut().unwrap().trailers = Some(trailers);

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_none());
    }

    /// The two fields §11 permits in a trailer section, having listed them under the
    /// category §6.5.1 forbids. Both were in the prohibited table and both were
    /// reported; the permission is conditional on the authentication scheme, which
    /// this rule cannot see, so the conforming sender is the one that must be
    /// believed.
    #[rstest]
    #[case("authentication-info")]
    #[case("proxy-authentication-info")]
    fn field_whose_own_definition_permits_a_trailer_is_not_reported(#[case] field: &str) {
        let rule = MessageTrailerFieldsValidity;
        let mut tx = make_test_transaction_with_response(200, &[("trailer", field)]);
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert(
            field.parse::<hyper::header::HeaderName>().unwrap(),
            "nextnonce=\"abc\"".parse().unwrap(),
        );
        tx.response.as_mut().unwrap().trailers = Some(trailers);

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_none(), "expected no violation for '{field}': {v:?}");
    }

    #[test]
    fn common_valid_trailer_server_timing_passes() {
        let rule = MessageTrailerFieldsValidity;
        let mut tx = make_test_transaction_with_response(200, &[("trailer", "Server-Timing")]);
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("server-timing", "db;dur=53".parse().unwrap());
        tx.response.as_mut().unwrap().trailers = Some(trailers);

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_none());
    }

    #[test]
    fn mix_of_valid_and_prohibited_in_trailers_reports_prohibited() {
        let rule = MessageTrailerFieldsValidity;
        let mut tx = make_test_transaction_with_response(200, &[]);
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("x-checksum", "abc123".parse().unwrap());
        trailers.insert("transfer-encoding", "chunked".parse().unwrap());
        tx.response.as_mut().unwrap().trailers = Some(trailers);

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("prohibited"));
    }

    #[test]
    fn partial_declaration_match_flags_undeclared() {
        // Declare X-Checksum but send X-Checksum + X-Extra — X-Extra is undeclared.
        let rule = MessageTrailerFieldsValidity;
        let mut tx = make_test_transaction_with_response(200, &[("trailer", "X-Checksum")]);
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("x-checksum", "abc".parse().unwrap());
        trailers.insert("x-extra", "extra".parse().unwrap());
        tx.response.as_mut().unwrap().trailers = Some(trailers);

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("not declared"));
    }

    /// A `Trailer` value outside US-ASCII announces no field name — a member is a
    /// `field-name`, which is a `token`, and no `tchar` is outside US-ASCII. The
    /// octets are carried through rather than dropped, and the member they make
    /// matches nothing, so it can neither excuse an arriving field nor accuse one.
    #[test]
    fn non_ascii_trailer_declaration_announces_nothing() {
        let rule = MessageTrailerFieldsValidity;
        let mut tx = make_test_transaction_with_response(200, &[]);
        let mut hm = hyper::HeaderMap::new();
        hm.append(
            "trailer",
            hyper::header::HeaderValue::from_bytes(&[0xff]).unwrap(),
        );
        tx.response.as_mut().unwrap().headers = hm;

        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("x-checksum", "abc".parse().unwrap());
        tx.response.as_mut().unwrap().trailers = Some(trailers);

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("not declared"));
    }

    #[test]
    fn non_utf8_trailer_header_value_still_catches_prohibited() {
        // A prohibited field is prohibited whatever the declaration says, and the
        // declaration is unreadable here.
        let rule = MessageTrailerFieldsValidity;
        let mut tx = make_test_transaction_with_response(200, &[]);
        let mut hm = hyper::HeaderMap::new();
        hm.append(
            "trailer",
            hyper::header::HeaderValue::from_bytes(&[0xff]).unwrap(),
        );
        tx.response.as_mut().unwrap().headers = hm;

        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("content-type", "text/plain".parse().unwrap());
        tx.response.as_mut().unwrap().trailers = Some(trailers);

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("prohibited"));
    }

    #[test]
    fn both_request_and_response_prohibited_reports_request_first() {
        let rule = MessageTrailerFieldsValidity;
        let mut tx = make_test_transaction_with_response(200, &[]);

        let mut req_trailers = hyper::HeaderMap::new();
        req_trailers.insert("authorization", "Bearer x".parse().unwrap());
        tx.request.trailers = Some(req_trailers);

        let mut resp_trailers = hyper::HeaderMap::new();
        resp_trailers.insert("content-length", "99".parse().unwrap());
        tx.response.as_mut().unwrap().trailers = Some(resp_trailers);

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("authorization"));
    }

    #[test]
    fn response_only_prohibited_when_request_trailers_clean() {
        let rule = MessageTrailerFieldsValidity;
        let mut tx = make_test_transaction_with_response(200, &[]);

        let mut req_trailers = hyper::HeaderMap::new();
        req_trailers.insert("x-request-id", "123".parse().unwrap());
        tx.request.trailers = Some(req_trailers);

        let mut resp_trailers = hyper::HeaderMap::new();
        resp_trailers.insert("date", "Sat, 01 Jan 2026 00:00:00 GMT".parse().unwrap());
        tx.response.as_mut().unwrap().trailers = Some(resp_trailers);

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("date"));
    }

    #[test]
    fn multiple_valid_trailers_all_declared_passes() {
        let rule = MessageTrailerFieldsValidity;
        let mut tx = make_test_transaction_with_response(
            200,
            &[("trailer", "X-Checksum, ETag, Server-Timing")],
        );
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("x-checksum", "sha256=abc".parse().unwrap());
        trailers.insert("etag", "\"v1\"".parse().unwrap());
        trailers.insert("server-timing", "total;dur=100".parse().unwrap());
        tx.response.as_mut().unwrap().trailers = Some(trailers);

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_none());
    }

    // ---- Scope and config ----

    /// Every published snippet is run through the rule, and every Compliant one is
    /// also run through the rule that owns the declaration it carries: this rule
    /// judges what arrives after the content and cannot see a `Trailer` field it
    /// may not write. The sibling shipped a Compliant example announcing a field
    /// this rule rejects; this is the same guard pointing the other way.
    #[test]
    fn published_examples_are_judged_by_this_rule_and_by_the_one_that_owns_the_declaration() {
        use crate::rules::{Compliance, Rule as _};
        let rule = MessageTrailerFieldsValidity;
        let owner = crate::rules::message_trailer_headers_valid::MessageTrailerHeadersValid;
        let owner_cfg = crate::test_helpers::make_test_config_with_severity(
            "message_trailer_headers_valid",
            "warn",
        );

        for ex in rule.examples() {
            let mut header_pairs: Vec<(&str, &str)> = Vec::new();
            let mut trailer_pairs: Vec<(&str, &str)> = Vec::new();
            let mut past_the_body = false;
            for line in ex.snippet.lines() {
                if line.starts_with("HTTP/") || line.starts_with('<') {
                    continue;
                }
                if line.is_empty() {
                    past_the_body = true;
                    continue;
                }
                let (name, value) = line
                    .split_once(':')
                    .unwrap_or_else(|| panic!("example field line is not `Name: value`: {line:?}"));
                if past_the_body {
                    trailer_pairs.push((name, value.trim()));
                } else {
                    header_pairs.push((name, value.trim()));
                }
            }
            assert!(
                !trailer_pairs.is_empty(),
                "example carries no trailer section: {}",
                ex.snippet
            );

            let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&header_pairs);
            tx.response.as_mut().unwrap().trailers =
                Some(crate::test_helpers::make_headers_from_pairs(&trailer_pairs));

            let v = rule.check_transaction(&tx, &empty_history(), &cfg());
            match ex.compliance {
                Compliance::Compliant => assert!(v.is_none(), "{}: {v:?}", ex.snippet),
                Compliance::NonCompliant => assert!(v.is_some(), "{}", ex.snippet),
            }

            if !matches!(ex.compliance, Compliance::Compliant) {
                continue;
            }
            let v = owner.check_transaction(&tx, &empty_history(), &owner_cfg);
            assert!(
                v.is_none(),
                "the Compliant example writes a Trailer field its owner rejects: {v:?}\n{}",
                ex.snippet
            );
        }
    }

    #[test]
    fn id_and_scope_are_expected() {
        let rule = MessageTrailerFieldsValidity;
        assert_eq!(rule.id(), "message_trailer_fields_validity");
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_trailer_fields_validity");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
