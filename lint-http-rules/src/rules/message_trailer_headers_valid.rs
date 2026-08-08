// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// The `Trailer` header field's own syntax, and the fields it may name.
///
/// This rule reads the *declaration* and never the trailer section;
/// `message_trailer_fields_validity` reads the fields that actually arrive. The
/// two do not divide one question in half, they ask two: what a sender may write
/// in this list, and what a sender may put after the content.
///
/// cite(RFC 9110 § 6.5.2): "The "Trailer" header field (Section 6.6.2) can be sent to indicate fields likely to be sent in the trailer section, which allows recipients to prepare for their receipt before processing the content."
#[derive(Debug, Clone)]
pub struct MessageTrailerHeadersValid;

/// Trim `OWS`, and only `OWS`.
///
/// `str::trim` trims Unicode whitespace, and the value this rule works on carries
/// one `char` per octet — so U+00A0 in it is the octet %xA0, which is `obs-text`
/// and not whitespace of any kind. Trimming it would turn a member no production
/// admits into an empty one, reporting the list for a defect the element has.
///
/// cite(RFC 9110 § 5.6.3): "The OWS rule is used where zero or more linear whitespace octets might appear."
fn trim_ows(s: &str) -> &str {
    s.trim_matches(|c| c == ' ' || c == '\t')
}

/// The combined field value for `name` in one field section, one `char` per octet.
///
/// Two decisions, and the same sentence is behind both. A list-based field is one
/// list however many lines carry it, so the lines are joined before the members
/// are counted — an empty element written at a line boundary is an empty element.
/// And the join is over the raw octets: a value outside US-ASCII is not a value
/// this field may carry, but it is the *member* that is wrong, so every octet is
/// decoded to the `char` of the same value and reaches the check that owns it.
/// `to_str` would have folded the whole message into "no Trailer here", and
/// `get_all_header_values` folds it into `None` for the same reason — right for a
/// caller asking what a message advertised, wrong for one reporting what it wrote.
///
/// cite(RFC 9110 § 5.2): "When a field name is repeated within a section, its combined field value consists of the list of corresponding field line values within that section, concatenated in order, with each field line value separated by a comma."
/// cite(RFC 9110 § 5.5): "A recipient SHOULD treat other allowed octets in field content (i.e., obs-text) as opaque data."
fn combined_field_value(hdrs: &hyper::HeaderMap, name: &str) -> Option<String> {
    let mut lines = hdrs.get_all(name).iter().peekable();
    lines.peek()?;
    let mut combined = String::new();
    for hv in lines {
        if !combined.is_empty() {
            combined.push(',');
        }
        combined.extend(hv.as_bytes().iter().map(|&b| char::from(b)));
    }
    Some(combined)
}

impl MessageTrailerHeadersValid {
    /// One field section: its `Trailer` list, measured against its own `Connection`.
    ///
    /// The `Connection` read here is the one in the same section as the `Trailer`
    /// being read. A connection-option is a statement by the sender of *that*
    /// message about *that* hop — the cited sentence removes the named fields "from
    /// the message" the option arrived in — so a request's options say nothing about
    /// what the response may put in its trailers, and reading the request's
    /// `Connection` for the response's `Trailer` (and, when the request had one,
    /// reading it *instead of* the response's own) was wrong in both directions.
    ///
    /// cite(RFC 9110 § 7.6.1): "The "Connection" header field allows the sender to list desired control options for the current connection."
    fn check_field_section(
        &self,
        hdrs: &hyper::HeaderMap,
        config: &crate::rules::RuleConfig,
    ) -> Option<Violation> {
        let violation = |message: String| {
            Some(Violation {
                rule: self.id().to_string(),
                severity: config.severity,
                message,
            })
        };

        let value = combined_field_value(hdrs, "trailer")?;
        let connection_val = combined_field_value(hdrs, "connection");

        // The field's own production, in the form the collected grammar gives a
        // sender, and the two things it says about emptiness. The outer `[ ]` is
        // why a `Trailer:` carrying nothing is not reported: a list of no field
        // names is a list this production generates, and the field is `#field-name`
        // rather than `1#field-name`, so nothing here requires an element. What the
        // production never generates is a *member* that is empty — every position in
        // it holds a `field-name`, which is `token`, which is `1*tchar`.
        //
        // cite(RFC 9110 § A, label: Trailer grammar): "Trailer = [ field-name *( OWS "," OWS field-name ) ]"
        if trim_ows(&value).is_empty() {
            return None;
        }

        let mut saw_an_empty_element = false;

        for member in value.split(',') {
            let member = trim_ows(member);

            if member.is_empty() {
                // Reported after the members that are present, and reported as the
                // list's defect rather than the element's: there is no such thing as
                // an empty `field-name`, so what the sender generated is a member
                // that contributes nothing to the list. The recipient's reader
                // (`parse_list_header`) drops these, which is that party's
                // requirement and erases this one — so it is not used here.
                //
                // cite(RFC 9110 § 5.6.1.1): "In any production that uses the list construct, a sender MUST NOT generate empty list elements."
                saw_an_empty_element = true;
                continue;
            }

            // A member is a field-name and a field-name is a `token`; `tchar` is
            // transcribed once, on the helper that answers this.
            //
            // cite(RFC 9110 § A, label: field-name grammar): "field-name = token field-value = *field-content"
            if let Some(ch) = crate::helpers::token::find_invalid_token_char(member) {
                return violation(format!(
                    "Trailer header contains invalid character '{}' in member '{}'; a member is a field-name, which is a token",
                    ch, member
                ));
            }

            // The one § 6.5.1 field this rule checks at declaration time, and it
            // earns the exception by being circular rather than merely premature: a
            // Trailer field inside a trailer section announces a section the
            // recipient has already finished reading. Its own definition places it
            // in the header section, which is what § 6.5.1 asks the sender to know.
            //
            // cite(RFC 9110 § 6.5.1): "A sender MUST NOT generate a trailer field unless the sender knows the corresponding header field name's definition permits the field to be sent in trailers."
            // cite(RFC 9110 § 6.6.2): "A sender that intends to generate one or more trailer fields in a message SHOULD generate a Trailer header field in the header section of that message to indicate which fields might be present in the trailers."
            //
            // cite(RFC 9110 § 5.1): "Field names are case-insensitive and ought to be registered within the "Hypertext Transfer Protocol (HTTP) Field Name Registry"; see Section 16.3.1."
            if member.eq_ignore_ascii_case("trailer") {
                return violation(
                    "Trailer header nominates 'Trailer'; a Trailer field cannot announce the trailer section it is already inside (RFC 9110 §6.5.1)".to_string(),
                );
            }

            // Scope note: this rule checks the *declaration*, and § 6.5.1's "MUST NOT
            // generate a trailer field" binds the sending, not the announcing. So the
            // wider § 6.5.1 list is not applied here — `message_trailer_fields_validity`
            // applies it to the fields that actually arrive. What is checked here is
            // the narrower claim: a connection-specific field does not survive the
            // hop, so no recipient could ever read it as a trailer. The cited
            // sentence is the one that reaches into the trailer section, and it says
            // so in as many words.
            //
            // cite(RFC 9110 § 7.6.1): "Intermediaries MUST parse a received Connection header field before a message is forwarded and, for each connection-option in this field, remove any header or trailer field(s) from the message with the same name as the connection-option, and then remove the Connection header field itself (or replace it with the intermediary's own control options for the forwarded message)."
            if crate::helpers::headers::is_connection_specific_field(
                member,
                connection_val.as_deref(),
            ) {
                return violation(format!(
                    "Trailer header nominates connection-specific field '{}'; it does not survive the hop, so it cannot arrive as a trailer (RFC 9110 §7.6.1)",
                    member
                ));
            }
        }

        if saw_an_empty_element {
            return violation(format!("Trailer header holds an empty member: '{}'", value));
        }

        None
    }
}

impl Rule for MessageTrailerHeadersValid {
    fn id(&self) -> &'static str {
        "message_trailer_headers_valid"
    }

    /// The field is message metadata, and the section that groups it says which
    /// messages carry it.
    ///
    /// cite(RFC 9110 § 6.6): "Fields that describe the message itself, such as when and how the message has been generated, can appear in both requests and responses."
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

        if let Some(v) = self.check_field_section(&tx.request.headers, &config) {
            return Some(v);
        }

        if let Some(resp) = &tx.response {
            if let Some(v) = self.check_field_section(&resp.headers, &config) {
                return Some(v);
            }
        }

        None
    }

    fn description(&self) -> &'static str {
        "Validate `Trailer` header members are syntactically valid header field-names and do not nominate hop-by-hop headers. Trailer members must be `token`-formatted header field-names and MUST NOT be hop-by-hop headers such as `Connection`, `Keep-Alive`, `Proxy-Authenticate`, `Proxy-Authorization`, `TE`, `Trailer`, `Transfer-Encoding`, or `Upgrade`. When a header is nominated via `Connection`, it is considered hop-by-hop and therefore not appropriate as a trailer member."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9112",
                section: Some("7.1.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-7.1.2",
                note: "Chunked trailer section. This said RFC 7230 §4.1.2 — the right section of an obsoleted document, under the *other* entry's note",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("7.6.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6.1",
                note: "`Connection` and hop-by-hop semantics. This said RFC 7230 §6.1 — likewise, with the two notes swapped between them",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nTrailer: ETag, Expires\n\n<response body>",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nTrailer: Connection\n\n<response body>",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nConnection: Keep-Alive\nTrailer: Keep-Alive\n\n<response body>",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &MessageTrailerHeadersValid;

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::{HeaderName, HeaderValue};
    use rstest::rstest;

    fn cfg() -> crate::config::Config {
        crate::test_helpers::make_test_config_with_severity("message_trailer_headers_valid", "warn")
    }

    /// One field section is one fixture. Every test below states which section the
    /// headers are in, because for this rule that is the question: a `Connection`
    /// in the other section is not this message's, and until this iteration the
    /// rule read whichever one it found first.
    enum Section {
        Request,
        Response,
    }

    /// Header lines as raw octets, appended in order, in one section of a
    /// transaction that always has both.
    fn tx_with(
        section: Section,
        lines: &[(&str, &[u8])],
    ) -> crate::http_transaction::HttpTransaction {
        let mut hm = hyper::HeaderMap::new();
        for (name, value) in lines {
            hm.append(
                name.parse::<HeaderName>().expect("header name"),
                HeaderValue::from_bytes(value).expect("header value"),
            );
        }
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        match section {
            Section::Request => tx.request.headers = hm,
            Section::Response => tx.response.as_mut().expect("response").headers = hm,
        }
        tx
    }

    fn run(tx: &crate::http_transaction::HttpTransaction) -> Option<Violation> {
        MessageTrailerHeadersValid.check_transaction(
            tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg(),
        )
    }

    /// A single `Trailer` line, in one section, and nothing else.
    fn trailer(section: Section, value: &str) -> Option<Violation> {
        run(&tx_with(section, &[("trailer", value.as_bytes())]))
    }

    #[rstest]
    #[case("X-Checksum, X-Signature", false)]
    #[case("My-Header", false)]
    #[case("Connection", true)]
    #[case("Transfer-Encoding", true)]
    #[case("Proxy-Connection", true)]
    #[case("Proxy-Authorization", true)]
    #[case("bad token", true)]
    #[case("Trailer", true)]
    fn trailer_cases(#[case] value: &str, #[case] expect_violation: bool) {
        for section in [Section::Request, Section::Response] {
            let v = trailer(section, value);
            assert_eq!(
                v.is_some(),
                expect_violation,
                "'{value}' in one section: {v:?}"
            );
        }
    }

    /// `Trailer = [ field-name *( OWS "," OWS field-name ) ]`: the outer brackets
    /// are the whole of this test. The rule used to report all three of these as
    /// "empty member", and three tests asserted it.
    #[rstest]
    #[case("")]
    #[case("   ")]
    #[case("\t")]
    fn a_list_of_no_field_names_is_a_list(#[case] value: &str) {
        for section in [Section::Request, Section::Response] {
            let v = trailer(section, value);
            assert!(v.is_none(), "{value:?} is a list of nothing: {v:?}");
        }
    }

    /// What the production never generates is a member that is empty. The
    /// recipient's list reader drops these, which is why the rule cannot use it.
    #[rstest]
    #[case("X-Checksum,,X-Signature")]
    #[case("X-Checksum,")]
    #[case(",X-Checksum")]
    #[case(",")]
    #[case("X-Checksum, , X-Signature")]
    fn an_empty_member_is_the_senders_defect(#[case] value: &str) {
        for section in [Section::Request, Section::Response] {
            let v = trailer(section, value).expect("empty member is reported");
            assert!(
                v.message.contains("empty member"),
                "{value:?}: {}",
                v.message
            );
        }
    }

    /// § 5.2: the lines are one value, so the boundary between them is a comma
    /// and an empty line contributes an empty member to the list.
    #[test]
    fn field_lines_in_one_section_are_one_list() {
        let v = run(&tx_with(
            Section::Response,
            &[("trailer", b"X-Checksum"), ("trailer", b"")],
        ))
        .expect("the joined value holds an empty member");
        assert!(v.message.contains("empty member"), "{}", v.message);

        let v = run(&tx_with(
            Section::Response,
            &[("trailer", b"X-Checksum"), ("trailer", b"bad token")],
        ))
        .expect("a defect on the second line is still a defect");
        assert!(v.message.contains("invalid character"), "{}", v.message);

        assert!(
            run(&tx_with(
                Section::Response,
                &[("trailer", b"X-Checksum"), ("trailer", b"X-Signature")],
            ))
            .is_none(),
            "two lines each carrying a field-name are one two-member list"
        );
    }

    /// A connection-option is a statement about the message it arrived in. Reading
    /// the request's `Connection` for the response's `Trailer` reported a
    /// conforming message; reading it *instead of* the response's own missed a
    /// non-conforming one. Both directions are pinned here.
    #[test]
    fn connection_is_read_from_the_section_the_trailer_is_in() {
        for section in [Section::Request, Section::Response] {
            let v = run(&tx_with(
                section,
                &[("connection", b"Keep-Alive"), ("trailer", b"Keep-Alive")],
            ));
            assert!(v.is_some(), "same section, nominated: {v:?}");
        }

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("connection", "Keep-Alive"),
            ("trailer", "X-Checksum"),
        ]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("trailer", "X-Request-Id")]);
        assert!(
            run(&tx).is_none(),
            "the request's connection options say nothing about the response's trailers"
        );

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("connection", "Keep-Alive"),
            ("trailer", "X-Checksum"),
        ]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            ("connection", "X-Response-Control"),
            ("trailer", "X-Response-Control"),
        ]);
        let v = run(&tx).expect("the response's own Connection is read, not the request's");
        assert!(v.message.contains("X-Response-Control"), "{}", v.message);
    }

    /// A connection-option is matched case-insensitively, like every field name.
    #[test]
    fn a_nomination_matches_whatever_case_it_is_written_in() {
        let v = run(&tx_with(
            Section::Request,
            &[("connection", b"Keep-Alive"), ("trailer", b"keep-alive")],
        ));
        assert!(v.is_some(), "{v:?}");
    }

    /// An octet outside US-ASCII is not a `tchar`, so the member is what is wrong
    /// with the value — and the rule says so. It used to answer "not valid UTF-8",
    /// which is a claim about the encoding and false for, say, a Latin-1 octet.
    #[test]
    fn an_octet_no_field_name_admits_is_reported_as_the_member_it_breaks() {
        for section in [Section::Request, Section::Response] {
            let v = run(&tx_with(section, &[("trailer", b"X-\xffChecksum")]))
                .expect("an octet outside the token production is reported");
            assert!(v.message.contains("invalid character"), "{}", v.message);
            assert!(
                !v.message.contains("UTF-8"),
                "the octet is not a claim about the encoding: {}",
                v.message
            );
        }
    }

    /// %xA0 is `obs-text`, and `str::trim` would have taken it for whitespace —
    /// turning a member no production admits into the list's defect instead of the
    /// member's.
    #[test]
    fn a0_is_obs_text_and_not_optional_whitespace() {
        let v = run(&tx_with(Section::Response, &[("trailer", b"\xa0")]))
            .expect("a value of one obs-text octet is a member, and an invalid one");
        assert!(v.message.contains("invalid character"), "{}", v.message);
    }

    #[test]
    fn invalid_token_violation_message_includes_char_and_member() {
        let v = trailer(Section::Response, "bad token").expect("violation");
        assert!(v.message.contains("invalid character"), "{}", v.message);
        assert!(v.message.contains("bad token"), "{}", v.message);
    }

    #[test]
    fn hop_by_hop_violation_message_includes_header_name() {
        let v = trailer(Section::Response, "Transfer-Encoding").expect("violation");
        assert!(v.message.contains("connection-specific"), "{}", v.message);
        assert!(v.message.contains("Transfer-Encoding"), "{}", v.message);
    }

    #[rstest]
    #[case("trailer")]
    #[case("Trailer")]
    #[case("TRAILER")]
    fn trailer_cannot_announce_the_section_it_is_inside(#[case] value: &str) {
        let v = trailer(Section::Response, value).expect("violation");
        assert!(v.message.contains("already inside"), "{}", v.message);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let rule = MessageTrailerHeadersValid;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("severity".to_string(), toml::Value::String("warn".into()));
        cfg.rules.insert(
            "message_trailer_headers_valid".into(),
            toml::Value::Table(table),
        );

        rule.validate(&cfg)?;
        Ok(())
    }

    #[test]
    fn id_and_scope_are_expected() {
        let rule = MessageTrailerHeadersValid;
        assert_eq!(rule.id(), "message_trailer_headers_valid");
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }
}
