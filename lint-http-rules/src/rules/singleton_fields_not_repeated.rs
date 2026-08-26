// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct SingletonFieldsNotRepeated;

/// The singleton fields this rule counts, each with the reason it is one —
/// the field's own grammar, which is what § 5.3's exception turns on.
///
/// **A field absent from this table draws nothing.** The exception clause asks
/// whether *"at least one alternative of the field's definition allows a
/// comma-separated list"*, which is a fact about the definition and not about
/// the message — so a field this catalogue has not read is not assumed to be a
/// singleton, and the table is the set whose grammars the campaign has read
/// and cited, minus the eight whose repetition another rule already reports
/// (named in `description()`).
///
/// Four productions here are too short to quote: `Date = HTTP-date`,
/// `ETag = entity-tag`, `Age = delta-seconds` and `Expires = HTTP-date` all
/// fall under the extractor's floor, stand alone between two paragraphs in
/// their own sections, *and* are separated from their neighbours by blank
/// lines in the collected grammars — the `From = mailbox` shape, where the
/// drag-a-neighbour trick fails too. Each is carried by its section's
/// definitional prose instead, and `Age` by the sentence that says the word
/// *singleton* outright.
//
// cite(RFC 9110 § 10.2.4): "Server = product *( RWS ( product / comment ) )"
// cite(RFC 9110 § 10.1.5): "User-Agent = product *( RWS ( product / comment ) )"
// cite(RFC 9110 § 6.6.1): "The "Date" header field represents the date and time at which the message was originated, having the same semantics as the Origination Date Field (orig-date) defined in Section 3.6.1 of [RFC5322]."
// cite(RFC 9110 § 8.8.2): "The "Last-Modified" header field in a response provides a timestamp indicating the date and time at which the origin server believes the selected representation was last modified"
// cite(RFC 9110 § 8.8.3): "The "ETag" field in a response provides the current entity tag for the selected representation, as determined at the conclusion of handling the request."
// cite(RFC 9110 § 8.3): "Content-Type = media-type"
// cite(RFC 9110 § 14.4): "Content-Range = range-unit SP ( range-resp / unsatisfied-range )"
// cite(RFC 9110 § 14.2): "Range = ranges-specifier"
// cite(RFC 9110 § 13.1.5): "If-Range = entity-tag / HTTP-date"
// cite(RFC 9110 § 13.1.3): "If-Modified-Since = HTTP-date"
// cite(RFC 9110 § 13.1.4): "If-Unmodified-Since = HTTP-date"
// cite(RFC 9110 § 11.6.2): "Authorization = credentials"
// cite(RFC 9110 § 11.7.2): "Proxy-Authorization = credentials"
// cite(RFC 9110 § 10.2.3): "Retry-After = HTTP-date / delay-seconds"
// cite(RFC 9111 § 5.1): "The "Age" response header field conveys the sender's estimate of the time since the response was generated or successfully validated at the origin server."
// cite(RFC 9111 § 5.1): "Although it is defined as a singleton header field, a cache encountering a message with a list-based Age field value SHOULD use the first member of the field value, discarding subsequent ones."
// cite(RFC 9111 § 5.3): "The "Expires" response header field gives the date/time after which the response is considered stale."
const SINGLETON_FIELDS: &[(&str, &str)] = &[
    (
        "server",
        "`Server = product *( RWS ( product / comment ) )` (RFC 9110 §10.2.4)",
    ),
    (
        "user-agent",
        "`User-Agent = product *( RWS ( product / comment ) )` (RFC 9110 §10.1.5)",
    ),
    ("date", "`Date = HTTP-date` (RFC 9110 §6.6.1)"),
    (
        "last-modified",
        "`Last-Modified = HTTP-date` (RFC 9110 §8.8.2)",
    ),
    ("etag", "`ETag = entity-tag` (RFC 9110 §8.8.3)"),
    (
        "content-type",
        "`Content-Type = media-type` (RFC 9110 §8.3)",
    ),
    (
        "content-range",
        "`Content-Range = range-unit SP ( range-resp / unsatisfied-range )` (RFC 9110 §14.4)",
    ),
    ("range", "`Range = ranges-specifier` (RFC 9110 §14.2)"),
    (
        "if-range",
        "`If-Range = entity-tag / HTTP-date` (RFC 9110 §13.1.5)",
    ),
    (
        "if-modified-since",
        "`If-Modified-Since = HTTP-date` (RFC 9110 §13.1.3)",
    ),
    (
        "if-unmodified-since",
        "`If-Unmodified-Since = HTTP-date` (RFC 9110 §13.1.4)",
    ),
    (
        "authorization",
        "`Authorization = credentials` (RFC 9110 §11.6.2)",
    ),
    (
        "proxy-authorization",
        "`Proxy-Authorization = credentials` (RFC 9110 §11.7.2)",
    ),
    (
        "retry-after",
        "`Retry-After = HTTP-date / delay-seconds` (RFC 9110 §10.2.3)",
    ),
    ("age", "`Age = delta-seconds` (RFC 9111 §5.1)"),
    ("expires", "`Expires = HTTP-date` (RFC 9111 §5.3)"),
];

impl Rule for SingletonFieldsNotRepeated {
    fn id(&self) -> &'static str {
        "singleton_fields_not_repeated"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Option<Violation> {
        let message =
            judge(&tx.request.headers, tx.request.trailers.as_ref(), "Request").or_else(|| {
                tx.response
                    .as_ref()
                    .and_then(|resp| judge(&resp.headers, resp.trailers.as_ref(), "Response"))
            })?;

        Some(Violation {
            rule: self.id().into(),
            severity: ctx.severity,
            message,
        })
    }

    fn description(&self) -> &'static str {
        "Reports a message writing more than one field line of a singleton field. RFC 9110 §5.3: \
         a sender MUST NOT generate multiple field lines with the same name in a message — \
         *whether in the headers or trailers* — unless at least one alternative of the field's \
         definition allows a comma-separated list, and no definition of the sixteen fields this \
         rule counts has one. §5.5 is why the check is worth making at all: it asks senders to \
         anticipate recombination *\"since a singleton field might be erroneously sent with \
         multiple members and detecting such errors improves interoperability\"*.\
         \n\n\
         **The count is per message, not per section.** §5.3's MUST NOT names the headers and \
         trailers together — its second clause forbids *appending* a field line where one \
         already exists — so a `Date` in the header section and another in the trailer section \
         are two field lines of one message and are reported. (Most of these fields are also \
         forbidden in trailers outright by other sentences; that is \
         `trailer_fields_valid`'s question and does not change this one.)\
         \n\n\
         **A field absent from the table draws nothing.** The exception clause turns on the \
         field's *definition*, which a linter cannot read off the wire — so only fields whose \
         grammars this catalogue has read and cited are counted, and an unknown field name is \
         never assumed to be a singleton. The sixteen are: `Server`, `User-Agent`, `Date`, \
         `Last-Modified`, `ETag`, `Content-Type`, `Content-Range`, `Range`, `If-Range`, \
         `If-Modified-Since`, `If-Unmodified-Since`, `Authorization`, `Proxy-Authorization`, \
         `Retry-After`, `Age` and `Expires` — for `Age`, RFC 9111 §5.1 says the word \
         *singleton* outright.\
         \n\n\
         **Eight singleton fields are deliberately not here**, because their repetition is \
         already reported where their values are read, with the joined value in the finding: \
         `Referer`, `Content-Location`, `Location`, `Max-Forwards`, `From` and \
         `Content-Disposition` each carry the check in their own rule, `Host` in \
         `host_header` (where RFC 9112 §3.2 adds the recipient's 400), and \
         `Content-Length` in the body-length rules — RFC 9110 §8.6 gives that field its own \
         arithmetic for duplicate values, which is a different question from this rule's.\
         \n\n\
         **What a recipient does with the repetition is each field's own hazard**, and this \
         rule does not guess at it: the finding names the field's grammar and §5.3, not a \
         reconstruction of what any particular recipient would read. §5.2's recombination is \
         defined within a section, and for none of these fields does the recombined value \
         derive from the field's grammar."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("5.3"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.3",
                note: "Field Order: the MUST NOT this rule enforces — multiple field lines with \
                       one name in a message, headers or trailers, unless the field's \
                       definition has a comma-separated-list alternative",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("5.5"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.5",
                note: "Field Values: what a singleton field is, and the sentence saying that \
                       detecting an erroneously repeated one improves interoperability",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("5.6.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1",
                note: "Lists: the `#rule` extension — the shape a field's definition has when \
                       §5.3's exception applies to it, and the shape none of the sixteen \
                       grammars in this rule's table has",
            },
            crate::rules::SpecRef {
                spec: "RFC 9111",
                section: Some("5.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-5.1",
                note: "Age — defined as a singleton header field in as many words, with the \
                       recipient's first-member recovery beside it, which is a recipient's \
                       SHOULD and not a sender's licence",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nDate: Tue, 15 Nov 1994 08:12:31 GMT\nContent-Type: text/plain\n\nHello",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(a list field may span field lines — not this rule's subject)"),
                snippet: "HTTP/1.1 200 OK\nCache-Control: max-age=60\nCache-Control: must-revalidate",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(two Date field lines — `Date = HTTP-date` has no list alternative)"),
                snippet: "HTTP/1.1 200 OK\nDate: Tue, 15 Nov 1994 08:12:31 GMT\nDate: Wed, 16 Nov 1994 08:12:31 GMT",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(two Content-Type field lines)"),
                snippet: "HTTP/1.1 200 OK\nContent-Type: text/html\nContent-Type: text/plain",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &SingletonFieldsNotRepeated;

/// Count each table field across one message's two sections and report the
/// first that is written more than once.
///
/// The count is header lines plus trailer lines, because § 5.3's MUST NOT is
/// about the message and says so — *"whether in the headers or trailers"* —
/// and its second clause forbids appending a line where one already exists,
/// which is exactly what a line in each section is. This is the
/// `content_disposition_token_valid` shape, not
/// [`crate::helpers::headers::singleton_field_preamble`]'s: the preamble's
/// recombining clause is § 5.2's, § 5.2 recombines *within* a section, and a
/// rule counting both sections cannot honestly say what § 5.2 recombines.
// cite(RFC 9110 § 5.3): "a sender MUST NOT generate multiple field lines with the same name in a message (whether in the headers or trailers) or append a field line when a field line of the same name already exists in the message, unless that field's definition allows multiple field line values to be recombined as a comma-separated list"
// cite(RFC 9110 § 5.3, label: the exception's shape): "such as an ABNF rule of #(values) defined in Section 5.6.1"
// cite(RFC 9110 § 5.5): "Fields that only anticipate a single member as the field value are referred to as "singleton fields"."
// cite(RFC 9110 § 5.5): "This is true for both list-based and singleton fields, since a singleton field might be erroneously sent with multiple members and detecting such errors improves interoperability."
fn judge(
    headers: &hyper::HeaderMap,
    trailers: Option<&hyper::HeaderMap>,
    side: &str,
) -> Option<String> {
    for (name, grammar) in SINGLETON_FIELDS {
        let header_lines = headers.get_all(*name).iter().count();
        let trailer_lines = trailers.map_or(0, |t| t.get_all(*name).iter().count());
        let lines = header_lines + trailer_lines;
        if lines > 1 {
            let where_written = if header_lines > 0 && trailer_lines > 0 {
                " across the header and trailer sections"
            } else if trailer_lines > 0 {
                " in the trailer section"
            } else {
                ""
            };
            return Some(format!(
                "{side} writes {lines} field lines of '{name}'{where_written}; the field is a \
                 singleton — {grammar} has no comma-separated-list alternative — so a sender \
                 must not generate more than one in a message, whether in the headers or \
                 trailers (RFC 9110 §5.3)"
            ));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::{HeaderName, HeaderValue};
    use rstest::rstest;

    fn cfg() -> crate::config::Config {
        crate::test_helpers::make_test_config_with_enabled_rules(&["singleton_fields_not_repeated"])
    }

    fn run(tx: &crate::http_transaction::HttpTransaction) -> Option<String> {
        crate::test_helpers::run_rule(
            &SingletonFieldsNotRepeated,
            tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg(),
        )
        .map(|v| v.message)
    }

    fn response_with_lines(pairs: &[(&str, &str)]) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let headers = &mut tx.response.as_mut().expect("a response").headers;
        for (name, value) in pairs {
            headers.append(
                HeaderName::from_bytes(name.as_bytes()).expect("a test field name"),
                HeaderValue::from_str(value).expect("a test field value"),
            );
        }
        tx
    }

    /// One line of a singleton draws nothing, and neither does a list field on
    /// however many lines — the exception clause is exactly for it.
    #[test]
    fn single_lines_and_list_fields_draw_nothing() {
        let tx = response_with_lines(&[
            ("date", "Tue, 15 Nov 1994 08:12:31 GMT"),
            ("content-type", "text/plain"),
            ("cache-control", "max-age=60"),
            ("cache-control", "must-revalidate"),
            ("vary", "accept"),
            ("vary", "accept-language"),
        ]);
        assert_eq!(run(&tx), None);
    }

    /// Exact message, pinned once per clause that can vary: the side, the
    /// count, and the field's own grammar parenthetical.
    #[test]
    fn two_date_lines_are_reported_with_the_grammar() {
        let tx = response_with_lines(&[
            ("date", "Tue, 15 Nov 1994 08:12:31 GMT"),
            ("date", "Wed, 16 Nov 1994 08:12:31 GMT"),
        ]);
        assert_eq!(
            run(&tx).expect("reported"),
            "Response writes 2 field lines of 'date'; the field is a singleton — `Date = \
             HTTP-date` (RFC 9110 §6.6.1) has no comma-separated-list alternative — so a sender \
             must not generate more than one in a message, whether in the headers or trailers \
             (RFC 9110 §5.3)"
        );
    }

    /// Every table row reports on its second line, in both directions — the
    /// table is data, and a row that never fired is a row a typo can disable.
    #[rstest]
    #[case("server", "a")]
    #[case("user-agent", "a")]
    #[case("date", "Tue, 15 Nov 1994 08:12:31 GMT")]
    #[case("last-modified", "Tue, 15 Nov 1994 08:12:31 GMT")]
    #[case("etag", "\"x\"")]
    #[case("content-type", "text/plain")]
    #[case("content-range", "bytes 0-1/2")]
    #[case("range", "bytes=0-1")]
    #[case("if-range", "\"x\"")]
    #[case("if-modified-since", "Tue, 15 Nov 1994 08:12:31 GMT")]
    #[case("if-unmodified-since", "Tue, 15 Nov 1994 08:12:31 GMT")]
    #[case("authorization", "Basic dGVzdA==")]
    #[case("proxy-authorization", "Basic dGVzdA==")]
    #[case("retry-after", "120")]
    #[case("age", "60")]
    #[case("expires", "Tue, 15 Nov 1994 08:12:31 GMT")]
    fn every_table_row_fires_on_its_second_line(#[case] name: &str, #[case] value: &str) {
        let tx = response_with_lines(&[(name, value), (name, value)]);
        let msg = run(&tx).unwrap_or_else(|| panic!("{name} not reported in response"));
        assert!(msg.contains(&format!("field lines of '{name}'")), "{msg}");

        // A fresh header map: the shared test request carries a User-Agent of
        // its own, and this test is about exactly two lines.
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut headers = hyper::HeaderMap::new();
        for _ in 0..2 {
            headers.append(
                HeaderName::from_bytes(name.as_bytes()).expect("a test field name"),
                HeaderValue::from_str(value).expect("a test field value"),
            );
        }
        tx.request.headers = headers;
        let msg = run(&tx).unwrap_or_else(|| panic!("{name} not reported in request"));
        assert!(msg.starts_with("Request writes 2 field lines"), "{msg}");
    }

    /// § 5.3's second clause: appending a line where one exists is forbidden
    /// across sections, so one header line plus one trailer line is the
    /// finding — and the message says which sections it counted.
    #[test]
    fn a_header_line_plus_a_trailer_line_is_two_lines_of_one_message() {
        let mut tx = response_with_lines(&[("etag", "\"a\"")]);
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("etag", HeaderValue::from_static("\"b\""));
        tx.response.as_mut().expect("a response").trailers = Some(trailers);

        let msg = run(&tx).expect("reported");
        assert!(
            msg.contains("2 field lines of 'etag' across the header and trailer sections"),
            "{msg}"
        );

        // Two lines wholly inside the trailer section say that instead.
        let mut tx = response_with_lines(&[]);
        let mut trailers = hyper::HeaderMap::new();
        trailers.append("etag", HeaderValue::from_static("\"a\""));
        trailers.append("etag", HeaderValue::from_static("\"b\""));
        tx.response.as_mut().expect("a response").trailers = Some(trailers);
        let msg = run(&tx).expect("reported");
        assert!(
            msg.contains("2 field lines of 'etag' in the trailer section"),
            "{msg}"
        );
    }

    /// The eight fields whose repetition another rule reports are absent from
    /// the table on purpose — two lines of them draw nothing *here*.
    #[rstest]
    #[case("referer", "/a")]
    #[case("content-location", "/a")]
    #[case("location", "/a")]
    #[case("max-forwards", "3")]
    #[case("from", "a@example.com")]
    #[case("content-disposition", "attachment")]
    #[case("host", "example.com")]
    #[case("content-length", "3")]
    fn fields_owned_by_other_rules_draw_nothing_here(#[case] name: &str, #[case] value: &str) {
        let tx = response_with_lines(&[(name, value), (name, value)]);
        assert_eq!(run(&tx), None, "{name}");
    }

    #[test]
    fn scope_is_both() {
        assert_eq!(
            SingletonFieldsNotRepeated.scope(),
            crate::rules::RuleScope::Both
        );
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "singleton_fields_not_repeated");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
