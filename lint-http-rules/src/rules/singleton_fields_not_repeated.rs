// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::field::{FIELD_LINE_DUPLICATED, RFC_9110_5_3};
use crate::violations::ViolationDef;

/// The one entry, and this rule is the widest declarer of it there will be.
///
/// Eleven fields with no rule of their own are counted here; every other
/// declarer reads one field and reports the same sentence about it. What stays
/// this rule's own is the *table* — which field definitions have no
/// comma-separated-list alternative — because that is a reading of eleven
/// documents rather than of § 5.3.
static DECLARED: &[&ViolationDef] = &[&FIELD_LINE_DUPLICATED];

pub struct SingletonFieldsNotRepeated;

/// The singleton fields this rule counts, each with the reason it is one —
/// the field's own grammar, which is what § 5.3's exception turns on.
///
/// **A field absent from this table draws nothing.** The exception clause asks
/// whether *"at least one alternative of the field's definition allows a
/// comma-separated list"*, which is a fact about the definition and not about
/// the message — so a field this catalogue has not read is not assumed to be a
/// singleton, and the table is the set whose grammars the campaign has read
/// and cited, minus the thirteen whose repetition another rule already reports
/// (named in `description()`).
///
/// **The exclusion is the invariant, and it used to be broken five ways.**
/// `Content-Type`, `ETag`, `Retry-After`, `If-Modified-Since` and
/// `If-Unmodified-Since` sat in this table *and* were counted by the rule that
/// reads each one's value, so one repetition drew this entry twice — two
/// findings a reader has to reconcile before discovering they are one claim.
/// The field's own rule keeps the report, because it says more: that recipients
/// differ over which `Content-Type` member wins, that a combined
/// `If-Modified-Since` is a list of dates the recipient must ignore. **What that
/// costs is the cross-section count, for four of the five.** This rule counts
/// headers plus trailers, and so does `content_type_valid`; `etag_syntax`,
/// `retry_after_date_or_delay` and `conditional_headers_consistent` count header
/// lines only, so one line of those four in each section no longer draws this
/// entry — `trailer_fields_valid` reports the trailer line itself, and § 6.5.1
/// forbids them there outright, which is why the cost is worth the single
/// report.
///
/// Three productions here are too short to quote: `Date = HTTP-date`,
/// `Age = delta-seconds` and `Expires = HTTP-date` all fall under the
/// extractor's floor, stand alone between two paragraphs in their own sections,
/// *and* are separated from their neighbours by blank lines in the collected
/// grammars — the `From = mailbox` shape, where the drag-a-neighbour trick
/// fails too. Each is carried by its section's definitional prose instead, and
/// `Age` by the sentence that says the word *singleton* outright.
//
// cite(RFC 9110 § 10.2.4): "Server = product *( RWS ( product / comment ) )"
// cite(RFC 9110 § 10.1.5): "User-Agent = product *( RWS ( product / comment ) )"
// cite(RFC 9110 § 6.6.1): "The "Date" header field represents the date and time at which the message was originated, having the same semantics as the Origination Date Field (orig-date) defined in Section 3.6.1 of [RFC5322]."
// cite(RFC 9110 § 8.8.2): "The "Last-Modified" header field in a response provides a timestamp indicating the date and time at which the origin server believes the selected representation was last modified"
// cite(RFC 9110 § 14.4): "Content-Range = range-unit SP ( range-resp / unsatisfied-range )"
// cite(RFC 9110 § 14.2): "Range = ranges-specifier"
// cite(RFC 9110 § 13.1.5): "If-Range = entity-tag / HTTP-date"
// cite(RFC 9110 § 11.6.2): "Authorization = credentials"
// cite(RFC 9110 § 11.7.2): "Proxy-Authorization = credentials"
// cite(RFC 9111 § 5.1): "The "Age" response header field conveys the sender's estimate of the time since the response was generated or successfully validated at the origin server."
// cite(RFC 9111 § 5.1): "Although it is defined as a singleton header field, a cache encountering a message with a list-based Age field value SHOULD use the first member of the field value, discarding subsequent ones."
// cite(RFC 9111 § 5.3): "The "Expires" response header field gives the date/time after which the response is considered stale."
const SINGLETON_FIELDS: &[(&str, &str, Split)] = &[
    (
        "server",
        "`Server = product *( RWS ( product / comment ) )` (RFC 9110 §10.2.4)",
        Split::Forbidden,
    ),
    (
        "user-agent",
        "`User-Agent = product *( RWS ( product / comment ) )` (RFC 9110 §10.1.5)",
        Split::Forbidden,
    ),
    (
        "date",
        "`Date = HTTP-date` (RFC 9110 §6.6.1)",
        Split::Forbidden,
    ),
    (
        "last-modified",
        "`Last-Modified = HTTP-date` (RFC 9110 §8.8.2)",
        Split::Forbidden,
    ),
    (
        "content-range",
        "`Content-Range = range-unit SP ( range-resp / unsatisfied-range )` (RFC 9110 §14.4)",
        Split::Forbidden,
    ),
    (
        "range",
        "`Range = ranges-specifier` (RFC 9110 §14.2)",
        Split::Forbidden,
    ),
    (
        "if-range",
        "`If-Range = entity-tag / HTTP-date` (RFC 9110 §13.1.5)",
        Split::Forbidden,
    ),
    (
        "authorization",
        "`Authorization = credentials` (RFC 9110 §11.6.2)",
        Split::Forbidden,
    ),
    (
        "proxy-authorization",
        "`Proxy-Authorization = credentials` (RFC 9110 §11.7.2)",
        Split::Forbidden,
    ),
    (
        "age",
        "`Age = delta-seconds` (RFC 9111 §5.1)",
        Split::Forbidden,
    ),
    (
        "expires",
        "`Expires = HTTP-date` (RFC 9111 §5.3)",
        Split::Forbidden,
    ),
    (
        "cookie",
        "`Cookie = cookie-string` where `cookie-string = cookie-pair *( \";\" SP cookie-pair )` \
         (RFC 6265 §4.2.1)",
        Split::PermittedOverHttp2And3,
    ),
];

/// Whether a version's own document restores the split this rule reports.
///
/// **Eleven of the twelve rows can only be [`Forbidden`](Self::Forbidden)**,
/// and that is not an accident of which fields have been read: § 5.3's
/// exception turns on the field's *definition*, and no version rewrites a
/// definition. A protocol document that wanted the split back would have to
/// say so about the field by name, and for one field two of them do.
///
/// **`Cookie` is that field, and the licence is not a curiosity.** Its pairs
/// are delimited by a semicolon, so § 5.2's comma cannot recombine them — which
/// RFC 9113 § 8.2.3 states as the reason the field is stuck on one line, in the
/// paragraph before it hands HPACK the exception. Splitting a cookie across
/// field lines is what a compressing sender *should* do, and the concatenation
/// both documents then require is what makes the two spellings the same value.
/// A reading of this field that does not read the version is wrong in one
/// direction or the other: it either reports every HTTP/2 browser request that
/// carries more than one cookie, or it reports no split at all.
///
// cite(RFC 9113 § 8.2.3): "This header field contains multiple values, but does not use a COMMA (",") as a separator, thereby preventing cookie-pairs from being sent on multiple field lines (see Section 5.2 of [HTTP])."
// cite(RFC 9113 § 8.2.3): "To allow for better compression efficiency, the Cookie header field MAY be split into separate header fields, each with one or more cookie-pairs."
// cite(RFC 9114 § 4.2.1): "To allow for better compression efficiency, the Cookie header field ([COOKIES]) MAY be split into separate field lines, each with one or more cookie-pairs, before compression."
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Split {
    /// No document restores it, which is every row but one.
    Forbidden,
    /// RFC 9113 § 8.2.3 and RFC 9114 § 4.2.1 permit it for compression, and
    /// require the lines rejoined with `"; "` before the message is passed
    /// anywhere else.
    PermittedOverHttp2And3,
}

impl Split {
    /// Whether the version *this field section* arrived on restores the split.
    ///
    /// Per section rather than per transaction, for the reason
    /// `no_connection_specific_fields` states at greater length: a proxy may
    /// have received the request over one version and the response over
    /// another, so the request's version decides nothing about the response's
    /// field lines. A value naming no messaging syntax restores nothing —
    /// that is `http_version_syntax`'s finding, not this rule's.
    ///
    // cite(RFC 9110 § 2.5): "The first digit (major version) indicates the messaging syntax"
    fn permitted_on(self, version: &str) -> bool {
        match self {
            Self::Forbidden => false,
            Self::PermittedOverHttp2And3 => {
                matches!(crate::http_version::major(version), Some(2 | 3))
            }
        }
    }

    /// What a finding adds when the version was the half that decided it.
    ///
    /// Written on every finding about such a field rather than only where a
    /// reader might doubt it, because the operator's repair is in it: the
    /// delimiter to join the pairs with is the one the exception's own
    /// documents rejoin them with, and an operator told only that the field is
    /// a singleton would reach for § 5.2's comma, which is the octet that
    /// cannot appear here.
    ///
    // cite(RFC 6265 § 5.4): "When the user agent generates an HTTP request, the user agent MUST NOT attach more than one Cookie header field."
    fn caveat(self) -> &'static str {
        match self {
            Self::Forbidden => "",
            Self::PermittedOverHttp2And3 => {
                ". RFC 6265 §5.4 says it of this field in its own words — a user agent must not \
                 attach more than one Cookie header field — and the split RFC 9113 §8.2.3 and \
                 RFC 9114 §4.2.1 permit for compression belongs to HTTP/2 and HTTP/3 alone: on \
                 this version the pairs belong on one line, joined by the '; ' those documents \
                 rejoin them with"
            }
        }
    }
}

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9110_5_5: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("5.5"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.5",
    note: "Field Values: what a singleton field is, and the sentence saying that \
           detecting an erroneously repeated one improves interoperability",
};
const RFC_9110_5_6_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("5.6.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1",
    note: "Lists: the `#rule` extension — the shape a field's definition has when \
           §5.3's exception applies to it, and the shape none of the eleven \
           grammars in this rule's table has",
};
/// The prohibition stated for `Cookie` in its own document, addressed to the
/// user agent that writes the field.
const RFC_6265_5_4: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 6265",
    section: Some("5.4"),
    url: "https://www.rfc-editor.org/rfc/rfc6265.html#section-5.4",
    note: "The Cookie Header — a user agent MUST NOT attach more than one Cookie \
           header field to a request it generates",
};
/// HTTP/2's licence to split that field anyway, and the paragraph before it
/// saying why the field is otherwise stuck on one line.
const RFC_9113_8_2_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9113",
    section: Some("8.2.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9113.html#section-8.2.3",
    note: "Compressing the Cookie Header Field — the semicolon that keeps §5.2 from \
           recombining the field, and the compression exception that permits the split \
           anyway, rejoined with \"; \"",
};
/// The same licence in HTTP/3's own words, which is why this is two references
/// and not one.
const RFC_9114_4_2_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9114",
    section: Some("4.2.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9114.html#section-4.2.1",
    note: "Field Compression — HTTP/3's statement of the same exception, before \
           compression rather than after it",
};
const RFC_9111_5_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9111",
    section: Some("5.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-5.1",
    note: "Age — defined as a singleton header field in as many words, with the \
           recipient's first-member recovery beside it, which is a recipient's \
           SHOULD and not a sender's licence",
};

impl RuleMeta for SingletonFieldsNotRepeated {
    fn id(&self) -> &'static str {
        "singleton_fields_not_repeated"
    }

    fn config_example(&self) -> &'static str {
        r#"# RFC 9110 §5.3's MUST NOT is unconditional, so the shipped severity is error:
# a second field line of a singleton is a defect of the message however a
# recipient recovers from it.
enabled = true
"#
    }

    fn description(&self) -> &'static str {
        "Reports a message writing more than one field line of a singleton field. RFC 9110 §5.3: \
         a sender MUST NOT generate multiple field lines with the same name in a message — \
         *whether in the headers or trailers* — unless at least one alternative of the field's \
         definition allows a comma-separated list, and no definition of the twelve fields this \
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
         never assumed to be a singleton. The twelve are: `Server`, `User-Agent`, `Date`, \
         `Last-Modified`, `Content-Range`, `Range`, `If-Range`, `Authorization`, \
         `Proxy-Authorization`, `Age`, `Expires` and `Cookie` — for `Age`, RFC 9111 §5.1 says \
         the word *singleton* outright, and for `Cookie` RFC 6265 §5.4 states the prohibition \
         in as many words.\
         \n\n\
         **`Cookie` is the one row a protocol version can excuse, and it is excused on two of \
         them.** RFC 6265 §4.2.1 delimits `cookie-pair`s with a semicolon, so §5.2's comma \
         cannot recombine the lines — RFC 9113 §8.2.3 says exactly that — and RFC 9113 §8.2.3 \
         and RFC 9114 §4.2.1 then permit the split anyway, for compression, requiring the lines \
         rejoined with `\"; \"` before the message is passed anywhere else. So a `Cookie` on \
         several field lines is a defect over HTTP/1.1 and the recommended spelling over HTTP/2 \
         and HTTP/3, and this rule reads the version **the field section itself arrived on** — \
         a request received over one version and a response sent over another are judged \
         separately. No other field in the table has such an exception, and both documents \
         grant it by name.\
         \n\n\
         **Thirteen singleton fields are deliberately not here**, because their repetition is \
         already reported where their values are read, with the joined value in the finding: \
         `Referer`, `Content-Location`, `Location`, `Max-Forwards`, `From`, \
         `Content-Disposition`, `Content-Type`, `ETag` and `Retry-After` each carry the check \
         in their own rule, `If-Modified-Since` and `If-Unmodified-Since` in \
         `conditional_headers_consistent`, `Host` in \
         `host_header` (where RFC 9112 §3.2 adds the recipient's 400), and \
         `Content-Length` in the body-length rules — RFC 9110 §8.6 gives that field its own \
         arithmetic for duplicate values, which is a different question from this rule's. \
         The last five moved out of the table rather than being kept out of it: they were in \
         both places, so one repetition drew this entry twice, and the rule reading the value \
         is the one that can say what the repetition costs the recipient.\
         \n\n\
         **What a recipient does with the repetition is each field's own hazard**, and this \
         rule does not guess at it: the finding names the field's grammar and §5.3, not a \
         reconstruction of what any particular recipient would read. §5.2's recombination is \
         defined within a section, and for none of these fields does the recombined value \
         derive from the field's grammar."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_9110_5_3,
            RFC_9110_5_5,
            RFC_9110_5_6_1,
            RFC_9111_5_1,
            RFC_6265_5_4,
            RFC_9113_8_2_3,
            RFC_9114_4_2_1,
        ]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    /// **Two field lines of a singleton field are two lines one sender wrote**,
    /// and the count is taken per message — the request's two sections together,
    /// then the response's. The party travels with the judgement, since the one
    /// reporting site cannot tell afterwards which call answered.
    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::PerSite
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
                label: Some("(two Age field lines — RFC 9111 §5.1 calls the field a singleton)"),
                snippet: "HTTP/1.1 200 OK\nAge: 60\nAge: 120",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some(
                    "(two Cookie field lines over HTTP/1.1 — the pairs belong on one line, \
                     joined with `; `)",
                ),
                snippet: "GET / HTTP/1.1\nHost: example.com\nCookie: a=1\nCookie: b=2",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some(
                    "(the same two lines over HTTP/2 — RFC 9113 §8.2.3 splits Cookie for \
                     compression, and RFC 9114 §4.2.1 says the same of HTTP/3)",
                ),
                snippet: "GET / HTTP/2.0\nHost: example.com\nCookie: a=1\nCookie: b=2",
            },
        ]
    }
}

impl Rule for SingletonFieldsNotRepeated {
    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // One finding per section. A singleton the client repeated and one the
        // origin repeated are two senders each breaking the same requirement,
        // and the repair is in a different message for each.
        let mut out = Vec::new();
        if let Some(message) = judge(
            &tx.request.headers,
            tx.request.trailers.as_ref(),
            "Request",
            &tx.request.version,
        ) {
            out.push(ctx.by_client().report_with(&FIELD_LINE_DUPLICATED, message));
        }
        if let Some(resp) = &tx.response {
            if let Some(message) = judge(
                &resp.headers,
                resp.trailers.as_ref(),
                "Response",
                &resp.version,
            ) {
                out.push(ctx.by_server().report_with(&FIELD_LINE_DUPLICATED, message));
            }
        }
        out
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
    version: &str,
) -> Option<String> {
    for (name, grammar, split) in SINGLETON_FIELDS {
        // The version is read before the lines are counted, because for the one
        // row it can answer, a permitted split is not a defect a recipient
        // recovers from — it is the spelling the sender was asked for.
        if split.permitted_on(version) {
            continue;
        }
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
            let caveat = split.caveat();
            return Some(format!(
                "{side} writes {lines} field lines of '{name}'{where_written}; the field is a \
                 singleton — {grammar} has no comma-separated-list alternative — so a sender \
                 must not generate more than one in a message, whether in the headers or \
                 trailers (RFC 9110 §5.3){caveat}"
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

    /// Two `Cookie` field lines, and the version is the whole verdict.
    ///
    /// RFC 9113 § 8.2.3 and RFC 9114 § 4.2.1 permit the split for compression;
    /// no other version does, and RFC 6265 § 5.4 forbids it in as many words.
    /// **Both directions are asserted from one value**, because a reading that
    /// gets either half alone is the shape this case exists to refuse: silent
    /// everywhere is a false negative on every HTTP/1.1 sender, and loud
    /// everywhere reports the ordinary spelling of a cookie in a browser's
    /// HTTP/2 request.
    #[rstest]
    #[case("HTTP/1.1", true)]
    #[case("HTTP/1.0", true)]
    #[case("HTTP/2.0", false)]
    #[case("HTTP/3.0", false)]
    // A version naming no messaging syntax restores nothing: what it is, is
    // `http_version_syntax`'s finding, and it is not a licence here.
    #[case("nonsense", true)]
    fn a_split_cookie_is_read_against_the_version_that_carried_it(
        #[case] version: &str,
        #[case] reported: bool,
    ) {
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut headers = hyper::HeaderMap::new();
        headers.append("cookie", HeaderValue::from_static("a=1"));
        headers.append("cookie", HeaderValue::from_static("b=2"));
        tx.request.headers = headers;
        tx.request.version = version.to_string();
        assert_eq!(run(&tx).is_some(), reported, "{version}");
    }

    /// The exact sentence, once: the operator is told the delimiter to join the
    /// pairs with, and told that the two versions which permit the split are
    /// not this one.
    #[test]
    fn a_split_cookie_names_the_delimiter_that_rejoins_it() {
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut headers = hyper::HeaderMap::new();
        headers.append("cookie", HeaderValue::from_static("a=1"));
        headers.append("cookie", HeaderValue::from_static("b=2"));
        tx.request.headers = headers;
        assert_eq!(
            run(&tx).expect("reported"),
            "Request writes 2 field lines of 'cookie'; the field is a singleton — `Cookie = \
             cookie-string` where `cookie-string = cookie-pair *( \";\" SP cookie-pair )` (RFC \
             6265 §4.2.1) has no comma-separated-list alternative — so a sender must not \
             generate more than one in a message, whether in the headers or trailers (RFC 9110 \
             §5.3). RFC 6265 §5.4 says it of this field in its own words — a user agent must \
             not attach more than one Cookie header field — and the split RFC 9113 §8.2.3 and \
             RFC 9114 §4.2.1 permit for compression belongs to HTTP/2 and HTTP/3 alone: on this \
             version the pairs belong on one line, joined by the '; ' those documents rejoin \
             them with"
        );
    }

    /// The licence is the field section's own, not the transaction's.
    ///
    /// A proxy may receive a request over HTTP/2 and send its response over
    /// HTTP/1.1 — the corpus this was found in carries exactly that record — so
    /// reading both halves against one version excuses a section no document
    /// excused. Here the request's split is permitted and the response's is
    /// not, and the finding that comes back is the response's.
    #[test]
    fn each_field_section_is_judged_by_the_version_it_arrived_on() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut request_headers = hyper::HeaderMap::new();
        request_headers.append("cookie", HeaderValue::from_static("a=1"));
        request_headers.append("cookie", HeaderValue::from_static("b=2"));
        tx.request.headers = request_headers;
        tx.request.version = "HTTP/2.0".to_string();

        let response = tx.response.as_mut().expect("a response");
        response.version = "HTTP/1.1".to_string();
        response
            .headers
            .append("cookie", HeaderValue::from_static("a=1"));
        response
            .headers
            .append("cookie", HeaderValue::from_static("b=2"));

        let message = run(&tx).expect("the response's split is reported");
        assert!(
            message.starts_with("Response writes 2 field lines of 'cookie'"),
            "{message}"
        );
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
    #[case("content-range", "bytes 0-1/2")]
    #[case("range", "bytes=0-1")]
    #[case("if-range", "\"x\"")]
    #[case("authorization", "Basic dGVzdA==")]
    #[case("proxy-authorization", "Basic dGVzdA==")]
    #[case("age", "60")]
    #[case("expires", "Tue, 15 Nov 1994 08:12:31 GMT")]
    // The twelfth row, on the version its two documents do not excuse. The
    // helpers build HTTP/1.1 messages, which is what makes this an ordinary row
    // here and what the version cases below say out loud.
    #[case("cookie", "a=1")]
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
        let mut tx = response_with_lines(&[("age", "60")]);
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("age", HeaderValue::from_static("120"));
        tx.response.as_mut().expect("a response").trailers = Some(trailers);

        let msg = run(&tx).expect("reported");
        assert!(
            msg.contains("2 field lines of 'age' across the header and trailer sections"),
            "{msg}"
        );

        // Two lines wholly inside the trailer section say that instead.
        let mut tx = response_with_lines(&[]);
        let mut trailers = hyper::HeaderMap::new();
        trailers.append("age", HeaderValue::from_static("60"));
        trailers.append("age", HeaderValue::from_static("120"));
        tx.response.as_mut().expect("a response").trailers = Some(trailers);
        let msg = run(&tx).expect("reported");
        assert!(
            msg.contains("2 field lines of 'age' in the trailer section"),
            "{msg}"
        );
    }

    /// What leaving the table costs, said as a test rather than left to the
    /// comment above it. The five fields' own rules count header lines only, so
    /// one line in each section is a repetition this rule used to report and no
    /// rule reports now. `trailer_fields_valid` answers for the trailer line
    /// being there at all, which is why the cost is bounded — but it is a cost,
    /// and a reading that gives one of those rules the trailer section back
    /// should change this row rather than discover it.
    #[test]
    fn a_field_that_left_the_table_is_not_counted_across_sections_here() {
        let mut tx = response_with_lines(&[("etag", "\"a\"")]);
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("etag", HeaderValue::from_static("\"b\""));
        tx.response.as_mut().expect("a response").trailers = Some(trailers);
        assert_eq!(run(&tx), None);
    }

    /// The thirteen fields whose repetition another rule reports are absent
    /// from the table on purpose — two lines of them draw nothing *here*.
    ///
    /// The last five are the ones that were in both places: each drew
    /// `field_line_duplicated` from its own rule *and* from this one, so the
    /// message carried it twice. This is the row that holds them out.
    #[rstest]
    #[case("referer", "/a")]
    #[case("content-location", "/a")]
    #[case("location", "/a")]
    #[case("max-forwards", "3")]
    #[case("from", "a@example.com")]
    #[case("content-disposition", "attachment")]
    #[case("host", "example.com")]
    #[case("content-length", "3")]
    #[case("content-type", "text/plain")]
    #[case("etag", "\"x\"")]
    #[case("retry-after", "120")]
    #[case("if-modified-since", "Tue, 15 Nov 1994 08:12:31 GMT")]
    #[case("if-unmodified-since", "Tue, 15 Nov 1994 08:12:31 GMT")]
    fn fields_owned_by_other_rules_draw_nothing_here(#[case] name: &str, #[case] value: &str) {
        let tx = response_with_lines(&[(name, value), (name, value)]);
        assert_eq!(run(&tx), None, "{name}");
    }

    #[test]
    fn needs_no_response() {
        assert!(!SingletonFieldsNotRepeated.needs_response());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "singleton_fields_not_repeated");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
