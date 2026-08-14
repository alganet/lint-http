// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::helpers::headers::{
    combined_field_value_as_written, describe_char, quoted_string_end, quoting_is_balanced,
    response_field_sections, shown_in_finding, split_commas_respecting_quotes,
    split_semicolons_respecting_quotes, trim_ows, unescape_quoted_string,
};
use crate::helpers::token::find_invalid_token_char;
use crate::lint::Violation;
use crate::rules::Rule;
use std::borrow::Cow;

/// The two `server-timing-param-name`s this specification establishes, spelled
/// as the two getters that read them spell their lookups.
///
/// Standing modal-subject step, run over the whole document: nine BCP 14
/// keywords, seven of them addressed to the user agent, one a MAY permitting a
/// response to repeat a metric name, and one -- § 2's SHOULD NOT on a repeated
/// parameter name -- the only sentence measuring what a server wrote. Which is
/// why every grammar finding in this file rests on RFC 9110 § 2.2 instead.
///
/// The spelling is the whole content of the constant. `params` is an ordered map
/// keyed by the name as the sender wrote it, and § 3.2 and § 3.3 index it with
/// these exact strings -- so `DUR` is not `dur` to the attribute that would have
/// surfaced it. Everything else about a name a user agent does not recognise is
/// settled one paragraph above: it is ignored, without error.
// cite(Server Timing § 2): "This specification establishes the server-timing-params for server-timing-param-names "dur" for duration and "desc" for description, both optional."
// cite(Server Timing § 2): "A user agent that does not recognize particular server-timing-param-name in the Server-Timing header field of a response MUST ignore those tokens and continue processing instead of signaling an error."
const ESTABLISHED_PARAM_NAMES: [&str; 2] = ["dur", "desc"];

/// Whether `s` is HTML's *valid floating-point number*, which is the production
/// `dur` is measured against and is not `f64::from_str`.
///
/// The two disagree in both directions, and each disagreement is a finding the
/// old check got backwards. Rust accepts `inf`, `infinity` and `NaN` in any
/// case, which the sentence below excludes by name; it accepts a leading `+`,
/// which appears nowhere in the production and which the parsing algorithm calls
/// non-conforming while ignoring it; and it refuses `53abc`, which is indeed not
/// a valid floating-point number but which the parsing algorithm reads as 53
/// rather than as an error -- so a finding phrased *"is not a number"* was
/// wrong about what the recipient does with it.
///
/// This is the authoring half of a pair HTML keeps deliberately apart: the
/// *valid floating-point number* is what a conforming author writes, and the
/// *rules for parsing floating-point number values* are what a user agent runs
/// over whatever arrived. A rule measuring a sender wants the first. Written
/// privately because it has one caller and there is no HTML-microsyntax reader
/// anywhere in `helpers/`; the shared answer moves there on the second. The
/// campaign's only other WHATWG microsyntax is
/// `message_refresh_header_syntax_valid`'s *valid non-negative integer*, and it
/// is an inline `chars().all(is_ascii_digit)` rather than a function -- one
/// production is not a subroutine of the other, and a shared module holding the
/// two of them would be filed by which document they came from rather than by
/// what they do.
// cite(HTML Common Microsyntaxes § 2.3.4.3): "A string is a valid floating-point number if it consists of:"
// cite(HTML Common Microsyntaxes § 2.3.4.3): "The Infinity and Not-a-Number (NaN) values are not valid floating-point numbers."
// cite(HTML Common Microsyntaxes § 2.3.4.3): "The valid floating-point number concept is typically only used to restrict what is allowed for authors, while the user agent requirements use the rules for parsing floating-point number values below"
fn is_valid_floating_point_number(s: &str) -> bool {
    let b = s.as_bytes();
    let mut i = 0usize;

    // "Optionally, a U+002D HYPHEN-MINUS character (-)." -- and only that one.
    // A U+002B PLUS SIGN is not part of the production; the parsing algorithm
    // below says in a parenthesis that it is ignored and not conforming, which
    // is the same answer said twice.
    // cite(HTML Common Microsyntaxes § 2.3.4.3): "Advance position to the next character. (The "+" is ignored, but it is not conforming.)"
    if b.first() == Some(&b'-') {
        i += 1;
    }

    let digits = |i: &mut usize| {
        let start = *i;
        while b.get(*i).is_some_and(u8::is_ascii_digit) {
            *i += 1;
        }
        *i > start
    };

    // "One or both of the following, in the given order: A series of one or more
    // ASCII digits. / Both of the following, in the given order: A single U+002E
    // FULL STOP character (.). A series of one or more ASCII digits." -- so
    // `5`, `.5` and `5.5` derive and `5.` does not, the FULL STOP being
    // available only as the first half of a pair.
    let integral = digits(&mut i);
    let mut fractional = false;
    if b.get(i) == Some(&b'.') {
        i += 1;
        fractional = digits(&mut i);
        if !fractional {
            return false;
        }
    }
    if !integral && !fractional {
        return false;
    }

    // "Optionally: Either a U+0065 LATIN SMALL LETTER E character (e) or a
    // U+0045 LATIN CAPITAL LETTER E character (E). Optionally, a U+002D
    // HYPHEN-MINUS character (-) or U+002B PLUS SIGN character (+). A series of
    // one or more ASCII digits." The PLUS SIGN is in the production here and
    // nowhere else, which is why the two sign branches above and below are not
    // the same branch.
    if matches!(b.get(i), Some(b'e' | b'E')) {
        i += 1;
        if matches!(b.get(i), Some(b'-' | b'+')) {
            i += 1;
        }
        if !digits(&mut i) {
            return false;
        }
    }

    // The production is the whole string. The *parsing* algorithm stops at the
    // first character that is not part of a number and returns what it has; the
    // conformance definition has no such step, and this function is the
    // conformance definition.
    i == b.len()
}

/// `Server-Timing` carries the server's own account of the request-response
/// cycle, and this rule asks whether the account is written in the grammar
/// § 2 prints.
pub struct ServerServerTimingHeaderSyntax;

impl Rule for ServerServerTimingHeaderSyntax {
    fn id(&self) -> &'static str {
        "server_server_timing_header_syntax"
    }

    /// The field is a response field, and every finding here is about what a
    /// server wrote. RFC 9110 § 3.7 is why a capture of a gateway's answer is
    /// measured by the same sentences.
    // cite(Server Timing § 2): "The Server-Timing header field is used to communicate one or more metrics and descriptions for the given request-response cycle."
    // cite(RFC 9110 § 3.7): "All HTTP requirements applicable to an origin server also apply to the outbound communication of a gateway."
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
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;

        // Both field sections, because the specification's own worked exchange
        // uses both: § 6 announces `Trailer: Server-Timing` and then writes
        // `Server-Timing: total;dur=123.4` after the content. Reading the header
        // section alone left the last line of the only example this document
        // publishes measured by nobody.
        //
        // Whether the field belongs in a trailer section at all is a different
        // question and not this rule's: RFC 9110 § 6.5.1 asks the sender to know
        // its own field's definition, § 6 here is marked non-normative, and
        // `message_trailer_fields_validity` owns that question and declines it
        // by name for every field whose definition this tree does not hold.
        // What is asked here is the same thing of both sections -- that what the
        // server wrote derives from § 2's grammar. The walk is the shared one;
        // the permission is what differs per field, and this rule's is the one
        // it does not have.
        //
        // cite(RFC 9110 § 6.5.1): "A sender MUST NOT generate a trailer field unless the sender knows the corresponding header field name's definition permits the field to be sent in trailers."
        for (section, headers) in response_field_sections(resp) {
            // One `char` per octet, and the lines of this section joined into
            // the one list they are. `to_str` folds a field carrying any octet
            // at or above %x80 into "no such field here" -- and `qdtext` admits
            // `obs-text`, so the old reader turned a conforming `desc` into a
            // finding that named UTF-8, a property of the reader rather than of
            // the grammar. Where such an octet is genuinely inadmissible it is
            // inside a `token`, and the finding that owns it names the octet.
            //
            // cite(RFC 9110 § 5.3): "A recipient MAY combine multiple field lines within a field section that have the same field name into one field line, without changing the semantics of the message, by appending each subsequent field line value to the initial field line value in order, separated by a comma (",") and optional whitespace (OWS, defined in Section 5.6.3)."
            // cite(RFC 9110 § 5.5): "A recipient SHOULD treat other allowed octets in field content (i.e., obs-text) as opaque data."
            let Some(value) = combined_field_value_as_written(headers, "server-timing") else {
                continue;
            };
            // The section names itself at the front of the sentence rather than
            // in a parenthesis at the back: several of these findings already
            // end in an `(advice: …)` clause, and a second parenthetical after
            // it reads as an afterthought about the first.
            if let Some(message) = check_field_value(&value) {
                return Some(self.violation(
                    config.severity,
                    format!("In the response {section}: {message}"),
                ));
            }
        }

        None
    }

    fn title(&self) -> Option<&'static str> {
        Some("Server Server-Timing Header Syntax")
    }

    fn description(&self) -> &'static str {
        "Checks that a `Server-Timing` response field derives from the grammar the Server Timing specification prints in § 2: `Server-Timing = #server-timing-metric`, each metric a `metric-name` (a `token`) followed by `*( OWS \";\" OWS server-timing-param )`, each parameter a `token` name, an `=` with `OWS` either side, and a value that is a `token` or a `quoted-string`.\n\n**The requirement is RFC 9110 § 2.2's, not this document's.** The Server Timing specification holds nine BCP 14 keywords. Seven are addressed to the *user agent*: it MUST process and expose repeated metric names, it MAY surface them in any order, it MUST ignore a parameter name it does not recognise, it MUST ignore every occurrence of a repeated parameter after the first, it MUST ignore extraneous characters in two named places — all without signalling an error — and § 4 lets it MAY keep the same-origin restriction anyway. The eighth is a MAY permitting a response to repeat a metric name. Exactly one measures what a server wrote, and it is the SHOULD NOT below. So a rule that reports a server has to reach out of the document for its modal, and \"A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules\" is it. A recipient being told to tolerate something is not the sender being told it may write it.\n\n**A `quoted-string` may hold a comma and a semicolon, and both are separators here.** `Server-Timing: cache;desc=\"Cache Read, DB\"` is one metric with one parameter. This rule splits both levels quote-aware; the value used to be split on bare `,` and `;`, which reported that field for an unterminated `quoted-string` it does not have.\n\n**The one sentence the document does address to the field's content is reported.** \"To avoid any possible ambiguity, individual server-timing-param-names SHOULD NOT appear multiple times within a server-timing-metric.\" A repeated parameter name is a finding, and it is the only advice-shaped one that comes from this document rather than from the grammar. The rule used to implement the user agent's *ignore the rest* MUST as its own silence, which made the SHOULD NOT the one thing in the document nothing enforced.\n\n**Both field sections are read.** The specification's only worked exchange announces `Trailer: Server-Timing` and writes a fourth metric after the content. The lines of one section are joined into one list, in order; the two sections are not joined to each other. Whether the field may sit in a trailer section at all is RFC 9110 § 6.5.1's question and `message_trailer_fields_validity`'s to ask.\n\n**`dur` is measured against HTML's *valid floating-point number*, and the finding is advice.** No sentence anywhere requires `dur` to be a number: § 3.2 parses it with HTML's rules for parsing floating-point number values and returns 0 if that is an error, which is a consequence and not a violation. The production is not `f64::from_str` either — that one accepts `inf`, `NaN` and a leading `+`, none of which HTML admits, and refuses `53abc`, which HTML's parser reads as 53. The rule's own doc comment used to state a SHOULD that appears in no document.\n\n**A parameter name that is `dur` or `desc` in another case is reported as advice.** § 3.2 reads `params[\"dur\"]` and § 3.3 reads `params[\"desc\"]` — an ordered map keyed by the name as written — so `db;DUR=53` surfaces a duration of 0 and `db;DESC=x` an empty description. Nothing forbids the name; it is simply a parameter no user agent will recognise, which the document says is to be ignored without error.\n\n**What is not reported.** An empty field value: `#server-timing-metric` has no floor, so `Server-Timing:` is zero metrics rather than an empty one — an empty *element* between commas is reported, on § 5.6.1.1's sender MUST NOT. Repeated `metric-name`s across metrics: § 2 grants a response a MAY to send them and requires the user agent to expose all of them. The order of metrics: the user agent MAY surface them in any order. An unregistered parameter name, which the document establishes exactly two of and tells recipients to ignore the rest of. And whether the numbers are true, which no capture can answer."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "Server Timing",
                section: Some("2"),
                url: "https://www.w3.org/TR/server-timing/#the-server-timing-header-field",
                note: "The `Server-Timing` Header Field: the ABNF this rule enforces, the two parameter names the specification establishes, and the user-agent parsing algorithm. Eight BCP 14 keywords: six addressed to the user agent, a MAY permitting a response to repeat a metric name, and a SHOULD NOT on a parameter name appearing twice in one metric — that last one is the only sentence in the whole document that measures what a server wrote. The section takes `#`, `*`, `OWS`, `token` and `quoted-string` from `[RFC7230]`, which is obsolete; the current productions are RFC 9110 § 5.6.1, § 5.6.3, § 5.6.2 and § 5.6.4 and are carried forward unchanged, so nothing this rule decides turns on which document is read. The document is a W3C Working Draft (7 April 2026) whose own Status section says \"It is inappropriate to cite this document as other than a work in progress\" — and it is nonetheless the field's only specification: the IANA HTTP Field Name Registry lists `Server-Timing` as **permanent** with this document as its sole reference, the same way it lists `Keep-Alive` against an obsoleted RFC. A work in progress is what there is to read",
            },
            crate::rules::SpecRef {
                spec: "Server Timing",
                section: Some("3.2"),
                url: "https://www.w3.org/TR/server-timing/#dom-performanceservertiming-duration",
                note: "The `duration` attribute: `params[\"dur\"]` parsed with HTML's rules for parsing floating-point number values, returning 0 on error. This is what a non-numeric `dur` costs, and it is a consequence rather than a requirement — the lookup is by the exact string, which is why a differently-cased name surfaces nothing",
            },
            crate::rules::SpecRef {
                spec: "Server Timing",
                section: Some("3.3"),
                url: "https://www.w3.org/TR/server-timing/#dom-performanceservertiming-description",
                note: "The `description` attribute: `params[\"desc\"]` if it exists, otherwise the empty string. The same exact-string lookup as § 3.2's",
            },
            crate::rules::SpecRef {
                spec: "IANA HTTP Field Name Registry",
                section: None,
                url: "https://www.iana.org/assignments/http-fields/http-fields.xhtml",
                note: "Where the claim above is checkable: `Server-Timing` is listed `permanent`, with the W3C Working Draft as its only reference. No branch of this rule consults the registry — the field's grammar comes from the document, not from an entry — but the footing does, and an operator asked to trust a work in progress should be able to see that IANA does",
            },
            crate::rules::SpecRef {
                spec: "HTML Common Microsyntaxes",
                section: Some("2.3.4.3"),
                url: "https://html.spec.whatwg.org/multipage/common-microsyntaxes.html#floating-point-numbers",
                note: "Floating-point numbers: the *valid floating-point number* production a conforming author writes, kept deliberately apart from the *rules for parsing floating-point number values* a user agent runs. `dur` is measured against the first. Neither is `f64::from_str`, which admits Infinity, NaN and a leading `+`",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("2.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-2.2",
                note: "Conformance and Error Handling: \"A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules.\" The Server Timing specification states no requirement on a server, so every grammar finding here rests on this sentence",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("5.6.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1",
                note: "Lists (#rule ABNF Extension): `#element => [ 1#element ]` is why an empty `Server-Timing` field value is zero metrics and not a defect, and § 5.6.1.1's \"a sender MUST NOT generate empty list elements\" is why a comma with nothing between it and the next one is",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("5.6.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.2",
                note: "Tokens: `metric-name` and both halves of a parameter's name are `token`, whose characters are all visible US-ASCII — so an `obs-text` octet in one of those positions is the defect, not the reader's inability to decode it",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("5.6.4"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.4",
                note: "Quoted Strings: the other alternative a `server-timing-param-value` may be. `qdtext` admits `obs-text`, which is why a `desc` carrying a high octet is conforming, and `quoted-pair` is why a DQUOTE inside one is not a terminator",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("6.5.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-6.5.1",
                note: "Limitations on Use of Trailers: the sentence that decides whether this field may sit in a trailer section at all. Not asked here — `message_trailer_fields_validity` owns it — but it is why the second section this rule reads is worth naming: the Server Timing specification puts the field there only in a section marked non-normative",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("The specification's own worked exchange, including the trailer line"),
                snippet: "Server-Timing: miss, db;dur=53, app;dur=47.2\nServer-Timing: customView, dc;desc=atl\nServer-Timing: cache;desc=\"Cache Read\";dur=23.2\nTrailer: Server-Timing\nServer-Timing: total;dur=123.4",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("A comma and a semicolon inside a quoted-string are data, not separators"),
                snippet: "Server-Timing: cache;desc=\"Cache Read, DB Write\", db;dur=.5e1",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("An empty field value is zero metrics, which the list production allows"),
                snippet: "Server-Timing:",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("Grammar: an empty list element, a metric-name that is not a token, a parameter with no value, and a value that is neither a token nor a quoted-string"),
                snippet: "Server-Timing: ,miss\nServer-Timing: b@d;dur=5\nServer-Timing: db;desc\nServer-Timing: db;desc=Cache Read\nServer-Timing: db;desc=\"abc\"x",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("Advice: a repeated parameter name, a `dur` that is not a valid floating-point number, and a name the getters will not find"),
                snippet: "Server-Timing: db;dur=50;dur=51\nServer-Timing: db;dur=NaN\nServer-Timing: db;dur=+5\nServer-Timing: db;DUR=53",
            },
        ]
    }
}

/// One field section's combined value, measured against `#server-timing-metric`.
fn check_field_value(value: &str) -> Option<String> {
    // Asked before anything is split, because a DQUOTE that never closes makes
    // every separator after it a guess: the splitters collapse the rest of the
    // value into one member, so a claim about how many metrics there are, or
    // about which of them is empty, would be a claim about a reading that never
    // happened. The `quoted-string` is the finding, and it is the honest one.
    //
    // cite(RFC 9110 § 5.6.4): "quoted-string  = DQUOTE *( qdtext / quoted-pair ) DQUOTE"
    if !quoting_is_balanced(value) {
        return Some(format!(
            "Server-Timing '{}' opens a quoted-string that never closes, so the rest of the value cannot be read as metrics: a server-timing-param-value that is a quoted-string is DQUOTE-delimited at both ends",
            shown_in_finding(value)
        ));
    }

    // `#element => [ 1#element ]`: the whole list is optional, so a field value
    // holding nothing is zero metrics rather than one empty metric. The
    // whitespace-only spelling is the same value, because excluding that
    // whitespace is a MUST on the parser rather than a choice.
    //
    // This branch is why the old rule reported `Server-Timing:` -- it split the
    // empty string on a comma, got one empty piece back, and called it a
    // trailing comma.
    //
    // cite(RFC 9110 § 5.6.1, label: hash rule expansion): "#element => [ 1#element ]"
    // cite(RFC 9110 § 5.5): "A field value does not include leading or trailing whitespace."
    if trim_ows(value).is_empty() {
        return None;
    }

    // cite(Server Timing, label: Server-Timing grammar): "Server-Timing = #server-timing-metric"
    // cite(Server Timing § 2): "See [RFC7230] for definitions of #, *, OWS, token, and quoted-string."
    for member in split_commas_respecting_quotes(value) {
        // The comma splitter is the one that does not trim, so the `OWS` the
        // list production prints around its separators comes off here -- and
        // `trim_ows` rather than `str::trim`, because this value carries one
        // `char` per octet and %xA0 in it is `obs-text` a sender wrote inside
        // the member.
        let metric = trim_ows(member);

        // A sender's empty list element, which is a different party's rule from
        // the recipient's *parse and ignore* and is why the shared list reader
        // cannot answer this: by the time it answers, the evidence is gone.
        //
        // cite(RFC 9110 § 5.6.1.1): "In any production that uses the list construct, a sender MUST NOT generate empty list elements."
        if metric.is_empty() {
            return Some(format!(
                "Server-Timing '{}' holds an empty list element, which no sender may generate: two commas with nothing between them, or a comma at either end of the value",
                shown_in_finding(value)
            ));
        }

        if let Some(message) = check_metric(metric) {
            return Some(message);
        }
    }

    None
}

/// One `server-timing-metric`.
// cite(Server Timing, label: server-timing-metric grammar): "server-timing-metric = metric-name *( OWS ";" OWS server-timing-param )"
// cite(Server Timing, label: metric-name grammar): "*( OWS ";" OWS server-timing-param ) metric-name = token"
fn check_metric(metric: &str) -> Option<String> {
    // Quote-aware, and the segments come back `OWS`-trimmed: the semicolon
    // splitter trims where the comma splitter does not. A bare `split(';')`
    // here cut `desc="a;b"` in half.
    let segments = split_semicolons_respecting_quotes(metric);
    // `split_first` rather than `first()` plus `&segments[1..]`: the invariant
    // that there is always a first segment is returned as data instead of
    // asserted in two places that could drift apart.
    let (name, params) = segments
        .split_first()
        .expect("the splitter yields at least one segment");

    // `token = 1*tchar` has a floor of one, so a metric that opens with its
    // first semicolon names nothing.
    // cite(RFC 9110 § 5.6.2): "token = 1*tchar tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA"
    if name.is_empty() {
        return Some(format!(
            "Server-Timing metric '{}' has an empty metric-name: `metric-name = token` and a token is one character or more",
            shown_in_finding(metric)
        ));
    }
    if let Some(c) = find_invalid_token_char(name) {
        return Some(format!(
            "Server-Timing metric-name '{}' holds {}, which no token admits: every character of a token is visible US-ASCII and not a delimiter",
            shown_in_finding(name),
            describe_char(c)
        ));
    }

    // The names seen so far in *this* metric, as written. The comparison is
    // exact because the sentence is about a name appearing twice, and the map a
    // user agent builds is keyed by the string -- `dur` and `DUR` are two names
    // to it, and the finding for the second of those is the case one below.
    let mut seen: Vec<&str> = Vec::new();

    for &param in params {
        if let Some(message) = check_param(metric, param, &mut seen) {
            return Some(message);
        }
    }

    None
}

/// One `server-timing-param`, and what the two established names mean for it.
///
/// **The third hand-written copy of `token <ws> "=" <ws> ( token /
/// quoted-string )`, and the divergence is recorded here because this is the
/// site that creates it.** `helpers::headers::parse_token_bws_word` owns
/// `token [ BWS "=" BWS word ]`; `server_alt_svc_header_syntax::check_parameter`
/// owns RFC 7838's `parameter = token "=" ( token / quoted-string )`; and this
/// one is that second production with `OWS` printed either side of the `=`.
/// The three differ on exactly the two axes `BWS` has been the tell for all
/// campaign: **whether the value is optional** (the helper's is, neither of the
/// other two is, so a bare `db;desc` is a finding here and a valueless name
/// there) and **what whitespace beside the `=` means** (a tolerated historical
/// artefact reported separately in the helper, a *defect* in Alt-Svc, and part
/// of the production here -- so the one thing a shared reader would have to be
/// told per caller is the one thing all three disagree about). Alt-Svc's and
/// this one are one terminal apart and could be folded on a flag; that is
/// `server_alt_svc_header_syntax`'s question as much as this rule's, and
/// neither audit may answer it alone.
///
/// The leading-DQUOTE alternation below is separately the **sixth** copy in the
/// tree, counted at `message_keep_alive_header_validity::validate_param_value`.
// cite(Server Timing, label: server-timing-param grammar): "server-timing-param = server-timing-param-name OWS "=" OWS server-timing-param-value"
// cite(Server Timing, label: server-timing-param-name grammar): "server-timing-param-name = token"
fn check_param<'a>(metric: &str, param: &'a str, seen: &mut Vec<&'a str>) -> Option<String> {
    // The repetition is `*( OWS ";" OWS server-timing-param )`: every semicolon
    // it generates owes a parameter behind it, so a trailing `;` and a `; ;`
    // are both a semicolon with nothing to its name. This used to be skipped
    // *"per lenient parsing"*, which is the user agent's job description and
    // not a sentence about what a server may write.
    if param.is_empty() {
        return Some(format!(
            "Server-Timing metric '{}' has a ';' with no server-timing-param behind it: the repetition `*( OWS \";\" OWS server-timing-param )` generates no bare semicolon",
            shown_in_finding(metric)
        ));
    }

    // The first `=` is the production's, whatever follows it: a
    // `server-timing-param-name` is a `token`, and `=` is not a `tchar`, so no
    // name can contain one and no earlier `=` exists to be confused with it.
    let Some((raw_name, raw_value)) = param.split_once('=') else {
        return Some(format!(
            "Server-Timing parameter '{}' has no '=': a server-timing-param is a name, an '=', and a value, and the value is not optional",
            shown_in_finding(param)
        ));
    };
    // The `OWS` either side of the `=` is printed in the production, so taking
    // it off is reading the grammar rather than tolerating a sender.
    // cite(RFC 9110 § 5.6.3, label: OWS grammar): "OWS            = *( SP / HTAB )"
    let name = trim_ows(raw_name);
    let value = trim_ows(raw_value);

    // `server-timing-param-name = token`, and `token = 1*tchar`. The old rule
    // skipped this one too, on the parsing algorithm's *"If paramName is an
    // empty string or params[paramName] exists, continue"* -- a step in the
    // user agent's error recovery, quoted below at the branch it belongs to.
    if name.is_empty() {
        return Some(format!(
            "Server-Timing parameter '{}' has an empty server-timing-param-name: `server-timing-param-name = token` and a token is one character or more",
            shown_in_finding(param)
        ));
    }
    if let Some(c) = find_invalid_token_char(name) {
        return Some(format!(
            "Server-Timing server-timing-param-name '{}' holds {}, which no token admits",
            shown_in_finding(name),
            describe_char(c)
        ));
    }

    // The document's one sentence about what a server writes. A user agent's
    // answer to the same fact is to take the first occurrence and ignore the
    // rest without signalling anything -- which is precisely why nothing else
    // will ever tell the server it wrote an ambiguity. The rule used to
    // implement the user agent's half and call the question answered.
    //
    // cite(Server Timing § 2): "To avoid any possible ambiguity, individual server-timing-param-names SHOULD NOT appear multiple times within a server-timing-metric."
    // cite(Server Timing § 2): "If any server-timing-param-name is specified more than once, only the first instance is to be considered, even if the server-timing-param is incomplete or invalid."
    // cite(Server Timing § 2): "All subsequent occurrences MUST be ignored without signaling an error or otherwise altering the processing of the server-timing-metric."
    if seen.contains(&name) {
        return Some(format!(
            "Server-Timing metric '{}' names the server-timing-param '{}' more than once; a user agent takes the first occurrence and ignores the rest without signalling anything, so the later values are silently discarded (advice: the specification says SHOULD NOT, to avoid any possible ambiguity)",
            shown_in_finding(metric),
            shown_in_finding(name)
        ));
    }
    seen.push(name);

    // `server-timing-param-value = token / quoted-string`. Neither alternative
    // derives the empty string: `token = 1*tchar`, and the shortest
    // `quoted-string` is the two DQUOTEs.
    // cite(Server Timing, label: server-timing-param-value grammar): "server-timing-param-value = token / quoted-string"
    if value.is_empty() {
        return Some(format!(
            "Server-Timing parameter '{}' has an empty value: a server-timing-param-value is a token or a quoted-string, and neither of those is nothing",
            shown_in_finding(param)
        ));
    }

    let text = if value.starts_with('"') {
        // Where the `quoted-string` ends decides whether anything follows it,
        // and something following it is the case § 2 has a user agent ignore.
        // Being told to ignore a thing is not being told one may write it --
        // the value still has to derive from one of the two alternatives, and
        // `"abc"x` derives from neither.
        //
        // cite(Server Timing § 2): "User agents MUST ignore extraneous characters found after a server-timing-param-value but before the next server-timing-param and before the end of the current server-timing-metric."
        let end = quoted_string_end(value).expect("the field value's quoting is balanced");
        if end + 1 != value.len() {
            return Some(format!(
                "Server-Timing parameter '{}' has {} after the closing DQUOTE of its quoted-string; a user agent ignores those characters without signalling anything, but the value as written derives from neither alternative of `server-timing-param-value`",
                shown_in_finding(name),
                shown_in_finding(&value[end + 1..])
            ));
        }
        // Balanced quoting and nothing after the close still leaves the
        // interior to judge, and the value a user agent stores is the
        // unescaped one -- it collects the quoted string with the extract-value
        // flag set. Those are one call rather than two: `unescape_quoted_string`
        // opens by asking `validate_quoted_string`, so validating separately
        // would run the interior walk twice and leave a discarded `Err` behind.
        // The neighbour records the same fold at the same production.
        //
        // **The error arm is a boundary rather than a live finding, and saying
        // so is the point.** Every value reaching this rule crossed a
        // `hyper::HeaderValue`, whose own predicate is `b >= 32 && b != 127 ||
        // b == b'\t'` -- so no octet that could fail the interior walk is in the
        // string at all: the controls are refused at the door, HTAB and every
        // `obs-text` octet are admitted by both `qdtext` and `quoted-pair`, an
        // unescaped DQUOTE before the end was found by `quoted_string_end`
        // above, and a trailing backslash would have unbalanced the quoting. The
        // arm stays because the grammar's reader is where the grammar's question
        // is answered; a rule that decided it by omission would be one capture
        // format away from being wrong.
        match unescape_quoted_string(value) {
            Ok(inner) => Cow::Owned(inner),
            Err(e) => {
                return Some(format!(
                    "Server-Timing parameter '{}' has a malformed quoted-string value: {e}",
                    shown_in_finding(name)
                ))
            }
        }
    } else {
        if let Some(c) = find_invalid_token_char(value) {
            return Some(format!(
                "Server-Timing server-timing-param-value '{}' holds {}, and the value is not quoted: a bare value is a token, whose characters are all visible US-ASCII and not delimiters",
                shown_in_finding(value),
                describe_char(c)
            ));
        }
        // A `token` is its own unescaping, so this half borrows where the other
        // owns.
        Cow::Borrowed(value)
    };

    established_param_advice(metric, name, &text)
}

/// What the two names § 2 establishes mean, for a parameter that is already a
/// well-formed `server-timing-param`.
///
/// Both findings below are advice and say so. Nothing here is a grammar
/// violation and no modal is broken -- the document establishes two names and
/// tells a user agent to ignore every other one without error. What is worth
/// reporting is that a server wrote something the two getters will not surface.
fn established_param_advice(metric: &str, name: &str, value: &str) -> Option<String> {
    // One lookup, folded, because both findings below turn on the same question
    // asked twice: which established name is this, and is it spelled the way the
    // getter spells it. A name matching neither is a name the document has a
    // user agent ignore without error, and there is nothing further to say.
    let established = ESTABLISHED_PARAM_NAMES
        .iter()
        .find(|established| name.eq_ignore_ascii_case(established))?;

    // `params` is keyed by the name as the sender wrote it and the two getters
    // index it with a literal, so a name matching one of them in every respect
    // but case is a name neither getter will find. It is conforming -- the
    // sentence at `ESTABLISHED_PARAM_NAMES` has a user agent ignore it without
    // error -- and it is also almost certainly not what the server meant.
    //
    // cite(Server Timing § 3.3): "The description getter steps are to return this’s params["desc"] if it exists, otherwise the empty string."
    if name != *established {
        return Some(format!(
            "Server-Timing metric '{}' names a server-timing-param '{}', which is '{}' in another case; the attribute that would surface it looks the name up as written, so this parameter is one no user agent recognises and every one of them ignores without error (advice: nothing forbids the name)",
            shown_in_finding(metric),
            shown_in_finding(name),
            established
        ));
    }

    // `desc` is whatever the server wrote and § 3.3 returns it unexamined, so
    // only `dur` has a value question. Not a MUST and not a SHOULD: the getter's
    // own answer to a `dur` it cannot parse is to return zero. The rule's doc
    // comment used to invent a SHOULD for this, and its check used to be
    // `f64::from_str`, which is a different production in both directions.
    //
    // cite(Server Timing § 3.2): "Let dur be the result of parsing this’s params["dur"] using the rules for parsing floating-point number values."
    // cite(Server Timing § 3.2): "If dur is an error, return 0; Otherwise return dur."
    if *established == "dur" && !is_valid_floating_point_number(value) {
        return Some(format!(
            "Server-Timing metric '{}' has a 'dur' of '{}', which is not a valid floating-point number; the parsing rules return an error for a value that does not begin with one — surfaced as a duration of 0 — and otherwise stop at the first character that is not part of the number, so neither reading is what this metric says (advice: no sentence requires 'dur' to be a number)",
            shown_in_finding(metric),
            shown_in_finding(value)
        ));
    }

    None
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ServerServerTimingHeaderSyntax;

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;
    use hyper::HeaderMap;
    use rstest::rstest;

    fn section(lines: &[&[u8]]) -> HeaderMap {
        let mut hm = HeaderMap::new();
        for line in lines {
            hm.append(
                "server-timing",
                HeaderValue::from_bytes(line).expect("a field value"),
            );
        }
        hm
    }

    fn response(headers: &[&[u8]], trailers: &[&[u8]]) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: section(headers),
            body_length: None,
            trailers: (!trailers.is_empty()).then(|| section(trailers)),
        });
        tx
    }

    fn run(tx: &crate::http_transaction::HttpTransaction) -> Option<Violation> {
        ServerServerTimingHeaderSyntax.check_transaction(
            tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "server_server_timing_header_syntax",
            ]),
        )
    }

    fn header(line: &[u8]) -> Option<Violation> {
        run(&response(&[line], &[]))
    }

    /// The specification's own worked exchange, every field line of it,
    /// including the one written after the content.
    #[test]
    fn the_specifications_own_example_is_clean() {
        let v = run(&response(
            &[
                b"miss, db;dur=53, app;dur=47.2",
                b"customView, dc;desc=atl",
                b"cache;desc=\"Cache Read\";dur=23.2",
            ],
            &[b"total;dur=123.4"],
        ));
        assert!(v.is_none(), "the example is a finding: {v:?}");
    }

    #[rstest]
    // A quoted-string is data, and both separators may sit inside one.
    #[case::comma_in_quotes(b"cache;desc=\"Cache Read, DB Write\"")]
    #[case::semicolon_in_quotes(b"cache;desc=\"a;b\";dur=1")]
    #[case::escaped_dquote(b"db;desc=\"a\\\"b\"")]
    // `#element => [ 1#element ]` -- the whole list is optional.
    #[case::empty_value(b"")]
    #[case::whitespace_only(b"   ")]
    // `OWS` is printed around the `;` and around the `=`.
    #[case::ows_everywhere(b"db ; dur = 53 ; desc = \"x\"")]
    // Every spelling the valid floating-point number production generates.
    #[case::fraction_only(b"db;dur=.5")]
    #[case::exponent(b"db;dur=5e-3")]
    #[case::exponent_plus(b"db;dur=5E+3")]
    #[case::negative(b"db;dur=-1.5")]
    // `qdtext` admits `obs-text`, so a high octet inside a quoted value is not
    // a defect -- and the old reader folded the whole field into a finding
    // about UTF-8 for exactly this.
    #[case::obs_text_in_quoted_value(b"db;desc=\"caf\xe9\"")]
    // § 2 grants the response a MAY for a repeated metric-name.
    #[case::repeated_metric_name(b"db;dur=1, db;dur=2")]
    // An unrecognised parameter name is to be ignored without error.
    #[case::unknown_param(b"db;cache=hit")]
    fn conforming(#[case] line: &[u8]) {
        let v = header(line);
        assert!(v.is_none(), "unexpected finding for {line:?}: {v:?}");
    }

    #[rstest]
    #[case::leading_comma(b",miss", "empty list element")]
    #[case::trailing_comma(b"miss,", "empty list element")]
    #[case::double_comma(b"miss,,db", "empty list element")]
    #[case::empty_metric_name(b";dur=23", "empty metric-name")]
    #[case::metric_name_not_a_token(b"b@d;dur=5", "which no token admits")]
    #[case::obs_text_in_metric_name(b"d\xe9b;dur=5", "0xE9")]
    #[case::param_name_not_a_token(b"db;d@r=5", "which no token admits")]
    #[case::empty_param_name(b"db;=5", "empty server-timing-param-name")]
    #[case::bare_semicolon(b"db; ;dur=5", "with no server-timing-param behind it")]
    #[case::trailing_semicolon(b"db;dur=5;", "with no server-timing-param behind it")]
    #[case::param_without_equals(b"db;desc", "has no '='")]
    #[case::empty_param_value(b"db;desc=", "empty value")]
    #[case::value_not_a_token(b"db;desc=Cache Read", "and the value is not quoted")]
    #[case::unterminated_quote(b"db;desc=\"unfinished", "never closes")]
    #[case::junk_after_quote(b"db;desc=\"abc\"x", "after the closing DQUOTE")]
    // Advice, and every one of these was silence before.
    #[case::repeated_param(b"db;dur=50;dur=51", "more than once")]
    #[case::repeated_param_second_invalid(b"db;dur=50;dur=abc", "more than once")]
    // Which spellings the production admits is the table at the bottom of this
    // module; these two cases are here for the wiring -- that the branch is
    // reached, and that it is reached through the quoted alternative too, where
    // `""` is a value the empty-value branch above cannot see.
    #[case::dur_not_a_number(b"db;dur=abc", "not a valid floating-point number")]
    #[case::dur_quoted_empty(b"db;dur=\"\"", "not a valid floating-point number")]
    #[case::dur_quoted_not_a_number(b"db;dur=\"abc\"", "not a valid floating-point number")]
    #[case::dur_wrong_case(b"db;DUR=53", "which is 'dur' in another case")]
    #[case::desc_wrong_case(b"db;Desc=x", "which is 'desc' in another case")]
    fn reported(#[case] line: &[u8], #[case] expected: &str) {
        let v = header(line).unwrap_or_else(|| panic!("expected a finding for {line:?}"));
        assert!(
            v.message.contains(expected),
            "message for {line:?} was {:?}, which does not contain {expected:?}",
            v.message
        );
    }

    /// The `dur` value a user agent stores is the unescaped one -- it collects
    /// the quoted string with the extract-value flag set -- so a `quoted-pair`
    /// inside it must not reach the number production as a backslash.
    #[test]
    fn a_quoted_dur_is_unescaped_before_it_is_measured() {
        assert!(header(b"db;dur=\"23.5\"").is_none());
        // `\5` is the digit 5, so this is a duration and not a finding.
        assert!(header(b"db;dur=\"\\5\"").is_none());
        // And the value a finding names is the unescaped one, not what was on
        // the wire.
        let v = header(b"db;dur=\"a\\b\"").expect("a finding");
        assert!(
            v.message.contains("'ab'"),
            "the finding names the unescaped value: {:?}",
            v.message
        );
    }

    /// A control octet other than HTAB never reaches this rule: it cannot enter
    /// a `HeaderValue`. The finding for one exists because the grammar has one,
    /// and this pins the boundary that keeps it unreachable.
    #[test]
    fn a_control_octet_cannot_reach_the_rule() {
        assert!(HeaderValue::from_bytes(b"db;desc=\"bad\x01str\"").is_err());
        assert!(HeaderValue::from_bytes(b"db;desc=\"bad\x7fstr\"").is_err());
        assert!(HeaderValue::from_bytes(b"db;desc=\"tab\there\"").is_ok());
        assert!(crate::helpers::headers::unescape_quoted_string("\"bad\u{1}str\"").is_err());
    }

    /// The lines of one section are one list, so a metric may be split across
    /// them and a member may be empty at a line boundary.
    #[test]
    fn the_lines_of_one_section_are_one_list() {
        assert!(run(&response(&[b"miss, db;dur=53", b"app;dur=47.2"], &[])).is_none());
        let v = run(&response(&[b"miss", b""], &[])).expect("a finding");
        assert!(v.message.contains("empty list element"), "{:?}", v.message);
    }

    /// A trailer section is read, and its findings say which section they came
    /// from -- the two sections are never joined into one list.
    #[test]
    fn a_trailer_section_is_read_and_named() {
        let v = run(&response(&[b"db;dur=1"], &[b"b@d;dur=5"])).expect("a finding");
        assert!(
            v.message.starts_with("In the response trailer section:"),
            "{:?}",
            v.message
        );

        // And the header section names itself too, so a finding never leaves a
        // reader to guess which half of the message it is about.
        let v = run(&response(&[b"b@d;dur=5"], &[])).expect("a finding");
        assert!(
            v.message.starts_with("In the response header section:"),
            "{:?}",
            v.message
        );

        // The two sections are not joined, and this is the fixture that can tell
        // the difference: an empty header-section value is zero metrics on its
        // own, while `"" + "," + "miss"` would be an empty list element. A pair
        // of separately-clean sections proves nothing here -- joined or not,
        // `miss` beside `db;dur=1` is a conforming list either way.
        assert!(run(&response(&[b""], &[b"miss"])).is_none());
    }

    /// The rule says nothing about a response that carries no such field, and
    /// nothing about a request.
    #[test]
    fn silence_where_there_is_nothing_to_measure() {
        assert!(run(&response(&[], &[])).is_none());
        assert!(run(&crate::test_helpers::make_test_transaction()).is_none());
    }

    /// The premise: `f64::from_str` and HTML's production disagree in both
    /// directions, and this is the table of where.
    #[rstest]
    #[case("53", true)]
    #[case("47.2", true)]
    #[case(".5", true)]
    #[case("-1.5e10", true)]
    #[case("5E+3", true)]
    #[case("0", true)]
    // Rust accepts every one of these and HTML admits none.
    #[case("NaN", false)]
    #[case("nan", false)]
    #[case("inf", false)]
    #[case("infinity", false)]
    #[case("-Infinity", false)]
    #[case("+5", false)]
    // Neither accepts these, but the reasons differ and the message does too.
    #[case("53abc", false)]
    #[case("5.", false)]
    #[case("", false)]
    #[case(" 53", false)]
    #[case("53 ", false)]
    #[case("0x10", false)]
    #[case("5e", false)]
    fn the_valid_floating_point_number_production(#[case] s: &str, #[case] valid: bool) {
        assert_eq!(
            is_valid_floating_point_number(s),
            valid,
            "valid floating-point number: {s:?}"
        );
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "server_server_timing_header_syntax");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
