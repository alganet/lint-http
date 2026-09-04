// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::helpers::headers::{combined_field_value_as_written, trim_ows};
use crate::helpers::shown::{describe_char, shown_in_finding};
use crate::helpers::uri::{
    authority_component, check_percent_encoding, find_non_uri_char, scheme_authority_marker,
    scheme_prefix, split_host_and_port, split_userinfo, validate_host_and_optional_port,
    validate_scheme_name,
};
use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};

pub struct RefererUriValid;

/// The value as a finding may print it: escaped, and with the password half of a
/// userinfo subcomponent withheld.
///
/// The whole point of the userinfo finding is that credentials arrived in a field
/// a server logs, and a lint report is one more place they would be written down
/// in clear. The sentence asking for this names the *first* colon and exempts an
/// empty tail, so `user:@host` is printed as written and `user:s3cret@host` is
/// not.
// cite(RFC 3986 § 3.2.1): "Applications should not render as clear text any data after the first colon (":") character found within a userinfo subcomponent unless the data after the colon is the empty string (indicating no password)."
fn shown_referer(value: &str) -> String {
    let redacted = redacted_userinfo(value);
    shown_in_finding(redacted.as_deref().unwrap_or(value))
}

/// `Some(value with the password elided)`, or `None` when there is nothing to
/// elide. Separate from [`shown_referer`] so the userinfo finding can say which
/// of the two it is showing. The elision itself is
/// [`crate::helpers::uri::userinfo_password_withheld`]'s, shared with the two
/// pseudo-header rules that print an authority; what stays here is putting the
/// redacted authority back into the whole reference this rule shows.
fn redacted_userinfo(value: &str) -> Option<String> {
    let authority = authority_component(value)?;
    let redacted = crate::helpers::uri::userinfo_password_withheld(authority)?;
    Some(value.replacen(authority, &redacted, 1))
}

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9110_10_1_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("10.1.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1.3",
    note: "Referer — the field's grammar, the fragment and userinfo MUST NOT, the unsecured-request MUST NOT, and the two declined conditionals",
};
const RFC_9110_4_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("4.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-4.1",
    note: "URI References — `partial-URI` is the rule for elements that carry a relative URI but no fragment, and an element's ABNF is what says which forms it allows",
};
const RFC_9110_4_2_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("4.2.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-4.2.1",
    note: "http URI Scheme — a TCP connection and no more, and the MUST NOT against an empty host identifier",
};
const RFC_9110_4_2_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("4.2.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-4.2.2",
    note: "https URI Scheme — what \"secured\" means for a resource named by one, and the MUST NOT against an empty host identifier",
};
const RFC_9110_5_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("5.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.3",
    note: "Field Order — the MUST NOT against a second field line for a field with no list alternative",
};
const RFC_9110_17_9: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("17.9"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-17.9",
    note: "Disclosure of Sensitive Information in URIs — why §10.1.3 limits the field",
};
const RFC_3986_3_2_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 3986",
    section: Some("3.2.1"),
    url: "https://www.rfc-editor.org/rfc/rfc3986.html#section-3.2.1",
    note: "User Information — the production, its `@` delimiter, the deprecated `user:password` form, and the request not to render what follows the first colon",
};
const RFC_3986_4_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 3986",
    section: Some("4.2"),
    url: "https://www.rfc-editor.org/rfc/rfc3986.html#section-4.2",
    note: "Relative Reference — `relative-part`, and why a first path segment holding a colon is not one",
};
const RFC_3986_4_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 3986",
    section: Some("4.3"),
    url: "https://www.rfc-editor.org/rfc/rfc3986.html#section-4.3",
    note: "Absolute URI — the form without a fragment identifier",
};
const RFC_3986_4_4: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 3986",
    section: Some("4.4"),
    url: "https://www.rfc-editor.org/rfc/rfc3986.html#section-4.4",
    note: "Same-Document Reference — what an empty value is",
};
const RFC_3986_2_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 3986",
    section: Some("2.1"),
    url: "https://www.rfc-editor.org/rfc/rfc3986.html#section-2.1",
    note: "Percent-Encoding — the triplet the `%` obliges",
};

impl RuleMeta for RefererUriValid {
    fn id(&self) -> &'static str {
        "referer_uri_valid"
    }

    fn title(&self) -> Option<&'static str> {
        Some("Message Referer Header URI Valid")
    }

    fn description(&self) -> &'static str {
        "Reads the `Referer` request header field against the production RFC 9110 §10.1.3 gives it — `Referer = absolute-URI / partial-URI` — and against the two components that section forbids a user agent to include.\n\n**The field's value is not a `URI-reference`, and the difference is the whole point.** `URI` and `relative-ref` each end in an optional `[ \"#\" fragment ]` group; `absolute-URI` and `partial-URI` are those two rules with that group dropped, which RFC 9110 §4.1 states in as many words — a `partial-URI` *\"is defined for protocol elements that can contain a relative URI but not a fragment component\"* — and RFC 3986 §4.3 says the same of the absolute form. So a fragment in this field derives from no reading of the grammar, and §10.1.3's own MUST NOT names it beside the userinfo: *\"A user agent MUST NOT include the fragment and userinfo components of the URI reference [URI], if any, when generating the Referer field value.\"* Both are reported. A percent-encoded `%23` is data, not a fragment.\n\n**A userinfo is a credential leaking into a field servers log.** The finding withholds everything after the first colon of the subcomponent, which is what RFC 3986 §3.2.1 asks of an application rendering a URI, and it says so in the message; that section also deprecates the `user:password` form outright.\n\n**An `https` referrer on an unsecured request is reported.** §10.1.3: *\"A user agent MUST NOT send a Referer header field in an unsecured HTTP request if the referring resource was accessed with a secure protocol.\"* Both halves are read from a scheme — §4.2.2 defines `https` over a connection secured for HTTP communication and requires a client to secure its requests for such a resource, and §4.2.1 defines `http` over a TCP connection and nothing more. **The request's own scheme is not always on the wire**: it is there when the target is in absolute form, which is how HTTP/2 and HTTP/3 reassemble a target from `:scheme` and how an HTTP/1.1 request to a proxy is written, and it is absent from an origin-form target, where no captured field records it. A request whose scheme is unknown draws nothing from this check rather than being guessed at.\n\n**The rest of the value.** Every character is measured against the set a URI is composed from — the union of `unreserved`, `gen-delims`, `sub-delims` and the `%` that opens a triplet — and each `%` against `pct-encoded = \"%\" HEXDIG HEXDIG`. That union is a **floor, not a ceiling**: `[` and `]` derive from no component but the host productions, and `:` and `@` from `pchar` but not from `reg-name`, so a character passing it has only been found somewhere in the generic syntax. What the value offers as a scheme is measured against `scheme = ALPHA *( ALPHA / DIGIT / \"+\" / \"-\" / \".\" )`, and a value failing it is not re-read as a relative reference, because a first path segment holding a colon is no `path-noscheme` (RFC 3986 §4.2). Where the value carries an authority — the `\"//\" authority path-abempty` alternative both `hier-part` and `relative-part` open with — the host and port are read as `uri-host [ \":\" port ]`, and an empty host under `http` or `https` is the MUST NOT those two schemes each state for themselves.\n\n**`Referer` is a singleton.** Neither alternative of its grammar is a comma-separated list, so RFC 9110 §5.3 forbids a second field line, and the report counts the lines rather than inspecting the joined value: a comma is a `sub-delims` character both alternatives admit inside a path or a query, so what a recipient recombines two lines into is a well-formed reference to a resource neither line named.\n\n**An empty value is reported as advice and says so.** `partial-URI` admits `path-empty`, so it is a same-document reference (RFC 3986 §4.4) resolving to the target URI the request already carried, and the grammar has no complaint. What makes it worth a word here — and this field differs from `Location` and `Content-Location` in it — is that §10.1.3 names the two things a user agent with no referring URI to state does, omit the field or send `about:blank`, and an empty value is neither. The MUST behind that is not reachable from a capture, because nothing in a message says where the target URI came from.\n\n**What this rule declines, and why.**\n\n- **The cross-origin SHOULD NOT.** §10.1.3 asks a user agent not to send the field when the referring resource was accessed securely and the request target has a different origin — *\"unless the referring resource explicitly allows Referer to be sent\"*. That permission is stated by the referring resource's own response, in a different transaction, so the escape clause's antecedent is invisible here and a finding would report every conforming cross-origin request that carries it.\n- **The exclude-or-`about:blank` MUST.** Its antecedent is that the target URI came from a source with no URI of its own — a keyboard, a bookmark. No field records that.\n- **The intermediary SHOULD NOT** — *\"An intermediary SHOULD NOT modify or delete the Referer header field when the field value shares the same scheme and host as the target URI.\"* Deciding it means comparing a message against the same message before some intermediary handled it, and a capture is one message.\n- **Whether the value names the resource the request actually came from.** §10.1.3 permits a user agent to *\"truncate parts other than the referring origin\"*, so a value naming less than the full URI is conforming, and nothing in a single transaction knows what the referring resource was.\n- **Whether an `http` or `https` authority resolves, or a port is one a transport could carry.** `port` is `*DIGIT` (RFC 3986 §3.2.3), which bounds nothing at either end.\n\n**What other rules own.** A fragment on the *request target* is `request_target_no_fragment`'s, on every version; a malformed percent-encoding in the target is `request_uri_percent_encoding_valid`'s. The same `absolute-URI / partial-URI` production governs `Content-Location` (RFC 9110 §8.7), whose rule reads the same fragment question from the grammar and RFC 9110 §2.2 alone — no MUST NOT names the component for that field."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_9110_10_1_3,
            RFC_9110_4_1,
            RFC_9110_4_2_1,
            RFC_9110_4_2_2,
            RFC_9110_5_3,
            RFC_9110_17_9,
            RFC_3986_3_2_1,
            RFC_3986_4_2,
            RFC_3986_4_3,
            RFC_3986_4_4,
            RFC_3986_2_1,
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("The example §10.1.3 prints"),
                snippet: "GET / HTTP/1.1\nReferer: http://www.example.org/hypertext/Overview.html",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("A `partial-URI`, resolved against the target URI"),
                snippet: "GET / HTTP/1.1\nReferer: /relative/path?q=1",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("The value §10.1.3 names for a source that has no URI"),
                snippet: "GET / HTTP/1.1\nReferer: about:blank",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("A network-path reference: `relative-part` opens with one"),
                snippet: "GET / HTTP/1.1\nReferer: //other.example/page",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("A fragment: neither alternative of the grammar generates one"),
                snippet: "GET / HTTP/1.1\nReferer: http://example.com/a#section",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("A userinfo subcomponent, credentials and all"),
                snippet: "GET / HTTP/1.1\nReferer: https://alice:s3cret@example.com/a",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("An `https` referrer on an unsecured request"),
                snippet: "GET http://example.com/ HTTP/1.1\nReferer: https://secure.example/page",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("A character no URI is composed from"),
                snippet: "GET / HTTP/1.1\nReferer: https://example.com/ bad",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("A `%` that does not open a triplet"),
                snippet: "GET / HTTP/1.1\nReferer: /bad%2Gencoding",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("An empty host identifier under `http`"),
                snippet: "GET / HTTP/1.1\nReferer: http:///page",
            },
        ]
    }
}

impl Rule for RefererUriValid {
    /// `Referer` is defined in § 10.1, *Request Context Fields*, and every modal
    /// in § 10.1.3 but one is addressed to the user agent. The exception is the
    /// intermediary SHOULD NOT at the end of the section, which is about a field
    /// this rule reads rather than about one it could measure — see
    /// `description()`.
    ///
    /// cite(RFC 9110 § 10.1): "The request header fields below provide additional information about the request context, including information about the user, user agent, and resource behind the request."
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
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
            let req = &tx.request;

            // The field probe first and the config after it: a request with no
            // `Referer` should not pay for several map lookups and a hash of the
            // rule id to learn that there is nothing to read.
            //
            // Read as the sender wrote it, one `char` per octet. The `to_str` this
            // replaced answered "Referer header value is not valid UTF-8" for any
            // octet above %x7E — a claim about an encoding, where the truth is that
            // no octet in that range is one a URI is composed from, which is the
            // finding the check below makes of it.
            //
            // The header section only. Whether *any* field may appear in a trailer
            // section is § 6.5.1's deny-by-default question and
            // `trailer_fields_valid`'s finding, and a field naming where
            // the request came from cannot arrive after the request's content.
            //
            // cite(RFC 9110 § 10.1.3): "The "Referer" [sic] header field allows the user agent to specify a URI reference for the resource from which the target URI was obtained (i.e., the "referrer", though the field name is misspelled)."
            // cite(RFC 9110 § 10.1.3, label: Referer grammar): "Referer = absolute-URI / partial-URI"
            let value = combined_field_value_as_written(&req.headers, "referer")?;
            let violation = |message: String| Some(self.violation(ctx.severity, message));

            let lines = req.headers.get_all("referer").iter().count();
            if lines > 1 {
                // Neither alternative of the grammar is a `#(...)` list, so § 5.3's
                // exception does not apply and one message carries at most one
                // `Referer` line.
                //
                // The preamble is `helpers::headers::singleton_field_preamble`'s;
                // what is appended is this field's, and the sibling carrying the same
                // production (`Content-Location`) appends the same fact because it is
                // the same fact.
                //
                // cite(RFC 3986 § 2.2): "sub-delims  = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "=""
                return violation(format!(
                    "{}. The comma a recipient joins them with is a `sub-delims` character both alternatives admit inside a path or a query (RFC 3986 §2.2), so the joined value is a well-formed reference to a resource neither line named",
                    crate::helpers::headers::singleton_field_preamble(
                        "Referer",
                        lines,
                        &shown_referer(&value),
                        "`Referer = absolute-URI / partial-URI`, and neither alternative is a comma-separated list",
                    )
                ));
            }

            // `OWS` and only `OWS`. The value carries one `char` per octet, so U+00A0
            // in it is the octet %xA0 — `obs-text`, which is whitespace in no
            // document and which `str::trim` removed before any check saw it.
            //
            // cite(RFC 9110 § 5.5): "A field value does not include leading or trailing whitespace.  When a specific version of HTTP allows such whitespace to appear in a message, a field parsing implementation MUST exclude such whitespace prior to evaluating the field value."
            let value = trim_ows(&value);

            if value.is_empty() {
                // The weakest finding here and the only one worded as advice, which
                // is what it is. `partial-URI` is `relative-part [ "?" query ]` and
                // `relative-part` admits `path-empty`, so the empty value derives
                // from the field's own grammar — it is a same-document reference,
                // resolving to the target URI the request already carried.
                //
                // What makes it worth a word is that this section, unlike the two
                // sibling fields carrying the same production, says what a user agent
                // with no referring URI to state does, and neither of its two
                // spellings is this one. The MUST is not reachable from a capture —
                // nothing in a message says where the target URI came from — so the
                // finding names the sentence without claiming it was broken.
                //
                // `location_header_uri_valid` and
                // `content_location_and_uri_consistent` reach the same
                // answer on their fields for the first reason alone; recorded here so
                // that a later harmonising commit does not upgrade one of the three.
                //
                // cite(RFC 9110 § 4.1, label: partial-URI): "partial-URI   = relative-part [ "?" query ]"
                // cite(RFC 3986 § 4.4): "The most frequent examples of same-document references are relative references that are empty or include only the number sign ("#") separator followed by a fragment identifier."
                // cite(RFC 9110 § 10.1.3): "If the target URI was obtained from a source that does not have its own URI (e.g., input from the user keyboard, or an entry within the user's bookmarks/favorites), the user agent MUST either exclude the Referer header field or send it with a value of "about:blank"."
                return violation(
                    "Referer is present with an empty value, which names the request's own target URI: `partial-URI` admits `path-empty`, so an empty value is a same-document reference (RFC 3986 §4.4) and the field's grammar has no complaint. RFC 9110 §10.1.3 names the two things a user agent with no referring URI to state does — omit the field, or send `about:blank` — and an empty value is neither. This is advice, not a violation"
                        .to_string(),
                );
            }

            // The alphabet, before any component question. The union of every
            // component's character set is a floor and not a ceiling — `[` and `]`
            // derive from no component but the host productions, and `:` and `@`
            // from `pchar` but not from `reg-name` — so a character passing here has
            // only been found somewhere in the generic syntax, and the checks below
            // are what ask whether it sits where it is written.
            //
            // The check this replaced was `contains_whitespace`, which is one sixth
            // of the same question: SP, HTAB, CR, LF and FF are five of the
            // characters no URI is composed from, and `<`, `>`, `"`, `{`, `}`, `|`,
            // `\`, `^`, `` ` `` and every octet at or above %x80 are the rest.
            //
            // cite(RFC 9110 § 2.2): "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules."
            if let Some(c) = find_non_uri_char(value) {
                return violation(format!(
                    "Referer value '{}' holds {}, which no part of a URI is composed from (RFC 3986 §2): an octet outside that set is percent-encoded before the reference is formed, or the value is not a URI reference at all",
                    shown_referer(value),
                    describe_char(c)
                ));
            }

            if let Some(msg) = check_percent_encoding(value) {
                return violation(format!(
                    "Referer value '{}' is not a well-formed URI reference: {}",
                    shown_referer(value),
                    msg
                ));
            }

            // The premise this rule was missing. `URI-reference` is what it was
            // written against — its own description said so — and that is not this
            // field's production: `URI = scheme ":" hier-part [ "?" query ] [ "#"
            // fragment ]` and `relative-ref = relative-part [ "?" query ] [ "#"
            // fragment ]`, and § 10.1.3 hands the field the two rules that are those
            // two with the fragment group dropped. So the component the section's own
            // MUST NOT names is exactly the one the two grammars differ in, and
            // `Referer: /a#b` derived from the rule's reading of the field and from
            // no reading of the document.
            //
            // A number sign is the only character that opens the component, and it
            // appears in no other one — `query` is `*( pchar / "/" / "?" )` and
            // `pchar` has none — so finding one is finding a fragment. A
            // percent-encoded `%23` is data and is not this.
            //
            // cite(RFC 9110 § 10.1.3): "A user agent MUST NOT include the fragment and userinfo components of the URI reference [URI], if any, when generating the Referer field value."
            // cite(RFC 9110 § 4.1): "A "partial-URI" rule is defined for protocol elements that can contain a relative URI but not a fragment component."
            // cite(RFC 9110 § 4.1): "Each protocol element in HTTP that allows a URI reference will indicate in its ABNF production whether the element allows any form of reference (URI-reference), only a URI in absolute form (absolute-URI), only the path and optional query components (partial-URI), or some combination of the above."
            // cite(RFC 3986 § 4.3): "Some protocol elements allow only the absolute form of a URI without a fragment identifier."
            // cite(RFC 3986 § 3.5): "The fragment identifier component of a URI allows indirect identification of a secondary resource by reference to a primary resource and additional identifying information."
            if let Some(hash) = value.find('#') {
                return violation(format!(
                    "Referer value '{}' carries the fragment component '{}': a user agent MUST NOT include one when generating the field (RFC 9110 §10.1.3), and neither alternative of `Referer = absolute-URI / partial-URI` generates one — each is a URI rule with the `[ \"#\" fragment ]` group dropped (RFC 9110 §4.1, RFC 3986 §4.3)",
                    shown_referer(value),
                    shown_in_finding(&value[hash..])
                ));
            }

            // Which alternative the value takes is decided by its first component,
            // and there is no third: a colon before any component delimiter opens a
            // scheme and makes the value an `absolute-URI`, and its absence makes it
            // a `partial-URI`. A first path segment holding a colon derives from
            // neither, which is what `path-noscheme` exists to say, so a value whose
            // scheme candidate is not a scheme name is not quietly re-read as a
            // relative reference.
            //
            // cite(RFC 3986 § 3.1): "scheme      = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )"
            // cite(RFC 3986 § 4.2): "A path segment that contains a colon character (e.g., "this:that") cannot be used as the first segment of a relative-path reference, as it would be mistaken for a scheme name."
            let scheme = scheme_prefix(value);
            if let Some(scheme) = scheme {
                if let Err(defect) = validate_scheme_name(scheme) {
                    return violation(format!(
                        "Referer value '{}' derives from neither alternative of `Referer = absolute-URI / partial-URI`: {} — and a first path segment holding a colon is no `path-noscheme` either, so it is not a relative reference (RFC 3986 §4.2)",
                        shown_referer(value),
                        defect.message()
                    ));
                }
            }

            // The shared reader, which returns `Some("")` for a value carrying an
            // empty authority and `None` for one carrying no authority at all. This
            // rule is the reason it keeps the two apart: the empty-host branch below
            // is a MUST NOT about exactly the first of them, and
            // `helpers::uri::reference_authority` — the neighbouring question —
            // folds it away, because a reference with an empty authority defines
            // none *to compare against*.
            if let Some(authority) = authority_component(value) {
                let (userinfo, host_and_port) = split_userinfo(authority);

                // Asked before the host's grammar so the answer names what is wrong:
                // a userinfo makes the host look like a port to any reader splitting
                // on the colon. The other half of § 10.1.3's MUST NOT, and the half
                // that is a credential leak rather than a stray component — which is
                // why the message shows the redacted rendering and says so.
                //
                // `Some("")` is a userinfo too: `*( ... )` generates the empty one,
                // and the `@` is what says the component was included at all.
                //
                // cite(RFC 3986 § 3.2.1): "Use of the format "user:password" in the userinfo field is deprecated."
                if userinfo.is_some() {
                    let redacted = redacted_userinfo(value);
                    return violation(format!(
                        "Referer value '{}' carries a userinfo subcomponent and its '@' delimiter before the host '{}': a user agent MUST NOT include one when generating the field (RFC 9110 §10.1.3), and the `user:password` form of it is deprecated outright (RFC 3986 §3.2.1){}",
                        shown_referer(value),
                        shown_in_finding(host_and_port),
                        match redacted {
                            Some(_) => ". Everything after the first colon of the userinfo is withheld from this message (RFC 3986 §3.2.1)",
                            None => "",
                        }
                    ));
                }

                let (host, _) = split_host_and_port(host_and_port);

                // The generic syntax admits an empty host — `reg-name` is `*( ... )`
                // — so this is not a grammar finding, and it is stated once per
                // scheme rather than once for URIs. Only the two schemes that state
                // it are asked, and they are matched without regard to case because
                // § 4.2.3 says a scheme is compared that way.
                //
                // cite(RFC 9110 § 4.2.1): "A sender MUST NOT generate an "http" URI with an empty host identifier."
                // cite(RFC 9110 § 4.2.2): "A sender MUST NOT generate an "https" URI with an empty host identifier."
                // cite(RFC 9110 § 4.2.3): "The scheme and host are case-insensitive and normally provided in lowercase; all other components are compared in a case-sensitive manner."
                let empty_host_scheme = scheme.filter(|s| {
                    host.is_empty()
                        && (s.eq_ignore_ascii_case("http") || s.eq_ignore_ascii_case("https"))
                });
                if let Some(scheme) = empty_host_scheme {
                    return violation(format!(
                        "Referer value '{}' names the scheme '{}' and then an empty host identifier: a sender MUST NOT generate an \"{}\" URI with one (RFC 9110 §4.2.{})",
                        shown_referer(value),
                        shown_in_finding(scheme),
                        scheme.to_ascii_lowercase(),
                        if scheme.eq_ignore_ascii_case("http") {
                            "1"
                        } else {
                            "2"
                        }
                    ));
                }

                // `uri-host [ ":" port ]` is one question with one answer, and the
                // shared reader is where it lives: the bracket that distinguishes an
                // IP literal, the address inside it, and a port of digits.
                if let Err(msg) = validate_host_and_optional_port(host_and_port) {
                    return violation(format!(
                        "Referer value '{}' does not carry a well-formed authority: {}",
                        shown_referer(value),
                        msg
                    ));
                }
            }

            // The one finding here that is not about the value's shape, and the only
            // requirement in this section a capture can decide besides the two
            // components. Both halves are read from a scheme: § 4.2.2 defines
            // "https" over a connection secured for HTTP communication and requires
            // a client to secure its requests for such a resource, so a referring
            // resource named by an `https` URI was accessed with a secure protocol;
            // § 4.2.1 defines "http" over a TCP connection and nothing more, and
            // § 4.2.2 adds that the two schemes are distinct origins with separate
            // namespaces rather than two views of one resource.
            //
            // **What this cannot see.** The request's own scheme is on the wire only
            // when the target is in absolute form, which is how HTTP/2 and HTTP/3
            // reassemble it from `:scheme` and how an HTTP/1.1 request to a proxy is
            // written; an origin-form target carries a path and nothing else, and no
            // captured field records the scheme that would have completed it. So a
            // request whose scheme is unknown draws nothing, rather than being
            // guessed at in either direction. `scheme_authority_marker` is what asks
            // the question, because it takes only a `://` in the first component —
            // an authority-form CONNECT target naming a host called `http` is not a
            // scheme, and this must not read one out of it.
            //
            // cite(RFC 9110 § 10.1.3): "A user agent MUST NOT send a Referer header field in an unsecured HTTP request if the referring resource was accessed with a secure protocol."
            // cite(RFC 9110 § 4.2.2): "The "https" URI scheme is hereby defined for minting identifiers within the hierarchical namespace governed by a potential origin server listening for TCP connections on a given port and capable of establishing a TLS ([TLS13]) connection that has been secured for HTTP communication."
            // cite(RFC 9110 § 4.2.2): "A client MUST ensure that its HTTP requests for an "https" resource are secured, prior to being communicated, and that it only accepts secured responses to those requests."
            // cite(RFC 9110 § 4.2.1): "The "http" URI scheme is hereby defined for minting identifiers within the hierarchical namespace governed by a potential HTTP origin server listening for TCP ([TCP]) connections on a given port."
            // cite(RFC 9110 § 4.2.2): "Resources made available via the "https" scheme have no shared identity with the "http" scheme.  They are distinct origins with separate namespaces."
            // cite(RFC 9110 § 17.9): "Since the Referer header field tells a target site about the context that resulted in a request, it has the potential to reveal information about the user's immediate browsing history and any personal information that might be found in the referring resource's URI."
            let target_scheme = scheme_authority_marker(&req.uri).map(|i| &req.uri[..i]);
            if scheme.is_some_and(|s| s.eq_ignore_ascii_case("https"))
                && target_scheme.is_some_and(|s| s.eq_ignore_ascii_case("http"))
            {
                return violation(format!(
                    "Referer names '{}', an `https` resource, on a request whose own target URI is an `http` one ('{}'): a user agent MUST NOT send a Referer header field in an unsecured HTTP request if the referring resource was accessed with a secure protocol (RFC 9110 §10.1.3)",
                    shown_referer(value),
                    shown_in_finding(&req.uri)
                ));
            }

            None
        };
        Vec::from_iter(finding())
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &RefererUriValid;

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::{HeaderName, HeaderValue};
    use rstest::rstest;

    /// Run the rule over a request carrying `referer` field lines, with the
    /// request-target the caller names.
    fn judge_target(target: &str, referer: &[&str]) -> Option<String> {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.uri = target.to_string();
        let mut headers = crate::test_helpers::make_headers_from_pairs(&[]);
        for r in referer {
            headers.append(
                HeaderName::from_static("referer"),
                HeaderValue::from_bytes(r.as_bytes()).expect("a test Referer value"),
            );
        }
        tx.request.headers = headers;
        let config =
            crate::test_helpers::make_test_config_with_severity("referer_uri_valid", "warn");
        crate::test_helpers::run_rule(
            &RefererUriValid,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        )
        .map(|v| v.message)
    }

    fn judge(referer: &str) -> Option<String> {
        judge_target("/", &[referer])
    }

    #[rstest]
    // The document's own example, and the value it names for a source with no URI.
    #[case("http://www.example.org/hypertext/Overview.html")]
    #[case("about:blank")]
    // `partial-URI`: every `relative-part` alternative but `path-empty`.
    #[case("/relative/path")]
    #[case("/path%20with%20spaces?q=1")]
    #[case("relative/path")]
    #[case("//other.example/page")]
    // A colon past the first component is a `pchar` and not a scheme delimiter.
    #[case("/v1/entities/x:batchGet")]
    // `port = *DIGIT` bounds nothing, and a bracketed IPv6 literal is a host.
    #[case("https://example.com:99999/a")]
    #[case("https://[2001:db8::1]:8080/a")]
    // A percent-encoded number sign is data, not a fragment component.
    #[case("/a%23b")]
    // An empty host derives from `reg-name` under a scheme that does not forbid it.
    #[case("foo:///page")]
    fn conforming_values_draw_nothing(#[case] referer: &str) {
        assert_eq!(judge(referer), None, "reported '{referer}'");
    }

    /// One exact message per branch that emits. A finding here is assembled from
    /// a prefix and a verb phrase in two places, and an `is_some` assertion
    /// cannot see the two disagree.
    #[test]
    fn a_fragment_is_reported_against_both_halves_of_the_alternation() {
        assert_eq!(
            judge("http://example.com/a#section").as_deref(),
            Some("Referer value 'http://example.com/a#section' carries the fragment component '#section': a user agent MUST NOT include one when generating the field (RFC 9110 §10.1.3), and neither alternative of `Referer = absolute-URI / partial-URI` generates one — each is a URI rule with the `[ \"#\" fragment ]` group dropped (RFC 9110 §4.1, RFC 3986 §4.3)")
        );
        // The `partial-URI` half of the alternation, and an empty fragment: the
        // number sign is what says the component is present.
        assert!(judge("/a#").is_some_and(|m| m.contains("carries the fragment component '#'")));
        assert!(judge("#frag").is_some_and(|m| m.contains("fragment component")));
    }

    #[test]
    fn a_userinfo_is_reported_and_its_password_is_withheld() {
        let m = judge("https://alice:s3cret@example.com/a").expect("a userinfo is reported");
        assert_eq!(
            m,
            "Referer value 'https://alice:...@example.com/a' carries a userinfo subcomponent and its '@' delimiter before the host 'example.com': a user agent MUST NOT include one when generating the field (RFC 9110 §10.1.3), and the `user:password` form of it is deprecated outright (RFC 3986 §3.2.1). Everything after the first colon of the userinfo is withheld from this message (RFC 3986 §3.2.1)"
        );
        assert!(
            !m.contains("s3cret"),
            "the password reached the finding: {m}"
        );
        // No colon, or nothing after it: the sentence exempts both, so the value
        // is shown as written and the message does not claim to have withheld
        // anything.
        let m = judge("https://alice@example.com/a").expect("a userinfo is reported");
        assert!(
            m.starts_with("Referer value 'https://alice@example.com/a' carries a userinfo"),
            "{m}"
        );
        assert!(!m.contains("withheld"), "{m}");
        assert!(judge("https://alice:@example.com/a")
            .is_some_and(|m| m.contains("'https://alice:@example.com/a'")));
    }

    #[test]
    fn an_https_referrer_on_an_unsecured_request_is_reported() {
        assert_eq!(
            judge_target("http://example.com/p", &["https://secure.example/page"]).as_deref(),
            Some("Referer names 'https://secure.example/page', an `https` resource, on a request whose own target URI is an `http` one ('http://example.com/p'): a user agent MUST NOT send a Referer header field in an unsecured HTTP request if the referring resource was accessed with a secure protocol (RFC 9110 §10.1.3)")
        );
        // The scheme is compared without regard to case, on both sides.
        assert!(judge_target("HTTP://example.com/p", &["HTTPS://secure.example/page"]).is_some());
    }

    #[test]
    fn a_request_whose_own_scheme_is_not_on_the_wire_draws_nothing() {
        // An origin-form target carries a path and nothing else, and no captured
        // field records the scheme that would complete it.
        assert_eq!(judge_target("/p", &["https://secure.example/page"]), None);
        // A secured request is not the antecedent.
        assert_eq!(
            judge_target("https://example.com/p", &["https://secure.example/page"]),
            None
        );
        // A `partial-URI` referrer shares the target's scheme, so there is no
        // downgrade to report.
        assert_eq!(judge_target("http://example.com/p", &["/page"]), None);
        // An authority-form CONNECT target naming a host called `http` is not a
        // scheme, and nothing may read one out of it.
        assert_eq!(
            judge_target("http:443", &["https://secure.example/page"]),
            None
        );
    }

    #[test]
    fn the_singleton_finding_counts_the_lines_rather_than_reading_the_join() {
        // Both lines are well-formed references, so nothing but the count can
        // find this: the comma the recombination writes is a `sub-delims`
        // character a path admits.
        assert_eq!(
            judge_target("/", &["/first", "/second"]).as_deref(),
            Some("Referer is written on 2 header lines, which recombine into the one value '/first,/second'; the field is a singleton — `Referer = absolute-URI / partial-URI`, and neither alternative is a comma-separated list — so a sender must not generate more than one field line for it (RFC 9110 §5.3). The comma a recipient joins them with is a `sub-delims` character both alternatives admit inside a path or a query (RFC 3986 §2.2), so the joined value is a well-formed reference to a resource neither line named")
        );
    }

    #[test]
    fn an_empty_value_is_advice_and_says_so() {
        let m = judge("").expect("an empty value is reported");
        assert_eq!(
            m,
            "Referer is present with an empty value, which names the request's own target URI: `partial-URI` admits `path-empty`, so an empty value is a same-document reference (RFC 3986 §4.4) and the field's grammar has no complaint. RFC 9110 §10.1.3 names the two things a user agent with no referring URI to state does — omit the field, or send `about:blank` — and an empty value is neither. This is advice, not a violation"
        );
        // The `OWS` a field value does not include, and only that: the trim is
        // not a Unicode one.
        assert_eq!(judge(" \t"), Some(m));
    }

    #[rstest]
    // The five characters the whitespace check this replaced could see...
    #[case("https://example.com/ bad", "' '")]
    #[case("https://example.com/\tbad", "0x09")]
    // ...and the ones it could not, which are the rest of the alphabet question.
    #[case("/a<b>c", "'<'")]
    #[case("/a\"b", "'\"'")]
    #[case("/a{b}c", "'{'")]
    #[case("/a|b", "'|'")]
    #[case("/a\\b", "'\\'")]
    #[case("/a^b", "'^'")]
    #[case("/a`b", "'`'")]
    fn a_character_no_uri_is_composed_from_is_reported(#[case] referer: &str, #[case] shown: &str) {
        let m = judge(referer).unwrap_or_else(|| panic!("accepted '{referer}'"));
        assert!(
            m.contains(&format!(
                "holds {shown}, which no part of a URI is composed from"
            )),
            "{m}"
        );
    }

    /// An octet at or above %x80 is one no URI is composed from, and it used to
    /// be the one value this rule could not describe: `to_str` folded every one
    /// of them into a claim about UTF-8.
    #[test]
    fn an_obs_text_octet_is_named_as_the_octet_it_is() {
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut headers = crate::test_helpers::make_headers_from_pairs(&[]);
        headers.insert(
            HeaderName::from_static("referer"),
            HeaderValue::from_bytes(b"/caf\xe9/x").expect("a test Referer value"),
        );
        tx.request.headers = headers;
        let config =
            crate::test_helpers::make_test_config_with_severity("referer_uri_valid", "warn");
        let m = crate::test_helpers::run_rule(
            &RefererUriValid,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        )
        .expect("an obs-text octet is reported")
        .message;
        assert!(
            m.contains("holds 0xE9, which no part of a URI is composed from"),
            "{m}"
        );
        assert!(!m.contains("UTF-8"), "{m}");
    }

    #[rstest]
    #[case("/bad%2Gchar", "Invalid percent-encoding '%2G'")]
    #[case("/incomplete%2", "Percent-encoding incomplete")]
    fn a_malformed_triplet_is_reported(#[case] referer: &str, #[case] fragment: &str) {
        let m = judge(referer).unwrap_or_else(|| panic!("accepted '{referer}'"));
        assert!(
            m.starts_with("Referer value") && m.contains("is not a well-formed URI reference: "),
            "{m}"
        );
        assert!(m.contains(fragment), "{m}");
    }

    #[rstest]
    #[case("1http://ex", "scheme '1http' must begin with a letter")]
    #[case("ht!tp://ex", "invalid character '!' in scheme 'ht!tp'")]
    #[case(":foo", "scheme must not be empty")]
    fn a_value_deriving_from_neither_alternative_says_so(
        #[case] referer: &str,
        #[case] fragment: &str,
    ) {
        let m = judge(referer).unwrap_or_else(|| panic!("accepted '{referer}'"));
        assert!(
            m.contains(
                "derives from neither alternative of `Referer = absolute-URI / partial-URI`"
            ),
            "{m}"
        );
        assert!(m.contains(fragment), "{m}");
        assert!(m.contains("no `path-noscheme` either"), "{m}");
    }

    #[rstest]
    #[case("http:///page", "http", "1")]
    #[case("https:///page", "https", "2")]
    #[case("HTTP:///page", "HTTP", "1")]
    fn an_empty_host_is_reported_for_the_two_schemes_that_forbid_it(
        #[case] referer: &str,
        #[case] scheme: &str,
        #[case] subsection: &str,
    ) {
        let m = judge(referer).unwrap_or_else(|| panic!("accepted '{referer}'"));
        assert_eq!(
            m,
            format!(
                "Referer value '{referer}' names the scheme '{scheme}' and then an empty host identifier: a sender MUST NOT generate an \"{}\" URI with one (RFC 9110 §4.2.{subsection})",
                scheme.to_ascii_lowercase()
            )
        );
    }

    #[rstest]
    #[case("https://exam[ple/a", "holds a bracket")]
    #[case("https://example.com:8o8/a", "invalid character 'o' in port")]
    #[case("https://[::1x]/a", "is not an IPv6 address")]
    #[case("https://[::1/a", "missing its ']'")]
    fn a_malformed_authority_is_reported(#[case] referer: &str, #[case] fragment: &str) {
        let m = judge(referer).unwrap_or_else(|| panic!("accepted '{referer}'"));
        assert!(
            m.contains("does not carry a well-formed authority: "),
            "{m}"
        );
        assert!(m.contains(fragment), "{m}");
    }

    #[test]
    fn scope_is_client() {
        assert_eq!(RefererUriValid.scope(), crate::rules::RuleScope::Client);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&["referer_uri_valid"]);
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    /// Nothing runs a rule's own `examples()` through the engine, so a
    /// `Compliant` value the rule rejects is published as guidance.
    #[test]
    fn published_examples_are_judged_the_way_they_are_labelled() {
        use crate::rules::Compliance;
        let mut saw_a_finding = false;
        for ex in RefererUriValid.examples() {
            let mut lines = ex.snippet.lines();
            let start = lines.next().expect("an example has a start line");
            let target = start
                .strip_prefix("GET ")
                .and_then(|r| r.strip_suffix(" HTTP/1.1"))
                .unwrap_or_else(|| panic!("this guard reads an example's target: {start:?}"));
            let fields: Vec<&str> = lines
                .filter(|l| !l.trim().is_empty())
                .map(|l| {
                    l.strip_prefix("Referer: ")
                        .unwrap_or_else(|| panic!("not a Referer line: {l:?}"))
                })
                .collect();
            let found = judge_target(target, &fields);
            match ex.compliance {
                Compliance::Compliant => assert!(
                    found.is_none(),
                    "rule reports its Compliant example {:?}: {found:?}",
                    ex.snippet
                ),
                Compliance::NonCompliant => {
                    found.unwrap_or_else(|| {
                        panic!("rule accepts its NonCompliant example {:?}", ex.snippet)
                    });
                    saw_a_finding = true;
                }
            }
        }
        assert!(saw_a_finding, "no published example produced a finding");
    }
}
