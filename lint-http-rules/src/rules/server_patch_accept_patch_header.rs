// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::helpers::headers::{
    combined_field_value_as_written, list_members_as_written, media_type_parts_defect,
    parse_media_type, shown_in_finding, trim_ows,
};
use crate::lint::Violation;
use crate::rules::Rule;

/// The `Accept-Patch` response header field: its grammar wherever it appears,
/// and the two responses RFC 5789 asks for it in.
///
/// **What this rule used to check.** It reported *any* response to a `PATCH`
/// that did not carry `Accept-Patch`, under the message *"PATCH response is
/// missing a valid Accept-Patch header declaring supported patch media types"*.
/// No sentence says that, and three say otherwise. The SHOULD is § 3.1's and it
/// is about the **OPTIONS** response; § 2.2 adds a second one for a **415**
/// answering a `PATCH`; and § 3 writes down that a server may advertise `PATCH`
/// without the field at all. RFC 5789 § 2.1's own worked example — the
/// successful `PATCH` exchange the document opens with, answered `204 No
/// Content` with `Content-Location` and `ETag` and no `Accept-Patch` — was
/// therefore a finding, and a `#[test]` below runs it.
pub struct ServerPatchAcceptPatchHeader;

impl ServerPatchAcceptPatchHeader {
    /// The field's own value, measured against `1#media-type`.
    ///
    /// `value` is the response header section's combined field value: one field
    /// section is one list however many lines carry it, so a member written on a
    /// second line is a member of this list, and an `Accept-Patch:` line beside a
    /// non-empty one is an empty *member* of it rather than a second empty
    /// field. Reading it as octets rather than through a UTF-8 decode is what
    /// keeps a value carrying `obs-text` measurable: an octet at or above %x80
    /// is one `field-content` admits and `token` does not, so it is the member
    /// that fails rather than the whole field becoming unreadable. Half of that
    /// was still untrue when this rule was written — every trim under
    /// `parse_media_type` was `str::trim`, which trims Unicode whitespace, and
    /// %xA0 and %x85 are Unicode whitespace once each octet is a `char` — so the
    /// two `obs-text` octets that most look like a space were the two the walk
    /// could not see.
    ///
    /// The `[RFC2616]` in the sentence that hands the members off is the RFC's
    /// own wording and stays byte-exact; § 3.7 of that document is RFC 9110
    /// § 8.3.1 today, which is where `media_type_parts_defect` takes the grammar
    /// from.
    ///
    /// cite(RFC 5789 § 3.1, label: Accept-Patch grammar): "Accept-Patch = "Accept-Patch" ":" 1#media-type"
    /// cite(RFC 5789 § 3.1): "The Accept-Patch header specifies a comma-separated listing of media-types (with optional parameters) as defined by [RFC2616], Section 3.7."
    fn check_value(&self, value: &str, config: &crate::rules::RuleConfig) -> Option<Violation> {
        let violation = |message: String| {
            Some(Violation {
                rule: self.id().to_string(),
                severity: config.severity,
                message,
            })
        };

        let mut saw_an_empty_element = false;
        let mut members_present = 0usize;

        // The split respects quoting because a `media-type`'s parameters may
        // carry a `quoted-string` value and a `quoted-string` may contain the
        // comma this list is delimited with — `application/example;q="a,b"` is
        // one member, not two.
        //
        // One `trim_ows` call standing on two sentences, because a one-member
        // list's only member is also the whole value. For an interior member it
        // is the `OWS` the list construct prints beside its commas; for the
        // outermost it is § 5.5's MUST on the parser, and that is the half that
        // decides a verdict — without it `Accept-Patch:   ` holds one member
        // that no `media-type` generates, and with it the field names no format
        // at all, which is what the `1#` floor below reports.
        //
        // The expansion quoted is the *sender's*, from § 5.6.1.1, and it is the
        // one this field has: `Accept-Patch` is `1#media-type`, so every position
        // in it holds an element and none of them is bracketed. § 5.6.1.2's
        // recipient expansion is the lenient reading that the empty-member branch
        // below explicitly declines to use.
        // cite(RFC 9110 § 5.6.1.1): "1#element => element *( OWS "," OWS element )"
        // cite(RFC 9110 § 5.5): "A field value does not include leading or trailing whitespace.  When a specific version of HTTP allows such whitespace to appear in a message, a field parsing implementation MUST exclude such whitespace prior to evaluating the field value."
        for member in list_members_as_written(value) {
            if member.is_empty() {
                // Reported after the members that are present, and reported as
                // the list's defect rather than the element's: there is no such
                // thing as an empty `media-type`, so what the sender generated is
                // a member advertising nothing. § 5.6.1.2 has the *recipient*
                // parse and ignore these, which is the other party's requirement
                // and would erase this one.
                //
                // cite(RFC 9110 § 5.6.1.1): "In any production that uses the list construct, a sender MUST NOT generate empty list elements."
                // cite(RFC 9110 § 5.6.1.2): "Empty elements do not contribute to the count of elements present.  A recipient MUST parse and ignore a reasonable number of empty list elements: enough to handle common mistakes by senders that merge values, but not so much that they could be used as a denial-of-service mechanism."
                saw_an_empty_element = true;
                continue;
            }

            members_present += 1;

            // Two shapes of "this is not a media-type at all" — no "/", or a
            // half with nothing in it — and the production is what says so. The
            // member is escaped for display: a value that failed a grammar check
            // is exactly the kind that carries an octet which would break the
            // line the finding is printed on.
            // cite(RFC 9110 § 8.3.1, label: media-type grammar): "media-type = type "/" subtype parameters"
            let Ok(parsed) = parse_media_type(member) else {
                return violation(format!(
                    "Accept-Patch member '{}' derives from no media-type: the production is a type and a subtype separated by '/', and neither may be empty",
                    shown_in_finding(member)
                ));
            };

            // What the two halves and the parameters after them must *be* is the
            // shared transcription of § 8.3.1 and § 5.6.6, which this rule was
            // the second caller of; the reason comes back as a clause so the
            // finding can name the field it was found in.
            //
            // The offending character arrives escaped rather than named as an
            // octet, which is a third rendering beside the two the `#token` walks
            // in this tree use. Recorded rather than harmonised: this value is
            // one `char` per octet only because the caller below read it as
            // octets, while the helper is also called on a `Content-Type` that
            // was not, so `describe_octet` would be claiming more than the helper
            // knows.
            if let Some(reason) = media_type_parts_defect(&parsed) {
                return violation(format!(
                    "Accept-Patch member '{}' derives from no media-type: {}",
                    shown_in_finding(member),
                    reason
                ));
            }

            // Not reported: an asterisk. `*` is a `tchar`, so `*/*` derives from
            // `media-type` and this field's grammar has no `media-range` in it
            // for one to mean anything — a server writing it has advertised a
            // media type spelled with an asterisk. That the exchange then
            // contradicts itself is `client_patch_method_content_type_match`'s
            // finding, against the request that took it for permission.
        }

        // The `1#` floor. § 5.6.1.2 prints the values this rejects, and they are
        // exactly the values above whose every position was empty: the empty
        // field value, a lone comma, and commas with only whitespace between
        // them.
        //
        // What the message does *not* say is that the server should have omitted
        // the field instead. RFC 5789 § 3's sentence about a `PATCH` in `Allow`
        // without an `Accept-Patch` beside it was quoted here to say so, and it
        // is about the OPTIONS response's `Allow` listing rather than about every
        // response's field — the same sentence is read at the OPTIONS branch
        // below, where it is load-bearing, and reading it as a general licence to
        // omit here would have contradicted that reading in the same file.
        // cite(RFC 9110 § 5.6.1.2): "In contrast, the following values would be invalid, since at least one non-empty element is required by the example-list production:"
        if members_present == 0 {
            return violation(format!(
                "Accept-Patch is `1#media-type` and names no patch document format; the response's field lines combine to '{}'",
                shown_in_finding(value)
            ));
        }

        if saw_an_empty_element {
            // The value is quoted as the section's *combined* value and the
            // message says so, because for the case this branch exists to catch
            // it is not a string the sender wrote: an `Accept-Patch:` line beside
            // an `Accept-Patch: text/example` line combines to `text/example,`,
            // whose comma is the join's. An operator grepping a capture for the
            // quoted text would otherwise find nothing.
            return violation(format!(
                "Accept-Patch holds an empty list element; the response's field lines combine to '{}'. Every position in `1#media-type` holds a media type, and a comma with nothing beside it holds none",
                shown_in_finding(value)
            ));
        }

        None
    }
}

/// Whether an `Allow` value names `PATCH` — the resource saying, in the words
/// § 3 gives a server for saying it, that it supports the method.
///
/// Compared exactly. A member spelled `patch` names a method this specification
/// does not define, and a resource advertising that one has said nothing about
/// `PATCH`. `message_allow_header_method_tokens` is the rule that measures this
/// value's grammar; this reads it and reports nothing about it.
///
/// cite(RFC 5789 § 3): "A server can advertise its support for the PATCH method by adding it to the listing of allowed methods in the "Allow" OPTIONS response header defined in HTTP/1.1."
/// cite(RFC 9110 § 10.2.1): "The "Allow" header field lists the set of methods advertised as supported by the target resource."
/// cite(RFC 9110 § 9.1): "The method token is case-sensitive because it might be used as a gateway to object-based systems with case-sensitive method names."
fn allow_names_patch(headers: &hyper::HeaderMap) -> bool {
    combined_field_value_as_written(headers, "allow")
        .is_some_and(|value| value.split(',').any(|member| trim_ows(member) == "PATCH"))
}

impl Rule for ServerPatchAcceptPatchHeader {
    fn id(&self) -> &'static str {
        "server_patch_accept_patch_header"
    }

    /// Every one of the three findings is about a response — the field is
    /// defined as a response header, and the two SHOULDs are addressed to a
    /// server generating one. `Server` is the scope that says so, and skipping a
    /// capture with no response costs nothing here because there is nothing in a
    /// request for this rule to measure.
    ///
    /// cite(RFC 5789 § 3.1): "This specification introduces a new response header Accept-Patch used to specify the patch document formats accepted by the server."
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

        // The field is read first and on every response, whatever method drew
        // it: § 3.1 defines it as a response header and describes its presence
        // "in response to any method", so wherever it appears its value is a
        // list of media types. Only the header section is read — whether a field
        // name may arrive as a trailer at all is § 6.5.1's question, asked of
        // every name at once by `message_trailer_fields_validity`.
        //
        // Each of the reads below is one `HeaderMap` probe, and
        // `parse_rule_config` is several map probes plus a hash over the rule
        // id; a response carrying no `Accept-Patch` and answering neither of the
        // two methods below is the overwhelming majority of traffic, so it pays
        // for none of them.
        //
        // cite(RFC 5789 § 3.1): "The presence of the Accept-Patch header in response to any method is an implicit indication that PATCH is allowed on the resource identified by the Request-URI."
        if let Some(value) = combined_field_value_as_written(&resp.headers, "accept-patch") {
            let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
            return self.check_value(&value, &config);
        }

        // Compared exactly, both of them: a request whose method is `patch` or
        // `options` is a request with some other method, and a method this
        // specification does not define has neither of these responses' meanings
        // for the field's absence to be measured against.
        // cite(RFC 9110 § 9.1): "The method token is case-sensitive because it might be used as a gateway to object-based systems with case-sensitive method names."
        if tx.request.method == "PATCH" {
            // § 2.2 names the status and then asks for the field in the response
            // carrying it. What a 415 means is most of that section's antecedent
            // — a format the server does not support — but not all of it: the
            // status is defined over the content's *coding* as well as its media
            // type, and a server refusing a coding has no patch format to name.
            // The status definition supplies its own tell for that case, so the
            // field a server sends when the coding was the problem stands this
            // finding down; a 415 about a coding that names none is the residue,
            // and `description()` says so.
            // cite(RFC 5789 § 2.2): "Can be specified using a 415 (Unsupported Media Type) response when the client sends a patch document format that the server does not support for the resource identified by the Request-URI."
            // cite(RFC 5789 § 2.2): "Such a response SHOULD include an Accept-Patch response header as described in Section 3.1 to notify the client what patch document media types are supported."
            // cite(RFC 9110 § 15.5.16): "The format problem might be due to the request's indicated Content-Type or Content-Encoding, or as a result of inspecting the data directly."
            // cite(RFC 9110 § 15.5.16): "If the problem was caused by an unsupported content coding, the Accept-Encoding response header field (Section 12.5.3) ought to be used"
            if resp.status == 415 && !resp.headers.contains_key("accept-encoding") {
                let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "415 (Unsupported Media Type) response to a PATCH carries no Accept-Patch; RFC 5789 § 2.2 says such a response SHOULD include an Accept-Patch response header to notify the client what patch document media types are supported".into(),
                });
            }

            return None;
        }

        if tx.request.method == "OPTIONS" {
            // The SHOULD's antecedent is "any resource that supports the use of
            // the PATCH method", and § 3 says in the sentence above it how a
            // server states that: by listing the method in the `Allow` of this
            // very response. So the two sentences together make the condition
            // observable in one exchange, and a resource that says nothing about
            // `PATCH` is asked for nothing.
            //
            // No status gate. The sibling rule reading an OPTIONS response gates
            // on 2xx because § 9.3.7's SHOULD carries the word "successful";
            // § 3.1's says "the OPTIONS response" and stops there, and a 405
            // answering an OPTIONS carries the `Allow` § 10.2.1 requires of it —
            // so a resource can advertise `PATCH` in a response that is not 2xx.
            //
            // The second sentence is quoted in the finding and is the reason the
            // first one is reported at all rather than written off: it leaves
            // the `Allow` listing conforming and then names the consequence of
            // the omission rather than excusing it, which is what a SHOULD
            // already means. Read the other way it would empty § 3.1's SHOULD of
            // every case it could ever be measured against.
            //
            // The asterisk target is out for the reason the SHOULD is in: its
            // subject is a *resource*, and such a request has none — the `Allow`
            // of that response lists what the server in general does, so it
            // states nothing about a resource supporting `PATCH`. The comparison
            // reaches the asterisk over HTTP/1.1 only, for the reason the sibling
            // OPTIONS rule records at the same gate: the HTTP/3 capture path
            // rebuilds a URI from the pseudo-headers and a `:path` of `*` is
            // recorded as an authority with the asterisk swallowed into it.
            //
            // cite(RFC 5789 § 3.1): "Accept-Patch SHOULD appear in the OPTIONS response for any resource that supports the use of the PATCH method."
            // cite(RFC 5789 § 3): "The PATCH method MAY appear in the "Allow" header even if the Accept-Patch header is absent, in which case the list of allowed patch documents is not advertised."
            // cite(RFC 9110 § 9.3.7): "An OPTIONS request with an asterisk ("*") as the request target (Section 7.1) applies to the server in general rather than to a specific resource."
            if tx.request.uri != "*" && allow_names_patch(&resp.headers) {
                let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!(
                        "OPTIONS response ({}) advertises PATCH in Allow and carries no Accept-Patch; RFC 5789 § 3.1 says Accept-Patch SHOULD appear in the OPTIONS response for any resource that supports the use of the PATCH method. § 3 leaves the Allow listing conforming without it and names what is lost: the list of allowed patch documents is not advertised",
                        resp.status
                    ),
                });
            }
        }

        None
    }

    fn title(&self) -> Option<&'static str> {
        Some("Server Accept-Patch Header")
    }

    fn description(&self) -> &'static str {
        "Checks the `Accept-Patch` response header field — its grammar wherever it appears, and the two responses RFC 5789 asks for it in.\n\n**The grammar, on every response that carries the field.** `Accept-Patch = \"Accept-Patch\" \":\" 1#media-type` (RFC 5789 §3.1), so every member is a media type: `type \"/\" subtype parameters` with each half a `token` and each parameter a `name=value` pair (RFC 9110 §8.3.1, §5.6.6). §3.1 hands the members off to \"[RFC2616], Section 3.7\", which is §8.3.1 today. The field is read on a response to any method, because §3.1 describes its presence \"in response to any method\" as an indication about the resource — an `Accept-Patch` sent in the OPTIONS response §3.1 asks for it in used to be validated by nothing at all. `1#` has a floor of one: `Accept-Patch:` and `Accept-Patch: ,` name no format and are the values §5.6.1.2 prints as invalid, while `Accept-Patch: text/example,` holds an empty member, which a sender MUST NOT generate (§5.6.1.1). Where the field appears on several lines in one section, the lines are one list (§5.2).\n\n**Where the field is asked for, and where it is not.** Two sentences, both SHOULD:\n\n- §2.2 — a `415 (Unsupported Media Type)` answering a `PATCH` \"SHOULD include an Accept-Patch response header ... to notify the client what patch document media types are supported\". A 415 is what a server sends when the client's format is one it does not support — but RFC 9110 §15.5.16 defines the status over the content's *coding* too, and a server refusing a coding has no patch format to name. The same section says such a server \"ought to\" send `Accept-Encoding`, so a 415 carrying that field stands this finding down. The residue is a 415 that was about a coding and named none; it is reported, and there is nothing in the message that says which of the two happened.\n- §3.1 — \"Accept-Patch SHOULD appear in the OPTIONS response for any resource that supports the use of the PATCH method\". §3 says how a resource states that support: by listing the method in the `Allow` of that response. So the finding is an OPTIONS response whose `Allow` names `PATCH` and which carries no `Accept-Patch`. An `OPTIONS *` request is out: RFC 9110 §9.3.7 says such a request \"applies to the server in general rather than to a specific resource\", so its `Allow` states nothing about the resource §3.1's sentence is about. §3 leaves such a response's `Allow` listing conforming and names the cost — \"the list of allowed patch documents is not advertised\" — which the finding repeats rather than treating as an exemption; a SHOULD that no case could ever be measured against would be a sentence with nothing under it.\n\n**Not reported: a successful `PATCH` response with no `Accept-Patch`.** This rule used to report every response to a `PATCH` that lacked the field. Nothing asks for it there. RFC 5789 §2.1's own worked example is a successful `PATCH` answered `204 No Content` with `Content-Location` and `ETag` and no `Accept-Patch`, so the document's first illustration of the method was a finding; a test runs it.\n\n**Not reported: an asterisk.** `*` is a `tchar`, so `Accept-Patch: */*` derives from `media-type`, and this field's grammar contains no `media-range` for a wildcard to mean anything in. A server writing it has advertised a media type spelled with an asterisk. `client_patch_method_content_type_match` reports the request that reads it as permission.\n\n**Not reported: which formats are advertised.** RFC 5789 defines no default patch document format and no registry of them, so no list of media types is the right one. Whether a `PATCH` request's `Content-Type` is among those advertised is `client_patch_method_content_type_match`'s question; whether a `PATCH` carrying content names its format at all is `semantic_patch_partial_update`'s.\n\nScope: responses only — §3.1 defines `Accept-Patch` as a response header, and an `Accept-Patch` in a request is measured by nothing here. A trailer section is not read: whether a field name may arrive as a trailer at all is §6.5.1's question, asked of every name at once by `message_trailer_fields_validity`. Method comparisons are exact, because the method token is case-sensitive (§9.1)."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 5789",
                section: Some("3.1"),
                url: "https://www.rfc-editor.org/rfc/rfc5789.html#section-3.1",
                note: "The field: its grammar, its definition as a response header, its meaning in a response to any method, and the SHOULD that asks for it — in the OPTIONS response, not in the response to a PATCH. This reference said §2.2, which is Error Handling — and §2.2 turned out to hold a second SHOULD, listed below",
            },
            crate::rules::SpecRef {
                spec: "RFC 5789",
                section: Some("3"),
                url: "https://www.rfc-editor.org/rfc/rfc5789.html#section-3",
                note: "Advertising support in OPTIONS — how a resource says it supports PATCH, which is the antecedent §3.1's SHOULD needs, and the sentence that leaves an Allow listing conforming without the field while naming what its absence costs",
            },
            crate::rules::SpecRef {
                spec: "RFC 5789",
                section: Some("2.2"),
                url: "https://www.rfc-editor.org/rfc/rfc5789.html#section-2.2",
                note: "Error handling — the second SHOULD: a 415 answering a PATCH is told to carry the field, and what a 415 means is the whole of that requirement's condition",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("8.3.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3.1",
                note: "`media-type`, transcribed once in `helpers::headers` and shared with the Content-Type rule. It is where RFC 5789 §3.1's pointer at `[RFC2616], Section 3.7` resolves today; the obsolete name stays byte-exact inside the quote because it is the RFC's own wording",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("5.6.1.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.2",
                note: "The list construct expanded, and the worked example naming the values a `1#` production rejects for holding no non-empty member. §5.6.1.1 is the sender's half — the empty-member finding",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("9.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-9.1",
                note: "The method token is case-sensitive, which is why `PATCH` and `OPTIONS` are compared exactly and a `patch` request draws nothing from this rule",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("10.2.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.1",
                note: "`Allow` — the value read to decide whether the OPTIONS response's resource supports PATCH. Its own grammar is `message_allow_header_method_tokens`'s",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("§3.2's own OPTIONS exchange"),
                snippet: "OPTIONS /example/buddies.xml HTTP/1.1\nHost: www.example.com\n\nHTTP/1.1 200 OK\nAllow: GET, PUT, POST, OPTIONS, HEAD, DELETE, PATCH\nAccept-Patch: application/example, text/example",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some(
                    "§2.1's own successful PATCH — nothing asks a response like this for the field",
                ),
                snippet: "PATCH /file.txt HTTP/1.1\nHost: www.example.com\nContent-Type: application/example\n\nHTTP/1.1 204 No Content\nContent-Location: /file.txt\nETag: \"e0023aa4f\"",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("Two field lines in one section are one list"),
                snippet: "HTTP/1.1 200 OK\nAccept-Patch: application/example-patch+json\nAccept-Patch: application/merge-patch+json",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("A member that is no media-type — there is no '/'"),
                snippet: "HTTP/1.1 200 OK\nAccept-Patch: badmedia",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("A `1#` list with no non-empty member names no format"),
                snippet: "HTTP/1.1 200 OK\nAccept-Patch: ,",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("A trailing comma is an empty member"),
                snippet: "HTTP/1.1 200 OK\nAccept-Patch: application/example,",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("§2.2's SHOULD — a 415 answering a PATCH says which formats it takes"),
                snippet: "PATCH /file.txt HTTP/1.1\nHost: www.example.com\nContent-Type: application/example\n\nHTTP/1.1 415 Unsupported Media Type",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("§3.1's SHOULD — the resource advertises PATCH and not its formats"),
                snippet: "OPTIONS /example/buddies.xml HTTP/1.1\nHost: www.example.com\n\nHTTP/1.1 200 OK\nAllow: GET, PUT, POST, OPTIONS, HEAD, DELETE, PATCH",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ServerPatchAcceptPatchHeader;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_transaction::ResponseInfo;
    use crate::test_helpers::make_test_transaction;
    use hyper::header::HeaderValue;
    use hyper::HeaderMap;
    use rstest::rstest;

    /// Run the rule over a transaction whose request carries `method` and whose
    /// response carries `status` plus the given response field lines.
    ///
    /// The lines are appended rather than inserted, because several field lines
    /// in one section are what the joining is about and a single-line helper
    /// cannot reach the case; they are raw octets, because a value carrying
    /// `obs-text` is not a string any Rust source file can stand in for.
    fn check(method: &str, status: u16, lines: &[(&str, &[u8])]) -> Option<Violation> {
        check_target(method, None, status, lines)
    }

    /// The same, with the request target written by hand. The shared fixture
    /// builds an absolute-form URI, and the one request target this rule reads
    /// is the asterisk — which no default fixture produces.
    fn check_target(
        method: &str,
        uri: Option<&str>,
        status: u16,
        lines: &[(&str, &[u8])],
    ) -> Option<Violation> {
        let rule = ServerPatchAcceptPatchHeader;
        let mut tx = make_test_transaction();
        tx.request.method = method.into();
        if let Some(uri) = uri {
            tx.request.uri = uri.into();
        }

        let mut headers = HeaderMap::new();
        for (name, value) in lines {
            headers.append(
                hyper::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_bytes(value).unwrap(),
            );
        }

        tx.response = Some(ResponseInfo {
            status,
            version: "HTTP/1.1".into(),
            headers,
            body_length: None,
            trailers: None,
        });

        rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
    }

    fn accept_patch(value: &str) -> Option<Violation> {
        check("PATCH", 200, &[("accept-patch", value.as_bytes())])
    }

    /// The value is `1#media-type`, and these members are media types.
    #[rstest]
    #[case("application/example-patch+json")]
    #[case("application/example, text/example")]
    #[case("application/example,text/example")]
    #[case("text/example;charset=utf-8")]
    #[case("application/example;q=\"a,b\"")]
    // `*` is a `tchar`. What an asterisk means in this field is the neighbour's
    // question, not this one's; the grammar admits it.
    #[case("*/*")]
    #[case("application/*")]
    fn a_list_of_media_types_is_what_the_field_is(#[case] value: &str) {
        assert!(
            accept_patch(value).is_none(),
            "Accept-Patch: {} — {:?}",
            value,
            accept_patch(value)
        );
    }

    /// A member that derives from no `media-type`.
    #[rstest]
    #[case("badmedia")]
    #[case("application/example, badmedia")]
    #[case("/example")]
    #[case("application/")]
    #[case("appl ication/example")]
    #[case("application/exa mple")]
    // `media-type = type "/" subtype` prints no `OWS` between the halves, and
    // each half used to be trimmed before the character scan saw it.
    #[case("application / example")]
    #[case("application /example")]
    #[case("application/ example")]
    #[case("application/example;charset")]
    #[case("application/example;=utf-8")]
    #[case("application/example;charset=utf 8")]
    #[case("application/example;char set=utf-8")]
    fn a_member_that_derives_from_no_media_type_is_reported(#[case] value: &str) {
        let violation = accept_patch(value).expect("member is not a media-type");
        assert!(
            violation.message.contains("derives from no media-type"),
            "{}",
            violation.message
        );
    }

    /// The `1#` floor: § 5.6.1.2 prints exactly these as the values a `1#`
    /// production rejects. The rule used to report the whole field's absence on
    /// every PATCH response and accept `Accept-Patch: ,` on any other.
    #[rstest]
    #[case("")]
    #[case(",")]
    #[case(",   ,")]
    #[case("   ")]
    fn a_list_with_no_non_empty_member_names_no_format(#[case] value: &str) {
        let violation = accept_patch(value).expect("1# has a floor of one");
        assert!(
            violation.message.contains("names no patch document format"),
            "{}",
            violation.message
        );
    }

    /// An empty member is not an empty list — the other side of the same
    /// sentence, and the branch that separates them is the count of members
    /// present.
    #[rstest]
    #[case("application/example,")]
    #[case(",application/example")]
    #[case("application/example,,text/example")]
    fn an_empty_member_is_not_an_empty_list(#[case] value: &str) {
        let violation = accept_patch(value).expect("empty list element is reported");
        assert!(
            violation.message.contains("empty list element"),
            "{}",
            violation.message
        );
    }

    /// One field section is one list however many lines carry it. Reading the
    /// lines one at a time answered both directions of this backwards: it
    /// accepted the whole field as soon as any one line held a media type, so a
    /// malformed second line went unreported.
    #[test]
    fn field_lines_in_one_section_are_one_list() {
        assert!(check(
            "PATCH",
            200,
            &[
                ("accept-patch", b"application/example"),
                ("accept-patch", b"text/example"),
            ]
        )
        .is_none());

        let violation = check(
            "PATCH",
            200,
            &[
                ("accept-patch", b"application/example"),
                ("accept-patch", b"badmedia"),
            ],
        )
        .expect("a malformed second line is a malformed member");
        assert!(
            violation.message.contains("badmedia"),
            "{}",
            violation.message
        );

        // The comma in the quoted value is the join's, and the finding says the
        // lines were combined rather than quoting a string either line carries.
        let empty = check(
            "PATCH",
            200,
            &[
                ("accept-patch", b"application/example"),
                ("accept-patch", b""),
            ],
        )
        .expect("an empty second line is an empty member");
        assert!(
            empty
                .message
                .contains("field lines combine to 'application/example,'"),
            "{}",
            empty.message
        );
    }

    /// `obs-text` is an octet `field-content` admits and `token` does not.
    /// Reading the value through `to_str` turned the whole field into "this
    /// response carries no Accept-Patch" — and, in the rule as it stood, into a
    /// finding whose message named UTF-8, which is not a thing HTTP has an
    /// opinion about.
    ///
    /// The octets are chosen for the second half of the story: %xC9 is the easy
    /// one, and %xA0 and %x85 are the two that reach a `char` which `str::trim`
    /// calls whitespace. Every trim under `parse_media_type` was `str::trim`, so
    /// those two were removed before any check saw them and
    /// `application/example%xA0` came back clean. A test using only %xC9 passes
    /// for a reason unrelated to what it asserts.
    #[rstest]
    #[case(b"application/exa\xC9mple")]
    #[case(b"application/example\xA0")]
    #[case(b"\xA0application/example")]
    #[case(b"application/example\x85")]
    #[case(b"application/example;charset=utf-8\xA0")]
    #[case(b"application/example;\xA0charset=utf-8")]
    fn obs_text_is_measured_rather_than_skipped(#[case] value: &[u8]) {
        let violation =
            check("PATCH", 200, &[("accept-patch", value)]).expect("obs-text is not a tchar");
        assert!(
            violation.message.contains("derives from no media-type"),
            "{:?} -> {}",
            value,
            violation.message
        );
        assert!(
            !violation.message.contains("UTF"),
            "the finding is about the grammar, not about a decoder: {}",
            violation.message
        );
    }

    /// A finding quotes what the sender wrote, and what the sender wrote is
    /// exactly the kind of value that carries an octet printing as nothing. Both
    /// halves of the message go through an escape — the member, and the reason
    /// clause the shared helper returns beside it.
    ///
    /// HTAB is the only control octet these cases can use, and that is a fact
    /// about the capture rather than about the grammar: a `HeaderValue` admits
    /// SP, HTAB, %x21-7E and `obs-text` and nothing else, so no capture read back
    /// through a `HeaderMap` can carry %x01. The escape is still applied to every
    /// interpolated value, because the shared helper is also called on a
    /// `Content-Type` assembled elsewhere.
    #[rstest]
    #[case(b"application/example;p\tq")]
    #[case(b"applic\tation/example")]
    #[case(b"application/exam\tple;charset=utf-8")]
    fn no_finding_carries_a_raw_control_octet(#[case] value: &[u8]) {
        let violation = check("PATCH", 200, &[("accept-patch", value)])
            .unwrap_or_else(|| panic!("{:?} derives from no media-type", value));
        assert!(
            !violation.message.chars().any(|c| c.is_control()),
            "{:?} -> {:?}",
            value,
            violation.message
        );
    }

    /// The one leniency this rule inherited from the shared `media-type` walk,
    /// asserted rather than left silent. `parameter` is
    /// `parameter-name "=" parameter-value` with no `OWS` in it, and § 5.6.6 says
    /// so again in prose — but the whitespace beside the `=` is trimmed, which is
    /// the reading three other rules in this tree publish as a known leniency.
    /// Changing it is their audits' work; a test here is what keeps it from being
    /// mistaken for the grammar.
    #[rstest]
    #[case("application/example;charset = utf-8")]
    #[case("application/example;charset =utf-8")]
    #[case("application/example;charset= utf-8")]
    fn whitespace_beside_the_equals_is_the_inherited_leniency(#[case] value: &str) {
        assert!(accept_patch(value).is_none());
    }

    /// The claim the rewrite is named for: the field is measured on a response
    /// to *any* method, because § 3.1 describes its presence "in response to any
    /// method". The rule this replaced read it only on a response to a `PATCH`,
    /// so the `Accept-Patch` in the OPTIONS response § 3.1 asks for it in was
    /// validated by nothing in the tree.
    #[rstest]
    #[case("GET")]
    #[case("OPTIONS")]
    #[case("HEAD")]
    #[case("POST")]
    fn the_value_is_measured_on_a_response_to_any_method(#[case] method: &str) {
        let violation = check(method, 200, &[("accept-patch", b"badmedia")])
            .unwrap_or_else(|| panic!("a malformed Accept-Patch is malformed on a {}", method));
        assert!(
            violation.message.contains("derives from no media-type"),
            "{}",
            violation.message
        );

        assert!(
            check(method, 200, &[("accept-patch", b",")]).is_some(),
            "the `1#` floor holds on a response to {} too",
            method
        );
    }

    /// § 2.2's SHOULD, and the two halves of what a 415 is about.
    #[test]
    fn a_415_answering_a_patch_is_asked_for_the_field() {
        let violation = check("PATCH", 415, &[]).expect("§2.2 asks a 415 for the field");
        assert!(violation.message.contains("415"), "{}", violation.message);

        assert!(
            check("PATCH", 415, &[("accept-patch", b"application/example")]).is_none(),
            "the field is there"
        );
        assert!(
            check("GET", 415, &[]).is_none(),
            "§2.2 is about a response to a PATCH"
        );
        // RFC 9110 §15.5.16 defines the status over the content's coding as well
        // as its media type, and names the field a server sends when the coding
        // was the problem. Such a server has no patch document format to name,
        // so §2.2's antecedent is not met.
        assert!(
            check("PATCH", 415, &[("accept-encoding", b"gzip, deflate")]).is_none(),
            "the server said the coding was the problem"
        );
        // A malformed value is still a malformed value on this response; the
        // presence branch never runs when the field is there.
        let malformed =
            check("PATCH", 415, &[("accept-patch", b"badmedia")]).expect("the value is measured");
        assert!(
            malformed.message.contains("derives from no media-type"),
            "{}",
            malformed.message
        );
    }

    /// § 3.1's SHOULD, with § 3's sentence supplying the antecedent: the
    /// resource says it supports PATCH by listing the method in `Allow`.
    #[test]
    fn an_options_response_advertising_patch_is_asked_for_the_field() {
        let violation = check("OPTIONS", 200, &[("allow", b"GET, PUT, PATCH")])
            .expect("§3.1 asks the OPTIONS response for the field");
        assert!(
            violation.message.contains("advertises PATCH in Allow"),
            "{}",
            violation.message
        );

        assert!(
            check(
                "OPTIONS",
                200,
                &[
                    ("allow", b"GET, PUT, PATCH"),
                    ("accept-patch", b"text/example")
                ]
            )
            .is_none(),
            "the field is there"
        );
        assert!(
            check("OPTIONS", 200, &[("allow", b"GET, PUT")]).is_none(),
            "the resource says nothing about PATCH"
        );
        assert!(
            check("OPTIONS", 200, &[]).is_none(),
            "no Allow is no statement of support"
        );
        // A 405 answering an OPTIONS carries the `Allow` §10.2.1 requires of it,
        // and §3.1's SHOULD says "the OPTIONS response" without a word about
        // success — so this is measured where the sibling OPTIONS rule stops.
        assert!(
            check("OPTIONS", 405, &[("allow", b"GET, PATCH")]).is_some(),
            "§3.1 carries no `successful`"
        );
        // `Allow` is a list however many lines carry it, and the member the rule
        // is looking for can be on the second one.
        assert!(
            check("OPTIONS", 200, &[("allow", b"GET"), ("allow", b"PATCH")]).is_some(),
            "one field section is one list"
        );
    }

    /// The method token is case-sensitive, and an `Allow` member is a `method`.
    /// A resource advertising `patch` has advertised a method this
    /// specification does not define and has said nothing about `PATCH`.
    #[rstest]
    #[case(b"GET, patch")]
    #[case(b"PATCHY")]
    #[case(b"XPATCH")]
    fn an_allow_member_that_is_not_the_patch_method_says_nothing(#[case] allow: &[u8]) {
        assert!(check("OPTIONS", 200, &[("allow", allow)]).is_none());
    }

    /// An asterisk target names no resource, and § 3.1's SHOULD is about one.
    /// The `Allow` of such a response lists what the server does in general.
    #[test]
    fn an_asterisk_target_has_no_resource_for_the_sentence_to_be_about() {
        assert!(
            check_target("OPTIONS", Some("*"), 200, &[("allow", b"GET, PATCH")]).is_none(),
            "OPTIONS * applies to the server in general"
        );
        // The same response at a real target is the finding, so the gate above
        // is the only difference between the two.
        assert!(check_target(
            "OPTIONS",
            Some("http://example.com/r"),
            200,
            &[("allow", b"GET, PATCH")]
        )
        .is_some());
        // The field's own grammar is still measured on such a response: the
        // asterisk gate is on the SHOULD, not on the value.
        assert!(
            check_target("OPTIONS", Some("*"), 200, &[("accept-patch", b"badmedia")]).is_some(),
            "a malformed value is malformed wherever it was sent"
        );
    }

    /// The method token is case-sensitive, so neither absence branch fires on a
    /// method this specification does not define.
    #[rstest]
    #[case("patch", 415u16, &[][..])]
    #[case("options", 200, &[("allow", b"GET, PATCH".as_slice())][..])]
    fn the_method_is_compared_exactly(
        #[case] method: &str,
        #[case] status: u16,
        #[case] lines: &[(&str, &[u8])],
    ) {
        assert!(check(method, status, lines).is_none());
    }

    /// The rule used to report every response to a `PATCH` that did not carry
    /// the field. RFC 5789 § 2.1's own worked example is one, so the document's
    /// first illustration of the method was a finding.
    #[test]
    fn the_specifications_own_successful_patch_is_clean() {
        assert!(check(
            "PATCH",
            204,
            &[
                ("content-location", b"/file.txt"),
                ("etag", b"\"e0023aa4f\"")
            ]
        )
        .is_none());
    }

    /// A response carrying neither the field nor either of the two methods'
    /// conditions is the overwhelming majority of traffic, and this rule says
    /// nothing about it.
    #[rstest]
    #[case("GET", 200u16)]
    #[case("PATCH", 200)]
    #[case("PATCH", 400)]
    #[case("POST", 415)]
    fn nothing_is_asked_of_a_response_no_sentence_names(#[case] method: &str, #[case] status: u16) {
        assert!(check(method, status, &[]).is_none());
    }

    #[test]
    fn scope_is_server_because_every_finding_is_about_a_response() {
        assert_eq!(
            ServerPatchAcceptPatchHeader.scope(),
            crate::rules::RuleScope::Server
        );
    }

    /// Every published example is a case this rule actually decides the way the
    /// label claims. The example set this replaced asserted that a response to a
    /// `PATCH` with no `Accept-Patch` was non-compliant, which is the finding
    /// this iteration deleted.
    #[test]
    fn published_examples_agree_with_the_rule() {
        use crate::rules::Compliance;

        let mut asserted_a_finding = false;

        for example in ServerPatchAcceptPatchHeader.examples() {
            // The snippet is a request half, a blank line, and a response half;
            // a snippet with no blank line is a response on its own.
            let (request, response) = match example.snippet.split_once("\n\n") {
                Some((req, resp)) => (req, resp),
                None => ("PATCH / HTTP/1.1", example.snippet),
            };

            let method = request
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().next())
                .expect("a request line names a method");

            let mut lines = response.lines();
            let status: u16 = lines
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|s| s.parse().ok())
                .expect("a status line names a status code");

            let fields: Vec<(String, Vec<u8>)> = lines
                .filter_map(|l| l.split_once(": "))
                .map(|(n, v)| (n.to_ascii_lowercase(), v.as_bytes().to_vec()))
                .collect();
            let borrowed: Vec<(&str, &[u8])> = fields
                .iter()
                .map(|(n, v)| (n.as_str(), v.as_slice()))
                .collect();

            let violation = check(method, status, &borrowed);
            match example.compliance {
                Compliance::Compliant => assert!(
                    violation.is_none(),
                    "compliant example reported: {} -> {:?}",
                    example.snippet,
                    violation
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

        assert!(
            asserted_a_finding,
            "the guard is vacuous unless at least one example produces a finding"
        );
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "server_patch_accept_patch_header");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
