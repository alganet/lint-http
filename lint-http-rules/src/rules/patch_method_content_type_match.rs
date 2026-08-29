// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// Reports a `PATCH` whose `Content-Type` names a patch document format no
/// response for this resource has advertised in `Accept-Patch`.
///
/// The advertisement is the only thing in a capture that says which formats a
/// server takes — RFC 5789 defines no default patch document format and no
/// registry of them, which is why `patch_partial_update` can require
/// the field on a `PATCH` and not judge its value.
pub struct PatchMethodContentTypeMatch;

/// A media type as this rule compares them: `type/subtype`, lowercased, or
/// `None` where the value names no media type at all.
///
/// The grammar is read here rather than through `parse_media_type`, whose own
/// doc comment says it does not validate the tokens: it locates the delimiters
/// and `str::trim`s around each of them, and `str::trim` removes **Unicode**
/// whitespace. A value read octet by octet carries U+00A0 for the octet %xA0,
/// which is `obs-text` and not whitespace of any kind, so that trim would turn
/// `application/example` + %xA0 — a member no production admits — into a clean
/// advertisement the server never made. Only `OWS` is trimmed here, and only
/// where the grammar puts it; everything between the delimiters is measured.
///
/// It matters in both directions. On the advertisement side a tidied member
/// would suppress a finding; on the request side a malformed value would be
/// compared and reported as unadvertised, which is
/// `content_type_valid`'s finding and not this rule's. An asterisk
/// survives, `*` being a `tchar`; what that means for this field is decided at
/// the comparison.
///
/// Parameters are dropped rather than compared. Whether one matters is a
/// property of the media type's registration and not of either message, so two
/// values differing only in a parameter are not comparable here. The first `;`
/// is the boundary: a `quoted-string` can only appear in a parameter value, so
/// there is none in front of it to hide one.
///
/// cite(RFC 9110 § 8.3.1): "media-type = type "/" subtype parameters type       = token subtype    = token"
/// cite(RFC 9110 § 8.3.1): "The presence or absence of a parameter might be significant to the processing of a media type, depending on its definition within the media type registry."
/// cite(RFC 9110 § 8.3.1): "The type and subtype tokens are case-insensitive."
fn normalized_media_type(val: &str) -> Option<String> {
    let media = crate::helpers::headers::trim_ows(val.split(';').next()?);
    let (type_, subtype) = media.split_once('/')?;
    // `token = 1*tchar`, so an absent one is not one; `/` is not a `tchar`, so a
    // second slash fails here rather than needing a count of its own.
    if type_.is_empty()
        || subtype.is_empty()
        || crate::helpers::token::find_invalid_token_char(type_).is_some()
        || crate::helpers::token::find_invalid_token_char(subtype).is_some()
    {
        return None;
    }
    let mut out = String::with_capacity(media.len());
    out.push_str(type_);
    out.push('/');
    out.push_str(subtype);
    out.make_ascii_lowercase();
    Some(out)
}

/// Every patch document format a response advertised, in the order written, or
/// `None` where the response carried no `Accept-Patch` at all — which is a
/// different answer from an empty list, where it carried one that named no
/// format.
///
/// The field is a list, so its lines are one list however many carry it, and the
/// join is over the octets: a member outside US-ASCII is not a `media-type`, but
/// it is that *member* that fails, and the members beside it are still
/// advertisements. A member no grammar admits is skipped rather than reported —
/// this rule reads the advertisement, it does not judge it, and such a member
/// cannot equal a request's `Content-Type`, which has to parse to be compared at
/// all. `accept_patch_header_valid` is the rule that judges the value.
///
/// The split respects quoting because a parameter value may be a `quoted-string`
/// and a `quoted-string` may contain the comma the list is delimited with.
///
/// The `[RFC2616]` in the sentence that hands the members off is the RFC's own
/// wording and stays byte-exact; §3.7 of that document is RFC 9110 §8.3.1 today,
/// which is where `parse_media_type` takes the grammar from and where the two
/// RFC 9110 sentences below come from.
///
/// cite(RFC 5789 § 3.1, label: Accept-Patch grammar): "Accept-Patch = "Accept-Patch" ":" 1#media-type"
/// cite(RFC 5789 § 3.1): "The Accept-Patch header specifies a comma-separated listing of media-types (with optional parameters) as defined by [RFC2616], Section 3.7."
/// cite(RFC 9110 § 8.3.1): "The type/subtype MAY be followed by semicolon-delimited parameters (Section 5.6.6) in the form of name/value pairs."
/// cite(RFC 9110 § 5.6.6, label: parameter-value grammar): "parameter-value = ( token / quoted-string )"
fn advertised_formats(headers: &hyper::HeaderMap) -> Option<Vec<String>> {
    let joined = crate::helpers::headers::combined_field_value_as_written(headers, "accept-patch")?;
    Some(
        crate::helpers::list::split_commas_respecting_quotes(&joined)
            .into_iter()
            .filter_map(normalized_media_type)
            .collect(),
    )
}

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_5789_3_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 5789",
    section: Some("3.1"),
    url: "https://www.rfc-editor.org/rfc/rfc5789.html#section-3.1",
    note: "The `Accept-Patch` header — the patch document formats a server accepts, advertised per resource and readable from a response to any method. This reference said §2.2, which is Error Handling",
};
const RFC_5789_2_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 5789",
    section: Some("2.2"),
    url: "https://www.rfc-editor.org/rfc/rfc5789.html#section-2.2",
    note: "Error handling — `415 (Unsupported Media Type)` is what a server may answer a format it does not support with, which is the consequence this rule anticipates rather than a requirement it enforces",
};
const RFC_9110_12_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("12.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-12.3",
    note: "Request content negotiation — enrols `Accept-Patch` among the preferences a server sends to influence the content of subsequent requests, which is what lets §12.4.3 reach it",
};
const RFC_9110_12_4_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("12.4.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-12.4.3",
    note: "Wildcard values — a field has one only where its own definition indicates one, and where none is present the values not mentioned are considered unacceptable. Both halves of this rule",
};
const RFC_9110_8_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("8.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3",
    note: "`Content-Type` is a singleton, and recipients differ over which member wins when it is sent more than once — so a duplicated field states no media type to compare",
};
const RFC_9110_8_3_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("8.3.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3.1",
    note: "The `media-type` grammar: type and subtype are case-insensitive, and whether a parameter is significant depends on the media type's registration",
};

impl Rule for PatchMethodContentTypeMatch {
    fn id(&self) -> &'static str {
        "patch_method_content_type_match"
    }

    /// The finding is about the request this transaction carries; the response
    /// it is measured against belongs to an *earlier* transaction. So the rule
    /// needs no response of its own, and `Client` keeps it running on a capture
    /// that has none.
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
    }

    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // Single-finding body behind an Option: `?` ends it early, and the
        // one finding (or none) becomes the vector.
        let finding = || -> Option<Violation> {
            // Compared exactly: a request whose method is `patch` is a request with
            // some other method, and its content has whatever semantics that method
            // gives it. `request_method_token_valid` reports the spelling.
            //
            // cite(RFC 9110 § 9.1): "The method token is case-sensitive because it might be used as a gateway to object-based systems with case-sensitive method names."
            if tx.request.method != "PATCH" {
                return None;
            }

            // What the client said it was sending, settled before the history is
            // walked: every arm below is a decline, and none of them needs to know
            // what was advertised.
            //
            // A singleton field, so its lines are not joined: more than one and the
            // media type the peer acts on is not the one the message states, which
            // makes the comparison meaningless. `content_type_valid`
            // reports the duplication.
            //
            // cite(RFC 9110 § 8.3): "Although Content-Type is defined as a singleton field, it is sometimes incorrectly generated multiple times, resulting in a combined field value that appears to be a list."
            // cite(RFC 9110 § 8.3): "Recipients often attempt to handle this error by using the last syntactically valid member of the list, leading to potential interoperability and security issues if different implementations have different error handling behaviors."
            let mut lines = tx.request.headers.get_all("content-type").iter();
            let ct = lines.next()?;
            if lines.next().is_some() {
                return None;
            }

            // Read as octets, one `char` per octet, because a parameter value may be
            // a `quoted-string` and `qdtext` admits `obs-text` — so a media type this
            // rule can compare may legitimately arrive with a byte `to_str` refuses,
            // and refusing the whole value would lose the type and subtype with it.
            // Whether those two are tokens is `normalized_media_type`'s question; a
            // value that answers no is `content_type_valid`'s finding,
            // and a `PATCH` carrying content with no field at all is
            // `patch_partial_update`'s.
            //
            // cite(RFC 9110 § 5.5): "A recipient SHOULD treat other allowed octets in field content (i.e., obs-text) as opaque data."
            let ct: String = ct.as_bytes().iter().map(|&b| b as char).collect();
            let sent = normalized_media_type(&ct)?;

            // The most recent response for this resource that carried the field, not
            // merely the most recent response: the advertisement is discovery, and a
            // client that asked once and then made other requests still has it.
            // Which method drew that response does not matter, and the section says
            // so — the history is scoped to one resource by the rule's `ByResource`
            // query, which is the other half of the same sentence. The search stops
            // at the first response carrying the field even when nothing in it
            // parses: that is the server's current statement of what it accepts, and
            // reaching past it would measure the request against one the resource has
            // since replaced.
            //
            // cite(RFC 5789 § 3.1): "The presence of the Accept-Patch header in response to any method is an implicit indication that PATCH is allowed on the resource identified by the Request-URI."
            let advertised = history
                .iter()
                .find_map(|prev| advertised_formats(&prev.response.as_ref()?.headers))?;
            if advertised.is_empty() {
                return None;
            }

            // cite(RFC 5789 § 3.1): "The presence of a specific patch document format in this header indicates that that specific format is allowed on the resource identified by the Request-URI."
            if advertised.contains(&sent) {
                return None;
            }

            // `Accept-Patch` is `1#media-type`, so it has no wildcard form: the
            // asterisk belongs to `Accept`'s `media-range`, a different production in
            // a different field. A server writing `*/*` here has advertised a media
            // type named `*/*`, and nothing licenses reading it as "any format" — but
            // it is worth saying which mistake produced the finding.
            //
            // cite(RFC 9110 § 12.4.3): "Most of these header fields, where indicated, define a wildcard value ("*") to select unspecified values."
            // cite(RFC 9110 § 12.5.1): "The asterisk "*" character is used to group media types into ranges, with "*/*" indicating all media types and "type/*" indicating all subtypes of that type."
            let wildcard_note = if advertised
                .iter()
                .any(|a| a.starts_with("*/") || a.ends_with("/*"))
            {
                ". The advertisement uses an asterisk, which is Accept's media-range form: Accept-Patch is a list of media types and defines no wildcard, so that member names a media type spelled with an asterisk"
            } else {
                ""
            };

            // What makes this a finding rather than an observation: the field exists
            // to influence the content of subsequent requests, and a field with no
            // wildcard says nothing is acceptable beyond what it mentions. RFC 5789
            // does not oblige a client to pick from the list — it offers the server a
            // 415 for the case instead — so the report says what the exchange states,
            // not that a requirement was broken.
            //
            // cite(RFC 9110 § 12.3): "When content negotiation preferences are sent in a server's response, the listed preferences are called "request content negotiation" because they intend to influence selection of an appropriate content for subsequent requests to that resource."
            // cite(RFC 9110 § 12.4.3): "If no wildcard is present, values that are not explicitly mentioned in the field are considered unacceptable."
            // cite(RFC 5789 § 2.2): "Can be specified using a 415 (Unsupported Media Type) response when the client sends a patch document format that the server does not support for the resource identified by the Request-URI."
            Some(self.violation(ctx.severity, format!(
                    "PATCH request sends Content-Type '{}', which no Accept-Patch for this resource has mentioned; the most recent advertisement listed {}. A format the advertisement does not mention is one the server has said it does not accept, and 415 (Unsupported Media Type) is the answer RFC 5789 offers for it{}",
                    sent,
                    advertised.join(", "),
                    wildcard_note
                )))
        };
        Vec::from_iter(finding())
    }

    fn title(&self) -> Option<&'static str> {
        Some("Client PATCH Content-Type Matches Accept-Patch")
    }

    fn description(&self) -> &'static str {
        "Reports a `PATCH` request whose `Content-Type` names a patch document format that no `Accept-Patch` for this resource has mentioned.\n\n**Why the advertisement is the only evidence.** RFC 5789 defines no default patch document format, no registry of them and no naming convention, so nothing in a lone `PATCH` says whether its media type is one a server takes — `patch_partial_update` requires the field and does not judge its value for exactly that reason. RFC 9110 §12.3 names where the answer lives: `Accept-Patch` \"allows discovery of which content types are accepted in PATCH requests\", and preferences a server sends in a response are \"request content negotiation\" because they \"intend to influence selection of an appropriate content for subsequent requests to that resource\".\n\n**What makes an unlisted type a finding.** RFC 5789 places no requirement on the client: §3.1 says the presence of a format \"indicates that that specific format is allowed\", and §2.2 gives the server a `415 (Unsupported Media Type)` for one it does not support. The sentence that closes the list is RFC 9110 §12.4.3's — \"[i]f no wildcard is present, values that are not explicitly mentioned in the field are considered unacceptable\" — which reaches this field through §12.3. So the report is that the exchange contradicts itself: the client sent a format the server had already said it does not accept. It is not a disobeyed MUST or SHOULD, and there is none to disobey.\n\n**There is no wildcard.** `Accept-Patch` is `1#media-type`. The asterisk forms are `Accept`'s `media-range` (RFC 9110 §12.5.1), a different production in a different field, and §12.4.3 makes wildcards a feature a field has only \"where indicated\". A server writing `Accept-Patch: */*` or `application/*` has therefore advertised a media type spelled with an asterisk; the finding says so when it happens, rather than treating it as permission.\n\n**Which advertisement counts.** The most recent response *for this resource* that carried the field, whichever method drew it — §3.1 makes the field's presence \"in response to any method\" an indication about the resource, so an `OPTIONS` exchange several requests back still counts.\n\n**What is not judged here.** The advertisement's syntax: members that do not parse as a media type are skipped, and a field with no parseable member leaves the rule unable to answer, so it declines. `accept_patch_header_valid` is the rule that reports a malformed `Accept-Patch`, on a response to any method — including the `OPTIONS` response §3.1 asks for it in, which nothing validated until that rule was audited. On the request side, more than one `Content-Type` line makes the comparison meaningless, because recipients differ over which member wins (§8.3); a value that is not a media type, and an absent one, are `content_type_valid`'s and `patch_partial_update`'s findings. Parameters are not compared: whether one is significant depends on the media type's registration (§8.3.1), so `text/example` and `text/example;charset=utf-8` are treated as the same format."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_5789_3_1,
            RFC_5789_2_2,
            RFC_9110_12_3,
            RFC_9110_12_4_3,
            RFC_9110_8_3,
            RFC_9110_8_3_1,
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some(
                    "advertised by the OPTIONS response, and a parameter does not make a different format",
                ),
                snippet: "OPTIONS /example/buddies.xml HTTP/1.1\nHost: www.example.com\n\nHTTP/1.1 200 OK\nAllow: GET, PUT, POST, OPTIONS, HEAD, DELETE, PATCH\nAccept-Patch: application/example, text/example\n\nPATCH /example/buddies.xml HTTP/1.1\nHost: www.example.com\nContent-Type: text/example;charset=utf-8\nContent-Length: 11\n\n[patch doc]",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("a format the advertisement never mentioned"),
                snippet: "OPTIONS /example/buddies.xml HTTP/1.1\nHost: www.example.com\n\nHTTP/1.1 200 OK\nAccept-Patch: application/example, text/example\n\nPATCH /example/buddies.xml HTTP/1.1\nHost: www.example.com\nContent-Type: application/merge-patch+json\nContent-Length: 11\n\n[patch doc]",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &PatchMethodContentTypeMatch;

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;
    use hyper::HeaderMap;
    use rstest::rstest;

    /// A `PATCH` to the fixture's resource, plus one earlier transaction whose
    /// response carries the given `Accept-Patch` field lines.
    fn judge(
        method: &str,
        request_content_types: &[&[u8]],
        accept_patch_lines: &[&[u8]],
    ) -> Option<Violation> {
        judge_history(method, request_content_types, &[Some(accept_patch_lines)])
    }

    /// The same, over a history written newest-first. Each entry is the
    /// `Accept-Patch` field lines of one earlier transaction's response, or
    /// `None` for an earlier transaction that has no response at all.
    ///
    /// `TransactionHistory` asserts its entries are newest-first, so the
    /// timestamps are staggered here rather than at each call site.
    fn judge_history(
        method: &str,
        request_content_types: &[&[u8]],
        prior: &[Option<&[&[u8]]>],
    ) -> Option<Violation> {
        let rule = PatchMethodContentTypeMatch;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = method.into();
        let mut req_headers = HeaderMap::new();
        for ct in request_content_types {
            req_headers.append("content-type", HeaderValue::from_bytes(ct).unwrap());
        }
        tx.request.headers = req_headers;

        let entries: Vec<_> = prior
            .iter()
            .enumerate()
            .map(|(age, lines)| {
                let mut prev = match lines {
                    Some(_) => crate::test_helpers::make_test_transaction_with_response(200, &[]),
                    None => crate::test_helpers::make_test_transaction(),
                };
                prev.request.uri = tx.request.uri.clone();
                prev.timestamp = tx.timestamp - chrono::Duration::seconds(age as i64 + 1);
                if let Some(lines) = lines {
                    let mut resp_headers = HeaderMap::new();
                    for line in *lines {
                        resp_headers.append("accept-patch", HeaderValue::from_bytes(line).unwrap());
                    }
                    prev.response.as_mut().unwrap().headers = resp_headers;
                }
                prev
            })
            .collect();

        let history = crate::transaction_history::TransactionHistory::from_transactions(entries);
        crate::test_helpers::run_rule(&rule, &tx, &history, &cfg)
    }

    #[rstest]
    // The advertised format, sent back verbatim.
    #[case("PATCH", &[b"application/example-patch+json" as &[u8]], &[b"application/example-patch+json" as &[u8]], false)]
    // A format the advertisement never mentioned.
    #[case("PATCH", &[b"application/merge-patch+json" as &[u8]], &[b"application/example-patch+json" as &[u8]], true)]
    // Parameters are not part of the comparison.
    #[case("PATCH", &[b"application/merge-patch+json; charset=utf-8" as &[u8]], &[b"application/example-patch+json, application/merge-patch+json" as &[u8]], false)]
    // Type and subtype are case-insensitive.
    #[case("PATCH", &[b"Application/Merge-Patch+JSON" as &[u8]], &[b"application/merge-patch+json" as &[u8]], false)]
    // A member that is not a media type is skipped; the one beside it still advertises.
    #[case("PATCH", &[b"application/merge-patch+json" as &[u8]], &[b"badmedia, application/merge-patch+json" as &[u8]], false)]
    // No parseable member at all: the rule cannot answer, so it declines.
    #[case("PATCH", &[b"application/merge-patch+json" as &[u8]], &[b"badmedia" as &[u8]], false)]
    // No Accept-Patch anywhere in the history.
    #[case("PATCH", &[b"application/merge-patch+json" as &[u8]], &[], false)]
    // A trailing comma is an empty list element, not an advertisement.
    #[case("PATCH", &[b"application/json" as &[u8]], &[b"application/json," as &[u8]], false)]
    fn check_cases(
        #[case] method: &str,
        #[case] content_types: &[&[u8]],
        #[case] accept_patch: &[&[u8]],
        #[case] expect_violation: bool,
    ) {
        assert_eq!(
            judge(method, content_types, accept_patch).is_some(),
            expect_violation
        );
    }

    /// § 3.1's `1#media-type` is one list however many field lines carry it, so a
    /// format written on the second line is advertised.
    #[test]
    fn advertisement_is_joined_across_field_lines() {
        assert!(judge(
            "PATCH",
            &[b"application/merge-patch+json"],
            &[b"application/example", b"application/merge-patch+json"],
        )
        .is_none());
    }

    /// A member may straddle the boundary, which is the reason the join is over
    /// the lines rather than per line.
    #[test]
    fn a_member_split_across_two_lines_is_still_one_member() {
        assert!(judge(
            "PATCH",
            &[b"application/merge-patch+json"],
            &[b"application/example,", b"application/merge-patch+json"]
        )
        .is_none());
    }

    /// § 9.1: the method token is case-sensitive, so `patch` is another method and
    /// this rule has nothing to say about its content.
    #[test]
    fn lowercase_patch_is_a_different_method() {
        assert!(judge(
            "patch",
            &[b"application/json"],
            &[b"application/merge-patch+json"],
        )
        .is_none());
    }

    #[test]
    fn non_patch_requests_are_ignored() {
        assert!(judge(
            "GET",
            &[b"application/json"],
            &[b"application/merge-patch+json"],
        )
        .is_none());
    }

    /// `Accept-Patch` has no wildcard form, so `*/*` names a media type rather
    /// than granting permission — and the finding says which mistake it was.
    #[rstest]
    #[case(b"*/*" as &[u8])]
    #[case(b"application/*" as &[u8])]
    fn an_asterisk_is_not_a_wildcard_in_this_field(#[case] advertised: &[u8]) {
        let v = judge("PATCH", &[b"application/json"], &[advertised])
            .expect("an unmentioned media type is a finding");
        assert!(v.message.contains("media-range"), "{}", v.message);
    }

    /// An advertisement the rule cannot read is still the resource's current
    /// one, so an earlier readable one is not reached for.
    #[test]
    fn an_unreadable_advertisement_stops_the_rule_rather_than_falling_back() {
        assert!(judge_history(
            "PATCH",
            &[b"application/json"],
            &[
                Some(&[b"badmedia" as &[u8]][..]),
                Some(&[b"application/merge-patch+json" as &[u8]][..]),
            ],
        )
        .is_none());
    }

    /// The advertisement is about the resource, not about the request that drew
    /// it, and it does not expire when another request goes past.
    #[test]
    fn an_older_advertisement_still_counts() {
        assert!(judge_history(
            "PATCH",
            &[b"application/json"],
            &[
                Some(&[][..]),
                Some(&[b"application/merge-patch+json" as &[u8]][..])
            ],
        )
        .is_some());
    }

    /// § 8.3: with two field lines the media type the peer acts on is not the one
    /// the message states, so there is nothing to compare — even when the first
    /// line matches. `content_type_valid` reports the duplication,
    /// which this asserts by calling it.
    #[test]
    fn a_duplicated_content_type_is_not_compared_and_is_reported_next_door() {
        assert!(judge(
            "PATCH",
            &[b"application/merge-patch+json", b"application/json"],
            &[b"application/merge-patch+json"],
        )
        .is_none());

        let neighbour = crate::rules::content_type_valid::ContentTypeValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[neighbour.id()]);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "PATCH".into();
        let mut hm = HeaderMap::new();
        hm.append(
            "content-type",
            HeaderValue::from_static("application/merge-patch+json"),
        );
        hm.append("content-type", HeaderValue::from_static("application/json"));
        tx.request.headers = hm;
        assert!(crate::test_helpers::run_rule(
            &neighbour,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .is_some());
    }

    /// `type` and `subtype` are `token`, so a value carrying an octet outside
    /// visible US-ASCII is not a media type at all — there is no format here to
    /// compare, and the well-formedness rule owns the value.
    #[test]
    fn a_content_type_that_is_not_a_media_type_is_not_compared() {
        assert!(judge("PATCH", &[&[0xff]], &[b"application/merge-patch+json"],).is_none());
        assert!(judge("PATCH", &[b"bad"], &[b"application/merge-patch+json"]).is_none());
    }

    /// A `PATCH` with no `Content-Type` states no format, so this rule has
    /// nothing to compare; `patch_partial_update` is the rule that
    /// reports the absence, which this asserts by calling it.
    #[test]
    fn a_missing_content_type_belongs_to_the_neighbour() {
        assert!(judge("PATCH", &[], &[b"application/merge-patch+json"]).is_none());

        let neighbour = crate::rules::patch_partial_update::PatchPartialUpdate;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[neighbour.id()]);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "PATCH".into();
        tx.request.headers = HeaderMap::new();
        tx.request.body_length = Some(12);
        assert!(crate::test_helpers::run_rule(
            &neighbour,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .is_some());
    }

    /// The octets of an advertisement are kept, so a member outside US-ASCII
    /// fails on its own and the media types beside it still advertise.
    #[test]
    fn one_bad_octet_does_not_erase_the_whole_advertisement() {
        assert!(judge(
            "PATCH",
            &[b"application/merge-patch+json"],
            &[b"text/\xff, application/merge-patch+json"],
        )
        .is_none());
    }

    /// `type` and `subtype` are `token`, so a member carrying an octet outside
    /// `tchar` names no media type — and it must not be *tidied* into one either.
    /// `str::trim` strips U+00A0, which is the octet %xA0 read through the
    /// isomorphic decode and is `obs-text`, so without the token check
    /// `application/example\xA0` would advertise `application/example`.
    /// Each bad member sits beside a readable one, so the rule still has an
    /// advertisement to answer with and the finding is the suppression the check
    /// prevents — not the decline an empty list would produce.
    #[test]
    fn a_member_no_production_admits_is_not_tidied_into_an_advertisement() {
        assert!(judge(
            "PATCH",
            &[b"application/example"],
            &[b"application/other, application/example\xa0"],
        )
        .is_some());
        assert!(judge(
            "PATCH",
            &[b"text/plain"],
            &[b"application/other, text/pla in"],
        )
        .is_some());
    }

    /// The same grammar in the other direction: a request value `parse_media_type`
    /// splits but no production admits is not compared, because reporting it as
    /// unadvertised would double with `content_type_valid`.
    #[test]
    fn a_request_value_no_production_admits_is_not_compared() {
        assert!(judge("PATCH", &[b"text/pla in"], &[b"application/example"]).is_none());
    }

    /// `qdtext` admits `obs-text`, so a parameter may legitimately carry an octet
    /// `to_str` refuses — and the type and subtype in front of it are still a
    /// media type this rule can compare.
    #[test]
    fn obs_text_inside_a_parameter_does_not_hide_the_media_type() {
        assert!(judge(
            "PATCH",
            &[b"text/example; title=\"caf\xe9\""],
            &[b"application/example"],
        )
        .is_some());
    }

    /// A `quoted-string` parameter value may contain the comma the list is
    /// delimited with, so the split has to respect quoting.
    #[test]
    fn a_quoted_comma_does_not_split_a_member() {
        assert!(judge("PATCH", &[b"text/example"], &[b"text/example;x=\"a,b\""],).is_none());
    }

    #[test]
    fn a_transaction_without_a_response_carries_no_advertisement() {
        assert!(judge_history("PATCH", &[b"application/merge-patch+json"], &[None]).is_none());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "patch_method_content_type_match");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn scope_is_client() {
        let rule = PatchMethodContentTypeMatch;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Client);
    }
}
