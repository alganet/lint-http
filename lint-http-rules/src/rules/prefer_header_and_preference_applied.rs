// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::helpers::headers::{combined_field_value_as_written, parse_token_bws_word};
use crate::helpers::list::list_members_as_written;
use crate::helpers::shown::shown_in_finding;
use crate::lint::Violation;
use crate::rules::Rule;

pub struct PreferHeaderAndPreferenceApplied;

/// Why applying `name` changes what a cache would hand the next client — for the
/// four preferences RFC 7240 defines, and for no other name.
///
/// RFC 7240 § 2 conditions its `Vary` requirement on a preference *"that might
/// result in a variance to a cache's handling of a response entity"*, and it is
/// each preference's own definition that says whether it is one. All four of
/// this document's are: two of them decide what the response entity contains,
/// and two decide whether the entity is the result at all or an acknowledgement
/// standing in for it.
///
/// A name this function does not know is a preference registered elsewhere. § 5.1
/// puts what a registration does in the registration itself, so whether applying
/// it varies the entity is not readable from RFC 7240 — and a rule that guessed
/// would be inventing the antecedent of a MUST.
///
/// cite(RFC 7240 § 2): "If a server supports the optional application of a preference that might result in a variance to a cache's handling of a response entity, a Vary header field MUST be included in the response listing the Prefer header field regardless of whether the client actually used Prefer in the request."
/// cite(RFC 7240 § 5.1): "Value: (An enumeration or description of possible values for the"
fn varies_the_response_entity(name: &str) -> Option<&'static str> {
    // The comparison folds case because § 2 says a preference token name is
    // compared that way -- and here the question really is § 2's, since it is
    // whether the name in this message is the name the document defines.
    //
    // cite(RFC 7240 § 2): "For both preference token names and parameter names, comparison is case insensitive while values are case sensitive regardless of whether token or quoted-string values are used."
    let known = |literal: &str| name.eq_ignore_ascii_case(literal);

    if known("return") {
        // The clearest of the four: one value asks for the resource's current
        // state in the response and the other asks for as little as the server
        // can send, so the same target URI answers with two different entities
        // depending on what the request preferred.
        //
        // cite(RFC 7240 § 4.2): "The "return=representation" preference indicates that the client prefers that the server include an entity representing the current state of the resource in the response to a successful request."
        // cite(RFC 7240 § 4.2): "The "return=minimal" preference, on the other hand, indicates that the client wishes the server to return only a minimal response to a successful request."
        return Some(
            "its two values decide whether the response carries a representation of the resource or as little as the server can send",
        );
    }
    if known("respond-async") {
        // cite(RFC 7240 § 4.1): "the server can honor the "respond-async" preference by returning a 202 (Accepted) response."
        return Some(
            "a server honoring it answers 202 (Accepted) instead of with the result of the request",
        );
    }
    if known("wait") {
        // cite(RFC 7240 § 4.3): "the server, or proxy, can choose to utilize an asynchronous processing model by returning -- for example -- a 202 (Accepted) response."
        return Some(
            "a server that would exceed the stated time answers 202 (Accepted) instead of with the result of the request",
        );
    }
    if known("handling") {
        // cite(RFC 7240 § 4.4): "a decision must be made to either reject the request with an appropriate "4xx" error response or go ahead with processing."
        return Some(
            "it decides whether a request the server could still process is rejected with a 4xx instead",
        );
    }
    None
}

/// Whether a response's `Vary` nominates `Prefer`, in either of the two
/// spellings RFC 7240 § 2 admits.
///
/// The reader is `helpers::headers::vary_nomination`, shared with the two
/// caching rules that ask the same question. This site was the only one of the
/// three that joined the field's lines — which is what makes a `*` written on a
/// second line a `*` — and the only one that survived an `obs-text` octet, and
/// it was the one using the **wrong walk**: it split quote-aware, and
/// `Vary = #( "*" / field-name )` with `field-name = token` admits no
/// `quoted-string`, so a stray DQUOTE made the next comma data rather than a
/// separator and `Vary: "x, prefer` did not nominate `Prefer`. Each of the three
/// was right about something the other two were not; the shared reader is all
/// three answers.
///
/// cite(RFC 7240 § 2): "Alternatively, the server MAY include a Vary header with the special value "*""
fn vary_nominates_prefer(response_headers: &hyper::HeaderMap) -> bool {
    crate::helpers::vary::vary_nomination(response_headers).nominates("prefer")
}

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_7240_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 7240",
    section: Some("2"),
    url: "https://www.rfc-editor.org/rfc/rfc7240.html#section-2",
    note: "The `Vary` MUST this rule enforces, its `Vary: *` alternative, the case rule for comparing preference token names, and the statement that servers are allowed to ignore stated preferences — which is why a missing `Preference-Applied` is not a finding",
};
const RFC_7240_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 7240",
    section: Some("3"),
    url: "https://www.rfc-editor.org/rfc/rfc7240.html#section-3",
    note: "`Preference-Applied` — a MAY, with its grammar, and the sentence narrowing its use to the case where a client could not otherwise tell that a preference was applied. The field's presence is this rule's evidence, not its requirement",
};
const RFC_7240_4: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 7240",
    section: Some("4"),
    url: "https://www.rfc-editor.org/rfc/rfc7240.html#section-4",
    note: "What each of the four defined preferences does to the response, which is what makes it one that \"might result in a variance to a cache's handling of a response entity\": §4.1 and §4.3 (a 202 in place of the result), §4.2 (a representation or a minimal answer), §4.4 (a 4xx in place of processing)",
};
const RFC_7240_5_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 7240",
    section: Some("5.1"),
    url: "https://www.rfc-editor.org/rfc/rfc7240.html#section-5.1",
    note: "The \"HTTP Preferences\" registry keeps a preference's effect in its own registration, which is why a name RFC 7240 does not define is left unjudged rather than assumed to vary the entity",
};
const RFC_9110_12_5_5: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("12.5.5"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.5",
    note: "`Vary = #( \"*\" / field-name )` — a list field, read across its lines, whose members are field names and so compared case-insensitively",
};
const RFC_9110_9_2_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("9.2.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-9.2.3",
    note: "Which methods have caching semantics. With §9.3.3's condition on POST responses, this is why the gate is GET and HEAD — the methods where one exchange shows a cache would hold the response under the target URI alone",
};
const RFC_9110_9_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("9.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-9.1",
    note: "The method token is case-sensitive, so the gate compares the octets as written rather than folding an unrecognized method into GET",
};
const RFC_9111_4_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9111",
    section: Some("4.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-4.1",
    note: "What the `Vary` this rule asks for buys: without it a stored response is matched on the target URI alone, and the request field that selected it is not part of the key",
};

impl Rule for PreferHeaderAndPreferenceApplied {
    fn id(&self) -> &'static str {
        "prefer_header_and_preference_applied"
    }

    /// The evidence is a field the server wrote and the finding is a field it
    /// omitted, so the rule has nothing to measure on a capture whose upstream
    /// never answered. The id keeps its `client_` prefix because it is the
    /// rule's name in every configuration file that already enables it; the
    /// sentences it applies address the server.
    ///
    /// cite(RFC 7240 § 3): "The Preference-Applied response header MAY be included within a response message as an indication as to which Prefer tokens were honored by the server and applied to the processing of a request."
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
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
            let resp = tx.response.as_ref()?;

            // § 2's requirement is conditioned on a variance to *a cache's* handling
            // of the entity, and a captured exchange establishes that only where a
            // cache would store the response under the target URI alone. GET and
            // HEAD are those methods. POST is cacheable too and is deliberately out:
            // its responses become storable only with explicit freshness information
            // and a `Content-Location`, so a `Preference-Applied` on a POST is not by
            // itself evidence that any cache is holding anything -- which is why
            // § 4.2's own `POST /collection` example, a 201 carrying only a
            // `Location`, is not a finding here. Neither is § 3's `PATCH` example.
            //
            // The comparison is against the octets as written: an unrecognized method
            // is not GET however it is spelled, so folding case would put a request
            // this document says nothing about inside the gate.
            //
            // cite(RFC 9110 § 9.2.3): "This specification defines caching semantics for GET, HEAD, and POST, although the overwhelming majority of cache implementations only support GET and HEAD."
            // cite(RFC 9110 § 9.3.3): "Responses to POST requests are only cacheable when they include explicit freshness information"
            // cite(RFC 9110 § 9.1): "The method token is case-sensitive"
            if !matches!(tx.request.method.as_str(), "GET" | "HEAD") {
                return None;
            }

            // The one thing a captured message says about the antecedent. A request's
            // `Prefer` says what a client asked for and nothing about the server, but
            // a response naming a preference applied is the server stating it applies
            // that preference -- which is why the trigger is this field and not the
            // request's, exactly as the sentence's "regardless of whether the client
            // actually used Prefer in the request" says it should be.
            //
            // Read as octets and joined across the field's lines, for the reasons
            // `preference_applied_header_valid` reads the same field the same
            // way: a `word` may be a `quoted-string`, `qdtext` admits `obs-text`, and
            // a member may be written at a line boundary.
            //
            // cite(RFC 7240 § 3, label: Preference-Applied grammar): "Preference-Applied = "Preference-Applied" ":" 1#applied-pref"
            let applied = combined_field_value_as_written(&resp.headers, "preference-applied")?;

            // The first member naming a preference whose application varies the
            // entity. A member this cannot parse is one whose name is not readable,
            // so it cannot establish the antecedent either -- the finding below is
            // that a field is *absent*, and a claim of absence rests on the rest of
            // the message being legible. Its syntax is the neighbouring rule's
            // finding, reported there rather than twice. An empty member needs no
            // filter of its own: it has no `token` before the optional `=` either, so
            // the parse below is where it stops.
            //
            // cite(RFC 7240 § 3): "applied-pref = token [ BWS "=" BWS word ]"
            let (name, why) = list_members_as_written(&applied)
                .into_iter()
                .filter_map(|member| parse_token_bws_word(member).ok())
                .find_map(|parsed| {
                    varies_the_response_entity(parsed.name).map(|why| (parsed.name, why))
                })?;

            // Read once and used twice: the value decides the verdict, and on the
            // reporting path it is also what the finding has to show.
            if vary_nominates_prefer(&resp.headers) {
                return None;
            }

            // Read last, where the severity it carries is finally needed: every gate
            // above ends the rule, and each of them is a map lookup or a comparison
            // where the config read is several. Only a response that is about to be
            // reported pays for it.

            // The name reached here through `parse_token_bws_word`, which admits only
            // `tchar`, so it is safe in a message as written; the `Vary` value is
            // whatever the server sent, so it is read as written and escaped. Read
            // here rather than at the gate above, which asks the shared predicate a
            // question about the field rather than for its text.
            let vary = combined_field_value_as_written(&resp.headers, "vary");
            let vary_state = match &vary {
                Some(v) => format!("its Vary field is '{}'", shown_in_finding(v)),
                None => "it carries no Vary field".to_string(),
            };

            Some(self.violation(ctx.severity, format!(
                    "Response states the '{}' preference was applied — {} — but {}, so a cache holding this response under the target URI alone can serve it to a request that preferred otherwise",
                    name, why, vary_state
                )))
        };
        Vec::from_iter(finding())
    }

    fn title(&self) -> Option<&'static str> {
        Some("Prefer, Preference-Applied and the Vary a cache needs")
    }

    fn description(&self) -> &'static str {
        "Reports a response that states a preference was applied — `Preference-Applied` naming one of the four preferences RFC 7240 defines — without the `Vary` that §2 requires of a server whose preferences affect caching: *\"If a server supports the optional application of a preference that might result in a variance to a cache's handling of a response entity, a Vary header field MUST be included in the response listing the Prefer header field regardless of whether the client actually used Prefer in the request.\"* §2 admits `Vary: *` as the alternative, and either spelling satisfies the rule.\n\n**The trigger is the response, not the request.** A `Prefer` request header says what a client asked for and nothing about what the server supports; a `Preference-Applied` response header is the server stating that it applies that preference. That is the half of the sentence's antecedent a captured exchange can establish, and it is what the *\"regardless of whether the client actually used Prefer in the request\"* clause points at.\n\n**Only GET and HEAD.** The requirement is conditioned on a variance to *a cache's* handling of the entity, and a single exchange shows that only where a cache would store the response under the target URI alone. POST is a cacheable method but its responses become storable only with explicit freshness information and a `Content-Location` (RFC 9110 §9.3.3), so `Preference-Applied` on a POST is not by itself evidence that anything is stored — which is why RFC 7240 §4.2's own `POST /collection` example and §3's own `PATCH` example are not findings here.\n\n**Only the four preferences RFC 7240 defines.** `return` decides whether the response carries a representation or as little as the server can send (§4.2); `respond-async` and `wait` decide whether the response is the result or a 202 standing in for it (§4.1, §4.3); `handling` decides whether a request the server could still process is rejected with a 4xx (§4.4). Each of those is a variance the document itself describes. A preference registered elsewhere has its effect written in its own registration (§5.1), so whether it varies the entity is not readable here and the rule stays silent rather than invent the antecedent of a MUST.\n\n**What this rule does not report, and why.** A response that omits `Preference-Applied` after a `Prefer` request is not a finding. §3 makes the field a MAY; §2 says outright that *\"servers are allowed to ignore stated preferences\"*, so silence may correctly mean nothing was applied; and §3's own next sentence narrows it further — *\"Use of the Preference-Applied header is only necessary when it is not readily and obviously apparent that a server applied a given preference and such ambiguity might have an impact on the client's handling of the response.\"* — a condition about what a client application can determine, which no message states. RFC 7240 §4.2's two example responses honor `return` and carry no `Preference-Applied` at all.\n\n**The boundary.** §2's MUST binds a server that *supports* applying such a preference, whether or not it applied one here and whether or not the client asked. The only in-message evidence of that support is `Preference-Applied`, and §3 leaves a server free to apply a preference and say nothing — so a server that varies its responses silently is outside what any single capture can show. `prefer_header_valid` reads the request's field against its grammar and `preference_applied_header_valid` reads the response's against its own and against what was asked for; neither looks at `Vary`."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_7240_2,
            RFC_7240_3,
            RFC_7240_4,
            RFC_7240_5_1,
            RFC_9110_12_5_5,
            RFC_9110_9_2_3,
            RFC_9110_9_1,
            RFC_9111_4_1,
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some(
                    "(the applied preference is named, and Vary makes it part of the cache key)",
                ),
                snippet: "GET /my-document HTTP/1.1\nHost: example.org\nPrefer: return=minimal\n\nHTTP/1.1 200 OK\nContent-Type: application/json\nPreference-Applied: return=minimal\nVary: Prefer",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(RFC 7240 §2's alternative spelling)"),
                snippet: "GET /my-document HTTP/1.1\nHost: example.org\nPrefer: respond-async\n\nHTTP/1.1 200 OK\nPreference-Applied: respond-async\nVary: *",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some(
                    "(RFC 7240 §3's own example — a PATCH response is not one a cache holds under the target URI)",
                ),
                snippet: "PATCH /my-document HTTP/1.1\nHost: example.org\nContent-Type: application/example-patch\nPrefer: return=representation\n\nHTTP/1.1 200 OK\nContent-Type: application/json\nPreference-Applied: return=representation\nContent-Location: /my-document",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some(
                    "(a preference registered elsewhere; RFC 7240 does not say what applying it changes)",
                ),
                snippet: "GET /my-document HTTP/1.1\nHost: example.org\nPrefer: depth-noroot\n\nHTTP/1.1 200 OK\nPreference-Applied: depth-noroot",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some(
                    "(the server states it varied the entity and left it out of the cache key)",
                ),
                snippet: "GET /my-document HTTP/1.1\nHost: example.org\nPrefer: return=minimal\n\nHTTP/1.1 200 OK\nContent-Type: application/json\nPreference-Applied: return=minimal",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(Vary is present but does not list Prefer)"),
                snippet: "GET /my-document HTTP/1.1\nHost: example.org\nPrefer: return=representation\n\nHTTP/1.1 200 OK\nContent-Type: application/json\nPreference-Applied: return=representation\nVary: Accept-Encoding",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &PreferHeaderAndPreferenceApplied;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    use crate::test_helpers::make_headers_from_octet_pairs as headers;

    fn run(
        method: &str,
        req: &[(&str, &[u8])],
        resp: &[(&str, &[u8])],
    ) -> Option<crate::lint::Violation> {
        let rule = PreferHeaderAndPreferenceApplied;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.request.method = method.to_string();
        tx.request.headers = headers(req);
        tx.response.as_mut().unwrap().headers = headers(resp);
        crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
    }

    /// Each of the four preferences RFC 7240 defines is one whose application
    /// varies the entity, so each of them needs the `Vary`.
    #[rstest]
    #[case(b"return=minimal")]
    #[case(b"return=representation")]
    #[case(b"respond-async")]
    #[case(b"wait=100")]
    #[case(b"handling=lenient")]
    fn defined_preference_applied_without_vary_is_reported(#[case] applied: &[u8]) {
        let v = run("GET", &[], &[("preference-applied", applied)]);
        assert!(v.is_some(), "expected a finding for {:?}", applied);
    }

    /// § 2 admits two spellings, and a `Vary` listing something else is neither.
    /// The absent case is the test above's subject, not this one's.
    #[rstest]
    #[case(b"Prefer", false)]
    #[case(b"prefer", false)]
    #[case(b"Accept-Encoding, Prefer", false)]
    #[case(b"*", false)]
    #[case(b"Accept-Encoding", true)]
    fn a_present_vary_decides(#[case] vary: &[u8], #[case] expect_violation: bool) {
        let resp: Vec<(&str, &[u8])> =
            vec![("preference-applied", b"return=minimal"), ("vary", vary)];
        assert_eq!(run("GET", &[], &resp).is_some(), expect_violation);
    }

    /// `Vary` is a list field, so a `*` written on a second field line is a `*`.
    #[test]
    fn vary_is_read_across_its_field_lines() {
        let v = run(
            "GET",
            &[],
            &[
                ("preference-applied", b"return=minimal"),
                ("vary", b"Accept-Encoding"),
                ("vary", b"Prefer"),
            ],
        );
        assert!(v.is_none());
    }

    /// The gate is the method, and it is compared as written: `get` is a method
    /// RFC 9110 does not define, so nothing here says a cache holds its response.
    #[rstest]
    #[case("GET", true)]
    #[case("HEAD", true)]
    #[case("POST", false)]
    #[case("PATCH", false)]
    #[case("PUT", false)]
    #[case("get", false)]
    fn method_gate(#[case] method: &str, #[case] expect_violation: bool) {
        let v = run(method, &[], &[("preference-applied", b"return=minimal")]);
        assert_eq!(v.is_some(), expect_violation, "method {}", method);
    }

    /// RFC 7240 § 3's own example exchange, which the rule must not report: a
    /// PATCH response is not one a cache holds under the target URI alone.
    #[test]
    fn rfc7240_section_3_example_is_clean() {
        let v = run(
            "PATCH",
            &[("prefer", b"return=representation")],
            &[
                ("content-type", b"application/json"),
                ("preference-applied", b"return=representation"),
                ("content-location", b"/my-document"),
            ],
        );
        assert!(v.is_none());
    }

    /// § 5.1 keeps a registered preference's effect in its own registration, so a
    /// name this document does not define is not assumed to vary the entity.
    #[test]
    fn preference_defined_elsewhere_is_left_alone() {
        let v = run("GET", &[], &[("preference-applied", b"depth-noroot")]);
        assert!(v.is_none());
    }

    /// The name is compared the way § 2 says preference token names are.
    #[test]
    fn preference_name_comparison_folds_case() {
        let v = run("GET", &[], &[("preference-applied", b"Return=Minimal")]);
        assert!(v.is_some());
    }

    /// A member the grammar does not admit says nothing about which preference
    /// was applied; its syntax is the neighbouring rule's finding.
    #[rstest]
    #[case(b"")]
    #[case(b",")]
    #[case(b"=minimal")]
    #[case(b"return=\"unterminated")]
    fn an_unreadable_applied_pref_states_nothing(#[case] applied: &[u8]) {
        let v = run("GET", &[], &[("preference-applied", applied)]);
        assert!(v.is_none(), "expected silence for {:?}", applied);
    }

    /// A defined preference beside an unreadable member is still a defined
    /// preference the server says it applied.
    #[test]
    fn a_defined_preference_beside_an_unreadable_member_is_found() {
        let v = run(
            "GET",
            &[],
            &[("preference-applied", b"=bad, return=minimal")],
        );
        assert!(v.is_some());
    }

    /// A `word` may be a `quoted-string` and `qdtext` admits `obs-text`, so the
    /// field is not decoded before it is read — and the quoting is not the value.
    #[test]
    fn an_obs_text_octet_does_not_hide_the_field() {
        let v = run(
            "GET",
            &[],
            &[("preference-applied", b"return=\"minimal\", foo=\"caf\xe9\"")],
        );
        assert!(v.is_some());
    }

    /// § 2 says several field lines are one list, so a member written at a line
    /// boundary is one member.
    #[test]
    fn preference_applied_is_read_across_its_field_lines() {
        let v = run(
            "GET",
            &[],
            &[
                ("preference-applied", b"foo"),
                ("preference-applied", b"return=minimal"),
            ],
        );
        assert!(v.is_some());
    }

    /// The requirement holds *"regardless of whether the client actually used
    /// Prefer in the request"*, so the request's field decides nothing here.
    #[rstest]
    #[case(None)]
    #[case(Some(&b"return=minimal"[..]))]
    #[case(Some(&b","[..]))]
    #[case(Some(&b"\xff"[..]))]
    fn the_request_field_does_not_gate_the_finding(#[case] prefer: Option<&[u8]>) {
        let mut req: Vec<(&str, &[u8])> = vec![];
        if let Some(p) = prefer {
            req.push(("prefer", p));
        }
        let v = run("GET", &req, &[("preference-applied", b"return=minimal")]);
        assert!(v.is_some());
    }

    /// A response that says nothing about a preference is not evidence of
    /// anything: § 3 makes the field a MAY, and § 2 lets a server ignore every
    /// preference it was sent. One request field is enough to assert it — the
    /// rule exits on the response before it could read a second.
    #[test]
    fn a_missing_preference_applied_is_not_a_finding() {
        let v = run("GET", &[("prefer", b"return=representation")], &[]);
        assert!(v.is_none());
    }

    #[test]
    fn the_finding_names_the_preference_and_what_vary_said() {
        let v = run(
            "GET",
            &[],
            &[
                ("preference-applied", b"return=minimal"),
                ("vary", b"Accept-Encoding"),
            ],
        )
        .expect("expected a finding");
        assert!(v.message.contains("'return'"), "{}", v.message);
        assert!(v.message.contains("Accept-Encoding"), "{}", v.message);
    }

    #[test]
    fn rule_id_and_scope() {
        let rule = PreferHeaderAndPreferenceApplied;
        assert_eq!(rule.id(), "prefer_header_and_preference_applied");
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "prefer_header_and_preference_applied");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
