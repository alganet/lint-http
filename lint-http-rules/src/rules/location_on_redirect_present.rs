// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};

pub struct LocationOnRedirectPresent;

/// The sentence that asks a response on `status` for a `Location` field, phrased
/// for the operator reading the finding — `None` where no sentence asks at all.
///
/// Seven statuses have `Location` in their definition and five of them ask for it.
/// Every one of those sentences is in the status's *own* definition, not in the
/// field's section: §10.2.2 says what the value refers to on a 201 and on a 3xx and
/// asks nobody to send it.
///
/// The two that do not ask are answered first and by name, so that each carries the
/// sentence it was read from rather than falling into the silence at the bottom.
fn location_asked_for(status: u16) -> Option<&'static str> {
    // §15.3.2 describes the 201 without the field rather than discouraging it — with
    // no `Location`, the resource created is the target URI. The one sentence that
    // asks a 201 for the field is §9.3.3's, which is about POST;
    // `post_creates_resource` gates on the request method and reports it.
    // Reporting it here too would report every PUT that created a resource at the URI
    // it was sent to, and report a POST twice.
    // cite(RFC 9110 § 15.3.2): "The primary resource created by the request is identified by either a Location header field in the response or, if no Location header field is received, by the target URI."
    // cite(RFC 9110 § 10.2.2): "For 201 (Created) responses, the Location value refers to the primary resource created by the request."
    if status == 201 {
        return None;
    }

    // A 300's SHOULD is conditioned on something no field on the wire records:
    // whether the server *has* a preferred choice. Offering alternatives with no
    // preference among them is what the status is for, and §15.4.1 asks that server
    // for content listing the alternatives, not for a `Location`.
    // cite(RFC 9110 § 15.4.1): "If the server has a preferred choice, the server SHOULD generate a Location header field containing a preferred choice's URI reference."
    // cite(RFC 9110 § 15.4.1): "For request methods other than HEAD, the server SHOULD generate content in the 300 response containing a list of representation metadata and URI reference(s) from which the user or user agent can choose the one most preferred."
    if status == 300 {
        return None;
    }

    // cite(RFC 9110 § 15.4.2): "The server SHOULD generate a Location header field in the response containing a preferred URI reference for the new permanent URI."
    if status == 301 {
        return Some(
            "§15.4.2 asks for a preferred URI reference for the new permanent URI, with a SHOULD",
        );
    }

    // cite(RFC 9110 § 15.4.3): "The server SHOULD generate a Location header field in the response containing a URI reference for the different URI."
    if status == 302 {
        return Some("§15.4.3 asks for a URI reference for the different URI, with a SHOULD");
    }

    // 303 is the one without a SHOULD, and the modal is weaker only in wording: the
    // field is not recommended for this status, it is what the status *is*. A 303
    // whose Location is missing names no resource for the user agent to retrieve.
    // cite(RFC 9110 § 15.4.4): "The 303 (See Other) status code indicates that the server is redirecting the user agent to a different resource, as indicated by a URI in the Location header field, which is intended to provide an indirect response to the original request."
    if status == 303 {
        return Some(
            "§15.4.4 defines the status as a redirection to the resource this field names, so \
             without it the response identifies nothing",
        );
    }

    // The same sentence as 302's, one section away and written for a status whose
    // method is preserved. Two sections, two cites.
    // cite(RFC 9110 § 15.4.8): "The server SHOULD generate a Location header field in the response containing a URI reference for the different URI."
    if status == 307 {
        return Some("§15.4.8 asks for a URI reference for the different URI, with a SHOULD");
    }

    // The same sentence as 301's, for the method-preserving permanent redirect.
    // cite(RFC 9110 § 15.4.9): "The server SHOULD generate a Location header field in the response containing a preferred URI reference for the new permanent URI."
    if status == 308 {
        return Some(
            "§15.4.9 asks for a preferred URI reference for the new permanent URI, with a SHOULD",
        );
    }

    // No cite here, because *no sentence* is what this means. 304 and the deprecated
    // 305/306 are 3xx and are asked for nothing; a 3xx nobody has registered is asked
    // for nothing by anybody. Reaching this arm is not a judgement about the response.
    None
}

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9110_10_2_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("10.2.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.2",
    note: "Defines `Location = URI-reference` and what the value refers to on a 201 and on a 3xx; it asks no one to send the field",
};
const RFC_9110_15_4: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("15.4"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4",
    note: "What a provided Location buys: a user agent MAY redirect to it automatically, even where it does not understand the status code",
};
const RFC_9110_15_4_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("15.4.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.1",
    note: "300 Multiple Choices: the SHOULD applies only if the server has a preferred choice, so this rule does not report a 300",
};
const RFC_9110_15_4_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("15.4.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.2",
    note: "301 Moved Permanently: the server SHOULD generate a Location header field containing a preferred URI reference for the new permanent URI",
};
const RFC_9110_15_4_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("15.4.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.3",
    note: "302 Found: the server SHOULD generate a Location header field containing a URI reference for the different URI",
};
const RFC_9110_15_4_4: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("15.4.4"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.4",
    note: "303 See Other: the status is defined as a redirection to the resource indicated by a URI in the Location header field",
};
const RFC_9110_15_4_8: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("15.4.8"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.8",
    note: "307 Temporary Redirect: the server SHOULD generate a Location header field containing a URI reference for the different URI",
};
const RFC_9110_15_4_9: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("15.4.9"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.9",
    note: "308 Permanent Redirect: the server SHOULD generate a Location header field containing a preferred URI reference for the new permanent URI",
};
const RFC_9110_15_3_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("15.3.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.2",
    note: "201 Created: with no Location field, the resource created is identified by the target URI — which is why this rule does not report a 201",
};

impl RuleMeta for LocationOnRedirectPresent {
    fn id(&self) -> &'static str {
        "location_on_redirect_present"
    }

    fn title(&self) -> Option<&'static str> {
        Some("Redirects that do not say where to")
    }

    fn description(&self) -> &'static str {
        "Five status codes name a `Location` header field in their own definition — four asking for it with a SHOULD, and `303` by being defined in terms of it — and this rule reports a response on one of them that carries none.\n\n- `301 Moved Permanently` — a preferred URI reference for the new permanent URI (RFC 9110 §15.4.2, SHOULD)\n- `302 Found` — a URI reference for the different URI (§15.4.3, SHOULD)\n- `303 See Other` — §15.4.4 defines the status as a redirection to the resource the field names; there is no separate SHOULD because the field is what the status *is*\n- `307 Temporary Redirect` — a URI reference for the different URI (§15.4.8, SHOULD)\n- `308 Permanent Redirect` — a preferred URI reference for the new permanent URI (§15.4.9, SHOULD)\n\n**`300 Multiple Choices` is not reported.** §15.4.1's SHOULD is conditioned on the server *having* a preferred choice, which no field on the wire records; a 300 that offers alternatives with no preference among them is the status working as defined, and §15.4.1 asks that server for content listing the alternatives rather than for a `Location`.\n\n**`201 Created` is not reported either.** §15.3.2 describes the response without the field rather than discouraging it — with no `Location`, the resource created is the target URI. The one sentence that asks a 201 for the field is §9.3.3's, which is about `POST`; `post_creates_resource` knows the request method and reports that case.\n\n`304`, the deprecated `305` and `306`, and any unregistered 3xx are not reported: no sentence asks them for the field.\n\nOnly presence is read. Whether the value is a usable `URI-reference` belongs to `location_header_uri_valid`, and a `Location` on a status that gives it no referent belongs to `redirect_status_and_location_valid`."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_9110_10_2_2,
            RFC_9110_15_4,
            RFC_9110_15_4_1,
            RFC_9110_15_4_2,
            RFC_9110_15_4_3,
            RFC_9110_15_4_4,
            RFC_9110_15_4_8,
            RFC_9110_15_4_9,
            RFC_9110_15_3_2,
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("301: the preferred URI reference for the new permanent URI"),
                snippet: "HTTP/1.1 301 Moved Permanently\nLocation: https://example.org/new",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("303: the resource the user agent is being redirected to"),
                snippet: "HTTP/1.1 303 See Other\nLocation: /orders/9001",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some(
                    "300 with no preferred choice: §15.4.1's SHOULD does not apply, and the alternatives go in the content",
                ),
                snippet: "HTTP/1.1 300 Multiple Choices\nContent-Type: text/html",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some(
                    "201 with no Location: the resource created is the target URI. A POST that created one is `post_creates_resource`'s question",
                ),
                snippet: "HTTP/1.1 201 Created\nContent-Type: application/json",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("302 with nothing to be found at"),
                snippet: "HTTP/1.1 302 Found\nContent-Type: text/html",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("308: a permanent redirect that does not say where to"),
                snippet: "HTTP/1.1 308 Permanent Redirect\nContent-Type: text/html",
            },
        ]
    }
}

impl Rule for LocationOnRedirectPresent {
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

            // The status is read first because the status is what gives the field a
            // referent at all — which is also why the set below is not the one
            // `redirect_status_and_location_valid` carries. That rule asks
            // which statuses give `Location` something to refer *to*, so its list keeps
            // the 201 and the 300; this one asks which statuses have a sentence asking
            // for the field, and neither of those does. The two lists were byte-identical
            // and are not the same question.
            // cite(RFC 9110 § 10.2.2): "For 3xx (Redirection) responses, the Location value refers to the preferred target resource for automatically redirecting the request."
            let reason = location_asked_for(resp.status)?;

            // Presence is the whole input, and this is what presence buys: a user agent
            // that would have followed the redirect has a URI to follow. So a value on any
            // field line counts and nothing is joined across lines; an empty value counts
            // too, because a field line is what the sentence asked for and whether the
            // value is usable is `location_header_uri_valid`'s question — it reads
            // each `Location` line and this rule reads none of them.
            // cite(RFC 9110 § 15.4): "If a Location header field (Section 10.2.2) is provided, the user agent MAY automatically redirect its request to the URI referenced by the Location field value, even if the specific status code is not understood."
            if resp.headers.get_all("location").iter().next().is_some() {
                return None;
            }

            // No cite of its own: what makes this a violation is the sentence
            // `location_asked_for` matched, cited at the branch that matched it and
            // carried into the message from there.
            Some(self.violation(
                ctx.severity,
                format!(
                    "Response with status {status} carries no Location header field, and {reason}. \
                     A user agent has no target to redirect to",
                    status = resp.status,
                ),
            ))
        };
        Vec::from_iter(finding())
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &LocationOnRedirectPresent;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// Every fixture is a response on some status, carrying the field or not.
    fn response_with(
        status: u16,
        location: Option<&str>,
    ) -> crate::http_transaction::HttpTransaction {
        let pairs: Vec<(&str, &str)> = location.into_iter().map(|v| ("location", v)).collect();
        crate::test_helpers::make_test_transaction_with_response(status, &pairs)
    }

    fn judge(tx: &crate::http_transaction::HttpTransaction) -> Option<Violation> {
        let rule = LocationOnRedirectPresent;
        crate::test_helpers::run_rule(
            &rule,
            tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
    }

    /// One case per arm of `location_asked_for`, in both directions.
    #[rstest]
    #[case(301, false, true)]
    #[case(301, true, false)]
    #[case(302, false, true)]
    #[case(302, true, false)]
    #[case(303, false, true)]
    #[case(303, true, false)]
    #[case(307, false, true)]
    #[case(307, true, false)]
    #[case(308, false, true)]
    #[case(308, true, false)]
    fn the_five_statuses_a_sentence_asks(
        #[case] status: u16,
        #[case] with_location: bool,
        #[case] expect_violation: bool,
    ) {
        let tx = response_with(status, with_location.then_some("/new"));
        let v = judge(&tx);
        assert_eq!(v.is_some(), expect_violation, "{status} -> {v:?}");
    }

    /// §15.4.1's SHOULD applies only if the server has a preferred choice, which is
    /// not on the wire — so a 300 with no Location is the status working as defined.
    #[rstest]
    #[case(300, None)]
    #[case(300, Some("/preferred"))]
    fn a_300_is_never_reported(#[case] status: u16, #[case] location: Option<&str>) {
        assert!(judge(&response_with(status, location)).is_none());
    }

    /// §15.3.2 defines the no-Location 201: the resource created is the target URI.
    /// The POST case is `post_creates_resource`'s, which knows the method.
    #[rstest]
    #[case(201, None)]
    #[case(201, Some("/resource/123"))]
    fn a_201_is_never_reported(#[case] status: u16, #[case] location: Option<&str>) {
        assert!(judge(&response_with(status, location)).is_none());
    }

    /// No sentence asks these for the field, so reaching the fall-through is not a
    /// judgement about the response.
    #[rstest]
    #[case(304)]
    #[case(305)]
    #[case(306)]
    #[case(309)]
    #[case(399)]
    #[case(200)]
    #[case(404)]
    fn statuses_no_sentence_asks(#[case] status: u16) {
        assert!(judge(&response_with(status, None)).is_none());
        assert!(judge(&response_with(status, Some("/somewhere"))).is_none());
    }

    #[test]
    fn no_response_no_violation() {
        let rule = LocationOnRedirectPresent;
        let tx = crate::test_helpers::make_test_transaction();
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn id_and_scope() {
        let rule = LocationOnRedirectPresent;
        assert_eq!(rule.id(), "location_on_redirect_present");
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "location_on_redirect_present",
        ]);
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    /// The message is derived data: it names the status and the sentence that asked.
    /// Both are claims, so both are pinned, per arm.
    #[rstest]
    #[case(301, "§15.4.2")]
    #[case(302, "§15.4.3")]
    #[case(303, "§15.4.4")]
    #[case(307, "§15.4.8")]
    #[case(308, "§15.4.9")]
    fn the_message_names_the_status_and_its_sentence(#[case] status: u16, #[case] section: &str) {
        let v = judge(&response_with(status, None)).expect("expected violation");
        assert!(
            v.message.contains(&format!("status {status}")),
            "{}",
            v.message
        );
        assert!(v.message.contains(section), "{}", v.message);
    }

    /// Every published snippet is run through the rule.
    #[test]
    fn published_examples_are_judged_by_this_rule() {
        use crate::rules::{Compliance, RuleMeta as _};
        let rule = LocationOnRedirectPresent;

        for ex in rule.examples() {
            let mut status = None;
            let mut pairs: Vec<(&str, &str)> = Vec::new();
            for (i, line) in ex.snippet.lines().enumerate() {
                if i == 0 {
                    let code = line
                        .strip_prefix("HTTP/1.1 ")
                        .and_then(|rest| rest.split_whitespace().next())
                        .and_then(|code| code.parse::<u16>().ok())
                        .unwrap_or_else(|| {
                            panic!("the first line of an example is its status line: {line:?}")
                        });
                    status = Some(code);
                    continue;
                }
                let (name, value) = line.split_once(':').unwrap_or_else(|| {
                    panic!("example header line is not `Name: value`: {line:?}")
                });
                pairs.push((name, value.trim()));
            }
            let status = status.expect("example has a status line");

            let tx = crate::test_helpers::make_test_transaction_with_response(status, &pairs);
            let v = judge(&tx);
            match ex.compliance {
                Compliance::Compliant => assert!(v.is_none(), "{}: {v:?}", ex.snippet),
                Compliance::NonCompliant => assert!(v.is_some(), "{}", ex.snippet),
            }
        }
    }
}
