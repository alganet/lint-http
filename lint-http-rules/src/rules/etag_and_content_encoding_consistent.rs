// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::etag::{ETAG_CONFLICTING, RFC_9110_8_8_1, RFC_9110_8_8_3};
use crate::violations::ViolationDef;

/// One entry: a strong tag two content codings share.
static DECLARED: &[&ViolationDef] = &[&ETAG_CONFLICTING];

/// A strong `ETag` is a claim that no other representation of the resource
/// carries it unless its octets are identical, and a content coding changes the
/// octets. This rule compares each `200` to a `GET` against the earlier `200`s
/// for the same resource, and reports the same strong tag on two whose
/// `Content-Encoding` differs.
pub struct EtagAndContentEncodingConsistent;

impl RuleMeta for EtagAndContentEncodingConsistent {
    fn id(&self) -> &'static str {
        "etag_and_content_encoding_consistent"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn title(&self) -> Option<&'static str> {
        Some("A strong ETag belongs to one content coding")
    }

    fn description(&self) -> &'static str {
        "Reports a strong entity tag that a server sent on two `200` responses for the same resource whose content codings differ — `Content-Encoding: br` on one and none on the other, or `gzip` on one and `br` on the other.\n\n**A content coding is part of the representation data.** RFC 9110 §8.8.1 gives exactly this pairing as its example of a validator that is weak, whatever it is labelled: *\"if the origin server sends the same validator for a representation with a gzip content coding applied as it does for a representation with no content coding, then that validator is weak.\"* §8.8.3.3 says why the label matters: a cache updating a stored response after a `304`, and a client resuming a download with `If-Range`, both take a matching strong tag to mean the octets they hold are the octets the server would send. Under a shared tag, the second half of one coding is spliced onto the first half of the other.\n\n**The usual cause is compression added after the tag was computed** — a server or a CDN edge that compresses on the way out and passes the origin's tag through. Two repairs work: a distinct tag per coding (the §8.8.3.3 example appends a suffix), or marking the tag weak with `W/`, which is what several servers do when they compress on the fly.\n\n**What is compared.** Only `GET` requests answered `200`: a `HEAD` response may leave out a field that is determined while generating content (§9.3.2), and a `206` carries a part of a representation rather than a whole one. Two responses are the same resource when they answer the same client for the same target URI. The codings are compared as lists — case-insensitively, with `identity` and empty members dropped — so `gzip` and `GZIP` are one coding and `gzip, br` and `br, gzip` are two. A weak tag is never reported: sharing is what `W/` permits.\n\n**Not this rule's.** Two media types under one strong tag are allowed — §8.8.1 says representations differing only in metadata may share one. Whether the tag is well formed is `etag_syntax`'s."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_9110_8_8_1, RFC_9110_8_8_3]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::Presumed(crate::lint::Party::Server)
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("— a distinct tag per coding"),
                snippet: "GET /a HTTP/1.1\nHost: example.com\n\nHTTP/1.1 200 OK\nETag: \"123-a\"\nVary: Accept-Encoding\n\nGET /a HTTP/1.1\nHost: example.com\nAccept-Encoding: gzip\n\nHTTP/1.1 200 OK\nETag: \"123-b\"\nContent-Encoding: gzip\nVary: Accept-Encoding\n",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("— one weak tag for both"),
                snippet: "GET /a HTTP/1.1\nHost: example.com\n\nHTTP/1.1 200 OK\nETag: W/\"123\"\nVary: Accept-Encoding\n\nGET /a HTTP/1.1\nHost: example.com\nAccept-Encoding: gzip\n\nHTTP/1.1 200 OK\nETag: W/\"123\"\nContent-Encoding: gzip\nVary: Accept-Encoding\n",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— the unencoded and the gzip response share a strong tag"),
                snippet: "GET /a HTTP/1.1\nHost: example.com\n\nHTTP/1.1 200 OK\nETag: \"123\"\nVary: Accept-Encoding\n\nGET /a HTTP/1.1\nHost: example.com\nAccept-Encoding: gzip\n\nHTTP/1.1 200 OK\nETag: \"123\"\nContent-Encoding: gzip\nVary: Accept-Encoding\n",
            },
        ]
    }
}

/// How a finding names a list of codings: the list, or `no content coding`.
fn shown_codings(codings: &[String]) -> String {
    if codings.is_empty() {
        "no content coding".to_string()
    } else {
        format!(
            "Content-Encoding: {}",
            crate::helpers::shown::shown_in_finding(&codings.join(", "))
        )
    }
}

/// The strong tag a `200` to a `GET` carries, as written and trimmed.
///
/// One field line, the first: `ETag` is a singleton, and a repeated one is
/// `singleton_fields_not_repeated`'s. A `W/` tag is no claim of uniqueness, so
/// it has nothing to conflict with.
fn strong_tag(tx: &crate::http_transaction::HttpTransaction) -> Option<String> {
    let resp = tx.response.as_ref()?;
    if tx.request.method != "GET" || resp.status != 200 {
        return None;
    }
    let (etag, _) =
        crate::helpers::validator::extract_strong_validators_from_response(&resp.headers);
    etag.filter(|tag| tag.starts_with('"'))
}

impl Rule for EtagAndContentEncodingConsistent {
    fn needs_response(&self) -> bool {
        true
    }

    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        let Some(tag) = strong_tag(tx) else {
            return Vec::new();
        };
        let Some(resp) = tx.response.as_ref() else {
            return Vec::new();
        };
        let here = crate::helpers::content_coding::applied_codings(&resp.headers);

        // The newest earlier `200` under the same tag with a different coding.
        // One finding per response: the tag is the defect, and naming every
        // earlier response that shares it would be one defect reported once
        // per exchange the client happened to make.
        //
        // Tag equality is octet-for-octet on the whole `opaque-tag`, which is
        // strong comparison with the `W/` already excluded on both sides.
        // cite(RFC 9110 § 8.8.3.2): "two entity tags are equivalent if both are not weak and their opaque-tags match character-by-character."
        let Some(there) = history.iter().find_map(|earlier| {
            let earlier_resp = earlier.response.as_ref()?;
            let theirs = crate::helpers::content_coding::applied_codings(&earlier_resp.headers);
            (strong_tag(earlier).as_deref() == Some(tag.as_str()) && theirs != here)
                .then_some(theirs)
        }) else {
            return Vec::new();
        };

        vec![ctx.report_with(
            &ETAG_CONFLICTING,
            format!(
                "Strong ETag {} names this response ({}) and an earlier 200 for the same URI \
                 ({}) \u{2014} a content coding changes the representation data, so the tag \
                 must differ per coding or be marked weak (W/); RFC 9110 \u{a7} 8.8.1, \
                 \u{a7} 8.8.3.3",
                crate::helpers::shown::shown_in_finding(&tag),
                shown_codings(&here),
                shown_codings(&there),
            ),
        )]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &EtagAndContentEncodingConsistent;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// An earlier exchange and this one, for the same client and resource.
    fn pair(
        earlier_method: &str,
        earlier_status: u16,
        earlier: &[(&str, &str)],
        method: &str,
        status: u16,
        now: &[(&str, &str)],
    ) -> Vec<Violation> {
        let base = chrono::Utc::now();
        let mut first =
            crate::test_helpers::make_test_transaction_with_response(earlier_status, earlier);
        first.request.method = earlier_method.to_string();
        first.request.uri = "http://example/a".to_string();
        first.timestamp = base - chrono::Duration::seconds(1);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(status, now);
        tx.request.method = method.to_string();
        tx.request.uri = "http://example/a".to_string();
        tx.timestamp = base;

        crate::test_helpers::run_rule_all(
            &EtagAndContentEncodingConsistent,
            &tx,
            &crate::transaction_history::TransactionHistory::from_transactions(vec![first]),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "etag_and_content_encoding_consistent",
            ]),
        )
    }

    fn get_pair(earlier: &[(&str, &str)], now: &[(&str, &str)]) -> Vec<Violation> {
        pair("GET", 200, earlier, "GET", 200, now)
    }

    /// The codings that differ, in either order, and the ones that only look
    /// different.
    #[rstest]
    #[case::gzip_and_none(Some("gzip"), None, true)]
    #[case::none_and_br(None, Some("br"), true)]
    #[case::gzip_and_br(Some("gzip"), Some("br"), true)]
    #[case::two_orders(Some("gzip, br"), Some("br, gzip"), true)]
    #[case::same(Some("gzip"), Some("gzip"), false)]
    #[case::case_only(Some("gzip"), Some("GZIP"), false)]
    #[case::identity_is_none(Some("identity"), None, false)]
    #[case::empty_is_none(Some(""), None, false)]
    #[case::ows_only(Some(" gzip "), Some("gzip"), false)]
    fn a_strong_tag_is_one_coding(
        #[case] earlier: Option<&str>,
        #[case] now: Option<&str>,
        #[case] reported: bool,
    ) {
        fn with(coding: Option<&str>) -> Vec<(&str, &str)> {
            let mut h = vec![("etag", "\"123\"")];
            if let Some(c) = coding {
                h.push(("content-encoding", c));
            }
            h
        }
        let found = get_pair(&with(earlier), &with(now));
        assert_eq!(found.len(), usize::from(reported), "{found:?}");
        if reported {
            assert_eq!(found[0].violation, "etag_conflicting");
            assert_eq!(found[0].severity, crate::lint::Severity::Warn);
        }
    }

    /// The finding names the tag and both codings, so an operator has the three
    /// values to look for.
    #[test]
    fn the_finding_names_the_tag_and_both_codings() {
        let found = get_pair(
            &[("etag", "\"3632-65bd\"")],
            &[("etag", "\"3632-65bd\""), ("content-encoding", "br")],
        );
        let msg = &found[0].message;
        assert!(msg.contains("\"3632-65bd\""), "{msg}");
        assert!(msg.contains("Content-Encoding: br"), "{msg}");
        assert!(msg.contains("no content coding"), "{msg}");
    }

    /// Different tags, a weak tag on either side, and a tag that is not a tag
    /// are all silence.
    #[rstest]
    #[case::distinct_tags("\"123-a\"", "\"123-b\"")]
    #[case::both_weak("W/\"123\"", "W/\"123\"")]
    #[case::earlier_weak("W/\"123\"", "\"123\"")]
    #[case::now_weak("\"123\"", "W/\"123\"")]
    #[case::unquoted("123", "123")]
    fn only_one_strong_tag_can_conflict(#[case] earlier: &str, #[case] now: &str) {
        let found = get_pair(
            &[("etag", earlier)],
            &[("etag", now), ("content-encoding", "gzip")],
        );
        assert!(found.is_empty(), "{found:?}");
    }

    /// A `HEAD` may leave `Content-Encoding` out, and a `206` is a part: the
    /// comparison is between two whole `GET` answers.
    #[rstest]
    #[case::earlier_head("HEAD", 200, "GET", 200)]
    #[case::now_head("GET", 200, "HEAD", 200)]
    #[case::earlier_partial("GET", 206, "GET", 200)]
    #[case::now_partial("GET", 200, "GET", 206)]
    #[case::not_modified("GET", 304, "GET", 200)]
    fn only_two_whole_get_answers_are_compared(
        #[case] earlier_method: &str,
        #[case] earlier_status: u16,
        #[case] method: &str,
        #[case] status: u16,
    ) {
        let found = pair(
            earlier_method,
            earlier_status,
            &[("etag", "\"123\"")],
            method,
            status,
            &[("etag", "\"123\""), ("content-encoding", "gzip")],
        );
        assert!(found.is_empty(), "{found:?}");
    }

    /// One finding however many earlier responses share the tag.
    #[test]
    fn one_finding_for_many_earlier_responses() {
        let base = chrono::Utc::now();
        let earlier: Vec<_> = (1..=3)
            .map(|i| {
                let mut t = crate::test_helpers::make_test_transaction_with_response(
                    200,
                    &[("etag", "\"123\"")],
                );
                t.request.uri = "http://example/a".to_string();
                t.timestamp = base - chrono::Duration::seconds(i);
                t
            })
            .collect();
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("etag", "\"123\""), ("content-encoding", "gzip")],
        );
        tx.request.uri = "http://example/a".to_string();
        tx.timestamp = base;
        let found = crate::test_helpers::run_rule_all(
            &EtagAndContentEncodingConsistent,
            &tx,
            &crate::transaction_history::TransactionHistory::from_transactions(earlier),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "etag_and_content_encoding_consistent",
            ]),
        );
        assert_eq!(found.len(), 1, "{found:?}");
    }

    /// No history, nothing to compare.
    #[test]
    fn a_first_response_has_nothing_to_conflict_with() {
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("etag", "\"123\""), ("content-encoding", "gzip")],
        );
        let found = crate::test_helpers::run_rule_all(
            &EtagAndContentEncodingConsistent,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "etag_and_content_encoding_consistent",
            ]),
        );
        assert!(found.is_empty());
    }
}
