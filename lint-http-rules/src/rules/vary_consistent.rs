// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::vary::{RFC_9111_4_1, VARY_CONFLICTING};
use crate::violations::ViolationDef;

/// One entry: a default response whose `Vary` leaves out a field a sibling
/// names.
static DECLARED: &[&ViolationDef] = &[&VARY_CONFLICTING];

/// Compares each cacheable response's `Vary` with the earlier ones for the same
/// resource, and reports the default response — the one to a request that did
/// not carry a field — that does not name the field its siblings name.
pub struct VaryConsistent;

impl RuleMeta for VaryConsistent {
    fn id(&self) -> &'static str {
        "vary_consistent"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn title(&self) -> Option<&'static str> {
        Some("A resource's default response names the fields its siblings vary on")
    }

    fn description(&self) -> &'static str {
        "Reports a resource whose responses disagree about what selects them: one names a request field in `Vary`, and another — sent to a request that did not carry the field — does not.\n\n**RFC 9111 §4.1 names this as a mistake.** *\"Some resources mistakenly omit the Vary header field from their default response (i.e., the one sent when the request does not express any preferences), with the effect of choosing it for subsequent requests to that resource even when more preferable responses are available.\"* The common shape is a server that adds `Vary: Accept-Encoding` only when it compresses: its answer to a request without `Accept-Encoding` goes out with no `Vary`, a cache stores it, and every later client gets the uncompressed body. The same shape with `Cookie` hands the anonymous page to a signed-in user.\n\n**Which responses are compared.** Two responses to `GET`s from the same client for the same target URI, both with the same status code, both of which a cache could have stored (RFC 9111 §3). A `Vary: *` on either side is no list to compare. A field counts as absent from a request only where the request carried no line of it at all.\n\n**One finding for each response that omits the field.** When the omitting response arrives after one that named the field, the finding is on it. When it arrived first, the finding is on the first response that names the field, naming the earlier one — and not again on every response after that, so a resource that was wrong once is reported once.\n\n**Not this rule's.** A `206` or a `304` that leaves out the `Vary` its `200` carried is `status_206_required_fields`' and `status_304_required_fields`'. A coded response without `Accept-Encoding` in `Vary` is `vary_and_content_encoding_consistent`'s, whatever its siblings say."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_9111_4_1]
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
                label: Some("— the default response names the field too"),
                snippet: "GET /a HTTP/1.1\nHost: example.com\n\nHTTP/1.1 200 OK\nVary: Accept-Encoding\nCache-Control: max-age=600\n\nGET /a HTTP/1.1\nHost: example.com\nAccept-Encoding: gzip\n\nHTTP/1.1 200 OK\nContent-Encoding: gzip\nVary: Accept-Encoding\nCache-Control: max-age=600\n",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— Vary only when the response was compressed"),
                snippet: "GET /a HTTP/1.1\nHost: example.com\n\nHTTP/1.1 200 OK\nCache-Control: max-age=600\n\nGET /a HTTP/1.1\nHost: example.com\nAccept-Encoding: gzip\n\nHTTP/1.1 200 OK\nContent-Encoding: gzip\nVary: Accept-Encoding\nCache-Control: max-age=600\n",
            },
        ]
    }
}

/// The fields a response nominates, if it is one this rule compares: a `GET`
/// answer a cache could have stored, whose `Vary` is a list rather than `*`.
///
/// `*` is no list: it says the selection turned on something no request field
/// names, so there is no field for a sibling to have left out.
// cite(RFC 9111 § 4.1): "A stored response with a Vary header field value containing a member "*" always fails to match."
fn nominated(tx: &crate::http_transaction::HttpTransaction) -> Option<Vec<String>> {
    let resp = tx.response.as_ref()?;
    if tx.request.method != "GET"
        || !crate::helpers::stored_response::response_is_storable(
            &tx.request.method,
            &tx.request.headers,
            resp.status,
            &resp.headers,
        )
    {
        return None;
    }
    match crate::helpers::vary::vary_nomination(&resp.headers) {
        crate::helpers::vary::VaryNomination::Wildcard => None,
        crate::helpers::vary::VaryNomination::Fields(fields) => Some(fields),
    }
}

/// Whether the request carried no line of `field` — the request § 4.1 calls
/// one that "does not express any preferences" in it.
// cite(RFC 9111 § 4.1): "Some resources mistakenly omit the Vary header field from their default response (i.e., the one sent when the request does not express any preferences)"
fn lacks(tx: &crate::http_transaction::HttpTransaction, field: &str) -> bool {
    !tx.request.headers.contains_key(field)
}

impl Rule for VaryConsistent {
    fn needs_response(&self) -> bool {
        true
    }

    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        let Some(here) = nominated(tx) else {
            return Vec::new();
        };
        let Some(status) = tx.response.as_ref().map(|r| r.status) else {
            return Vec::new();
        };
        // The siblings: earlier answers of the same status, each with the
        // fields it named. A `404` and a `200` for one URI are two states of the
        // resource, not two selections from one.
        let siblings: Vec<_> = history
            .iter()
            .filter(|e| e.response.as_ref().is_some_and(|r| r.status == status))
            .filter_map(|e| nominated(e).map(|fields| (e, fields)))
            .collect();

        let mut out = Vec::new();

        // This response is the default one: its request lacked a field an
        // earlier sibling named, and it names no such field itself.
        let mut omitted: Vec<&String> = Vec::new();
        for (_, fields) in &siblings {
            for field in fields {
                if !here.contains(field) && lacks(tx, field) && !omitted.contains(&field) {
                    omitted.push(field);
                }
            }
        }
        for field in omitted {
            out.push(ctx.report_with(
                &VARY_CONFLICTING,
                format!(
                    "Vary here does not name {name}, which an earlier {status} for the same URI \
                     named, and this request carried no {name} \u{2014} a cache holding this \
                     default response answers every later request with it whatever {name} they \
                     carry; name {name} in this response's Vary too (RFC 9111 \u{a7} 4.1)",
                    name = crate::helpers::shown::shown_in_finding(field),
                ),
            ));
        }

        // An earlier sibling was the default one. Reported here only where this
        // response is the first to name the field, so the earlier omission is
        // one finding and not one per response after it.
        for field in &here {
            let named_before = siblings.iter().any(|(_, fields)| fields.contains(field));
            let omitted_before = siblings
                .iter()
                .any(|(e, fields)| !fields.contains(field) && lacks(e, field));
            if !named_before && omitted_before {
                out.push(ctx.report_with(
                    &VARY_CONFLICTING,
                    format!(
                        "Vary here names {name}, and an earlier {status} for the same URI, \
                         answering a request without {name}, named no {name} \u{2014} a cache \
                         holding that default response answers every later request with it \
                         whatever {name} they carry; name {name} in its Vary too \
                         (RFC 9111 \u{a7} 4.1)",
                        name = crate::helpers::shown::shown_in_finding(field),
                    ),
                ));
            }
        }

        out
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &VaryConsistent;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    type Exchange<'a> = (&'a [(&'a str, &'a str)], u16, &'a [(&'a str, &'a str)]);

    /// A sequence of `GET`s for one resource, oldest first; the last is judged.
    fn judge(exchanges: &[Exchange<'_>]) -> Vec<Violation> {
        let base = chrono::Utc::now();
        let n = exchanges.len() as i64;
        let mut txs: Vec<_> = exchanges
            .iter()
            .enumerate()
            .map(|(i, (request, status, response))| {
                let mut t =
                    crate::test_helpers::make_test_transaction_with_response(*status, response);
                t.request.uri = "http://example/a".to_string();
                t.request.headers = crate::test_helpers::make_headers_from_pairs(request);
                t.timestamp = base - chrono::Duration::seconds(n - i as i64);
                t
            })
            .collect();
        let tx = txs.pop().expect("an exchange to judge");
        txs.reverse();
        crate::test_helpers::run_rule_all(
            &VaryConsistent,
            &tx,
            &crate::transaction_history::TransactionHistory::from_transactions(txs),
            &crate::test_helpers::make_test_config_with_enabled_rules(&["vary_consistent"]),
        )
    }

    const NONE: &[(&str, &str)] = &[];
    const GZIP: &[(&str, &str)] = &[("accept-encoding", "gzip")];
    const PLAIN: &[(&str, &str)] = &[("cache-control", "max-age=600")];
    const NAMED_PLAIN: &[(&str, &str)] = &[
        ("cache-control", "max-age=600"),
        ("vary", "accept-encoding"),
    ];
    const WILDCARD: &[(&str, &str)] = &[("cache-control", "max-age=600"), ("vary", "*")];
    const NO_STORE: &[(&str, &str)] = &[("cache-control", "no-store")];
    const BR: &[(&str, &str)] = &[("accept-encoding", "br")];
    const VARIED: &[(&str, &str)] = &[
        ("cache-control", "max-age=600"),
        ("vary", "Accept-Encoding"),
        ("content-encoding", "gzip"),
    ];

    /// The default response second: it is the finding.
    #[test]
    fn a_default_response_after_a_varied_one_is_reported() {
        let found = judge(&[(GZIP, 200, VARIED), (NONE, 200, PLAIN)]);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].violation, "vary_conflicting");
        assert_eq!(found[0].severity, crate::lint::Severity::Warn);
        assert!(
            found[0]
                .message
                .contains("Vary here does not name accept-encoding"),
            "{}",
            found[0].message
        );
    }

    /// The default response first: the first response to name the field says so,
    /// and the ones after it do not say it again.
    #[test]
    fn a_default_response_before_a_varied_one_is_reported_once() {
        let first = judge(&[(NONE, 200, PLAIN), (NONE, 200, PLAIN), (GZIP, 200, VARIED)]);
        assert_eq!(first.len(), 1, "{first:?}");
        assert!(
            first[0].message.contains("an earlier 200"),
            "{}",
            first[0].message
        );

        let later = judge(&[(NONE, 200, PLAIN), (GZIP, 200, VARIED), (GZIP, 200, VARIED)]);
        assert!(later.is_empty(), "{later:?}");
    }

    /// Silence wherever the two responses agree, or are not two selections
    /// from one resource.
    #[rstest]
    #[case::both_name_it(&[(NONE, 200, NAMED_PLAIN), (GZIP, 200, VARIED)])]
    #[case::neither_names_it(&[(NONE, 200, PLAIN), (GZIP, 200, PLAIN)])]
    #[case::the_request_carried_it(&[(GZIP, 200, VARIED), (BR, 200, PLAIN)])]
    #[case::other_status(&[(GZIP, 200, VARIED), (NONE, 404, PLAIN)])]
    #[case::not_storable(&[(GZIP, 200, VARIED), (NONE, 200, NO_STORE)])]
    #[case::wildcard_default(&[(GZIP, 200, VARIED), (NONE, 200, WILDCARD)])]
    #[case::wildcard_sibling(&[(GZIP, 200, WILDCARD), (NONE, 200, PLAIN)])]
    #[case::alone(&[(NONE, 200, PLAIN)])]
    fn agreement_is_silence(#[case] exchanges: &[Exchange<'_>]) {
        let found = judge(exchanges);
        assert!(found.is_empty(), "{found:?}");
    }

    /// A field named on a second `Vary` line is named; one named in another
    /// case is the same field.
    #[test]
    fn the_whole_vary_field_is_read() {
        let two_lines: &[(&str, &str)] = &[
            ("cache-control", "max-age=600"),
            ("vary", "Origin"),
            ("vary", "ACCEPT-ENCODING"),
        ];
        let one_line: &[(&str, &str)] = &[
            ("cache-control", "max-age=600"),
            ("vary", "origin, accept-encoding"),
        ];
        let found = judge(&[(GZIP, 200, two_lines), (NONE, 200, one_line)]);
        assert!(found.is_empty(), "{found:?}");
    }

    /// Two fields omitted are two findings, each naming its field.
    #[test]
    fn each_omitted_field_is_its_own_finding() {
        let asked: &[(&str, &str)] = &[("accept-encoding", "gzip"), ("cookie", "s=1")];
        let varied: &[(&str, &str)] = &[
            ("cache-control", "max-age=600"),
            ("vary", "Accept-Encoding, Cookie"),
        ];
        let found = judge(&[(asked, 200, varied), (NONE, 200, PLAIN)]);
        assert_eq!(found.len(), 2, "{found:?}");
        assert!(found.iter().any(|v| v.message.contains("name cookie")));
        assert!(found
            .iter()
            .any(|v| v.message.contains("name accept-encoding")));
    }
}
