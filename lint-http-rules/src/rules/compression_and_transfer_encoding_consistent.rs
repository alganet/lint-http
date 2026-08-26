// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct CompressionAndTransferEncodingConsistent;

impl Rule for CompressionAndTransferEncodingConsistent {
    fn id(&self) -> &'static str {
        "compression_and_transfer_encoding_consistent"
    }

    /// `Both`, because both fields are defined for both directions and the
    /// observation this rule makes is about two *layers*, not two roles. It was
    /// `Server`, which in this engine means "skip when there is no response" --
    /// so a request carrying the same coding in both fields was never examined
    /// at all.
    /// cite(RFC 9110 § 8.4): "An origin server MAY respond with a status code of 415 (Unsupported Media Type) if a representation in the request message has a content coding that is not acceptable."
    /// cite(RFC 9112 § 6.1): "If any transfer coding other than chunked is applied to a request's content, the sender MUST apply chunked as the final transfer coding to ensure that the message is properly framed."
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Option<Violation> {
        // Both fields are lists whose members a sender may spread over several
        // field lines, and there the resemblance ends: their grammars differ in
        // a way that decides how each is split.
        //
        // Values are decoded from the raw octets rather than read through
        // `to_str`, which refuses everything outside visible US-ASCII and used
        // to drop the whole field line. Neither coding name can contain such an
        // octet -- both are `token` -- so one appearing where a name belongs
        // simply fails to match anything, which is the right outcome; dropping
        // the line instead hid every *other* name on it.
        let decode = crate::helpers::headers::field_line_as_written;

        let check = |headers: &hyper::HeaderMap, side: &str| -> Option<Violation> {
            // `content-coding` is a bare `token` with no parameters, so every comma
            // is a separator and there is no quoting to respect.
            // cite(RFC 9110 § 8.4): "Content-Encoding = #content-coding"
            // cite(RFC 9110 § 8.4.1): "content-coding   = token"
            let mut ce_set = std::collections::HashSet::new();
            for hv in headers.get_all("content-encoding").iter() {
                let s = decode(hv);
                for part in crate::helpers::headers::list_members(&s) {
                    // Nothing in this field's grammar sits behind a `;`, so this
                    // strips something that cannot legally be there. It is kept as
                    // a deliberate tolerance: a sender writing `gzip;q=1.0` here
                    // has produced one malformed token, and reading the name out of
                    // it keeps this advisory useful on a value that
                    // `content_encoding_registered` is already
                    // reporting as malformed. It cannot invent an overlap -- the
                    // text before the `;` is text the sender wrote.
                    // The trim is `OWS`, not `str::trim`: the value is read one
                    // `char` per octet, so %xA0 reaches here as U+00A0 —
                    // `char::is_whitespace` admits it and no `token` does, and
                    // taking it would turn a name no production writes into
                    // `gzip`.
                    // cite(RFC 9110 § 5.6.3, label: OWS grammar): "OWS            = *( SP / HTAB )"
                    // cite(RFC 9110 § 8.4.1): "All content codings are case-insensitive and ought to be registered within the "HTTP Content Coding Registry","
                    let token = crate::helpers::headers::trim_ows(part.split(';').next().unwrap())
                        .to_ascii_lowercase();
                    if token.is_empty() {
                        continue;
                    }
                    ce_set.insert(token);
                }
            }

            // `transfer-coding` does carry parameters, and a parameter value may be
            // a `quoted-string` holding a comma, so this split has to respect them.
            //
            // No unbalanced-quote guard, unlike the two sibling rules on these
            // fields. Quoting that never closes swallows the rest of the value
            // into one member, and the name this reads off it is still the name
            // in front of the first `;` -- a name the sender wrote. Later names
            // are lost, so the only thing at risk is a finding, never a false
            // one, and this rule reports nothing about the malformed value
            // anyway. Do not "harmonise" a decline into this loop: it would
            // trade a missed advisory for nothing.
            // cite(RFC 9110 § 10.1.4): "transfer-coding    = token *( OWS ";" OWS transfer-parameter )"
            // cite(RFC 9110 § 10.1.4): "transfer-parameter = token BWS "=" BWS ( token / quoted-string )"
            let mut te_set = std::collections::HashSet::new();
            for hv in headers.get_all("transfer-encoding").iter() {
                let s = decode(hv);
                for part in crate::helpers::headers::split_commas_respecting_quotes(&s) {
                    // `OWS` for the same reason as the `Content-Encoding` loop
                    // above, and this production prints it: the whitespace around
                    // the `;` is `OWS` and nothing wider.
                    // cite(RFC 9110 § 5.6.3, label: OWS grammar): "OWS            = *( SP / HTAB )"
                    // cite(RFC 9112 § 7): "All transfer-coding names are case-insensitive and ought to be registered within the HTTP Transfer Coding registry, as defined in Section 7.3."
                    let token = crate::helpers::headers::trim_ows(part.split(';').next().unwrap())
                        .to_ascii_lowercase();
                    if token.is_empty() {
                        continue;
                    }
                    te_set.insert(token);
                }
            }

            // If either header is absent or no valid tokens present, nothing to check
            if ce_set.is_empty() || te_set.is_empty() {
                return None;
            }

            // The comparison, and the whole premise of the rule -- which had no
            // citation of any kind, and a user-facing message pointing at
            // § 5.3, "Field Order".
            //
            // The two fields address different layers, and both specifications
            // say so in mirrored sentences:
            // cite(RFC 9112 § 6.1): "Unlike Content-Encoding (Section 8.4.1 of [HTTP]), Transfer-Encoding is a property of the message, not of the representation."
            // cite(RFC 9110 § 8.4): "Unlike Transfer-Encoding (Section 6.1 of [HTTP/1.1]), the codings listed in Content-Encoding are a characteristic of the representation; the representation is defined in terms of the coded form, and all other metadata about the representation is about the coded form unless otherwise noted in the metadata definition."
            //
            // **Nothing forbids naming the same coding at both layers.** It
            // means the representation was coded and then coded again in
            // transit, which is well defined rather than ambiguous: the two
            // namespaces may share a name only where the transformation is
            // identical, and the compression transfer codings are defined by
            // the algorithm of the content coding they are named after.
            // cite(RFC 9112 § 7.3): "Names of transfer codings MUST NOT overlap with names of content codings (Section 8.4.1 of [HTTP]) unless the encoding transformation is identical, as is the case for the compression codings defined in Section 7.2."
            // cite(RFC 9112 § 7.2): "The following transfer coding names for compression are defined by the same algorithm as their corresponding content coding:"
            //
            // § 8.4 goes further and contemplates a coding applied twice,
            // declining to forbid it and remarking only on how odd it would be.
            // That sentence is about an encoding inherent in the media type
            // rather than about Transfer-Encoding, so it does not govern this
            // check -- but it settles the modal, which is what was in doubt.
            // cite(RFC 9110 § 8.4): "Such a content coding would only be listed if, for some bizarre reason, it is applied a second time to form the representation."
            //
            // So the finding is advisory, and the message now says what is
            // unusual rather than implying something was broken.
            //
            // Content-Encoding is taken at its word -- nothing here decodes a
            // body -- and § 8.4 is what makes that reading fair.
            // cite(RFC 9110 § 8.4): "If one or more encodings have been applied to a representation, the sender that applied the encodings MUST generate a Content-Encoding header field that lists the content codings in the order in which they were applied."
            let mut overlap: Vec<String> = ce_set
                .intersection(&te_set)
                .map(|s| s.to_string())
                .collect();
            overlap.sort();

            if !overlap.is_empty() {
                return Some(Violation {
                rule: self.id().into(),
                severity: ctx.severity,
                message: format!(
                    "Compression coding(s) '{}' appear in both Content-Encoding and Transfer-Encoding of the {}; the representation is coded once and then coded again in transit, which is decodable but almost never intended",
                    overlap.join(", "),
                    side
                ),
            });
            }

            None
        };

        if let Some(v) = check(&tx.request.headers, "request") {
            return Some(v);
        }
        if let Some(resp) = &tx.response {
            if let Some(v) = check(&resp.headers, "response") {
                return Some(v);
            }
        }

        None
    }

    fn description(&self) -> &'static str {
        "Flags a message that names the same coding in both `Content-Encoding` and `Transfer-Encoding` — for example `Content-Encoding: gzip` alongside `Transfer-Encoding: gzip, chunked`. Both directions are checked, and the finding names the side it describes.\n\n**This is advisory, and no sentence forbids it.** The two fields address different layers, which both specifications say in mirrored sentences: RFC 9112 §6.1, \"Unlike Content-Encoding …, Transfer-Encoding is a property of the message, not of the representation\"; RFC 9110 §8.4, \"Unlike Transfer-Encoding …, the codings listed in Content-Encoding are a characteristic of the representation\". Naming a coding at both layers means the representation is compressed and then compressed *again* in transit. That is decodable, not malformed — RFC 9112 §7.3 guarantees a transfer coding and a content coding sharing a name are \"identical\" transformations, and RFC 9110 §8.4 contemplates a coding \"applied a second time\" outright, remarking only that it would take \"some bizarre reason\". The finding says the message is almost certainly not what its sender meant; it does not say the message breaks a rule.\n\n**What it does not do.** It makes no claim about the *body*: nothing here decodes anything or checks that the codings were really applied. `Content-Encoding` is taken at its word, which RFC 9110 §8.4 licenses — a sender that applied encodings \"MUST generate a Content-Encoding header field that lists the content codings in the order in which they were applied\".\n\n**Parsing.** The two fields are split by their own grammars: `content-coding` is a bare `token`, so every comma separates; `transfer-coding` carries parameters whose values may be quoted-strings, so that split respects quoting. Names are compared case-insensitively, as both specifications define them to be, and values are decoded from raw octets so that one bad byte cannot hide the names beside it."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("8.4"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.4",
                note: "Content-Encoding — a property of the representation, and the MUST that makes it a trustworthy record of what was applied. Also contemplates a coding applied a second time, which is why this rule is advisory",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("8.4.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.4.1",
                note: "`content-coding = token` — no parameters, which is why this field's members are split naively",
            },
            crate::rules::SpecRef {
                spec: "RFC 9112",
                section: Some("6.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-6.1",
                note: "Transfer-Encoding — a property of the message, not the representation. The mirror of §8.4's sentence, and the whole basis of the distinction this rule watches",
            },
            crate::rules::SpecRef {
                spec: "RFC 9112",
                section: Some("7.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-7.2",
                note: "The compression transfer codings, defined by the same algorithm as the content coding of the same name",
            },
            crate::rules::SpecRef {
                spec: "RFC 9112",
                section: Some("7.3"),
                url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-7.3",
                note: "Transfer and content coding names may only overlap where the transformation is identical — so a shared name is unambiguous, and coding twice is coherent rather than malformed",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("10.1.4"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1.4",
                note: "The `transfer-coding` grammar, including the quoted-string a parameter may carry — why that field's split is quote-aware",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nContent-Encoding: gzip\nTransfer-Encoding: chunked\n",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(transfer-level gzip without Content-Encoding)"),
                snippet: "HTTP/1.1 200 OK\nTransfer-Encoding: gzip, chunked\n",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(different codings at each layer)"),
                snippet: "HTTP/1.1 200 OK\nContent-Encoding: br\nTransfer-Encoding: gzip, chunked\n",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(the same coding at both layers)"),
                snippet: "HTTP/1.1 200 OK\nContent-Encoding: gzip\nTransfer-Encoding: gzip, chunked\n",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(a request codes its body twice)"),
                snippet: "POST /upload HTTP/1.1\nHost: example.com\nContent-Encoding: gzip\nTransfer-Encoding: gzip, chunked\n",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &CompressionAndTransferEncodingConsistent;

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;
    use rstest::rstest;

    fn make_tx_with_headers(
        ce: Option<&str>,
        te: Option<&str>,
    ) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        if let Some(v) = ce {
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[("content-encoding", v)]);
        }
        if let Some(v) = te {
            // Merge TE header without clobbering CE
            let mut hm = tx.response.as_mut().unwrap().headers.clone();
            hm.extend(crate::test_helpers::make_headers_from_pairs(&[(
                "transfer-encoding",
                v,
            )]));
            tx.response.as_mut().unwrap().headers = hm;
        }
        tx
    }

    #[rstest]
    // Added coverage for params, case-insensitive tokens, trailing commas
    #[case(Some("gzip"), Some("chunked, gzip"), true)]
    #[case(Some("gzip"), Some("chunked"), false)]
    #[case(Some("br, gzip"), Some("gzip, chunked"), true)]
    #[case(Some("gzip"), None, false)]
    #[case(None, Some("gzip"), false)]
    #[case(Some("gzip;q=1.0"), Some("gzip"), true)]
    #[case(Some("GZip"), Some("gzip"), true)]
    #[case(Some("gzip, "), Some("gzip"), true)]
    fn overlap_cases(
        #[case] ce: Option<&str>,
        #[case] te: Option<&str>,
        #[case] expect_violation: bool,
    ) {
        let tx = make_tx_with_headers(ce, te);
        let rule = CompressionAndTransferEncodingConsistent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "compression_and_transfer_encoding_consistent",
        ]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(
                v.is_some(),
                "expected violation for ce={:?} te={:?}",
                ce,
                te
            );
        } else {
            assert!(
                v.is_none(),
                "unexpected violation for ce={:?} te={:?}: {:?}",
                ce,
                te,
                v
            );
        }
    }

    /// `Some("gzip"), Some("chunked, gzip")` — the first `overlap_cases` row —
    /// with one `obs-text` octet on the `Content-Encoding` name. `content-coding
    /// = token`, so `gzip<%xA0>` is not the `gzip` coding and the two fields
    /// name nothing in common. The value is read with `from_utf8_lossy`, so the
    /// pair arrives as one `char`; the list walk trimmed it and the name split
    /// below trimmed it again, and the finding claimed an overlap between a
    /// coding and a value that is not one.
    ///
    /// Both name splits are exercised, because they are two separate trims on
    /// two separate productions and only one of them was covered.
    #[rstest]
    #[case(b"gzip\xA0", b"chunked, gzip")]
    #[case(b"gzip", b"chunked, gzip\xA0")]
    fn a_coding_name_carrying_obs_text_overlaps_nothing(#[case] ce: &[u8], #[case] te: &[u8]) {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_octet_pairs(&[
                ("content-encoding", ce),
                ("transfer-encoding", te),
            ]);
        let rule = CompressionAndTransferEncodingConsistent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "compression_and_transfer_encoding_consistent",
        ]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none(), "{v:?}");
    }

    #[test]
    fn multiple_header_fields_detected() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        // Append multiple Content-Encoding fields
        let mut hm = hyper::HeaderMap::new();
        hm.append("content-encoding", HeaderValue::from_static("gzip"));
        hm.append("content-encoding", HeaderValue::from_static("br"));
        hm.append("transfer-encoding", HeaderValue::from_static("br, chunked"));
        tx.response.as_mut().unwrap().headers = hm;

        let rule = CompressionAndTransferEncodingConsistent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "compression_and_transfer_encoding_consistent",
        ]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    /// Every published snippet is run through the rule. The two Compliant ones
    /// used to end in pseudo-bodies (`<compressed-body-chunked>`), so nothing
    /// could have parsed them even if something had tried.
    #[test]
    fn published_examples_are_judged_the_way_they_are_labelled() {
        use crate::rules::{Compliance, Rule as _};
        let rule = CompressionAndTransferEncodingConsistent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);

        for ex in rule.examples() {
            let mut lines = ex.snippet.lines();
            let start = lines.next().expect("empty snippet");
            let is_response = start.starts_with("HTTP/");
            let pairs: Vec<(&str, &str)> = lines
                .take_while(|l| !l.trim().is_empty())
                .map(|l| {
                    l.split_once(": ")
                        .unwrap_or_else(|| panic!("not a header line: {l:?}"))
                })
                .collect();

            let mut tx = if is_response {
                crate::test_helpers::make_test_transaction_with_response(200, &[])
            } else {
                crate::test_helpers::make_test_transaction()
            };
            let headers = crate::test_helpers::make_headers_from_pairs(&pairs);
            if is_response {
                tx.response.as_mut().unwrap().headers = headers;
            } else {
                tx.request.headers = headers;
            }

            let found = crate::test_helpers::run_rule(
                &rule,
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            );
            let side = if is_response { "response" } else { "request" };
            match ex.compliance {
                Compliance::Compliant => assert!(
                    found.is_none(),
                    "rule rejects its Compliant example ({side}) {:?}: {found:?}",
                    ex.snippet
                ),
                Compliance::NonCompliant => {
                    let found = found.unwrap_or_else(|| {
                        panic!(
                            "rule accepts its NonCompliant example ({side}) {:?}",
                            ex.snippet
                        )
                    });
                    assert!(
                        found.message.contains(&format!("of the {side}")),
                        "example is a {side} but the finding says otherwise: {found:?}"
                    );
                }
            }
        }
    }

    /// Quoting that never closes can only cost this rule a finding, never
    /// manufacture one: the name in front of the first `;` is still a name the
    /// sender wrote. Pinned so the sibling rules' decline is not copied in.
    #[test]
    fn unterminated_quoting_costs_a_finding_and_invents_none() {
        let rule = CompressionAndTransferEncodingConsistent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "compression_and_transfer_encoding_consistent",
        ]);

        // The `gzip` in front of the stray DQUOTE is still read.
        let tx = make_tx_with_headers(Some("gzip"), Some("gzip;ext=\"a, chunked"));
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some_and(|v| v.message.contains("gzip")));

        // The `br` swallowed behind the unterminated quote is not, and no
        // finding is invented in its place.
        let tx = make_tx_with_headers(Some("br"), Some("gzip;ext=\"a, br"));
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none(), "{v:?}");
    }

    /// An octet outside visible US-ASCII is not a `tchar`, so a name carrying
    /// one matches nothing -- which is the right answer on its own account.
    /// Dropping the whole line, as `to_str` used to make this rule do, also hid
    /// every other name on it.
    #[test]
    fn a_stray_octet_does_not_hide_the_rest_of_the_line() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = hyper::HeaderMap::new();
        hm.append(
            "content-encoding",
            HeaderValue::from_bytes(b"\xff, gzip").unwrap(),
        );
        hm.append(
            "transfer-encoding",
            HeaderValue::from_static("gzip, chunked"),
        );
        tx.response.as_mut().unwrap().headers = hm;

        let rule = CompressionAndTransferEncodingConsistent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "compression_and_transfer_encoding_consistent",
        ]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(
            v.is_some_and(|v| v.message.contains("gzip")),
            "the gzip after the stray octet went unread"
        );
    }

    /// The undecodable name on its own overlaps with nothing.
    #[test]
    fn a_name_that_is_only_a_stray_octet_matches_nothing() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = hyper::HeaderMap::new();
        hm.append(
            "content-encoding",
            HeaderValue::from_bytes(&[0xff]).unwrap(),
        );
        hm.append(
            "transfer-encoding",
            HeaderValue::from_static("gzip, chunked"),
        );
        tx.response.as_mut().unwrap().headers = hm;

        let rule = CompressionAndTransferEncodingConsistent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "compression_and_transfer_encoding_consistent",
        ]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none(), "{v:?}");
    }

    /// A comma inside a transfer-parameter's quoted-string value is not a
    /// separator, so it must not manufacture a coding name that then appears to
    /// overlap. `Content-Encoding` needs no such care: its members are bare
    /// `token`s with no parameters and so no quoting.
    #[test]
    fn a_comma_inside_a_quoted_transfer_parameter_is_not_a_separator() {
        let tx = make_tx_with_headers(Some("br"), Some("chunked;ext=\"a,br,b\""));
        let rule = CompressionAndTransferEncodingConsistent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "compression_and_transfer_encoding_consistent",
        ]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none(), "the `br` is inside a parameter value: {v:?}");
    }

    #[test]
    fn overlapping_multiple_tokens_message_contains_both_sorted() {
        let tx = make_tx_with_headers(Some("gzip, br"), Some("br, gzip"));
        let rule = CompressionAndTransferEncodingConsistent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "compression_and_transfer_encoding_consistent",
        ]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("br, gzip"));
    }

    /// `Both`, so that a request-only transaction is examined too. It was
    /// `Server`, which in this engine means the rule never ran without a
    /// response.
    #[test]
    fn scope_is_both() {
        let rule = CompressionAndTransferEncodingConsistent;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }

    /// A request can apply a content coding to the body it sends and a transfer
    /// coding on top of it, which is the same observation on the same two
    /// layers. Nothing looked.
    #[test]
    fn a_request_with_the_same_coding_in_both_fields_is_reported() {
        let rule = CompressionAndTransferEncodingConsistent;
        let tx = crate::test_helpers::make_test_transaction_with_headers(&[
            ("content-encoding", "gzip"),
            ("transfer-encoding", "gzip, chunked"),
        ]);
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "compression_and_transfer_encoding_consistent",
        ]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(
            v.is_some_and(|v| v.message.contains("of the request")),
            "the request side was never examined"
        );
    }

    /// The two sides are reported separately, so a clean request does not
    /// suppress a response finding and the message says which is which.
    #[test]
    fn the_message_names_the_side_it_is_about() {
        let rule = CompressionAndTransferEncodingConsistent;
        let tx = make_tx_with_headers(Some("br"), Some("br, chunked"));
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "compression_and_transfer_encoding_consistent",
        ]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some_and(|v| v.message.contains("of the response")));
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        // Use the project test helper to enable the rule and validate full engine path
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "compression_and_transfer_encoding_consistent",
        ]);
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn validate_rules_missing_severity_errors() {
        // When rule is enabled but missing required 'severity', validation should fail
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "compression_and_transfer_encoding_consistent",
        ]);
        // Remove severity key from the rule table
        if let Some(toml::Value::Table(table)) = cfg
            .rules
            .get_mut("compression_and_transfer_encoding_consistent")
        {
            table.remove("severity");
        }

        let res = crate::rules::validate_rules(&cfg);
        assert!(res.is_err());
    }
}
