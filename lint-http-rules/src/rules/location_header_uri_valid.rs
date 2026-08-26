// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::helpers::headers::{combined_field_value_as_written, describe_octet, trim_ows};
use crate::lint::Violation;
use crate::rules::Rule;

pub struct LocationHeaderUriValid;

impl Rule for LocationHeaderUriValid {
    fn id(&self) -> &'static str {
        "location_header_uri_valid"
    }

    /// `Location` is defined in § 10.2, *Response Context Fields* — there is no
    /// request half of it to read, which is the sentence behind the scope rather
    /// than the dispatch convenience of skipping transactions with no response.
    ///
    /// cite(RFC 9110 § 10.2): "The response header fields below provide additional information about the response, beyond what is implied by the status code, including information about the server, about the target resource, or about related resources."
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
        let Some(resp) = &tx.response else {
            return None;
        };
        let violation = |message: String| {
            Some(Violation {
                rule: self.id().to_string(),
                severity: config.severity,
                message,
            })
        };

        // The field, and the one production its value is measured against. No
        // status gate: which statuses may carry the field at all is
        // `redirect_status_and_location_valid`'s question, and the
        // grammar is the same whatever status line preceded it.
        //
        // The value is read as the sender wrote it, every octet decoded to the
        // `char` of the same value. `to_str` admits only visible US-ASCII, so a
        // `Location` carrying %xFF would otherwise become "this response has no
        // `Location` field" — a claim about the message, where the defect belongs
        // to one octet. A URI *is* written in a subset of US-ASCII, which is why
        // the old guard produced the right verdict; it announced the wrong reason
        // ("not valid UTF-8" of a value that may be perfectly good UTF-8) and the
        // octet check below states the real one.
        //
        // The header section only. Whether *any* field may appear in a trailer
        // section is § 6.5.1's deny-by-default question and
        // `trailer_fields_valid`'s finding, and a `Location` arriving
        // after the content could not have redirected anything.
        //
        // And the sentence that makes every finding below a violation rather than
        // advice, which is § 2.2's and not § 10.2.2's: § 10.2.2 defines the field
        // and forbids nothing about it, so a `Location` on a status that has no use
        // for one is advice (`redirect_status_and_location_valid` says so
        // on its own page). A value that is not a `URI-reference` is a different
        // matter — the field has an ABNF rule, and a sender is forbidden from
        // generating a protocol element that does not match it.
        //
        // cite(RFC 9110 § 10.2.2): "The "Location" header field is used in some responses to refer to a specific resource in relation to the response."
        // cite(RFC 9110 § 10.2.2, label: Location grammar): "Location = URI-reference"
        // cite(RFC 3986 § 4.1): "URI-reference = URI / relative-ref"
        // cite(RFC 9110 § 2.2): "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules."
        let value = combined_field_value_as_written(&resp.headers, "location")?;
        let lines = resp.headers.get_all("location").iter().count();

        if lines > 1 {
            // `Location = URI-reference` has no `#(...)` alternative, so § 5.3's
            // exception does not apply and one message carries at most one field
            // line.
            //
            // The detection has to be this count, and cannot be the join that
            // works for every other singleton in the tree: § 5.2 recombines the
            // lines with a comma, and "," is a `sub-delim` — a valid data
            // character anywhere in a URI. So the combined value is still a
            // well-formed `URI-reference`, identifying neither of the resources
            // the sender named. § 5.5 says as much about fields carrying a
            // URI-reference, and § 10.2.2's Note says it about this field by
            // name, including what a recipient downstream is left with. § 16.3.2.2
            // names this very field as the counter-example new field definitions
            // should not emulate.
            //
            // cite(RFC 9110 § 5.5): "Fields that expect to contain a comma within a member, such as within an HTTP-date or URI-reference element, ought to be defined with delimiters around that element to distinguish any comma within that data from potential list separators."
            // cite(RFC 9110 § 10.2.2): "A Location field value cannot | allow a list of members because the comma list separator is a | valid data character within a URI-reference."
            // cite(RFC 9110 § 10.2.2): "If an invalid | message is sent with multiple Location field lines, a recipient | along the path might combine those field lines into one value."
            // cite(RFC 9110 § 16.3.2.2): "because URIs can include commas, it is not possible to reliably distinguish between a single value that includes a comma from two values"
            return violation(format!(
                "{}. The comma a recipient joins them with is a valid data character inside a URI-reference, so the combined value is a well-formed reference to neither resource (RFC 9110 §10.2.2)",
                crate::helpers::headers::singleton_field_preamble(
                    "Location",
                    lines,
                    &value.escape_debug().to_string(),
                    "`Location = URI-reference` has no comma-separated-list alternative",
                )
            ));
        }

        // Trimming `OWS` and only `OWS`: the value carries one `char` per octet, so
        // U+00A0 in it is the octet %xA0, which is `obs-text` and not whitespace of
        // any kind — removing it would report an empty value for a defect that
        // octet has.
        //
        // cite(RFC 9110 § 5.5): "A field value does not include leading or trailing whitespace.  When a specific version of HTTP allows such whitespace to appear in a message, a field parsing implementation MUST exclude such whitespace prior to evaluating the field value."
        let value = trim_ows(&value);

        if value.is_empty() {
            // **No honest quote for this one**, and it is the rule's only finding
            // that has none. An empty value is a *legal* `URI-reference`:
            // `relative-part` admits `path-empty`, which makes it a same-document
            // reference resolving to the target URI. Nothing in RFC 9110 or
            // RFC 3986 forbids it, and § 10.2.2 forbids nothing about this field
            // in any case. What is left is the operator's reading — a sender that
            // writes `Location:` with nothing after it means to name a resource
            // and named the one already in hand — so the finding says so in the
            // message rather than claiming a violation. `content_location_and_uri_consistent`
            // reaches the same answer for the same reason on the sibling field.
            //
            // cite(RFC 3986 § 4.4): "The most frequent examples of same-document references are relative references that are empty or include only the number sign ("#") separator followed by a fragment identifier."
            return violation(
                "Location is present with an empty value, which resolves to the target URI itself. This is advice, not a violation: an empty `URI-reference` is a same-document reference (RFC 3986 §4.4) and no sentence in RFC 9110 or RFC 3986 forbids sending one".to_string(),
            );
        }

        if let Some(ch) = crate::helpers::uri::find_non_uri_char(value) {
            // The alphabet check, which the whitespace check this replaced was one
            // sixth of: SP is not a URI character, and neither are `"`, `<`, `>`,
            // `\`, `^`, `` ` ``, `{`, `|`, `}`, DEL, any CTL, or any octet above
            // %x7F. Each `char` here came from one octet and goes back to it
            // unchanged, so the finding names the octet that stopped the parse.
            return violation(format!(
                "Location value carries the octet {}, which no URI-reference admits; a URI is written from `unreserved`, `gen-delims` and `sub-delims` characters and `pct-encoded` triplets, and every other octet must be percent-encoded before the URI is formed (RFC 3986 §2.1)",
                describe_octet(ch as u8)
            ));
        }

        // `%` passed the alphabet check because it opens a triplet; whether it
        // actually does is the triplet's own production, and the helper carries it.
        if let Some(msg) = crate::helpers::uri::check_percent_encoding(value) {
            return violation(msg);
        }

        // Only the `URI` alternative has a scheme; the helper is a no-op on a
        // `relative-ref`, which is why nothing here gates on which alternative the
        // value took.
        if let Some(msg) = crate::helpers::uri::validate_scheme_if_present(value) {
            return violation(msg);
        }

        None
    }

    fn title(&self) -> Option<&'static str> {
        Some("Server Location Header URI Valid")
    }

    fn description(&self) -> &'static str {
        "Validates the `Location` response header field's value against its own production, `Location = URI-reference` (RFC 9110 §10.2.2), which is RFC 3986 §4.1's `URI-reference` — a URI or a relative reference, and nothing else.\n\nEvery finding here except one is a violation rather than advice, and the sentence that makes it so is RFC 9110 §2.2's — *\"A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules\"* — not anything in §10.2.2, which defines the field and forbids nothing about it. That is why *where* a `Location` may appear is advisory (`redirect_status_and_location_valid`) while *what it may say* is not.\n\nThe field is a **singleton**: its grammar has no comma-separated-list form, so a message carries at most one `Location` field line (RFC 9110 §5.3), and two lines are reported as that. The detection is a count of the lines rather than the join used for every other singleton, and the reason is in §10.2.2's own Note: the comma a recipient recombines field lines with is a valid data character inside a URI-reference, so joining two `Location` lines yields a *well-formed* reference — to neither of the resources the sender named. Recovering the intended value from that is, in the RFC's words, difficult and not interoperable.\n\nEvery octet is measured rather than skipped, and the finding names the octet. This is not a UTF-8 question: a URI is composed from `unreserved`, `gen-delims` and `sub-delims` characters plus `pct-encoded` triplets (RFC 3986 §2), so `obs-text` is reported for not being a URI character, which is what is wrong with it. So are `SP`, `\"`, `<`, `>`, `\\`, `^`, `` ` ``, `{`, `|`, `}` and every control character — each has to be percent-encoded before the URI is formed. Leading and trailing whitespace is excluded before the value is evaluated (RFC 9110 §5.5), and only `SP`/`HTAB` count as that.\n\nA `%` must open a well-formed `pct-encoded` triplet, and a value that carries a scheme must carry a `scheme` (RFC 3986 §3.1).\n\n**One finding here is advice rather than a violation, and is labelled as such in its own message: an empty value.** An empty `URI-reference` is legal — `relative-part` admits `path-empty`, making it a same-document reference that resolves to the target URI (RFC 3986 §4.4) — so no sentence forbids `Location:` with nothing after it. It is reported because a sender writing the field means to name a resource and has named the one the client already had.\n\n**Scope: this rule reads the field's syntax and nothing else.** Whether a given status code may carry a `Location` at all is `redirect_status_and_location_valid`'s finding, and whether a redirect status arrived without one is `location_on_redirect_present`'s; both are asked of every status, so no status gate is applied here. §10.2.2's requirement that a 3xx `Location` with no fragment component inherit the fragment of the reference that generated the target URI is addressed to the *user agent* processing the redirect, not to the sender, so no captured message can be measured against it. Only the header section is read: whether any field at all may be sent in a *trailer* section is RFC 9110 §6.5.1's deny-by-default question and `trailer_fields_valid`'s finding."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("10.2.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.2",
                note: "Location: the field definition, `Location = URI-reference`, and the Note explaining why the field cannot be a list — the comma list separator is valid data inside a URI-reference",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("2.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-2.2",
                note: "Conformance: a sender MUST NOT generate a protocol element that does not match its ABNF. This is what makes a malformed `Location` value a violation, since §10.2.2 itself forbids nothing",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("5.3"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.3",
                note: "Field Order: a sender MUST NOT generate multiple field lines for a field with no comma-separated-list alternative. `Location` has none, so two lines are reported",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("5.5"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.5",
                note: "Field Values: singleton fields, the care a comma needs in a field carrying a URI-reference, and the MUST to exclude leading and trailing whitespace before evaluating a field value",
            },
            crate::rules::SpecRef {
                spec: "RFC 3986",
                section: Some("2"),
                url: "https://www.rfc-editor.org/rfc/rfc3986.html#section-2",
                note: "Characters: the limited set a URI is composed from — `unreserved`, `gen-delims`, `sub-delims` — and the `pct-encoded` triplet every other octet must be written as",
            },
            crate::rules::SpecRef {
                spec: "RFC 3986",
                section: Some("4.1"),
                url: "https://www.rfc-editor.org/rfc/rfc3986.html#section-4.1",
                note: "`URI-reference = URI / relative-ref`. §4.4 is why an empty value is one of them, and so why the empty-value finding here is advisory",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("(absolute URI)"),
                snippet: "HTTP/1.1 302 Found\nLocation: https://example.com/new-location",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(relative URI-reference)"),
                snippet: "HTTP/1.1 302 Found\nLocation: /new-location?ref=1",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(a comma is a sub-delim, so it is ordinary data here)"),
                snippet: "HTTP/1.1 302 Found\nLocation: /archive/1996,1997",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(two field lines — `Location` is a singleton, and joining them yields a valid reference to neither)"),
                snippet: "HTTP/1.1 302 Found\nLocation: /first\nLocation: /second",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(empty value — advice, not a violation: it resolves to the target URI)"),
                snippet: "HTTP/1.1 302 Found\nLocation:",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(invalid percent-encoding)"),
                snippet: "HTTP/1.1 302 Found\nLocation: /bad%2Gencoding",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(SP is not a URI character; it has to be written `%20`)"),
                snippet: "HTTP/1.1 302 Found\nLocation: https://example.com/ bad",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &LocationHeaderUriValid;

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::{HeaderName, HeaderValue};
    use rstest::rstest;

    /// One constructor for every fixture, taking the field's octets as written and
    /// as many field lines as the case needs. Two of this rule's checks are about
    /// what `to_str` refuses and about how many lines there are, so a fixture that
    /// can only express one line of visible US-ASCII cannot reach them.
    fn make_tx_with_locs(locs: &[&[u8]]) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut headers = crate::test_helpers::make_headers_from_pairs(&[]);
        for loc in locs {
            headers.append(
                HeaderName::from_static("location"),
                HeaderValue::from_bytes(loc).expect("test fixture is a field value"),
            );
        }
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 302,
            version: "HTTP/1.1".into(),
            headers,
            body_length: None,
            trailers: None,
        });
        tx
    }

    fn judge(tx: &crate::http_transaction::HttpTransaction) -> Option<Violation> {
        let config = crate::test_helpers::make_test_config_with_severity(
            "location_header_uri_valid",
            "warn",
        );
        LocationHeaderUriValid.check_transaction(
            tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        )
    }

    #[rstest]
    #[case(b"https://example.com/path")]
    #[case(b"/relative/path")]
    #[case(b"/path%20with%20spaces")]
    // Every `sub-delim` and `gen-delim` is a URI character wherever it appears;
    // the comma in particular is what makes this field impossible to recombine.
    #[case(b"/archive/1996,1997")]
    #[case(b"//example.com/network-path")]
    #[case(b"?query-only=1")]
    #[case(b"#fragment-only")]
    #[case(b"/a!$&'()*+;=:@~-._")]
    fn a_uri_reference_is_not_reported(#[case] loc: &[u8]) {
        let v = judge(&make_tx_with_locs(&[loc]));
        assert!(v.is_none(), "{:?}: {v:?}", loc);
    }

    #[rstest]
    // Not "not valid UTF-8": %xFF is `obs-text`, a legal field-value octet that no
    // URI-reference admits, and the finding names it.
    #[case(b"/caf\xff", "0xFF")]
    // Valid UTF-8 and still not a URI: the old guard called this one a UTF-8 error
    // too, which was wrong about the value as well as about the field.
    #[case("/caf\u{e9}".as_bytes(), "0xC3")]
    #[case(b"https://example.com/ bad", "' '")]
    #[case(b"/tab\there", "0x09")]
    #[case(b"/angle<brackets>", "'<'")]
    #[case(b"/back\\slash", "'\\'")]
    #[case(b"/brace{s}", "'{'")]
    #[case(b"/quote\"x", "'\"'")]
    fn an_octet_no_uri_reference_admits_is_reported_as_that(
        #[case] loc: &[u8],
        #[case] octet: &str,
    ) {
        let v = judge(&make_tx_with_locs(&[loc])).expect("expected a finding");
        assert!(
            v.message.contains("no URI-reference admits") && v.message.contains(octet),
            "{}",
            v.message
        );
        assert!(!v.message.contains("UTF-8"), "{}", v.message);
    }

    #[test]
    fn two_field_lines_are_reported_as_the_singleton_they_break() {
        // Both lines are perfectly good URI-references, and their §5.2 recombination
        // "/first,/second" is a third one — which is the whole point of the check
        // and the reason it cannot be the join every other singleton in the tree
        // uses.
        let v = judge(&make_tx_with_locs(&[b"/first", b"/second"])).expect("expected a finding");
        // Pinned whole, because the finding is written in two functions now and
        // the second one carries § 10.2.2's reason -- the half that distinguishes
        // this field from a singleton whose join is merely malformed.
        assert_eq!(
            v.message,
            "Location is written on 2 header lines, which recombine into the one value \
             '/first,/second'; the field is a singleton — `Location = URI-reference` has no \
             comma-separated-list alternative — so a sender must not generate more than one field \
             line for it (RFC 9110 §5.3). The comma a recipient joins them with is a valid data \
             character inside a URI-reference, so the combined value is a well-formed reference \
             to neither resource (RFC 9110 §10.2.2)"
        );
        assert!(judge(&make_tx_with_locs(&[b"/first"])).is_none());
    }

    #[test]
    fn an_empty_value_is_reported_as_advice_and_says_so() {
        // `relative-part` admits `path-empty`, so this is a same-document reference
        // and no sentence forbids it. The message carries that, and the test pins
        // the wording so a later "tidying" commit cannot quietly upgrade the claim.
        let v = judge(&make_tx_with_locs(&[b""])).expect("expected a finding");
        assert!(
            v.message.contains("advice, not a violation"),
            "{}",
            v.message
        );
        assert!(
            v.message.contains("same-document reference"),
            "{}",
            v.message
        );
    }

    #[test]
    fn a_value_of_only_ows_is_the_empty_value_and_not_a_character_finding() {
        // §5.5 excludes leading and trailing whitespace *before* the value is
        // evaluated, so this is not a message carrying two spaces — it is a message
        // carrying nothing.
        let v = judge(&make_tx_with_locs(&[b"  "])).expect("expected a finding");
        assert!(
            v.message.contains("advice, not a violation"),
            "{}",
            v.message
        );
    }

    #[test]
    fn obs_text_is_not_whitespace_and_is_not_trimmed_away() {
        // %xA0 is NO-BREAK SPACE in Latin-1 and `str::trim` removes it. It is an
        // octet, so the finding has to be about the octet and not about an empty
        // value.
        let v = judge(&make_tx_with_locs(&[b"\xa0"])).expect("expected a finding");
        assert!(v.message.contains("0xA0"), "{}", v.message);
    }

    #[rstest]
    #[case(b"/bad%2Gchar", "Invalid percent-encoding")]
    #[case(b"/truncated%2", "Percent-encoding incomplete")]
    fn a_malformed_triplet_is_reported(#[case] loc: &[u8], #[case] expected: &str) {
        let v = judge(&make_tx_with_locs(&[loc])).expect("expected a finding");
        assert!(v.message.contains(expected), "{}", v.message);
    }

    #[test]
    fn invalid_scheme_start_is_violation() {
        let v = judge(&make_tx_with_locs(&[b"1http://ex"])).expect("expected a finding");
        assert!(v.message.contains("Invalid scheme"), "{}", v.message);
    }

    #[test]
    fn invalid_scheme_char_is_violation() {
        // "!" is a `sub-delim`, so the alphabet check passes it and the `scheme`
        // production is what rejects it — two questions, two checks.
        let v = judge(&make_tx_with_locs(&[b"ht!tp://ex"])).expect("expected a finding");
        assert!(v.message.contains("invalid character"), "{}", v.message);
    }

    #[test]
    fn no_location_field_is_not_a_finding() {
        assert!(judge(&make_tx_with_locs(&[])).is_none());
    }

    #[test]
    fn published_examples_are_judged_by_this_rule() {
        use crate::rules::{Compliance, Rule as _};
        let rule = LocationHeaderUriValid;

        for ex in rule.examples() {
            let mut locs: Vec<&[u8]> = Vec::new();
            for (i, line) in ex.snippet.lines().enumerate() {
                if line.is_empty() {
                    break;
                }
                if i == 0 {
                    assert!(
                        line.starts_with("HTTP/1.1 "),
                        "the first line of an example is its status line: {line:?}"
                    );
                    continue;
                }
                let (name, value) = line.split_once(':').unwrap_or_else(|| {
                    panic!("example header line is not `Name: value`: {line:?}")
                });
                assert_eq!(name.to_ascii_lowercase(), "location", "{line:?}");
                locs.push(value.trim().as_bytes());
            }

            let v = judge(&make_tx_with_locs(&locs));
            match ex.compliance {
                Compliance::Compliant => assert!(v.is_none(), "{}: {v:?}", ex.snippet),
                Compliance::NonCompliant => assert!(v.is_some(), "{}", ex.snippet),
            }
        }
    }

    #[test]
    fn scope_is_server() {
        let rule = LocationHeaderUriValid;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }
}
