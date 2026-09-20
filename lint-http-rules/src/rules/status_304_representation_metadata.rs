// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::status::{RFC_9110_15_4_5, RFC_9110_8_6, STATUS_304_METADATA_FORBIDDEN};
use crate::violations::ViolationDef;

/// One entry: a 304 carrying representation metadata § 15.4.5 does not have it
/// generate.
static DECLARED: &[&ViolationDef] = &[&STATUS_304_METADATA_FORBIDDEN];

pub struct Status304RepresentationMetadata;

/// § 8.2, which is what makes "representation metadata" a *set* of fields
/// rather than a turn of phrase. § 15.4.5 writes the prohibition against the
/// class and names none of its members, so the members have to be read from the
/// section that defines them — and that is the whole reason this rule exists
/// apart from any one field's own.
const RFC_9110_8_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("8.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.2",
    note: "Representation Metadata — the representation header fields, whose members § 8.3 to § 8.7 define one per subsection: Content-Type, Content-Encoding, Content-Language, Content-Length and Content-Location. § 15.4.5's SHOULD NOT is written against this class and names no member of it",
};

/// § 8.7, for the one member of the class § 15.4.5 puts on its own MUST list.
const RFC_9110_8_7: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("8.7"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.7",
    note: "Content-Location — representation metadata by its own words, and the one member of the class a 304 is told to send rather than to withhold, which is why it is exempt here by name",
};

/// The three fields this rule reports, in the order § 8 defines them: the name
/// a header map is keyed by, and the name a sender writes, which is what the
/// finding says.
///
/// **A closed list and not a guess.** § 15.4.5 forbids the class, § 8.3 to § 8.7
/// enumerate it, and each of the two members missing from this array is missing
/// because a sentence names it: `Content-Location` is on § 15.4.5's own MUST
/// list, and `Content-Length` has an explicit MAY in § 8.6. Everything else a
/// 304 carries — `Date`, `ETag`, `Vary`, `Cache-Control`, `Expires`,
/// `Last-Modified`, a `Set-Cookie`, a CDN's own trace fields — is not
/// representation metadata at all and is not this rule's business.
const REPRESENTATION_METADATA: [(&str, &str); 3] = [
    ("content-type", "Content-Type"),
    ("content-encoding", "Content-Encoding"),
    ("content-language", "Content-Language"),
];

impl RuleMeta for Status304RepresentationMetadata {
    fn id(&self) -> &'static str {
        "status_304_representation_metadata"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn title(&self) -> Option<&'static str> {
        Some("The representation metadata a 304 does not owe")
    }

    fn description(&self) -> &'static str {
        "A `304 (Not Modified)` exists to transfer as little as possible: the recipient already holds the representation, and RFC 9110 §15.4.5 lists the header fields the response owes — `Content-Location`, `Date`, `ETag`, `Vary`, `Cache-Control` and `Expires` — and then tells a sender not to generate *representation metadata* beyond them.\n\n**The prohibition is written against a class, and names no member of it.** §8.2 is where the class is defined and §8.3 to §8.7 enumerate it one field per subsection: `Content-Type`, `Content-Encoding`, `Content-Language`, `Content-Length` and `Content-Location`. This rule reads the first three.\n\n**The two it does not read are exempt by a sentence each, not by judgement.** `Content-Location` is on §15.4.5's own MUST list. `Content-Length` has an explicit MAY of its own in §8.6, where on a 304 it means the length of the `200` that was not sent; `no_body_for_1xx_204_304` documents the same carve-out from the other side.\n\n**One finding per field.** A response carrying `Content-Type` *and* `Content-Language` is two things to take off it, and each finding names the field and the value as written, so an operator can find the line.\n\n**The escape clause is read narrowly, and this is the rule's one judgement.** §15.4.5 permits metadata that \"exists for the purpose of guiding cache updates\", and its own example of that is a *validator* — `Last-Modified` where there is no `ETag`. A cache does update its stored header fields from a 304 (RFC 9111 §4.3.4), so a wide reading of the clause would permit every field and leave the SHOULD NOT with nothing to forbid. The narrow reading is taken: a field that describes the representation is the information transfer the status code was chosen to avoid, not a thing that guides the update.\n\n**Read against the response alone.** Every other check about a 304 in this crate compares it with the request it answers or with an earlier message; this one is decided by the status code and a field beside it, which is why it is its own rule and not an arm of the conditional-request one."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_9110_15_4_5, RFC_9110_8_2, RFC_9110_8_6, RFC_9110_8_7]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    /// The status line and the fields beside it are the origin's, and no part of
    /// the request is read to reach the finding.
    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::Presumed(crate::lint::Party::Server)
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("304 — the fields §15.4.5 has it generate, and nothing else"),
                snippet: "HTTP/1.1 304 Not Modified\nDate: Mon, 01 Jan 2024 00:00:00 GMT\nETag: \"abc\"\nVary: Accept-Encoding\nCache-Control: max-age=60\nContent-Location: /a\n",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("304 — Content-Length has a MAY of its own in §8.6"),
                snippet:
                    "HTTP/1.1 304 Not Modified\nETag: \"abc\"\nContent-Length: 1024\n",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("304 — the media type of a representation the client already has"),
                snippet: "HTTP/1.1 304 Not Modified\nETag: \"abc\"\nContent-Type: text/html\n",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("304 — the language of that same representation"),
                snippet: "HTTP/1.1 304 Not Modified\nETag: \"abc\"\nContent-Language: en\n",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("304 — a coding describing content that was not sent"),
                snippet: "HTTP/1.1 304 Not Modified\nETag: \"abc\"\nContent-Encoding: gzip\n",
            },
        ]
    }
}

impl Rule for Status304RepresentationMetadata {
    fn needs_response(&self) -> bool {
        true
    }

    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        let Some(resp) = tx.response.as_ref() else {
            return Vec::new();
        };
        if resp.status != 304 {
            return Vec::new();
        }

        // The sentence this rule is: a prohibition on a class, with an escape
        // clause whose own example is a validator rather than a description of
        // the representation.
        // cite(RFC 9110 § 15.4.5): "Since the goal of a 304 response is to minimize information transfer when the recipient already has one or more cached representations, a sender SHOULD NOT generate representation metadata other than the above listed fields unless said metadata exists for the purpose of guiding cache updates (e.g., Last-Modified might be useful if the response does not have an ETag field)."
        //
        // "the above listed fields" is the list immediately before it, and
        // `Content-Location` is the only representation header field on it —
        // which is why the array below has two members missing rather than one.
        // cite(RFC 9110 § 15.4.5): "The server generating a 304 response MUST generate any of the following header fields that would have been sent in a 200 (OK) response to the same request:"
        //
        // And the class itself, which § 15.4.5 never enumerates:
        // cite(RFC 9110 § 8.2): "Representation header fields provide metadata about the representation."
        //
        // `Content-Length` is the other member left out, and it is left out by a
        // permission written for this exact status rather than by a reading of
        // the escape clause. Its own MUST NOT — the value must equal what the
        // unsent 200 would have carried — compares against octets no capture
        // holds, so it is not enforced here or anywhere.
        // cite(RFC 9110 § 8.6): "A server MAY send a Content-Length header field in a 304 (Not Modified) response to a conditional GET request (Section 15.4.5); a server MUST NOT send Content-Length in such a response unless its field value equals the decimal number of octets that would have been sent in the content of a 200 (OK) response to the same request."
        //
        // One finding per field and not one per response: two of these are two
        // things to take off the message, and a finding that named neither would
        // be the same sentence written twice.
        REPRESENTATION_METADATA
            .iter()
            .filter_map(|(name, field)| {
                // The whole field section, joined: a value written on two lines
                // is one field and one finding, and what the operator has to
                // find is every line of it.
                let value =
                    crate::helpers::headers::combined_field_value_as_written(&resp.headers, name)?;
                let shown = crate::helpers::shown::shown_in_finding(&value);
                Some(ctx.report_with(
                    &STATUS_304_METADATA_FORBIDDEN,
                    format!(
                        "A 304 Not Modified sends {field}: \"{shown}\", which is representation \
                         metadata and not one of the fields the status code is required to carry: \
                         the response exists to transfer as little as possible when the recipient \
                         already holds the representation"
                    ),
                ))
            })
            .collect()
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &Status304RepresentationMetadata;

#[cfg(test)]
mod tests {
    use super::*;

    use rstest::rstest;

    fn run(status: u16, pairs: &[(&str, &str)]) -> Vec<crate::lint::Violation> {
        let tx = crate::test_helpers::make_test_transaction_with_response(status, pairs);
        crate::test_helpers::run_rule_all(
            &Status304RepresentationMetadata,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "status_304_representation_metadata",
            ]),
        )
    }

    /// The three members of the class, each drawn once and each naming itself.
    ///
    /// The field is in the message because a finding an operator cannot act on
    /// is not one: a 304 may carry two of these, and two findings that did not
    /// say which field they were about would be one sentence written twice.
    #[rstest]
    #[case("content-type", "text/html", "Content-Type", "text/html")]
    #[case("content-encoding", "gzip", "Content-Encoding", "gzip")]
    #[case("content-language", "en", "Content-Language", "en")]
    fn a_member_of_the_class_is_reported_and_names_itself(
        #[case] field: &str,
        #[case] value: &str,
        #[case] shown_field: &str,
        #[case] shown_value: &str,
    ) {
        let found = run(304, &[("etag", "\"abc\""), (field, value)]);
        assert_eq!(found.len(), 1, "{field}: {found:?}");
        assert_eq!(found[0].violation, "status_304_metadata_forbidden");
        assert_eq!(found[0].severity, crate::lint::Severity::Warn);
        assert!(
            found[0]
                .message
                .contains(&format!("{shown_field}: \"{shown_value}\"")),
            "{field}: {}",
            found[0].message
        );
    }

    /// The two members left out, each by a sentence of its own rather than by a
    /// reading of § 15.4.5's escape clause.
    ///
    /// **These are the rows the rule can most easily get wrong**, because the
    /// class § 8.2 defines has five members and only three of them are the
    /// finding. A reader that took the class whole would report both of these
    /// and be wrong about a permission each is granted by name.
    #[rstest]
    #[case::the_may_in_8_6("content-length", "1024")]
    #[case::on_15_4_5s_own_must_list("content-location", "/a")]
    fn a_member_the_specification_permits_on_a_304_is_silent(
        #[case] field: &str,
        #[case] value: &str,
    ) {
        let found = run(304, &[("etag", "\"abc\""), (field, value)]);
        assert!(found.is_empty(), "{field}: {found:?}");
    }

    /// Two of them are two things to take off the message, and the count is the
    /// assertion: a walk that answered once per response would satisfy a test
    /// asking only whether *something* fired.
    #[test]
    fn two_members_on_one_response_are_two_findings() {
        let found = run(
            304,
            &[
                ("etag", "\"abc\""),
                ("content-type", "text/html"),
                ("content-language", "en"),
            ],
        );
        assert_eq!(found.len(), 2, "{found:?}");
        let mut named: Vec<&str> = found
            .iter()
            .map(|v| {
                if v.message.contains("Content-Type") {
                    "type"
                } else if v.message.contains("Content-Language") {
                    "language"
                } else {
                    "?"
                }
            })
            .collect();
        named.sort_unstable();
        assert_eq!(named, vec!["language", "type"]);
    }

    /// One field written on two lines is one field, and the finding shows every
    /// line of it — what the operator has to find is the whole section.
    #[test]
    fn a_field_written_twice_is_one_finding_over_both_lines() {
        let found = run(
            304,
            &[("content-language", "en"), ("content-language", "fr")],
        );
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].message.contains("en,fr"), "{}", found[0].message);
    }

    /// The status code is the whole of the premise. The identical response
    /// under any other code carries metadata about a representation the client
    /// is receiving, which is what the fields are for.
    #[rstest]
    #[case(200)]
    #[case(204)]
    #[case(206)]
    fn the_same_fields_under_another_status_are_silent(#[case] status: u16) {
        let found = run(
            status,
            &[("content-type", "text/html"), ("content-language", "en")],
        );
        assert!(found.is_empty(), "{status}: {found:?}");
    }

    /// A 304 carrying none of the class, and carrying every field § 15.4.5 has
    /// it generate, is silent — including `Last-Modified`, which the escape
    /// clause names as its own example of metadata that guides a cache update.
    #[test]
    fn a_304_carrying_what_it_owes_is_silent() {
        let found = run(
            304,
            &[
                ("date", "Mon, 01 Jan 2024 00:00:00 GMT"),
                ("etag", "\"abc\""),
                ("vary", "Accept-Encoding"),
                ("cache-control", "max-age=60"),
                ("expires", "Mon, 01 Jan 2024 01:00:00 GMT"),
                ("last-modified", "Sun, 31 Dec 2023 00:00:00 GMT"),
                ("content-location", "/a"),
            ],
        );
        assert!(found.is_empty(), "{found:?}");
    }
}
