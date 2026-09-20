// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::field::{FIELD_LINE_DUPLICATED, RFC_9110_5_3};
use crate::violations::sec_fetch::{
    SEC_FETCH_STORAGE_ACCESS_VALUE_INVALID, SEC_FETCH_VALUE_EMPTY, SEC_FETCH_VALUE_MALFORMED,
    STORAGE_ACCESS_HEADERS_4_1,
};
use crate::violations::ViolationDef;

/// The one entry a field with no list form always has available: its own
/// repetition. The value on each line here is measured by the checks below;
/// what § 5.3 forbids is there being two lines at all.
static DECLARED: &[&ViolationDef] = &[
    &FIELD_LINE_DUPLICATED,
    &SEC_FETCH_VALUE_EMPTY,
    &SEC_FETCH_VALUE_MALFORMED,
    &SEC_FETCH_STORAGE_ACCESS_VALUE_INVALID,
];

/// `Sec-Fetch-Storage-Access` must be one of the three storage access statuses
/// Storage Access Headers § 4.1 names: `none`, `inactive`, `active`. The match
/// is exact: the statuses are lowercase tokens and the structured-field token
/// carries no case folding; token syntax is validated.
///
/// **The fifth member of a family whose other four are one document's.** The
/// four `Sec-Fetch-*` rules beside this one read Fetch Metadata § 2.1 — § 2.4;
/// this field is defined elsewhere and joins them from there, § 5 of its own
/// document appending it "alongside other Fetch Metadata headers". Reading the
/// family off the one document is what left this field unread, and the shared
/// entries it reports through are the same two its siblings report through.
pub struct SecFetchStorageAccessValueValid;

// Every reference this rule names lives on the subject it reports through and
// is imported back for `specifications()`, so a def's citation and the rule's
// documented reading are the same value rather than two copies of it.

impl RuleMeta for SecFetchStorageAccessValueValid {
    fn id(&self) -> &'static str {
        "sec_fetch_storage_access_value_valid"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn description(&self) -> &'static str {
        "Validate the `Sec-Fetch-Storage-Access` request header, the fifth member of the `Sec-Fetch-*` family and the one its four siblings' document does not define. Storage Access Headers § 4.1 makes it a Structured Field item whose value is a token, and names three valid values — `none`, `inactive` and `active`, the user agent's answer to whether this request can reach unpartitioned cookies. The match is exact: the statuses are lowercase tokens and structured-field tokens carry no case folding, so `Active` is not a valid value. Token syntax is enforced. Multiple header fields are treated as a violation.\n\n**The value is computed by the user agent, not chosen by the page**, which is why an unrecognised one is worth reporting against the sender: the field exists so a server can decide whether to answer with `Activate-Storage-Access`, and a value outside the three leaves that decision with nothing to read. § 4.1 tells servers to ignore an invalid value for forward-compatibility, in the same words its four siblings use; this rule lints the sender, where an unrecognised status means the header came from something that is not implementing the document."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[STORAGE_ACCESS_HEADERS_4_1, RFC_9110_5_3]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::Presumed(crate::lint::Party::Client)
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("the request already carries unpartitioned cookies"),
                snippet: "GET /embed HTTP/1.1\nHost: example.com\nSec-Fetch-Storage-Access: active",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("permission granted, but this request did not use it"),
                snippet:
                    "GET /embed HTTP/1.1\nHost: example.com\nSec-Fetch-Storage-Access: inactive",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("the statuses are lowercase; the match is exact"),
                snippet: "GET /embed HTTP/1.1\nHost: example.com\nSec-Fetch-Storage-Access: Active",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("a status the document does not define"),
                snippet:
                    "GET /embed HTTP/1.1\nHost: example.com\nSec-Fetch-Storage-Access: granted",
            },
        ]
    }
}

impl Rule for SecFetchStorageAccessValueValid {
    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // Single-finding body behind an Option: `?` ends it early, and the
        // one finding (or none) becomes the vector.
        let finding = || -> Option<Violation> {
            // Sec-Fetch-* are request-sent headers; check only requests.
            // cite(Storage Access Headers § 4.1): "The Sec-Fetch-Storage-Access HTTP request header exposes a request’s ability or inability to access cookies to a server."
            let headers = &tx.request.headers;
            let count = headers.get_all("sec-fetch-storage-access").iter().count();
            if count == 0 {
                return None;
            }

            // A single structured-field item, never a list, so a sender may not
            // repeat the field.
            // cite(RFC 9110 § 5.3): "a sender MUST NOT generate multiple field lines with the same name in a message (whether in the headers or trailers) or append a field line when a field line of the same name already exists in the message, unless that field's definition allows multiple field line values to be recombined as a comma-separated list"
            if count > 1 {
                return Some(ctx.report_with(
                    &FIELD_LINE_DUPLICATED,
                    "Multiple Sec-Fetch-Storage-Access header fields present".into(),
                ));
            }

            // Read as the octets the sender wrote. Every character an `sf-token`
            // generates is inside visible US-ASCII, so a value the string reader
            // refuses is a value the token check below refuses — and that check
            // can say which octet, where a verdict about the whole value could
            // only say that one was in there somewhere.
            let hv = headers
                .get_all("sec-fetch-storage-access")
                .iter()
                .next()
                .expect("a field line, since the count above is one");
            let line = crate::helpers::headers::field_line_as_written(hv);
            let val = crate::helpers::headers::trim_ows(&line);

            // An empty value cannot be a token.
            // cite(Storage Access Headers § 4.1): "It is a Structured Field item which is a token."
            if val.is_empty() {
                return Some(ctx.report_with(
                    &SEC_FETCH_VALUE_EMPTY,
                    "Sec-Fetch-Storage-Access header is empty".into(),
                ));
            }

            // Token must not contain invalid token chars. This checks the HTTP
            // `token` grammar, slightly looser than sf-token; the closed value
            // match below is what actually gates acceptance, so the difference
            // only picks which message a bad value gets.
            // cite(Storage Access Headers § 4.1): "It is a Structured Field item which is a token."
            if let Some(c) = crate::helpers::token::find_invalid_token_char(val) {
                return Some(ctx.report_with(
                    &SEC_FETCH_VALUE_MALFORMED,
                    format!(
                        "Sec-Fetch-Storage-Access header contains invalid token character: {}",
                        crate::helpers::shown::describe_char(c)
                    ),
                ));
            }

            // The document tells servers to ignore unknown values for forward
            // compatibility; this rule lints the sender, where an unknown status
            // means a non-conforming (or non-browser) origin of the header.
            // cite(Storage Access Headers § 4.1): "In order to support forward-compatibility with as-yet-unknown semantics, servers SHOULD ignore this header if it contains an invalid value."
            // cite(Storage Access Headers § 4.1): "Valid Sec-Fetch-Storage-Access values include "none", "inactive", and "active"."
            match val {
                "none" | "inactive" | "active" => None,
                _ => Some(ctx.report_with(
                    &SEC_FETCH_STORAGE_ACCESS_VALUE_INVALID,
                    format!("Unrecognized Sec-Fetch-Storage-Access value: '{}'", val),
                )),
            }
        };
        Vec::from_iter(finding())
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &SecFetchStorageAccessValueValid;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn cfg() -> crate::config::Config {
        crate::test_helpers::make_test_config_with_enabled_rules(&[
            "sec_fetch_storage_access_value_valid",
        ])
    }

    fn run(header: Option<&str>) -> Option<Violation> {
        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(v) = header {
            tx.request.headers =
                crate::test_helpers::make_headers_from_pairs(&[("sec-fetch-storage-access", v)]);
        }
        crate::test_helpers::run_rule(
            &SecFetchStorageAccessValueValid,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg(),
        )
    }

    #[rstest]
    // The three statuses § 4.1 names, and the only three.
    #[case(Some("none"), None)]
    #[case(Some("inactive"), None)]
    #[case(Some("active"), None)]
    // What 114 request lines of observed traffic actually write, padded: OWS
    // around a field value is the recipient's to strip, not the sender's defect.
    #[case(Some(" active "), None)]
    #[case(None, None)]
    // A token that is not one of the three. `Active` is here because the
    // difference between it and `active` is the whole of what "the match is
    // exact" means, and a later edit lowercasing the comparison would pass every
    // other case in this table.
    #[case(Some("Active"), Some("sec_fetch_storage_access_value_invalid"))]
    #[case(Some("granted"), Some("sec_fetch_storage_access_value_invalid"))]
    #[case(Some("enabled"), Some("sec_fetch_storage_access_value_invalid"))]
    // Not a token at all, and not the closed set's business.
    #[case(Some("act ive"), Some("sec_fetch_value_malformed"))]
    #[case(Some("\"active\""), Some("sec_fetch_value_malformed"))]
    // Written, and holding nothing.
    #[case(Some(""), Some("sec_fetch_value_empty"))]
    fn storage_access_status_cases(#[case] header: Option<&str>, #[case] expect: Option<&str>) {
        let v = run(header);
        match expect {
            None => assert!(v.is_none(), "unexpected finding for {:?}: {:?}", header, v),
            Some(id) => {
                let v = v.unwrap_or_else(|| panic!("expected {} for {:?}", id, header));
                assert_eq!(v.violation, id, "wrong entry for {:?}", header);
            }
        }
    }

    #[test]
    fn a_repeated_field_is_the_fields_own_defect_whatever_the_values_are() {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        hm.append(
            "sec-fetch-storage-access",
            HeaderValue::from_static("active"),
        );
        hm.append(
            "sec-fetch-storage-access",
            HeaderValue::from_static("inactive"),
        );
        tx.request.headers = hm;

        let v = crate::test_helpers::run_rule(
            &SecFetchStorageAccessValueValid,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg(),
        )
        .expect("a finding");
        assert_eq!(v.violation, "field_line_duplicated");
    }

    #[test]
    fn an_obs_text_octet_is_named_by_the_token_check() {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        let bad = HeaderValue::from_bytes(&[0xff]).expect("should construct non-utf8 header");
        hm.insert("sec-fetch-storage-access", bad);
        tx.request.headers = hm;

        let v = crate::test_helpers::run_rule(
            &SecFetchStorageAccessValueValid,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg(),
        )
        .expect("a finding");
        assert_eq!(
            v.message,
            "Sec-Fetch-Storage-Access header contains invalid token character: 0xFF"
        );
    }

    #[test]
    fn the_finding_names_the_value_it_refused() {
        let v = run(Some("Active")).expect("a finding");
        assert!(
            v.message.contains("'Active'"),
            "the message must name the value, got: {}",
            v.message
        );
    }

    #[test]
    fn message_and_id() {
        let rule = SecFetchStorageAccessValueValid;
        assert_eq!(rule.id(), "sec_fetch_storage_access_value_valid");
        assert!(!rule.needs_response());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "sec_fetch_storage_access_value_valid");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
