// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct LastModifiedRfc1123Syntax;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9110_5_6_7: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("5.6.7"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.7",
    note: "Date/Time Formats",
};

impl Rule for LastModifiedRfc1123Syntax {
    fn id(&self) -> &'static str {
        "last_modified_rfc1123_syntax"
    }

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
            let Some(resp) = &tx.response else {
                return None;
            };

            if let Some(s) = crate::helpers::headers::get_header_str(&resp.headers, "last-modified")
            {
                // A response is a sender, so HTTP-date is not the bar here: the field is
                // *defined* as HTTP-date, and a sender is still confined to IMF-fixdate.
                // Checking `is_valid_http_date` accepted the two obsolete formats and so
                // could never fail on the thing this rule exists to report.
                // The `OWS` is excluded here, because only this side knows the value
                // came off a field line. `IMF-fixdate` prints no whitespace but the
                // `SP`s at its fixed offsets and § 5.6.7 forbids a sender any more,
                // so `is_valid_imf_fixdate` measures whatever it is handed; what
                // makes a leading or trailing `OWS` not part of *this* value is the
                // `field-line` production and § 5.5's sentence about it, and the
                // trim is `OWS` rather than `str::trim` for the reason recorded at
                // `trim_ows`.
                //
                // cite(RFC 9110 § 8.8.2): "Last-Modified = HTTP-date"
                // cite(RFC 9110 § 5.5): "A field value does not include leading or trailing whitespace"
                // cite(RFC 9112 § 5): "field-line   = field-name ":" OWS field-value OWS"
                // cite(RFC 9110 § 5.6.7): "When a sender generates a field that contains one or more timestamps defined as HTTP-date, the sender MUST generate those timestamps in the IMF-fixdate format."
                if !crate::http_date::is_valid_imf_fixdate(crate::helpers::headers::trim_ows(s)) {
                    return Some(self.violation(
                        ctx.severity,
                        "Last-Modified header is not a valid IMF-fixdate (RFC 9110)".into(),
                    ));
                }
            } else if resp.headers.contains_key("last-modified") {
                // Non-UTF8 header values are considered invalid for date parsing
                return Some(self.violation(
                    ctx.severity,
                    "Last-Modified header contains non-UTF8 bytes and is invalid".into(),
                ));
            }
            None
        };
        Vec::from_iter(finding())
    }

    fn title(&self) -> Option<&'static str> {
        Some("Server Last-Modified RFC 1123 Format")
    }

    fn description(&self) -> &'static str {
        "Verifies that the `Last-Modified` header (when present) uses the IMF-fixdate format (a.k.a. RFC 1123 date) as required by HTTP date formatting rules."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_9110_5_6_7]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nLast-Modified: Wed, 21 Oct 2015 07:28:00 GMT\nContent-Type: text/plain\n\nHello",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nLast-Modified: 2015-10-21T07:28:00Z\nContent-Type: text/plain\n\nHello",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &LastModifiedRfc1123Syntax;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(Some(vec![("last-modified", "Wed, 21 Oct 2015 07:28:00 GMT")] ), false)]
    #[case(Some(vec![("last-modified", "not-a-date")] ), true)]
    #[case(Some(vec![("last-modified", "Wed, 02 Jan 2030 12:00:00 GMT")] ), false)]
    #[case(None, false)]
    // The two obsolete formats, in RFC 9110 § 5.6.7's own words. A recipient must
    // accept both; a sender may generate neither, and a response is a sender. These
    // are the cases this rule advertised and could not catch until it stopped asking
    // the recipient's question.
    #[case(Some(vec![("last-modified", "Sunday, 06-Nov-94 08:49:37 GMT")] ), true)]
    #[case(Some(vec![("last-modified", "Sun Nov  6 08:49:37 1994")] ), true)]
    // The `OWS` a `field-line` is allowed to carry around its value, which is
    // this side's to exclude now that `is_valid_imf_fixdate` measures the whole
    // string. Reporting these would report an HTTP/1.1 sender for something
    // RFC 9112 § 5 lets it write — and hyper's own parser has already removed
    // them from live traffic, so what this pins is the capture-file path.
    //
    // What these two guard is the `trim_ows` call, not the whole change: they
    // fail if it is deleted and pass if the trim moves back inside the date
    // reader, because both spellings tolerate the padding. That is the guard
    // worth having, since the call is the load-bearing half here.
    #[case(Some(vec![("last-modified", " Wed, 21 Oct 2015 07:28:00 GMT")] ), false)]
    #[case(Some(vec![("last-modified", "Wed, 21 Oct 2015 07:28:00 GMT\t")] ), false)]
    fn check_last_modified_cases(
        #[case] headers: Option<Vec<(&str, &str)>>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = LastModifiedRfc1123Syntax;
        let mut tx = crate::test_helpers::make_test_transaction();

        if let Some(h) = headers {
            tx.response = Some(crate::http_transaction::ResponseInfo {
                status: 200,
                version: "HTTP/1.1".into(),
                headers: crate::test_helpers::make_headers_from_pairs(&h),

                body_length: None,
                trailers: None,
            });
        }

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        if expect_violation {
            assert!(v.is_some());
            let m = v.unwrap().message;
            assert!(m.contains("Last-Modified"));
        } else {
            assert!(v.is_none());
        }
        Ok(())
    }

    #[test]
    fn invalid_non_utf8_last_modified_is_violation() -> anyhow::Result<()> {
        let rule = LastModifiedRfc1123Syntax;
        let mut tx = crate::test_helpers::make_test_transaction();

        // Construct a response with non-UTF8 Last-Modified header
        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        let bad = HeaderValue::from_bytes(&[0xff])?;
        hm.insert("last-modified", bad);
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,

            body_length: None,
            trailers: None,
        });

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn scope_is_server() {
        let rule = LastModifiedRfc1123Syntax;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }
}
