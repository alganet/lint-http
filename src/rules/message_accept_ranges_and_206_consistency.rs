// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageAcceptRangesAnd206Consistency;

impl Rule for MessageAcceptRangesAnd206Consistency {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_accept_ranges_and_206_consistency"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _previous: Option<&crate::http_transaction::HttpTransaction>,
        config: &Self::Config,
    ) -> Option<Violation> {
        let resp = match &tx.response {
            Some(r) => r,
            None => return None,
        };

        if resp.status != 206 {
            return None;
        }

        // If Accept-Ranges is present, ensure it indicates support (not 'none') and includes
        // the unit used in Content-Range (when present). Iterate all header fields and combine
        // their advertised units; non-UTF8 fields are ignored.
        let mut saw_units: Vec<String> = Vec::new();
        let mut any_accept_ranges_present = false;

        for hv in resp.headers.get_all("accept-ranges").iter() {
            if let Ok(s) = hv.to_str() {
                any_accept_ranges_present = true;
                for token in crate::helpers::headers::parse_list_header(s) {
                    if let Some(c) = crate::helpers::token::find_invalid_token_char(token) {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!("Invalid token '{}' in Accept-Ranges header", c),
                        });
                    }
                    saw_units.push(token.to_ascii_lowercase());
                }
            }
        }

        if any_accept_ranges_present {
            // 'none' must not be present when server returned a 206
            if saw_units.iter().any(|t| t == "none") {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Accept-Ranges indicates no range support ('none') while response is 206 Partial Content".into(),
                });
            }

            // If Content-Range present and ASCII-valid, ensure its unit is advertised in Accept-Ranges
            if let Some(hv) = resp
                .headers
                .get_all("content-range")
                .iter()
                .find(|h| h.to_str().is_ok())
            {
                if let Ok(cr) = hv.to_str() {
                    if let Some(unit) = cr.split_whitespace().next() {
                        let unit_l = unit.to_ascii_lowercase();
                        if !saw_units.iter().any(|u| u == &unit_l) {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: format!("Content-Range uses unit '{}' but Accept-Ranges does not advertise it", unit),
                            });
                        }
                    }
                }
            }

            return None;
        }

        // No ASCII-valid Accept-Ranges header present — recommend advertising support for ranges when returning 206
        Some(Violation {
            rule: self.id().into(),
            severity: config.severity,
            message: "206 Partial Content response should include an Accept-Ranges header indicating supported range units (e.g., 'bytes')".into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(Some((200, None)), false)]
    #[case(Some((206, Some(("bytes", "bytes")))), false)]
    #[case(Some((206, Some(("bytes", "none")))), true)]
    #[case(Some((206, None)), true)]
    #[case(Some((206, Some(("bytes", "pages")))), true)]
    fn check_accept_ranges_and_206_cases(
        #[case] input: Option<(u16, Option<(&str, &str)>)>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        // input: (status, Option<(content-range-unit, accept-ranges-value)>)
        let rule = MessageAcceptRangesAnd206Consistency;
        let cfg = crate::test_helpers::make_test_rule_config();

        let tx = match input {
            Some((status, maybe)) => {
                let tx = match maybe {
                    Some((cr_unit, ar_val)) => {
                        crate::test_helpers::make_test_transaction_with_response(
                            status,
                            &[
                                ("content-range", &format!("{} 0-0/1", cr_unit)),
                                ("accept-ranges", ar_val),
                            ],
                        )
                    }
                    None => crate::test_helpers::make_test_transaction_with_response(status, &[]),
                };
                tx
            }
            None => crate::test_helpers::make_test_transaction(),
        };

        let v = rule.check_transaction(&tx, None, &cfg);
        if expect_violation {
            assert!(v.is_some(), "expected violation for input={:?}", input);
        } else {
            assert!(
                v.is_none(),
                "unexpected violation for input={:?}: {:?}",
                input,
                v
            );
        }
        Ok(())
    }

    #[test]
    fn accept_ranges_case_insensitive_and_multiple_values_are_accepted() -> anyhow::Result<()> {
        let rule = MessageAcceptRangesAnd206Consistency;
        let cfg = crate::test_helpers::make_test_rule_config();

        // uppercase Accept-Ranges matches lowercase Content-Range
        let tx1 = crate::test_helpers::make_test_transaction_with_response(
            206,
            &[("content-range", "bytes 0-0/1"), ("accept-ranges", "BYTES")],
        );
        assert!(rule.check_transaction(&tx1, None, &cfg).is_none());

        // multiple values include the used unit
        let tx2 = crate::test_helpers::make_test_transaction_with_response(
            206,
            &[
                ("content-range", "bytes 0-0/1"),
                ("accept-ranges", "pages, bytes"),
            ],
        );
        assert!(rule.check_transaction(&tx2, None, &cfg).is_none());

        Ok(())
    }

    #[test]
    fn invalid_token_in_accept_ranges_is_reported() {
        let rule = MessageAcceptRangesAnd206Consistency;
        let cfg = crate::test_helpers::make_test_rule_config();

        let tx = crate::test_helpers::make_test_transaction_with_response(
            206,
            [("accept-ranges", "x@bad")].as_slice(),
        );
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("Invalid token"));
    }

    #[test]
    fn multiple_accept_ranges_fields_are_combined_and_checked() -> anyhow::Result<()> {
        let rule = MessageAcceptRangesAnd206Consistency;
        let cfg = crate::test_helpers::make_test_rule_config();

        // Two separate header fields that together advertise the needed unit
        use hyper::header::HeaderValue;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(206, &[]);
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        hm.append("content-range", HeaderValue::from_static("bytes 0-0/1"));
        hm.append("accept-ranges", HeaderValue::from_static("pages"));
        hm.append("accept-ranges", HeaderValue::from_static("bytes"));
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 206,
            version: "HTTP/1.1".into(),
            headers: hm,
            body_length: None,
        });

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn accept_ranges_none_in_any_field_reports_violation() -> anyhow::Result<()> {
        let rule = MessageAcceptRangesAnd206Consistency;
        let cfg = crate::test_helpers::make_test_rule_config();

        use hyper::header::HeaderValue;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(206, &[]);
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        hm.append("content-range", HeaderValue::from_static("bytes 0-0/1"));
        hm.append("accept-ranges", HeaderValue::from_static("bytes"));
        hm.append("accept-ranges", HeaderValue::from_static("none"));
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 206,
            version: "HTTP/1.1".into(),
            headers: hm,
            body_length: None,
        });

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn multiple_accept_ranges_fields_invalid_token_reports_violation() -> anyhow::Result<()> {
        let rule = MessageAcceptRangesAnd206Consistency;
        let cfg = crate::test_helpers::make_test_rule_config();

        use hyper::header::HeaderValue;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(206, &[]);
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        hm.append("accept-ranges", HeaderValue::from_static("bytes"));
        hm.append("accept-ranges", HeaderValue::from_static("x@bad"));
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 206,
            version: "HTTP/1.1".into(),
            headers: hm,
            body_length: None,
        });

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn all_accept_ranges_fields_non_utf8_treated_as_missing() -> anyhow::Result<()> {
        let rule = MessageAcceptRangesAnd206Consistency;
        let cfg = crate::test_helpers::make_test_rule_config();

        use hyper::header::HeaderValue;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(206, &[]);
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        hm.append("accept-ranges", HeaderValue::from_bytes(&[0xff])?);
        hm.append("accept-ranges", HeaderValue::from_bytes(&[0xfe])?);
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 206,
            version: "HTTP/1.1".into(),
            headers: hm,
            body_length: None,
        });

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn non_utf8_accept_ranges_treated_as_missing() -> anyhow::Result<()> {
        let rule = MessageAcceptRangesAnd206Consistency;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(206, &[]);
        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        hm.append("accept-ranges", HeaderValue::from_bytes(&[0xff])?);
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 206,
            version: "HTTP/1.1".into(),
            headers: hm,
            body_length: None,
        });

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("should include an Accept-Ranges") || msg.contains("Accept-Ranges"));
        Ok(())
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_accept_ranges_and_206_consistency");
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn scope_is_server() {
        let rule = MessageAcceptRangesAnd206Consistency;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }
}
