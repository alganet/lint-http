// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ClientAcceptRangesOnPartialContent;

impl Rule for ClientAcceptRangesOnPartialContent {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "client_accept_ranges_on_partial_content"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        previous: Option<&crate::http_transaction::HttpTransaction>,
        config: &Self::Config,
    ) -> Option<Violation> {
        // Only applies to requests that contain a UTF-8 Range header we can parse.
        let range_val = crate::helpers::headers::get_header_str(&tx.request.headers, "range")?;
        // Only treat the header as having a unit if it includes a '=' delimiter (e.g. 'bytes=0-499')
        let range_unit = {
            let mut parts = range_val.splitn(2, '=');
            let unit = parts.next().unwrap_or_default();
            if parts.next().is_some() {
                Some(unit.trim().to_ascii_lowercase())
            } else {
                None
            }
        };

        let prev = previous?;

        let resp = prev.response.as_ref()?;

        // Collect any ASCII-valid Accept-Ranges tokens from previous response
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

        // Range unit already parsed from validated UTF-8 header above.

        // If Accept-Ranges explicitly advertises 'none' -> client should not send Range
        if saw_units.iter().any(|t| t == "none") {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Client sent Range request despite previous response advertising 'Accept-Ranges: none'".into(),
            });
        }

        // If Accept-Ranges was present, but does not advertise the unit used by the client, flag violation
        if any_accept_ranges_present {
            if let Some(unit) = &range_unit {
                if !saw_units.iter().any(|u| u == unit) {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!("Client sent Range using unit '{}' but previous response did not advertise it in Accept-Ranges", unit),
                    });
                }
            }
            // If unit could not be parsed, be lenient and do not raise here
            return None;
        }

        // No Accept-Ranges present in previous response. If previous response was 206, recommend client to avoid sending Range requests without prior advertisement
        if resp.status == 206 {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Client sent Range request but previous 206 Partial Content response did not advertise Accept-Ranges".into(),
            });
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn make_prev_resp(
        status: u16,
        accept_ranges: Option<&str>,
    ) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(status, &[]);
        if let Some(ar) = accept_ranges {
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[("accept-ranges", ar)]);
        }
        tx
    }

    #[rstest]
    #[case(Some((206, Some("bytes"))), "bytes=0-1", false)]
    #[case(Some((200, Some("none"))), "bytes=0-1", true)]
    #[case(Some((206, None)), "bytes=0-1", true)]
    #[case(Some((200, None)), "bytes=0-1", false)]
    #[case(Some((206, Some("pages"))), "bytes=0-1", true)]
    #[case(None, "bytes=0-1", false)]
    fn check_cases(
        #[case] prev: Option<(u16, Option<&str>)>,
        #[case] range_val: &str,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = ClientAcceptRangesOnPartialContent;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[("range", range_val)]);

        let previous = match prev {
            Some((status, ar)) => {
                let mut p = make_prev_resp(status, ar);
                // set previous request URI to same resource to simulate stateful match
                p.request.uri = tx.request.uri.clone();
                Some(p)
            }
            None => None,
        };

        let prev_ref = previous.as_ref();
        let v = rule.check_transaction(&tx, prev_ref, &cfg);
        if expect_violation {
            assert!(v.is_some());
        } else {
            assert!(v.is_none());
        }
        Ok(())
    }

    #[test]
    fn invalid_accept_ranges_token_reports_violation() {
        let rule = ClientAcceptRangesOnPartialContent;
        let cfg = crate::test_helpers::make_test_rule_config();
        let mut p = make_prev_resp(200, Some("x@bad"));
        p.request.uri = crate::test_helpers::make_test_transaction()
            .request
            .uri
            .clone();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("range", "bytes=0-1")]);

        let v = rule.check_transaction(&tx, Some(&p), &cfg);
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("Invalid token"));
    }

    #[test]
    fn no_previous_response_does_nothing() -> anyhow::Result<()> {
        let rule = ClientAcceptRangesOnPartialContent;
        let cfg = crate::test_helpers::make_test_rule_config();
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("range", "bytes=0-1")]);
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn scope_is_client() {
        let rule = ClientAcceptRangesOnPartialContent;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Client);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "client_accept_ranges_on_partial_content");
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn non_utf8_accept_ranges_treated_as_missing_reports_violation() -> anyhow::Result<()> {
        let rule = ClientAcceptRangesOnPartialContent;
        let cfg = crate::test_helpers::make_test_rule_config();

        // Create a previous response 206 with non-UTF8 Accept-Ranges header
        let mut p = make_prev_resp(206, None);
        // replace header map with one that has a non-utf8 value
        let mut hm = p.response.as_ref().unwrap().headers.clone();
        use hyper::header::HeaderValue;
        hm.insert("accept-ranges", HeaderValue::from_bytes(&[0xff]).unwrap());
        p.response = Some(crate::http_transaction::ResponseInfo {
            status: 206,
            version: p.response.as_ref().unwrap().version.clone(),
            headers: hm,
            body_length: None,
        });

        // ensure URI matches so previous state is relevant
        p.request.uri = crate::test_helpers::make_test_transaction()
            .request
            .uri
            .clone();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("range", "bytes=0-1")]);

        let v = rule.check_transaction(&tx, Some(&p), &cfg);
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("Accept-Ranges") || msg.contains("should include"));
        Ok(())
    }

    #[test]
    fn non_utf8_range_with_accept_ranges_present_is_lenient() -> anyhow::Result<()> {
        let rule = ClientAcceptRangesOnPartialContent;
        let cfg = crate::test_helpers::make_test_rule_config();

        // Previous response advertises 'bytes' in Accept-Ranges
        let mut p = make_prev_resp(200, Some("bytes"));
        p.request.uri = crate::test_helpers::make_test_transaction()
            .request
            .uri
            .clone();

        // Create a request with a non-utf8 Range header value
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = tx.request.headers.clone();
        use hyper::header::HeaderValue;
        hm.insert("range", HeaderValue::from_bytes(&[0xff]).unwrap());
        tx.request.headers = hm;

        let v = rule.check_transaction(&tx, Some(&p), &cfg);
        // Be lenient: if the request Range header is non-utf8, do not raise a violation when Accept-Ranges was present
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn non_utf8_range_with_previous_206_is_lenient() -> anyhow::Result<()> {
        let rule = ClientAcceptRangesOnPartialContent;
        let cfg = crate::test_helpers::make_test_rule_config();

        // Create a previous 206 response with no Accept-Ranges header
        let mut p = make_prev_resp(206, None);
        p.request.uri = crate::test_helpers::make_test_transaction()
            .request
            .uri
            .clone();

        // Create a request with a non-utf8 Range header value
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = tx.request.headers.clone();
        use hyper::header::HeaderValue;
        hm.insert("range", HeaderValue::from_bytes(&[0xff]).unwrap());
        tx.request.headers = hm;

        let v = rule.check_transaction(&tx, Some(&p), &cfg);
        // If Range header itself is not valid UTF-8, the rule should not emit a misleading violation about Accept-Ranges
        assert!(v.is_none());
        Ok(())
    }
}
