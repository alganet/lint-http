// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// Stateful checks for conditional requests and their responses.
///
/// - Conditional request headers (`If-None-Match`, `If-Match`, `If-Modified-Since`,
///   `If-Unmodified-Since`) should only be used when the client previously
///   observed a validator (ETag or Last-Modified) for the same resource.
/// - For `If-None-Match` / `If-Modified-Since` on `GET`/`HEAD`, a response that
///   matches the validator SHOULD be `304 Not Modified` rather than a `200`.
pub struct StatefulConditionalRequestHandling;

impl Rule for StatefulConditionalRequestHandling {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "stateful_conditional_request_handling"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        previous: Option<&crate::http_transaction::HttpTransaction>,
        config: &Self::Config,
    ) -> Option<Violation> {
        // Only applies when request contains one or more conditional headers
        let req = &tx.request;
        let has_inm = req.headers.get("if-none-match").is_some();
        let has_ifm = req.headers.get("if-modified-since").is_some();
        let has_imatch = req.headers.get("if-match").is_some();
        let has_iunmod = req.headers.get("if-unmodified-since").is_some();

        if !(has_inm || has_ifm || has_imatch || has_iunmod) {
            return None;
        }

        // If we have no previous transaction recorded for this client+resource,
        // warn that conditionals were sent without an observed validator.
        let prev = match previous {
            Some(p) => p,
            None => {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Conditional request sent but no previous response recorded for this resource (no ETag/Last-Modified to validate against)".into(),
                })
            }
        };

        // Previous transaction must include a response with validators when
        // entity-tag/date conditionals are used.
        if let Some(resp) = &prev.response {
            if (has_inm || has_imatch) && resp.headers.get("etag").is_none() {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Request contains entity-tag conditional (If-Match/If-None-Match) but previous response did not include an ETag".into(),
                });
            }

            if (has_ifm || has_iunmod) && resp.headers.get("last-modified").is_none() {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Request contains time-based conditional (If-Modified-Since/If-Unmodified-Since) but previous response did not include Last-Modified".into(),
                });
            }
        } else {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message:
                    "Conditional request sent but previous transaction has no response recorded"
                        .into(),
            });
        }

        // Response-side sanity checks for common conditional patterns (GET/HEAD):
        // - If-None-Match: if response ETag equals one of the request's ETags and
        //   server returned 200 for GET/HEAD, recommend 304.
        if has_inm
            && (req.method.eq_ignore_ascii_case("GET") || req.method.eq_ignore_ascii_case("HEAD"))
        {
            if let Some(resp) = &tx.response {
                if resp.status == 200 {
                    if let Some(resp_etag_hv) = resp.headers.get("etag") {
                        if let Ok(resp_etag) = resp_etag_hv.to_str() {
                            for hv in req.headers.get_all("if-none-match").iter() {
                                if let Ok(inm_raw) = hv.to_str() {
                                    for member in
                                        crate::helpers::headers::parse_list_header(inm_raw)
                                    {
                                        if member.trim() == resp_etag.trim() || member.trim() == "*"
                                        {
                                            return Some(Violation {
                                                rule: self.id().into(),
                                                severity: config.severity,
                                                message: "Conditional GET/HEAD used If-None-Match but server returned 200 while ETag matched; consider returning 304 Not Modified".into(),
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // - If-Modified-Since: if response Last-Modified equals the conditional
        //   value and server returned 200 for GET/HEAD, recommend 304.
        if has_ifm
            && (req.method.eq_ignore_ascii_case("GET") || req.method.eq_ignore_ascii_case("HEAD"))
        {
            if let Some(resp) = &tx.response {
                if resp.status == 200 {
                    if let (Some(req_ifms), Some(resp_lm_hv)) = (
                        crate::helpers::headers::get_header_str(&req.headers, "if-modified-since"),
                        resp.headers.get("last-modified"),
                    ) {
                        if let Ok(resp_lm) = resp_lm_hv.to_str() {
                            if crate::http_date::is_valid_http_date(req_ifms)
                                && crate::http_date::is_valid_http_date(resp_lm)
                            {
                                if let (Ok(req_dt), Ok(resp_dt)) = (
                                    crate::http_date::parse_http_date_to_datetime(req_ifms),
                                    crate::http_date::parse_http_date_to_datetime(resp_lm),
                                ) {
                                    if resp_dt <= req_dt {
                                        return Some(Violation {
                                            rule: self.id().into(),
                                            severity: config.severity,
                                            message: "Conditional GET/HEAD used If-Modified-Since but server returned 200 even though Last-Modified indicates the resource was not modified; consider returning 304 Not Modified".into(),
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_prev_with_headers(
        headers: &[(&str, &str)],
    ) -> crate::http_transaction::HttpTransaction {
        let mut prev = crate::test_helpers::make_test_transaction_with_response(200, headers);
        prev.request.method = "GET".to_string();
        prev
    }

    #[test]
    fn conditional_request_without_previous_is_reported() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"a\"")]);

        let rule = StatefulConditionalRequestHandling;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("no previous response recorded"));
    }

    #[test]
    fn conditional_request_requires_matching_previous_validator() {
        let rule = StatefulConditionalRequestHandling;

        // If-None-Match without previous ETag -> violation
        let mut tx1 = crate::test_helpers::make_test_transaction();
        tx1.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"a\"")]);
        let prev_empty = make_prev_with_headers(&[]);
        let v1 = rule.check_transaction(
            &tx1,
            Some(&prev_empty),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v1.is_some());

        // If-Modified-Since without previous Last-Modified -> violation
        let mut tx2 = crate::test_helpers::make_test_transaction();
        tx2.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "if-modified-since",
            "Wed, 21 Oct 2015 07:28:00 GMT",
        )]);
        let v2 = rule.check_transaction(
            &tx2,
            Some(&prev_empty),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v2.is_some());

        // If-Match without previous ETag -> violation
        let mut tx3 = crate::test_helpers::make_test_transaction();
        tx3.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-match", "\"a\"")]);
        let v3 = rule.check_transaction(
            &tx3,
            Some(&prev_empty),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v3.is_some());

        // If-Unmodified-Since without previous Last-Modified -> violation
        let mut tx4 = crate::test_helpers::make_test_transaction();
        tx4.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "if-unmodified-since",
            "Wed, 21 Oct 2015 07:28:00 GMT",
        )]);
        let v4 = rule.check_transaction(
            &tx4,
            Some(&prev_empty),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v4.is_some());
    }

    #[test]
    fn conditional_request_with_prev_etag_or_lm_ok() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"a\"")]);

        // previous response with ETag
        let prev = make_prev_with_headers(&[("etag", "\"a\"")]);

        let rule = StatefulConditionalRequestHandling;
        let v = rule.check_transaction(
            &tx,
            Some(&prev),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());

        // time-based conditional with Last-Modified
        let mut tx2 = crate::test_helpers::make_test_transaction();
        tx2.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "if-modified-since",
            "Wed, 21 Oct 2015 07:28:00 GMT",
        )]);
        let prev2 = make_prev_with_headers(&[("last-modified", "Wed, 21 Oct 2015 07:28:00 GMT")]);
        let v2 = rule.check_transaction(
            &tx2,
            Some(&prev2),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v2.is_none());
    }

    #[test]
    fn inm_response_matching_etag_reports_violation_for_get() {
        let mut tx =
            crate::test_helpers::make_test_transaction_with_response(200, &[("etag", "\"a\"")]);
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"a\"")]);
        tx.request.method = "GET".to_string();

        let prev = make_prev_with_headers(&[("etag", "\"a\"")]);

        let rule = StatefulConditionalRequestHandling;
        // previous satisfies validator check
        let v = rule.check_transaction(
            &tx,
            Some(&prev),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("consider returning 304"));
    }

    #[test]
    fn if_modified_since_response_matching_lm_reports_violation_for_get() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("last-modified", "Wed, 21 Oct 2015 07:28:00 GMT")],
        );
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "if-modified-since",
            "Wed, 21 Oct 2015 07:28:00 GMT",
        )]);
        tx.request.method = "GET".to_string();

        let prev = make_prev_with_headers(&[("last-modified", "Wed, 21 Oct 2015 07:28:00 GMT")]);

        let rule = StatefulConditionalRequestHandling;
        let v = rule.check_transaction(
            &tx,
            Some(&prev),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("consider returning 304"));
    }

    #[test]
    fn if_none_match_non_matching_etag_is_ok() {
        let mut tx =
            crate::test_helpers::make_test_transaction_with_response(200, &[("etag", "\"b\"")]);
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"a\"")]);
        tx.request.method = "GET".to_string();

        let prev = make_prev_with_headers(&[("etag", "\"a\"")]);

        let rule = StatefulConditionalRequestHandling;
        // response ETag doesn't match request conditional -> allowed
        let v = rule.check_transaction(
            &tx,
            Some(&prev),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn previous_without_response_reports_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"a\"")]);

        // previous transaction exists but has no response
        let prev = crate::test_helpers::make_test_transaction();

        let rule = StatefulConditionalRequestHandling;
        let v = rule.check_transaction(
            &tx,
            Some(&prev),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v
            .unwrap()
            .message
            .contains("previous transaction has no response recorded"));
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "stateful_conditional_request_handling");
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
