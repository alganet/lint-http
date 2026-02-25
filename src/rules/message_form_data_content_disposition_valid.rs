// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageFormDataContentDispositionValid;

impl Rule for MessageFormDataContentDispositionValid {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_form_data_content_disposition_valid"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        config: &Self::Config,
    ) -> Option<Violation> {
        // Helper that checks a single header value
        let check_value = |_hdr: &str, val: &str| -> Option<Violation> {
            let s = val.trim();
            if s.is_empty() {
                return None; // other rules handle empty disposition
            }

            let mut parts = s.splitn(2, ';');
            let dispo = parts.next().unwrap().trim();
            let params_part = parts.next().map(|p| p.trim()).unwrap_or("");

            if !dispo.eq_ignore_ascii_case("form-data") {
                return None; // only applies to form-data dispositions
            }

            // We MUST have a 'name' parameter with a non-empty value per RFC 7578 §4.2
            if params_part.is_empty() {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Content-Disposition: 'form-data' missing 'name' parameter".into(),
                });
            }

            let mut name_found = false;
            for raw_param in
                crate::helpers::headers::split_semicolons_respecting_quotes(params_part)
            {
                let p = raw_param.trim();
                if p.is_empty() {
                    continue;
                }
                let eq = p.find('=');
                if eq.is_none() {
                    // malformed param - leave to parameter validation rule; be conservative
                    continue;
                }
                let (name, val) = p.split_at(eq.unwrap());
                if name.trim().eq_ignore_ascii_case("name") {
                    let raw = val[1..].trim(); // skip '=' and trim

                    if raw.starts_with('"') {
                        // quoted-string: check if inner trimmed content is empty or invalid
                        match crate::helpers::headers::quoted_string_inner_trimmed_is_empty(raw) {
                            Ok(true) => {
                                return Some(Violation {
                                    rule: self.id().into(),
                                    severity: config.severity,
                                    message: "Content-Disposition 'form-data' has empty 'name' parameter"
                                        .into(),
                                });
                            }
                            Ok(false) => {
                                name_found = true;
                                break;
                            }
                            Err(e) => {
                                return Some(Violation {
                                    rule: self.id().into(),
                                    severity: config.severity,
                                    message: format!(
                                        "Content-Disposition 'form-data' has invalid quoted 'name' parameter: {}",
                                        e
                                    ),
                                })
                            }
                        }
                    } else {
                        // token/unquoted value
                        if raw.is_empty() {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message:
                                    "Content-Disposition 'form-data' has empty 'name' parameter"
                                        .into(),
                            });
                        }
                        name_found = true;
                        break;
                    }
                }
            }

            if !name_found {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Content-Disposition: 'form-data' missing 'name' parameter".into(),
                });
            }

            None
        };

        // Check response headers
        if let Some(resp) = &tx.response {
            for hv in resp.headers.get_all("content-disposition").iter() {
                match hv.to_str() {
                    Ok(s) => {
                        if let Some(v) = check_value("Content-Disposition", s) {
                            return Some(v);
                        }
                    }
                    Err(_) => {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: "Content-Disposition header value is not valid UTF-8".into(),
                        })
                    }
                }
            }
        }

        // Check request headers (multipart/form-data parts may present Content-Disposition in requests)
        for hv in tx.request.headers.get_all("content-disposition").iter() {
            match hv.to_str() {
                Ok(s) => {
                    if let Some(v) = check_value("Content-Disposition", s) {
                        return Some(v);
                    }
                }
                Err(_) => {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Content-Disposition header value is not valid UTF-8".into(),
                    })
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(Some("form-data; name=\"user\""), false)]
    #[case(Some("form-data; name=user; filename=example.txt"), false)]
    #[case(Some("form-data; filename=example.txt"), true)]
    #[case(Some("form-data; name="), true)]
    #[case(Some("attachment; filename=example.txt"), false)]
    #[case(None, false)]
    fn check_request_cases(
        #[case] cd: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageFormDataContentDispositionValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(v) = cd {
            tx.request.headers =
                crate::test_helpers::make_headers_from_pairs(&[("content-disposition", v)]);
        }

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(v.is_some(), "expected violation for '{:?}'", cd);
        } else {
            assert!(v.is_none(), "unexpected violation for '{:?}': {:?}", cd, v);
        }
        Ok(())
    }

    #[rstest]
    #[case(Some("form-data; name=\"user\""), false)]
    #[case(Some("form-data; filename=example.txt"), true)]
    #[case(Some("attachment; filename=example.txt"), false)]
    #[case(None, false)]
    fn check_response_cases(
        #[case] cd: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageFormDataContentDispositionValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        if let Some(v) = cd {
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[("content-disposition", v)]);
        }

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(v.is_some(), "expected violation for '{:?}'", cd);
        } else {
            assert!(v.is_none(), "unexpected violation for '{:?}': {:?}", cd, v);
        }
        Ok(())
    }

    #[test]
    fn non_utf8_header_is_reported() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        let rule = MessageFormDataContentDispositionValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        hm.insert("content-disposition", HeaderValue::from_bytes(&[0xff])?);
        tx.response.as_mut().unwrap().headers = hm;

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn quoted_empty_name_reports_violation() {
        let rule = MessageFormDataContentDispositionValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-disposition",
            "form-data; name=\"\"",
        )]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn quoted_whitespace_name_reports_violation() {
        let rule = MessageFormDataContentDispositionValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-disposition",
            "form-data; name=\"   \"",
        )]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn malformed_quoted_name_reports_violation() {
        let rule = MessageFormDataContentDispositionValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-disposition",
            "form-data; name=\"unterminated",
        )]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn request_non_utf8_header_is_reported() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        let rule = MessageFormDataContentDispositionValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        hm.insert("content-disposition", HeaderValue::from_bytes(&[0xff])?);
        tx.request.headers = hm;

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn form_data_without_params_reports_missing_name() {
        let rule = MessageFormDataContentDispositionValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-disposition", "form-data")]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn case_insensitive_disposition_and_param_name_is_accepted() {
        let rule = MessageFormDataContentDispositionValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-disposition",
            "Form-Data; NAME=User",
        )]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn empty_disposition_type_is_ignored() {
        let rule = MessageFormDataContentDispositionValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-disposition", "; name=user")]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn form_data_with_trailing_semicolon_reports_missing_name() {
        let rule = MessageFormDataContentDispositionValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-disposition", "form-data;")]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn multiple_content_disposition_all_valid_is_ok() {
        use hyper::header::HeaderValue;
        let rule = MessageFormDataContentDispositionValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers.append(
            "content-disposition",
            HeaderValue::from_static("form-data; name=\"a\""),
        );
        tx.response.as_mut().unwrap().headers.append(
            "content-disposition",
            HeaderValue::from_static("form-data; name=\"b\""),
        );

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn empty_header_value_is_ignored() {
        let rule = MessageFormDataContentDispositionValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-disposition", "")]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn malformed_param_without_eq_is_ignored_by_this_rule() {
        let rule = MessageFormDataContentDispositionValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-disposition",
            "form-data; badparam",
        )]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        // Although a parameter is present, the absence of a 'name' parameter should still be
        // treated as a violation for 'form-data' dispositions.
        assert!(v.is_some());
    }

    #[test]
    fn multiple_content_disposition_headers_one_invalid_reports_violation() {
        use hyper::header::HeaderValue;
        let rule = MessageFormDataContentDispositionValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        // append a valid and an invalid header
        tx.response.as_mut().unwrap().headers.append(
            "content-disposition",
            HeaderValue::from_static("form-data; name=\"u\""),
        );
        tx.response.as_mut().unwrap().headers.append(
            "content-disposition",
            HeaderValue::from_static("form-data; filename=example.txt"),
        );

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_form_data_content_disposition_valid");
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
