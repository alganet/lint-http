// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct FormDataContentDispositionValid;

impl Rule for FormDataContentDispositionValid {
    fn id(&self) -> &'static str {
        "form_data_content_disposition_valid"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Option<Violation> {
        // Scope worth being honest about: RFC 7578 §4.2 places its requirement on
        // each *part* of a multipart/form-data body, and this proxy does not parse
        // bodies — the transaction carries header maps, not parts. So what is
        // actually inspected is a message-level `Content-Disposition`, which is a
        // different position from the one the spec is talking about. A message-level
        // `form-data` disposition is itself out of place (RFC 6266 defines `inline`
        // and `attachment` for HTTP messages), so when this rule does fire the
        // missing `name` is usually the lesser of the two oddities. Part-level
        // checking would need a body parser; until then this is a best-effort
        // approximation and not the §4.2 check itself.
        // Helper that checks a single header value
        let check_value = |_hdr: &str, val: &str| -> Option<Violation> {
            let s = val.trim();
            if s.is_empty() {
                return None; // other rules handle empty disposition
            }

            let mut parts = s.splitn(2, ';');
            let dispo = parts.next().unwrap().trim();
            let params_part = parts.next().map(|p| p.trim()).unwrap_or("");

            // Everything below is scoped to the `form-data` disposition type; an
            // `inline` or `attachment` disposition (RFC 6266) carries no `name`
            // requirement and is left alone. The previous quote here stopped at
            // "...Content-Disposition header field", dropping the very clause that
            // licenses this gate. The full sentence cannot be quoted as one span
            // because an `[RFC2183]` hyperlink sits in the middle of it, so the
            // operative clause is quoted on its own.
            // cite(RFC 7578 § 4.2): "where the disposition type is "form-data"."
            if !dispo.eq_ignore_ascii_case("form-data") {
                return None; // only applies to form-data dispositions
            }

            // The `name` parameter is a MUST, and its value is meant to be the form
            // field name — which is the basis for treating an empty one as a defect
            // below, though the spec does not spell out "non-empty" and an empty
            // value is a linter judgement rather than a quoted requirement.
            // cite(RFC 7578 § 4.2): "The Content-Disposition header field MUST also contain an additional parameter of "name"; the value of the "name" parameter is the original field name from the form"
            if params_part.is_empty() {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: ctx.severity,
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
                                    severity: ctx.severity,
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
                                    severity: ctx.severity,
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
                                severity: ctx.severity,
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

            // Not reported when the quoting never closes. After a stray DQUOTE
            // everything collapses into one segment and no separator past it is
            // a separator, so `p="x; name="a"` — which plainly carries a name —
            // was announced as missing one. Whether that text is a parameter is
            // exactly what the broken quoting makes unknowable, and this is a
            // claim about absence. A name the scan did find is judged above and
            // needs no such gate.
            if !name_found && crate::helpers::headers::quoting_is_balanced(params_part) {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: ctx.severity,
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
                            severity: ctx.severity,
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
                        severity: ctx.severity,
                        message: "Content-Disposition header value is not valid UTF-8".into(),
                    })
                }
            }
        }

        None
    }

    fn title(&self) -> Option<&'static str> {
        Some("Message Form-Data Content-Disposition Validity")
    }

    fn description(&self) -> &'static str {
        "Ensure that a `form-data` `Content-Disposition` includes a non-empty `name` parameter. RFC 7578 §4.2 requires the parameter and defines its value as the original field name from the form; receiving applications rely on it to associate part data with form fields, so a missing or empty `name` breaks form processing.\n\n**Scope:** RFC 7578 places this requirement on each *part* of a multipart body, but the linter inspects message header fields rather than parsed body parts, so what it checks is a message-level `Content-Disposition`. That position is itself unusual — RFC 6266 defines `inline` and `attachment` for HTTP messages, not `form-data` — so this is a best-effort approximation of the §4.2 check rather than the check itself. Dispositions other than `form-data` are ignored.\n\nAn empty `name` value is reported as a defect. The specification requires the parameter and says what it means, but does not literally say \"non-empty\"; treating an empty field name as broken is this linter's judgement.\n\n**Quoting that never closes is declined, not guessed at.** After a stray `\"` no separator can be trusted, so `form-data; p=\"x; name=\"a\"` is not reported as missing a name — whether that text is a parameter is exactly what the broken quoting makes unknowable. This applies only to the *absence* claim: a `name` the scan did find is still judged."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 7578",
                section: Some("4.2"),
                url: "https://www.rfc-editor.org/rfc/rfc7578.html#section-4.2",
                note: "Each multipart/form-data *part* MUST contain a `Content-Disposition` header with disposition-type `form-data` and MUST also contain a `name` parameter — a requirement on parts, which this rule approximates at the message level",
            },
            crate::rules::SpecRef {
                spec: "RFC 6266",
                section: Some("4.1"),
                url: "https://www.rfc-editor.org/rfc/rfc6266.html#section-4.1",
                note: "The disposition types HTTP messages actually use (`inline`, `attachment`); a message-level `form-data` is outside this grammar, which is why the type gate skips everything else",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "Content-Disposition: form-data; name=\"user\"\nContent-Disposition: form-data; name=user; filename=\"photo.png\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "Content-Disposition: form-data; filename=\"photo.png\"   # missing 'name'\nContent-Disposition: form-data; name=   # empty 'name'",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &FormDataContentDispositionValid;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(Some("form-data; name=\"user\""), false)]
    #[case(Some("form-data; name=user; filename=example.txt"), false)]
    #[case(Some("form-data; filename=example.txt"), true)]
    #[case(Some("form-data; name="), true)]
    // Quoting that never closes makes the absence of a name unknowable, so the
    // rule declines rather than announce one is missing from a value that
    // plainly carries it.
    #[case(Some("form-data; p=\"x; name=\"a\""), false)]
    #[case(Some("form-data; p=a\"b; name=\"a\""), false)]
    // A backslash outside a quoted-string escapes nothing, so this list is
    // readable and the missing name is a real finding.
    #[case(Some("form-data; p=a\\"), true)]
    // Balanced quoting with no name is still reported, so the gate narrows
    // nothing it should not.
    #[case(Some("form-data; p=\"a;b\""), true)]
    #[case(Some("attachment; filename=example.txt"), false)]
    #[case(None, false)]
    fn check_request_cases(
        #[case] cd: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = FormDataContentDispositionValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "form_data_content_disposition_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(v) = cd {
            tx.request.headers =
                crate::test_helpers::make_headers_from_pairs(&[("content-disposition", v)]);
        }

        let v = crate::test_helpers::run_rule(
            &rule,
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
        let rule = FormDataContentDispositionValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "form_data_content_disposition_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        if let Some(v) = cd {
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[("content-disposition", v)]);
        }

        let v = crate::test_helpers::run_rule(
            &rule,
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
        let rule = FormDataContentDispositionValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "form_data_content_disposition_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        hm.insert("content-disposition", HeaderValue::from_bytes(&[0xff])?);
        tx.response.as_mut().unwrap().headers = hm;

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn quoted_empty_name_reports_violation() {
        let rule = FormDataContentDispositionValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "form_data_content_disposition_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-disposition",
            "form-data; name=\"\"",
        )]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn quoted_whitespace_name_reports_violation() {
        let rule = FormDataContentDispositionValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "form_data_content_disposition_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-disposition",
            "form-data; name=\"   \"",
        )]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn malformed_quoted_name_reports_violation() {
        let rule = FormDataContentDispositionValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "form_data_content_disposition_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-disposition",
            "form-data; name=\"unterminated",
        )]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn request_non_utf8_header_is_reported() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        let rule = FormDataContentDispositionValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "form_data_content_disposition_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        hm.insert("content-disposition", HeaderValue::from_bytes(&[0xff])?);
        tx.request.headers = hm;

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn form_data_without_params_reports_missing_name() {
        let rule = FormDataContentDispositionValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "form_data_content_disposition_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-disposition", "form-data")]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn case_insensitive_disposition_and_param_name_is_accepted() {
        let rule = FormDataContentDispositionValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "form_data_content_disposition_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-disposition",
            "Form-Data; NAME=User",
        )]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn empty_disposition_type_is_ignored() {
        let rule = FormDataContentDispositionValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "form_data_content_disposition_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-disposition", "; name=user")]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn form_data_with_trailing_semicolon_reports_missing_name() {
        let rule = FormDataContentDispositionValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "form_data_content_disposition_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-disposition", "form-data;")]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn multiple_content_disposition_all_valid_is_ok() {
        use hyper::header::HeaderValue;
        let rule = FormDataContentDispositionValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "form_data_content_disposition_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers.append(
            "content-disposition",
            HeaderValue::from_static("form-data; name=\"a\""),
        );
        tx.response.as_mut().unwrap().headers.append(
            "content-disposition",
            HeaderValue::from_static("form-data; name=\"b\""),
        );

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn empty_header_value_is_ignored() {
        let rule = FormDataContentDispositionValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "form_data_content_disposition_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-disposition", "")]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn malformed_param_without_eq_is_ignored_by_this_rule() {
        let rule = FormDataContentDispositionValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "form_data_content_disposition_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-disposition",
            "form-data; badparam",
        )]);
        let v = crate::test_helpers::run_rule(
            &rule,
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
        let rule = FormDataContentDispositionValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "form_data_content_disposition_valid",
        ]);

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

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "form_data_content_disposition_valid");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
