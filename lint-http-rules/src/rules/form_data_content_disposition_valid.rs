// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::parameter::{PARAMETER_VALUE_EMPTY, RFC_9110_5_6_6};
use crate::violations::quoted_string::{
    quoted_string_defect, QUOTED_STRING_CONTROL_CHARACTER_FORBIDDEN,
    QUOTED_STRING_DELIMITER_MISSING, QUOTED_STRING_QUOTED_PAIR_MALFORMED,
    QUOTED_STRING_QUOTE_ESCAPE_MISSING, RFC_9110_5_6_4,
};
use crate::violations::ViolationDef;

pub struct FormDataContentDispositionValid;

/// The defects this rule reports through the catalogue, all of them borrowed.
///
/// **The position decides the grammar, and the position is an HTTP header
/// field.** RFC 7578 § 4.2 states its requirement about a *part* of a
/// `multipart/form-data` body, where the field is MIME's and its parameters are
/// RFC 2183's; what this rule can actually read is a message-level
/// `Content-Disposition`, which RFC 6266 § 4.1 defines and which takes its
/// `token`, its `quoted-string` and its `name=value` shape from HTTP. So the
/// parameter defects are the shared ones — the same entries
/// `content_disposition_parameter_valid` declares for the same field — and what
/// stays this rule's own is what RFC 7578 says the `name` parameter *means*.
/// The day the linter parses body parts, that reading is RFC 2183's and the
/// question is worth asking again.
///
/// Two findings are deliberately absent. A `form-data` disposition missing its
/// `name` altogether is § 4.2's MUST about the *set* of parameters, not a
/// defect of any one of them. And a `name` whose quoted value holds nothing is
/// a `quoted-string` deriving exactly as § 5.6.4 says, around a form field name
/// of nothing: the production is satisfied and the requirement is not, which is
/// why it does not answer with [`PARAMETER_VALUE_EMPTY`] the way the unquoted
/// spelling does.
static DECLARED: &[&ViolationDef] = &[
    &PARAMETER_VALUE_EMPTY,
    &QUOTED_STRING_DELIMITER_MISSING,
    &QUOTED_STRING_QUOTED_PAIR_MALFORMED,
    &QUOTED_STRING_QUOTE_ESCAPE_MISSING,
    &QUOTED_STRING_CONTROL_CHARACTER_FORBIDDEN,
];

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_7578_4_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 7578",
    section: Some("4.2"),
    url: "https://www.rfc-editor.org/rfc/rfc7578.html#section-4.2",
    note: "Each multipart/form-data *part* MUST contain a `Content-Disposition` header with disposition-type `form-data` and MUST also contain a `name` parameter — a requirement on parts, which this rule approximates at the message level",
};
const RFC_6266_4_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 6266",
    section: Some("4.1"),
    url: "https://www.rfc-editor.org/rfc/rfc6266.html#section-4.1",
    note: "The disposition types HTTP messages actually use (`inline`, `attachment`); a message-level `form-data` is outside this grammar, which is why the type gate skips everything else",
};

impl RuleMeta for FormDataContentDispositionValid {
    fn id(&self) -> &'static str {
        "form_data_content_disposition_valid"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
severity = "warn"
"#
    }

    fn title(&self) -> Option<&'static str> {
        Some("Message Form-Data Content-Disposition Validity")
    }

    fn description(&self) -> &'static str {
        "Ensure that a `form-data` `Content-Disposition` includes a non-empty `name` parameter. RFC 7578 §4.2 requires the parameter and defines its value as the original field name from the form; receiving applications rely on it to associate part data with form fields, so a missing or empty `name` breaks form processing.\n\n**Scope:** RFC 7578 places this requirement on each *part* of a multipart body, but the linter inspects message header fields rather than parsed body parts, so what it checks is a message-level `Content-Disposition`. That position is itself unusual — RFC 6266 defines `inline` and `attachment` for HTTP messages, not `form-data` — so this is a best-effort approximation of the §4.2 check rather than the check itself. Dispositions other than `form-data` are ignored.\n\nAn empty `name` value is reported as a defect. The specification requires the parameter and says what it means, but does not literally say \"non-empty\"; treating an empty field name as broken is this linter's judgement.\n\n**Quoting that never closes is declined, not guessed at.** After a stray `\"` no separator can be trusted, so `form-data; p=\"x; name=\"a\"` is not reported as missing a name — whether that text is a parameter is exactly what the broken quoting makes unknowable. This applies only to the *absence* claim: a `name` the scan did find is still judged."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_7578_4_2, RFC_6266_4_1, RFC_9110_5_6_6, RFC_9110_5_6_4]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
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

impl Rule for FormDataContentDispositionValid {
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
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
                    return Some(self.cited(
                        &RFC_7578_4_2,
                        ctx.severity,
                        "Content-Disposition: 'form-data' missing 'name' parameter".into(),
                    ));
                }

                let mut name_found = false;
                for raw_param in
                    crate::helpers::list::split_semicolons_respecting_quotes(params_part)
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
                            match crate::helpers::quoted_string::quoted_string_inner_trimmed_is_empty(raw) {
                                // The production is satisfied here and the
                                // requirement is not: a pair of DQUOTEs around
                                // nothing is the `quoted-string` § 5.6.4
                                // writes, carrying a form field name of
                                // nothing. That is § 4.2's sentence about what
                                // the value *is*, so it stays this rule's, and
                                // the unquoted spelling below — where there is
                                // no value at all — is the parameter's.
                                Ok(true) => {
                                    return Some(self.violation(ctx.severity, "Content-Disposition 'form-data' has empty 'name' parameter"
                                            .into()));
                                }
                                Ok(false) => {
                                    name_found = true;
                                    break;
                                }
                                // Whatever stopped the walk is the production's
                                // defect and not this field's, and the sentence
                                // it breaks is the same one whichever field
                                // carried the value.
                                Err(defect) => {
                                    return Some(ctx.report_with(
                                        quoted_string_defect(defect),
                                        format!(
                                            "Content-Disposition 'form-data' has invalid quoted 'name' parameter: {}",
                                            defect.message(raw)
                                        ),
                                    ))
                                }
                            }
                        } else {
                            // token/unquoted value
                            if raw.is_empty() {
                                return Some(ctx.report_with(
                                    &PARAMETER_VALUE_EMPTY,
                                    "Content-Disposition 'form-data' has empty 'name' parameter"
                                        .into(),
                                ));
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
                if !name_found && crate::helpers::list::quoting_is_balanced(params_part) {
                    return Some(self.violation(
                        ctx.severity,
                        "Content-Disposition: 'form-data' missing 'name' parameter".into(),
                    ));
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
                            return Some(self.violation(
                                ctx.severity,
                                "Content-Disposition header value is not valid UTF-8".into(),
                            ))
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
                        return Some(self.violation(
                            ctx.severity,
                            "Content-Disposition header value is not valid UTF-8".into(),
                        ))
                    }
                }
            }

            None
        };
        Vec::from_iter(finding())
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &FormDataContentDispositionValid;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// The `name` parameter is read against the same productions any other
    /// parameter of this field is, and the last two rows are the pair that
    /// looks like one finding and is two: a value that does not exist is
    /// § 5.6.6's, and a pair of DQUOTEs around nothing is a `quoted-string`
    /// that derives — leaving a form field name of nothing, which is § 4.2's
    /// sentence and stays this rule's.
    ///
    /// The first two rows are asserted against `content_disposition_parameter_
    /// valid` reading the same shapes at the same field, out of a rule that
    /// walks the parameters differently and shares no code with this one.
    #[rstest]
    #[case("form-data; name=\"unterminated", "quoted_string_delimiter_missing")]
    // The fourth defect of the production, a control octet inside the quotes,
    // is declared and unreachable from here: a `HeaderValue` refuses the octet
    // outright, so the transaction cannot be built to carry one.
    #[case("form-data; name=\"a\"b\"", "quoted_string_quote_escape_missing")]
    #[case("form-data; name=", "parameter_value_empty")]
    #[case("form-data; name=\"\"", "")]
    #[case("form-data; filename=example.txt", "")]
    fn the_name_parameter_reports_the_productions_it_borrows(
        #[case] value: &str,
        #[case] id: &str,
    ) {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-disposition", value)]);
        let found = crate::test_helpers::run_rule(
            &FormDataContentDispositionValid,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_severity(
                "form_data_content_disposition_valid",
                "warn",
            ),
        )
        .expect("a finding");
        // An unconverted site carries no defect id at all, which is what the
        // two empty rows assert.
        assert_eq!(found.violation, id, "{value}");
    }

    /// The same two values at the same field, judged by the rule that reads an
    /// `attachment` disposition: two rules, one id apiece, no shared code.
    #[rstest]
    #[case(
        "attachment; filename=\"unterminated",
        "quoted_string_delimiter_missing"
    )]
    #[case("attachment; filename=", "parameter_value_empty")]
    fn the_sibling_rule_answers_with_the_same_ids(#[case] value: &str, #[case] id: &str) {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().expect("a response").headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-disposition", value)]);
        let found = crate::test_helpers::run_rule(
            &crate::rules::content_disposition_parameter_valid::ContentDispositionParameterValid,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_severity(
                "content_disposition_parameter_valid",
                "warn",
            ),
        )
        .expect("a finding");
        assert_eq!(found.violation, id, "{value}");
    }

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
