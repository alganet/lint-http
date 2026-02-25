// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageMultipartBoundarySyntax;

impl Rule for MessageMultipartBoundarySyntax {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_multipart_boundary_syntax"
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
        // Check request Content-Type
        if let Some(hv) = tx.request.headers.get("content-type") {
            if let Ok(s) = hv.to_str() {
                if let Some(v) = check_multipart_boundary("request", s, config) {
                    return Some(v);
                }
            }
        }

        // Check response Content-Type
        if let Some(resp) = &tx.response {
            if let Some(hv) = resp.headers.get("content-type") {
                if let Ok(s) = hv.to_str() {
                    if let Some(v) = check_multipart_boundary("response", s, config) {
                        return Some(v);
                    }
                }
            }
        }

        None
    }
}

fn check_multipart_boundary(
    which: &str,
    val: &str,
    config: &crate::rules::RuleConfig,
) -> Option<Violation> {
    let parsed = match crate::helpers::headers::parse_media_type(val) {
        Ok(p) => p,
        Err(_) => return None, // other rules validate Content-Type well-formedness
    };

    if parsed.type_.eq_ignore_ascii_case("multipart") {
        // params must include boundary
        let mut found = false;
        if let Some(params) = parsed.params {
            for raw in params.split(';') {
                let p = raw.trim();
                if p.is_empty() {
                    continue;
                }
                if let Some(eq) = p.find('=') {
                    let (name, value) = p.split_at(eq);
                    let name = name.trim();
                    let value = value[1..].trim(); // skip '='
                    if name.eq_ignore_ascii_case("boundary") {
                        found = true;
                        if value.is_empty() {
                            return Some(Violation {
                                rule: MessageMultipartBoundarySyntax.id().into(),
                                severity: config.severity,
                                message: format!(
                                    "Invalid multipart Content-Type in {}: empty 'boundary' parameter",
                                    which
                                ),
                            });
                        }

                        // If quoted-string, validate quoted-string and unescape
                        let boundary_unquoted = if value.starts_with('"') {
                            // Unescape quoted-string interior using helper
                            match crate::helpers::headers::unescape_quoted_string(value) {
                                Ok(u) => u,
                                Err(e) => {
                                    return Some(Violation {
                                        rule: MessageMultipartBoundarySyntax.id().into(),
                                        severity: config.severity,
                                        message: format!(
                                            "Invalid multipart Content-Type in {}: boundary quoted-string invalid: {}",
                                            which, e
                                        ),
                                    })
                                }
                            }
                        } else {
                            // unquoted token: ensure token characters
                            if let Some(c) = crate::helpers::token::find_invalid_token_char(value) {
                                return Some(Violation {
                                    rule: MessageMultipartBoundarySyntax.id().into(),
                                    severity: config.severity,
                                    message: format!(
                                        "Invalid multipart Content-Type in {}: boundary contains invalid token character '{}'",
                                        which, c
                                    ),
                                });
                            }
                            value.to_string()
                        };

                        // length 1..70
                        let len = boundary_unquoted.len();
                        if len == 0 || len > 70 {
                            return Some(Violation {
                                rule: MessageMultipartBoundarySyntax.id().into(),
                                severity: config.severity,
                                message: format!(
                                    "Invalid multipart Content-Type in {}: 'boundary' must be between 1 and 70 characters",
                                    which
                                ),
                            });
                        }

                        // must not end with whitespace
                        if boundary_unquoted
                            .chars()
                            .last()
                            .map(|c| c.is_whitespace())
                            .unwrap_or(false)
                        {
                            return Some(Violation {
                                rule: MessageMultipartBoundarySyntax.id().into(),
                                severity: config.severity,
                                message: format!(
                                    "Invalid multipart Content-Type in {}: 'boundary' must not end with whitespace",
                                    which
                                ),
                            });
                        }

                        // For quoted values ensure characters are from bchars set (DIGIT / ALPHA / "'()" / "+_,-./:=?") or space
                        // (unquoted tokens already validated against token grammar)
                        for ch in boundary_unquoted.chars() {
                            if ch.is_ascii_alphanumeric()
                                || matches!(
                                    ch,
                                    '\'' | '('
                                        | ')'
                                        | '+'
                                        | '_'
                                        | ','
                                        | '-'
                                        | '.'
                                        | '/'
                                        | ':'
                                        | '='
                                        | '?'
                                )
                                || ch == ' '
                            {
                                continue;
                            }
                            return Some(Violation {
                                rule: MessageMultipartBoundarySyntax.id().into(),
                                severity: config.severity,
                                message: format!(
                                    "Invalid multipart Content-Type in {}: boundary contains invalid character '{}'",
                                    which, ch
                                ),
                            });
                        }
                    }
                }
            }
        }

        if !found {
            return Some(Violation {
                rule: MessageMultipartBoundarySyntax.id().into(),
                severity: config.severity,
                message: format!(
                    "Invalid multipart Content-Type in {}: missing required 'boundary' parameter",
                    which
                ),
            });
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[test]
    fn debug_long_boundary_len() {
        // ensure parsing returns the expected long value length (71 a's)
        let boundary = "a".repeat(71);
        let long = format!("multipart/mixed; boundary={}", boundary);
        let parsed = crate::helpers::headers::parse_media_type(&long).unwrap();
        assert!(parsed.params.is_some());
        let params = parsed.params.unwrap();
        let mut found_val: Option<&str> = None;
        for raw in params.split(';') {
            let p = raw.trim();
            if p.is_empty() {
                continue;
            }
            if let Some(eq) = p.find('=') {
                let (_name, value) = p.split_at(eq);
                let value = value[1..].trim();
                if _name.trim().eq_ignore_ascii_case("boundary") {
                    found_val = Some(value);
                }
            }
        }
        assert!(found_val.is_some());
        assert_eq!(found_val.unwrap().len(), 71);
    }

    #[rstest]
    #[case(Some("multipart/mixed; boundary=gc0p4Jq0M2Yt08j34c0p"), false)]
    #[case(
        Some("multipart/mixed; boundary=gc0p4Jq0M2Yt08j34c0p; charset=utf-8"),
        false
    )]
    #[case(Some("multipart/mixed; boundary=\"gc0pJq0M:08jU534c0p\""), false)]
    #[case(Some("multipart/mixed"), true)]
    #[case(Some("multipart/mixed; boundary="), true)]
    #[case(Some("multipart/mixed; boundary=\"\""), true)]
    #[case(Some("multipart/mixed; boundary=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabb"), true)] // >70 chars
    #[case(Some("multipart/mixed; boundary=gc0pJq0M:08jU534c0p"), true)]
    #[case(Some("multipart/mixed; boundary=\"abc \""), true)]
    #[case(None, false)]
    fn multipart_boundary_cases(#[case] header: Option<&str>, #[case] expect_violation: bool) {
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(h) = header {
            tx.request.headers =
                crate::test_helpers::make_headers_from_pairs(&[("content-type", h)]);
        }

        let v = MessageMultipartBoundarySyntax.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(v.is_some(), "expected violation for {:?}", header);
        } else {
            assert!(
                v.is_none(),
                "unexpected violation for {:?}: {:?}",
                header,
                v
            );
        }

        // Also test response
        let cfg2 = crate::test_helpers::make_test_rule_config();
        let mut tx2 = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        if let Some(h) = header {
            tx2.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[("content-type", h)]);
        }
        let v2 = MessageMultipartBoundarySyntax.check_transaction(
            &tx2,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg2,
        );
        if expect_violation {
            assert!(v2.is_some(), "expected violation for response {:?}", header);
        } else {
            assert!(
                v2.is_none(),
                "unexpected violation for response {:?}: {:?}",
                header,
                v2
            );
        }
    }

    #[test]
    fn parse_media_type_error_no_violation() {
        // malformed Content-Type that fails parse_media_type should not cause this rule to run
        let cfg = crate::test_helpers::make_test_rule_config();
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-type", "not-a-media-type")]);
        let v = MessageMultipartBoundarySyntax.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn quoted_string_unterminated_reports_violation() {
        let cfg = crate::test_helpers::make_test_rule_config();
        let mut tx = crate::test_helpers::make_test_transaction();
        // boundary quoted-string not terminated
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-type",
            "multipart/mixed; boundary=\"unfinished",
        )]);
        let v = MessageMultipartBoundarySyntax.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("boundary quoted-string invalid"));
    }

    #[test]
    fn non_multipart_ignored() {
        let cfg = crate::test_helpers::make_test_rule_config();
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-type",
            "text/plain; boundary=abc",
        )]);
        let v = MessageMultipartBoundarySyntax.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn quoted_string_invalid_char_reports_violation() {
        let cfg = crate::test_helpers::make_test_rule_config();
        let mut tx = crate::test_helpers::make_test_transaction();
        // $ is not permitted in bchars set
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-type",
            "multipart/mixed; boundary=\"bad$\"",
        )]);
        let v = MessageMultipartBoundarySyntax.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("boundary contains invalid character"));
    }
}
