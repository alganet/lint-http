// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageDigestAuthValidity;

impl Rule for MessageDigestAuthValidity {
    fn id(&self) -> &'static str {
        "message_digest_auth_validity"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
        for hv in tx.request.headers.get_all("authorization").iter() {
            match hv.to_str() {
                Ok(s) => {
                    let s = s.trim();
                    if s.is_empty() {
                        continue;
                    }
                    // Only care about the Digest scheme; auth-scheme names are
                    // matched case-insensitively.
                    // cite(RFC 9110 § 11.1): "It uses a case-insensitive token to identify the authentication scheme"
                    let mut parts = s.splitn(2, char::is_whitespace);
                    let scheme = parts.next().unwrap();
                    if !scheme.eq_ignore_ascii_case("digest") {
                        continue;
                    }
                    let rest = match parts.next() {
                        Some(r) => r.trim(),
                        None => {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: "Authorization Digest scheme missing parameters".into(),
                            })
                        }
                    };

                    // parse auth-param list into map
                    match crate::helpers::auth::parse_auth_params(rest) {
                        Ok(map) => {
                            // Required fields: username, realm, nonce, uri, response. §3.4 lists the
                            // parameters and names the consequence for missing required ones, but
                            // labels no "required" set; these five are the ones the response
                            // computation (§3.4.1) cannot be verified without whatever the
                            // credential's vintage. cnonce and nc are demanded below, behind the
                            // observable line that keeps RFC 2617-style credentials checkable.
                            // cite(RFC 7616 § 3.4): "If a parameter or its value is improper, or required parameters are missing, the proper response is a 4xx error code."
                            let required = ["username", "realm", "nonce", "uri", "response"];
                            for &k in &required {
                                match map.get(k) {
                                    Some(v) => {
                                        // treat empty unquoted values or quoted-strings with empty inner content
                                        let is_empty = if v.is_empty() {
                                            true
                                        } else if v.starts_with('"') {
                                            // if quoted-string is syntactically invalid, default to 'false' so
                                            // it will be reported by the later quoted-string validation
                                            crate::helpers::headers::quoted_string_inner_trimmed_is_empty(v).unwrap_or_default()
                                        } else {
                                            false
                                        };

                                        if is_empty {
                                            return Some(Violation {
                                                rule: self.id().into(),
                                                severity: config.severity,
                                                message: format!(
                                                    "Digest Authorization missing or empty required parameter '{}'",
                                                    k
                                                ),
                                            })
                                        }
                                    }
                                    None => {
                                        return Some(Violation {
                                            rule: self.id().into(),
                                            severity: config.severity,
                                            message: format!(
                                                "Digest Authorization missing or empty required parameter '{}'",
                                                k
                                            ),
                                        })
                                    }
                                }
                            }
                            // The two parameters RFC 7616 §3.4 marks "MUST be used by all
                            // implementations", demanded where the credential's own qop makes
                            // the demand observable. RFC 2617 computes a qop-less response
                            // without either, so requiring them of every Digest credential
                            // would reject that document's otherwise-checkable shape — but a
                            // credential that *carries* qop is inside both documents' MUSTs at
                            // once: RFC 2617's conditional is met by the message itself, and
                            // both compute the response value over cnonce and nc, so their
                            // absence leaves the response unverifiable by the recipient it was
                            // written for. The qop-less decline is published in
                            // `description()`.
                            // cite(RFC 7616 § 3.4, label: cnonce): "This parameter MUST be used by all implementations."
                            // cite(RFC 2617 § 3.2.2): "This MUST be specified if a qop directive is sent (see above), and MUST NOT be specified if the server did not send a qop directive in the WWW-Authenticate header field."
                            if map.contains_key("qop") {
                                for &k in &["cnonce", "nc"] {
                                    if !map.contains_key(k) {
                                        return Some(Violation {
                                            rule: self.id().into(),
                                            severity: config.severity,
                                            message: format!(
                                                "Digest Authorization sends 'qop' and no '{k}': RFC 7616 \u{a7}3.4 marks the parameter \"MUST be used by all implementations\", RFC 2617 \u{a7}3.2.2 requires it whenever a qop directive is sent, and both documents compute the response value over it, so without it the credential cannot be verified"
                                            ),
                                        });
                                    }
                                }
                            }

                            // validate tokensexp and quoted values basic syntax
                            for (k, v) in map.iter() {
                                // param names must be tokens
                                if let Some(inv) = crate::helpers::token::find_invalid_token_char(k)
                                {
                                    return Some(Violation {
                                        rule: self.id().into(),
                                        severity: config.severity,
                                        message: format!(
                                            "Invalid character '{}' in Digest auth-param name",
                                            inv
                                        ),
                                    });
                                }
                                // §3.4's two per-parameter quoting MUSTs, enforced in both
                                // directions. The historical reason is the point: recipients
                                // of these parameters were deployed against one spelling each,
                                // so the wrong spelling is a credential some verifiers will
                                // not read. The seven-name list is why the old `uri` branch —
                                // which deliberately accepted an unquoted value — is gone: an
                                // unquoted uri is exactly what the first sentence forbids.
                                // `username*`, `userhash` and unknown extensions are in
                                // neither list, and only their present spelling is judged.
                                // cite(RFC 7616 § 3.4): "For historical reasons, a sender MUST only generate the quoted string syntax for the following parameters: username, realm, nonce, uri, response, cnonce, and opaque."
                                // cite(RFC 7616 § 3.4): "For historical reasons, a sender MUST NOT generate the quoted string syntax for the following parameters: algorithm, qop, and nc."
                                const MUST_QUOTE: &[&str] = &[
                                    "username", "realm", "nonce", "uri", "response", "cnonce",
                                    "opaque",
                                ];
                                const MUST_NOT_QUOTE: &[&str] = &["algorithm", "qop", "nc"];

                                let quoted = v.starts_with('"');
                                if MUST_QUOTE.contains(&k.as_str()) && !quoted {
                                    return Some(Violation {
                                        rule: self.id().into(),
                                        severity: config.severity,
                                        message: format!(
                                            "Digest Authorization sends '{k}' unquoted, and RFC 7616 \u{a7}3.4 admits only the quoted string syntax for it (\"a sender MUST only generate the quoted string syntax for the following parameters: username, realm, nonce, uri, response, cnonce, and opaque\")"
                                        ),
                                    });
                                }
                                if MUST_NOT_QUOTE.contains(&k.as_str()) && quoted {
                                    return Some(Violation {
                                        rule: self.id().into(),
                                        severity: config.severity,
                                        message: format!(
                                            "Digest Authorization sends '{k}' as a quoted string, and RFC 7616 \u{a7}3.4 forbids that spelling for it (\"a sender MUST NOT generate the quoted string syntax for the following parameters: algorithm, qop, and nc\")"
                                        ),
                                    });
                                }

                                // A value that opens with a quote is validated as a quoted-string
                                // (grammar helper-owned, RFC 9110 §5.6.4).
                                if quoted {
                                    if let Err(msg) =
                                        crate::helpers::headers::validate_quoted_string(v)
                                    {
                                        return Some(Violation {
                                            rule: self.id().into(),
                                            severity: config.severity,
                                            message: format!(
                                                "Invalid quoted-string in Digest auth-param '{}': {}",
                                                k, msg
                                            ),
                                        });
                                    }
                                } else {
                                    // Unquoted values are tokens. The `uri` carve-out that
                                    // stood here (allow anything without control characters)
                                    // is unreachable now: an unquoted `uri` returns above.
                                    if let Some(inv) =
                                        crate::helpers::token::find_invalid_token_char(v)
                                    {
                                        return Some(Violation {
                                            rule: self.id().into(),
                                            severity: config.severity,
                                            message: format!(
                                                "Invalid character '{}' in Digest auth-param value for '{}'",
                                                inv, k
                                            ),
                                        });
                                    }
                                }
                            }
                        }
                        Err(msg) => {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: format!("Invalid Digest auth parameters: {}", msg),
                            })
                        }
                    }
                }
                Err(_) => {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Authorization header contains non-UTF8 value".into(),
                    })
                }
            }
        }
        None
    }

    fn description(&self) -> &'static str {
        "Digest `Authorization` credentials must include the required auth-params and use syntactically valid tokens or quoted-strings. This rule checks `Authorization: Digest ...` request headers for presence of required fields and basic syntactic validity (e.g., `username`, `realm`, `nonce`, `uri`, `response`).\n\n**`cnonce` and `nc` are demanded exactly where the credential's own `qop` makes the demand observable.** RFC 7616 §3.4 marks each *\"MUST be used by all implementations\"*; RFC 2617 computes a qop-less response without either and makes both conditional on a qop directive. A credential that carries `qop` is inside both documents' requirements at once — and both compute the `response` value over `cnonce` and `nc`, so their absence leaves the credential unverifiable by the recipient it was written for. A credential with no `qop` is RFC 2617's older shape and neither is demanded of it: RFC 7616 alone would ask for them, but rejecting the qop-less form outright would reject credentials the obsolete document defines and deployed servers still verify, and no observable line short of `qop` separates the two vintages.\n\n**§3.4's two per-parameter quoting MUSTs are enforced in both directions.** A sender *\"MUST only generate the quoted string syntax\"* for `username`, `realm`, `nonce`, `uri`, `response`, `cnonce` and `opaque`, and *\"MUST NOT\"* for `algorithm`, `qop` and `nc` — for historical reasons, which is the point: recipients of each parameter were deployed against one spelling, so the wrong spelling is a credential some verifiers will not read. An unquoted `uri` was deliberately accepted here for a long time and no longer is. `username*`, `userhash` and unknown extension parameters are in neither list, so only the spelling they arrived in is judged.\n\nServers and clients relying on Digest authentication may behave incorrectly when required parameters are missing or malformed."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 7616",
                section: Some("3.4"),
                url: "https://www.rfc-editor.org/rfc/rfc7616.html#section-3.4",
                note: "The Authorization Header Field — the Digest credentials, their parameters, the 4xx consequence for missing or improper ones, the \"MUST be used by all implementations\" on cnonce and nc, and the two historical-reasons quoting MUSTs enforced here in both directions",
            },
            crate::rules::SpecRef {
                spec: "RFC 2617",
                section: Some("3.2.2"),
                url: "https://www.rfc-editor.org/rfc/rfc2617.html#section-3.2.2",
                note: "The obsolete document whose qop-less credential shape is why cnonce and nc are demanded only beside a qop: its own conditional (\"MUST be specified if a qop directive is sent\") is the observable line, and deployed servers still verify the older shape",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "GET /protected HTTP/1.1\nAuthorization: Digest username=\"Mufasa\", realm=\"test\", nonce=\"abc\", uri=\"/protected\", response=\"d41d8cd98f00b204e9800998ecf8427e\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(missing response)"),
                snippet: "GET /protected HTTP/1.1\nAuthorization: Digest username=\"Mufasa\", realm=\"test\", nonce=\"abc\", uri=\"/protected\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(username unquoted — §3.4 admits only the quoted string syntax for it)"),
                snippet: "GET /protected HTTP/1.1\nAuthorization: Digest username=Mu!fasa, realm=\"test\", nonce=\"abc\", uri=\"/protected\", response=\"d41d8c\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(qop sent with no cnonce or nc — the response value is computed over both)"),
                snippet: "GET /protected HTTP/1.1\nAuthorization: Digest username=\"Mufasa\", realm=\"test\", nonce=\"abc\", uri=\"/protected\", response=\"d41d8c\", qop=auth",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &MessageDigestAuthValidity;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    // The conforming fixtures write each parameter in the spelling §3.4's two
    // historical-reasons MUSTs assign it — the seven quoted, `algorithm`, `qop`
    // and `nc` bare. The fixtures used to write everything unquoted, which is
    // the tolerance RULECITES P37 removed.
    #[rstest]
    #[case(
        Some(
            "Digest username=\"Mufasa\", realm=\"test\", nonce=\"abc\", uri=\"/\", response=\"d\""
        ),
        false
    )]
    #[case(
        Some("Digest username=\"Mufasa\", realm=\"test\", nonce=\"abc\", uri=\"/\", response=\"d\", algorithm=MD5"),
        false
    )]
    // RFC 7616's full shape: qop with cnonce and nc beside it.
    #[case(
        Some("Digest username=\"Mufasa\", realm=\"test\", nonce=\"abc\", uri=\"/\", response=\"d\", qop=auth, cnonce=\"xyz\", nc=00000001"),
        false
    )]
    // qop without nc, and qop without cnonce: both documents' MUSTs at once.
    #[case(
        Some("Digest username=\"Mufasa\", realm=\"test\", nonce=\"abc\", uri=\"/\", response=\"d\", qop=auth, cnonce=\"xyz\""),
        true
    )]
    #[case(
        Some("Digest username=\"Mufasa\", realm=\"test\", nonce=\"abc\", uri=\"/\", response=\"d\", qop=auth, nc=00000001"),
        true
    )]
    // The spelling findings, one per direction: an unquoted `uri` — the value
    // the old rule deliberately accepted — and a quoted `nc`.
    #[case(
        Some("Digest username=\"Mufasa\", realm=\"test\", nonce=\"abc\", uri=/, response=\"d\""),
        true
    )]
    #[case(
        Some("Digest username=\"Mufasa\", realm=\"test\", nonce=\"abc\", uri=\"/\", response=\"d\", qop=auth, cnonce=\"xyz\", nc=\"00000001\""),
        true
    )]
    #[case(
        Some("Digest username=\"Mufasa\", realm=\"test\", nonce=\"abc\", uri=\"/\""),
        true
    )]
    #[case(
        Some("Digest username=, realm=\"test\", nonce=\"abc\", uri=\"/\", response=\"d\""),
        true
    )]
    #[case(
        Some("Digest username=\"Mufasa\", realm=\"test\", nonce=a@bad, uri=\"/\", response=\"d\""),
        true
    )]
    #[case(Some("Basic abc"), false)]
    #[case(Some("Digest"), true)]
    #[case(
        Some("Digest username=\"Mufasa, realm=test, nonce=abc, uri=/, response=d"),
        true
    )]
    #[case(None, false)]
    fn check_digest_authorization(
        #[case] header: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageDigestAuthValidity;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_digest_auth_validity",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(h) = header {
            tx.request
                .headers
                .append("authorization", h.parse().unwrap());
        }

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(v.is_some());
        } else {
            assert!(v.is_none());
        }
        Ok(())
    }

    #[test]
    fn invalid_param_name_reports_violation() -> anyhow::Result<()> {
        let rule = MessageDigestAuthValidity;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_digest_auth_validity",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers.append(
            "authorization",
            "Digest user@name=abc, realm=test, nonce=abc, uri=/, response=d"
                .parse()
                .unwrap(),
        );

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let v = v.unwrap();
        assert!(v.message.contains("Invalid character"));
        Ok(())
    }

    #[test]
    fn lowercase_scheme_is_accepted() -> anyhow::Result<()> {
        let rule = MessageDigestAuthValidity;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_digest_auth_validity",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers.append(
            "authorization",
            "digest username=\"Mufasa\", realm=\"test\", nonce=\"abc\", uri=\"/\", response=\"d\""
                .parse()
                .unwrap(),
        );

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn parse_params_missing_value_reports_violation() -> anyhow::Result<()> {
        let rule = MessageDigestAuthValidity;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_digest_auth_validity",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers.append(
            "authorization",
            "Digest username, realm=test, nonce=abc, uri=/, response=d"
                .parse()
                .unwrap(),
        );

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let v = v.unwrap();
        assert!(v.message.contains("Invalid Digest auth parameters"));
        Ok(())
    }

    #[test]
    fn non_utf8_header_reports_violation() -> anyhow::Result<()> {
        let rule = MessageDigestAuthValidity;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers.append(
            "authorization",
            hyper::header::HeaderValue::from_bytes(b"Digest \xff").unwrap(),
        );
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn required_param_quoted_empty_reports_violation() -> anyhow::Result<()> {
        let rule = MessageDigestAuthValidity;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_digest_auth_validity",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers.append(
            "authorization",
            "Digest username=\"\", realm=\"test\", nonce=\"abc\", uri=\"/\", response=\"d\""
                .parse()
                .unwrap(),
        );

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let v = v.unwrap();
        assert!(
            v.message.contains("missing or empty required parameter")
                || v.message.contains("Invalid Digest auth parameters")
        );
        Ok(())
    }

    #[test]
    fn quoted_string_with_escaped_quote_is_accepted() -> anyhow::Result<()> {
        let rule = MessageDigestAuthValidity;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_digest_auth_validity",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        // username contains an escaped quote inside the quoted-string which is valid
        tx.request.headers.append(
            "authorization",
            "Digest username=\"Mu\\\"fasa\", realm=\"test\", nonce=\"abc\", uri=\"/\", response=\"d\"".parse().unwrap(),
        );

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn invalid_quoted_string_reports_specific_message() -> anyhow::Result<()> {
        let rule = MessageDigestAuthValidity;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_digest_auth_validity",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        // username quoted-string missing closing quote should trigger quoted-string validation error
        tx.request.headers.append(
            "authorization",
            "Digest username=\"Mufasa, realm=test, nonce=abc, uri=/, response=d"
                .parse()
                .unwrap(),
        );

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(
            msg.contains("Invalid quoted-string")
                || msg.contains("Invalid Digest auth parameters")
                || msg.contains("missing or empty required parameter")
        );
        Ok(())
    }

    #[test]
    fn header_value_construction_rejects_control_chars() -> anyhow::Result<()> {
        // Hyper's HeaderValue validation rejects control characters in header values (as per the HTTP
        // specification). Therefore it's not possible to construct a header containing LF/CR to feed
        // through the normal header pipeline; the constructor will return an error. Assert that
        // behavior here so we don't rely on impossible-to-construct inputs.
        use hyper::header::HeaderValue;
        let raw = b"Digest username=Mufasa, realm=test, nonce=abc, uri=/bad\n, response=d";
        let hv = HeaderValue::from_bytes(raw);
        assert!(hv.is_err());
        Ok(())
    }

    #[test]
    fn digest_scheme_with_whitespace_but_no_params_reports_invalid_params() -> anyhow::Result<()> {
        let rule = MessageDigestAuthValidity;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_digest_auth_validity",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request
            .headers
            .append("authorization", "Digest    ".parse().unwrap());

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let v = v.unwrap();
        // message should be non-empty and indicate a problem with parameters
        assert!(!v.message.is_empty());
        Ok(())
    }

    #[test]
    fn digest_scheme_without_params_reports_missing_parameters_message() -> anyhow::Result<()> {
        let rule = MessageDigestAuthValidity;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_digest_auth_validity",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request
            .headers
            .append("authorization", "Digest".parse().unwrap());

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let v = v.unwrap();
        assert!(v.message.contains("missing parameters"));
        Ok(())
    }

    #[test]
    fn invalid_response_value_token_char_reports_violation() -> anyhow::Result<()> {
        let rule = MessageDigestAuthValidity;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_digest_auth_validity",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers.append(
            "authorization",
            "Digest username=\"Mufasa\", realm=\"test\", nonce=\"abc\", uri=\"/\", response=\"d\", userhash=tr@e"
                .parse()
                .unwrap(),
        );

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(
            msg.contains("Invalid character") || msg.contains("Invalid Digest auth parameters")
        );
        Ok(())
    }

    #[test]
    fn invalid_quoted_string_extra_chars_reports_violation() -> anyhow::Result<()> {
        let rule = MessageDigestAuthValidity;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_digest_auth_validity",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        // username quoted-string followed by extra chars should trigger quoted-string validation error
        tx.request.headers.append(
            "authorization",
            "Digest username=\"Mufasa\"x, realm=\"test\", nonce=\"abc\", uri=\"/\", response=\"d\""
                .parse()
                .unwrap(),
        );

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(
            msg.contains("Invalid quoted-string") || msg.contains("Invalid Digest auth parameters")
        );
        Ok(())
    }

    #[test]
    fn duplicate_param_last_empty_reports_violation() -> anyhow::Result<()> {
        let rule = MessageDigestAuthValidity;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_digest_auth_validity",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        // username appears twice; last one is empty -> should trigger missing/empty required param
        tx.request.headers.append(
            "authorization",
            "Digest username=Mufasa, username=, realm=test, nonce=abc, uri=/, response=d"
                .parse()
                .unwrap(),
        );

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let v = v.unwrap();
        assert!(
            v.message.contains("missing or empty required parameter")
                || v.message.contains("Invalid Digest auth parameters")
        );
        Ok(())
    }

    #[test]
    fn multiple_authorization_headers_one_invalid_triggers_violation() -> anyhow::Result<()> {
        let rule = MessageDigestAuthValidity;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_digest_auth_validity",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        // add a Basic header first, then an invalid Digest (empty response)
        tx.request
            .headers
            .append("authorization", "Basic abc".parse().unwrap());
        tx.request.headers.append(
            "authorization",
            "Digest username=Mufasa, realm=test, nonce=abc, uri=/, response="
                .parse()
                .unwrap(),
        );

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let v = v.unwrap();
        assert!(
            v.message.contains("missing or empty required parameter")
                || v.message.contains("Invalid Digest auth parameters")
        );
        Ok(())
    }

    #[test]
    fn multiple_digest_headers_one_invalid_after_valid_triggers_violation() -> anyhow::Result<()> {
        let rule = MessageDigestAuthValidity;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_digest_auth_validity",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        // first a valid Digest, then an invalid Digest (empty response)
        tx.request.headers.append(
            "authorization",
            "Digest username=\"Alice\", realm=\"test\", nonce=\"abc\", uri=\"/\", response=\"resp1\""
                .parse()
                .unwrap(),
        );
        tx.request.headers.append(
            "authorization",
            "Digest username=Bob, realm=test, nonce=abc, uri=/, response="
                .parse()
                .unwrap(),
        );

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn multiple_digest_headers_all_valid_no_violation() -> anyhow::Result<()> {
        let rule = MessageDigestAuthValidity;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_digest_auth_validity",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers.append(
            "authorization",
            "Digest username=\"Alice\", realm=\"test\", nonce=\"abc\", uri=\"/\", response=\"resp1\""
                .parse()
                .unwrap(),
        );
        tx.request.headers.append(
            "authorization",
            "Digest username=\"Bob\", realm=\"test\", nonce=\"def\", uri=\"/\", response=\"resp2\""
                .parse()
                .unwrap(),
        );

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn empty_authorization_header_ignored() {
        let rule = MessageDigestAuthValidity;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_digest_auth_validity",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        // An empty Authorization value should be ignored
        tx.request
            .headers
            .append("authorization", "".parse().unwrap());
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn unquoted_username_with_space_reports_violation() -> anyhow::Result<()> {
        let rule = MessageDigestAuthValidity;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_digest_auth_validity",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers.append(
            "authorization",
            "Digest username=Mu fasa, realm=test, nonce=abc, uri=/, response=d"
                .parse()
                .unwrap(),
        );

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn quoted_string_ends_with_escape_reports_violation() -> anyhow::Result<()> {
        let rule = MessageDigestAuthValidity;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_digest_auth_validity",
        ]);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers.append(
            "authorization",
            "Digest username=\"Mu\\\", realm=\"test\", nonce=\"abc\", uri=\"/\", response=\"d\""
                .parse()
                .unwrap(),
        );
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(
            msg.contains("Invalid quoted-string")
                || msg.contains("Invalid Digest auth parameters")
                || msg.contains("missing or empty required parameter")
        );
        Ok(())
    }

    #[test]
    fn required_param_unquoted_empty_reports_violation() -> anyhow::Result<()> {
        let rule = MessageDigestAuthValidity;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_digest_auth_validity",
        ]);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers.append(
            "authorization",
            "Digest username=, realm=test, nonce=abc, uri=/, response=d"
                .parse()
                .unwrap(),
        );
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(
            msg.contains("missing or empty required parameter")
                || msg.contains("Invalid Digest auth parameters")
        );
        Ok(())
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_digest_auth_validity");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn scope_is_client() {
        let rule = MessageDigestAuthValidity;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Client);
    }
}
