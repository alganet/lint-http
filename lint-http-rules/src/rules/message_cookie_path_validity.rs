// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageCookiePathValidity;

impl Rule for MessageCookiePathValidity {
    fn id(&self) -> &'static str {
        "message_cookie_path_validity"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
        let resp = tx.response.as_ref()?;

        for hv in resp.headers.get_all("set-cookie").iter() {
            let s = match hv.to_str() {
                Ok(v) => v,
                Err(_) => {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Set-Cookie header value is not valid UTF-8".into(),
                    })
                }
            };

            // Split into cookie-pair and attribute segments
            let parts = s.split(';').map(|p| p.trim()).collect::<Vec<_>>();
            if parts.is_empty() {
                // No segments at all; nothing to validate here
                continue;
            }

            for attr in parts.iter().skip(1) {
                if attr.is_empty() {
                    continue;
                }
                let mut av = attr.splitn(2, '=');
                let key = av.next().unwrap().trim();
                let val_opt = av.next().map(|v| v.trim());

                if key.eq_ignore_ascii_case("path") {
                    let v = match val_opt {
                        Some(v) => v,
                        None => {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: "Set-Cookie attribute 'Path' requires a value".into(),
                            })
                        }
                    };

                    if let Err(e) = crate::helpers::cookie::validate_cookie_path(v) {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!("Set-Cookie attribute 'Path' invalid: {}", e),
                        });
                    }
                }
            }
        }

        None
    }

    fn description(&self) -> &'static str {
        "Validate the `Path` attribute in `Set-Cookie` header fields. The `Path` attribute should be a valid RFC 6265 `path-value` that begins with `/`, does not contain control characters or `;`, and uses valid percent-encodings where applicable. Raw non-ASCII characters are rejected by this rule — non-ASCII data should be percent-encoded (see RFC 3986 §2.1). This rule is intentionally stricter than RFC 6265: it also rejects unencoded whitespace in the `Path` attribute (spaces should be sent as `%20`) to reduce ambiguity in cookie scope and avoid syntactic errors that can affect cookie delivery and security."
    }

    fn rfc_references(&self) -> &'static [&'static str] {
        &[
            "[RFC 6265 §5.2.4 — Path attribute](https://www.rfc-editor.org/rfc/rfc6265.html#section-5.2.4) — defines the `Path` attribute syntax and semantics (including `path-value`).",
            "[RFC 9110 §5.6.3 — Whitespace](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.3) — rationale for being conservative about whitespace in header fields; this rule adopts a stricter profile by disallowing unencoded whitespace in cookie paths.",
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet:
                    "HTTP/1.1 200 OK\nSet-Cookie: SID=31d4d96e407aad42; Path=/; HttpOnly; Secure",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(percent-encoded)"),
                snippet: "HTTP/1.1 200 OK\nSet-Cookie: user=alice; Path=/users/alice%2Fprofile",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(missing leading slash)"),
                snippet: "HTTP/1.1 200 OK\nSet-Cookie: SID=abcd; Path=login",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(contains space)"),
                snippet: "HTTP/1.1 200 OK\nSet-Cookie: SID=abcd; Path=/has space",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(raw non-ASCII)"),
                snippet: "HTTP/1.1 200 OK\nSet-Cookie: SID=abcd; Path=/café",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(non-ASCII percent-encoded)"),
                snippet: "HTTP/1.1 200 OK\nSet-Cookie: SID=abcd; Path=/caf%C3%A9",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &MessageCookiePathValidity;

#[cfg(test)]
mod tests {
    use super::*;

    fn check_set_cookie(value: &str) -> Option<Violation> {
        use crate::test_helpers::make_test_transaction_with_response;
        let tx = make_test_transaction_with_response(200, &[("set-cookie", value)]);
        let rule = MessageCookiePathValidity;
        rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
    }

    #[test]
    fn valid_paths_ok() {
        assert!(check_set_cookie("SID=1; Path=/").is_none());
        assert!(check_set_cookie("SID=1; Path=/login").is_none());
        assert!(check_set_cookie("SID=1; Path=/foo%20bar").is_none());
    }

    #[test]
    fn missing_value_reports() {
        let v = check_set_cookie("SID=1; Path");
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("requires a value"));
    }

    #[test]
    fn not_starting_with_slash_reports() {
        let v = check_set_cookie("SID=1; Path=login");
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("should start with '/'") || msg.contains("invalid"));
    }

    #[test]
    fn invalid_percent_encoding_reports() {
        let v = check_set_cookie("SID=1; Path=/%ZZ");
        assert!(v.is_some());
    }

    #[test]
    fn message_and_id() {
        let rule = MessageCookiePathValidity;
        assert_eq!(rule.id(), "message_cookie_path_validity");
    }

    #[test]
    fn scope_is_server() {
        let rule = MessageCookiePathValidity;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }

    #[test]
    fn incomplete_percent_encoding_reports() {
        let v = check_set_cookie("SID=1; Path=/%2");
        assert!(v.is_some());
    }

    #[test]
    fn path_with_space_reports() {
        let v = check_set_cookie("SID=1; Path=/has space");
        assert!(v.is_some());
    }

    #[test]
    fn empty_path_value_reports() {
        // Path= should be flagged as empty
        let v = check_set_cookie("SID=1; Path=");
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("empty") || msg.contains("invalid"));
    }

    #[test]
    fn non_utf8_set_cookie_value_reports() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        let bad = HeaderValue::from_bytes(&[0xff]).expect("should construct non-utf8 header");
        hm.insert("set-cookie", bad);
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,

            body_length: None,
            trailers: None,
        });

        let rule = MessageCookiePathValidity;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("not valid UTF-8"));
        Ok(())
    }

    #[test]
    fn multiple_set_cookie_headers_one_invalid_reports() {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        hm.append("set-cookie", HeaderValue::from_static("SID=1; Path=/"));
        hm.append("set-cookie", HeaderValue::from_static("SID=1; Path=login"));
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,

            body_length: None,
            trailers: None,
        });

        let rule = MessageCookiePathValidity;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
    }

    #[test]
    fn no_path_attribute_no_violation() {
        let v = check_set_cookie("SID=1; Secure");
        assert!(v.is_none());
    }

    #[test]
    fn cookie_pair_missing_is_ignored() {
        let v = check_set_cookie("; Secure");
        assert!(v.is_none());
    }

    #[test]
    fn trailing_empty_attribute_ignored() {
        let v = check_set_cookie("SID=1; ; Secure");
        assert!(v.is_none());
    }

    #[test]
    fn path_with_tab_reports() {
        let v = check_set_cookie("SID=1; Path=/has\tTab");
        assert!(v.is_some());
    }

    #[test]
    fn lowercase_path_is_accepted() {
        let v = check_set_cookie("SID=1; path=/lowercase");
        assert!(v.is_none());
    }

    #[test]
    fn spaces_around_equals_are_accepted() {
        let v = check_set_cookie("SID=1; Path = /login");
        assert!(v.is_none());
    }

    #[test]
    fn check_missing_response() {
        let tx = crate::test_helpers::make_test_transaction();
        let rule = MessageCookiePathValidity;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_cookie_path_validity");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
