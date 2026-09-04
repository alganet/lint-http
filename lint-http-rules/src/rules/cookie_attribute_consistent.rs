// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};

pub struct CookieAttributeConsistent;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_6265_4_1_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 6265",
    section: Some("4.1.1"),
    url: "https://www.rfc-editor.org/rfc/rfc6265.html#section-4.1.1",
    note:
        "Set-Cookie syntax — the cookie-name/`Secure`/`HttpOnly`/`Expires` grammar this rule checks",
};
const RFC_6265_5_2_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 6265",
    section: Some("5.2.2"),
    url: "https://www.rfc-editor.org/rfc/rfc6265.html#section-5.2.2",
    note: "The Max-Age attribute — ignored unless it is a `-`-or-DIGIT first character with an all-DIGIT remainder",
};
const DRAFT_IETF_HTTPBIS_RFC6265BIS: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "draft-ietf-httpbis-rfc6265bis",
    section: None,
    url: "https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis",
    note: "`SameSite` value grammar and the `SameSite=None` requires `Secure` rule. No section: a draft renumbers between revisions",
};
const MDN_SET_COOKIE: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "MDN Set-Cookie",
    section: None,
    url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie",
    note: "SameSite cookies (SameSite=None should be Secure) — browser compatibility guidance on `SameSite` usage",
};
const RFC_9110_5_6_7: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("5.6.7"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.7",
    note: "HTTP-date (IMF-fixdate) — used for the `Expires` attribute",
};

impl CookieAttributeConsistent {
    /// The first defect in one `Set-Cookie` field line, if it has one.
    ///
    /// The line is a cookie-pair and then attributes, and those are two
    /// different grammars: the pair is judged here, each attribute by
    /// [`Self::attribute_defect`], and the one question that needs both — a
    /// `SameSite=None` cookie that is not `Secure` — after the walk.
    fn set_cookie_defect(&self, line: &str, severity: crate::lint::Severity) -> Option<Violation> {
        let (pair, attributes) = crate::helpers::cookie::split_set_cookie(line);
        if pair.is_empty() {
            return Some(self.violation(severity, "Set-Cookie header missing cookie-pair".into()));
        }

        let name = pair.split('=').next().unwrap_or("").trim();
        if name.is_empty() {
            return Some(self.violation(severity, "Set-Cookie cookie name is empty".into()));
        }
        // cite(RFC 6265 § 4.1.1): "cookie-pair       = cookie-name "=" cookie-value cookie-name       = token"
        if let Some(c) = crate::helpers::token::find_invalid_token_char(name) {
            return Some(self.cited(
                &RFC_6265_4_1_1,
                severity,
                format!("Set-Cookie cookie-name contains invalid character: '{}'", c),
            ));
        }

        let mut secure_present = false;
        let mut same_site: Option<String> = None;
        for attribute in attributes {
            if let Some(defect) = self.attribute_defect(&attribute, severity) {
                return Some(defect);
            }
            // Past the defect check the values are known good, so what is
            // recorded here is what the sender successfully asked for.
            if attribute.is("secure") {
                secure_present = true;
            } else if attribute.is("samesite") {
                same_site = attribute.value.map(|v| v.to_ascii_lowercase());
            }
        }

        // `SameSite=None` without `Secure` is not a cookie with a weaker policy — it is
        // a cookie the user agent throws away. That is why this is a violation and not
        // a suggestion.
        // cite(draft-ietf-httpbis-rfc6265bis § 5.7): "If the cookie's "same-site-flag" is "None", abort this algorithm and ignore the cookie entirely unless the cookie's secure-only-flag is true."
        if same_site.as_deref() == Some("none") && !secure_present {
            return Some(self.violation(
                severity,
                "Set-Cookie with 'SameSite=None' must also set 'Secure'".into(),
            ));
        }
        None
    }

    /// What is wrong with one `cookie-av`, if anything.
    ///
    /// An attribute this rule does not know is not a defect: the grammar ends
    /// in `extension-av`, and a user agent ignores what it does not recognise.
    // cite(RFC 6265 § 4.1.1): "extension-av      = <any CHAR except CTLs or ";">"
    fn attribute_defect(
        &self,
        attribute: &crate::helpers::cookie::Attribute<'_>,
        severity: crate::lint::Severity,
    ) -> Option<Violation> {
        // The two flag attributes: the grammar admits no "=", so the attribute
        // is its own presence and a value written after it is a defect.
        // cite(RFC 6265 § 4.1.1): "secure-av         = "Secure""
        // cite(RFC 6265 § 4.1.1): "httponly-av       = "HttpOnly""
        for flag in ["Secure", "HttpOnly"] {
            if attribute.is(flag) {
                return attribute.has_value().then(|| {
                    self.cited(
                        &RFC_6265_4_1_1,
                        severity,
                        format!("Set-Cookie attribute '{}' must not have a value", flag),
                    )
                });
            }
        }

        if attribute.is("SameSite") {
            let Some(value) = attribute.value else {
                return Some(self.violation(
                    severity,
                    "Set-Cookie attribute 'SameSite' requires a value".into(),
                ));
            };
            // cite(draft-ietf-httpbis-rfc6265bis § 4.1.1): "samesite-value = "Strict" / "Lax" / "None""
            let known = ["strict", "lax", "none"]
                .iter()
                .any(|known| value.eq_ignore_ascii_case(known));
            return (!known).then(|| {
                self.violation(
                    severity,
                    format!(
                        "Set-Cookie attribute 'SameSite' has invalid value: '{}'",
                        value
                    ),
                )
            });
        }

        if attribute.is("Max-Age") {
            let Some(value) = attribute.value else {
                return Some(self.violation(
                    severity,
                    "Set-Cookie attribute 'Max-Age' requires a numeric value".into(),
                ));
            };
            // A leading "-" is accepted on purpose: the ABNF says non-zero-digit
            // *DIGIT, but the parsing algorithm the ABNF is a summary of admits a
            // sign, and a negative Max-Age is how a cookie is deleted.
            // `parse::<i64>` enforces both of §5.2.2's processing gates: a
            // valid first character *and* an all-DIGIT remainder.
            // cite(RFC 6265 § 5.2.2): "If the first character of the attribute-value is not a DIGIT or a "-" character, ignore the cookie-av."
            // cite(RFC 6265 § 5.2.2): "If the remainder of attribute-value contains a non-DIGIT character, ignore the cookie-av."
            return value.parse::<i64>().is_err().then(|| {
                self.cited(
                    &RFC_6265_5_2_2,
                    severity,
                    format!(
                        "Set-Cookie attribute 'Max-Age' is not a valid integer: '{}'",
                        value
                    ),
                )
            });
        }

        if attribute.is("Expires") {
            let Some(value) = attribute.value else {
                return Some(self.violation(
                    severity,
                    "Set-Cookie attribute 'Expires' requires a HTTP-date value".into(),
                ));
            };
            // cite(RFC 6265 § 4.1.1): "expires-av        = "Expires=" sane-cookie-date"
            return (!crate::http_date::is_valid_http_date(value)).then(|| {
                self.cited(
                    &RFC_6265_4_1_1,
                    severity,
                    format!(
                        "Set-Cookie attribute 'Expires' is not a valid HTTP-date: '{}'",
                        value
                    ),
                )
            });
        }

        if attribute.is("Path") {
            let Some(value) = attribute.value else {
                return Some(self.violation(
                    severity,
                    "Set-Cookie attribute 'Path' requires a value".into(),
                ));
            };
            return (!value.starts_with('/')).then(|| {
                self.violation(
                    severity,
                    format!(
                        "Set-Cookie attribute 'Path' should start with '/': '{}'",
                        value
                    ),
                )
            });
        }

        if attribute.is("Domain") {
            let Some(value) = attribute.value else {
                return Some(self.violation(
                    severity,
                    "Set-Cookie attribute 'Domain' requires a value".into(),
                ));
            };
            if value.is_empty() {
                return Some(self.violation(
                    severity,
                    "Set-Cookie attribute 'Domain' must not be empty".into(),
                ));
            }
            return value.contains(' ').then(|| {
                self.violation(
                    severity,
                    format!(
                        "Set-Cookie attribute 'Domain' must not contain spaces: '{}'",
                        value
                    ),
                )
            });
        }

        None
    }
}

impl RuleMeta for CookieAttributeConsistent {
    fn id(&self) -> &'static str {
        "cookie_attribute_consistent"
    }

    fn description(&self) -> &'static str {
        "Validate `Set-Cookie` attributes for syntactic correctness and common security consistency rules. This rule parses `Set-Cookie` header values and flags:\n\n- Invalid cookie-name tokens.\n- Malformed attributes (e.g., `Max-Age` non-numeric, `Expires` not an HTTP-date).\n- `Path` values that don't start with `/`.\n- `Domain` values that are empty or contain spaces.\n- `SameSite` values other than `Strict`, `Lax`, or `None`.\n- `SameSite=None` cookies that are not marked `Secure` (browser behaviour / compatibility requirement).\n- `Secure` and `HttpOnly` attributes that incorrectly include a value (they must be flags)."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_6265_4_1_1,
            RFC_6265_5_2_2,
            DRAFT_IETF_HTTPBIS_RFC6265BIS,
            MDN_SET_COOKIE,
            RFC_9110_5_6_7,
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet:
                    "Set-Cookie: SID=31d4d96e407aad42; Secure; HttpOnly; Path=/; SameSite=None",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "Set-Cookie: sid=abcd; Path=/login; HttpOnly",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— SameSite=None must be Secure"),
                snippet: "Set-Cookie: id=1; SameSite=None",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— Max-Age must be numeric"),
                snippet: "Set-Cookie: SID=1; Max-Age=abc",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— Expires must be a valid HTTP-date"),
                snippet: "Set-Cookie: SID=1; Expires=NotADate",
            },
        ]
    }
}

impl Rule for CookieAttributeConsistent {
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
            let resp = tx.response.as_ref()?;
            resp.headers
                .get_all("set-cookie")
                .iter()
                .find_map(|line| match line.to_str() {
                    Err(_) => Some(self.violation(
                        ctx.severity,
                        "Set-Cookie header value is not valid UTF-8".into(),
                    )),
                    Ok(line) => self.set_cookie_defect(line, ctx.severity),
                })
        };
        Vec::from_iter(finding())
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &CookieAttributeConsistent;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn check_set_cookie(value: &str) -> Option<Violation> {
        use crate::test_helpers::make_test_transaction_with_response;
        let tx = make_test_transaction_with_response(200, &[("set-cookie", value)]);
        let rule = CookieAttributeConsistent;
        crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
    }

    #[rstest]
    #[case("SID=31d4d96e407aad42; Secure; HttpOnly; Path=/; SameSite=None", false)]
    #[case("sid=abcd; Path=/login; HttpOnly", false)]
    #[case("id=1; SameSite=Strict; Secure", false)]
    #[case("id=1; SameSite=None", true)]
    #[case("id=1; SameSite=none", true)]
    #[case("id=1; SameSite=Weird", true)]
    #[case("=bad; Secure", true)]
    #[case("SID=1; Max-Age=abc", true)]
    #[case("SID=1; Max-Age=10", false)]
    #[case("SID=1; Expires=NotADate", true)]
    #[case("SID=1; Expires=Wed, 21 Oct 2015 07:28:00 GMT", false)]
    #[case("SID=1; Path=login", true)]
    #[case("SID=1; Path", true)]
    #[case("SID=1; Domain=bad host", true)]
    #[case("SID=1; Domain", true)]
    #[case("SID=1; Secure=1", true)]
    #[case("SID=1; HttpOnly=1", true)]
    #[case("SID=1; SameSite", true)]
    #[case("SID", false)]
    #[case("", true)]
    fn set_cookie_cases(#[case] value: &str, #[case] expect_violation: bool) {
        let v = check_set_cookie(value);
        if expect_violation {
            assert!(v.is_some(), "expected violation for '{}', got none", value);
        } else {
            assert!(v.is_none(), "unexpected violation for '{}': {:?}", value, v);
        }
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let rule = CookieAttributeConsistent;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("severity".to_string(), toml::Value::String("error".into()));
        cfg.rules.insert(
            "cookie_attribute_consistent".into(),
            toml::Value::Table(table),
        );

        // validate should succeed without error
        rule.prepare(&cfg)?;
        Ok(())
    }

    #[test]
    fn non_utf8_set_cookie_is_reported() -> anyhow::Result<()> {
        use crate::http_transaction::ResponseInfo;
        use crate::test_helpers::make_test_transaction;
        use hyper::header::HeaderValue;

        let mut tx = make_test_transaction();
        tx.response = Some(ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hyper::HeaderMap::new(),

            body_length: None,
            trailers: None,
        });

        // Append a non-UTF8 header value
        tx.response
            .as_mut()
            .unwrap()
            .headers
            .append("set-cookie", HeaderValue::from_bytes(&[0xff])?);

        let rule = CookieAttributeConsistent;
        let v = crate::test_helpers::run_rule(
            &rule,
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
    fn invalid_cookie_name_token_reports_char() {
        // Name containing invalid token character '@' should be reported
        let v = check_set_cookie("N@ME=1; Secure");
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("invalid character") && msg.contains("@"));
    }

    #[test]
    fn unknown_attribute_is_ignored() {
        // Unknown attribute 'Foo=bar' should not cause a violation
        let v = check_set_cookie("id=1; Foo=bar");
        assert!(v.is_none());
    }

    #[test]
    fn trailing_empty_attribute_ignored_and_path_ok() {
        // Trailing empty attribute should be skipped; Path value trimmed and checked
        let v = check_set_cookie("SID=1; ; Path= /home ");
        assert!(v.is_none());
    }

    #[test]
    fn secure_with_empty_value_is_accepted_but_secure_with_value_reports() {
        // Secure= (empty) is accepted by current implementation
        let v_ok = check_set_cookie("SID=1; Secure=");
        assert!(v_ok.is_none());

        // Secure=1 with a value is a violation (already covered in parametrized cases)
        let v_bad = check_set_cookie("SID=1; Secure=1");
        assert!(v_bad.is_some());
    }

    #[test]
    fn cookie_value_with_equals_is_valid() {
        // Cookie value containing '=' characters should be accepted
        let v = check_set_cookie("SID=abc=def; Path=/");
        assert!(v.is_none());
    }

    #[test]
    fn multiple_set_cookie_headers_one_invalid_reports_violation() -> anyhow::Result<()> {
        use crate::http_transaction::ResponseInfo;
        use crate::test_helpers::make_test_transaction;
        use hyper::header::HeaderValue;

        let mut tx = make_test_transaction();
        tx.response = Some(ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hyper::HeaderMap::new(),

            body_length: None,
            trailers: None,
        });

        // Append a valid and an invalid Set-Cookie header
        tx.response
            .as_mut()
            .unwrap()
            .headers
            .append("set-cookie", HeaderValue::from_static("SID=1; Path=/"));
        tx.response
            .as_mut()
            .unwrap()
            .headers
            .append("set-cookie", HeaderValue::from_static("=bad; Secure"));

        let rule = CookieAttributeConsistent;
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
    fn samesite_requires_value_reports_message() {
        let v = check_set_cookie("SID=1; SameSite");
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("requires a value"));
    }

    #[test]
    fn lone_semicolon_is_missing_cookie_pair() {
        let v = check_set_cookie("; Secure");
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("missing cookie-pair"));
    }

    #[test]
    fn domain_empty_reports_violation() {
        let v = check_set_cookie("SID=1; Domain=");
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("must not be empty"));
    }

    #[test]
    fn max_age_negative_is_accepted() {
        let v = check_set_cookie("SID=1; Max-Age=-10");
        assert!(v.is_none());
    }
}
