// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::cookie::DRAFT_IETF_HTTPBIS_RFC6265BIS;
use crate::violations::cookie::{
    COOKIE_DOMAIN_EMPTY, COOKIE_DOMAIN_MISSING, COOKIE_EXPIRES_MISSING, COOKIE_MAX_AGE_MALFORMED,
    COOKIE_MAX_AGE_MISSING, COOKIE_PATH_LEADING_SLASH_MISSING, COOKIE_PATH_MISSING,
    COOKIE_SAME_SITE_INVALID, COOKIE_SAME_SITE_MISSING, RFC_6265_4_1_1, RFC_6265_5_2_2,
    RFC_6265_5_2_3, RFC_6265_5_2_4,
};
use crate::violations::domain::{DOMAIN_NAME_WHITESPACE_OR_CONTROL_FORBIDDEN, RFC_1035_2_3_1};
use crate::violations::http_date::{HTTP_DATE_MALFORMED, RFC_9110_5_6_7};
use crate::violations::token::{
    token_character, RFC_9110_5_6_2, TOKEN_CHARACTER_FORBIDDEN, TOKEN_EMPTY,
    TOKEN_WHITESPACE_OR_CONTROL_FORBIDDEN,
};
use crate::violations::ViolationDef;

pub struct CookieAttributeConsistent;

/// What this rule reports that another reading already named.
///
/// Three imports, each for a different reason. `sane-cookie-date` is RFC
/// 6265's name for the timestamp RFC 9110 § 5.6.7 writes, so an `Expires` a
/// recipient cannot read is the same defect a `Date` or a `Sunset` a recipient
/// cannot read is. `cookie-name = token` imports the HTTP production by name,
/// so a name that is empty or holds a delimiter answers to `token` — the
/// alphabets are not merely similar, they are the same set. And `Path` and
/// `Domain` were read out by `cookie_path_valid` and `cookie_domain_valid`
/// first: this rule asks a coarser question of the same two attributes, so it
/// reports what they report rather than a second name for it.
///
/// What is left in the rule's own words is the shape of the field line and the
/// attributes nothing else reads — `SameSite`, `Max-Age`, the two flags, and
/// the pairing that makes a `SameSite=None` cookie disappear.
static DECLARED: &[&ViolationDef] = &[
    &HTTP_DATE_MALFORMED,
    &COOKIE_SAME_SITE_MISSING,
    &COOKIE_SAME_SITE_INVALID,
    &COOKIE_MAX_AGE_MISSING,
    &COOKIE_MAX_AGE_MALFORMED,
    &COOKIE_EXPIRES_MISSING,
    &TOKEN_EMPTY,
    &TOKEN_CHARACTER_FORBIDDEN,
    &TOKEN_WHITESPACE_OR_CONTROL_FORBIDDEN,
    &COOKIE_PATH_MISSING,
    &COOKIE_PATH_LEADING_SLASH_MISSING,
    &COOKIE_DOMAIN_MISSING,
    &COOKIE_DOMAIN_EMPTY,
    &DOMAIN_NAME_WHITESPACE_OR_CONTROL_FORBIDDEN,
];

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const MDN_SET_COOKIE: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "MDN Set-Cookie",
    section: None,
    url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie",
    note: "SameSite cookies (SameSite=None should be Secure) — browser compatibility guidance on `SameSite` usage",
};

impl CookieAttributeConsistent {
    /// The first defect in one `Set-Cookie` field line, if it has one.
    ///
    /// The line is a cookie-pair and then attributes, and those are two
    /// different grammars: the pair is judged here, each attribute by
    /// [`Self::attribute_defect`], and the one question that needs both — a
    /// `SameSite=None` cookie that is not `Secure` — after the walk.
    fn set_cookie_defect(
        &self,
        line: &str,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Option<Violation> {
        // The unconverted branches read the rule's own severity, exactly as
        // they did before the context was threaded through.
        let severity = ctx.severity;
        let (pair, attributes) = crate::helpers::cookie::split_set_cookie(line);
        if pair.is_empty() {
            return Some(self.violation(severity, "Set-Cookie header missing cookie-pair".into()));
        }

        // The name is a `token` by import rather than by resemblance -- § 4.1.1
        // writes `cookie-name = token` and takes the production from the HTTP
        // document -- so both of its defects are that production's.
        // cite(RFC 6265 § 4.1.1): "cookie-pair       = cookie-name "=" cookie-value cookie-name       = token"
        let name = pair.split('=').next().unwrap_or("").trim();
        if name.is_empty() {
            return Some(ctx.report_with(&TOKEN_EMPTY, "Set-Cookie cookie name is empty".into()));
        }
        if let Some(c) = crate::helpers::token::find_invalid_token_char(name) {
            return Some(ctx.report_with(
                token_character(c),
                format!("Set-Cookie cookie-name contains invalid character: '{}'", c),
            ));
        }

        let mut secure_present = false;
        let mut same_site: Option<String> = None;
        for attribute in attributes {
            if let Some(defect) = self.attribute_defect(&attribute, ctx) {
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
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Option<Violation> {
        let severity = ctx.severity;
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
                return Some(ctx.report(&COOKIE_SAME_SITE_MISSING));
            };
            let known = ["strict", "lax", "none"]
                .iter()
                .any(|known| value.eq_ignore_ascii_case(known));
            return (!known).then(|| {
                ctx.report_with(
                    &COOKIE_SAME_SITE_INVALID,
                    format!(
                        "Set-Cookie attribute 'SameSite' has invalid value: '{}'",
                        value
                    ),
                )
            });
        }

        if attribute.is("Max-Age") {
            let Some(value) = attribute.value else {
                return Some(ctx.report(&COOKIE_MAX_AGE_MISSING));
            };
            // A leading "-" is accepted on purpose: the ABNF says non-zero-digit
            // *DIGIT, but the parsing algorithm the ABNF is a summary of admits a
            // sign, and a negative Max-Age is how a cookie is deleted.
            // `parse::<i64>` enforces both of §5.2.2's processing gates: a
            // valid first character *and* an all-DIGIT remainder.
            // cite(RFC 6265 § 5.2.2): "If the first character of the attribute-value is not a DIGIT or a "-" character, ignore the cookie-av."
            return value.parse::<i64>().is_err().then(|| {
                ctx.report_with(
                    &COOKIE_MAX_AGE_MALFORMED,
                    format!(
                        "Set-Cookie attribute 'Max-Age' is not a valid integer: '{}'",
                        value
                    ),
                )
            });
        }

        if attribute.is("Expires") {
            let Some(value) = attribute.value else {
                return Some(ctx.report(&COOKIE_EXPIRES_MISSING));
            };
            // `sane-cookie-date` is the timestamp § 5.6.7 writes, under RFC
            // 6265's name for it, so what is wrong with an unreadable `Expires`
            // is not a fact about cookies. This is the recipient's parse — the
            // one § 5.6.7 obliges every reader to perform — so a failure means
            // the attribute names no instant at all.
            // cite(RFC 6265 § 4.1.1): "expires-av        = "Expires=" sane-cookie-date"
            return (!crate::http_date::is_valid_http_date(value)).then(|| {
                ctx.report_with(
                    &HTTP_DATE_MALFORMED,
                    format!(
                        "Set-Cookie attribute 'Expires' is not a valid HTTP-date: '{}'",
                        value
                    ),
                )
            });
        }

        // `Path` and `Domain` are read here as far as their presence and their
        // first character, and in full by `cookie_path_valid` and
        // `cookie_domain_valid`. The coarser reading reports the same ids: what
        // an operator silences is the defect, not which of the two rules noticed
        // it first.
        if attribute.is("Path") {
            let Some(value) = attribute.value else {
                return Some(ctx.report(&COOKIE_PATH_MISSING));
            };
            return (!value.starts_with('/')).then(|| {
                ctx.report_with(
                    &COOKIE_PATH_LEADING_SLASH_MISSING,
                    format!(
                        "Set-Cookie attribute 'Path' should start with '/': '{}'",
                        value
                    ),
                )
            });
        }

        if attribute.is("Domain") {
            let Some(value) = attribute.value else {
                return Some(ctx.report(&COOKIE_DOMAIN_MISSING));
            };
            if value.is_empty() {
                return Some(ctx.report_with(
                    &COOKIE_DOMAIN_EMPTY,
                    "Set-Cookie attribute 'Domain' must not be empty".into(),
                ));
            }
            // A space inside a host name is the *name's* defect and not the
            // attribute's: the same octet in a `Host`, a `Forwarded` host or a
            // `From` mailbox reports under this id already.
            return value.contains(' ').then(|| {
                ctx.report_with(
                    &DOMAIN_NAME_WHITESPACE_OR_CONTROL_FORBIDDEN,
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

    fn config_example(&self) -> &'static str {
        r#"enabled = true
severity = "warn"
"#
    }

    fn description(&self) -> &'static str {
        "Validate `Set-Cookie` attributes for syntactic correctness and common security consistency rules. This rule parses `Set-Cookie` header values and flags:\n\n- Invalid cookie-name tokens.\n- Malformed attributes (e.g., `Max-Age` non-numeric, `Expires` not an HTTP-date).\n- `Path` values that don't start with `/`.\n- `Domain` values that are empty or contain spaces.\n- `SameSite` values other than `Strict`, `Lax`, or `None`.\n- `SameSite=None` cookies that are not marked `Secure` (browser behaviour / compatibility requirement).\n- `Secure` and `HttpOnly` attributes that incorrectly include a value (they must be flags)."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_6265_4_1_1,
            RFC_6265_5_2_2,
            RFC_6265_5_2_3,
            RFC_6265_5_2_4,
            DRAFT_IETF_HTTPBIS_RFC6265BIS,
            MDN_SET_COOKIE,
            RFC_9110_5_6_7,
            RFC_9110_5_6_2,
            RFC_1035_2_3_1,
        ]
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
                // Read as octets, one field line at a time: `Set-Cookie` is
                // not a list, and § 4.1.1's grammar stops at `CHAR`, so an
                // octet above %x7F is the attribute reader's finding rather
                // than a verdict about the field's encoding.
                .find_map(|line| {
                    self.set_cookie_defect(
                        &crate::helpers::headers::field_line_as_written(line),
                        ctx,
                    )
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
    fn an_obs_text_octet_is_read_where_it_lands() -> anyhow::Result<()> {
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

        // A field line holding an octet above %x7F
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
        // The octet is in the cookie-name, and that is what the finding says
        // now: § 4.1.1 writes the name as a `token`, so an octet above %x7F is
        // a character it does not admit. The verdict this replaces named the
        // field's encoding and stopped before the name was read.
        let v = v.expect("a finding");
        assert_eq!(
            v.message,
            "Set-Cookie cookie-name contains invalid character: '\u{ff}'"
        );
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
