// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::cookie::{
    path_defect, COOKIE_PATH_CONTROL_CHARACTER_FORBIDDEN, COOKIE_PATH_EMPTY,
    COOKIE_PATH_LEADING_SLASH_MISSING, COOKIE_PATH_MISSING,
    COOKIE_PATH_NON_ASCII_CHARACTER_FORBIDDEN, COOKIE_PATH_PERCENT_ENCODING_MALFORMED,
    COOKIE_PATH_WHITESPACE_INVALID, RFC_3986_2_1, RFC_6265_4_1_1, RFC_6265_5_2_4,
};
use crate::violations::ViolationDef;

pub struct CookiePathValid;

/// The defects this rule reports, in the order their severities resolve. A
/// named `static` because the engine finds a def in here by address, and an
/// array of references to statics is not const-promotable.
///
/// Their definitions — title, default severity, and the sentence each enforces
/// — are in `violations::cookie`, which is also where the `Path` half of this
/// rule's specification references now live: a defect belongs to the attribute
/// it is about, not to whichever rule noticed it.
static DECLARED: &[&ViolationDef] = &[
    &COOKIE_PATH_MISSING,
    &COOKIE_PATH_EMPTY,
    &COOKIE_PATH_LEADING_SLASH_MISSING,
    &COOKIE_PATH_PERCENT_ENCODING_MALFORMED,
    &COOKIE_PATH_NON_ASCII_CHARACTER_FORBIDDEN,
    &COOKIE_PATH_CONTROL_CHARACTER_FORBIDDEN,
    &COOKIE_PATH_WHITESPACE_INVALID,
];

/// The specification references this rule declares that no defect of its own
/// carries: the parsing algorithm the rule performs before any defect exists,
/// and the rationale for refusing whitespace the grammar admits.
/// `specifications()` below is these two plus the three the defects cite, so
/// the docs name every document the rule answers to.
const RFC_6265_5_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 6265",
    section: Some("5.2"),
    url: "https://www.rfc-editor.org/rfc/rfc6265.html#section-5.2",
    note: "The Set-Cookie header parsing algorithm — where the `;` split, the WSP trim and the case-insensitive `Path` match come from",
};
const RFC_9110_5_6_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("5.6.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.3",
    note: "Whitespace — rationale for being conservative about whitespace in header fields; this rule adopts a stricter profile by disallowing unencoded whitespace in cookie paths",
};

impl RuleMeta for CookiePathValid {
    fn id(&self) -> &'static str {
        "cookie_path_valid"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
severity = "warn"
"#
    }

    fn description(&self) -> &'static str {
        "Validate the `Path` attribute in `Set-Cookie` header fields. The `Path` attribute should be a valid RFC 6265 `path-value` that begins with `/`, does not contain control characters or `;`, and uses valid percent-encodings where applicable. Raw non-ASCII characters are rejected by this rule — non-ASCII data should be percent-encoded (see RFC 3986 §2.1). This rule is intentionally stricter than RFC 6265: it also rejects unencoded whitespace in the `Path` attribute (spaces should be sent as `%20`) to reduce ambiguity in cookie scope and avoid syntactic errors that can affect cookie delivery and security."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_3986_2_1,
            RFC_6265_4_1_1,
            RFC_6265_5_2,
            RFC_6265_5_2_4,
            RFC_9110_5_6_3,
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

impl Rule for CookiePathValid {
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

            for hv in resp.headers.get_all("set-cookie").iter() {
                let Ok(s) = hv.to_str() else {
                    return Some(self.violation(
                        ctx.severity,
                        "Set-Cookie header value is not valid UTF-8".into(),
                    ));
                };

                // Split into cookie-pair and attribute segments. The `;` and
                // the trim are § 5.2's own parsing algorithm, which is what
                // this rule enforces of its own accord — the defects it
                // reports are elsewhere, and so are their sentences.
                //
                // cite(RFC 6265 § 5.2): "Consume the characters of the unparsed-attributes up to, but not including, the first %x3B (";") character."
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

                    // cite(RFC 6265 § 5.2): "If the attribute-name case-insensitively matches the string "Path", the user agent MUST process the cookie-av as follows."
                    if key.eq_ignore_ascii_case("path") {
                        let v = match val_opt {
                            Some(v) => v,
                            None => return Some(ctx.report(&COOKIE_PATH_MISSING)),
                        };

                        if let Err(defect) = crate::helpers::cookie::validate_cookie_path(v) {
                            // The message stays here, where its argument is;
                            // which defect it is comes from the helper's own
                            // answer, named in `violations::cookie`.
                            return Some(ctx.report_with(
                                path_defect(&defect),
                                format!(
                                    "Set-Cookie attribute 'Path' invalid: {}",
                                    defect.message()
                                ),
                            ));
                        }
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
static REGISTRATION: &dyn crate::rules::Rule = &CookiePathValid;

#[cfg(test)]
mod tests {
    use super::*;

    fn check_set_cookie(value: &str) -> Option<Violation> {
        use crate::test_helpers::make_test_transaction_with_response;
        let tx = make_test_transaction_with_response(200, &[("set-cookie", value)]);
        let rule = CookiePathValid;
        crate::test_helpers::run_rule(
            &rule,
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

    /// The rule still reports through a message, so the message is asserted —
    /// but the defect underneath is now named, and that is what this checks.
    /// It read `contains("should start with '/'") || contains("invalid")`, an
    /// `||` that passed if *any* defect fired, including one about a control
    /// character. A `String` gave it nothing better to ask.
    #[test]
    fn not_starting_with_slash_reports() {
        use crate::helpers::cookie::{validate_cookie_path, CookiePathDefect};
        assert_eq!(
            validate_cookie_path("login"),
            Err(CookiePathDefect::NotAbsolute("login"))
        );

        let v = check_set_cookie("SID=1; Path=login");
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("should start with '/'"));
    }

    #[test]
    fn invalid_percent_encoding_reports() {
        let v = check_set_cookie("SID=1; Path=/%ZZ");
        assert!(v.is_some());
    }

    #[test]
    fn message_and_id() {
        let rule = CookiePathValid;
        assert_eq!(rule.id(), "cookie_path_valid");
    }

    /// One rule, one message shape, three different things said — which is
    /// what the catalogue buys. A control character in a cookie path is an
    /// error, a path the user agent will silently replace is a warning, and
    /// the whitespace this crate refuses past the grammar is information.
    /// None of the three was expressible while `severity` was the rule's.
    #[test]
    fn each_defect_reports_under_its_own_name_and_severity() {
        for (path, violation, severity) in [
            (
                "/has space",
                "cookie_path_whitespace_invalid",
                crate::lint::Severity::Info,
            ),
            (
                "login",
                "cookie_path_leading_slash_missing",
                crate::lint::Severity::Warn,
            ),
            // HTAB is a `CTL`, not this rule's stricter-than-grammar
            // whitespace — the helper's variants say so and the two defects
            // report at different levels because of it.
            (
                "/has\ttab",
                "cookie_path_control_character_forbidden",
                crate::lint::Severity::Error,
            ),
        ] {
            let v = check_set_cookie(&format!("SID=1; Path={path}"))
                .unwrap_or_else(|| panic!("{path} reports"));
            assert_eq!(v.rule, "cookie_path_valid");
            assert_eq!(v.violation, violation);
            assert_eq!(v.severity, severity);
        }
    }

    /// The defect an operator tunes is the defect, not the rule: raising the
    /// whitespace profile to `error` leaves everything else this rule reports
    /// where it was.
    #[test]
    fn tuning_one_defect_leaves_the_others() {
        let rule = CookiePathValid;
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        crate::test_helpers::override_violation_severity(
            &mut cfg,
            "cookie_path_whitespace_invalid",
            "error",
        );

        let run = |value: &str| {
            let tx = crate::test_helpers::make_test_transaction_with_response(
                200,
                &[("set-cookie", value)],
            );
            crate::test_helpers::run_rule(
                &rule,
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            )
            .expect("reports")
        };

        assert_eq!(
            run("SID=1; Path=/has space").severity,
            crate::lint::Severity::Error,
        );
        assert_eq!(
            run("SID=1; Path=login").severity,
            crate::lint::Severity::Warn,
        );
    }

    /// The three defects about a discarded value carry § 5.2.4, and the
    /// citation reaches the finding from the def — the rule site attaches
    /// none.
    #[test]
    fn a_discarded_path_cites_the_substitution() {
        let cite = check_set_cookie("SID=1; Path=login")
            .expect("reports")
            .cite
            .expect("cited from the def");
        assert_eq!(cite.spec, "RFC 6265");
        assert_eq!(cite.section.as_deref(), Some("5.2.4"));
    }

    #[test]
    fn scope_is_server() {
        let rule = CookiePathValid;
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

        let rule = CookiePathValid;
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

        let rule = CookiePathValid;
        let v = crate::test_helpers::run_rule(
            &rule,
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
        let rule = CookiePathValid;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "cookie_path_valid");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
