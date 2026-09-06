// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::cookie::{
    domain_defect, COOKIE_DOMAIN_EMPTY, COOKIE_DOMAIN_IPV4_ADDRESS_FORBIDDEN,
    COOKIE_DOMAIN_IPV6_LITERAL_FORBIDDEN, COOKIE_DOMAIN_LEADING_DOT_OBSOLETE,
    COOKIE_DOMAIN_MISSING, RFC_6265_5_1_3, RFC_6265_5_2_3,
};
use crate::violations::domain::{
    DOMAIN_LABEL_CHARACTER_FORBIDDEN, DOMAIN_LABEL_EDGE_HYPHEN_FORBIDDEN, DOMAIN_LABEL_EMPTY,
    DOMAIN_LABEL_LENGTH_INVALID, DOMAIN_NAME_CHARACTER_FORBIDDEN, DOMAIN_NAME_LENGTH_INVALID,
    RFC_1035_2_3_1, RFC_1035_2_3_4,
};
use crate::violations::ViolationDef;

pub struct CookieDomainValid;

/// The defects this rule reports. Six of the eleven are not its own: a domain
/// name is answered by the same sentences wherever a field carries one, so
/// `domain_*` is what a `From` mailbox's host half will report too. Declaring
/// them here is what says this rule may report them; it does not own them.
static DECLARED: &[&ViolationDef] = &[
    &COOKIE_DOMAIN_MISSING,
    &COOKIE_DOMAIN_EMPTY,
    &COOKIE_DOMAIN_LEADING_DOT_OBSOLETE,
    &COOKIE_DOMAIN_IPV4_ADDRESS_FORBIDDEN,
    &COOKIE_DOMAIN_IPV6_LITERAL_FORBIDDEN,
    &DOMAIN_NAME_LENGTH_INVALID,
    &DOMAIN_NAME_CHARACTER_FORBIDDEN,
    &DOMAIN_LABEL_EMPTY,
    &DOMAIN_LABEL_LENGTH_INVALID,
    &DOMAIN_LABEL_EDGE_HYPHEN_FORBIDDEN,
    &DOMAIN_LABEL_CHARACTER_FORBIDDEN,
];

impl RuleMeta for CookieDomainValid {
    fn id(&self) -> &'static str {
        "cookie_domain_valid"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
severity = "warn"
"#
    }

    fn description(&self) -> &'static str {
        "Validate the `Domain` attribute of `Set-Cookie` header values. This rule checks that\n`Domain` values are syntactically valid domain names (no spaces, valid label characters,\nlabel length and overall length limits) and flags uses that are likely incorrect, such as\nIP addresses or empty values. A leading `.` is tolerated for historical reasons but is\nreported as deprecated."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_1035_2_3_1,
            RFC_1035_2_3_4,
            RFC_6265_5_1_3,
            RFC_6265_5_2_3,
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
                snippet: "Set-Cookie: SID=1; Domain=example.com",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(attribute order tolerated)"),
                snippet: "Set-Cookie: SID=1; Secure; Domain=example.com",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— IP address used as Domain"),
                snippet: "Set-Cookie: SID=1; Domain=192.168.0.1",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— invalid characters in domain"),
                snippet: "Set-Cookie: SID=1; Domain=exa_mple.com",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— empty domain value"),
                snippet: "Set-Cookie: SID=1; Domain=",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— leading dot is deprecated (this rule reports it)"),
                snippet: "Set-Cookie: SID=1; Domain=.example.com",
            },
        ]
    }
}

impl Rule for CookieDomainValid {
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

                // Split into cookie-pair and attributes — § 5.2's own parsing
                // algorithm, which is the reading this rule does before any
                // defect exists. The defects' sentences are on their defs.
                //
                // cite(RFC 6265 § 5.2): "Consume the characters of the unparsed-attributes up to, but not including, the first %x3B (";") character."
                let parts = s.split(';').map(|p| p.trim()).collect::<Vec<_>>();
                for attr in parts.iter().skip(1) {
                    if attr.is_empty() {
                        continue;
                    }
                    let mut av = attr.splitn(2, '=');
                    let key = av.next().unwrap().trim();
                    let val = av.next().map(|v| v.trim()).unwrap_or("");
                    // cite(RFC 6265 § 5.2.3): "If the attribute-name case-insensitively matches the string "Domain", the user agent MUST process the cookie-av as follows."
                    if key.eq_ignore_ascii_case("domain") {
                        if val.is_empty() {
                            return Some(ctx.report(&COOKIE_DOMAIN_MISSING));
                        }
                        match crate::helpers::domain::validate_cookie_domain(val) {
                            Ok(()) => {
                                if val.starts_with('.') {
                                    return Some(ctx.report(&COOKIE_DOMAIN_LEADING_DOT_OBSOLETE));
                                }
                            }
                            Err(e) => {
                                return Some(ctx.report_with(
                                    domain_defect(e),
                                    format!(
                                        "Invalid Set-Cookie Domain attribute '{}': {}",
                                        val,
                                        e.message()
                                    ),
                                ));
                            }
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
static REGISTRATION: &dyn crate::rules::Rule = &CookieDomainValid;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn check_set_cookie(value: &str) -> Option<Violation> {
        use crate::test_helpers::make_test_transaction_with_response;
        let tx = make_test_transaction_with_response(200, &[("set-cookie", value)]);
        let rule = CookieDomainValid;
        crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
    }

    #[rstest]
    #[case("SID=1; Domain=example.com", false)]
    #[case("SID=1; Domain=.example.com", true)] // leading dot => warn
    #[case("SID=1; Domain=", true)]
    #[case("SID=1; Domain=192.168.0.1", true)]
    #[case("SID=1; Domain=exa_mple.com", true)]
    #[case("SID=1; Domain=example..com", true)]
    fn domain_cases(#[case] cookie: &str, #[case] expect_violation: bool) {
        let v = check_set_cookie(cookie);
        if expect_violation {
            assert!(v.is_some(), "expected violation for '{}', got none", cookie);
        } else {
            assert!(
                v.is_none(),
                "unexpected violation for '{}': {:?}",
                cookie,
                v
            );
        }
    }

    /// The same rule, five names. The last two are the interesting pair: an
    /// underscore and a doubled dot are defects of *domain names*, not of
    /// cookies, so they report under the shared `domain_*` ids that any other
    /// field carrying a name will report under too.
    #[rstest]
    #[case("SID=1; Domain=", "cookie_domain_missing", crate::lint::Severity::Warn)]
    #[case(
        "SID=1; Domain=.example.com",
        "cookie_domain_leading_dot_obsolete",
        crate::lint::Severity::Info
    )]
    #[case(
        "SID=1; Domain=192.168.0.1",
        "cookie_domain_ipv4_address_forbidden",
        crate::lint::Severity::Warn
    )]
    #[case(
        "SID=1; Domain=exa_mple.com",
        "domain_label_character_forbidden",
        crate::lint::Severity::Warn
    )]
    #[case(
        "SID=1; Domain=example..com",
        "domain_label_empty",
        crate::lint::Severity::Warn
    )]
    fn each_defect_reports_under_its_own_name(
        #[case] cookie: &str,
        #[case] violation: &str,
        #[case] severity: crate::lint::Severity,
    ) {
        let v = check_set_cookie(cookie).expect("reports");
        assert_eq!(v.rule, "cookie_domain_valid");
        assert_eq!(v.violation, violation);
        assert_eq!(v.severity, severity);
    }

    /// The leading dot costs nothing at run time and is `info` because of it —
    /// so a report filtered to warnings and above does not carry it, while the
    /// same rule's IP-address finding still does. One rule, two audiences.
    #[test]
    fn the_obsolete_form_is_below_the_defects_that_break_something() {
        let dot = check_set_cookie("SID=1; Domain=.example.com").expect("reports");
        let ip = check_set_cookie("SID=1; Domain=192.168.0.1").expect("reports");
        assert!(dot.severity < crate::lint::Severity::Warn);
        assert!(ip.severity >= crate::lint::Severity::Warn);
    }

    #[test]
    fn multiple_set_cookie_headers_one_invalid_reports_violation() {
        use crate::test_helpers::make_test_transaction;
        use hyper::header::HeaderValue;

        let mut tx = make_test_transaction();
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[(
            "set-cookie",
            "SID=1; Domain=example.com",
        )]);
        hm.append(
            "set-cookie",
            HeaderValue::from_static("SID=2; Domain=192.168.0.1"),
        );
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,

            body_length: None,
            trailers: None,
        });

        let rule = CookieDomainValid;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
    }

    #[test]
    fn leading_dot_reports_deprecation_message() {
        let v = check_set_cookie("SID=1; Domain=.example.com");
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("deprecated") || msg.contains("leading '.'"));
    }

    #[test]
    fn attribute_order_and_spacing_are_tolerated() {
        // Domain not first and spaces around '='
        let v = check_set_cookie("SID=1; Secure; Domain = example.com");
        assert!(v.is_none(), "unexpected violation: {:?}", v);
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

        let rule = CookieDomainValid;
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
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "cookie_domain_valid");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
