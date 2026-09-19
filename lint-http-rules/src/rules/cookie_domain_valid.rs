// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::cookie::{
    domain_defect, COOKIE_DOMAIN_EMPTY, COOKIE_DOMAIN_IPV4_ADDRESS_FORBIDDEN,
    COOKIE_DOMAIN_IPV6_LITERAL_FORBIDDEN, COOKIE_DOMAIN_LEADING_DOT_OBSOLETE,
    COOKIE_DOMAIN_MISSING, COOKIE_DOMAIN_MISSING_WORDING, RFC_6265_5_1_3, RFC_6265_5_2_3,
};
use crate::violations::domain::{
    DOMAIN_LABEL_CHARACTER_FORBIDDEN, DOMAIN_LABEL_EDGE_HYPHEN_FORBIDDEN, DOMAIN_LABEL_EMPTY,
    DOMAIN_LABEL_LENGTH_INVALID, DOMAIN_NAME_LENGTH_INVALID,
    DOMAIN_NAME_WHITESPACE_OR_CONTROL_FORBIDDEN, RFC_1035_2_3_1, RFC_1035_2_3_4,
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
    &DOMAIN_NAME_WHITESPACE_OR_CONTROL_FORBIDDEN,
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

    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::Presumed(crate::lint::Party::Server)
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
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— two cookies, two findings, each naming its own"),
                snippet:
                    "Set-Cookie: a=1; Domain=.example.com\nSet-Cookie: b=2; Domain=192.168.0.1",
            },
        ]
    }
}

impl Rule for CookieDomainValid {
    fn needs_response(&self) -> bool {
        true
    }

    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        let Some(resp) = tx.response.as_ref() else {
            return Vec::new();
        };
        // One finding per cookie, not one per response. A response setting ten
        // cookies is answering this rule's question ten times, and a walk that
        // stopped at the first bad `Domain` told an operator about one of them
        // -- with a sentence that could not say which, since a `Set-Cookie`
        // line is identified by the cookie-name it opens with and nothing here
        // was reading it.
        resp.headers
            .get_all("set-cookie")
            .iter()
            .filter_map(|hv| {
                // Read as octets, one field line at a time. `Set-Cookie` is
                // not a list -- § 5.3's recombination does not apply to it, so
                // the lines are never joined -- and § 4.1.1's grammar stops at
                // `CHAR`, %x01-7F, so an octet above that is a character the
                // production does not admit rather than a verdict about the
                // field's encoding. The readers below have an entry for it.
                self.line_defect(
                    crate::helpers::headers::field_line_as_written(hv).as_str(),
                    ctx,
                )
            })
            .collect()
    }
}

impl CookieDomainValid {
    /// What is wrong with the `Domain` of one cookie, if anything.
    fn line_defect(&self, s: &str, ctx: &crate::rules::RuleContext<'_>) -> Option<Violation> {
        let cookie = crate::helpers::cookie::set_cookie_name(s);
        let about = |sentence: &str| crate::helpers::cookie::about_cookie(cookie, sentence);

        // Split into cookie-pair and attributes — § 5.2's own parsing
        // algorithm, which is the reading this rule does before any
        // defect exists. The defects' sentences are at the sites below,
        // because each has to name the cookie it is about.
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
                    return Some(ctx.report_with(
                        &COOKIE_DOMAIN_MISSING,
                        about(COOKIE_DOMAIN_MISSING_WORDING),
                    ));
                }
                match crate::helpers::domain::validate_cookie_domain(val) {
                    Ok(()) => {
                        if val.starts_with('.') {
                            return Some(ctx.report_with(
                                &COOKIE_DOMAIN_LEADING_DOT_OBSOLETE,
                                about(
                                    "Set-Cookie 'Domain' attribute uses a leading '.' which is \
                                     deprecated; prefer the registry form without leading dot",
                                ),
                            ));
                        }
                    }
                    Err(e) => {
                        return Some(ctx.report_with(
                            domain_defect(e),
                            about(&format!(
                                "Invalid Set-Cookie Domain attribute '{}': {}",
                                val,
                                e.message()
                            )),
                        ));
                    }
                }
            }
        }
        None
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

    /// A response is allowed to set many cookies, and this rule answers for
    /// each of them.
    ///
    /// The walk used to stop at the first `Domain` it had something to say
    /// about, so the second line here — an IP address, which is the whole of
    /// what `cookie_domain_ipv4_address_forbidden` is for — was reported
    /// nowhere as long as the first line had a leading dot. Ten `Set-Cookie`
    /// lines is an ordinary response; one of the corpus's carries exactly ten.
    #[test]
    fn every_cookie_on_the_response_is_answered_for() {
        use crate::test_helpers::make_test_transaction_with_response;
        let tx = make_test_transaction_with_response(
            200,
            &[
                ("set-cookie", "a=1; Domain=.example.com"),
                ("set-cookie", "b=2; Domain=192.168.0.1"),
            ],
        );
        let rule = CookieDomainValid;
        let found = crate::test_helpers::run_rule_all(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        let ids: Vec<&str> = found.iter().map(|v| v.violation.as_str()).collect();
        assert_eq!(
            ids,
            [
                "cookie_domain_leading_dot_obsolete",
                "cookie_domain_ipv4_address_forbidden"
            ]
        );
    }

    /// And each of them says which cookie it is about, because two findings of
    /// one entry on one response are otherwise the same sentence twice.
    #[test]
    fn a_finding_names_the_cookie_it_is_about() {
        use crate::test_helpers::make_test_transaction_with_response;
        let tx = make_test_transaction_with_response(
            200,
            &[
                ("set-cookie", "session=1; Domain=.example.com"),
                ("set-cookie", "tracker=2; Domain=.example.com"),
            ],
        );
        let rule = CookieDomainValid;
        let found = crate::test_helpers::run_rule_all(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert_eq!(found.len(), 2);
        assert!(
            found[0].message.ends_with("(cookie 'session')"),
            "{:?}",
            found[0].message
        );
        assert!(
            found[1].message.ends_with("(cookie 'tracker')"),
            "{:?}",
            found[1].message
        );
        assert_ne!(found[0].message, found[1].message);
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
            body_interrupted: false,
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
    fn an_obs_text_octet_in_a_domain_is_the_names_defect() -> anyhow::Result<()> {
        use crate::http_transaction::ResponseInfo;
        use crate::test_helpers::make_test_transaction;
        use hyper::header::HeaderValue;

        let mut tx = make_test_transaction();
        tx.response = Some(ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hyper::HeaderMap::new(),

            body_length: None,
            body_interrupted: false,
            trailers: None,
        });

        tx.response.as_mut().unwrap().headers.append(
            "set-cookie",
            HeaderValue::from_bytes(b"SID=1; Domain=ex\xffample.com")?,
        );

        // Inside the attribute this rule reads, the octet is one the preferred
        // name syntax does not admit, and it answers with the shared `domain`
        // subject's id -- the same one a `From` address or a `Forwarded` node
        // answers with. The verdict this replaces named the field's encoding
        // and never reached the name.
        let rule = CookieDomainValid;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .expect("a finding");
        assert_eq!(v.violation, "domain_label_character_forbidden");
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
