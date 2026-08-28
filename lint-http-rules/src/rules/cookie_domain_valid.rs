// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct CookieDomainValid;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_6265_5_2_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 6265",
    section: Some("5.2.3"),
    url: "https://www.rfc-editor.org/rfc/rfc6265.html#section-5.2.3",
    note: "`Domain` attribute processing — an empty value is undefined (UA ignores it) and a leading dot is stripped; the domain-value *format* is §4.1.1 / RFC 1035",
};
const RFC_1035: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 1035",
    section: None,
    url: "https://www.rfc-editor.org/rfc/rfc1035.html",
    note: "Domain name label rules (length, allowed characters)",
};

impl Rule for CookieDomainValid {
    fn id(&self) -> &'static str {
        "cookie_domain_valid"
    }

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

                // split into cookie-pair and attributes
                let parts = s.split(';').map(|p| p.trim()).collect::<Vec<_>>();
                for attr in parts.iter().skip(1) {
                    if attr.is_empty() {
                        continue;
                    }
                    let mut av = attr.splitn(2, '=');
                    let key = av.next().unwrap().trim();
                    let val = av.next().map(|v| v.trim()).unwrap_or("");
                    if key.eq_ignore_ascii_case("domain") {
                        // cite(RFC 6265 § 5.2.3): "If the attribute-value is empty, the behavior is undefined."
                        if val.is_empty() {
                            return Some(self.cited(
                                &RFC_6265_5_2_3,
                                ctx.severity,
                                "Set-Cookie attribute 'Domain' requires a value".into(),
                            ));
                        }
                        match crate::helpers::domain::validate_cookie_domain(val) {
                            Ok(()) => {
                                // A leading dot is not a *syntax* error — the user agent
                                // strips it, so `.example.com` and `example.com` are the same
                                // cookie-domain. That is exactly why it is flagged: the dot is a
                                // redundant legacy form (RFC 2965 gave it meaning; RFC 6265 does
                                // not), so the server should send the registry form without it.
                                // cite(RFC 6265 § 5.2.3): "Let cookie-domain be the attribute-value without the leading %x2E (".") character."
                                if val.starts_with('.') {
                                    return Some(self.cited(&RFC_6265_5_2_3, ctx.severity, "Set-Cookie 'Domain' attribute uses a leading '.' which is deprecated; prefer the registry form without leading dot".into()));
                                }
                            }
                            Err(e) => {
                                return Some(self.cited(
                                    &RFC_6265_5_2_3,
                                    ctx.severity,
                                    format!("Invalid Set-Cookie Domain attribute '{}': {}", val, e),
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

    fn description(&self) -> &'static str {
        "Validate the `Domain` attribute of `Set-Cookie` header values. This rule checks that\n`Domain` values are syntactically valid domain names (no spaces, valid label characters,\nlabel length and overall length limits) and flags uses that are likely incorrect, such as\nIP addresses or empty values. A leading `.` is tolerated for historical reasons but is\nreported as deprecated."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_6265_5_2_3, RFC_1035]
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
