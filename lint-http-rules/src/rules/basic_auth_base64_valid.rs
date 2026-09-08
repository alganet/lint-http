// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::base64::{BASE64_MALFORMED, RFC_4648_3_3};
use crate::violations::basic_credentials::{
    basic_credentials_defect, BASIC_CREDENTIALS_CONTROL_CHARACTER_FORBIDDEN,
    BASIC_CREDENTIALS_SEPARATOR_MISSING, RFC_7617_2,
};
use crate::violations::credentials::{CREDENTIALS_MISSING, RFC_9110_11_6_2};
use crate::violations::ViolationDef;

pub struct BasicAuthBase64Valid;

/// The defects this rule reports. Two are RFC 7617's own — the separator and
/// the control characters it forbids — and two are not this scheme's at all: a
/// `Basic` with nothing after it is the framework's `credentials_missing`,
/// which `authorization_credentials_present` reports about the same request,
/// and a value that does not decode is `base64_malformed`, which the WebSocket
/// handshake's key will report under the same name. Naming either of them after
/// this scheme would give an operator one id per field for one mistake.
static DECLARED: &[&ViolationDef] = &[
    &BASIC_CREDENTIALS_SEPARATOR_MISSING,
    &BASIC_CREDENTIALS_CONTROL_CHARACTER_FORBIDDEN,
    &CREDENTIALS_MISSING,
    &BASE64_MALFORMED,
];

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_4648_4: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 4648",
    section: Some("4"),
    url: "https://www.rfc-editor.org/rfc/rfc4648.html#section-4",
    note: "Base64 encoding used for `token68`",
};

impl RuleMeta for BasicAuthBase64Valid {
    fn id(&self) -> &'static str {
        "basic_auth_base64_valid"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
severity = "warn"
"#
    }

    fn description(&self) -> &'static str {
        "Validate that `Authorization: Basic ...` credentials are syntactically valid Base64-encoded `user-id:password` octet sequences as defined by RFC 7617. The rule ensures the credentials decode successfully, include the required `:` separator, and that neither the user-id nor the password contains control characters."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_7617_2, RFC_4648_4, RFC_4648_3_3, RFC_9110_11_6_2]
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
                snippet: "GET /protected HTTP/1.1\nHost: example.com\nAuthorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "GET /protected HTTP/1.1\nHost: example.com\nAuthorization: Basic not-base64",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "GET /protected HTTP/1.1\nHost: example.com\nAuthorization: Basic YWJj",
            },
        ]
    }
}

impl Rule for BasicAuthBase64Valid {
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
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
            // Read as octets: the credential is Base64, whose alphabet is
            // where an octet outside visible US-ASCII belongs, and the reader
            // that refused the value outright reported it as the field's
            // encoding instead.
            for hv in tx.request.headers.get_all("authorization").iter() {
                let s = crate::helpers::headers::field_line_as_written(hv);
                let s = s.as_str();
                // Scheme names match case-insensitively.
                // cite(RFC 9110 § 11.1): "It uses a case-insensitive token to identify the authentication scheme"
                let mut parts = s.splitn(2, char::is_whitespace);
                let scheme = parts.next().unwrap_or("").trim();
                if scheme.eq_ignore_ascii_case("Basic") {
                    let creds = parts.next().unwrap_or("").trim();
                    if creds.is_empty() {
                        // The framework's defect rather than this
                        // scheme's: a scheme with nothing after it is
                        // what `credentials` says must not happen,
                        // whichever scheme was named.
                        return Some(ctx.report_with(
                            &CREDENTIALS_MISSING,
                            "Basic Authorization missing credentials".into(),
                        ));
                    }
                    // The rule's own claim: the credential the client sends encodes a
                    // user-id and password. How that value is built and checked — the
                    // Base64 alphabet, the ":" separator, control characters — is owned
                    // by validate_basic_credentials (RFC 7617 §2 / RFC 4648).
                    // cite(RFC 7617 § 2): "The value is computed based on user-id and password as defined below."
                    if let Err(defect) = crate::helpers::auth::validate_basic_credentials(creds) {
                        return Some(ctx.report_with(
                            basic_credentials_defect(&defect),
                            format!("Invalid Basic credentials: {} (RFC 7617)", defect.message()),
                        ));
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
static REGISTRATION: &dyn crate::rules::Rule = &BasicAuthBase64Valid;

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use hyper::header::HeaderValue;
    use rstest::rstest;

    /// Four names where the rule had one, and two of them are not this
    /// scheme's: a `Basic` with nothing after it is the framework's defect,
    /// reported under the id `authorization_credentials_present` reports about
    /// the same request, and a value that does not decode is the encoding's.
    /// The control octet defaults a level above the rest — RFC 7617 forbids it
    /// in either half in so many words.
    #[rstest]
    #[case("Basic", "credentials_missing", crate::lint::Severity::Warn)]
    #[case("Basic not-base64", "base64_malformed", crate::lint::Severity::Warn)]
    #[case(
        "Basic YWJj",
        "basic_credentials_separator_missing",
        crate::lint::Severity::Warn
    )]
    #[case(
        "Basic YQE6Yg==",
        "basic_credentials_control_character_forbidden",
        crate::lint::Severity::Error
    )]
    fn each_finding_names_the_defect_and_carries_its_severity(
        #[case] header: &str,
        #[case] violation: &str,
        #[case] severity: crate::lint::Severity,
    ) -> anyhow::Result<()> {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request
            .headers
            .append("authorization", HeaderValue::from_str(header)?);
        let v = crate::test_helpers::run_rule(
            &BasicAuthBase64Valid,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&["basic_auth_base64_valid"]),
        )
        .unwrap_or_else(|| panic!("expected a finding for {header:?}"));
        assert_eq!(v.violation, violation, "{}", v.message);
        assert_eq!(v.severity, severity, "{}", v.message);
        Ok(())
    }

    #[rstest]
    #[case(Some("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="), false)]
    #[case(Some("Basic not-base64"), true)]
    #[case(Some("Basic YWJj"), true)] // 'abc' -> missing colon
    #[case(Some("Bearer abc"), false)]
    #[case(None, false)]
    fn check_basic_cases(
        #[case] header: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = BasicAuthBase64Valid;
        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(h) = header {
            tx.request
                .headers
                .append("authorization", HeaderValue::from_str(h)?);
        }

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        if expect_violation {
            assert!(v.is_some(), "expected violation for header '{:?}'", header);
        } else {
            assert!(
                v.is_none(),
                "unexpected violation for header '{:?}': {:?}",
                header,
                v
            );
        }
        Ok(())
    }

    #[test]
    fn basic_with_ctl_in_password_reports_violation() {
        let creds = b"user:\x01pass";
        let enc = base64::engine::general_purpose::STANDARD.encode(creds);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers.append(
            "authorization",
            HeaderValue::from_str(&format!("Basic {}", enc)).unwrap(),
        );
        let rule = BasicAuthBase64Valid;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("control"));
    }

    #[test]
    fn multiple_auth_headers_one_invalid_is_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers.append(
            "authorization",
            HeaderValue::from_static("Bearer goodtoken"),
        );
        tx.request.headers.append(
            "authorization",
            HeaderValue::from_static("Basic not-base64"),
        );
        let rule = BasicAuthBase64Valid;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
    }

    #[test]
    fn missing_credentials_reports_violation() {
        let mut tx1 = crate::test_helpers::make_test_transaction();
        tx1.request
            .headers
            .append("authorization", HeaderValue::from_static("Basic"));
        let rule = BasicAuthBase64Valid;
        let v1 = crate::test_helpers::run_rule(
            &rule,
            &tx1,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v1.is_some());
        assert!(v1.unwrap().message.contains("missing credentials"));

        let mut tx2 = crate::test_helpers::make_test_transaction();
        tx2.request
            .headers
            .append("authorization", HeaderValue::from_static("Basic "));
        let v2 = crate::test_helpers::run_rule(
            &rule,
            &tx2,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v2.is_some());
        assert!(v2.unwrap().message.contains("missing credentials"));
    }

    /// An octet outside visible US-ASCII is an octet the Base64 alphabet does
    /// not hold, which is what the credential is measured against — not a
    /// verdict about the field's encoding, which is what the reader this
    /// replaces reported.
    #[test]
    fn an_obs_text_octet_is_outside_the_base64_alphabet() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers.append(
            "authorization",
            HeaderValue::from_bytes(b"Basic \xff").unwrap(),
        );
        let rule = BasicAuthBase64Valid;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .expect("a finding");
        assert_eq!(v.violation, "base64_malformed");
    }

    #[test]
    fn basic_lowercase_scheme_is_accepted() {
        // scheme is case-insensitive
        let creds = b"Aladdin:open sesame";
        let enc = base64::engine::general_purpose::STANDARD.encode(creds);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers.append(
            "authorization",
            HeaderValue::from_str(&format!("basic {}", enc)).unwrap(),
        );
        let rule = BasicAuthBase64Valid;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn basic_empty_password_allowed() {
        // 'user:' should be allowed (empty password)
        let creds = b"user:";
        let enc = base64::engine::general_purpose::STANDARD.encode(creds);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers.append(
            "authorization",
            HeaderValue::from_str(&format!("Basic {}", enc)).unwrap(),
        );
        let rule = BasicAuthBase64Valid;
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
        crate::test_helpers::enable_rule(&mut cfg, "basic_auth_base64_valid");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
