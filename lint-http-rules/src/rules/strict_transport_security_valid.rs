// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::quoted_string::{
    quoted_string_defect, QUOTED_STRING_CONTROL_CHARACTER_FORBIDDEN,
    QUOTED_STRING_DELIMITER_MISSING, QUOTED_STRING_QUOTED_PAIR_MALFORMED,
    QUOTED_STRING_QUOTE_ESCAPE_MISSING, RFC_9110_5_6_4,
};
use crate::violations::token::{
    token_character, RFC_9110_5_6_2, TOKEN_CHARACTER_FORBIDDEN, TOKEN_EMPTY,
    TOKEN_WHITESPACE_OR_CONTROL_FORBIDDEN,
};
use crate::violations::ViolationDef;

pub struct StrictTransportSecurityValid;

/// Six defects over two subjects, borrowed from a document RFC 6797 does not
/// name — and the reading that says it may be.
///
/// § 6.1 imports both productions from RFC 2616 § 2.2 by reference:
/// `directive-name = token`, `directive-value = token | quoted-string`. RFC
/// 2616's `token` is RFC 9110's `tchar` set, which is the judgment
/// `Sec-WebSocket-Extensions` reached from its own grammar — 2616 subtracts its
/// separators and CTLs from `CHAR`, and what is left is `tchar`. So the two
/// `token` entries transfer with nothing to decide.
///
/// **The `quoted-string` half genuinely differs, and the difference cannot
/// arrive.** RFC 2616 writes `quoted-pair = "\" CHAR`, which admits an escaped
/// control octet § 5.6.4 refuses and refuses the `obs-text` § 5.6.4 admits — so
/// `quoted_string_quoted_pair_malformed` names a sentence this field's document
/// does not use, for those two octets. Neither reaches this rule: the value is
/// read through `to_str`, whose alphabet is HTAB and visible US-ASCII, so an
/// escaped CTL and an `obs-text` are both refused at the door and every escape
/// that gets here is one both documents admit. What does reach the def is a
/// backslash with nothing after it, which is two octets short of a
/// `quoted-pair` in either. **A divergence that no value can express is not a
/// reason to decline the id** — but it is a reason to write down which reader
/// keeps it that way, because a rule reading these octets some other day would
/// have to ask again.
///
/// The other two `quoted_string_*` entries are declared and unreachable for the
/// same reason the mapping is exhaustive: a control octet cannot enter a
/// `hyper::HeaderValue`, and the grammar's reader is where the grammar's
/// question is answered.
static DECLARED: &[&ViolationDef] = &[
    &TOKEN_EMPTY,
    &TOKEN_CHARACTER_FORBIDDEN,
    &TOKEN_WHITESPACE_OR_CONTROL_FORBIDDEN,
    &QUOTED_STRING_DELIMITER_MISSING,
    &QUOTED_STRING_QUOTED_PAIR_MALFORMED,
    &QUOTED_STRING_QUOTE_ESCAPE_MISSING,
    &QUOTED_STRING_CONTROL_CHARACTER_FORBIDDEN,
];

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_6797_6_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 6797",
    section: Some("6.1"),
    url: "https://www.rfc-editor.org/rfc/rfc6797.html#section-6.1",
    note: "Strict-Transport-Security header",
};
const RFC_6797_6_1_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 6797",
    section: Some("6.1.1"),
    url: "https://www.rfc-editor.org/rfc/rfc6797.html#section-6.1.1",
    note: "The max-age Directive",
};
const RFC_6797_6_1_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 6797",
    section: Some("6.1.2"),
    url: "https://www.rfc-editor.org/rfc/rfc6797.html#section-6.1.2",
    note: "The includeSubDomains Directive",
};

impl RuleMeta for StrictTransportSecurityValid {
    fn id(&self) -> &'static str {
        "strict_transport_security_valid"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
severity = "warn"
"#
    }

    fn description(&self) -> &'static str {
        "The `Strict-Transport-Security` response header signals HSTS policies. This rule ensures responses include the required `max-age` directive (a non-negative integer) and that optional directives `includeSubDomains` and `preload` are present without values. Unknown directives are accepted but any value must be a `token` or `quoted-string`. Non-UTF8 header values and syntactic violations are reported as rule violations."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_6797_6_1,
            RFC_6797_6_1_1,
            RFC_6797_6_1_2,
            RFC_9110_5_6_2,
            RFC_9110_5_6_4,
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
                snippet: "Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "Strict-Transport-Security: max-age=0",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— missing `max-age`"),
                snippet: "Strict-Transport-Security: includeSubDomains",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— `max-age` not numeric"),
                snippet: "Strict-Transport-Security: max-age=abc",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— `includeSubDomains` must not have a value"),
                snippet: "Strict-Transport-Security: max-age=63072000; includeSubDomains=1",
            },
        ]
    }
}

impl Rule for StrictTransportSecurityValid {
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
            // Only applicable to responses
            let resp = tx.response.as_ref()?;

            // A malformed STS header is not a weaker policy — the UA drops it whole and the
            // host is not treated as Known HSTS, so every syntax check below enforces this MUST.
            // cite(RFC 6797 § 6.1): "UAs MUST ignore any STS header field containing directives, or other header field value data, that does not conform to the syntax defined in this specification."
            for hv in resp.headers.get_all("strict-transport-security").iter() {
                let v = match hv.to_str() {
                    Ok(s) => s.trim(),
                    Err(_) => {
                        return Some(self.cited(
                            &RFC_6797_6_1,
                            ctx.severity,
                            "Strict-Transport-Security header contains non-UTF8 value".into(),
                        ));
                    }
                };

                // Unnamed, and the grammar is the reason. § 6.1 writes
                // `[ directive ] *( ";" [ directive ] )`, so the empty value
                // derives — this finding is the rule saying a policy that
                // declares nothing is not a policy, which is a statement about
                // this field and not about a production it broke.
                if v.is_empty() {
                    return Some(self.violation(
                        ctx.severity,
                        "Strict-Transport-Security header must not be empty".into(),
                    ));
                }

                let mut saw_max_age = false;
                let mut max_age_count = 0usize;

                for member in crate::helpers::list::split_semicolons_respecting_quotes(v) {
                    let member = member.trim();
                    // **Not `list_member_empty`.** That def carries § 5.6.1.1's
                    // MUST NOT against an empty element of a `#` list, and this
                    // is not one: the members are semicolon-separated by this
                    // field's own production, whose optional brackets *generate*
                    // the empty one. The rule refuses it anyway and that is its
                    // own claim, which is the same shape of refusal
                    // `Sec-WebSocket-Extensions` made about RFC 2616's list.
                    if member.is_empty() {
                        // skip stray semicolons but flag as violation
                        return Some(self.violation(
                            ctx.severity,
                            "Empty directive in Strict-Transport-Security header".into(),
                        ));
                    }

                    // directive = token [ "=" token ]
                    let mut kv = member.splitn(2, '=');
                    let name = kv.next().unwrap().trim();
                    if name.is_empty() {
                        return Some(ctx.report_with(
                            &TOKEN_EMPTY,
                            "Empty directive name in Strict-Transport-Security header".into(),
                        ));
                    }

                    // The statement below is RFC 6797's and stays: *this
                    // field's* directive name is a token, which is what licenses
                    // borrowing the subject at all. What moves onto the two defs
                    // is the sentence saying what a token is — § 5.6.2's
                    // `token = 1*tchar`, the character set RFC 2616's derives too.
                    // cite(RFC 6797 § 6.1): "directive-name            = token"
                    if let Some(c) = crate::helpers::token::find_invalid_token_char(name) {
                        return Some(ctx.report_with(token_character(c), format!("Strict-Transport-Security directive name contains invalid character: '{}'", c)));
                    }

                    let lname = name.to_ascii_lowercase();
                    match lname.as_str() {
                        // max-age is REQUIRED (enforced by the `saw_max_age` check after the loop)
                        // and its value is a count of seconds, i.e. all-digits (checked below).
                        // cite(RFC 6797 § 6.1.1): "The REQUIRED "max-age" directive specifies the number of seconds, after the reception of the STS header field, during which the UA regards the host (from whom the message was received) as a Known HSTS Host."
                        "max-age" => {
                            max_age_count += 1;
                            saw_max_age = true;
                            // must have a value
                            if let Some(vpart) = kv.next() {
                                let vpart = vpart.trim();
                                if vpart.is_empty() {
                                    return Some(self.violation(ctx.severity, "Strict-Transport-Security 'max-age' must have a numeric value".into()));
                                }
                                // Asked before the digits, and answered by the
                                // catalogue: a `directive-value` is a `token` or
                                // a `quoted-string` whatever the directive means
                                // by it, so an octet no `tchar` admits is the
                                // production's defect and not `max-age`'s.
                                if let Some(c) =
                                    crate::helpers::token::find_invalid_token_char(vpart)
                                {
                                    return Some(ctx.report_with(token_character(c), format!("Strict-Transport-Security 'max-age' contains invalid character: '{}'", c)));
                                }
                                if vpart.chars().any(|ch| !ch.is_ascii_digit()) {
                                    return Some(self.violation(ctx.severity, "Strict-Transport-Security 'max-age' must be a non-negative integer".into()));
                                }
                                if vpart.parse::<u64>().is_err() {
                                    return Some(self.violation(ctx.severity, "Strict-Transport-Security 'max-age' value is not a valid integer".into()));
                                }
                            } else {
                                return Some(self.violation(
                                    ctx.severity,
                                    "Strict-Transport-Security 'max-age' must have a value".into(),
                                ));
                            }
                        }
                        // cite(RFC 6797 § 6.1.2): "The OPTIONAL "includeSubDomains" directive is a valueless directive which, if present (i.e., it is "asserted"), signals the UA that the HSTS Policy applies to this HSTS Host as well as any subdomains of the host's domain name."
                        "includesubdomains" => {
                            // canonical name is includeSubDomains, but accept case-insensitively
                            // must NOT have a value (it is "valueless" per §6.1.2)
                            if kv.next().is_some() {
                                return Some(self.violation(ctx.severity, "Strict-Transport-Security 'includeSubDomains' directive must not have a value".into()));
                            }
                        }
                        // `preload` is not an RFC 6797 directive — it is a de-facto extension (the
                        // browser HSTS preload list), the kind §6.1 anticipates being "defined in
                        // other specifications". Its valueless form is convention, so no 6797 quote
                        // governs this branch; it is validated like a known valueless directive.
                        "preload" => {
                            if kv.next().is_some() {
                                return Some(self.violation(ctx.severity, "Strict-Transport-Security 'preload' directive must not have a value".into()));
                            }
                        }
                        _ => {
                            // Unknown directives: allow but ensure if a value is present it is token or quoted-string
                            // cite(RFC 6797 § 6.1): "directive-value           = token | quoted-string"
                            if let Some(vpart) = kv.next() {
                                let vpart = vpart.trim();
                                if vpart.starts_with('"') {
                                    if let Err(defect) =
                                        crate::helpers::quoted_string::check_quoted_string(vpart)
                                    {
                                        return Some(ctx.report_with(quoted_string_defect(defect), format!("Invalid quoted-string in Strict-Transport-Security directive value: {}", defect.message(vpart))));
                                    }
                                } else if let Some(c) =
                                    crate::helpers::token::find_invalid_token_char(vpart)
                                {
                                    return Some(ctx.report_with(token_character(c), format!("Strict-Transport-Security directive '{}' value contains invalid character: '{}'", name, c)));
                                }
                            }
                        }
                    }
                }

                // cite(RFC 6797 § 6.1): "All directives MUST appear only once in an STS header field."
                if max_age_count > 1 {
                    return Some(self.cited(&RFC_6797_6_1, ctx.severity, "Strict-Transport-Security MUST NOT contain multiple 'max-age' directives"
                                .into()));
                }

                if !saw_max_age {
                    return Some(
                        self.cited(
                            &RFC_6797_6_1,
                            ctx.severity,
                            "Strict-Transport-Security header missing required 'max-age' directive"
                                .into(),
                        ),
                    );
                }
            }

            None
        };
        Vec::from_iter(finding())
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &StrictTransportSecurityValid;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn make_resp(val: &str) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[(
                "strict-transport-security",
                val,
            )]),

            body_length: None,
            trailers: None,
        });
        tx
    }

    #[rstest]
    #[case("max-age=63072000", false)]
    #[case("max-age=0", false)]
    #[case("max-age=63072000; includeSubDomains; preload", false)]
    #[case("includeSubDomains", true)]
    #[case("max-age=abc", true)]
    #[case("max-age=63072000; includeSubDomains=1", true)]
    #[case("max-age=63072000; preload=1", true)]
    #[case("max-age=63072000; max-age=1", true)]
    fn cases(#[case] val: &str, #[case] expect_violation: bool) -> anyhow::Result<()> {
        let rule = StrictTransportSecurityValid;
        let tx = make_resp(val);
        let cfg = crate::test_helpers::make_test_config_with_severity(
            "strict_transport_security_valid",
            "warn",
        );
        let got = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .is_some();
        assert_eq!(got, expect_violation, "value: {}", val);
        Ok(())
    }

    /// Every finding, with the sentence it says it in and the defect it reports
    /// as. The named rows are the two productions § 6.1 imports and does not
    /// define; the empty ones are RFC 6797's own policy — that a policy
    /// declaring nothing is not one, that `max-age` counts seconds and is
    /// required, that two directives are valueless, and that a directive
    /// appears once.
    #[rstest]
    #[case::empty_value("", "must not be empty", "")]
    #[case::empty_directive("max-age=1;;preload", "Empty directive in", "")]
    #[case::empty_name("max-age=1; =2", "Empty directive name", "token_empty")]
    #[case::name_character(
        "max-age=1; pre@load",
        "directive name contains",
        "token_character_forbidden"
    )]
    #[case::max_age_character(
        "max-age=1@2",
        "'max-age' contains invalid",
        "token_character_forbidden"
    )]
    #[case::max_age_not_a_number("max-age=1.5", "non-negative integer", "")]
    #[case::max_age_empty("max-age=", "must have a numeric value", "")]
    #[case::max_age_valueless("max-age", "must have a value", "")]
    #[case::include_subdomains_valued(
        "max-age=1; includeSubDomains=1",
        "must not have a value",
        ""
    )]
    #[case::preload_valued("max-age=1; preload=1", "must not have a value", "")]
    #[case::value_character(
        "max-age=1; foo=b@r",
        "value contains invalid",
        "token_character_forbidden"
    )]
    #[case::unterminated_quote(
        "max-age=1; foo=\"bar",
        "Invalid quoted-string",
        "quoted_string_delimiter_missing"
    )]
    #[case::unescaped_quote(
        "max-age=1; foo=\"a\"b\"",
        "Invalid quoted-string",
        "quoted_string_quote_escape_missing"
    )]
    #[case::trailing_escape(
        "max-age=1; foo=\"ab\\\"",
        "Invalid quoted-string",
        "quoted_string_quoted_pair_malformed"
    )]
    #[case::repeated_max_age("max-age=1; max-age=2", "multiple 'max-age'", "")]
    #[case::missing_max_age("includeSubDomains", "missing required 'max-age'", "")]
    fn each_finding_reports_the_production_it_belongs_to(
        #[case] value: &str,
        #[case] expected: &str,
        #[case] violation: &str,
    ) {
        let finding = crate::test_helpers::run_rule(
            &StrictTransportSecurityValid,
            &make_resp(value),
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_severity(
                "strict_transport_security_valid",
                "warn",
            ),
        )
        .unwrap_or_else(|| panic!("expected a finding for {value:?}"));
        assert!(
            finding.message.contains(expected),
            "for {value:?}: {:?}",
            finding.message
        );
        assert_eq!(finding.violation, violation, "for {value:?}");
    }

    /// A directive name is a `token` here and in every other field, and RFC
    /// 6797 taking the production from RFC 2616 changes nothing about the
    /// octet: 2616 subtracts its separators and CTLs from `CHAR`, and what is
    /// left is `tchar`. Asserted against a rule reading a field defined by
    /// RFC 9110 itself, which shares no code with this one.
    #[test]
    fn a_directive_name_is_a_token_under_either_document() {
        let here = crate::test_helpers::run_rule(
            &StrictTransportSecurityValid,
            &make_resp("max-age=1; pre@load"),
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_severity(
                "strict_transport_security_valid",
                "warn",
            ),
        )
        .expect("a finding");
        let elsewhere = crate::test_helpers::run_rule(
            &crate::rules::vary_header_valid::VaryHeaderValid,
            &crate::test_helpers::make_test_transaction_with_response(200, &[("vary", "b@d")]),
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&["vary_header_valid"]),
        )
        .expect("a finding");

        assert_eq!(here.violation, elsewhere.violation);
        assert_ne!(here.message, elsewhere.message);
    }

    /// The one place RFC 2616's `quoted-pair` and RFC 9110's disagree — an
    /// escaped control octet, which 2616 admits and § 5.6.4 refuses — cannot
    /// arrive, because the reader this rule uses does not admit the octet at
    /// all. That is what makes borrowing the def safe here rather than a claim
    /// about a sentence the field's document does not use.
    #[test]
    fn the_two_documents_disagreement_cannot_reach_this_rule() {
        use hyper::header::HeaderValue;
        assert!(HeaderValue::from_bytes(b"max-age=1; foo=\"a\x01b\"").is_err());
        // `to_str` is what the rule reads through, and it refuses `obs-text`
        // too -- the other half of the disagreement, in the other direction.
        let obs = HeaderValue::from_bytes(b"max-age=1; foo=\"a\\\xe9b\"").expect("a value");
        assert!(obs.to_str().is_err());
    }

    #[test]
    fn non_utf8_header_is_violation() {
        use hyper::header::HeaderValue;
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut headers = crate::test_helpers::make_headers_from_pairs(&[]);
        headers.append(
            "strict-transport-security",
            HeaderValue::from_bytes(b"max-age=1\xFF" as &[u8]).unwrap(),
        );
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers,

            body_length: None,
            trailers: None,
        });
        let rule = StrictTransportSecurityValid;
        let cfg = crate::test_helpers::make_test_config_with_severity(
            "strict_transport_security_valid",
            "warn",
        );
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .is_some());
    }

    #[test]
    fn empty_value_is_violation() {
        let rule = StrictTransportSecurityValid;
        let tx = make_resp("");
        let cfg = crate::test_helpers::make_test_config_with_severity(
            "strict_transport_security_valid",
            "warn",
        );
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .is_some());
    }

    #[test]
    fn trailing_semicolon_reports_empty_directive() {
        let rule = StrictTransportSecurityValid;
        let tx = make_resp("max-age=1;");
        let cfg = crate::test_helpers::make_test_config_with_severity(
            "strict_transport_security_valid",
            "warn",
        );
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .is_some());
    }

    #[test]
    fn unknown_directive_with_bad_quoted_string_reports_violation() {
        let rule = StrictTransportSecurityValid;
        let tx = make_resp("max-age=1; foo=\"unterminated");
        let cfg = crate::test_helpers::make_test_config_with_severity(
            "strict_transport_security_valid",
            "warn",
        );
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .is_some());
    }

    #[test]
    fn unknown_directive_with_invalid_token_value_reports_violation() {
        let rule = StrictTransportSecurityValid;
        let tx = make_resp("max-age=1; bar=bad@val");
        let cfg = crate::test_helpers::make_test_config_with_severity(
            "strict_transport_security_valid",
            "warn",
        );
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .is_some());
    }

    #[test]
    fn unknown_directive_with_quoted_string_is_ok() {
        let rule = StrictTransportSecurityValid;
        let tx = make_resp("max-age=1; foo=\"valid\"");
        let cfg = crate::test_helpers::make_test_config_with_severity(
            "strict_transport_security_valid",
            "warn",
        );
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .is_none());
    }

    #[test]
    fn max_age_empty_value_is_violation() {
        let rule = StrictTransportSecurityValid;
        let tx = make_resp("max-age=");
        let cfg = crate::test_helpers::make_test_config_with_severity(
            "strict_transport_security_valid",
            "warn",
        );
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .is_some());
    }

    #[test]
    fn max_age_without_equals_is_violation() {
        let rule = StrictTransportSecurityValid;
        let tx = make_resp("max-age");
        let cfg = crate::test_helpers::make_test_config_with_severity(
            "strict_transport_security_valid",
            "warn",
        );
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .is_some());
    }

    #[test]
    fn max_age_quoted_is_violation() {
        let rule = StrictTransportSecurityValid;
        let tx = make_resp("max-age=\"3600\"");
        let cfg = crate::test_helpers::make_test_config_with_severity(
            "strict_transport_security_valid",
            "warn",
        );
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .is_some());
    }

    #[test]
    fn directive_name_with_invalid_char_is_violation() {
        let rule = StrictTransportSecurityValid;
        let tx = make_resp("ma x=1");
        let cfg = crate::test_helpers::make_test_config_with_severity(
            "strict_transport_security_valid",
            "warn",
        );
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .is_some());
    }

    #[test]
    fn unknown_directive_with_token_value_is_ok() {
        let rule = StrictTransportSecurityValid;
        let tx = make_resp("max-age=1; foo=bar");
        let cfg = crate::test_helpers::make_test_config_with_severity(
            "strict_transport_security_valid",
            "warn",
        );
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .is_none());
    }

    #[test]
    fn include_subdomains_case_insensitive_is_ok() {
        let rule = StrictTransportSecurityValid;
        let tx = make_resp("max-age=1; IncludeSubDomains");
        let cfg = crate::test_helpers::make_test_config_with_severity(
            "strict_transport_security_valid",
            "warn",
        );
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .is_none());
    }

    #[test]
    fn multiple_header_fields_one_invalid_reports_violation() {
        // two header fields: one valid, one missing max-age
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[
                ("strict-transport-security", "max-age=1"),
                ("strict-transport-security", "includeSubDomains"),
            ]),

            body_length: None,
            trailers: None,
        });
        let rule = StrictTransportSecurityValid;
        let cfg = crate::test_helpers::make_test_config_with_severity(
            "strict_transport_security_valid",
            "warn",
        );
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .is_some());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "strict_transport_security_valid");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
