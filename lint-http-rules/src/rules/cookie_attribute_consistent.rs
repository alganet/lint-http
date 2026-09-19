// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::helpers::cookie::find_invalid_cookie_octet;
use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::cookie::DRAFT_IETF_HTTPBIS_RFC6265BIS;
use crate::violations::cookie::{
    COOKIE_DOMAIN_EMPTY, COOKIE_DOMAIN_MISSING, COOKIE_DOMAIN_MISSING_WORDING,
    COOKIE_EXPIRES_MALFORMED, COOKIE_EXPIRES_MISSING, COOKIE_FLAG_VALUE_FORBIDDEN,
    COOKIE_MAX_AGE_MALFORMED, COOKIE_MAX_AGE_MISSING, COOKIE_PAIR_EQUALS_MISSING,
    COOKIE_PAIR_MISSING, COOKIE_PATH_LEADING_SLASH_MISSING, COOKIE_PATH_MISSING,
    COOKIE_PATH_MISSING_WORDING, COOKIE_SAME_SITE_INVALID, COOKIE_SAME_SITE_MISSING,
    COOKIE_SECURE_MISSING, COOKIE_VALUE_CHARACTER_FORBIDDEN, RFC_6265_4_1_1, RFC_6265_5_1_1,
    RFC_6265_5_2_2, RFC_6265_5_2_3, RFC_6265_5_2_4,
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
/// Five imports, each for a different reason. `sane-cookie-date` is RFC
/// 6265's name for the timestamp RFC 9110 § 5.6.7 writes, so an `Expires` a
/// recipient cannot read is the same defect a `Date` or a `Sunset` a recipient
/// cannot read is. `cookie-name = token` imports the HTTP production by name,
/// so a name that is empty or holds a delimiter answers to `token` — the
/// alphabets are not merely similar, they are the same set. `cookie-pair`'s
/// own two failures — no `=` at all, and a `cookie-value` octet outside
/// `cookie-octet` — are `cookie_pair_valid`'s ids too, reused rather than
/// redeclared for the same reason `cookie-name`'s are: the production is one
/// grammar shared by both directions the cookie travels, and an operator
/// tunes either shape once. And `Path` and `Domain` were read out by
/// `cookie_path_valid` and `cookie_domain_valid` first: this rule asks a
/// coarser question of the same two attributes, so it reports what they
/// report rather than a second name for it.
///
/// What is left in the rule's own words is the shape of the field line and the
/// attributes nothing else reads — `SameSite`, `Max-Age`, the two flags, and
/// the pairing that makes a `SameSite=None` cookie disappear.
static DECLARED: &[&ViolationDef] = &[
    &HTTP_DATE_MALFORMED,
    &COOKIE_PAIR_MISSING,
    &COOKIE_PAIR_EQUALS_MISSING,
    &COOKIE_VALUE_CHARACTER_FORBIDDEN,
    &COOKIE_FLAG_VALUE_FORBIDDEN,
    &COOKIE_SECURE_MISSING,
    &COOKIE_SAME_SITE_MISSING,
    &COOKIE_SAME_SITE_INVALID,
    &COOKIE_MAX_AGE_MISSING,
    &COOKIE_MAX_AGE_MALFORMED,
    &COOKIE_EXPIRES_MISSING,
    &COOKIE_EXPIRES_MALFORMED,
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
        let (pair, attributes) = crate::helpers::cookie::split_set_cookie(line);
        // Which cookie every sentence below is about. A response sets many,
        // and until each finding said which one it was for, two of them read
        // as one repeated. The name is empty exactly where the line wrote no
        // `=` to put one before, and `about_cookie` then leaves the sentence
        // alone rather than naming a cookie called nothing.
        let cookie = crate::helpers::cookie::set_cookie_name(line);
        let about = |sentence: &str| crate::helpers::cookie::about_cookie(cookie, sentence);
        if pair.is_empty() {
            return Some(ctx.report_with(
                &COOKIE_PAIR_MISSING,
                about("Set-Cookie header missing cookie-pair"),
            ));
        }

        // `cookie-pair = cookie-name "=" cookie-value` requires the `=`
        // unconditionally -- an empty value is legal (`SID=`) but no `=` at
        // all derives from neither alternative of the production. A bare
        // token here used to fall through this whole function silently: the
        // old reading took whatever preceded the first `=` as the name and
        // never asked whether an `=` had been there to precede.
        // cite(RFC 6265 § 4.1.1): "cookie-pair       = cookie-name "=" cookie-value cookie-name       = token"
        let Some((name, value)) = pair.split_once('=') else {
            return Some(ctx.report_with(
                &COOKIE_PAIR_EQUALS_MISSING,
                about(&format!("Set-Cookie pair '{pair}' has no '=': `cookie-pair = cookie-name \"=\" cookie-value` requires one")),
            ));
        };

        // The name is a `token` by import rather than by resemblance -- § 4.1.1
        // writes `cookie-name = token` and takes the production from the HTTP
        // document -- so both of its defects are that production's.
        let name = name.trim();
        if name.is_empty() {
            return Some(ctx.report_with(&TOKEN_EMPTY, about("Set-Cookie cookie name is empty")));
        }
        if let Some(c) = crate::helpers::token::find_invalid_token_char(name) {
            return Some(ctx.report_with(
                token_character(c),
                about(&format!(
                    "Set-Cookie cookie-name contains invalid character: '{}'",
                    c
                )),
            ));
        }

        // `cookie-value = *cookie-octet / ( DQUOTE *cookie-octet DQUOTE )`,
        // the production's other half -- nothing before this read it either,
        // so a value carrying a comma, a bare quote or any other octet
        // outside `cookie-octet` passed as silently as a missing `=` did. A
        // semicolon in the value is already this function's own `pair`, cut
        // by `split_set_cookie` before this point -- it reports above, on the
        // segment it starts, as a pair with no `=`.
        if let Some(c) = find_invalid_cookie_octet(value) {
            return Some(ctx.report_with(
                &COOKIE_VALUE_CHARACTER_FORBIDDEN,
                about(&format!(
                    "Set-Cookie value '{value}' contains a character outside cookie-octet: '{c}'"
                )),
            ));
        }

        let mut secure_present = false;
        let mut same_site: Option<String> = None;
        for attribute in attributes {
            if let Some(defect) = self.attribute_defect(&attribute, cookie, ctx) {
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
            return Some(ctx.report_with(
                &COOKIE_SECURE_MISSING,
                about("Set-Cookie with 'SameSite=None' must also set 'Secure'"),
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
        cookie: &str,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Option<Violation> {
        let about = |sentence: &str| crate::helpers::cookie::about_cookie(cookie, sentence);
        // The two flag attributes: the grammar admits no "=", so the attribute
        // is its own presence and a value written after it is a defect.
        // cite(RFC 6265 § 4.1.1): "secure-av         = "Secure""
        // cite(RFC 6265 § 4.1.1): "httponly-av       = "HttpOnly""
        for flag in ["Secure", "HttpOnly"] {
            if attribute.is(flag) {
                return attribute.has_value().then(|| {
                    ctx.report_with(
                        &COOKIE_FLAG_VALUE_FORBIDDEN,
                        about(&format!(
                            "Set-Cookie attribute '{}' must not have a value",
                            flag
                        )),
                    )
                });
            }
        }

        if attribute.is("SameSite") {
            let Some(value) = attribute.value else {
                return Some(ctx.report_with(
                    &COOKIE_SAME_SITE_MISSING,
                    about("Set-Cookie attribute 'SameSite' requires a value"),
                ));
            };
            let known = ["strict", "lax", "none"]
                .iter()
                .any(|known| value.eq_ignore_ascii_case(known));
            return (!known).then(|| {
                ctx.report_with(
                    &COOKIE_SAME_SITE_INVALID,
                    about(&format!(
                        "Set-Cookie attribute 'SameSite' has invalid value: '{}'",
                        value
                    )),
                )
            });
        }

        if attribute.is("Max-Age") {
            let Some(value) = attribute.value else {
                return Some(ctx.report_with(
                    &COOKIE_MAX_AGE_MISSING,
                    about("Set-Cookie attribute 'Max-Age' requires a numeric value"),
                ));
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
                    about(&format!(
                        "Set-Cookie attribute 'Max-Age' is not a valid integer: '{}'",
                        value
                    )),
                )
            });
        }

        if attribute.is("Expires") {
            let Some(value) = attribute.value else {
                return Some(ctx.report_with(
                    &COOKIE_EXPIRES_MISSING,
                    about("Set-Cookie attribute 'Expires' requires a HTTP-date value"),
                ));
            };
            // Two questions, and this used to ask only the first. § 4.1.1 writes
            // `sane-cookie-date` as `rfc1123-date`, so § 5.6.7's parse answers
            // whether the *sender* wrote the form it was asked for. It does not
            // answer what the recipient makes of it: § 5.2.1 sends a user agent
            // to § 5.1.1 for this attribute, and that algorithm reads hyphenated
            // dates, two-digit years and an unrecognised zone alike.
            //
            // Asking only the grammar named every one of those `http_date_malformed`
            // — an id whose sentence is that the field names no instant — while
            // every user agent on the wire expired the cookie exactly when the
            // server meant. The narrower id says the true half.
            // cite(RFC 6265 § 4.1.1): "expires-av        = "Expires=" sane-cookie-date"
            if crate::http_date::is_valid_http_date(value) {
                return None;
            }
            return Some(if crate::helpers::cookie::cookie_date_is_readable(value) {
                ctx.report_with(
                    &COOKIE_EXPIRES_MALFORMED,
                    about(&format!(
                        "Set-Cookie attribute 'Expires' is not an rfc1123-date, though § 5.1.1 reads it: '{}'",
                        value
                    )),
                )
            } else {
                ctx.report_with(
                    &HTTP_DATE_MALFORMED,
                    about(&format!(
                        "Set-Cookie attribute 'Expires' is not a valid HTTP-date: '{}'",
                        value
                    )),
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
                return Some(
                    ctx.report_with(&COOKIE_PATH_MISSING, about(COOKIE_PATH_MISSING_WORDING)),
                );
            };
            return (!value.starts_with('/')).then(|| {
                ctx.report_with(
                    &COOKIE_PATH_LEADING_SLASH_MISSING,
                    about(&format!(
                        "Set-Cookie attribute 'Path' should start with '/': '{}'",
                        value
                    )),
                )
            });
        }

        if attribute.is("Domain") {
            let Some(value) = attribute.value else {
                return Some(
                    ctx.report_with(&COOKIE_DOMAIN_MISSING, about(COOKIE_DOMAIN_MISSING_WORDING)),
                );
            };
            if value.is_empty() {
                return Some(ctx.report_with(
                    &COOKIE_DOMAIN_EMPTY,
                    about("Set-Cookie attribute 'Domain' must not be empty"),
                ));
            }
            // A space inside a host name is the *name's* defect and not the
            // attribute's: the same octet in a `Host`, a `Forwarded` host or a
            // `From` mailbox reports under this id already.
            return value.contains(' ').then(|| {
                ctx.report_with(
                    &DOMAIN_NAME_WHITESPACE_OR_CONTROL_FORBIDDEN,
                    about(&format!(
                        "Set-Cookie attribute 'Domain' must not contain spaces: '{}'",
                        value
                    )),
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
"#
    }

    fn description(&self) -> &'static str {
        "Validate `Set-Cookie` attributes for syntactic correctness and common security consistency rules. This rule parses `Set-Cookie` header values and flags:\n\n- Invalid cookie-name tokens.\n- Malformed attributes (e.g., `Max-Age` non-numeric, `Expires` not an HTTP-date).\n- `Path` values that don't start with `/`.\n- `Domain` values that are empty or contain spaces.\n- `SameSite` values other than `Strict`, `Lax`, or `None`.\n- `SameSite=None` cookies that are not marked `Secure` (browser behaviour / compatibility requirement).\n- `Secure` and `HttpOnly` attributes that incorrectly include a value (they must be flags)."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_6265_4_1_1,
            RFC_6265_5_1_1,
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

    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::Presumed(crate::lint::Party::Server)
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
                label: Some("— two cookies, two findings, each naming its own"),
                snippet: "Set-Cookie: a=1; Max-Age=soon\nSet-Cookie: b=2; SameSite=maybe",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— Expires names no instant at all"),
                snippet: "Set-Cookie: SID=1; Expires=NotADate",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some(
                    "— the hyphenated form every user agent reads, which is still not the rfc1123-date § 4.1.1 asks a sender for",
                ),
                snippet: "Set-Cookie: SID=1; Expires=Wed, 27-Aug-2036 02:28:19 GMT",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— a bare token has no '=', so it is no cookie-pair at all"),
                snippet: "Set-Cookie: SID",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— a comma is outside cookie-octet"),
                snippet: "Set-Cookie: SID=abc,def",
            },
        ]
    }
}

impl Rule for CookieAttributeConsistent {
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
        // One finding per cookie, not one per response. `find_map` stood here
        // and stopped at the first line with anything wrong with it, so a
        // response setting a cookie with a malformed `Max-Age` beside one with
        // an unknown `SameSite` reported the first and was silent about the
        // second — a cookie the operator never learned about, under a rule that
        // had read it.
        resp.headers
            .get_all("set-cookie")
            .iter()
            // Read as octets, one field line at a time: `Set-Cookie` is
            // not a list, and § 4.1.1's grammar stops at `CHAR`, so an
            // octet above %x7F is the attribute reader's finding rather
            // than a verdict about the field's encoding.
            .filter_map(|line| {
                self.set_cookie_defect(&crate::helpers::headers::field_line_as_written(line), ctx)
            })
            .collect()
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

    /// A response is allowed to set many cookies, and this rule answers for
    /// each of them.
    ///
    /// `find_map` stood in the walk and stopped at the first line with
    /// anything wrong with it, so a malformed `Max-Age` on one cookie hid an
    /// unrecognised `SameSite` on the next — two different defects on two
    /// different cookies, one of them reported nowhere. Ten `Set-Cookie` lines
    /// is an ordinary response.
    #[test]
    fn every_cookie_on_the_response_is_answered_for() {
        use crate::test_helpers::make_test_transaction_with_response;
        let tx = make_test_transaction_with_response(
            200,
            &[
                ("set-cookie", "a=1; Max-Age=soon"),
                ("set-cookie", "b=2; SameSite=maybe"),
            ],
        );
        let rule = CookieAttributeConsistent;
        let found = crate::test_helpers::run_rule_all(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        let ids: Vec<&str> = found.iter().map(|v| v.violation.as_str()).collect();
        assert_eq!(
            ids,
            ["cookie_max_age_malformed", "cookie_same_site_invalid"]
        );
        assert!(
            found[0].message.ends_with("(cookie 'a')"),
            "{:?}",
            found[0].message
        );
        assert!(
            found[1].message.ends_with("(cookie 'b')"),
            "{:?}",
            found[1].message
        );
    }

    /// The same entry twice on one response, which is what a repeated field
    /// makes ordinary: without the cookie's name the two findings are one
    /// sentence written twice, and an operator reading them cannot tell how
    /// many cookies they have to fix or which.
    #[test]
    fn two_findings_of_one_entry_are_told_apart_by_the_cookie() {
        use crate::test_helpers::make_test_transaction_with_response;
        let tx = make_test_transaction_with_response(
            200,
            &[
                ("set-cookie", "session=1; SameSite=None"),
                ("set-cookie", "tracker=2; SameSite=None"),
            ],
        );
        let rule = CookieAttributeConsistent;
        let found = crate::test_helpers::run_rule_all(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert_eq!(found.len(), 2);
        assert!(found.iter().all(|v| v.violation == "cookie_secure_missing"));
        assert_ne!(found[0].message, found[1].message);
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
    }

    /// A line with no `=` has no cookie-name to be named by, and the sentence
    /// is left as it is rather than naming a cookie called nothing.
    #[test]
    fn a_line_with_no_name_is_not_named() {
        let v = check_set_cookie("SID").expect("a finding");
        assert_eq!(v.violation, "cookie_pair_equals_missing");
        assert!(!v.message.contains("(cookie"), "{:?}", v.message);
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
    // A bare token with no `=` at all: `cookie-pair` has no alternative
    // without one, so this is not a name with an empty value -- it is no
    // cookie-pair, and the cookie is lost the same way an empty pair loses
    // it. Was silently accepted; see `cookie_pair_equals_missing` below.
    #[case("SID", true)]
    #[case("", true)]
    // `cookie-value`'s own grammar, read for the first time: a comma and a
    // raw space are both outside `cookie-octet`.
    #[case("SID=abc,def", true)]
    #[case("SID=has space", true)]
    // The DQUOTE-wrapped alternative `cookie-value` offers, legal.
    #[case("SID=\"has space\"", true)]
    #[case("SID=\"abcdef\"", false)]
    fn set_cookie_cases(#[case] value: &str, #[case] expect_violation: bool) {
        let v = check_set_cookie(value);
        if expect_violation {
            assert!(v.is_some(), "expected violation for '{}', got none", value);
        } else {
            assert!(v.is_none(), "unexpected violation for '{}': {:?}", value, v);
        }
    }

    /// Which of the two `Expires` ids a value draws, and the rule is whether a
    /// user agent can read it. Every value here but the last two was taken off
    /// the wire from a widely used origin, and each one used to be reported as
    /// naming no instant.
    #[rstest]
    // rfc1123-date, so no finding at all.
    #[case("SID=1; Expires=Wed, 21 Oct 2015 07:28:00 GMT", None)]
    // `obs-date`: § 5.6.7 still parses the rfc850 form, spelled-out day and all.
    #[case("SID=1; Expires=Monday, 30-Aug-27 01:13:44 GMT", None)]
    // `-` is a § 5.1.1 delimiter, so this is `30 Aug 2026` to every user agent.
    #[case(
        "SID=1; Expires=Sun, 30-Aug-2026 02:23:34 GMT",
        Some("cookie_expires_malformed")
    )]
    // `year = 2*4DIGIT`, and 0-69 maps onto 20xx: this is 2027.
    #[case(
        "SID=1; Expires=Mon, 30-Aug-27 01:13:44 GMT",
        Some("cookie_expires_malformed")
    )]
    // No production matches the zone, so `UTC` is skipped and step 6 says UTC.
    #[case(
        "SID=1; Expires=Mon, 31 Aug 2026 00:16:39 UTC",
        Some("cookie_expires_malformed")
    )]
    // No time, no month, no year: § 5.1.1 fails too, so it names no instant.
    #[case("SID=1; Expires=NotADate", Some("http_date_malformed"))]
    // § 5.1.1 tokenizes this fine and then step 5 rejects the day-of-month.
    #[case(
        "SID=1; Expires=Sun, 32 Aug 2026 00:31:33 GMT",
        Some("http_date_malformed")
    )]
    // And the year floor, which is § 5.1.1's own and not the grammar's.
    #[case(
        "SID=1; Expires=Sun, 30-Aug-1500 02:23:34 GMT",
        Some("http_date_malformed")
    )]
    fn expires_reports_what_a_user_agent_can_read(
        #[case] value: &str,
        #[case] expected: Option<&str>,
    ) {
        let found = check_set_cookie(value);
        match expected {
            None => assert!(
                found.is_none(),
                "unexpected violation for '{value}': {found:?}"
            ),
            Some(id) => {
                let found =
                    found.unwrap_or_else(|| panic!("expected {id} for '{value}', got none"));
                assert_eq!(found.violation, id, "wrong id for '{value}'");
            }
        }
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let rule = CookieAttributeConsistent;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
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
            body_interrupted: false,
            trailers: None,
        });

        // A field line holding an octet above %x7F, in the cookie-name half
        // of an otherwise well-formed pair -- the `=` is what keeps this test
        // about the name's own character class rather than about the missing
        // `=` `cookie_pair_equals_missing` now reports first for a bare
        // octet with none.
        tx.response
            .as_mut()
            .unwrap()
            .headers
            .append("set-cookie", HeaderValue::from_bytes(&[0xff, b'=', b'1'])?);

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
        //
        // The name is also what the finding is about, so it is named twice —
        // once as the character that is wrong and once as the cookie the wrong
        // character belongs to. That reads oddly for a one-octet name and is
        // exactly right beside a second cookie on the same response, which is
        // the case the suffix exists for.
        let v = v.expect("a finding");
        assert_eq!(
            v.message,
            "Set-Cookie cookie-name contains invalid character: '\u{ff}' (cookie '\u{ff}')"
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

    /// `cookie_pair_valid` declares this id on the request side; this is the
    /// same id reported here, on `Set-Cookie`, for the same production.
    #[test]
    fn a_bare_token_with_no_equals_is_no_cookie_pair() {
        let v = check_set_cookie("SID").expect("a finding");
        assert_eq!(v.violation, "cookie_pair_equals_missing");
    }

    /// The other half of `cookie-pair` that had never been read: `Set-Cookie`
    /// validated `cookie-name` and skipped `cookie-value` entirely.
    #[test]
    fn a_cookie_value_octet_outside_cookie_octet_is_reported() {
        let v = check_set_cookie("SID=abc,def").expect("a finding");
        assert_eq!(v.violation, "cookie_value_character_forbidden");
        assert!(v.message.contains("','"), "{}", v.message);
    }

    /// The DQUOTE-wrapped alternative `cookie-value` offers is read the same
    /// way on both sides of the cookie: legal when its content is, illegal
    /// when a forbidden octet -- here, the space -- is inside the quotes too.
    #[test]
    fn a_quoted_cookie_value_is_read_inside_its_quotes() {
        assert!(check_set_cookie("SID=\"abcdef\"").is_none());
        let v = check_set_cookie("SID=\"has space\"").expect("a finding");
        assert_eq!(v.violation, "cookie_value_character_forbidden");
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
            body_interrupted: false,
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
