// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::content_security_policy::{
    CONTENT_SECURITY_POLICY_BASE64_VALUE_EMPTY, CONTENT_SECURITY_POLICY_BASE64_VALUE_MALFORMED,
    CONTENT_SECURITY_POLICY_DIRECTIVE_EMPTY,
    CONTENT_SECURITY_POLICY_DIRECTIVE_NAME_CHARACTER_FORBIDDEN, CONTENT_SECURITY_POLICY_EMPTY,
    CONTENT_SECURITY_POLICY_SOURCE_DELIMITER_MISSING, CONTENT_SECURITY_POLICY_SOURCE_EMPTY,
    CSP3_2_2, CSP3_2_3, CSP3_2_3_1, CSP3_3_2,
};
use crate::violations::list::{LIST_MEMBER_EMPTY, RFC_9110_5_6_1_1};
use crate::violations::ViolationDef;

/// The policy and directive level of the field, which is what the rule reads
/// before it reaches a source expression.
///
/// Eight entries. Three are ranked apart where the rule's one severity could
/// not — a header enforcing nothing at all, a directive a user agent will not
/// recognise and therefore not apply, and a stray semicolon in a policy that
/// still works. The four below them are the source expressions, and they sit
/// at one level: each is a source the user agent will parse as something else
/// or drop, and in every case the policy stops doing what its author wrote.
/// The eighth is the list's: a line is `1#serialized-policy`, and a stray comma
/// in it is the empty element every other `#` field's reader reports.
static DECLARED: &[&ViolationDef] = &[
    &CONTENT_SECURITY_POLICY_EMPTY,
    &LIST_MEMBER_EMPTY,
    &CONTENT_SECURITY_POLICY_DIRECTIVE_EMPTY,
    &CONTENT_SECURITY_POLICY_DIRECTIVE_NAME_CHARACTER_FORBIDDEN,
    &CONTENT_SECURITY_POLICY_SOURCE_DELIMITER_MISSING,
    &CONTENT_SECURITY_POLICY_SOURCE_EMPTY,
    &CONTENT_SECURITY_POLICY_BASE64_VALUE_EMPTY,
    &CONTENT_SECURITY_POLICY_BASE64_VALUE_MALFORMED,
];

/// Basic Content-Security-Policy validation focusing on directive name syntax,
/// minimal value sanity checks (quoted keywords and simple hash/nonce forms),
/// and obvious structural errors (empty header, empty directive, non-utf8).
///
/// This rule is intentionally conservative and avoids strict enforcement of
/// full CSP grammar; it aims to catch obvious syntactic problems and misuses.
pub struct ContentSecurityPolicyValid;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const CSP3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "CSP3",
    section: None,
    url: "https://www.w3.org/TR/CSP3/",
    note: "W3C Content Security Policy Level 3 — directive and source-list syntax",
};
const MDN_CONTENT_SECURITY_POLICY: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "MDN Content-Security-Policy",
    section: None,
    url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy",
    note: "Mozilla MDN overview and directive examples",
};

/// The three hash algorithms a `hash-source` may name. They were written out
/// three times, in two places each, with a message per algorithm — which is why
/// they are one list now: the check does not vary by algorithm, only the
/// example in the wording does.
// cite(CSP3 § 2.3): "hash-algorithm = "sha256" / "sha384" / "sha512""
const HASH_PREFIXES: [&str; 3] = ["sha256-", "sha384-", "sha512-"];

/// The two response fields § 3 delivers a policy in, each with the name a
/// finding about it has to say.
///
/// § 3.1 and § 3.2 write the same `1#serialized-policy` and differ only in
/// whether the user agent enforces what it parses. This list is not shared with
/// `content_security_policy_and_frame_options_consistent`, which reads the
/// enforced field alone and is right to: that rule asks what a policy *does*,
/// and a report-only one does nothing.
const POLICY_FIELDS: [(&str, &str); 2] = [
    ("Content-Security-Policy", "content-security-policy"),
    (
        "Content-Security-Policy-Report-Only",
        "content-security-policy-report-only",
    ),
];

impl ContentSecurityPolicyValid {
    /// One `;`-separated directive: its name, then each of its source
    /// expressions.
    ///
    /// **Every source expression the directive names is answered.** A
    /// `serialized-source-list` is written one `source-expression` per position
    /// -- each an origin, a scheme, a nonce or a hash the policy permits -- so
    /// `script-src 'nonce-' 'sha256-'` names two the browser cannot resolve and
    /// is two things to correct. The list is separated by whitespace rather
    /// than by commas, which is the only reason this walk is not the same
    /// construct as `1#element`; the sender's obligation is written per
    /// position either way.
    ///
    /// The directive-name defect does not end the reading of the sources: a
    /// name the production does not admit is the operator's to fix, and so is
    /// each unresolvable source beside it.
    fn directive_defects(
        &self,
        shown: &'static str,
        directive: &str,
        position: usize,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        if directive.is_empty() {
            // Only the first position, because only the first is unbracketed.
            // `serialized-policy` puts every directive after the first inside
            // an optional group, so a trailing `;`, a doubled `;;` and a `; ;`
            // are zero-directive repetitions the production generates — the
            // same shape a trailing `;` has in a `media-type`'s parameters.
            // Reporting them was one of the two readings a `;` has and the
            // wrong one.
            if position > 0 {
                return Vec::new();
            }
            // The sentence names no position: this is only ever the first,
            // and "at position 0" read as a character offset into the value.
            return vec![ctx.report_with(
                &CONTENT_SECURITY_POLICY_DIRECTIVE_EMPTY,
                format!("{shown} opens a policy with a ';' and names no directive before it"),
            )];
        }

        // ASCII whitespace, not Unicode: the value is one `char` per octet, so
        // %xA0 is an `obs-text` octet the sender wrote inside a token and not a
        // separator between two of them.
        let mut parts = directive.split_ascii_whitespace();
        let name = parts.next().expect(
            "split_ascii_whitespace yields at least one item since the directive is not empty",
        );

        // A CSP directive-name is narrower than the HTTP `token`: only
        // letters, digits and `-`. Enforcing `token` here let typos like
        // `default_src` (underscore is a legal tchar) pass unflagged.
        // cite(CSP3 § 2.3): "directive-name = 1*( ALPHA / DIGIT / "-" )"
        let mut out = Vec::new();
        if let Some(c) = name
            .chars()
            .find(|c| !(c.is_ascii_alphanumeric() || *c == '-'))
        {
            out.push(ctx.report_with(
                &CONTENT_SECURITY_POLICY_DIRECTIVE_NAME_CHARACTER_FORBIDDEN,
                // `position` counts directives, not characters, and the
                // sentence used to print it bare -- "at position 2" for the
                // third directive, which a reader counting characters in
                // `b@d` took to be the `d`. Counted from one, as the member
                // numbers other findings print are.
                format!(
                    "Invalid character {} in {shown} directive-name '{}', in directive {} of its policy",
                    crate::helpers::shown::describe_char(c),
                    crate::helpers::shown::shown_in_finding(name),
                    position + 1
                ),
            ));
        }

        out.extend(
            parts.filter_map(|source| self.source_expression_defect(shown, source, name, ctx)),
        );
        out
    }

    /// One source expression, quoted or not.
    ///
    /// The quoted forms are checked for being closed and non-empty, and for a
    /// nonce or hash that names no value. The unquoted ones are checked for
    /// being a nonce or hash at all: those two *must* be quoted, so an unquoted
    /// one is not a source expression the policy will enforce.
    ///
    /// This is deliberately not a full source-expression grammar — the rule
    /// catches the common, obvious mistakes and says so in its description.
    fn source_expression_defect(
        &self,
        shown: &'static str,
        source: &str,
        directive: &str,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Option<Violation> {
        if source.starts_with('\'') {
            // An opening quote and no closing one: the same defect as writing
            // no quotes at all, since `nonce-source` and `hash-source` print
            // both of them inside the production.
            if !source.ends_with('\'') || source.len() < 2 {
                return Some(ctx.report_with(
                    &CONTENT_SECURITY_POLICY_SOURCE_DELIMITER_MISSING,
                    format!(
                        "Unterminated single-quoted source expression '{}' in {shown} directive '{}'",
                        source, directive
                    ),
                ));
            }
            let inner = &source[1..source.len() - 1];
            if inner.is_empty() {
                return Some(ctx.report_with(
                    &CONTENT_SECURITY_POLICY_SOURCE_EMPTY,
                    format!(
                        "Empty single-quoted source expression '{}' in {shown} directive '{}'",
                        source, directive
                    ),
                ));
            }

            if let Some(nonce) = inner.strip_prefix("nonce-") {
                if nonce.is_empty() {
                    return Some(ctx.report_with(
                        &CONTENT_SECURITY_POLICY_BASE64_VALUE_EMPTY,
                        format!("Empty nonce value in {shown} directive '{}'", directive),
                    ));
                }
                // Unicode whitespace rather than ASCII, and the difference is
                // the whole reachable set: a source list is cut apart on
                // `required-ascii-whitespace`, so an ordinary space never
                // arrives inside a source expression and %xA0 does.
                if nonce.chars().any(char::is_whitespace) {
                    return Some(ctx.report_with(
                        &CONTENT_SECURITY_POLICY_BASE64_VALUE_MALFORMED,
                        format!(
                            "Invalid nonce value containing whitespace in {shown} directive '{}'",
                            directive
                        ),
                    ));
                }
            }

            if HASH_PREFIXES
                .iter()
                .any(|prefix| inner.strip_prefix(prefix) == Some(""))
            {
                return Some(ctx.report_with(
                    &CONTENT_SECURITY_POLICY_BASE64_VALUE_EMPTY,
                    format!("Empty hash value in {shown} directive '{}'", directive),
                ));
            }

            // Nothing below applies to a value that opens with a quote.
            return None;
        }

        // Unquoted. The value half is named first where both are wrong,
        // because putting quotes around nothing fixes nothing.
        if let Some(nonce) = source.strip_prefix("nonce-") {
            if nonce.is_empty() {
                return Some(ctx.report_with(
                    &CONTENT_SECURITY_POLICY_BASE64_VALUE_EMPTY,
                    format!("Empty nonce value in {shown} directive '{}'", directive),
                ));
            }
            return Some(ctx.report_with(
                &CONTENT_SECURITY_POLICY_SOURCE_DELIMITER_MISSING,
                format!(
                    "Nonce source expressions in {shown} MUST be single-quoted (e.g., 'nonce-...')"
                ),
            ));
        }

        let prefix = HASH_PREFIXES
            .iter()
            .find(|prefix| source.starts_with(**prefix))?;
        if source.len() == prefix.len() {
            return Some(ctx.report_with(
                &CONTENT_SECURITY_POLICY_BASE64_VALUE_EMPTY,
                format!("Empty hash value in {shown} directive '{}'", directive),
            ));
        }
        Some(ctx.report_with(
            &CONTENT_SECURITY_POLICY_SOURCE_DELIMITER_MISSING,
            format!(
                "Hash source expressions in {shown} MUST be single-quoted (e.g., '{}...')",
                prefix
            ),
        ))
    }
}

impl RuleMeta for ContentSecurityPolicyValid {
    fn id(&self) -> &'static str {
        "content_security_policy_valid"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn description(&self) -> &'static str {
        "Validate basic policy syntax in responses, in both fields § 3 delivers a policy in — `Content-Security-Policy` and `Content-Security-Policy-Report-Only`, whose § 3.1 and § 3.2 write the identical `1#serialized-policy`. The report-only field is the one it matters most to read: § 3.2 exists so a developer can watch a policy while *monitoring (but not enforcing)* its effects, so a directive the user agent cannot parse breaks nothing and is never noticed. Each finding names the field it read. This rule checks that the header value is UTF-8, not empty, directives are present and well-formed (directive names follow CSP's `directive-name = 1*( ALPHA / DIGIT / \"-\" )` grammar — narrower than the HTTP `token`), and common structural issues are flagged (unterminated single-quoted keywords, empty directives due to trailing semicolons, empty nonces/hashes).\n\nThis rule is intentionally conservative: it is not a full CSP grammar validator, but catches common, obvious mistakes and misconfigurations."
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::Presumed(crate::lint::Party::Server)
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            CSP3,
            CSP3_2_2,
            CSP3_2_3,
            CSP3_2_3_1,
            CSP3_3_2,
            RFC_9110_5_6_1_1,
            MDN_CONTENT_SECURITY_POLICY,
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nContent-Security-Policy: default-src 'self'; script-src 'nonce-abc123' https://example.com; upgrade-insecure-requests",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nContent-Security-Policy:",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nContent-Security-Policy: def@ult-src 'self'",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(a trailing `;` is a zero-directive repetition the production generates)"),
                snippet: "HTTP/1.1 200 OK\nContent-Security-Policy: default-src 'self';",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(two policies on one line, each enforced: the form two field lines take once a recipient joins them)"),
                snippet: "HTTP/1.1 200 OK\nContent-Security-Policy: default-src 'self', script-src 'none'",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nContent-Security-Policy: default-src 'self",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(the other field § 3 delivers a policy in, where nothing breaking is the point)"),
                snippet: "HTTP/1.1 200 OK\nContent-Security-Policy-Report-Only: def@ult-src 'self'",
            },
        ]
    }
}

impl Rule for ContentSecurityPolicyValid {
    fn needs_response(&self) -> bool {
        true
    }

    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // One finding per defective directive, in every policy the response
        // carries. A server may send several `Content-Security-Policy` field
        // lines and each is a policy enforced in its own right -- which is why
        // the walk below reads them all rather than stopping at the first that
        // has something wrong with it.
        let findings = || -> Vec<Violation> {
            let mut out = Vec::new();
            let Some(resp) = tx.response.as_ref() else {
                return out;
            };

            // Read as the octets the sender wrote. A `directive-name` is
            // `1*( ALPHA / DIGIT / "-" )`, so an octet outside visible US-ASCII is
            // a character the name cannot hold and the check in
            // `directive_defect` names it — where the deleted branch could only
            // say the whole policy was unreadable.
            //
            // Both fields § 3 delivers a policy in. § 3.1 and § 3.2 write the
            // identical `1#serialized-policy`, and the reason the report-only
            // field is the *worse* one to leave unread is § 3.2's own purpose:
            // it exists so a developer can deploy a policy while "monitoring
            // (but not enforcing) their effects", so a directive a browser
            // cannot parse breaks nothing, reports nothing, and is never
            // noticed. The consistency rule next door skips this field on
            // purpose — a policy that enforces nothing cannot conflict with
            // `X-Frame-Options` — but that is an argument about enforcement,
            // and nothing about enforcement bears on whether the value parses.
            // cite(CSP3 § 3.2): "Content-Security-Policy-Report-Only = 1#serialized-policy"
            for (shown, policy) in POLICY_FIELDS.into_iter().flat_map(|(shown, key)| {
                crate::helpers::headers::field_lines_as_written(&resp.headers, key)
                    .into_iter()
                    .map(move |policy| (shown, policy))
            }) {
                // Policies before directives. A field line is a comma-delimited
                // series of serialized policies, each enforced on its own, and
                // RFC 9110 § 5.3 lets any recipient join two lines into one
                // with a comma -- so a `;` split alone read `default-src
                // 'self', script-src 'none'` as one directive holding an
                // unclosed `'self',`. The cut is naive and exact: a
                // `directive-value` admits every visible octet but `;` and
                // `,`, so no comma is ever data inside a policy.
                //
                // cite(CSP3 § 2.2): "a comma-delimited series of serialized CSPs"
                // cite(CSP3 § 2.2.2): "For each token returned by extracting header list values given Content-Security-Policy and response’s header list"
                // cite(CSP3 § 2.3): "Directive values may contain whitespace and VCHAR characters, ; excluding ";" and ","."
                let policies: Vec<&str> =
                    crate::helpers::list::sender_list_members(&policy).collect();

                if policies.iter().all(|p| p.is_empty()) {
                    // The line names no policy at all, so there are no
                    // directives in it to read: this is the whole of what is
                    // wrong with this line, and the next line is its own.
                    out.push(ctx.report_with(
                        &CONTENT_SECURITY_POLICY_EMPTY,
                        format!("{shown} header MUST not be empty"),
                    ));
                    continue;
                }

                // A user agent skips a policy with no directives, which is the
                // recipient's half; the sender's is § 5.6.1.1's, and the empty
                // member is the evidence the skip erases. Once per line, since
                // the line is where the sender put the stray comma.
                // cite(RFC 9110 § 5.6.1.1): "In any production that uses the list construct, a sender MUST NOT generate empty list elements."
                if policies.iter().any(|p| p.is_empty()) {
                    out.push(ctx.report_with(
                        &LIST_MEMBER_EMPTY,
                        format!(
                            "{shown} '{}' holds an empty policy between its commas, and a \
                             sender must not generate an empty list element",
                            crate::helpers::shown::shown_in_finding(&policy)
                        ),
                    ));
                }

                for policy in policies.into_iter().filter(|p| !p.is_empty()) {
                    for (position, directive) in policy.split(';').enumerate() {
                        out.extend(self.directive_defects(
                            shown,
                            crate::helpers::headers::trim_ows(directive),
                            position,
                            ctx,
                        ));
                    }
                }
            }

            out
        };
        findings()
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ContentSecurityPolicyValid;

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;
    use rstest::rstest;

    fn make_cfg() -> crate::config::Config {
        crate::test_helpers::make_test_config_with_enabled_rules(&["content_security_policy_valid"])
    }

    /// **Both fields § 3 delivers a policy in, and each finding names the one
    /// it read.**
    ///
    /// `Content-Security-Policy-Report-Only: def@ult-src 'self'` drew nothing,
    /// where the identical value in the enforced field is a finding — § 3.1 and
    /// § 3.2 write the same `1#serialized-policy`. The message is asserted
    /// because every arm of this rule named the enforced field or said "CSP",
    /// so a second reader through them would have named the wrong field on a
    /// true finding.
    #[rstest]
    #[case("content-security-policy", "Content-Security-Policy")]
    #[case(
        "content-security-policy-report-only",
        "Content-Security-Policy-Report-Only"
    )]
    fn a_policy_is_read_in_both_fields_that_deliver_it(#[case] key: &str, #[case] shown: &str) {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().expect("a response").headers =
            crate::test_helpers::make_headers_from_pairs(&[(key, "def@ult-src 'self'")]);
        let found = crate::test_helpers::run_rule(
            &ContentSecurityPolicyValid,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &make_cfg(),
        )
        .unwrap_or_else(|| panic!("nothing reported for {key}"));
        assert_eq!(
            found.violation,
            "content_security_policy_directive_name_character_forbidden"
        );
        assert!(
            found.message.contains(shown),
            "a finding about {key} says {:?}, which does not name the field it read",
            found.message
        );
    }

    #[rstest]
    #[case(None, false)]
    #[case(Some("default-src 'self'"), false)]
    #[case(
        Some("script-src 'nonce-abc123' https://example.com; default-src 'none'"),
        false
    )]
    #[case(Some("upgrade-insecure-requests; default-src 'self'"), false)]
    #[case(Some(""), true)]
    fn csp_basic_cases(#[case] header: Option<&str>, #[case] expect_violation: bool) {
        let rule = ContentSecurityPolicyValid;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        if let Some(h) = header {
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[("content-security-policy", h)]);
        }

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
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
    }

    #[test]
    fn invalid_directive_name_reports_violation() {
        let rule = ContentSecurityPolicyValid;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "def@ult-src 'self'",
        )]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .unwrap();
        assert!(v.message.contains("Invalid character"));
    }

    #[test]
    fn underscore_in_directive_name_is_violation() {
        // CSP3 `directive-name = 1*( ALPHA / DIGIT / "-" )` forbids `_`; the HTTP
        // token grammar the rule used to apply accepted it, so `default_src` (a
        // plausible typo of `default-src`) slipped through unflagged.
        let rule = ContentSecurityPolicyValid;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "default_src 'self'",
        )]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .unwrap();
        assert!(v.message.contains("Invalid character") && v.message.contains('_'));
    }

    /// `serialized-policy` brackets every directive after the first, so these
    /// three are zero-directive repetitions the grammar produces. All three
    /// were reported as an empty directive, which is one of the two readings a
    /// `;` has and the wrong one.
    #[rstest]
    #[case::trailing("default-src \'self\'; ")]
    #[case::doubled("default-src \'self\';;;script-src \'self\'")]
    #[case::spaced("default-src \'self\'; ; script-src \'self\'")]
    fn a_semicolon_the_grammar_brackets_is_not_a_finding(#[case] policy: &str) {
        let rule = ContentSecurityPolicyValid;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-security-policy", policy)]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &make_cfg(),
        );
        assert!(v.is_none(), "{policy:?}: {v:?}");
    }

    /// **A line is a comma-delimited series of policies, and a recipient may
    /// have made it one.** RFC 9110 § 5.3 lets any recipient join two field
    /// lines with a comma, so the two policies an origin sent on two lines
    /// arrive as one. Read as one policy, the first of these drew
    /// "Unterminated single-quoted source expression ''self','". The third
    /// opens its second policy with a `;`, which is that policy's first
    /// position and not a bracketed repetition of the first policy's.
    #[rstest]
    #[case::keyword_before_comma("default-src 'self', script-src 'none'", None)]
    #[case::no_space("default-src 'self',script-src 'none'", None)]
    #[case::three("default-src 'self', img-src *, frame-ancestors 'none'", None)]
    #[case::second_opens_with_semicolon(
        "default-src 'self', ; script-src 'none'",
        Some("content_security_policy_directive_empty")
    )]
    #[case::defect_in_second(
        "default-src 'self', def@ult-src 'self'",
        Some("content_security_policy_directive_name_character_forbidden")
    )]
    fn a_line_is_read_one_policy_at_a_time(#[case] line: &str, #[case] expected: Option<&str>) {
        for key in [
            "content-security-policy",
            "content-security-policy-report-only",
        ] {
            let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[(key, line)]);
            let found: Vec<_> = crate::test_helpers::run_rule_all(
                &ContentSecurityPolicyValid,
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &make_cfg(),
            )
            .into_iter()
            .map(|v| v.violation)
            .collect();
            assert_eq!(found, Vec::from_iter(expected), "{key}: {line:?}");
        }
    }

    /// A stray comma is an empty element of `1#serialized-policy`, which a
    /// user agent skips and a sender must not write. A line of nothing but
    /// commas names no policy, which is the entry for an empty field.
    #[rstest]
    #[case::trailing("default-src 'self',", "list_member_empty")]
    #[case::leading(", default-src 'self'", "list_member_empty")]
    #[case::doubled("default-src 'self',, script-src 'none'", "list_member_empty")]
    #[case::only_commas(" , ,", "content_security_policy_empty")]
    fn an_empty_policy_in_the_list(#[case] line: &str, #[case] expected: &str) {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-security-policy", line)]);
        let found = crate::test_helpers::run_rule_all(
            &ContentSecurityPolicyValid,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &make_cfg(),
        );
        assert_eq!(
            found
                .iter()
                .map(|v| v.violation.as_str())
                .collect::<Vec<_>>(),
            [expected],
            "{line:?}"
        );
        if expected == "list_member_empty" {
            assert_eq!(
                found[0].message,
                format!(
                    "Content-Security-Policy '{line}' holds an empty policy between its commas, \
                     and a sender must not generate an empty list element"
                )
            );
        }
    }

    /// The one position the production does not bracket.
    #[test]
    fn a_policy_that_opens_with_a_semicolon_names_no_first_directive() {
        let rule = ContentSecurityPolicyValid;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "; default-src 'self'",
        )]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &make_cfg(),
        )
        .expect("a finding");
        assert_eq!(v.violation, "content_security_policy_directive_empty");
    }

    #[test]
    fn unterminated_single_quote_is_violation() {
        let rule = ContentSecurityPolicyValid;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "default-src 'self",
        )]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .unwrap();
        assert!(v.message.contains("Unterminated"));
    }

    #[test]
    fn empty_single_quoted_keyword_is_violation() {
        let rule = ContentSecurityPolicyValid;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "default-src ''",
        )]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .unwrap();
        assert!(v.message.contains("Empty single-quoted"));
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "content_security_policy_valid");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn an_obs_text_octet_in_a_directive_name_is_named() {
        let rule = ContentSecurityPolicyValid;
        let cfg = make_cfg();

        let bad = HeaderValue::from_bytes(&[0xff]).unwrap();
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut headers = crate::test_helpers::make_headers_from_pairs(&[]);
        headers.insert("content-security-policy", bad);
        tx.response.as_mut().unwrap().headers = headers;

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .unwrap();
        assert_eq!(
            v.message,
            "Invalid character 0xFF in Content-Security-Policy directive-name '\u{ff}', in directive 1 of its policy"
        );
    }

    #[test]
    fn empty_nonce_reports_violation() {
        let rule = ContentSecurityPolicyValid;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "script-src nonce-",
        )]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .unwrap();
        assert!(v.message.contains("Empty nonce value"));
    }

    #[test]
    fn empty_hash_reports_violation() {
        let rule = ContentSecurityPolicyValid;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "script-src sha256-",
        )]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .unwrap();
        assert!(v.message.contains("Empty hash value"));
    }

    /// **Every source expression the policy names is answered, in every
    /// directive, on every line.** A `serialized-source-list` is written one
    /// `source-expression` per position and a policy one directive per `;`, so
    /// a response carrying four unresolvable sources across two directives and
    /// two lines is four things to correct — and a walk that returned at the
    /// first of them named one.
    #[test]
    fn every_defective_source_is_reported_across_directives_and_lines() {
        let rule = ContentSecurityPolicyValid;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "script-src 'nonce-' 'sha256-'; img-src nonce-abc",
        )]);
        headers.append(
            "content-security-policy",
            HeaderValue::from_static("def@ult-src 'unterminated"),
        );
        tx.response.as_mut().unwrap().headers = headers;

        let found = crate::test_helpers::run_rule_all(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        let ids: Vec<_> = found.iter().map(|v| v.violation.as_str()).collect();
        // Two empty values in one directive: the walk did not end at the first.
        assert_eq!(
            ids.iter()
                .filter(|i| **i == "content_security_policy_base64_value_empty")
                .count(),
            2,
            "{ids:?}"
        );
        // A second directive, behind the first, and a second field line behind
        // the whole policy.
        assert!(
            ids.contains(&"content_security_policy_source_delimiter_missing"),
            "{ids:?}"
        );
        assert!(
            ids.contains(&"content_security_policy_directive_name_character_forbidden"),
            "the second field line is read too: {ids:?}"
        );
    }

    #[test]
    fn multiple_header_fields_with_one_invalid_reports_violation() {
        let rule = ContentSecurityPolicyValid;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "default-src 'self'",
        )]);
        headers.append(
            "content-security-policy",
            HeaderValue::from_static("def@ult-src 'self'"),
        );
        tx.response.as_mut().unwrap().headers = headers;

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .unwrap();
        assert!(v.message.contains("Invalid character"));
    }

    #[test]
    fn scope_and_id_are_expected() {
        let rule = ContentSecurityPolicyValid;
        assert_eq!(rule.id(), "content_security_policy_valid");
        assert!(rule.needs_response());
    }

    #[test]
    fn whitespace_only_header_is_violation() {
        let rule = ContentSecurityPolicyValid;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-security-policy", "   ")]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .unwrap();
        assert!(v.message.contains("MUST not be empty"));
    }

    /// The source-expression half, each shape pinned to the entry it draws. The
    /// two nonce rows and the two hash rows are the point: one `base64-value`
    /// production is carried by both, so a nonce with no nonce in it and a
    /// `sha256-` with no digest after it are one defect and one id.
    #[rstest]
    #[case(
        "script-src 'nonce-abc",
        "content_security_policy_source_delimiter_missing"
    )]
    #[case(
        "script-src nonce-abc",
        "content_security_policy_source_delimiter_missing"
    )]
    #[case(
        "script-src sha256-abc",
        "content_security_policy_source_delimiter_missing"
    )]
    #[case("script-src ''", "content_security_policy_source_empty")]
    #[case("script-src 'nonce-'", "content_security_policy_base64_value_empty")]
    #[case("script-src 'sha384-'", "content_security_policy_base64_value_empty")]
    #[case("script-src nonce-", "content_security_policy_base64_value_empty")]
    #[case("script-src sha512-", "content_security_policy_base64_value_empty")]
    #[case(
        "script-src 'nonce-a\u{a0}b'",
        "content_security_policy_base64_value_malformed"
    )]
    fn the_source_expression_findings_name_their_entries(#[case] policy: &str, #[case] id: &str) {
        let rule = ContentSecurityPolicyValid;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_octet_pairs(
            &[("content-security-policy", policy.as_bytes())],
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &make_cfg(),
        )
        .expect("a finding");
        assert_eq!(v.violation, id, "{policy:?}");
    }

    /// The three entries this half of the rule reports, each pinned to its id.
    #[rstest]
    #[case::blank("", "content_security_policy_empty")]
    #[case::leading_semicolon("; default-src 'self'", "content_security_policy_directive_empty")]
    #[case::underscore(
        "default_src 'self'",
        "content_security_policy_directive_name_character_forbidden"
    )]
    fn the_policy_level_findings_name_their_entries(#[case] policy: &str, #[case] id: &str) {
        let rule = ContentSecurityPolicyValid;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-security-policy", policy)]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &make_cfg(),
        )
        .expect("a finding");
        assert_eq!(v.violation, id, "{policy:?}");
    }

    #[test]
    fn nonce_with_whitespace_is_violation() {
        let rule = ContentSecurityPolicyValid;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "script-src nonce-abc def",
        )]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .unwrap();
        assert!(v.message.contains("single-quoted"));
    }

    #[test]
    fn quoted_nonce_with_whitespace_is_violation() {
        let rule = ContentSecurityPolicyValid;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "script-src 'nonce-abc def'",
        )]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .unwrap();
        assert!(v.message.contains("Invalid nonce value") || v.message.contains("Unterminated"));
    }

    #[test]
    fn quoted_empty_nonce_reports_violation() {
        let rule = ContentSecurityPolicyValid;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "script-src 'nonce-'",
        )]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .unwrap();
        assert!(v.message.contains("Empty nonce value"));
    }

    #[test]
    fn unquoted_hash_reports_single_quoted_violation() {
        let rule = ContentSecurityPolicyValid;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "script-src sha256-abc",
        )]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .unwrap();
        assert!(v.message.contains("single-quoted"));
    }

    #[test]
    fn quoted_empty_hash_reports_violation() {
        let rule = ContentSecurityPolicyValid;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "script-src 'sha256-'",
        )]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .unwrap();
        assert!(v.message.contains("Empty hash value"));
    }

    #[test]
    fn unquoted_sha384_reports_single_quoted_violation() {
        let rule = ContentSecurityPolicyValid;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "script-src sha384-abc",
        )]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .unwrap();
        assert!(v.message.contains("single-quoted"));
    }

    #[test]
    fn quoted_sha512_empty_hash_reports_violation() {
        let rule = ContentSecurityPolicyValid;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "script-src 'sha512-'",
        )]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .unwrap();
        assert!(v.message.contains("Empty hash value"));
    }

    #[test]
    fn unquoted_sha512_reports_single_quoted_violation() {
        let rule = ContentSecurityPolicyValid;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "script-src sha512-abc",
        )]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .unwrap();
        assert!(v.message.contains("single-quoted"));
    }

    #[test]
    fn quoted_hash_is_accepted() {
        let rule = ContentSecurityPolicyValid;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "script-src 'sha256-abc' https://example.com",
        )]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none(), "unexpected violation: {:?}", v);
    }

    #[test]
    fn quoted_sha384_is_accepted() {
        let rule = ContentSecurityPolicyValid;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "script-src 'sha384-abc' https://example.com",
        )]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none(), "unexpected violation: {:?}", v);
    }

    #[test]
    fn quoted_sha512_is_accepted() {
        let rule = ContentSecurityPolicyValid;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "script-src 'sha512-abc' https://example.com",
        )]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none(), "unexpected violation: {:?}", v);
    }

    #[test]
    fn quoted_nonce_and_hashes_accepted() {
        let rule = ContentSecurityPolicyValid;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "script-src 'nonce-abc' 'sha256-abc' 'sha384-abc' 'sha512-abc' default-src 'self'",
        )]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none(), "unexpected violation: {:?}", v);
    }

    #[test]
    fn quoted_sha384_empty_hash_reports_violation() {
        let rule = ContentSecurityPolicyValid;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "script-src 'sha384-'",
        )]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .unwrap();
        assert!(v.message.contains("Empty hash value"));
    }

    #[test]
    fn unquoted_sha384_empty_hash_reports_violation() {
        let rule = ContentSecurityPolicyValid;
        let cfg = make_cfg();
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "script-src sha384-",
        )]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .unwrap();
        assert!(v.message.contains("Empty hash value"));
    }

    #[test]
    fn unquoted_sha512_empty_hash_reports_violation() {
        let rule = ContentSecurityPolicyValid;
        let cfg = make_cfg();
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "script-src sha512-",
        )]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .unwrap();
        assert!(v.message.contains("Empty hash value"));
    }

    #[test]
    fn response_absent_returns_none() {
        let rule = ContentSecurityPolicyValid;
        let cfg = make_cfg();
        let tx = crate::test_helpers::make_test_transaction();
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    /// The number a directive-name finding prints is the directive's, counted
    /// from one: `b@d` in the third directive used to read "at position 2",
    /// and a reader counting characters took that to be the `d`.
    #[test]
    fn a_directive_name_finding_counts_directives_from_one() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "script-src 'self'; img-src 'self'; b@d 'self'",
        )]);
        let all = crate::test_helpers::run_rule_all(
            &ContentSecurityPolicyValid,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &make_cfg(),
        );
        let messages: Vec<&str> = all.iter().map(|v| v.message.as_str()).collect();
        assert_eq!(
            messages,
            ["Invalid character '@' in Content-Security-Policy directive-name 'b@d', in directive 3 of its policy"]
        );
    }
}
