// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ContentSecurityPolicyAndFrameOptionsConsistent;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const CSP3_6_4_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "CSP3",
    section: Some("6.4.2"),
    url: "https://www.w3.org/TR/CSP3/#directive-frame-ancestors",
    note: "`frame-ancestors` directive. Note: when present and enforceable, `frame-ancestors` overrides `X-Frame-Options` (see §6.4.2.2)",
};
const HTML_SPECULATIVE_LOADING: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "HTML Speculative Loading",
    section: None,
    url:
        "https://html.spec.whatwg.org/multipage/speculative-loading.html#the-x-frame-options-header",
    note: "HTML Living Standard — `X-Frame-Options` header and its relation to `frame-ancestors`",
};
const MDN_X_FRAME_OPTIONS: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "MDN X-Frame-Options",
    section: None,
    url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Frame-Options",
    note: "`X-Frame-Options` — legacy header with values `DENY`, `SAMEORIGIN`, and the obsolete `ALLOW-FROM`. Note: `ALLOW-FROM` is deprecated and not supported by most modern browsers — prefer using CSP's `frame-ancestors` for origin-specific framing policies",
};

/// What a `frame-ancestors` directive permits, across every enforced policy in
/// the response.
#[derive(Default)]
struct FrameAncestors {
    /// `'none'` was listed: nothing may frame the resource.
    none: bool,
    /// `'self'` was listed: the resource's own origin may frame it.
    own_origin: bool,
    /// The serialized origins listed, each without its trailing slash.
    origins: Vec<String>,
}

impl FrameAncestors {
    /// Read the directive from the response, or `None` where no enforced policy
    /// names it.
    ///
    /// Report-only policies are not read: they change no framing decision, so a
    /// disagreement with one is not a disagreement about what happens.
    // cite(CSP3 § 6.4.2): "The frame-ancestors directive restricts the URLs which can embed the resource using frame, iframe, object, or embed."
    fn of(headers: &hyper::HeaderMap) -> Option<Self> {
        let mut policy = Self::default();
        let mut named = false;

        for directive in crate::helpers::headers::field_lines(headers, "content-security-policy")
            .flat_map(crate::helpers::list::parse_semicolon_list)
        {
            let mut parts = directive.split_whitespace();
            if !parts
                .next()
                .is_some_and(|name| name.eq_ignore_ascii_case("frame-ancestors"))
            {
                continue;
            }
            // The directive is named even when it lists nothing, and a
            // `frame-ancestors` with no source expression permits no framing at
            // all — which is a finding for the rule that owns the grammar, not a
            // reason to read the header as absent here.
            named = true;

            for member in parts {
                // Keyword sources are written in single quotes; a serialized
                // origin is not. An unbalanced quote is left as written, since
                // it matches no keyword either way.
                let source = member
                    .strip_prefix('\'')
                    .and_then(|rest| rest.strip_suffix('\''))
                    .unwrap_or(member);
                if source.eq_ignore_ascii_case("none") {
                    policy.none = true;
                } else if source.eq_ignore_ascii_case("self") {
                    policy.own_origin = true;
                } else {
                    policy
                        .origins
                        .push(source.strip_suffix('/').unwrap_or(source).to_string());
                }
            }
        }

        named.then_some(policy)
    }

    /// Whether the policy permits framing by anyone at all.
    fn permits_framing(&self) -> bool {
        self.own_origin || !self.origins.is_empty()
    }

    /// Whether the policy lists this serialized origin.
    fn lists(&self, origin: &str) -> bool {
        self.origins.iter().any(|o| o.eq_ignore_ascii_case(origin))
    }
}

/// The framing policy an `X-Frame-Options` field value states.
// cite(HTML Speculative Loading § 7.7): "The `X-Frame-Options` HTTP response header is a way of controlling whether and how a Document may be loaded inside of a child navigable."
enum FrameOptions<'a> {
    /// `DENY`.
    Deny,
    /// `SAMEORIGIN`.
    SameOrigin,
    /// `ALLOW-FROM <origin>`, carrying the origin exactly as written — which is
    /// what a finding quotes back, while the comparison uses it without its
    /// trailing slash.
    AllowFrom(&'a str),
    /// Anything else, including an `ALLOW-FROM` naming no origin.
    Unrecognized,
}

impl<'a> FrameOptions<'a> {
    fn of(value: &'a str) -> Self {
        if value.eq_ignore_ascii_case("DENY") {
            return Self::Deny;
        }
        if value.eq_ignore_ascii_case("SAMEORIGIN") {
            return Self::SameOrigin;
        }
        let Some(rest) = value
            .get(..10)
            .filter(|head| head.eq_ignore_ascii_case("ALLOW-FROM"))
            .map(|_| value[10..].trim_start())
        else {
            return Self::Unrecognized;
        };
        if rest.is_empty() {
            return Self::Unrecognized;
        }
        Self::AllowFrom(rest)
    }
}

impl ContentSecurityPolicyAndFrameOptionsConsistent {
    /// Whether the one origin `ALLOW-FROM` permits is an origin the policy
    /// permits too.
    fn allow_from_defect(
        &self,
        csp: &FrameAncestors,
        as_written: &str,
        request_uri: &str,
        severity: crate::lint::Severity,
    ) -> Option<Violation> {
        let allowed = as_written.strip_suffix('/').unwrap_or(as_written);

        if csp.none {
            return Some(self.violation(severity, format!(
                "X-Frame-Options: ALLOW-FROM {} permits framing but Content-Security-Policy frame-ancestors is 'none'",
                as_written
            )));
        }

        // A listed origin agrees; `'self'` agrees when the request's own origin
        // is the one allowed, since that is the origin `'self'` stands for.
        let own_origin = || {
            csp.own_origin
                && extract_origin_from_uri(request_uri)
                    .is_some_and(|origin| origin.eq_ignore_ascii_case(allowed))
        };

        if !csp.origins.is_empty() {
            return (!csp.lists(allowed) && !own_origin()).then(|| {
                self.violation(severity, format!(
                    "X-Frame-Options: ALLOW-FROM {} is not included in Content-Security-Policy frame-ancestors",
                    as_written
                ))
            });
        }

        if csp.own_origin {
            let origin = extract_origin_from_uri(request_uri)?;
            return (!origin.eq_ignore_ascii_case(allowed)).then(|| {
                self.violation(severity, format!(
                    "X-Frame-Options: ALLOW-FROM {} does not match Content-Security-Policy frame-ancestors 'self' (origin {})",
                    as_written, origin
                ))
            });
        }

        None
    }
}

impl Rule for ContentSecurityPolicyAndFrameOptionsConsistent {
    fn id(&self) -> &'static str {
        "content_security_policy_and_frame_options_consistent"
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

            // With no frame-ancestors directive there is nothing to compare
            // X-Frame-Options against.
            let csp = FrameAncestors::of(&resp.headers)?;

            // The two headers answer the same question, and a browser that honours
            // `frame-ancestors` ignores `X-Frame-Options` — so when they disagree, one of
            // them is a statement of intent that nothing enforces. That precedence (and
            // why only enforced CSP counts, so report-only is skipped above) is
            // §6.4.2.2's; the two purpose cites give each header's own scope.
            // cite(CSP3 § 6.4.2.2): "the frame-ancestors directive overrides the ``X-Frame-Options`` header."
            // cite(CSP3 § 6.4.2): "The frame-ancestors directive restricts the URLs which can embed the resource using frame, iframe, object, or embed."
            // cite(HTML Speculative Loading § 7.7): "The `X-Frame-Options` HTTP response header is a way of controlling whether and how a Document may be loaded inside of a child navigable."
            //
            // A repeated X-Frame-Options is the duplicate-header rule's finding, and
            // an unreadable one belongs to the rule that owns the field: either way
            // there is no single policy here to compare.
            if resp.headers.get_all("x-frame-options").iter().count() != 1 {
                return None;
            }
            let xfo =
                crate::helpers::headers::get_header_str(&resp.headers, "x-frame-options")?.trim();

            match FrameOptions::of(xfo) {
                // DENY forbids framing, so it contradicts a policy that permits any.
                FrameOptions::Deny => (!csp.none && csp.permits_framing()).then(|| {
                    self.violation(ctx.severity, "X-Frame-Options: DENY contradicts Content-Security-Policy frame-ancestors which permits framing".into())
                }),
                // SAMEORIGIN permits same-origin framing, so only an outright
                // 'none' contradicts it.
                FrameOptions::SameOrigin => csp.none.then(|| {
                    self.violation(ctx.severity, "Content-Security-Policy frame-ancestors: 'none' forbids framing while X-Frame-Options: SAMEORIGIN permits same-origin frames".into())
                }),
                FrameOptions::AllowFrom(as_written) => {
                    self.allow_from_defect(&csp, as_written, &tx.request.uri, ctx.severity)
                }
                // A form no user agent implements says nothing to contradict;
                // reporting it belongs to the rule that owns the field.
                FrameOptions::Unrecognized => None,
            }
        };
        Vec::from_iter(finding())
    }

    fn description(&self) -> &'static str {
        "Detect contradictory framing directives between `Content-Security-Policy` (the `frame-ancestors` directive) and `X-Frame-Options`. These headers express framing restrictions; when they conflict, they create ambiguity that may cause different user agents to allow or block framing inconsistently.\n\nNote: this check considers only enforceable header-delivered CSP policies (`Content-Security-Policy`); `Content-Security-Policy-Report-Only` is ignored because it does not itself change framing enforcement."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[CSP3_6_4_2, HTML_SPECULATIVE_LOADING, MDN_X_FRAME_OPTIONS]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "Content-Security-Policy: frame-ancestors 'none'\n# No X-Frame-Options header present",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "Content-Security-Policy: frame-ancestors https://example.com\nX-Frame-Options: ALLOW-FROM https://example.com",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "Content-Security-Policy: frame-ancestors 'none'\nX-Frame-Options: SAMEORIGIN\n# CSP disallows all framing but XFO says allow same origin -> contradiction",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "Content-Security-Policy: frame-ancestors 'self'\nX-Frame-Options: DENY\n# CSP allows same-origin framing while XFO denies all framing -> contradiction",
            },
        ]
    }
}

// Helper to derive origin from a request uri like "http://example/" -> "http://example"
fn extract_origin_from_uri(uri: &str) -> Option<String> {
    let s = uri.trim();
    if s.is_empty() {
        return None;
    }
    if let Some(pos) = s.find("://") {
        let scheme = &s[..pos];
        let rest = &s[pos + 3..];
        let host_part = if let Some(idx) = rest.find('/') {
            &rest[..idx]
        } else {
            rest
        };
        if host_part.is_empty() {
            return None;
        }
        let mut origin = format!("{}://{}", scheme, host_part);
        if origin.ends_with('/') {
            origin.pop();
        }
        return Some(origin);
    }
    None
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ContentSecurityPolicyAndFrameOptionsConsistent;

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;
    use rstest::rstest;

    fn make_cfg() -> crate::config::Config {
        crate::test_helpers::make_test_config_with_severity(
            "content_security_policy_and_frame_options_consistent",
            "warn",
        )
    }

    #[rstest]
    #[case("frame-ancestors 'none'", "SAMEORIGIN", true)]
    #[case("frame-ancestors 'self'", "DENY", true)]
    #[case("frame-ancestors https://a", "ALLOW-FROM https://b", true)]
    #[case("frame-ancestors https://a https://b", "ALLOW-FROM https://b", false)]
    #[case("frame-ancestors 'none'", "DENY", false)]
    #[case("frame-ancestors 'self'", "ALLOW-FROM https://example", true)]
    fn consistency_cases(#[case] csp: &str, #[case] xfo: &str, #[case] expect_violation: bool) {
        let rule = ContentSecurityPolicyAndFrameOptionsConsistent;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            ("content-security-policy", csp),
            ("x-frame-options", xfo),
        ]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(
                v.is_some(),
                "expected violation for csp='{}' xfo='{}'",
                csp,
                xfo
            );
        } else {
            assert!(
                v.is_none(),
                "unexpected violation {:?} for csp='{}' xfo='{}'",
                v,
                csp,
                xfo
            );
        }
    }

    #[test]
    fn non_utf8_headers_are_ignored_by_this_rule() {
        let rule = ContentSecurityPolicyAndFrameOptionsConsistent;
        let cfg = make_cfg();

        // make a non-utf8 header value for XFO
        let bad = HeaderValue::from_bytes(&[0xff]).unwrap();
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "frame-ancestors 'self'",
        )]);
        headers.insert("x-frame-options", bad);
        tx.response.as_mut().unwrap().headers = headers;

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn mismatched_allow_from_vs_self_reports_violation() {
        let rule = ContentSecurityPolicyAndFrameOptionsConsistent;
        let cfg = make_cfg();

        // request uri default origin from test is http://example
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            ("content-security-policy", "frame-ancestors 'self'"),
            ("x-frame-options", "ALLOW-FROM https://example"),
        ]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .unwrap();
        assert!(v.message.contains("does not match"));
    }

    #[test]
    fn scope_and_id_expected() {
        let rule = ContentSecurityPolicyAndFrameOptionsConsistent;
        assert_eq!(
            rule.id(),
            "content_security_policy_and_frame_options_consistent"
        );
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(
            &mut cfg,
            "content_security_policy_and_frame_options_consistent",
        );
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn multiple_csp_headers_handled() {
        let rule = ContentSecurityPolicyAndFrameOptionsConsistent;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        // two CSP headers, one has frame-ancestors
        let headers = crate::test_helpers::make_headers_from_pairs(&[
            ("content-security-policy", "default-src 'self'"),
            ("content-security-policy", "frame-ancestors https://a"),
            ("x-frame-options", "ALLOW-FROM https://a"),
        ]);
        tx.response.as_mut().unwrap().headers = headers;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn malformed_frame_ancestors_no_members_is_ignored() {
        let rule = ContentSecurityPolicyAndFrameOptionsConsistent;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            ("content-security-policy", "frame-ancestors"),
            ("x-frame-options", "DENY"),
        ]);
        // since the directive is malformed (no members) we treat as absent and no violation
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn multiple_xfo_headers_are_ignored() {
        let rule = ContentSecurityPolicyAndFrameOptionsConsistent;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut headers = crate::test_helpers::make_headers_from_pairs(&[
            ("content-security-policy", "frame-ancestors https://a"),
            ("x-frame-options", "DENY"),
        ]);
        // add a second XFO header to simulate duplicates
        headers.append("x-frame-options", "DENY".parse().unwrap());
        tx.response.as_mut().unwrap().headers = headers;

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn allow_from_trailing_slash_matches_csp_origin() {
        let rule = ContentSecurityPolicyAndFrameOptionsConsistent;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            ("content-security-policy", "frame-ancestors https://example"),
            ("x-frame-options", "ALLOW-FROM https://example/"),
        ]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn unsupported_xfo_form_is_ignored() {
        let rule = ContentSecurityPolicyAndFrameOptionsConsistent;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            ("content-security-policy", "frame-ancestors https://example"),
            ("x-frame-options", "UNKNOWN https://example"),
        ]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn allow_from_matches_request_origin_with_self() {
        let rule = ContentSecurityPolicyAndFrameOptionsConsistent;
        let cfg = make_cfg();

        // request uri default origin from test is http://example
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.request.uri = "http://example/path".into();
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            ("content-security-policy", "frame-ancestors 'self'"),
            ("x-frame-options", "ALLOW-FROM http://example"),
        ]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn malformed_allow_from_is_ignored() {
        let rule = ContentSecurityPolicyAndFrameOptionsConsistent;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            ("content-security-policy", "frame-ancestors https://a"),
            ("x-frame-options", "ALLOW-FROM"),
        ]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn allow_from_with_csp_none_reports_violation() {
        let rule = ContentSecurityPolicyAndFrameOptionsConsistent;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            ("content-security-policy", "frame-ancestors 'none'"),
            ("x-frame-options", "ALLOW-FROM https://example"),
        ]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("permits framing") && msg.contains("'none'"));
    }

    #[test]
    fn allow_from_case_insensitive_match_with_csp_origin() {
        let rule = ContentSecurityPolicyAndFrameOptionsConsistent;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            ("content-security-policy", "frame-ancestors https://EXample"),
            ("x-frame-options", "ALLOW-FROM https://example"),
        ]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn csp_origin_trailing_slash_matches_allow_from() {
        let rule = ContentSecurityPolicyAndFrameOptionsConsistent;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            (
                "content-security-policy",
                "frame-ancestors https://example/",
            ),
            ("x-frame-options", "ALLOW-FROM https://example"),
        ]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn sameorigin_with_csp_origin_is_compatible() {
        let rule = ContentSecurityPolicyAndFrameOptionsConsistent;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            ("content-security-policy", "frame-ancestors https://example"),
            ("x-frame-options", "SAMEORIGIN"),
        ]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn multiple_csp_headers_with_none_and_origin_allow_from_reports_violation() {
        let rule = ContentSecurityPolicyAndFrameOptionsConsistent;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let headers = crate::test_helpers::make_headers_from_pairs(&[
            ("content-security-policy", "frame-ancestors 'none'"),
            ("content-security-policy", "frame-ancestors https://a"),
            ("x-frame-options", "ALLOW-FROM https://a"),
        ]);
        tx.response.as_mut().unwrap().headers = headers;

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(
            v.is_some(),
            "expected violation when CSP contains 'none' and also permits an origin"
        );
    }

    #[test]
    fn allow_from_lowercase_is_recognized() {
        let rule = ContentSecurityPolicyAndFrameOptionsConsistent;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            ("content-security-policy", "frame-ancestors https://example"),
            ("x-frame-options", "allow-from https://example"),
        ]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn extract_origin_from_uri_various_cases() {
        assert_eq!(
            extract_origin_from_uri("http://example/"),
            Some("http://example".into())
        );
        assert_eq!(
            extract_origin_from_uri("https://example:8080/path"),
            Some("https://example:8080".into())
        );
        assert_eq!(extract_origin_from_uri("noscheme.com/path"), None);
        assert_eq!(extract_origin_from_uri(""), None);
    }

    #[test]
    fn csp_report_only_ignored() {
        let rule = ContentSecurityPolicyAndFrameOptionsConsistent;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            (
                "content-security-policy-report-only",
                "frame-ancestors 'none'",
            ),
            ("x-frame-options", "SAMEORIGIN"),
        ]);
        // report-only policies should not affect framing enforcement -> ignore
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn sameorigin_with_self_is_compatible() {
        let rule = ContentSecurityPolicyAndFrameOptionsConsistent;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            ("content-security-policy", "frame-ancestors 'self'"),
            ("x-frame-options", "SAMEORIGIN"),
        ]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn non_utf8_csp_header_is_ignored() {
        let rule = ContentSecurityPolicyAndFrameOptionsConsistent;
        let cfg = make_cfg();

        // make a non-utf8 header value for CSP
        let bad = hyper::header::HeaderValue::from_bytes(&[0xff]).unwrap();
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut headers =
            crate::test_helpers::make_headers_from_pairs(&[("x-frame-options", "DENY")]);
        headers.insert("content-security-policy", bad);
        tx.response.as_mut().unwrap().headers = headers;

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn csp_present_but_no_xfo_returns_none() {
        let rule = ContentSecurityPolicyAndFrameOptionsConsistent;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "frame-ancestors https://example",
        )]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }
}
