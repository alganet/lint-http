// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct HostHeader;

/// Whether this request sent its authority as control data rather than as a
/// `Host` field — the state §7.2's MUST excepts.
///
/// Only HTTP/2 and HTTP/3 have pseudo-header fields, which is why the version
/// is half the question: an HTTP/1.1 request-target in absolute-form also
/// carries an authority, and §3.2.2 of [HTTP/1.1] says a `Host` field is
/// required anyway ("even if the request-target is in the absolute-form"). So a
/// target authority is the `:authority` only on the two versions that have one.
///
/// The capture records `:authority` as the authority of the request's target
/// URI — the same place `host_and_authority_consistent` reads it, over
/// both of the versions that carry one.
fn sends_authority_as_control_data(tx: &crate::http_transaction::HttpTransaction) -> bool {
    // cite(RFC 9110 § 7.2): "In HTTP/2 [HTTP/2] and HTTP/3 [HTTP/3], the Host header field is, in some cases, supplanted by the ":authority" pseudo-header field of a request's control data."
    // The major digit is what "in HTTP/2 and HTTP/3" means; `http_version` owns
    // the production that reads it. Two string-prefix tests said this until
    // 2026-08-03 and admitted `HTTP/2x` and `HTTP/20` on the way.
    let version = tx.request.version.as_str();
    if !matches!(crate::http_version::major(version), Some(2 | 3)) {
        return false;
    }
    crate::helpers::uri::extract_authority_from_request_target(&tx.request.uri).is_some()
}

impl Rule for HostHeader {
    fn id(&self) -> &'static str {
        "host_header"
    }

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
            let host_lines = tx.request.headers.get_all("host");
            let host_count = host_lines.iter().count();

            // The MUST has an `unless`, and the second sentence is what the `unless`
            // is about. A request that sent its authority as `:authority` has done
            // what the requirement asks; reporting it measures every HTTP/2 and
            // HTTP/3 request against the half of the sentence that excludes it.
            // §3.2 of [HTTP/1.1] says the same thing for one version, and says which.
            // cite(RFC 9110 § 7.2): "A user agent MUST generate a Host header field in a request unless it sends that information as an ":authority" pseudo-header field."
            // cite(RFC 9112 § 3.2): "A client MUST send a Host header field (Section 7.2 of [HTTP]) in all HTTP/1.1 request messages."
            if host_count == 0 {
                if sends_authority_as_control_data(tx) {
                    return None;
                }
                return Some(self.violation(
                    ctx.severity,
                    "Request carries no Host header field and no :authority pseudo-header".into(),
                ));
            }

            // Two lines of a field can only be read as one value when the field is a
            // list, and `Host = uri-host [ ":" port ]` has no `#` in it — so there is
            // no combined value to measure, which is why the recipient's answer is a
            // status code rather than a parse.
            // cite(RFC 9110 § 5.3): "a sender MUST NOT generate multiple field lines with the same name in a message (whether in the headers or trailers) or append a field line when a field line of the same name already exists in the message, unless that field's definition allows multiple field line values to be recombined as a comma-separated list"
            // cite(RFC 9112 § 3.2): "A server MUST respond with a 400 (Bad Request) status code to any HTTP/1.1 request message that lacks a Host header field and to any request message that contains more than one Host header field line or a Host header field with an invalid field value."
            if host_count > 1 {
                return Some(self.violation(ctx.severity, format!(
                        "{} Host header field lines: the field is not defined as a list, so they are not one value",
                        host_count
                    )));
            }

            // Every octet of the one field line as the `char` of the same value.
            // `to_str` refuses every octet outside visible US-ASCII, and the branch
            // under it used to announce a value "not valid UTF-8" — a claim about an
            // encoding, where the honest finding is that %x80-FF appears in none of
            // `uri-host`'s alternatives. The mapping is a bijection: every character
            // the productions are built from is ASCII and crosses unchanged, and
            // every octet none of them admits arrives as a `char` none of them admits
            // either, at the check that owns it.
            let value: String = host_lines
                .iter()
                .next()?
                .as_bytes()
                .iter()
                .map(|&b| b as char)
                .collect();

            // `OWS` is SP and HTAB and nothing else. `str::trim` is Unicode
            // whitespace, and on a value read octet-per-`char` U+00A0 is the octet
            // %xA0 — `obs-text`, which no host production admits — so trimming it
            // would drop the finding rather than the whitespace.
            // cite(RFC 9110 § 5.6.3): "OWS            = *( SP / HTAB )"
            // cite(RFC 9110 § 5.5): "A field value does not include leading or trailing whitespace."
            let s = value.trim_matches(|c| c == ' ' || c == '\t');

            // An empty field value is a `uri-host` of no characters — `reg-name` is
            // `*( ... )` — and in one case it is what the MUST demands. Reporting it
            // reports the client that read its specification.
            // cite(RFC 9112 § 3.2): "If the authority component is missing or undefined for the target URI, then a client MUST send a Host header field with an empty field value."
            if s.is_empty() {
                return None;
            }

            // The `@` is the userinfo's delimiter, and this is the sentence that
            // names it — RFC 9110 §4.2.4's MUST NOT is about an "http" or "https"
            // URI reference generated as a target URI or field value, and a `Host`
            // field value is neither: it is a `uri-host` and a port.
            // cite(RFC 9112 § 3.2): "If the target URI includes an authority component, then a client MUST send a field value for Host that is identical to that authority component, excluding any userinfo subcomponent and its "@" delimiter (Section 4.2 of [HTTP])."
            if s.contains('@') {
                return Some(self.violation(ctx.severity, format!(
                        "Host field value '{}' carries a userinfo subcomponent and its '@' delimiter",
                        s
                    )));
            }

            // Asked before the grammar so the answer names what is wrong. Without
            // the brackets nothing marks where the address stopped, so the generic
            // reader splits at the first colon and reports a port full of colons;
            // `fe80::1` has no colon it could call a delimiter at all and used to
            // pass, published as a Compliant example.
            // cite(RFC 3986 § 3.2.2): "A host identified by an Internet Protocol literal address, version 6 [RFC3513] or later, is distinguished by enclosing the IP literal within square brackets ("[" and "]")."
            if s.parse::<std::net::Ipv6Addr>().is_ok()
                || crate::helpers::ipv6::looks_like_unbracketed_ipv6_with_port(s)
            {
                return Some(self.violation(ctx.severity, format!(
                        "IPv6 literal '{}' in a Host field value must be enclosed in square brackets",
                        s
                    )));
            }

            // The field's own grammar, which this rule had never applied: a value
            // with no colon in it returned early, so `Host: exa mple.com` was as
            // acceptable as `Host: example.com`. `validate_host_and_optional_port`
            // is the `Host` production; the port it admits is `*DIGIT`, which is
            // the whole of what RFC 3986 §3.2.3 says a port looks like.
            // cite(RFC 9110 § 7.2, label: Host grammar): "Host = uri-host [ ":" port ]"
            if let Err(msg) = crate::helpers::uri::validate_host_and_optional_port(s) {
                return Some(self.violation(
                    ctx.severity,
                    format!("Host field value '{}' is not a host and port: {}", s, msg),
                ));
            }

            None
        };
        Vec::from_iter(finding())
    }

    fn description(&self) -> &'static str {
        "This rule reads the request's `Host` header field: whether it is there, whether it is there once, and whether its value is what `Host = uri-host [ \":\" port ]` generates.\n\n- A request that carries no `Host` field is reported **unless it is an HTTP/2 or HTTP/3 request that sent an `:authority` pseudo-header** — RFC 9110 §7.2's MUST is written with that exception, and RFC 9112 §3.2's is written for HTTP/1.1 messages. An HTTP/1.1 request in absolute-form is not exempt: RFC 9112 §3.2.2 requires the field there too.\n- `Host` is not a list field, so two field lines of it are not one value; RFC 9110 §5.3 forbids a sender from generating them and RFC 9112 §3.2 has the recipient answer 400.\n- The value must be a `uri-host` (RFC 3986 §3.2.2) and, if a port follows the colon, a port. An IPv6 address must be inside square brackets — that is the only thing distinguishing an IP literal from a registered name.\n- A userinfo subcomponent and its `@` are reported: RFC 9112 §3.2 requires the field value to be the authority component *excluding* them.\n\nThree things this rule deliberately does **not** report:\n\n- **An empty field value.** `reg-name` is `*( unreserved / pct-encoded / sub-delims )`, so a host of no characters is one, and RFC 9112 §3.2 *requires* an empty `Host` when the target URI's authority component is missing or undefined. A server facing one reconstructs an empty authority and may reject the request (RFC 9112 §3.3), but nothing makes the client's field a syntax error.\n- **A port outside the TCP range.** The production is `port = *DIGIT` (RFC 3986 §3.2.3) — no lower bound, no upper bound, and zero digits is a port, which is why `Host: example.com:0`, `Host: example.com:99999` and `Host: example.com:` are not findings here. `Host: example.com:abc` is, because it is not `*DIGIT`.\n- **Where the field sits in the header section.** RFC 9110 §7.2 says a user agent that sends `Host` SHOULD send it as the first field, and RFC 9110 §5.3 calls it good practice; the captured transaction holds its fields in a map whose iteration order is not the order they arrived in, so no check here can decide it."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("7.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-7.2",
                note: "Host and :authority — the grammar, the MUST, and the pseudo-header the MUST excepts. The SHOULD to send Host first is not checked: the capture does not preserve field order.",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("5.3"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.3",
                note: "Field Order — a sender MUST NOT repeat a field name unless the field is a comma-separated list, and Host is not one",
            },
            crate::rules::SpecRef {
                spec: "RFC 9112",
                section: Some("3.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2",
                note: "Request Target — Host is required in all HTTP/1.1 requests, its value excludes userinfo, and it is empty when the target URI has no authority",
            },
            crate::rules::SpecRef {
                spec: "RFC 3986",
                section: Some("3.2.2"),
                url: "https://www.rfc-editor.org/rfc/rfc3986.html#section-3.2.2",
                note: "Host — an IP literal is distinguished by its square brackets; every other host is a registered name",
            },
            crate::rules::SpecRef {
                spec: "RFC 3986",
                section: Some("3.2.3"),
                url: "https://www.rfc-editor.org/rfc/rfc3986.html#section-3.2.3",
                note: "Port — `port = *DIGIT` bounds nothing, so a port outside the TCP range is not a syntax finding",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("A registered name and a port"),
                snippet: "GET /path HTTP/1.1\nHost: example.com:8080",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("An IPv6 literal, inside the brackets that identify it"),
                snippet: "GET /path HTTP/1.1\nHost: [::1]:443",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("A port no TCP connection could use is still `*DIGIT`"),
                snippet: "GET /path HTTP/1.1\nHost: example.com:99999",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("A port that is not digits"),
                snippet: "GET /path HTTP/1.1\nHost: example.com:abc",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("An IPv6 address with nothing marking where it ended"),
                snippet: "GET /path HTTP/1.1\nHost: fe80::1",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("The authority component, userinfo and all"),
                snippet: "GET /path HTTP/1.1\nHost: user:pass@example.com",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("A character no host production generates"),
                snippet: "GET /path HTTP/1.1\nHost: exa mple.com",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("Two field lines of a field that does not recombine as a list"),
                snippet: "GET /path HTTP/1.1\nHost: a.example\nHost: b.example",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &HostHeader;

#[cfg(test)]
mod tests {
    use super::*;

    use rstest::rstest;

    fn judge(headers: &[(&str, &str)]) -> Option<String> {
        let rule = HostHeader;
        let tx = crate::test_helpers::make_test_transaction_with_headers(headers);
        crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .map(|v| v.message)
    }

    #[rstest]
    #[case(vec![], Some("Request carries no Host header field and no :authority pseudo-header"))]
    #[case(vec![("host", "example.com")], None)]
    #[case(vec![("host", "example.com:80")], None)]
    #[case(vec![("host", "  example.com  ")], None)]
    #[case(vec![("host", "[::1]:443")], None)]
    #[case(vec![("host", "[::1]")], None)]
    #[case(vec![("host", "1.2.3.4:80")], None)]
    #[case(vec![("host", "[v7.fe80::a+en1]")], None)]
    // `reg-name` admits every sub-delim, and a dotted quad out of range is one.
    #[case(vec![("host", "999.999.999.999")], None)]
    #[case(vec![("host", "a!$&'()*+,;=.example")], None)]
    #[case(vec![("host", "%41.example.com")], None)]
    fn accepted_values(#[case] headers: Vec<(&str, &str)>, #[case] expected: Option<&str>) {
        assert_eq!(judge(&headers), expected.map(str::to_string));
    }

    /// The value in each case is reported for the reason the message names, not
    /// merely reported. Three `#[case]`s used to assert `is_some()` alone, which
    /// a finding reached for any other reason satisfies.
    #[rstest]
    #[case("example.com:abc", "Host field value 'example.com:abc' is not a host and port: invalid character 'a' in port 'abc'")]
    #[case("exa mple.com", "Host field value 'exa mple.com' is not a host and port: invalid character ' ' in host 'exa mple.com'")]
    #[case("exam<ple>.com", "Host field value 'exam<ple>.com' is not a host and port: invalid character '<' in host 'exam<ple>.com'")]
    #[case("exa[mple.com", "Host field value 'exa[mple.com' is not a host and port: 'exa[mple.com' holds a bracket, which appears in no host form but an IP literal")]
    #[case(
        "%zz.example.com",
        "Host field value '%zz.example.com' is not a host and port: Invalid percent-encoding '%zz'"
    )]
    #[case(
        "[::1",
        "Host field value '[::1' is not a host and port: IP literal '[::1' is missing its ']'"
    )]
    #[case("[not-an-address]", "Host field value '[not-an-address]' is not a host and port: 'not-an-address' is not an IPv6 address")]
    #[case(
        "[::1]:-1",
        "Host field value '[::1]:-1' is not a host and port: invalid character '-' in port '-1'"
    )]
    #[case(
        "user:pass@example.com",
        "Host field value 'user:pass@example.com' carries a userinfo subcomponent and its '@' delimiter"
    )]
    #[case(
        "user@example.com:80",
        "Host field value 'user@example.com:80' carries a userinfo subcomponent and its '@' delimiter"
    )]
    #[case(
        "user:pass@[::1]:80",
        "Host field value 'user:pass@[::1]:80' carries a userinfo subcomponent and its '@' delimiter"
    )]
    #[case(
        "fe80::1",
        "IPv6 literal 'fe80::1' in a Host field value must be enclosed in square brackets"
    )]
    #[case(
        "::1",
        "IPv6 literal '::1' in a Host field value must be enclosed in square brackets"
    )]
    #[case(
        "fe80::abcd:8080",
        "IPv6 literal 'fe80::abcd:8080' in a Host field value must be enclosed in square brackets"
    )]
    fn reported_values(#[case] value: &str, #[case] expected: &str) {
        assert_eq!(judge(&[("host", value)]), Some(expected.to_string()));
    }

    /// `port = *DIGIT` has no bounds in it, and the sentence that would supply
    /// them belongs to TCP rather than to this field. Four of these were
    /// `NonCompliant` cases and one was a published example.
    #[rstest]
    #[case("example.com:0")]
    #[case("example.com:65536")]
    #[case("example.com:99999")]
    #[case("example.com:999999999999999999999")]
    #[case("example.com:")]
    #[case("example.com:080")]
    fn a_port_outside_the_tcp_range_is_still_a_port(#[case] value: &str) {
        assert_eq!(judge(&[("host", value)]), None);
    }

    /// RFC 9112 §3.2 requires exactly this value when the target URI's authority
    /// component is missing or undefined, so the rule that reported it reported
    /// the client that followed the MUST.
    #[rstest]
    #[case("")]
    #[case("   ")]
    fn an_empty_field_value_is_what_one_case_requires(#[case] value: &str) {
        assert_eq!(judge(&[("host", value)]), None);
    }

    #[test]
    fn multiple_host_field_lines_are_reported() {
        let rule = HostHeader;
        let tx = crate::test_helpers::make_test_transaction_with_headers(&[
            ("host", "example.com"),
            ("host", "other.example.com"),
        ]);
        let violation = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert_eq!(
            violation.map(|v| v.message),
            Some(
                "2 Host header field lines: the field is not defined as a list, so they are not one value"
                    .to_string()
            )
        );
    }

    /// The octet %xFF appears in no alternative of `uri-host`, and that — not
    /// the encoding it is not part of — is what the finding says. `to_str`
    /// refuses every octet above %x7F, so the old message called a conforming
    /// UTF-8 value invalid UTF-8 as readily as this one.
    #[test]
    fn a_non_ascii_octet_is_reported_at_the_production_that_excludes_it() {
        let rule = HostHeader;
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        hm.insert(
            "host",
            HeaderValue::from_bytes(b"ex\xffample.com").expect("obs-text is a legal field octet"),
        );
        tx.request.headers = hm;

        let violation = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert_eq!(
            violation.map(|v| v.message),
            Some(
                "Host field value 'ex\u{ff}ample.com' is not a host and port: invalid character '\u{ff}' in host 'ex\u{ff}ample.com'"
                    .to_string()
            )
        );
    }

    /// U+00A0 reaches this rule as the octet %xA0 — `obs-text`, not whitespace.
    /// `str::trim` treats it as whitespace and would have trimmed the one
    /// character the value is reported for.
    #[test]
    fn a_no_break_space_is_not_optional_whitespace() {
        let rule = HostHeader;
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        hm.insert(
            "host",
            HeaderValue::from_bytes(b"\xa0").expect("obs-text is a legal field octet"),
        );
        tx.request.headers = hm;

        let violation = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert_eq!(
            violation.map(|v| v.message),
            Some(
                "Host field value '\u{a0}' is not a host and port: invalid character '\u{a0}' in host '\u{a0}'"
                    .to_string()
            ),
            "an obs-text octet is a host of one character no production admits"
        );
    }

    /// The `unless` clause of §7.2's MUST. Every HTTP/2 and HTTP/3 request that
    /// sent its authority as control data was reported before this gate existed.
    #[rstest]
    #[case("HTTP/2.0", "https://example.com/path", None)]
    #[case("HTTP/3.0", "https://example.com/path", None)]
    #[case(
        "HTTP/2.0",
        "/path",
        Some("Request carries no Host header field and no :authority pseudo-header")
    )]
    // An HTTP/1.1 request-target in absolute-form carries an authority and is
    // not a pseudo-header: RFC 9112 §3.2.2 requires the field anyway.
    #[case(
        "HTTP/1.1",
        "http://example.com/path",
        Some("Request carries no Host header field and no :authority pseudo-header")
    )]
    #[case(
        "HTTP/1.0",
        "/path",
        Some("Request carries no Host header field and no :authority pseudo-header")
    )]
    fn the_authority_pseudo_header_excepts_the_must(
        #[case] version: &str,
        #[case] uri: &str,
        #[case] expected: Option<&str>,
    ) {
        let rule = HostHeader;
        let mut tx = crate::test_helpers::make_test_transaction_with_headers(&[]);
        tx.request.version = version.into();
        tx.request.uri = uri.into();
        let violation = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert_eq!(violation.map(|v| v.message), expected.map(str::to_string));
    }

    #[test]
    fn scope_is_client() {
        let r = HostHeader;
        assert_eq!(
            crate::rules::Rule::scope(&r),
            crate::rules::RuleScope::Client
        );
    }

    /// The field lines of an example, with its start line dropped — and checked,
    /// not assumed: this rule is request-scoped, so a response-shaped example
    /// added later would have its fields filed onto the request, where the guard
    /// would judge a value the rule never sees.
    fn published_fields(snippet: &str) -> Vec<(&str, &str)> {
        let mut lines = snippet.lines();
        let start = lines.next().expect("an example has a start line");
        assert!(
            !start.starts_with("HTTP/"),
            "a response-shaped example cannot be checked by this guard: {start:?}"
        );
        lines
            .filter(|l| !l.trim().is_empty())
            .map(|l| {
                l.split_once(": ")
                    .unwrap_or_else(|| panic!("not a header line: {l:?}"))
            })
            .collect()
    }

    /// Nothing runs a rule's own `examples()` through the engine, so a
    /// `Compliant` value the rule rejects is published as guidance. The
    /// previous set put five values in the body position, after the blank
    /// line, where they were neither judged nor field lines.
    #[test]
    fn published_examples_are_judged_the_way_they_are_labelled() {
        use crate::rules::Compliance;
        let mut saw_a_finding = false;
        for ex in HostHeader.examples() {
            let found = judge(&published_fields(ex.snippet));
            match ex.compliance {
                Compliance::Compliant => assert!(
                    found.is_none(),
                    "rule reports its Compliant example {:?}: {found:?}",
                    ex.snippet
                ),
                Compliance::NonCompliant => {
                    found.unwrap_or_else(|| {
                        panic!("rule accepts its NonCompliant example {:?}", ex.snippet)
                    });
                    saw_a_finding = true;
                }
            }
        }
        assert!(saw_a_finding, "no published example produced a finding");
    }
}
