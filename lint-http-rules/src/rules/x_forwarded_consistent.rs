// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! The `X-Forwarded-*` family, measured through the one sentence that reaches it.
//!
//! No document defines these fields. RFC 7239 §1 names three of them and calls
//! them non-standard; §7.4 then does the only thing any specification does with
//! them, which is to say what each converts into. That conversion is the whole of
//! this rule's licence: an `X-Forwarded-For` element becomes a `for=` value, so
//! its vocabulary is §6's node identifier; `X-Forwarded-Proto` becomes `proto=`,
//! whose value §5.4 hands to RFC 3986's scheme name; `X-Forwarded-Host` becomes
//! `host=`, which §5.3 hands to the `Host` field's ABNF.
//!
//! What the rule may not do is invent a vocabulary narrower than those. It used
//! to: `http` and `https` were the only accepted protocols on the strength of a
//! comment saying to "be conservative", and §5.4 calls those two *typical*.

use crate::helpers::forwarded_node::NodeForm;
use crate::helpers::headers::combined_field_value_as_written;
use crate::lint::Violation;
use crate::rules::Rule;

/// The production a field's members are measured against, after §7.4's
/// conversion has said which `Forwarded` parameter each field becomes.
#[derive(Clone, Copy)]
enum Members {
    /// A node identifier: `for=` and `by=` (RFC 7239 §5.1, §5.2 → §6).
    Node,
    /// A URI scheme name: `proto=` (RFC 7239 §5.4).
    Proto,
    /// A `Host` field value: `host=` (RFC 7239 §5.3).
    Host,
}

/// The four legacy fields, with the canonical spelling used in findings.
///
/// §1 names three; the fourth is reached by §7.4's wildcard, `X-Forwarded-*`,
/// together with §5.3's description of what a `host` parameter carries — "the
/// host request header field as received by the proxy", which is what this field
/// has always been used for. That mapping is a reading and not a sentence, and
/// it is the only one of the four that is.
///
/// `X-Forwarded-By` was absent from this rule until its audit, though §1 names it
/// in the same breath as the two that were checked and §7.4 discusses it by name.
// cite(RFC 7239 § 1): "A common way to disclose this information is by using the non-standard header fields such as X-Forwarded-For, X-Forwarded-By, and X-Forwarded-Proto."
// cite(RFC 7239 § 7.4): "If a proxy gets incoming requests with X-Forwarded-* header fields present, it is encouraged to convert these into the header field described in this document, if it can be done in a sensible way."
const FIELDS: &[(&str, &str, Members)] = &[
    ("x-forwarded-for", "X-Forwarded-For", Members::Node),
    ("x-forwarded-by", "X-Forwarded-By", Members::Node),
    ("x-forwarded-proto", "X-Forwarded-Proto", Members::Proto),
    ("x-forwarded-host", "X-Forwarded-Host", Members::Host),
];

/// The comma-separated members of one combined field value.
///
/// The trim is `OWS` and not `str::trim`: the value arrives one `char` per octet,
/// so `U+00A0` here is the octet %xA0 — which none of the three productions below
/// generates — and Unicode trimming would drop the character the member is
/// reported for rather than the whitespace around it.
///
/// Empty members are skipped. RFC 9110 §5.6.1.1's sender MUST NOT is written
/// about a field whose definition uses the list extension, and these fields have
/// no definition at all, so there is no sentence for `a,,b` to violate — the
/// commas in §7.4's example are the only thing any document says about the shape.
// cite(RFC 9110 § 5.6.3): "OWS            = *( SP / HTAB )"
fn members(value: &str) -> impl Iterator<Item = &str> {
    value
        .split(',')
        .map(|m| m.trim_matches(|c| c == ' ' || c == '\t'))
        .filter(|m| !m.is_empty())
}

/// One member of one field: the finding's text, or `None`.
fn check_member(field: &str, kind: Members, member: &str) -> Option<String> {
    match kind {
        // §7.4 converts an element of this field into a `for=` value by
        // prepending `for=`, and §5.2 sends that value to §6's `node` — so an
        // obfuscated identifier and a port are members here, and this rule used
        // to report both. The obfuscated form is not an exotic case: §8.3 asks
        // for it by default, so a proxy following the privacy recommendation
        // while still writing the legacy field name was the reported one.
        //
        // cite(RFC 7239 § 7.4): "If the request only contains one type -- for example, X-Forwarded-For -- this can be translated to "Forwarded", by prepending each element with "for="."
        // cite(RFC 7239 § 8.3): "The default configuration for both the "by" and "for" parameters SHOULD contain obfuscated identifiers."
        Members::Node => {
            crate::helpers::forwarded_node::validate_node(member, NodeForm::XForwarded)
                .err()
                .map(|e| format!("{} {}", field, e))
        }

        // The MUST has two halves and this is the first. A scheme is also
        // required to be registered with IANA, through an open procedure, so an
        // unregistered name is not a finding a fixed list in this file could
        // reach — and neither is a registered one that is not `http` or `https`,
        // which is what the second sentence settles.
        //
        // cite(RFC 7239 § 5.4): "The syntax of a "proto" value, after potential quoted-string unescaping, MUST conform to the URI scheme name as defined in Section 3.1 in [RFC3986] and registered with IANA according to [RFC4395]."
        // cite(RFC 7239 § 5.4): "Typical values are "http" or "https"."
        Members::Proto => crate::helpers::uri::validate_scheme_name(member)
            .err()
            .map(|e| format!("{} is not a URI scheme name: {}", field, e)),

        // The `Host` ABNF, whole: a `uri-host` and an optional `port`, where the
        // port is `*DIGIT` and has neither a lower bound nor an upper one. The
        // TCP range this rule reached for twice is a different sentence than
        // these, and it reported `:0`, `:70000` and the empty port the grammar
        // generates while a host of arbitrary characters passed a four-character
        // blocklist.
        //
        // cite(RFC 7239 § 5.3): "The syntax for a "host" value, after potential quoted-string unescaping, MUST conform to the Host ABNF described in Section 5.4 of [RFC7230]."
        // cite(RFC 9110 § 7.2, label: Host grammar): "Host = uri-host [ ":" port ]"
        Members::Host => crate::helpers::uri::validate_host_and_optional_port(member)
            .err()
            .map(|e| format!("{} is not a Host field value: {}", field, e)),
    }
}

pub struct XForwardedConsistent;

impl Rule for XForwardedConsistent {
    fn id(&self) -> &'static str {
        "x_forwarded_consistent"
    }

    /// The fields travel toward the origin. §7.4 is written about what a proxy
    /// receives on a request, and §1 describes the family as the way a proxy
    /// discloses to the *next* hop what it saw of the client — so a response
    /// carrying one of these names has no sentence to be measured against. This
    /// rule used to walk the response headers anyway, on a comment observing that
    /// some proxies echo them, which is a fact about deployments and not a claim
    /// about conformance. In this engine `Client` and `Both` dispatch alike, so
    /// the enum documents the direction and deleting the walk is the change.
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;

        for (name, field, kind) in FIELDS {
            // Every line of the field, and every octet of every line. A proxy
            // chain appends by adding a field line as often as by extending the
            // one already there, so reading `headers.get()` left a second hop
            // entirely unexamined; and a value outside US-ASCII used to make the
            // whole field disappear, which is the finding wearing a helper's
            // failure mode.
            let Some(value) = combined_field_value_as_written(&tx.request.headers, name) else {
                continue;
            };
            for member in members(&value) {
                if let Some(message) = check_member(field, *kind, member) {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message,
                    });
                }
            }
        }

        None
    }

    fn title(&self) -> Option<&'static str> {
        Some("Message X-Forwarded Consistency")
    }

    fn description(&self) -> &'static str {
        "Validates the legacy `X-Forwarded-For`, `X-Forwarded-By`, `X-Forwarded-Proto` and `X-Forwarded-Host` request fields.\n\n**No specification defines these fields.** RFC 7239 §1 names the first three and calls them non-standard; §7.4 says what a proxy should convert them into, and that conversion is the only route by which any sentence reaches them. This rule follows it:\n\n- an `X-Forwarded-For` or `X-Forwarded-By` member becomes a `for=` / `by=` value, so it is measured against RFC 7239 §6's node identifier — an IPv4 address, an IPv6 address, `unknown`, or an obfuscated identifier beginning with an underscore, each optionally followed by `:` and a port of one to five digits or an obfuscated port. §7.4 records that an IPv6 address is written here **without** the quotes and square brackets it wears inside `Forwarded`, so both spellings are accepted and neither is reported;\n- an `X-Forwarded-Proto` member becomes a `proto=` value, which RFC 7239 §5.4 requires to be a URI scheme name (RFC 3986 §3.1). `http` and `https` are what that section calls *typical*, not what it permits, so `wss` and any other well-formed scheme name pass;\n- an `X-Forwarded-Host` member is measured against the `Host` field ABNF (RFC 9110 §7.2), whose port is `*DIGIT` — no lower bound, no upper bound, and no digits at all is a port.\n\nAll four field names are read across every field line of the request, and each line is read octet by octet, so a value outside US-ASCII is reported as a character the production does not generate rather than skipped.\n\n**What this rule does not check.** The mapping of `X-Forwarded-Host` onto `host=` is the only one of the four that no sentence states — §1 does not name that field, and it is reached by §7.4's `X-Forwarded-*` wildcard together with §5.3's description of what a `host` parameter carries. A scheme name is not checked against the IANA URI scheme registry, which is open. An empty member (`a,,b`) is skipped rather than reported: RFC 9110 §5.6.1.1's prohibition is written about fields whose definition uses the list extension, and these fields have no definition. These are request fields, and a response carrying one is not examined.\n\nDespite its name, this rule checks each field on its own and cross-checks nothing: a message carrying both `Forwarded` and `X-Forwarded-For`, or an `X-Forwarded-Host` disagreeing with `Host`, is not reported. §7.4 encourages the conversion between the two families but states no relationship a receiver could measure, and it is explicit that where several `X-Forwarded-*` fields are present the order they were added in cannot be recovered."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 7239",
                section: Some("7.4"),
                url: "https://www.rfc-editor.org/rfc/rfc7239.html#section-7.4",
                note: "Transition: what each `X-Forwarded-*` field converts into, and the one difference in how an IPv6 address is written there. The only sentences in any specification that reach these fields.",
            },
            crate::rules::SpecRef {
                spec: "RFC 7239",
                section: Some("1"),
                url: "https://www.rfc-editor.org/rfc/rfc7239.html#section-1",
                note: "Names `X-Forwarded-For`, `X-Forwarded-By` and `X-Forwarded-Proto` as non-standard header fields",
            },
            crate::rules::SpecRef {
                spec: "RFC 7239",
                section: Some("6"),
                url: "https://www.rfc-editor.org/rfc/rfc7239.html#section-6",
                note: "`node` — the identifier an `X-Forwarded-For` / `X-Forwarded-By` member becomes once §7.4's conversion prepends `for=` / `by=`",
            },
            crate::rules::SpecRef {
                spec: "RFC 7239",
                section: Some("5.4"),
                url: "https://www.rfc-editor.org/rfc/rfc7239.html#section-5.4",
                note: "`proto` is a URI scheme name; `http` and `https` are called typical, not exhaustive",
            },
            crate::rules::SpecRef {
                spec: "RFC 7239",
                section: Some("5.3"),
                url: "https://www.rfc-editor.org/rfc/rfc7239.html#section-5.3",
                note: "`host` conforms to the `Host` field ABNF. That `X-Forwarded-Host` is the field this parameter carries is a reading of §7.4's `X-Forwarded-*` wildcard, not a sentence.",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("7.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-7.2",
                note: "`Host = uri-host [ \":\" port ]`, the production an `X-Forwarded-Host` member is measured against",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("The chain §7.4 prints, with the host and protocol the proxy saw"),
                snippet: "GET / HTTP/1.1\nHost: internal.example\nX-Forwarded-For: 192.0.2.43, 2001:db8:cafe::17\nX-Forwarded-Proto: https\nX-Forwarded-Host: example.com:443",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some(
                    "An obfuscated identifier and a node port are node identifiers, and `wss` is a URI scheme name",
                ),
                snippet: "GET / HTTP/1.1\nHost: internal.example\nX-Forwarded-For: _gazonk, 192.0.2.43:47011, unknown\nX-Forwarded-By: _SEVKISEK\nX-Forwarded-Proto: wss",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("`port = *DIGIT` has no range in it, and no digits is a port"),
                snippet: "GET / HTTP/1.1\nHost: internal.example\nX-Forwarded-Host: example.com:99999",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some(
                    "Neither an address, nor `unknown`, nor underscore-led: nothing in §6 generates it",
                ),
                snippet: "GET / HTTP/1.1\nHost: internal.example\nX-Forwarded-For: not-an-ip",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("`@` is the userinfo delimiter and appears in no `uri-host`"),
                snippet: "GET / HTTP/1.1\nHost: internal.example\nX-Forwarded-Host: user@host",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("A scheme name begins with a letter"),
                snippet: "GET / HTTP/1.1\nHost: internal.example\nX-Forwarded-Proto: 2https",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &XForwardedConsistent;

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;
    use rstest::rstest;

    /// One transaction built from field lines, judged. `append` is what makes a
    /// repeated name two field lines rather than one replaced value.
    ///
    /// The octets are the parameter because one of the cases below cannot be
    /// written as a `&str`: a lone %xFF is not UTF-8, and passing it as one would
    /// have put two octets on the wire and tested the wrong value.
    fn judge_bytes(pairs: &[(&str, &[u8])]) -> Option<String> {
        let rule = XForwardedConsistent;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[]);
        for (name, value) in pairs {
            tx.request.headers.append(
                hyper::header::HeaderName::from_bytes(name.as_bytes()).expect("a field name"),
                HeaderValue::from_bytes(value).expect("a field value"),
            );
        }
        crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .map(|v| v.message)
    }

    fn judge(pairs: &[(&str, &str)]) -> Option<String> {
        let octets: Vec<(&str, &[u8])> = pairs.iter().map(|(n, v)| (*n, v.as_bytes())).collect();
        judge_bytes(&octets)
    }

    #[rstest]
    // The two values §7.4 prints, in the spelling it prints them in.
    #[case("192.0.2.43", None)]
    #[case("2001:db8:cafe::17", None)]
    #[case("192.0.2.43, 2001:db8:cafe::17", None)]
    // `unknown` is an ABNF string literal, so either case is the production's.
    #[case("unknown", None)]
    #[case("UNKNOWN", None)]
    // A node identifier is more than an address: §7.4 turns each element into a
    // `for=` value, and §6's nodename has four alternatives and an optional port.
    #[case("_gazonk", None)]
    #[case("192.0.2.43:47011", None)]
    #[case("unknown:_hidden", None)]
    // A bracketed address is accepted too: §7.4 records that these fields do not
    // bracket, which is not a sentence forbidding the other spelling.
    #[case("[2001:db8::1]", None)]
    #[case(
        "not-an-ip",
        Some("X-Forwarded-For is not a node identifier: 'not-an-ip' is neither an IPv4 address, an IPv6 address, `unknown`, nor an obfuscated identifier (which must begin with `_` and hold only letters, digits, `.`, `_` and `-`)")
    )]
    #[case(
        "*",
        Some("X-Forwarded-For is not a node identifier: '*' is neither an IPv4 address, an IPv6 address, `unknown`, nor an obfuscated identifier (which must begin with `_` and hold only letters, digits, `.`, `_` and `-`)")
    )]
    #[case("203.0.113.1, bogus, 198.51.100.17", Some("X-Forwarded-For is not a node identifier: 'bogus' is neither an IPv4 address, an IPv6 address, `unknown`, nor an obfuscated identifier (which must begin with `_` and hold only letters, digits, `.`, `_` and `-`)"))]
    #[case("192.0.2.43:999999", Some("X-Forwarded-For has '999999' where a node-port is expected: one to five digits, or an obfuscated port beginning with `_`"))]
    fn a_member_is_the_node_identifier_it_would_become(
        #[case] value: &str,
        #[case] expected: Option<&str>,
    ) {
        assert_eq!(
            judge(&[("x-forwarded-for", value)]).as_deref(),
            expected,
            "{value}"
        );
    }

    #[test]
    fn the_by_field_is_read_and_measured_the_same_way() {
        // §1 names it beside the other two and this rule never looked at it.
        assert_eq!(judge(&[("x-forwarded-by", "203.0.113.60")]), None);
        assert_eq!(
            judge(&[("x-forwarded-by", "x-foo")]).as_deref(),
            Some("X-Forwarded-By is not a node identifier: 'x-foo' is neither an IPv4 address, an IPv6 address, `unknown`, nor an obfuscated identifier (which must begin with `_` and hold only letters, digits, `.`, `_` and `-`)")
        );
    }

    #[rstest]
    #[case("https", None)]
    #[case("http", None)]
    #[case("HTTPS", None)]
    // §5.4 calls `http` and `https` typical. A scheme name is what it requires,
    // and both of these are ones — the rule used to report each of them.
    #[case("wss", None)]
    #[case("ftp", None)]
    #[case("coap+tcp", None)]
    #[case(
        "2https",
        Some(
            "X-Forwarded-Proto is not a URI scheme name: scheme '2https' must begin with a letter"
        )
    )]
    #[case(
        "ht/tps",
        Some(
            "X-Forwarded-Proto is not a URI scheme name: invalid character '/' in scheme 'ht/tps'"
        )
    )]
    fn a_proto_member_is_a_uri_scheme_name(#[case] value: &str, #[case] expected: Option<&str>) {
        assert_eq!(
            judge(&[("x-forwarded-proto", value)]).as_deref(),
            expected,
            "{value}"
        );
    }

    #[rstest]
    #[case("example.com", None)]
    #[case("example.com:8080", None)]
    #[case("[::1]:8080", None)]
    // `port = *DIGIT`: no lower bound, no upper bound, and zero digits is a port.
    // All three were findings while the rule measured this port with the TCP
    // range, which is a different sentence than the `Host` ABNF.
    #[case("example.com:0", None)]
    #[case("[::1]:70000", None)]
    #[case("example.com:", None)]
    // `reg-name` is `*( ... )`, so a host of no characters is one.
    #[case(":80", None)]
    #[case(
        "user@host",
        Some(
            "X-Forwarded-Host is not a Host field value: invalid character '@' in host 'user@host'"
        )
    )]
    #[case(
        "user@host:80",
        Some(
            "X-Forwarded-Host is not a Host field value: invalid character '@' in host 'user@host'"
        )
    )]
    #[case(
        "example.com/extra",
        Some("X-Forwarded-Host is not a Host field value: invalid character '/' in host 'example.com/extra'")
    )]
    #[case(
        "exa mple.com",
        Some("X-Forwarded-Host is not a Host field value: invalid character ' ' in host 'exa mple.com'")
    )]
    // The four-character blocklist this replaced admitted every one of these.
    #[case(
        "exam<ple>.com",
        Some("X-Forwarded-Host is not a Host field value: invalid character '<' in host 'exam<ple>.com'")
    )]
    #[case(
        "%zz.example.com",
        Some("X-Forwarded-Host is not a Host field value: Invalid percent-encoding '%zz'")
    )]
    #[case(
        "[::1",
        Some("X-Forwarded-Host is not a Host field value: IP literal '[::1' is missing its ']'")
    )]
    #[case(
        "[::zz]:8080",
        Some("X-Forwarded-Host is not a Host field value: '::zz' is not an IPv6 address")
    )]
    #[case(
        "[::1]:notnum",
        Some("X-Forwarded-Host is not a Host field value: invalid character 'n' in port 'notnum'")
    )]
    fn a_host_member_is_measured_against_the_host_abnf(
        #[case] value: &str,
        #[case] expected: Option<&str>,
    ) {
        assert_eq!(
            judge(&[("x-forwarded-host", value)]).as_deref(),
            expected,
            "{value}"
        );
    }

    #[test]
    fn every_field_line_is_read() {
        // A proxy chain appends by adding a line as often as by extending one.
        // Reading only the first left the second hop unexamined.
        assert_eq!(
            judge(&[
                ("x-forwarded-for", "192.0.2.43"),
                ("x-forwarded-for", "not-an-ip"),
            ])
            .as_deref(),
            Some("X-Forwarded-For is not a node identifier: 'not-an-ip' is neither an IPv4 address, an IPv6 address, `unknown`, nor an obfuscated identifier (which must begin with `_` and hold only letters, digits, `.`, `_` and `-`)")
        );
    }

    #[test]
    fn an_octet_outside_us_ascii_reaches_the_production_that_excludes_it() {
        // `to_str` refuses every octet outside visible US-ASCII, so the whole
        // field used to vanish and a test asserted that it should. %xFF is not
        // an address, `unknown`, or an obfuscated identifier.
        let message = judge_bytes(&[("x-forwarded-for", b"\xff")]).expect("a finding");
        assert!(
            message.starts_with("X-Forwarded-For is not a node identifier: '\u{ff}'"),
            "{message}"
        );
    }

    #[test]
    fn a_response_carrying_one_of_these_names_is_not_examined() {
        // §7.4 is written about what a proxy receives on a request, and no
        // sentence measures a response value. The rule used to walk both.
        let rule = XForwardedConsistent;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[
                ("x-forwarded-for", "not-an-ip"),
                ("x-forwarded-host", "user@host"),
            ],
        );
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .is_none());
    }

    #[test]
    fn scope_is_the_request_direction() {
        assert_eq!(
            XForwardedConsistent.scope(),
            crate::rules::RuleScope::Client
        );
    }

    #[test]
    fn published_examples_are_judged_the_way_they_are_labelled() {
        use crate::rules::Compliance;

        let mut saw_a_finding = false;
        for ex in XForwardedConsistent.examples() {
            // The first line is the request line and is checked to be one rather
            // than skipped: a `skip(1)` that never looks at what it dropped is
            // how a field line goes unjudged when an example is edited later.
            let mut lines = ex.snippet.lines();
            let request_line = lines.next().expect("a snippet with a request line");
            assert!(
                request_line.ends_with(" HTTP/1.1"),
                "not a request line: {request_line:?}"
            );
            let pairs: Vec<(&str, &str)> = lines
                .map(|l| {
                    l.split_once(": ")
                        .unwrap_or_else(|| panic!("not a field line: {l:?}"))
                })
                .collect();
            let found = judge(&pairs);
            match ex.compliance {
                Compliance::Compliant => assert!(
                    found.is_none(),
                    "rule reports its Compliant example {:?}: {found:?}",
                    ex.snippet
                ),
                Compliance::NonCompliant => {
                    assert!(
                        found.is_some(),
                        "rule accepts its NonCompliant example {:?}",
                        ex.snippet
                    );
                    saw_a_finding = true;
                }
            }
        }
        assert!(saw_a_finding, "the guard ran without exercising a finding");
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "x_forwarded_consistent");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
