// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct Http3PseudoHeadersValid;

impl Rule for Http3PseudoHeadersValid {
    fn id(&self) -> &'static str {
        "http3_pseudo_headers_valid"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
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
            // Only applies to HTTP/3 transactions. The version gate is scoping, not a
            // normative check, so it carries no cite; each requirement below cites the
            // sentence it enforces. What it reads is the major digit and not a string:
            // this version has no version field on the wire, so the value is one a
            // writer chose, and `http_version` is where the production lives.
            if !crate::http_version::is_major(&tx.request.version, 3) {
                return None;
            }

            // :method is required. (The :scheme half of the same sentence is not
            // checked — the canonical model does not retain scheme for origin-form
            // requests, as the description says.)
            // cite(RFC 9114 § 4.3.1): "All HTTP/3 requests MUST include exactly one value for the :method, :scheme, and :path pseudo-header fields, unless the request is a CONNECT request; see Section 4.4."
            let method = tx.request.method.trim();
            if method.is_empty() {
                return Some(self.violation(
                    ctx.severity,
                    "HTTP/3 request missing required ':method' pseudo-header".into(),
                ));
            }

            let is_connect = method.eq_ignore_ascii_case("CONNECT");

            if is_connect {
                // CONNECT requires an authority; in the canonical model it comes from the
                // request-target (authority-form) or, for extended CONNECT using
                // origin-form, from the Host header.
                // cite(RFC 9114 § 4.4): "The :authority pseudo-header field contains the host and port to connect to"
                let uri_trimmed = tx.request.uri.trim();
                if uri_trimmed.is_empty() {
                    return Some(self.violation(ctx.severity, "HTTP/3 CONNECT request missing required ':authority' pseudo-header or Host header"
                                .into()));
                }
                let authority =
                    crate::helpers::uri::extract_authority_from_request_target(uri_trimmed);
                let has_authority = authority.is_some();
                let has_host = tx.request.headers.contains_key("host");
                let is_origin_form = uri_trimmed.starts_with('/');
                if is_origin_form {
                    // Extended CONNECT: origin-form target, authority MUST come from Host.
                    if !has_host {
                        return Some(self.violation(ctx.severity, "HTTP/3 extended CONNECT request with origin-form target must include Host header as authority"
                                .into()));
                    }
                } else if !has_authority && !has_host {
                    // Authority-form (or absolute-form) CONNECT without any authority.
                    return Some(self.violation(ctx.severity, "HTTP/3 CONNECT request must include ':authority' pseudo-header or Host header"
                                .into()));
                }

                // § 4.4 gives a CONNECT's `:authority` two components and no
                // third: the host and port to connect to. This is not the scheme
                // question the non-CONNECT branch asks — the field here is a
                // tunnel destination, not an http(s) URI's authority — so the
                // sentence is § 4.4's own and the '@' is reported whatever came
                // before it. The password half is withheld from the finding
                // (RFC 3986 § 3.2.1, at the shared helper).
                //
                // Only an authority-form target is judged. An absolute-form
                // CONNECT target is a conforming extended CONNECT and a malformed
                // basic one with nothing in a capture to choose between them —
                // the same decline the HTTP/2 twin publishes — and § 4.4's
                // sentence describes the basic form only.
                // cite(RFC 9114 § 4.4): "The :authority pseudo-header field contains the host and port to connect to"
                if let Some(authority) = authority
                    .filter(|a| a.contains('@'))
                    .filter(|_| crate::helpers::uri::scheme_authority_marker(uri_trimmed).is_none())
                {
                    let shown = crate::helpers::uri::userinfo_password_withheld(&authority)
                        .unwrap_or(authority);
                    return Some(self.violation(ctx.severity, format!(
                            "HTTP/3 CONNECT ':authority' '{}' carries a userinfo subcomponent and its '@' delimiter: the field is only the host and port to connect to",
                            crate::helpers::headers::shown_in_finding(&shown)
                        )));
                }
            } else {
                // Non-CONNECT: the request-target is either the asterisk-form (OPTIONS
                // only) or a path. RFC 9110 § 7.1 permits "*" for OPTIONS and forbids it
                // for every other method.
                // cite(RFC 9110 § 7.1): "For OPTIONS (Section 9.3.7), the request target can be a single asterisk ("*")."
                // cite(RFC 9110 § 7.1): "These forms MUST NOT be used with other methods."
                let uri_trimmed = tx.request.uri.trim();
                if uri_trimmed == "*" {
                    if !method.eq_ignore_ascii_case("OPTIONS") {
                        return Some(self.violation(ctx.severity, "Asterisk ('*') request-target is only permitted with OPTIONS method"
                                    .into()));
                    }
                } else {
                    // cite(RFC 9114 § 4.3.1): "This pseudo-header field MUST NOT be empty for "http" or "https" URIs; "http" or "https" URIs that do not contain a path component MUST include a value of / (ASCII 0x2f)."
                    let has_path =
                        crate::helpers::uri::extract_path_from_request_target(uri_trimmed)
                            .is_some();
                    if !has_path {
                        return Some(self.violation(
                            ctx.severity,
                            "HTTP/3 request missing required ':path' pseudo-header".into(),
                        ));
                    }
                }

                // HTTP/3 always runs over QUIC/TLS, so the scheme is always http or
                // https, both of which have a mandatory authority component — the
                // requirement applies to every non-CONNECT request.
                // cite(RFC 9114 § 4.3.1): "If the :scheme pseudo-header field identifies a scheme that has a mandatory authority component (including "http" and "https"), the request MUST contain either an :authority pseudo-header field or a Host header field."
                let authority =
                    crate::helpers::uri::extract_authority_from_request_target(&tx.request.uri);
                let has_host = tx.request.headers.contains_key("host");
                if authority.is_none() && !has_host {
                    return Some(
                        self.violation(
                            ctx.severity,
                            "HTTP/3 request must include ':authority' pseudo-header or Host header"
                                .into(),
                        ),
                    );
                }

                // § 4.3.1's userinfo MUST NOT, readable exactly where the
                // userinfo is. The deprecated subcomponent travels in
                // `:authority`, the capture shows that field only where the
                // transport reassembled it into an absolute-form target — and an
                // absolute-form target is also the one place the scheme the
                // sentence gates on is on the wire, so the gate and the evidence
                // arrive together or not at all. The twin sentence for HTTP/2 is
                // enforced by `http2_pseudo_headers_valid` in the same
                // shape. The password half is withheld from the finding
                // (RFC 3986 § 3.2.1, at the shared helper).
                // cite(RFC 9114 § 4.3.1): "The authority MUST NOT include the deprecated userinfo subcomponent for URIs of scheme "http" or "https"."
                if let Some(marker) = crate::helpers::uri::scheme_authority_marker(uri_trimmed) {
                    let scheme = &uri_trimmed[..marker];
                    if let Some(authority) = authority.filter(|a| a.contains('@')) {
                        if scheme.eq_ignore_ascii_case("http")
                            || scheme.eq_ignore_ascii_case("https")
                        {
                            let shown = crate::helpers::uri::userinfo_password_withheld(&authority)
                                .unwrap_or(authority);
                            return Some(self.violation(ctx.severity, format!(
                                    "HTTP/3 ':authority' '{}' of an '{scheme}' target includes the deprecated userinfo subcomponent and its '@' delimiter",
                                    crate::helpers::headers::shown_in_finding(&shown)
                                )));
                        }
                    }
                }
            }

            // **The response half is not this rule's.** This branch used to report a
            // `:status` outside 100–599, and the constraint it enforced was RFC 9110
            // § 15's, not HTTP/3's: RFC 9114 § 4.3.2 defines the field as carrying "the
            // HTTP status code; see Section 15 of [HTTP]" and states no range of its
            // own. Behind the major-version gate above, the same out-of-range
            // status over HTTP/1.1 or HTTP/2 went unreported here and the HTTP/3 one was
            // reported twice — `status_code_valid_range` asks it of every
            // version. Same shape as the three checks `http3_status_code_valid`
            // surrendered for RFC 9110 § 15.2.
            //
            // What RFC 9114 § 4.3.2 does require of a response — that the field be
            // present at all — cannot fail in this model: `ResponseInfo.status` is a
            // `u16` that always holds a value, so a response with no `:status` has no
            // representation to check.
            //
            // cite(RFC 9114 § 4.3.2): "For responses, a single ":status" pseudo-header field is defined that carries the HTTP status code; see Section 15 of [HTTP]."
            // cite(RFC 9114 § 4.3.2): "This pseudo-header field MUST be included in all responses; otherwise, the response is malformed (see Section 4.1.2)."

            None
        };
        Vec::from_iter(finding())
    }

    fn title(&self) -> Option<&'static str> {
        Some("HTTP/3 Pseudo-Headers Validity")
    }

    fn description(&self) -> &'static str {
        "HTTP/3 requests encode control data as pseudo-header fields. This rule validates that every request includes exactly one `:method` pseudo-header field and that every non-CONNECT request includes a non-empty `:path` pseudo-header field.\n\nFor schemes with a mandatory authority component (including `http` and `https`), the HTTP/3 specification requires that the request contain either an `:authority` pseudo-header field or a `Host` header field. This rule enforces that requirement by checking that at least one of `:authority` or `Host` is present. It does not validate the `:scheme` pseudo-header, because the canonical transaction model used by lint-http does not retain scheme information for origin-form requests.\n\n**The deprecated userinfo subcomponent is reported where it can be seen.** RFC 9114 §4.3.1 forbids `:authority` from including it for URIs of scheme `http` or `https`, and the capture shows `:authority` only where the transport reassembled it into an absolute-form target — which is also the one place the scheme the sentence gates on is on the wire, so the gate and the evidence arrive together or not at all. A CONNECT's `:authority` is §4.4's host-and-port tunnel destination, with no scheme to gate on and no third component, so a userinfo in an authority-form target is reported outright — while an absolute-form CONNECT target is a conforming extended CONNECT and a malformed basic one with nothing in a capture to choose between them, and is declined here as the HTTP/2 twin declines it. Both findings withhold the password half (RFC 3986 §3.2.1). The twin sentence for HTTP/2 (RFC 9113 §8.3.1) is `http2_pseudo_headers_valid`'s.\n\n**This rule reads requests only.** RFC 9114 §4.3.2 requires a response to carry exactly one `:status` pseudo-header field, which the canonical transaction model always supplies as a `u16`, so its absence has no representation here. The range that value must fall in is RFC 9110 §15's and is the same for every HTTP version — §4.3.2 states none of its own — so an out-of-range status is reported by `status_code_valid_range`, whatever version carried it. This rule used to report it too, but only when both ends spoke HTTP/3."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9114",
                section: Some("4.3"),
                url: "https://www.rfc-editor.org/rfc/rfc9114.html#section-4.3",
                note: "HTTP Control Data",
            },
            crate::rules::SpecRef {
                spec: "RFC 9114",
                section: Some("4.3.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9114.html#section-4.3.1",
                note: "Request Pseudo-Header Fields — the exactly-one MUST for `:method`, \
                       `:scheme` and `:path`, the `:authority`-or-Host requirement for schemes \
                       with a mandatory authority component, and the MUST NOT on the deprecated \
                       userinfo subcomponent for http and https URIs",
            },
            crate::rules::SpecRef {
                spec: "RFC 3986",
                section: Some("3.2.1"),
                url: "https://www.rfc-editor.org/rfc/rfc3986.html#section-3.2.1",
                note: "User Information — the sentence asking an application not to render what \
                       follows the first colon of a userinfo, which is why both findings here \
                       withhold the password half",
            },
            crate::rules::SpecRef {
                spec: "RFC 9114",
                section: Some("4.3.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9114.html#section-4.3.2",
                note: "Response Pseudo-Header Fields",
            },
            crate::rules::SpecRef {
                spec: "RFC 9114",
                section: Some("4.4"),
                url: "https://www.rfc-editor.org/rfc/rfc9114.html#section-4.4",
                note: "The CONNECT Method",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("7.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-7.1",
                note: "Determining the Target Resource (asterisk-form request target)",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "GET /resource HTTP/3\nHost: example.com\nAccept: text/html",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "OPTIONS * HTTP/3\nHost: example.com",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "CONNECT example.com:443 HTTP/3",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/3 200 OK\nContent-Type: text/html",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "GET /resource HTTP/3\nAccept: text/html",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: " HTTP/3\nHost: example.com",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "GET * HTTP/3\nHost: example.com",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/3 0",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(the deprecated userinfo subcomponent in :authority)"),
                snippet: "GET https://user@example.com/resource HTTP/3",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &Http3PseudoHeadersValid;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn make_h3_transaction() -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.version = "HTTP/3.0".into();
        tx
    }

    fn make_h3_transaction_with_response(
        status: u16,
        resp_headers: &[(&str, &str)],
    ) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(status, resp_headers);
        tx.request.version = "HTTP/3.0".into();
        if let Some(ref mut resp) = tx.response {
            resp.version = "HTTP/3.0".into();
        }
        tx
    }

    // --- :method pseudo-header required ---

    #[test]
    fn empty_method_is_violation() {
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "".into();

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains(":method"));
    }

    #[test]
    fn whitespace_only_method_is_violation() {
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "   ".into();

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains(":method"));
    }

    // --- the deprecated userinfo subcomponent ---

    fn judge(method: &str, uri: &str) -> Option<String> {
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = method.into();
        tx.request.uri = uri.into();
        crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .map(|v| v.message)
    }

    /// § 4.3.1's MUST NOT names the two schemes it is about, and the capture
    /// shows `:authority` where the transport reassembled it into an
    /// absolute-form target — the one place the scheme is on the wire too.
    #[rstest]
    #[case("https://user@example.com/p", true)]
    #[case("http://user:pass@example.com/p", true)]
    #[case("HTTPS://user@example.com/p", true)]
    // Another scheme is outside the sentence.
    #[case("ftp://user@example.com/p", false)]
    // No userinfo, nothing to report.
    #[case("https://example.com/p", false)]
    fn userinfo_is_reported_for_http_and_https_targets(#[case] uri: &str, #[case] reported: bool) {
        let message = judge("GET", uri);
        assert_eq!(
            message.as_deref().is_some_and(|m| m.contains("userinfo")),
            reported,
            "{uri}: {message:?}"
        );
    }

    /// A CONNECT's `:authority` is § 4.4's host and port, with no scheme to
    /// gate on: the '@' is reported whatever came before it.
    #[test]
    fn connect_authority_with_userinfo_is_reported() {
        let msg = judge("CONNECT", "user@example.com:443").expect("reported");
        assert_eq!(
            msg,
            "HTTP/3 CONNECT ':authority' 'user@example.com:443' carries a userinfo subcomponent \
             and its '@' delimiter: the field is only the host and port to connect to"
        );
        assert_eq!(judge("CONNECT", "example.com:443"), None);

        // An absolute-form CONNECT target is a conforming extended CONNECT
        // and a malformed basic one, with nothing in a capture to choose
        // between them — the HTTP/2 twin's decline, mirrored here, so the
        // § 4.4 wording is never pinned on a target § 4.4 may not describe.
        assert_eq!(judge("CONNECT", "https://user@example.com/ws"), None);
    }

    /// Both findings withhold the password half (RFC 3986 § 3.2.1): the
    /// finding is about credentials arriving where a server logs, and a lint
    /// report must not be one more place they are written in clear.
    #[test]
    fn userinfo_findings_withhold_the_password() {
        let msg = judge("GET", "https://user:s3cret@example.com/p").expect("reported");
        assert_eq!(
            msg,
            "HTTP/3 ':authority' 'user:...@example.com' of an 'https' target includes the \
             deprecated userinfo subcomponent and its '@' delimiter"
        );
        assert!(!msg.contains("s3cret"), "{msg}");

        let msg = judge("CONNECT", "user:s3cret@example.com:443").expect("reported");
        assert!(msg.contains("'user:...@example.com:443'"), "{msg}");
        assert!(!msg.contains("s3cret"), "{msg}");
    }

    // --- :path pseudo-header required for non-CONNECT ---

    #[test]
    fn get_with_path_is_ok() {
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "GET".into();
        tx.request.uri = "https://example.com/path".into();

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn get_origin_form_with_host_is_ok() {
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "GET".into();
        tx.request.uri = "/resource".into();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("host", "example.com")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn get_without_path_is_violation() {
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "GET".into();
        tx.request.uri = "example.com:443".into(); // authority-form, no path
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("host", "example.com")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains(":path"));
    }

    #[test]
    fn options_asterisk_with_host_is_ok() {
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "OPTIONS".into();
        tx.request.uri = "*".into();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("host", "example.com")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn asterisk_non_options_is_violation() {
        // Asterisk-form is only permitted with OPTIONS (RFC 9110 §7.1).
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "GET".into();
        tx.request.uri = "*".into();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("host", "example.com")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Asterisk"));
    }

    #[rstest]
    #[case("POST")]
    #[case("PUT")]
    #[case("DELETE")]
    #[case("PATCH")]
    #[case("HEAD")]
    fn asterisk_non_options_methods_are_violation(#[case] bad_method: &str) {
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = bad_method.into();
        tx.request.uri = "*".into();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("host", "example.com")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Asterisk"));
    }

    // --- :authority or Host required ---

    #[test]
    fn origin_form_without_host_is_violation() {
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "GET".into();
        tx.request.uri = "/resource".into();
        tx.request.headers = hyper::HeaderMap::new();

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains(":authority"));
    }

    #[test]
    fn absolute_form_has_authority_is_ok() {
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "GET".into();
        tx.request.uri = "https://example.com/path".into();
        tx.request.headers = hyper::HeaderMap::new(); // no Host needed

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn asterisk_without_host_or_authority_is_violation() {
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "OPTIONS".into();
        tx.request.uri = "*".into();
        tx.request.headers = hyper::HeaderMap::new();

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains(":authority"));
    }

    // --- CONNECT ---

    #[test]
    fn connect_with_authority_is_ok() {
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "CONNECT".into();
        tx.request.uri = "example.com:443".into();

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn connect_with_empty_uri_is_violation() {
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "CONNECT".into();
        tx.request.uri = "".into();

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains(":authority"));
    }

    #[test]
    fn connect_with_whitespace_only_uri_is_violation() {
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "CONNECT".into();
        tx.request.uri = "   ".into();

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains(":authority"));
    }

    #[test]
    fn connect_origin_form_with_host_is_ok() {
        // Extended CONNECT (RFC 9220) may use origin-form with Host header.
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "CONNECT".into();
        tx.request.uri = "/ws".into();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("host", "example.com")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn connect_origin_form_without_host_is_violation() {
        // Extended CONNECT with origin-form but no Host header.
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "CONNECT".into();
        tx.request.uri = "/ws".into();
        tx.request.headers = hyper::HeaderMap::new();

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("extended CONNECT"));
    }

    #[test]
    fn connect_asterisk_without_host_is_violation() {
        // CONNECT with "*" URI: extract_authority returns None, no Host → violation.
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "CONNECT".into();
        tx.request.uri = "*".into();
        tx.request.headers = hyper::HeaderMap::new();

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains(":authority"));
    }

    #[test]
    fn connect_asterisk_with_host_is_ok() {
        // CONNECT with "*" URI but Host header present → ok.
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "CONNECT".into();
        tx.request.uri = "*".into();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("host", "example.com:443")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn connect_authority_form_without_host_is_ok() {
        // Authority-form (host:port) is valid for CONNECT even without Host header.
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "CONNECT".into();
        tx.request.uri = "example.com:443".into();
        tx.request.headers = hyper::HeaderMap::new();

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    // --- Response :status ---

    #[test]
    fn response_valid_status_is_ok() {
        let rule = Http3PseudoHeadersValid;
        let tx = make_h3_transaction_with_response(200, &[]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    /// The status range is RFC 9110 § 15's and holds for every version, so it is
    /// `status_code_valid_range`'s finding and not this rule's. These cases
    /// pin the decline: each was asserted as a violation here until the branch was
    /// removed, and each is still reported — over HTTP/3 as over every other
    /// version — by the rule that owns the question.
    #[rstest]
    #[case(0)]
    #[case(99)]
    #[case(600)]
    #[case(1000)]
    fn out_of_range_status_is_not_this_rules_finding(#[case] status: u16) {
        let rule = Http3PseudoHeadersValid;
        let tx = make_h3_transaction_with_response(status, &[]);
        let history = crate::transaction_history::TransactionHistory::empty();

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none(), "{v:?}");

        let owner = crate::rules::status_code_valid_range::StatusCodeValidRange;
        assert!(
            crate::test_helpers::run_rule(
                &owner,
                &tx,
                &history,
                &crate::test_helpers::make_test_config_with_enabled_rules(&[owner.id()]),
            )
            .is_some(),
            "status {status} over HTTP/3 is reported by nobody"
        );
    }

    #[rstest]
    #[case(100)]
    #[case(200)]
    #[case(301)]
    #[case(404)]
    #[case(500)]
    #[case(599)]
    fn response_valid_status_range_is_ok(#[case] status: u16) {
        let rule = Http3PseudoHeadersValid;
        let tx = make_h3_transaction_with_response(status, &[]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    // --- HTTP version gating ---

    #[rstest]
    #[case("HTTP/1.1")]
    #[case("HTTP/1.0")]
    #[case("HTTP/2.0")]
    #[case("HTTP/2.0")]
    fn non_h3_version_is_skipped(#[case] version: &str) {
        let rule = Http3PseudoHeadersValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.version = version.into();
        tx.request.method = "".into(); // would be a violation for HTTP/3

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    // --- Response version gating ---

    #[test]
    fn response_non_h3_version_not_checked() {
        // HTTP/3 request but HTTP/1.1 upstream response (reverse-proxy).
        let rule = Http3PseudoHeadersValid;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(0, &[]);
        tx.request.version = "HTTP/3.0".into();
        // Response version stays HTTP/1.1 — status 0 should not be flagged.

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    // --- No response case ---

    #[test]
    fn request_only_no_response_is_ok() {
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "GET".into();
        tx.request.uri = "https://example.com/".into();
        tx.response = None;

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    // --- Scope and config validation ---

    #[test]
    fn scope_is_both() {
        let rule = Http3PseudoHeadersValid;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "http3_pseudo_headers_valid");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    // --- RFC edge cases ---

    #[test]
    fn connect_ipv6_authority_is_ok() {
        // CONNECT with bracketed IPv6 authority (RFC 9114 §4.4).
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "CONNECT".into();
        tx.request.uri = "[::1]:443".into();

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn extended_connect_with_scheme_and_path_is_ok() {
        // Extended CONNECT (RFC 9220) includes :scheme, :path, :authority.
        // We do not flag this because we cannot distinguish basic from extended
        // CONNECT in the canonical data model.
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "CONNECT".into();
        tx.request.uri = "https://example.com/ws".into();

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn post_origin_form_with_host_is_ok() {
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "POST".into();
        tx.request.uri = "/submit".into();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("host", "example.com"),
            ("content-type", "application/json"),
        ]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn head_absolute_uri_is_ok() {
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "HEAD".into();
        tx.request.uri = "https://example.com/resource".into();

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn host_present_but_empty_counts_as_present() {
        // An empty Host header still counts as "present" for the authority
        // presence check. Value validation is handled by other rules.
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "GET".into();
        tx.request.uri = "/resource".into();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[("host", "")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn delete_with_absolute_uri_is_ok() {
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "DELETE".into();
        tx.request.uri = "https://example.com/resource/42".into();

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn empty_uri_for_non_connect_is_path_violation() {
        // Empty URI means both :path and :authority are missing.
        // :path check fires first.
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "GET".into();
        tx.request.uri = "".into();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("host", "example.com")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains(":path"));
    }

    #[test]
    fn root_path_with_query_and_host_is_ok() {
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "GET".into();
        tx.request.uri = "/?q=search".into();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("host", "example.com")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn connect_case_insensitive() {
        // Method comparison is case-insensitive.
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "connect".into();
        tx.request.uri = "example.com:443".into();

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn absolute_uri_with_port_is_ok() {
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "GET".into();
        tx.request.uri = "https://example.com:8443/path".into();

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn informational_response_100_is_ok() {
        // 1xx informational responses are valid (RFC 9114 §4.1).
        let rule = Http3PseudoHeadersValid;
        let tx = make_h3_transaction_with_response(100, &[]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn id_returns_correct_value() {
        let rule = Http3PseudoHeadersValid;
        assert_eq!(rule.id(), "http3_pseudo_headers_valid");
    }

    #[test]
    fn connect_with_valid_response_is_ok() {
        // Validates response :status check runs after CONNECT request passes.
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction_with_response(200, &[]);
        tx.request.method = "CONNECT".into();
        tx.request.uri = "example.com:443".into();

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn connect_with_invalid_response_status_is_not_this_rules_finding() {
        // A valid CONNECT request whose response carries an out-of-range status.
        // The request is what this rule reads, and it is well formed; the status is
        // `status_code_valid_range`'s finding on every version.
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction_with_response(0, &[]);
        tx.request.method = "CONNECT".into();
        tx.request.uri = "example.com:443".into();

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none(), "{v:?}");
    }

    #[test]
    fn whitespace_only_uri_non_connect_is_path_violation() {
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "GET".into();
        tx.request.uri = "   ".into();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("host", "example.com")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains(":path"));
    }

    #[test]
    fn both_authority_and_host_present_is_ok() {
        // When both :authority (via absolute URI) and Host are present, no violation.
        // Value consistency is checked by host_and_authority_consistent,
        // which reads the same pair over both versions that carry an :authority.
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "GET".into();
        tx.request.uri = "https://example.com/path".into();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("host", "example.com")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn put_origin_form_with_host_is_ok() {
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "PUT".into();
        tx.request.uri = "/resource/1".into();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("host", "example.com"),
            ("content-type", "application/json"),
        ]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn patch_origin_form_without_host_is_violation() {
        let rule = Http3PseudoHeadersValid;
        let mut tx = make_h3_transaction();
        tx.request.method = "PATCH".into();
        tx.request.uri = "/resource/1".into();
        tx.request.headers = hyper::HeaderMap::new();

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains(":authority"));
    }
}
