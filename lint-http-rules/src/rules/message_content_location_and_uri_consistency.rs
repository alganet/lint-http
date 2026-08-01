// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageContentLocationAndUriConsistency;

impl Rule for MessageContentLocationAndUriConsistency {
    fn id(&self) -> &'static str {
        "message_content_location_and_uri_consistency"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
        let Some(resp) = &tx.response else {
            return None;
        };

        let vals: Vec<_> = resp.headers.get_all("content-location").iter().collect();

        // Neither alternative of the grammar is a `#(...)` list, so the §5.3 exception
        // does not apply and a message carries at most one Content-Location field line.
        // The damage is quiet rather than loud: "," is a legal sub-delim inside a path
        // and query, so a recipient combining two field lines gets "/a,/b" — a
        // well-formed URI that identifies neither representation.
        // cite(RFC 9110 § 8.7): "Content-Location = absolute-URI / partial-URI"
        // cite(RFC 9110 § 5.5): "Fields that only anticipate a single member as the field value are referred to as "singleton fields"."
        // cite(RFC 9110 § 5.3): "a sender MUST NOT generate multiple field lines with the same name in a message (whether in the headers or trailers) or append a field line when a field line of the same name already exists in the message, unless that field's definition allows multiple field line values to be recombined as a comma-separated list"
        if vals.len() > 1 {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Multiple Content-Location header fields present; Content-Location is a singleton field with no list alternative (RFC 9110 §8.7), so a message carries at most one Content-Location field line (RFC 9110 §5.3)".into(),
            });
        }

        for hv in vals {
            // UTF-8 check
            let Ok(s) = hv.to_str() else {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Content-Location header value is not valid UTF-8".into(),
                });
            };

            if s.trim().is_empty() {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Content-Location header must not be empty".into(),
                });
            }

            // cite(RFC 9110 § 8.7): "Content-Location = absolute-URI / partial-URI"
            if crate::helpers::uri::contains_whitespace(s) {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Content-Location header must not contain whitespace".into(),
                });
            }

            if let Some(msg) = crate::helpers::uri::check_percent_encoding(s) {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: msg,
                });
            }

            if let Some(msg) = crate::helpers::uri::validate_scheme_if_present(s) {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: msg,
                });
            }

            // The comparison the spec asks for is between the target URI and the
            // Content-Location *after conversion to absolute form*, and it is
            // scoped to 2xx.
            if (200..300).contains(&resp.status) {
                // Request path (if any) — preserve query when present and ignore fragment
                let req_path_opt = crate::helpers::uri::extract_path_and_query_from_request_target(
                    &tx.request.uri,
                );

                // If the request-target carries no path (authority-form or '*'), skip the consistency check
                let Some(req_path) = req_path_opt else {
                    continue;
                };
                let req_path = crate::helpers::uri::normalize_path_and_query(&req_path);

                // The value may be a partial-URI, which means nothing on its own:
                // it names a resource only once resolved against the target URI.
                // Comparing the two as raw strings reports every relative form as
                // a different resource, including one that resolves right back to
                // the target.
                let cl_path_opt =
                    crate::helpers::uri::resolve_reference_path_and_query(&req_path, s);

                // If absolute, also compare origin
                let cl_origin_opt = crate::helpers::uri::extract_origin_if_absolute(s);
                let req_origin_opt =
                    crate::helpers::uri::extract_origin_if_absolute(&tx.request.uri);

                let mut matches = false;
                if let Some(cl_path) = cl_path_opt.as_deref() {
                    // Scheme and host fold case; everything else in a URI does not,
                    // so the path and query compare byte for byte.
                    let origins_agree = match (req_origin_opt.as_deref(), cl_origin_opt.as_deref())
                    {
                        (Some(req_origin), Some(cl_origin)) => {
                            req_origin.eq_ignore_ascii_case(cl_origin)
                        }
                        // Only one side is in absolute form. An origin-form
                        // request-target keeps the target URI's authority in
                        // Host, which this rule does not reach, so the paths
                        // decide alone.
                        _ => true,
                    };
                    matches = origins_agree && req_path == cl_path;
                }

                if !matches {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Content-Location identifies a different resource than the request target; RFC 9110 §8.7 permits this (a negotiated variant, a 201 pointing at the created resource, or a report on a POST), so confirm it is deliberate".into(),
                    });
                }
            }
        }

        None
    }

    fn description(&self) -> &'static str {
        "Validate `Content-Location` header values. The value must be a well-formed URI reference (`absolute-URI / partial-URI`) with no whitespace, sound percent-encoding and a valid scheme where one is present, and — since neither alternative of the grammar is a comma-separated list — a message carries at most one `Content-Location` field line (RFC 9110 §5.3).\n\nFor 2xx responses the rule additionally compares the value against the request target, resolving a `partial-URI` against it first as RFC 9110 §8.7 requires (\"after conversion to absolute form\"), so a relative reference that names the target resource is not reported.\n\n**A difference is not a protocol error.** RFC 9110 §8.7 attaches no requirement to a differing `Content-Location`: it means \"the origin server claims that the URI is an identifier for a different resource\", which is exactly what a negotiated variant, a 201 pointing at the created resource, or a POST report is supposed to say. The rule reports the difference as an advisory — `config_example.toml` ships it at `info` — because the claim \"can only be trusted if both identifiers share the same resource owner, which cannot be programmatically determined via HTTP\", so it is worth a human glance and nothing stronger. Raise the severity only if your deployment intends `Content-Location` to always echo the target."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[crate::rules::SpecRef {
            spec: "RFC 9110",
            section: Some("8.7"),
            url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.7",
            note: "Content-Location",
        }]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "GET /foo HTTP/1.1\nHost: example.com\n\nHTTP/1.1 200 OK\nContent-Location: /foo\nContent-Type: text/plain\n\nHello",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(absolute)"),
                snippet: "GET /foo HTTP/1.1\nHost: example.com\n\nHTTP/1.1 200 OK\nContent-Location: http://example.com/foo\nContent-Type: text/plain\n\nHello",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(relative reference resolving to the target)"),
                snippet: "GET /dir/foo.html HTTP/1.1\nHost: example.com\n\nHTTP/1.1 200 OK\nContent-Location: foo.html\nContent-Type: text/html\n\n<p>Hello",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(invalid percent-encoding)"),
                snippet: "HTTP/1.1 200 OK\nContent-Location: /bad%2G",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(contains whitespace)"),
                snippet: "HTTP/1.1 200 OK\nContent-Location: /bad path",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(two field lines — Content-Location is a singleton)"),
                snippet: "HTTP/1.1 200 OK\nContent-Location: /foo\nContent-Location: /bar",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(negotiated variant — reported as an advisory, not an error)"),
                snippet: "GET /foo HTTP/1.1\nHost: example.com\nAccept-Language: en\n\nHTTP/1.1 200 OK\nContent-Location: /foo.en.html\nContent-Type: text/html\n\n<p>Hello",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &MessageContentLocationAndUriConsistency;

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;
    use rstest::rstest;

    fn make_tx_with_req_uri(
        req_uri: &str,
        status: u16,
        headers: &[(&str, &str)],
    ) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.uri = req_uri.into();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(headers),
            body_length: None,
            trailers: None,
        });
        tx
    }

    #[rstest]
    #[case("/foo", 200, &[ ("content-location", "/foo") ], false)]
    #[case("/foo", 200, &[ ("content-location", "/bar") ], true)]
    #[case("/foo", 200, &[ ("content-location", "http://example.com/foo") ], false)]
    #[case("http://example.com/foo", 200, &[ ("content-location", "http://example.com/foo") ], false)]
    #[case("http://example.com/foo", 200, &[ ("content-location", "http://example.com/bar") ], true)]
    // Query-string preservation: mismatched queries should be considered inconsistent
    #[case("/foo?x=1", 200, &[ ("content-location", "/foo?x=1") ], false)]
    #[case("/foo?x=1", 200, &[ ("content-location", "/foo?x=2") ], true)]
    #[case("http://example.com/foo?x=1", 200, &[ ("content-location", "http://example.com/foo?x=2") ], true)]
    // Authority-form request-targets (e.g., CONNECT) carry no path — skip consistency check
    #[case("example.com:443", 200, &[ ("content-location", "/foo") ], false)]
    fn check_consistency_cases(
        #[case] req_uri: &str,
        #[case] status: u16,
        #[case] headers: &[(&str, &str)],
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageContentLocationAndUriConsistency;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_content_location_and_uri_consistency",
        ]);
        let tx = make_tx_with_req_uri(req_uri, status, headers);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(v.is_some());
        } else {
            assert!(v.is_none());
        }
        Ok(())
    }

    #[test]
    fn bad_percent_encoding_reports_violation() {
        let rule = MessageContentLocationAndUriConsistency;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_content_location_and_uri_consistency",
        ]);
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-location", "/bad%2G")],
        );
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Invalid percent-encoding"));
    }

    #[test]
    fn whitespace_in_value_reports_violation() {
        let rule = MessageContentLocationAndUriConsistency;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_content_location_and_uri_consistency",
        ]);
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-location", "/a b")],
        );
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("must not contain whitespace"));
    }

    #[test]
    fn non_utf8_header_value_is_violation() {
        let rule = MessageContentLocationAndUriConsistency;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_content_location_and_uri_consistency",
        ]);
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = hyper::HeaderMap::new();
        hm.insert(
            "content-location",
            HeaderValue::from_bytes(&[0xff]).unwrap(),
        );
        tx.response.as_mut().unwrap().headers = hm;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn empty_value_reports_violation() {
        let rule = MessageContentLocationAndUriConsistency;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_content_location_and_uri_consistency",
        ]);
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-location", "")],
        );
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn fragment_in_content_location_is_ignored_for_matching() {
        let rule = MessageContentLocationAndUriConsistency;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_content_location_and_uri_consistency",
        ]);
        let tx = make_tx_with_req_uri("/foo", 200, &[("content-location", "/foo#frag")]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[rstest]
    // A relative-path reference that resolves straight back to the target URI.
    #[case("/dir/foo.html", "foo.html", false)]
    #[case("/dir/foo.html", "./foo.html", false)]
    #[case("/dir/sub/foo", "../sub/foo", false)]
    // Dot-segments in an absolute-path reference normalize away.
    #[case("/foo", "/a/../foo", false)]
    // The query rides along through resolution.
    #[case("/dir/foo?x=1", "foo?x=1", false)]
    #[case("/dir/foo?x=1", "foo?x=2", true)]
    // A relative reference that really does name something else still reports.
    #[case("/dir/foo.html", "bar.html", true)]
    #[case("/dir/sub/foo", "../bar", true)]
    // No comparable path: reported, since the rule cannot show they agree.
    #[case("/foo", "mailto:a@b", true)]
    fn relative_references_resolve_against_the_target(
        #[case] req_uri: &str,
        #[case] content_location: &str,
        #[case] expect_violation: bool,
    ) {
        let rule = MessageContentLocationAndUriConsistency;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_content_location_and_uri_consistency",
        ]);
        let tx = make_tx_with_req_uri(req_uri, 200, &[("content-location", content_location)]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert_eq!(
            v.is_some(),
            expect_violation,
            "{req_uri} + Content-Location: {content_location} -> {v:?}"
        );
    }

    #[test]
    fn shipped_severity_is_advisory() {
        // RFC 9110 §8.7 permits a differing Content-Location, so the mismatch
        // report is guidance rather than a protocol error. Guard the shipped
        // default against a silent bump.
        let s = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../config_example.toml"),
        )
        .expect("config_example.toml must be readable");
        let section = s
            .split("[rules.message_content_location_and_uri_consistency]")
            .nth(1)
            .expect("rule must appear in config_example.toml");
        let shipped = section
            .lines()
            .take_while(|l| !l.starts_with('['))
            .find_map(|l| l.strip_prefix("severity = "))
            .expect("rule must ship a severity");
        assert_eq!(shipped.trim(), "\"info\"");
    }

    #[test]
    fn multiple_content_location_field_lines_report_violation() {
        let rule = MessageContentLocationAndUriConsistency;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_content_location_and_uri_consistency",
        ]);
        // Both lines are individually well-formed and the first even matches the
        // target, so nothing else in the rule can catch this.
        let tx = make_tx_with_req_uri(
            "/foo",
            200,
            &[("content-location", "/foo"), ("content-location", "/bar")],
        );
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Multiple Content-Location"));
    }

    #[test]
    fn colon_in_path_segment_is_not_read_as_a_scheme() {
        let rule = MessageContentLocationAndUriConsistency;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_content_location_and_uri_consistency",
        ]);
        // ':' is a legal `pchar`; these are absolute-path references, not
        // schemed URIs, and must not be reported as a malformed scheme.
        for target in ["/users/urn:uuid:1", "/v1/entities/x:batchGet", "/a?x=b:c"] {
            let tx = make_tx_with_req_uri(target, 200, &[("content-location", target)]);
            let v = rule.check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            );
            assert!(v.is_none(), "unexpected violation for {target}: {v:?}");
        }
    }

    #[test]
    fn trailing_slash_mismatch_reports_violation() {
        let rule = MessageContentLocationAndUriConsistency;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_content_location_and_uri_consistency",
        ]);
        let tx = make_tx_with_req_uri("/foo", 200, &[("content-location", "/foo/")]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn origin_case_insensitive_match() {
        let rule = MessageContentLocationAndUriConsistency;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_content_location_and_uri_consistency",
        ]);
        let tx = make_tx_with_req_uri(
            "http://EXAMPLE.com/foo",
            200,
            &[("content-location", "http://example.com/foo")],
        );
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_content_location_and_uri_consistency");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn validate_rules_with_invalid_config_missing_severity() {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_content_location_and_uri_consistency");
        // remove severity to simulate invalid config
        if let Some(toml::Value::Table(ref mut table)) = cfg
            .rules
            .get_mut("message_content_location_and_uri_consistency")
        {
            table.remove("severity");
        }

        let err = crate::rules::validate_rules(&cfg).expect_err("expected validation to fail");
        assert!(err.to_string().contains("Missing required 'severity'"));
    }

    #[test]
    fn scope_is_server() {
        let rule = MessageContentLocationAndUriConsistency;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }
}
