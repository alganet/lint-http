// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::access_control_allow_credentials::{
    ACCESS_CONTROL_ALLOW_CREDENTIALS_CONFLICTING, ACCESS_CONTROL_ALLOW_CREDENTIALS_INVALID,
    ACCESS_CONTROL_ALLOW_CREDENTIALS_REDUNDANT, FETCH_3_3_4, FETCH_4_10,
};
use crate::violations::ViolationDef;

/// All three findings are this field's: the value that meant to share and
/// shares nothing, the `false` that states the default, and the `true` that is
/// dead beside a wildcard origin. The origin field is scanned for a `*` and
/// never reported on — what its value may be is
/// `access_control_allow_origin_valid`'s.
static DECLARED: &[&ViolationDef] = &[
    &ACCESS_CONTROL_ALLOW_CREDENTIALS_INVALID,
    &ACCESS_CONTROL_ALLOW_CREDENTIALS_REDUNDANT,
    &ACCESS_CONTROL_ALLOW_CREDENTIALS_CONFLICTING,
];

pub struct AccessControlAllowCredentialsWhenOrigin;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const MDN_ACCESS_CONTROL_ALLOW_CREDENTIALS: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "MDN Access-Control-Allow-Credentials",
    section: None,
    url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Access-Control-Allow-Credentials",
    note: "Access-Control-Allow-Credentials",
};
const MDN_ACCESS_CONTROL_ALLOW_ORIGIN: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "MDN Access-Control-Allow-Origin",
    section: None,
    url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Access-Control-Allow-Origin",
    note: "Access-Control-Allow-Origin",
};

impl RuleMeta for AccessControlAllowCredentialsWhenOrigin {
    fn id(&self) -> &'static str {
        "access_control_allow_credentials_when_origin"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn title(&self) -> Option<&'static str> {
        Some("Access-Control Allow Credentials When Origin")
    }

    fn description(&self) -> &'static str {
        "This rule reads the Cross-Origin Resource Sharing (CORS) response headers that decide whether a response may be shared with credentials, and asks two things.\n\n**The value.** `Access-Control-Allow-Credentials` carries one value and the CORS check compares it as bytes: `true` returns success and every other value falls through to the algorithm's failure. So `TRUE`, `false`, `1` or anything else is a header that is present and shares nothing, and is reported as that. The comparison here used to be case-insensitive, which told an operator that `TRUE` had enabled credentialed sharing.\n\n**The pairing.** A value of `true` must **not** accompany an `Access-Control-Allow-Origin` of `*`: the CORS check only succeeds on the wildcard for a request whose credentials mode is not \"include\", and a credentialed request must match the byte-serialized origin instead, which `*` never is. A server sending both is advertising a sharing it will never get.\n\nThe origin header is only scanned for a `*` here; what its value may be is `access_control_allow_origin_valid`'s finding."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            MDN_ACCESS_CONTROL_ALLOW_CREDENTIALS,
            MDN_ACCESS_CONTROL_ALLOW_ORIGIN,
            FETCH_3_3_4,
            FETCH_4_10,
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
                snippet: "HTTP/1.1 200 OK\nAccess-Control-Allow-Origin: https://example.com\nAccess-Control-Allow-Credentials: true",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(no credentials)"),
                snippet: "HTTP/1.1 200 OK\nAccess-Control-Allow-Origin: *",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(wildcard with credentials)"),
                snippet: "HTTP/1.1 200 OK\nAccess-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(`false` is what omitting the field already says)"),
                snippet: "HTTP/1.1 200 OK\nAccess-Control-Allow-Origin: https://example.com\nAccess-Control-Allow-Credentials: false",
            },
        ]
    }
}

impl Rule for AccessControlAllowCredentialsWhenOrigin {
    fn needs_response(&self) -> bool {
        true
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

            let headers = &resp.headers;

            // If there is no Access-Control-Allow-Origin header, nothing to check
            let acao_count = headers
                .get_all("access-control-allow-origin")
                .iter()
                .count();
            if acao_count == 0 {
                return None;
            }

            // The only question asked of Access-Control-Allow-Origin here is
            // whether a `*` is among its members, so the lines are read as the
            // octets the sender wrote and nothing is said about what they hold:
            // an octet is not a `*`, and the value belongs to
            // `access_control_allow_origin_valid`, which measures it against the
            // three alternatives. Reporting it from inside a reading this narrow
            // was a claim about a field this rule only scans.
            let acao_has_star = crate::helpers::headers::field_lines_as_written(
                headers,
                "access-control-allow-origin",
            )
            .iter()
            .any(|line| {
                crate::helpers::list::list_members(crate::helpers::headers::trim_ows(line))
                    .any(|member| member == "*")
            });

            let acc_count = headers
                .get_all("access-control-allow-credentials")
                .iter()
                .count();
            if acc_count == 0 {
                return None; // nothing to check
            }

            // Same reading, same reason: the question is whether this value is
            // the word `true`, and an octet is not it.
            let acc_line = crate::helpers::headers::field_lines_as_written(
                headers,
                "access-control-allow-credentials",
            )
            .into_iter()
            .next()
            .expect("a field line, since the count above is non-zero");
            let acc_val = crate::helpers::headers::trim_ows(&acc_line);

            // The production generates one value and the CORS check compares
            // against it as bytes, so `TRUE`, `false`, `1` and an octet all
            // fall through to the failure at the end of the algorithm. They do
            // not all mean the same thing, and the split here is what the
            // sender still believes afterwards.
            //
            // `false` first, because it is the one value outside the grammar
            // whose sender got what they asked for: no sharing, which is what
            // omitting the field would also have given them. Nothing downstream
            // differs and the repair is to delete the line, so it is reported
            // as the redundancy it is and not as a header that failed.
            if acc_val == "false" {
                return Some(ctx.report(&ACCESS_CONTROL_ALLOW_CREDENTIALS_REDUNDANT));
            }

            // Everything else is a server that wrote the field to turn
            // credentialed sharing on and missed the one value that does it.
            // **The comparison used to be case-insensitive**, which told an
            // operator that `TRUE` had worked, and reported the `*` pairing for
            // a combination no user agent ever reaches.
            // cite(Fetch § 3.3.4, label: the value the production generates): "Access-Control-Allow-Credentials = %s"true" ; case-sensitive"
            // cite(Fetch § 4.10, label: CORS check reads the field): "Let credentials be the result of getting `Access-Control-Allow-Credentials` from response’s header list."
            if acc_val != "true" {
                return Some(ctx.report_with(
                    &ACCESS_CONTROL_ALLOW_CREDENTIALS_INVALID,
                    format!(
                        "Access-Control-Allow-Credentials is '{}', which is not the byte sequence `true`: the CORS check shares nothing with credentials for any other value",
                        crate::helpers::shown::shown_in_finding(acc_val)
                    ),
                ));
            }

            // The value is `true`. `*` and credentials are mutually exclusive by
            // construction: the CORS check only returns success on `*` for a
            // request whose credentials mode is *not* "include", and a
            // credentialed request must instead match the byte-serialized origin
            // — which `*` is not. A server sending both is advertising a sharing
            // it will never get.
            if acao_has_star {
                return Some(ctx.report(&ACCESS_CONTROL_ALLOW_CREDENTIALS_CONFLICTING));
            }

            None
        };
        Vec::from_iter(finding())
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &AccessControlAllowCredentialsWhenOrigin;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    use crate::test_helpers::make_test_transaction;

    #[rstest]
    #[case(Some("*"), Some("true"), true)]
    // `false` is not the byte sequence `true`, so the header shares nothing —
    // a finding about the value rather than about the pairing.
    #[case(Some("*"), Some("false"), true)]
    #[case(Some("https://a.example"), Some("true"), false)]
    #[case(Some("https://a.example"), None, false)]
    #[case(Some("https://a.example, *"), Some("true"), true)]
    fn check_acl_credentials_cases(
        #[case] acao: Option<&str>,
        #[case] acc: Option<&str>,
        #[case] expect_violation: bool,
    ) {
        let rule = AccessControlAllowCredentialsWhenOrigin;
        let mut tx = make_test_transaction();
        let mut pairs = vec![];
        if let Some(a) = acao {
            pairs.push(("access-control-allow-origin", a));
        }
        if let Some(c) = acc {
            pairs.push(("access-control-allow-credentials", c));
        }
        if !pairs.is_empty() {
            tx = crate::test_helpers::make_test_transaction_with_response(200, &pairs);
        }

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        if expect_violation {
            assert!(v.is_some(), "expected violation for {:?} & {:?}", acao, acc);
        } else {
            assert!(
                v.is_none(),
                "did not expect violation for {:?} & {:?}: got {:?}",
                acao,
                acc,
                v
            );
        }
    }

    #[test]
    fn an_obs_text_octet_in_the_origin_is_not_a_wildcard() {
        use crate::test_helpers::make_headers_from_pairs;
        use hyper::header::HeaderValue;

        let rule = AccessControlAllowCredentialsWhenOrigin;
        let mut tx = make_test_transaction();
        let mut hdrs = make_headers_from_pairs(&[("access-control-allow-origin", "*")]);
        hdrs.insert(
            "access-control-allow-origin",
            HeaderValue::from_bytes(&[0xff]).unwrap(),
        );
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hdrs,
            body_length: None,
            body_interrupted: false,
            trailers: None,
        });

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(
            v.is_none(),
            "the value is this rule's business only if it is `*`, and the octet's own \
             finding is access_control_allow_origin_valid's: {:?}",
            v
        );
    }

    #[test]
    fn an_obs_text_octet_in_the_credentials_is_a_value_that_is_not_true() {
        use crate::test_helpers::make_headers_from_pairs;
        use hyper::header::HeaderValue;

        let rule = AccessControlAllowCredentialsWhenOrigin;
        let mut tx = make_test_transaction();
        let mut hdrs = make_headers_from_pairs(&[("access-control-allow-origin", "*")]);
        hdrs.insert(
            "access-control-allow-credentials",
            HeaderValue::from_bytes(&[0xff]).unwrap(),
        );
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hdrs,
            body_length: None,
            body_interrupted: false,
            trailers: None,
        });

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        // The octet reaches the value check, which is where the field's one
        // finding lives; nothing here is a claim about an encoding.
        assert_eq!(
            v.expect("a finding").message,
            "Access-Control-Allow-Credentials is 'ÿ', which is not the byte sequence `true`: the CORS check shares nothing with credentials for any other value"
        );
    }

    /// The three findings, and which field each one asks to change.
    ///
    /// A value that meant to enable sharing and did not is the field's own; a
    /// `true` beside a wildcard origin is the pairing, and it is reported on
    /// this field because deleting this field is what makes the response
    /// correct again.
    ///
    /// **`false` is the row that pins the split.** It fails the same production
    /// as `TRUE`, and it is the value real servers actually send — a
    /// deployment that turned credentials off and said so. Reporting it as a
    /// field that failed says a deployment is wrong about itself when it is
    /// not, so it draws the redundancy and never `_invalid`. `FALSE` is not
    /// that value: the comparison is byte-exact in both directions, so a sender
    /// who meant `false` and shouted it missed the grammar like any other
    /// miss, and lands back on `_invalid`.
    #[rstest]
    #[case::states_the_default("false", "access_control_allow_credentials_redundant")]
    #[case::case_folded_default("FALSE", "access_control_allow_credentials_invalid")]
    #[case::case_folded("TRUE", "access_control_allow_credentials_invalid")]
    #[case::not_a_boolean("1", "access_control_allow_credentials_invalid")]
    #[case::blank("", "access_control_allow_credentials_invalid")]
    #[case::wildcard("true", "access_control_allow_credentials_conflicting")]
    fn each_finding_names_its_entry(#[case] value: &str, #[case] id: &str) {
        let rule = AccessControlAllowCredentialsWhenOrigin;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[
                ("access-control-allow-origin", "*"),
                ("access-control-allow-credentials", value),
            ],
        );
        let found = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .unwrap_or_else(|| panic!("a finding for {value:?}"));
        assert_eq!(found.violation, id, "{value:?}");
    }

    #[test]
    fn no_response_no_violation() {
        let rule = AccessControlAllowCredentialsWhenOrigin;
        let tx = make_test_transaction();
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn credentials_header_without_origin_returns_none() {
        let rule = AccessControlAllowCredentialsWhenOrigin;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("access-control-allow-credentials", "true")],
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn multiple_origins_without_star_and_credentials_true_ok() {
        let rule = AccessControlAllowCredentialsWhenOrigin;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[
                ("access-control-allow-origin", "https://a, https://b"),
                ("access-control-allow-credentials", "true"),
            ],
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn uppercase_true_is_not_the_byte_sequence() {
        let rule = AccessControlAllowCredentialsWhenOrigin;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[
                ("access-control-allow-origin", "*"),
                ("access-control-allow-credentials", "TRUE"),
            ],
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        // Not the pairing finding: a user agent never reads `TRUE` as credentials
        // at all, so what is wrong is the value.
        let message = v.expect("a finding").message;
        assert!(
            message.starts_with("Access-Control-Allow-Credentials is 'TRUE'"),
            "{message}"
        );
    }

    #[test]
    fn star_with_whitespace_true_is_violation() {
        let rule = AccessControlAllowCredentialsWhenOrigin;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[
                ("access-control-allow-origin", "*"),
                ("access-control-allow-credentials", "  true  "),
            ],
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
    }

    #[test]
    fn acao_with_trailing_commas_and_star_is_violation() {
        use crate::test_helpers::make_headers_from_pairs;
        use hyper::header::HeaderValue;

        let rule = AccessControlAllowCredentialsWhenOrigin;
        let mut tx = make_test_transaction();
        let mut hdrs = make_headers_from_pairs(&[("access-control-allow-origin", "https://a")]);
        // append separate header value containing '*'
        hdrs.append("access-control-allow-origin", HeaderValue::from_static("*"));
        hdrs.insert(
            "access-control-allow-credentials",
            HeaderValue::from_static("true"),
        );
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hdrs,

            body_length: None,
            body_interrupted: false,
            trailers: None,
        });

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
    }

    #[test]
    fn a_credentials_value_that_is_not_true_is_its_own_finding() {
        let rule = AccessControlAllowCredentialsWhenOrigin;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[
                ("access-control-allow-origin", "*"),
                ("access-control-allow-credentials", "1"),
            ],
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        let message = v.expect("a finding").message;
        assert!(
            message.starts_with("Access-Control-Allow-Credentials is '1'"),
            "{message}"
        );
    }

    #[test]
    fn needs_a_response() {
        let rule = AccessControlAllowCredentialsWhenOrigin;
        assert!(rule.needs_response());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let rule = AccessControlAllowCredentialsWhenOrigin;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        cfg.rules.insert(
            "access_control_allow_credentials_when_origin".into(),
            toml::Value::Table(table),
        );

        // validate should succeed without error
        rule.prepare(&cfg)?;
        Ok(())
    }
}
