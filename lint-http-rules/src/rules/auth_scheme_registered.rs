// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::auth_scheme::{
    AUTH_SCHEME_CHARACTER_FORBIDDEN, AUTH_SCHEME_UNREGISTERED, RFC_9110_11_1, RFC_9110_11_2,
};
use crate::violations::challenge::{
    challenge_defect, CHALLENGE_MEMBER_EMPTY, CHALLENGE_SCHEME_MISSING, RFC_9110_11_3,
    RFC_9110_11_6_1,
};
use crate::violations::credentials::{
    credentials_defect, CREDENTIALS_CONTROL_CHARACTER_FORBIDDEN, CREDENTIALS_EMPTY,
    CREDENTIALS_MISSING, RFC_9110_11_4, RFC_9110_11_6_2,
};
use crate::violations::ViolationDef;

pub struct AuthSchemeRegistered;

/// Everything this rule measures about the *grammar*, and none of what it is
/// named for.
///
/// The list's two defects come from grouping `WWW-Authenticate`'s members
/// before a scheme can be read out of them; the scheme's own octet is
/// `auth-scheme = token`, one production written once and read from both
/// directions of the framework, so it answers with the same id here as it does
/// inside a challenge or a set of credentials; and the three
/// `credentials_*` entries are what an `Authorization` value fails to be before
/// any scheme is looked up.
///
/// **Those three were declared by a second rule until they were counted.**
/// `authorization_credentials_present` read the same field with the same
/// helper and reported the same four ids, all of them in this list — so the
/// two rules said the same things about one value under two names, and the one
/// that said less was folded in here.
///
/// **The registry question is the whole of what this rule is named for**, and
/// it is now an entry of the scheme's own subject rather than a sentence this
/// file words: a scheme spelled correctly and absent from the operator's
/// `allowed` list is not a defect of any production, and no sentence in
/// RFC 9110 makes it one — § 11.1 says schemes *ought to* be registered, which
/// is exactly what the entry carries.
static DECLARED: &[&ViolationDef] = &[
    &CHALLENGE_MEMBER_EMPTY,
    &CHALLENGE_SCHEME_MISSING,
    &AUTH_SCHEME_CHARACTER_FORBIDDEN,
    &AUTH_SCHEME_UNREGISTERED,
    &CREDENTIALS_EMPTY,
    &CREDENTIALS_MISSING,
    &CREDENTIALS_CONTROL_CHARACTER_FORBIDDEN,
];

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9110_16_4_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("16.4.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-16.4.1",
    note: "Authentication Scheme Registry",
};
const IANA_HTTP_AUTHENTICATION_SCHEMES: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "IANA HTTP Authentication Schemes",
    section: None,
    url: "https://www.iana.org/assignments/http-authschemes/http-authschemes.xhtml",
    note: "IANA HTTP Authentication Scheme Registry",
};
/// Further reading rather than a sentence this rule enforces: what the
/// credentials after a `Basic` or a `Bearer` scheme have to be. No defect here
/// cites either — the framework production is all this rule reads, and the two
/// scheme rules that *do* read them own these documents — but a page about
/// `Authorization` that names no scheme leaves the reader nowhere to go next.
const RFC_7617: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 7617",
    section: None,
    url: "https://www.rfc-editor.org/rfc/rfc7617.html",
    note: "Basic Authentication",
};
const RFC_6750: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 6750",
    section: None,
    url: "https://www.rfc-editor.org/rfc/rfc6750.html",
    note: "The OAuth 2.0 Authorization Framework: Bearer Token Usage",
};

impl RuleMeta for AuthSchemeRegistered {
    fn id(&self) -> &'static str {
        "auth_scheme_registered"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
allowed = ["Basic", "Bearer", "Digest"]
"#
    }

    fn prepare(&self, cfg: &crate::config::Config) -> anyhow::Result<crate::rules::ResolvedRule> {
        let allowed = crate::helpers::rule_config::parse_lowercased_list(
            cfg,
            self.id(),
            "allowed",
            "acceptable auth-schemes",
            "['Basic','Bearer']",
        )?;
        // The two standard keys, **after** this rule's own options, so a config
        // naming a bad option still fails on that option.
        crate::rules::validate_rule_table(cfg, self.id())?;
        Ok(crate::rules::ResolvedRule {
            state: Box::new(crate::helpers::rule_config::AllowedList { allowed }),
        })
    }

    fn description(&self) -> &'static str {
        "Reads the HTTP authentication framework's own grammar in both directions — a server's `WWW-Authenticate` challenges and a client's `Authorization` credentials — and then asks the registry question the rule is named for. The framework half is the structure: a challenge that names no scheme, an empty list member, an `auth-scheme` carrying a character no `token` admits, an `Authorization` value that is empty or that stops after the scheme where the scheme wants credentials. The registry half is the `auth-scheme` itself, which SHOULD be an IANA-registered scheme (for example, `Basic`, `Bearer`, `Digest`); this rule measures it against an operator-configured allowlist of acceptable schemes rather than against the live registry, and flags a value not in it. What those credentials must *be* once the scheme is known belongs to the scheme's own rule."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_9110_11_1,
            RFC_9110_11_2,
            RFC_9110_11_3,
            RFC_9110_11_4,
            RFC_9110_11_6_1,
            RFC_9110_11_6_2,
            RFC_9110_16_4_1,
            IANA_HTTP_AUTHENTICATION_SCHEMES,
            RFC_7617,
            RFC_6750,
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
                snippet: "WWW-Authenticate: Basic realm=\"example\"\nAuthorization: Bearer abc123",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "WWW-Authenticate: Digest realm=\"test\", nonce=\"abc\"\nAuthorization: Digest username=\"Mufasa\", realm=\"test\", nonce=\"abc\", uri=\"/resource\", response=\"d41d8cd98f00b204e9800998ecf8427e\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "WWW-Authenticate: NewScheme abc=\nAuthorization: X-MyAuth abc",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "Authorization: Basic",
            },
        ]
    }
}

impl Rule for AuthSchemeRegistered {
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
            let config: &crate::helpers::rule_config::AllowedList = ctx.state();
            // Helper to check a single scheme token against allowed list
            let check_scheme =
                |hdr_name: &str, scheme: &str, allowed: &Vec<String>| -> Option<Violation> {
                    // An auth-scheme is a token; the tchar set is helper-owned.
                    // cite(RFC 9110 § 11.1): "It uses a case-insensitive token to identify the authentication scheme"
                    if let Some(c) = crate::helpers::token::find_invalid_token_char(scheme) {
                        // Named rather than shown: both fields are read as
                        // octets, so this may be an `obs-text` byte, and a byte
                        // is what the finding says it is.
                        return Some(ctx.report_with(
                            &AUTH_SCHEME_CHARACTER_FORBIDDEN,
                            format!(
                                "Invalid character {} in {} auth-scheme",
                                crate::helpers::shown::describe_char(c),
                                hdr_name
                            ),
                        ));
                    }
                    // The guidance the allowlist stands for: schemes ought to be registered.
                    // The comparison is lowercase because the scheme token is case-insensitive
                    // (§11.1). Note this is checked against an operator-configured `allowed`
                    // list, not the live IANA registry — the allowlist is the operator's chosen
                    // subset of acceptable (typically registered) schemes, and §16.4.1 is where
                    // registered ones live.
                    // cite(RFC 9110 § 16.4.1): "The "Hypertext Transfer Protocol (HTTP) Authentication Scheme Registry" defines the namespace for the authentication schemes in challenges and credentials."
                    if !allowed.contains(&scheme.to_ascii_lowercase()) {
                        return Some(ctx.report_with(
                            &AUTH_SCHEME_UNREGISTERED,
                            format!("Unrecognized auth-scheme '{}' in {}", scheme, hdr_name),
                        ));
                    }
                    None
                };

            // Check WWW-Authenticate challenges in responses
            if let Some(resp) = &tx.response {
                // Read as octets and over the section: `WWW-Authenticate =
                // #challenge` makes the field lines one list, and an octet
                // outside visible US-ASCII belongs to whichever production it
                // landed in -- the scheme's `token`, a parameter's value --
                // rather than being a verdict about the field's encoding.
                if let Some(s) = crate::helpers::headers::combined_field_value_as_written(
                    &resp.headers,
                    "www-authenticate",
                ) {
                    // split into assembled challenges
                    match crate::helpers::auth::split_and_group_challenges(&s) {
                        Ok(challenges) => {
                            for challenge in challenges {
                                let scheme =
                                    challenge.split(char::is_whitespace).next().unwrap().trim();
                                if let Some(v) =
                                    check_scheme("WWW-Authenticate", scheme, &config.allowed)
                                {
                                    return Some(v);
                                }
                            }
                        }
                        Err(defect) => {
                            return Some(ctx.report_with(
                                challenge_defect(defect),
                                format!("Invalid WWW-Authenticate header: {}", defect.message()),
                            ))
                        }
                    }
                }
            }

            // Check Authorization credentials in requests. `Authorization =
            // credentials` is one value rather than a list, so the field lines
            // are **not** combined -- but every one of them is read, because a
            // sender wrote each and this rule measures what was written. That a
            // second line exists at all is `singleton_fields_not_repeated`'s
            // finding, not this one's, and picking a line to believe would make
            // the rest of them unreadable rather than reported. Read as octets,
            // for the reason above.
            for hv in tx.request.headers.get_all("authorization").iter() {
                let v = crate::helpers::headers::field_line_as_written(hv);
                let v = v.as_str();
                // The structure before the scheme is looked up: an
                // `auth-scheme` and, where the scheme wants them, the
                // credentials after it. The framework production is this
                // rule's; what those credentials must *be* belongs to the
                // scheme's own document, and to the rule that reads it.
                // cite(RFC 9110 § 11.6.2): "Its value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested"
                if let Err(defect) = crate::helpers::auth::validate_authorization_syntax(v) {
                    return Some(ctx.report_with(
                        credentials_defect(defect),
                        format!("Invalid Authorization header: {}", defect.message()),
                    ));
                }

                let scheme = v.split(char::is_whitespace).next().unwrap().trim();
                if let Some(vv) = check_scheme("Authorization", scheme, &config.allowed) {
                    return Some(vv);
                }
            }

            None
        };
        Vec::from_iter(finding())
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &AuthSchemeRegistered;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn make_cfg() -> crate::config::Config {
        let mut cfg = crate::config::Config::default();
        cfg.rules.insert(
            "auth_scheme_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![
                        toml::Value::String("basic".into()),
                        toml::Value::String("bearer".into()),
                        toml::Value::String("digest".into()),
                    ]),
                );
                t
            }),
        );
        cfg
    }

    /// The registry question and the grammar question are two entries, and a
    /// well-formed unknown name reaches the first: `NewScheme` is a `token`, so
    /// nothing is wrong with it except that this deployment has never heard of
    /// it. Both directions of the framework answer the same way.
    #[test]
    fn a_well_formed_unknown_scheme_is_the_registry_entry() {
        let mut response = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        response.response.as_mut().expect("a response").headers =
            crate::test_helpers::make_headers_from_pairs(&[("www-authenticate", "NewScheme abc=")]);
        let mut request = crate::test_helpers::make_test_transaction();
        request.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("authorization", "X-MyAuth abc")]);

        for tx in [response, request] {
            let found = crate::test_helpers::run_rule(
                &AuthSchemeRegistered,
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &make_cfg(),
            )
            .expect("a finding");
            assert_eq!(found.violation, "auth_scheme_unregistered");
        }
    }

    #[rstest]
    #[case(Some("Basic realm=\"x\""), false)]
    #[case(Some("Bearer realm=\"x\""), false)]
    #[case(Some("NewScheme abc="), true)]
    #[case(Some("b@d realm=\"x\""), true)]
    #[case(None, false)]
    fn check_www_authenticate_cases(#[case] h: Option<&str>, #[case] expect_violation: bool) {
        let rule = AuthSchemeRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        if let Some(v) = h {
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[("www-authenticate", v)]);
        }

        let violation = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(violation.is_some());
        } else {
            assert!(violation.is_none());
        }
    }

    #[rstest]
    #[case(Some("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="), false)]
    #[case(Some("Bearer abc123"), false)]
    #[case(Some("X-MyAuth abc"), true)]
    #[case(Some("B@sic xyz"), true)]
    #[case(None, false)]
    fn check_authorization_cases(#[case] h: Option<&str>, #[case] expect_violation: bool) {
        let rule = AuthSchemeRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(v) = h {
            tx.request.headers =
                crate::test_helpers::make_headers_from_pairs(&[("authorization", v)]);
        }

        let violation = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(violation.is_some());
        } else {
            assert!(violation.is_none());
        }
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "auth_scheme_registered");
        cfg.rules.insert(
            "auth_scheme_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![
                        toml::Value::String("Basic".into()),
                        toml::Value::String("Bearer".into()),
                    ]),
                );
                t
            }),
        );
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn www_authenticate_split_error_reports_violation() {
        let rule = AuthSchemeRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("www-authenticate", " realm=\"x\"")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v
            .unwrap()
            .message
            .contains("Invalid WWW-Authenticate header"));
    }

    #[test]
    fn an_obs_text_octet_is_read_where_it_lands_in_a_challenge() {
        use hyper::header::HeaderName;
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;

        let rule = AuthSchemeRegistered;
        let cfg = make_cfg();

        let judge = |value: &[u8]| {
            let mut tx = crate::test_helpers::make_test_transaction_with_response(401, &[]);
            let mut hm = HeaderMap::new();
            hm.insert(
                HeaderName::from_static("www-authenticate"),
                HeaderValue::from_bytes(value).unwrap(),
            );
            tx.response.as_mut().unwrap().headers = hm;
            crate::test_helpers::run_rule(
                &rule,
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            )
        };

        // An octet in the `token68` is not this rule's question — the scheme
        // is spelled correctly and is in the allowlist, and what the credential
        // holds is `www_authenticate_challenge_syntax`'s. An octet in the
        // scheme is, because the scheme is all this rule reads.
        assert!(judge(b"Basic \xff").is_none());
        assert_eq!(
            judge(b"Ba\xffsic realm=\"x\"")
                .expect("a finding")
                .violation,
            "challenge_scheme_missing"
        );
    }

    #[test]
    fn an_obs_text_octet_is_read_where_it_lands_in_credentials() {
        use hyper::header::HeaderName;
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;

        let rule = AuthSchemeRegistered;
        let cfg = make_cfg();

        let judge = |value: &[u8]| {
            let mut tx = crate::test_helpers::make_test_transaction();
            let mut hm = HeaderMap::new();
            hm.insert(
                HeaderName::from_static("authorization"),
                HeaderValue::from_bytes(value).unwrap(),
            );
            tx.request.headers = hm;
            crate::test_helpers::run_rule(
                &rule,
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            )
        };

        // The same split on the request side: the credential's octets belong
        // to the scheme's own document, and the scheme's belong here.
        assert!(judge(b"Basic \xff").is_none());
        assert_eq!(
            judge(b"Ba\xffsic abc").expect("a finding").violation,
            "auth_scheme_character_forbidden"
        );
    }

    #[test]
    fn authorization_missing_credentials_reports_violation() {
        let rule = AuthSchemeRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("authorization", "Basic")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Invalid Authorization header"));
    }

    #[test]
    fn parse_allowed_config_error_cases() {
        // Missing table
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "auth_scheme_registered");
        assert!(AuthSchemeRegistered.prepare(&cfg).is_err());

        // Not a table
        let mut cfg2 = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg2, "auth_scheme_registered");
        cfg2.rules.insert(
            "auth_scheme_registered".into(),
            toml::Value::String("invalid".into()),
        );
        assert!(AuthSchemeRegistered.prepare(&cfg2).is_err());

        // allowed not array
        let mut cfg3 = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg3, "auth_scheme_registered");
        cfg3.rules.insert(
            "auth_scheme_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("allowed".into(), toml::Value::String("Basic".into()));
                t
            }),
        );
        assert!(AuthSchemeRegistered.prepare(&cfg3).is_err());

        // empty allowed array
        let mut cfg4 = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg4, "auth_scheme_registered");
        cfg4.rules.insert(
            "auth_scheme_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("allowed".into(), toml::Value::Array(Vec::new()));
                t
            }),
        );
        assert!(AuthSchemeRegistered.prepare(&cfg4).is_err());

        // non-string item
        let mut cfg5 = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg5, "auth_scheme_registered");
        cfg5.rules.insert(
            "auth_scheme_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![toml::Value::Integer(1)]),
                );
                t
            }),
        );
        assert!(AuthSchemeRegistered.prepare(&cfg5).is_err());

        // normalization to lowercase
        let mut cfg6 = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg6, "auth_scheme_registered");
        cfg6.rules.insert(
            "auth_scheme_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![
                        toml::Value::String("BaSiC".into()),
                        toml::Value::String("BeArEr".into()),
                    ]),
                );
                t
            }),
        );
        let parsed = AuthSchemeRegistered.prepare(&cfg6).unwrap();
        let parsed: &crate::helpers::rule_config::AllowedList =
            parsed.state.downcast_ref().expect("allowed list state");
        assert_eq!(
            parsed.allowed,
            vec!["basic".to_string(), "bearer".to_string()]
        );
    }

    #[test]
    fn www_authenticate_multiple_challenges_reports_violation() {
        let rule = AuthSchemeRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "www-authenticate",
            "Basic realm=\"x\", NewScheme abc=",
        )]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn www_authenticate_multiple_header_fields_one_invalid_reports_violation() {
        use hyper::header::HeaderName;
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;

        let rule = AuthSchemeRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        let mut hm = HeaderMap::new();
        hm.append(
            HeaderName::from_static("www-authenticate"),
            HeaderValue::from_static("Basic realm=\"x\""),
        );
        hm.append(
            HeaderName::from_static("www-authenticate"),
            HeaderValue::from_static("NewScheme abc="),
        );
        tx.response.as_mut().unwrap().headers = hm;

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn www_authenticate_case_insensitive_scheme_accepted() {
        let rule = AuthSchemeRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "www-authenticate",
            "bAsIc realm=\"x\"",
        )]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    /// Every `Authorization` field line is read, not only the first.
    ///
    /// **This is what the fold had to choose.** The rule that used to sit
    /// beside this one walked `get_all`; this one stopped at the first line, on
    /// the reading that `Authorization = credentials` is not a list so the
    /// first line is the field. Both readings report the same defect *ids*,
    /// which is why nothing pointed at the disagreement — containment by id is
    /// not containment by coverage. The walk wins: a sender wrote both lines
    /// and a linter reports what was written, while *that* there are two lines
    /// is `singleton_fields_not_repeated`'s finding and not this rule's.
    #[rstest]
    #[case("Basic", "Bearer abc123")]
    #[case("Bearer abc123", "Basic")]
    fn every_authorization_field_line_is_read(#[case] first: &str, #[case] second: &str) {
        use hyper::header::{HeaderName, HeaderValue};

        let mut tx = crate::test_helpers::make_test_transaction();
        for value in [first, second] {
            tx.request.headers.append(
                HeaderName::from_static("authorization"),
                HeaderValue::from_str(value).expect("a test value"),
            );
        }

        let v = crate::test_helpers::run_rule(
            &AuthSchemeRegistered,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &make_cfg(),
        )
        .unwrap_or_else(|| panic!("expected a finding for {first:?} then {second:?}"));
        assert_eq!(v.violation, "credentials_missing", "{}", v.message);
    }

    /// Four names where one rule had one id, and the severity each carries.
    #[rstest]
    #[case("", "credentials_empty", crate::lint::Severity::Warn)]
    #[case("Basic", "credentials_missing", crate::lint::Severity::Warn)]
    #[case("Basic ", "credentials_missing", crate::lint::Severity::Warn)]
    #[case(
        "B@sic xyz",
        "auth_scheme_character_forbidden",
        crate::lint::Severity::Warn
    )]
    fn each_credentials_finding_names_the_defect_and_carries_its_severity(
        #[case] header: &str,
        #[case] violation: &str,
        #[case] severity: crate::lint::Severity,
    ) {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers.append(
            "authorization",
            hyper::header::HeaderValue::from_str(header).expect("a test value"),
        );
        let v = crate::test_helpers::run_rule(
            &AuthSchemeRegistered,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &make_cfg(),
        )
        .unwrap_or_else(|| panic!("expected a finding for {header:?}"));
        assert_eq!(v.violation, violation, "{}", v.message);
        assert_eq!(v.severity, severity, "{}", v.message);
    }

    /// A control octet cannot reach the rule through a `HeaderValue`, which
    /// refuses to hold one — so the defect is declared, reported by the helper,
    /// and asserted where it is constructible.
    #[test]
    fn a_control_octet_in_the_credentials_is_the_helpers_to_find() {
        assert!(hyper::header::HeaderValue::from_bytes(b"Basic ab\x01c").is_err());
        assert_eq!(
            crate::violations::credentials::credentials_defect(
                crate::helpers::auth::AuthorizationDefect::CredentialsControlCharacter
            )
            .id,
            "credentials_control_character_forbidden",
        );
    }

    /// The scheme rules own what a credential *is*, and the values this rule
    /// publishes as compliant have to satisfy them: this rule reads a
    /// credential only as far as "a scheme, then something", so every
    /// scheme-specific defect in an example it publishes is invisible to it. A
    /// `Digest` credential naming two of the five parameters its own rule
    /// requires was labelled `Compliant` in the docs the whole time a rule
    /// published one. Each owner declines on a value belonging to the other
    /// scheme, so both run over every example.
    #[test]
    fn published_credentials_satisfy_the_rules_that_own_their_schemes() {
        use crate::rules::bearer_token_syntax::BearerTokenSyntax;
        use crate::rules::digest_auth_valid::DigestAuthValid;
        use crate::rules::{Compliance, RuleMeta as _};

        let digest = DigestAuthValid;
        let bearer = BearerTokenSyntax;
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&[digest.id(), bearer.id()]);
        let history = crate::transaction_history::TransactionHistory::empty();

        let mut saw_a_credential = false;
        for ex in AuthSchemeRegistered.examples() {
            if ex.compliance != Compliance::Compliant {
                continue;
            }
            let fields: Vec<(&str, &str)> = ex
                .snippet
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(|l| {
                    l.split_once(": ")
                        .unwrap_or_else(|| panic!("not a header line: {l:?}"))
                })
                .collect();
            saw_a_credential |= fields.iter().any(|(name, _)| *name == "Authorization");
            let tx = crate::test_helpers::make_test_transaction_with_headers(&fields);
            for owner in [&digest as &dyn crate::rules::Rule, &bearer] {
                let found = crate::test_helpers::run_rule(owner, &tx, &history, &cfg);
                assert!(
                    found.is_none(),
                    "a Compliant example publishes a credential {} rejects {:?}: {found:?}",
                    owner.id(),
                    ex.snippet
                );
            }
        }
        assert!(saw_a_credential, "no published example carries credentials");
    }

    #[test]
    fn authorization_multiple_headers_first_missing_reports_violation() {
        use hyper::header::HeaderName;
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;

        let rule = AuthSchemeRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        hm.append(
            HeaderName::from_static("authorization"),
            HeaderValue::from_static("Basic"),
        );
        hm.append(
            HeaderName::from_static("authorization"),
            HeaderValue::from_static("Bearer abc123"),
        );
        tx.request.headers = hm;

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn authorization_case_insensitive_scheme_accepted() {
        let rule = AuthSchemeRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "authorization",
            "bAsIc QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
        )]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn allowed_list_case_insensitive_runtime_ok() -> anyhow::Result<()> {
        let mut cfgt = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfgt, "auth_scheme_registered");
        cfgt.rules.insert(
            "auth_scheme_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![toml::Value::String("BaSiC".into())]),
                );
                t
            }),
        );
        let mut tx = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "www-authenticate",
            "Basic realm=\"x\"",
        )]);

        let v = crate::test_helpers::run_rule(
            &AuthSchemeRegistered,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfgt,
        );
        assert!(v.is_none());
        Ok(())
    }
}
