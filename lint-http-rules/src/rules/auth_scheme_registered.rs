// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::auth_scheme::{AUTH_SCHEME_UNREGISTERED, RFC_9110_11_1, RFC_9110_11_2};
use crate::violations::challenge::{RFC_9110_11_3, RFC_9110_11_6_1};
use crate::violations::credentials::{RFC_9110_11_4, RFC_9110_11_6_2};
use crate::violations::ViolationDef;

pub struct AuthSchemeRegistered;

/// The one defect this rule reports, which is the one it is named for.
///
/// A scheme spelled correctly and absent from the operator's `allowed` list is
/// not a defect of any production, and no sentence in RFC 9110 makes it one —
/// § 11.1 says schemes *ought to* be registered, which is exactly what the
/// entry carries. That makes this rule policy where every rule around it is
/// grammar, and the list is one entry long because policy is the whole of it.
///
/// **It held seven entries and lost six in one session, for two different
/// reasons.** Three were `www_authenticate_challenge_syntax`'s: this rule
/// groups a challenge in order to reach a scheme name, and reported what the
/// grouping refused on the way past — a field parsed as a *route* is not a
/// field owned. The other three are `Authorization`'s framework grammar, which
/// is a real reading and a different one: it belongs to a rule with no
/// configuration, because an operator who wants a malformed credential
/// reported should not first have to decide which schemes their deployment
/// accepts. That rule is `authorization_credentials_valid`, and this one asks
/// the registry question of a scheme both it and the challenge rule have
/// already vouched for.
static DECLARED: &[&ViolationDef] = &[&AUTH_SCHEME_UNREGISTERED];

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
        "The `auth-scheme` naming an HTTP authentication scheme SHOULD be one the IANA registry holds (for example, `Basic`, `Bearer`, `Digest`), and this rule asks that of both directions of the framework — a server's `WWW-Authenticate` challenges and a client's `Authorization` credentials. It measures the name against an operator-configured allowlist rather than against the live registry, so `allowed` is the deployment's chosen subset of acceptable schemes. **This rule reports nothing about grammar.** A scheme that is not a `token`, a challenge that does not parse, a credential missing after its scheme — each belongs to the rule that owns the field it sits in (`www_authenticate_challenge_syntax`, `authorization_credentials_valid`), and a name those rules refuse is skipped here rather than reported as unregistered, because the registry could not hold it either way."
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
        ]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    /// **One vocabulary, two fields, two writers.** The `auth-scheme` this
    /// reads out of `WWW-Authenticate` is the challenge the origin issued, and
    /// the one it reads out of `Authorization` is the credentials the client
    /// presented.
    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::PerSite
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
            // The registry question, asked of one scheme token that is already
            // known to be one.
            //
            // The guidance the allowlist stands for: schemes ought to be registered.
            // The comparison is lowercase because the scheme token is case-insensitive
            // (§11.1). Note this is checked against an operator-configured `allowed`
            // list, not the live IANA registry — the allowlist is the operator's chosen
            // subset of acceptable (typically registered) schemes, and §16.4.1 is where
            // registered ones live.
            //
            // A name that is not a `token` is not a name the registry could
            // hold, so it is skipped rather than answered: the character is
            // reported by whichever rule owns the field it sits in --
            // `www_authenticate_challenge_syntax` on the response side,
            // `authorization_credentials_valid` on the request side.
            //
            // An auth-scheme is a token; the tchar set is helper-owned.
            // cite(RFC 9110 § 11.1): "It uses a case-insensitive token to identify the authentication scheme"
            // cite(RFC 9110 § 16.4.1): "The "Hypertext Transfer Protocol (HTTP) Authentication Scheme Registry" defines the namespace for the authentication schemes in challenges and credentials."
            let check_registered =
                |hdr_name: &str, scheme: &str, party: crate::lint::Party| -> Option<Violation> {
                    if crate::helpers::token::find_invalid_token_char(scheme).is_some()
                        || config.allowed.contains(&scheme.to_ascii_lowercase())
                    {
                        return None;
                    }
                    Some(ctx.by(party).report_with(
                        &AUTH_SCHEME_UNREGISTERED,
                        format!("Unrecognized auth-scheme '{}' in {}", scheme, hdr_name),
                    ))
                };

            // The challenges a response advertises. Read as octets and over the
            // section: `WWW-Authenticate = #challenge` makes the field lines one
            // list, and an octet outside visible US-ASCII belongs to whichever
            // production it landed in rather than being a verdict about the
            // field's encoding. A value that will not group is not this rule's
            // to report.
            if let Some(resp) = &tx.response {
                if let Some(s) = crate::helpers::headers::combined_field_value_as_written(
                    &resp.headers,
                    "www-authenticate",
                ) {
                    if let Ok(challenges) = crate::helpers::auth::split_and_group_challenges(&s) {
                        for challenge in challenges {
                            let scheme =
                                challenge.split(char::is_whitespace).next().unwrap().trim();
                            if let Some(v) = check_registered(
                                "WWW-Authenticate",
                                scheme,
                                crate::lint::Party::Server,
                            ) {
                                return Some(v);
                            }
                        }
                    }
                }
            }

            // The credentials a request presents. `Authorization = credentials`
            // is one value rather than a list, so the field lines are not
            // combined -- and every one of them is read, because a sender wrote
            // each. A value whose framework structure is wrong is
            // `authorization_credentials_valid`'s finding, so what is taken
            // from each line here is only the scheme in front of it.
            for hv in tx.request.headers.get_all("authorization").iter() {
                let v = crate::helpers::headers::field_line_as_written(hv);
                let scheme = v.split(char::is_whitespace).next().unwrap_or("").trim();
                if scheme.is_empty() {
                    continue;
                }
                if let Some(vv) =
                    check_registered("Authorization", scheme, crate::lint::Party::Client)
                {
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
    // The scheme is not a `token`, so the registry could not hold the name
    // whatever it says — and the character is `www_authenticate_challenge_syntax`'s
    // finding. This rule is silent.
    #[case(Some("b@d realm=\"x\""), false)]
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
    // Not a `token`, so not a name the registry could hold — the character is
    // `authorization_credentials_valid`'s finding and this rule is silent, the
    // same answer it gives a malformed challenge.
    #[case(Some("B@sic xyz"), false)]
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

    /// The challenge grammar belongs to the rule named for it, and this one
    /// says nothing about it.
    ///
    /// **Each row used to draw two byte-identical findings under two rule
    /// ids** — this rule parsed `WWW-Authenticate` on its way to a scheme name
    /// and reported what the parse refused, beside a neighbour that declares
    /// all fifteen of the field's defects and runs on the same response. The
    /// assertion is two-sided on purpose: silence here is only right because
    /// the defect is still reported, and a test that checked only the silence
    /// would pass just as well if nobody reported it at all.
    #[rstest]
    #[case(" realm=\"x\"", "challenge_scheme_missing")]
    #[case("Basic realm=\"a\", , Bearer realm=\"b\"", "challenge_member_empty")]
    #[case("b@d realm=\"x\"", "challenge_scheme_missing")]
    fn a_malformed_challenge_is_the_neighbours_finding(#[case] value: &str, #[case] id: &str) {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        tx.response.as_mut().expect("a response").headers =
            crate::test_helpers::make_headers_from_pairs(&[("www-authenticate", value)]);
        let history = crate::transaction_history::TransactionHistory::empty();

        assert!(
            crate::test_helpers::run_rule(&AuthSchemeRegistered, &tx, &history, &make_cfg())
                .is_none(),
            "{value:?}",
        );

        let owner = crate::rules::www_authenticate_challenge_syntax::WwwAuthenticateChallengeSyntax;
        let found = crate::test_helpers::run_rule(
            &owner,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "www_authenticate_challenge_syntax",
            ]),
        )
        .unwrap_or_else(|| panic!("the owning rule reports nothing for {value:?}"));
        assert_eq!(found.violation, id, "{value:?}");
    }

    #[test]
    fn an_obs_text_octet_in_a_challenge_is_not_this_rules_question() {
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

        // Neither octet is this rule's question. In the `token68` the scheme
        // is spelled correctly and is in the allowlist, so there is nothing to
        // ask; in the scheme the name is not a `token`, so the registry could
        // not hold it whatever it says. Both are
        // `www_authenticate_challenge_syntax`'s, which is the rule named for
        // the field's grammar — see
        // `a_malformed_challenge_is_the_neighbours_finding`.
        assert!(judge(b"Basic \xff").is_none());
        assert!(judge(b"Ba\xffsic realm=\"x\"").is_none());
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
