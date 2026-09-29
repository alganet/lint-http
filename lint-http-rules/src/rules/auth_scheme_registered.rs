// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::auth_scheme::{AUTH_SCHEME_UNREGISTERED, RFC_9110_11_1, RFC_9110_11_2};
use crate::violations::challenge::{RFC_9110_11_3, RFC_9110_11_6_1};
use crate::violations::credentials::{RFC_9110_11_4, RFC_9110_11_6_2, RFC_9110_11_7_2};
use crate::violations::proxy_authenticate::RFC_9110_11_7_1;
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
# The IANA HTTP Authentication Scheme registry is the check, and this crate
# carries a snapshot of it. `allowed` names the schemes this deployment knowingly
# uses beyond it, and adds to the registry rather than replacing it.
allowed = []
"#
    }

    fn prepare(&self, cfg: &crate::config::Config) -> anyhow::Result<crate::rules::ResolvedRule> {
        let allowed = crate::helpers::rule_config::parse_lowercased_additions(
            cfg,
            self.id(),
            "allowed",
            "['X-MyAuth']",
        )?;
        // The two standard keys, **after** this rule's own options, so a config
        // naming a bad option still fails on that option.
        crate::rules::validate_rule_table(cfg, self.id())?;
        Ok(crate::rules::ResolvedRule {
            state: Box::new(crate::helpers::rule_config::AllowedList { allowed }),
        })
    }

    fn description(&self) -> &'static str {
        "The `auth-scheme` naming an HTTP authentication scheme ought to be one the IANA registry holds (for example, `Basic`, `Bearer`, `Digest`, `Negotiate`), and this rule asks that of every field § 11 writes the framework into — the challenges of a `WWW-Authenticate` or `Proxy-Authenticate`, and the credentials of an `Authorization` or `Proxy-Authorization`. The registry is the namespace for schemes in challenges and credentials, not for one hop of them, so the proxy-authentication half of the framework is asked the same question as the origin half. It measures the name against a snapshot of the registry this crate carries, and `allowed` adds the schemes a deployment knowingly uses beyond it. It used to ask a three-name list in its configuration instead, which reported `Negotiate`, `DPoP` and every other registered scheme as unregistered. **This rule reports nothing about grammar.** A scheme that is not a `token`, a challenge that does not parse, a credential missing after its scheme — each belongs to the rule that owns the field it sits in (`www_authenticate_challenge_syntax`, `authorization_credentials_valid`), and a name those rules refuse is skipped here rather than reported as unregistered, because the registry could not hold it either way."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_9110_11_1,
            RFC_9110_11_2,
            RFC_9110_11_3,
            RFC_9110_11_4,
            RFC_9110_11_6_1,
            RFC_9110_11_6_2,
            RFC_9110_11_7_1,
            RFC_9110_11_7_2,
            RFC_9110_16_4_1,
            IANA_HTTP_AUTHENTICATION_SCHEMES,
        ]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    /// **One vocabulary, four fields, two writers.** The `auth-scheme` this
    /// reads out of a `WWW-Authenticate` or `Proxy-Authenticate` is a challenge
    /// whoever wrote the response issued, and the one it reads out of an
    /// `Authorization` or `Proxy-Authorization` is credentials the client
    /// presented. Which hop the field addresses does not move that: a
    /// `Proxy-Authorization` is still written by the client, and a
    /// `Proxy-Authenticate` still arrives from the response side of this seam.
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
                compliance: Compliance::Compliant,
                label: Some("(registered, and on no list a deployment keeps)"),
                snippet: "WWW-Authenticate: Negotiate\nAuthorization: Negotiate YIIFxAYGKwYBBQUCoIIFuDCCBbSgh==",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "WWW-Authenticate: NewScheme abc=\nAuthorization: X-MyAuth abc",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(the proxy half of the framework, which § 11.7 writes out of the same two productions)"),
                snippet: "Proxy-Authenticate: NewScheme abc=\nProxy-Authorization: X-MyAuth abc",
            },
        ]
    }
}

impl Rule for AuthSchemeRegistered {
    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // Each section is read on its own and the findings it yields are kept.
        // The scheme a server names in a challenge and the scheme a client names
        // in its credentials are two peers' choices, and an unregistered name in
        // each is two defects — a challenge inviting a scheme nobody registered
        // said nothing about the credentials sent back to it.
        //
        // **And within a section every scheme is read, not the first.**
        // `WWW-Authenticate` is `#challenge` and a client picks the strongest
        // alternative it supports, so a field offering two names nobody
        // registered has offered a client two things it cannot use; the same
        // holds of a request writing `Authorization` on two lines, since
        // `credentials` is not a list and every line is a value its sender
        // wrote. Answering with the first named that scheme and left the
        // others unstated — and the finding's whole content is the name.
        //
        // The unit is the **scheme**, not the challenge. Two challenges in one
        // field naming the same unregistered scheme are one name to register
        // and would otherwise be one sentence printed twice, so a field reports
        // each distinct name once. The comparison folds case for the reason the
        // registry check does: § 11.1 makes the token case-insensitive.
        let mut out = Vec::new();
        {
            let config: &crate::helpers::rule_config::AllowedList = ctx.state();
            // The registry question, asked of one scheme token that is already
            // known to be one: the snapshot this crate carries of the registry
            // § 16.4.1 names, and then what the operator adds to it. The
            // comparison ignores case because the scheme token is
            // case-insensitive (§ 11.1).
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
            let check_registered = |hdr_name: &str,
                                    scheme: &str,
                                    party: crate::lint::Party|
             -> Option<Violation> {
                if crate::helpers::token::find_invalid_token_char(scheme).is_some()
                    || crate::registries::auth_scheme_registered(scheme)
                    || config.allowed.contains(&scheme.to_ascii_lowercase())
                {
                    return None;
                }
                Some(ctx.by(party).report_with(
                        &AUTH_SCHEME_UNREGISTERED,
                        format!(
                            "Auth-scheme '{}' in {} is not in the IANA HTTP Authentication Scheme registry, and this rule's `allowed` list does not name it",
                            scheme, hdr_name
                        ),
                    ))
            };

            // The challenges a response advertises, in each field § 11 writes
            // as `#challenge`. Read as octets and over the section: the field
            // lines are one list, and an octet outside visible US-ASCII belongs
            // to whichever production it landed in rather than being a verdict
            // about the field's encoding. A value that will not group is not
            // this rule's to report.
            if let Some(resp) = &tx.response {
                for field in crate::helpers::auth::CHALLENGE_FIELDS {
                    out.extend((|| -> Vec<Violation> {
                        let Some(s) = crate::helpers::headers::combined_field_value_as_written(
                            &resp.headers,
                            field.key,
                        ) else {
                            return Vec::new();
                        };
                        let Ok(challenges) = crate::helpers::auth::split_and_group_challenges(&s)
                        else {
                            return Vec::new();
                        };
                        let mut seen = Vec::new();
                        let mut found = Vec::new();
                        for challenge in challenges {
                            // The same split as the credentials side below, and
                            // for the same reason: the separator § 11.3 writes
                            // after an `auth-scheme` is `1*SP`, and cutting on
                            // `char::is_whitespace` also cuts at %xA0 and %x85,
                            // which are `obs-text` octets the sender wrote
                            // inside the name. A scheme truncated at one was
                            // then asked about by the registry under a name
                            // nobody sent.
                            // cite(RFC 9110 § 11.3): "challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]"
                            let scheme = crate::helpers::headers::trim_ows(
                                challenge.split([' ', '\t']).next().unwrap(),
                            );
                            let folded = scheme.to_ascii_lowercase();
                            if seen.contains(&folded) {
                                continue;
                            }
                            seen.push(folded);
                            found.extend(check_registered(
                                field.shown,
                                scheme,
                                crate::lint::Party::Server,
                            ));
                        }
                        found
                    })());
                }
            }

            // The credentials a request presents, in each field § 11 writes as
            // `credentials`. The production is one value rather than a list, so
            // the field lines are not combined -- and every one of them is
            // read, because a sender wrote each. A value whose framework
            // structure is wrong is `authorization_credentials_valid`'s
            // finding, so what is taken from each line here is only the scheme
            // in front of it.
            for field in crate::helpers::auth::CREDENTIALS_FIELDS {
                let mut seen = Vec::new();
                for hv in tx.request.headers.get_all(field.key).iter() {
                    let v = crate::helpers::headers::field_line_as_written(hv);
                    // The separator is `1*SP`, so the split is on SP and HTAB
                    // and not on `char::is_whitespace`: on a value carrying one
                    // `char` per octet the latter also cuts at %xA0 and %x85,
                    // which are `obs-text` the wire never wrote as a space --
                    // so a scheme ending in one was looked up in the registry
                    // with the offending octet already removed, and found.
                    // cite(RFC 9110 § 11.4): "credentials = auth-scheme [ 1*SP ( token68 / #auth-param ) ]"
                    let scheme = crate::helpers::headers::trim_ows(
                        v.split([' ', '\t']).next().unwrap_or(""),
                    );
                    if scheme.is_empty() {
                        continue;
                    }
                    let folded = scheme.to_ascii_lowercase();
                    if seen.contains(&folded) {
                        continue;
                    }
                    seen.push(folded);
                    out.extend(check_registered(
                        field.shown,
                        scheme,
                        crate::lint::Party::Client,
                    ));
                }
            }
        }
        out
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

    /// The scheme the registry is asked about is the one the sender wrote.
    ///
    /// § 11.3 and § 11.4 put `1*SP` after an `auth-scheme`, so the split is on
    /// SP and HTAB. It was `char::is_whitespace`, which on a value carrying one
    /// `char` per octet also cuts at %xA0 and %x85 — `obs-text` octets a sender
    /// wrote *inside* the name — so `Frobnicate\xA0abc` was truncated to
    /// `Frobnicate` and the registry answered about a name nobody sent.
    ///
    /// What the value carries now is a scheme that is not a `token`, which this
    /// rule declines by design and the grammar rule beside it reports. So the
    /// finding withdrawn here is not lost; it moves to the entry whose claim is
    /// true of the value.
    #[test]
    fn the_registry_is_asked_about_the_whole_name() {
        let mut request = crate::test_helpers::make_test_transaction();
        request.request.headers = crate::test_helpers::make_headers_from_octet_pairs(&[(
            "authorization",
            b"Frobnicate\xa0abc",
        )]);
        assert!(
            crate::test_helpers::run_rule(
                &AuthSchemeRegistered,
                &request,
                &crate::transaction_history::TransactionHistory::empty(),
                &make_cfg(),
            )
            .is_none(),
            "the scheme is not a token, which is the grammar rule's finding"
        );

        // The challenge side splits the same way and must answer the same.
        let mut response = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        response.response.as_mut().expect("a response").headers =
            crate::test_helpers::make_headers_from_octet_pairs(&[(
                "www-authenticate",
                b"Frobnicate\xa0realm=\"x\"",
            )]);
        assert!(crate::test_helpers::run_rule(
            &AuthSchemeRegistered,
            &response,
            &crate::transaction_history::TransactionHistory::empty(),
            &make_cfg(),
        )
        .is_none());

        // And the separator that IS one still separates.
        let mut request = crate::test_helpers::make_test_transaction();
        request.request.headers = crate::test_helpers::make_headers_from_octet_pairs(&[(
            "authorization",
            b"Frobnicate\tabc",
        )]);
        assert_eq!(
            crate::test_helpers::run_rule(
                &AuthSchemeRegistered,
                &request,
                &crate::transaction_history::TransactionHistory::empty(),
                &make_cfg(),
            )
            .expect("a finding")
            .violation,
            "auth_scheme_unregistered"
        );
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

    /// **Every field § 11 writes the framework into, and each finding names the
    /// one it read.**
    ///
    /// The proxy half was silent: `Proxy-Authenticate: NoSuchScheme realm="x"`
    /// on a `407` and `Proxy-Authorization: X-MyAuth abc` both drew nothing,
    /// where the identical value one field over is a finding. The message is
    /// asserted and not just the id, because the way this reader could be
    /// wrong once it exists is to report a true finding under the wrong
    /// field's name -- the sentence used to be written for one field per arm.
    #[rstest]
    #[case("www-authenticate", true, "WWW-Authenticate")]
    #[case("proxy-authenticate", true, "Proxy-Authenticate")]
    #[case("authorization", false, "Authorization")]
    #[case("proxy-authorization", false, "Proxy-Authorization")]
    fn the_registry_question_is_asked_of_every_field_that_carries_the_framework(
        #[case] key: &str,
        #[case] on_response: bool,
        #[case] shown: &str,
    ) {
        let value = if on_response {
            "NoSuchScheme realm=\"x\""
        } else {
            "NoSuchScheme abc"
        };
        let mut tx = if on_response {
            crate::test_helpers::make_test_transaction_with_response(407, &[])
        } else {
            crate::test_helpers::make_test_transaction()
        };
        let headers = crate::test_helpers::make_headers_from_pairs(&[(key, value)]);
        if on_response {
            tx.response.as_mut().expect("a response").headers = headers;
        } else {
            tx.request.headers = headers;
        }

        let found = crate::test_helpers::run_rule(
            &AuthSchemeRegistered,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &make_cfg(),
        )
        .unwrap_or_else(|| panic!("nothing reported for {key}"));
        assert_eq!(found.violation, "auth_scheme_unregistered");
        assert!(
            found.message.contains(shown),
            "a finding about {key} says {:?}, which does not name the field it read",
            found.message
        );
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
        // is spelled correctly and is registered, so there is nothing to
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
        // No `allowed` at all: the registry alone, which is not an error --
        // the list adds to the registry and adding nothing is the default.
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "auth_scheme_registered");
        assert!(AuthSchemeRegistered.prepare(&cfg).is_ok());

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

        // An empty `allowed` array is the shipped default, and the same answer.
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
        assert!(AuthSchemeRegistered.prepare(&cfg4).is_ok());

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

    /// Under the shipped configuration, which lists nothing, every scheme the
    /// registry holds is silent in all four fields, whatever its case. The
    /// three-name list that stood in for the registry reported every one of
    /// these.
    #[rstest]
    #[case("www-authenticate", "Negotiate")]
    #[case("www-authenticate", "DPoP algs=\"ES256\"")]
    #[case("www-authenticate", "HOBA challenge=\"x\", max-age=10")]
    #[case("proxy-authenticate", "Mutual realm=\"x\"")]
    #[case("authorization", "SCRAM-SHA-256 data=biws")]
    #[case("authorization", "vapid t=abc, k=def")]
    #[case("proxy-authorization", "negotiate YIIF")]
    #[case("authorization", "PrivateToken token=abc")]
    fn a_registered_scheme_is_not_reported(#[case] key: &str, #[case] value: &str) {
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["auth_scheme_registered"]);
        let mut tx = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        let headers = crate::test_helpers::make_headers_from_pairs(&[(key, value)]);
        if key.ends_with("authenticate") {
            tx.response.as_mut().expect("a response").headers = headers;
        } else {
            tx.request.headers = headers;
        }
        let found = crate::test_helpers::run_rule_all(
            &AuthSchemeRegistered,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(found.is_empty(), "{key}: {value}: {found:?}");
    }

    /// **Every unregistered scheme a field offers is its own finding.** The
    /// challenge walk `return`ed at the first, so a `WWW-Authenticate` naming
    /// two schemes nobody registered told a client about one of them — and the
    /// finding's whole content is the name, so the second had no sentence
    /// anywhere. `#challenge` is a list of alternatives and a client picks the
    /// strongest it supports; two it cannot use are two things to fix.
    #[test]
    fn every_unregistered_scheme_in_a_challenge_is_reported() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        tx.response.as_mut().expect("a response").headers =
            crate::test_helpers::make_headers_from_pairs(&[(
                "www-authenticate",
                "Zork realm=\"a\", Basic realm=\"b\", Quux realm=\"c\"",
            )]);
        let found = crate::test_helpers::run_rule_all(
            &AuthSchemeRegistered,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &make_cfg(),
        );
        let messages: Vec<&String> = found.iter().map(|v| &v.message).collect();
        assert_eq!(found.len(), 2, "{messages:?}");
        for scheme in ["'Zork'", "'Quux'"] {
            assert!(
                messages.iter().any(|m| m.contains(scheme)),
                "no finding names {scheme}: {messages:?}"
            );
        }
    }

    /// The same on the request side, where the repetition is field lines rather
    /// than list members: `credentials` is not a list, so a second
    /// `Authorization` line is a second value its sender wrote.
    #[test]
    fn every_unregistered_scheme_across_credential_lines_is_reported() {
        use hyper::header::{HeaderName, HeaderValue};
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = hyper::HeaderMap::new();
        for value in ["Zork abc", "Basic dGVzdA==", "Quux def"] {
            hm.append(
                HeaderName::from_static("authorization"),
                HeaderValue::from_str(value).expect("a test field value"),
            );
        }
        tx.request.headers = hm;
        let found = crate::test_helpers::run_rule_all(
            &AuthSchemeRegistered,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &make_cfg(),
        );
        let messages: Vec<&String> = found.iter().map(|v| &v.message).collect();
        assert_eq!(found.len(), 2, "{messages:?}");
        for scheme in ["'Zork'", "'Quux'"] {
            assert!(
                messages.iter().any(|m| m.contains(scheme)),
                "no finding names {scheme}: {messages:?}"
            );
        }
    }

    /// **The unit is the scheme, not the challenge.** One name written twice is
    /// one name to register, and the finding says nothing but the name — so two
    /// of them would be one sentence printed twice and an operator could not
    /// tell how many things they had to fix. Case folds, because § 11.1 makes
    /// the token case-insensitive and the registry check already reads it so.
    #[rstest]
    #[case("Zork realm=\"a\", Zork realm=\"b\"")]
    #[case("Zork realm=\"a\", zork realm=\"b\"")]
    fn one_scheme_named_twice_in_a_field_is_one_finding(#[case] value: &str) {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        tx.response.as_mut().expect("a response").headers =
            crate::test_helpers::make_headers_from_pairs(&[("www-authenticate", value)]);
        let found = crate::test_helpers::run_rule_all(
            &AuthSchemeRegistered,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &make_cfg(),
        );
        assert_eq!(
            found.len(),
            1,
            "{:?}",
            found.iter().map(|v| &v.message).collect::<Vec<_>>()
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
