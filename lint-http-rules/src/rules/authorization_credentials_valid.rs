// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::auth_scheme::{AUTH_SCHEME_CHARACTER_FORBIDDEN, RFC_9110_11_2};
use crate::violations::credentials::{
    credentials_defect, CREDENTIALS_CONTROL_CHARACTER_FORBIDDEN, CREDENTIALS_EMPTY,
    CREDENTIALS_MISSING, RFC_9110_11_4, RFC_9110_11_6_2,
};
use crate::violations::ViolationDef;

/// `Authorization`'s framework grammar: an `auth-scheme`, and the credentials
/// the scheme wants after it.
///
/// The request-side twin of `www_authenticate_challenge_syntax`, which reads
/// the same framework from the response side. Neither performs the
/// authentication and neither knows what a particular scheme's credentials must
/// contain — `basic_auth_base64_valid`, `bearer_token_syntax` and
/// `digest_auth_valid` own that, each for its own document.
///
/// **It has no configuration, and that is the point of it existing.** This
/// reading spent one commit inside `auth_scheme_registered`, which requires an
/// `allowed` list of acceptable schemes; an operator who wants a malformed
/// credential reported would have had to decide their registry policy first.
/// Grammar and policy are two questions and only one of them is the operator's
/// to answer.
pub struct AuthorizationCredentialsValid;

/// The defects this rule reports. Three belong to `credentials = auth-scheme
/// [ 1*SP ( token68 / #auth-param ) ]`, which `Proxy-Authorization` carries
/// too; the fourth is the scheme's, shared with the response side of the
/// framework — `www_authenticate_challenge_syntax` reports the same id about a
/// server's `WWW-Authenticate`, because `auth-scheme = token` is written once
/// and used from both directions.
///
/// **There is no non-UTF-8 finding.** The verdict that once stood here named an
/// encoding where the defect is an octet the field's grammar does not admit;
/// the value is read as octets, and each octet reaches the production that
/// refuses it — or, in the credentials, the scheme's own document next door.
static DECLARED: &[&ViolationDef] = &[
    &CREDENTIALS_EMPTY,
    &CREDENTIALS_MISSING,
    &CREDENTIALS_CONTROL_CHARACTER_FORBIDDEN,
    &AUTH_SCHEME_CHARACTER_FORBIDDEN,
];

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
///
/// The last two are further reading rather than sentences this rule enforces:
/// what the credentials after a `Basic` or a `Bearer` scheme have to be. No
/// defect cites either — the framework production is all this rule reads, and
/// the scheme rules that *do* read them own these documents — but a page about
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

impl RuleMeta for AuthorizationCredentialsValid {
    fn id(&self) -> &'static str {
        "authorization_credentials_valid"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn title(&self) -> Option<&'static str> {
        Some("Authorization Credentials")
    }

    fn description(&self) -> &'static str {
        "The `Authorization` request header field carries credentials: an authentication scheme, then the authentication information that scheme defines. This rule reads that framework structure and reports a field that is empty, one whose `auth-scheme` carries a character no `token` admits, one that stops after the scheme where the scheme wants credentials, and a control octet in the credentials themselves. Every field line is read, because a sender wrote each — that a request carries more than one `Authorization` line is `singleton_fields_not_repeated`'s finding. What the credentials must *be* once the scheme is known belongs to the scheme's own rule; whether the scheme is one the deployment accepts belongs to `auth_scheme_registered`."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_9110_11_6_2,
            RFC_9110_11_4,
            RFC_9110_11_2,
            RFC_7617,
            RFC_6750,
        ]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::Presumed(crate::lint::Party::Client)
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "GET /resource HTTP/1.1\nHost: example.com\nAuthorization: Bearer abc123",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "GET /resource HTTP/1.1\nHost: example.com\nAuthorization: Digest username=\"Mufasa\", realm=\"test\", nonce=\"abc\", uri=\"/resource\", response=\"d41d8cd98f00b204e9800998ecf8427e\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "GET /resource HTTP/1.1\nHost: example.com\nAuthorization: Basic",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "GET /resource HTTP/1.1\nHost: example.com\nAuthorization: B@sic abc",
            },
        ]
    }
}

impl Rule for AuthorizationCredentialsValid {
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
            // Read as octets. `to_str` refuses everything outside visible
            // US-ASCII, which made an octet in the credentials a verdict about
            // the field's encoding; the productions here own that octet -- the
            // scheme's `token`, and each scheme's own credential grammar next
            // door.
            //
            // `Authorization = credentials` is one value rather than a list, so
            // the field lines are **not** combined -- and every one of them is
            // read, because a sender wrote each and this rule measures what was
            // written. That a second line exists at all is
            // `singleton_fields_not_repeated`'s finding, and picking a line to
            // believe would make the rest of them unreadable rather than
            // reported.
            for hv in tx.request.headers.get_all("authorization").iter() {
                let s = crate::helpers::headers::field_line_as_written(hv);
                // The Authorization value is credentials — an auth-scheme with its
                // authentication information — which is the structure validated here.
                // The "credentials must actually be present" half is scheme-derived
                // (the framework grammar permits a bare scheme); the helper owns that
                // reasoning and the §11.4 structure cite.
                // cite(RFC 9110 § 11.6.2): "Its value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested"
                if let Err(defect) = crate::helpers::auth::validate_authorization_syntax(&s) {
                    return Some(ctx.report_with(
                        credentials_defect(defect),
                        format!("Invalid Authorization header: {}", defect.message()),
                    ));
                }
            }
            None
        };
        Vec::from_iter(finding())
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &AuthorizationCredentialsValid;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn judge(tx: &crate::http_transaction::HttpTransaction) -> Option<Violation> {
        crate::test_helpers::run_rule(
            &AuthorizationCredentialsValid,
            tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "authorization_credentials_valid",
            ]),
        )
    }

    fn with_authorization(values: &[&str]) -> crate::http_transaction::HttpTransaction {
        use hyper::header::{HeaderName, HeaderValue};
        let mut tx = crate::test_helpers::make_test_transaction();
        for value in values {
            tx.request.headers.append(
                HeaderName::from_static("authorization"),
                HeaderValue::from_str(value).expect("a test Authorization value"),
            );
        }
        tx
    }

    /// Four names where the rule had one id, and the severity each carries.
    #[rstest]
    #[case("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==", None)]
    #[case("Bearer abc123", None)]
    #[case("Digest username=\"Mufasa\", realm=\"test\"", None)]
    #[case("", Some("credentials_empty"))]
    #[case(" ", Some("credentials_empty"))]
    #[case("Basic", Some("credentials_missing"))]
    #[case("Basic ", Some("credentials_missing"))]
    #[case("B@sic xyz", Some("auth_scheme_character_forbidden"))]
    fn each_finding_names_the_defect(#[case] value: &str, #[case] expected: Option<&str>) {
        let found = judge(&with_authorization(&[value]));
        assert_eq!(
            found.as_ref().map(|v| v.violation.as_str()),
            expected,
            "{value:?}: {found:?}",
        );
    }

    #[test]
    fn a_request_with_no_authorization_is_silent() {
        assert!(judge(&with_authorization(&[])).is_none());
    }

    /// Every field line is read, not only the first. A sender wrote both, and
    /// *that* there are two is `singleton_fields_not_repeated`'s finding.
    #[rstest]
    #[case("Basic", "Bearer abc123")]
    #[case("Bearer abc123", "Basic")]
    fn every_field_line_is_read(#[case] first: &str, #[case] second: &str) {
        let found = judge(&with_authorization(&[first, second]))
            .unwrap_or_else(|| panic!("expected a finding for {first:?} then {second:?}"));
        assert_eq!(found.violation, "credentials_missing", "{}", found.message);
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

    /// An octet outside visible US-ASCII is read rather than refused, and
    /// where it lands decides whether this rule has anything to say. In the
    /// scheme it is the `token`'s defect and reports here; in the credentials
    /// it is the scheme's own grammar's — `b64token`, a Base64 alphabet, a set
    /// of `auth-param`s — and this rule is silent, because the framework
    /// production it enforces is satisfied. The value used to be reported as
    /// *non-UTF8* either way, which named the reader rather than the field.
    #[test]
    fn an_obs_text_octet_is_read_where_it_lands() {
        use hyper::header::{HeaderName, HeaderValue};
        let judge_bytes = |value: &[u8]| {
            let mut tx = crate::test_helpers::make_test_transaction();
            tx.request.headers.append(
                HeaderName::from_static("authorization"),
                HeaderValue::from_bytes(value).expect("a test Authorization value"),
            );
            judge(&tx)
        };

        assert!(judge_bytes(b"Bearer \xff").is_none());
        assert_eq!(
            judge_bytes(b"B\xffarer abc").expect("a finding").violation,
            "auth_scheme_character_forbidden",
        );
    }

    /// Grammar and policy are two questions, and this rule answers only the
    /// first — which is what taking it out of `auth_scheme_registered` bought.
    /// An unknown-but-well-formed scheme is nothing to this rule, and its
    /// configuration has no allowlist to have asked about.
    #[test]
    fn an_unregistered_scheme_is_not_this_rules_question() {
        assert!(judge(&with_authorization(&["X-MyAuth abc"])).is_none());

        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "authorization_credentials_valid");
        crate::rules::validate_rules(&cfg).expect("this rule needs no options");
    }

    #[test]
    fn id_and_scope_are_expected() {
        let r = AuthorizationCredentialsValid;
        assert_eq!(r.id(), "authorization_credentials_valid");
        assert_eq!(r.scope(), crate::rules::RuleScope::Client);
    }

    /// This rule reads a credential only as far as "a scheme, then something",
    /// so every scheme-specific defect in a value it publishes is invisible to
    /// it. The published Digest credential named two parameters of the five its
    /// own scheme rule requires, and was labelled `Compliant` in the docs the
    /// whole time. The scheme owners judge these values now; each declines on a
    /// value belonging to the other scheme, so both run over every example.
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
        for ex in AuthorizationCredentialsValid.examples() {
            if ex.compliance != Compliance::Compliant {
                continue;
            }
            let fields: Vec<(&str, &str)> = ex
                .snippet
                .lines()
                .skip(1)
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

    /// The published examples are judged the way they are labelled.
    #[test]
    fn published_examples_are_judged_the_way_they_are_labelled() {
        use crate::rules::{Compliance, RuleMeta as _};

        let mut saw_a_finding = false;
        for ex in AuthorizationCredentialsValid.examples() {
            let mut lines = ex.snippet.lines();
            let start = lines.next().expect("an example has a start line");
            assert!(
                !start.starts_with("HTTP/"),
                "a response-shaped example cannot be checked by this guard: {start:?}"
            );
            let fields: Vec<(&str, &str)> = lines
                .filter(|l| !l.trim().is_empty())
                .map(|l| {
                    l.split_once(": ")
                        .unwrap_or_else(|| panic!("not a header line: {l:?}"))
                })
                .collect();
            let tx = crate::test_helpers::make_test_transaction_with_headers(&fields);
            let found = judge(&tx);
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
