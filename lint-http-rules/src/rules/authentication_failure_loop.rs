// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::helpers::headers::combined_field_value_as_written;
use crate::helpers::shown::shown_in_finding;
use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::status::{RFC_9110_15_5_2, STATUS_401_IGNORED};
use crate::violations::ViolationDef;

/// One entry, and the threshold below is not part of it: the catalogue says the
/// loop happened, this rule says how many rounds it takes to call one.
static DECLARED: &[&ViolationDef] = &[&STATUS_401_IGNORED];

/// Detects repeated 401 challenges for the same protection space (origin),
/// which indicates an authentication failure loop.
pub struct AuthenticationFailureLoop;

// The one reference this rule names lives on the entry it reports through and
// is imported back for `specifications()`, so the citation and the documented
// reading are the same value rather than two copies of it.

impl RuleMeta for AuthenticationFailureLoop {
    fn id(&self) -> &'static str {
        "authentication_failure_loop"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn description(&self) -> &'static str {
        "Reports a client that keeps presenting credentials one challenge keeps refusing. It could imply a broken client, misconfigured credentials, or a flawed authentication handshake, and the rule declines to choose between the three.\n\n**The sentence behind it states two conditions and both are read.** RFC 9110 §15.5.2: *\"If the 401 response contains the same challenge as the prior response, and the user agent has already attempted authentication at least once, then the user agent SHOULD present the enclosed representation to the user\"*. So a link in the run is a `401` that **refused an attempt** — the request carried an `Authorization` field — and **handed back the same challenge** as the one in front of the rule. Anything else ends the run: another status, an exchange with no answer, a request that carried no credentials, a different challenge.\n\n**Four is this rule's number and not the catalogue's.** No sentence fixes one — §15.5.2 says *\"at least once\"* and stops — so the threshold sits with the rule that chose it: four consecutive refusals, which is comfortably past the single retry-and-re-present the section sanctions.\n\n**Presence is the whole of the credentials test.** `Authorization = credentials`, and what is inside the field is `authorization_credentials_valid`'s question; a client that wrote the field attempted authentication however badly, so a value this rule cannot decode still counts as an attempt.\n\n**The challenge is compared as written, byte for byte.** `challenge` folds case in its scheme and its parameter names, but §11.5 makes a `realm` *\"a free-form string that can only be compared for equality\"* — so folding the value would fold the one part that must not be. What the exactness costs is a server that respells its challenge between two responses, which reads here as a different challenge and is not reported; that is the safe direction for a finding about a client that will not stop, and it is also why a `Digest` challenge with a fresh `nonce` each round is silent, since that client is being handed something new to answer.\n\n**Two 401s carrying no challenge at all do not match each other.** *\"Contains the same challenge as the prior response\"* is not satisfied by two responses that contain none, and a 401 without the field is its own MUST violation rather than evidence for this one.\n\n**History is scoped to the origin**, which is where the question can be asked and not the protection space itself: §11.5 makes a `realm` in combination with the canonical root URI the protection space, and the challenge comparison above is what narrows an origin's run to one of them."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_9110_15_5_2]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    /// **Neither peer, and the rule's own description says so before this
    /// field existed to record it**: a run of 401s "could imply a broken
    /// client, misconfigured credentials, or a flawed authentication
    /// handshake", and the rule declines to choose between the three.
    ///
    /// The evidence is not in a message at all. Four transactions read
    /// together are what a loop is, and no single one of them is the defect —
    /// the client re-presenting credentials is doing what §15.5.2 invites, and
    /// each 401 answering them is correct on its own terms. `Neither` is the
    /// value that says a reader narrowing to one end still wants this, because
    /// it is about the exchange they are in rather than about the half they
    /// wrote.
    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::Presumed(crate::lint::Party::Neither)
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("— the challenge answered once, and accepted"),
                snippet: "> GET /protected HTTP/1.1\n> Host: example.com\n\n< 401 Unauthorized HTTP/1.1\n< WWW-Authenticate: Basic realm=\"Access\"\n\n> GET /protected HTTP/1.1\n> Host: example.com\n> Authorization: Basic ...\n\n< 200 OK HTTP/1.1",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("— a client that has attempted nothing"),
                snippet: "> GET /protected HTTP/1.1\n> Host: example.com\n\n< 401 Unauthorized HTTP/1.1\n< WWW-Authenticate: Basic realm=\"Access\"\n\n> GET /protected HTTP/1.1\n> Host: example.com\n\n< 401 Unauthorized HTTP/1.1\n< WWW-Authenticate: Basic realm=\"Access\"\n\n> GET /protected HTTP/1.1\n> Host: example.com\n\n< 401 Unauthorized HTTP/1.1\n< WWW-Authenticate: Basic realm=\"Access\"\n\n> GET /protected HTTP/1.1\n> Host: example.com\n\n< 401 Unauthorized HTTP/1.1\n< WWW-Authenticate: Basic realm=\"Access\"\n\n# no request carried credentials, so nothing has been replayed: this is the\n# first four rounds of an authentication that has not started",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("— a different challenge each time"),
                snippet: "> GET /a HTTP/1.1\n> Host: example.com\n> Authorization: Basic ...\n\n< 401 Unauthorized HTTP/1.1\n< WWW-Authenticate: Basic realm=\"one\"\n\n> GET /b HTTP/1.1\n> Host: example.com\n> Authorization: Basic ...\n\n< 401 Unauthorized HTTP/1.1\n< WWW-Authenticate: Basic realm=\"two\"\n\n> GET /c HTTP/1.1\n> Host: example.com\n> Authorization: Basic ...\n\n< 401 Unauthorized HTTP/1.1\n< WWW-Authenticate: Basic realm=\"three\"\n\n> GET /d HTTP/1.1\n> Host: example.com\n> Authorization: Basic ...\n\n< 401 Unauthorized HTTP/1.1\n< WWW-Authenticate: Basic realm=\"four\"\n\n# four protection spaces, each answered for the first time",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— the same credential refused by the same challenge, four times"),
                snippet: "> GET /api/v1/data HTTP/1.1\n> Host: example.com\n> Authorization: Bearer INVALID\n\n< 401 Unauthorized HTTP/1.1\n< WWW-Authenticate: Bearer realm=\"API\"\n\n> GET /api/v1/data HTTP/1.1\n> Host: example.com\n> Authorization: Bearer INVALID\n\n< 401 Unauthorized HTTP/1.1\n< WWW-Authenticate: Bearer realm=\"API\"\n\n> GET /api/v1/data HTTP/1.1\n> Host: example.com\n> Authorization: Bearer INVALID\n\n< 401 Unauthorized HTTP/1.1\n< WWW-Authenticate: Bearer realm=\"API\"\n\n> GET /api/v1/data HTTP/1.1\n> Host: example.com\n> Authorization: Bearer INVALID\n\n< 401 Unauthorized HTTP/1.1\n< WWW-Authenticate: Bearer realm=\"API\"",
            },
        ]
    }
}

impl Rule for AuthenticationFailureLoop {
    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // Single-finding body behind an Option: `?` ends it early, and the
        // one finding (or none) becomes the vector.
        let finding = || -> Option<Violation> {
            // Only 401 responses matter — the status that means credentials were missing
            // or rejected, i.e. an authentication attempt that did not succeed.
            // cite(RFC 9110 § 15.5.2): "The 401 (Unauthorized) status code indicates that the request has not been applied because it lacks valid authentication credentials for the target resource."
            let resp = tx.response.as_ref()?;
            if resp.status != 401 {
                return None;
            }

            // § 15.5.2's second term, and the one whose absence made the finding
            // untrue rather than merely wide. The sentence binds a user agent
            // that "has already attempted authentication at least once", and the
            // entry says a client *replays credentials* — so a request carrying
            // none is not the client this reports, it is the first half of an
            // authentication that has not started. Four bare requests to a
            // protected resource were reported as a credential replayed four
            // times.
            //
            // Presence is the whole test: `Authorization = credentials` and what
            // is in the field is `authorization_credentials_valid`'s question, so
            // a value this rule cannot decode is still an attempt the client made.
            // cite(RFC 9110 § 11.6.2): "The "Authorization" header field allows a user agent to authenticate itself with an origin server -- usually, but not necessarily, after receiving a 401 (Unauthorized) response."
            if !attempted_authentication(&tx.request) {
                return None;
            }

            // § 15.5.2's first term. The sentence is about the *same* challenge
            // coming back, and a 401 that answers with a different one has not
            // refused this attempt before — a client answering a realm it has
            // not yet been refused by is doing what the section sanctions.
            //
            // Read as written and compared byte for byte. `challenge` is
            // case-insensitive in its scheme and its parameter names and § 11.5
            // makes a `realm` comparable only for equality, so folding the value
            // would fold the one part that must not be folded; what the exactness
            // costs is a server that respells its challenge between two
            // responses, which reads here as a different challenge and is not
            // reported. That is the safe direction for a finding about a client
            // that will not stop.
            //
            // A 401 that carries no challenge at all ends the run rather than
            // matching another that carries none: "contains the same challenge as
            // the prior response" is not satisfied by two responses that contain
            // none, and a 401 without the field is `status_401_challenge_missing`'s finding
            // rather than evidence for this one.
            // cite(RFC 9110 § 15.5.2): "The server generating a 401 response MUST send a WWW-Authenticate header field (Section 11.6.1) containing at least one challenge applicable to the target resource."
            let challenge = combined_field_value_as_written(&resp.headers, "www-authenticate")?;

            // History is scoped to this origin by the rule's ByOrigin query, so a "run" of
            // 401s here is one protection space's failures, not a mix across hosts.
            //
            // A link in the run is one thing and the loop says it once: a 401
            // that refused an attempt and handed back this same challenge.
            // Anything else — another status, an exchange with no answer, a
            // request that carried no credentials, a different challenge — is
            // where the run ends, because past it the two terms above stop
            // holding of the messages being counted.
            let mut consecutive_401s = 0;

            for prev_tx in history.iter() {
                let Some(prev_resp) = prev_tx.response.as_ref() else {
                    break;
                };
                if prev_resp.status != 401 || !attempted_authentication(&prev_tx.request) {
                    break;
                }
                match combined_field_value_as_written(&prev_resp.headers, "www-authenticate") {
                    Some(prev) if prev == challenge => consecutive_401s += 1,
                    _ => break,
                }
            }

            // Loop = more than 3 consecutive 401s *before* this one (4th and up).
            // The exact count of 4 is this rule's heuristic threshold and stays
            // here rather than moving onto the entry with the sentence: no
            // sentence fixes a number, §15.5.2 says "at least once" and stops,
            // so a linter that picked one owns it. Four sits comfortably past
            // the single sanctioned retry-and-re-present.
            if consecutive_401s >= 3 {
                Some(ctx.report_with(&STATUS_401_IGNORED, format!(
                        "Authentication failure loop: {} consecutive 401 Unauthorized responses at this origin have answered credentials with the same challenge '{}', and the client presented credentials again after each one.",
                        consecutive_401s + 1,
                        shown_in_finding(&challenge)
                    )))
            } else {
                None
            }
        };
        Vec::from_iter(finding())
    }
}

/// Whether this request states an authentication attempt.
///
/// The half of § 15.5.2's antecedent a captured request can answer. It is
/// presence and not a reading: the sentence asks whether the user agent
/// *attempted* authentication, and a client that wrote the field attempted it
/// however badly — a malformed `credentials` is a defect the field's own rule
/// reports, not evidence that nothing was tried.
fn attempted_authentication(req: &crate::http_transaction::RequestInfo) -> bool {
    req.headers.contains_key("authorization")
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &AuthenticationFailureLoop;

#[cfg(test)]
mod tests {
    use super::*;

    /// One exchange in a run: a request that did or did not attempt
    /// authentication, and a 401 that did or did not hand back a challenge.
    ///
    /// Every test below builds its run out of this, because the two terms
    /// § 15.5.2 states are exactly the two arguments — and a helper taking a
    /// status alone is what let the old tests pin a run of four bare requests
    /// as a client replaying credentials.
    fn exchange(
        status: u16,
        credentials: Option<&str>,
        challenge: Option<&str>,
    ) -> crate::http_transaction::HttpTransaction {
        let resp: Vec<(&str, &str)> = challenge
            .map(|c| vec![("www-authenticate", c)])
            .unwrap_or_default();
        let mut tx = crate::test_helpers::make_test_transaction_with_response(status, &resp);
        if let Some(c) = credentials {
            tx.request.headers.insert(
                "authorization",
                hyper::header::HeaderValue::from_str(c).unwrap(),
            );
        }
        tx
    }

    fn refused(realm: &str) -> crate::http_transaction::HttpTransaction {
        exchange(401, Some("Basic dXNlcjpwYXNz"), Some(realm))
    }

    fn judge(
        tx: &crate::http_transaction::HttpTransaction,
        prior: Vec<crate::http_transaction::HttpTransaction>,
    ) -> Option<Violation> {
        // Newest first, which is the order `TransactionHistory` walks and
        // asserts. The helper stamps each transaction with the wall clock at
        // the moment it was built, so a `Vec` written newest-first is stamped
        // oldest-first; the timestamps are rewritten here rather than left to
        // the order the test happened to construct them in.
        let mut prior = prior;
        for (i, t) in prior.iter_mut().enumerate() {
            t.timestamp = chrono::Utc::now() - chrono::Duration::seconds(i as i64 + 1);
        }
        let history = crate::transaction_history::TransactionHistory::from_transactions(prior);
        crate::test_helpers::run_rule(
            &AuthenticationFailureLoop,
            tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "authentication_failure_loop",
            ]),
        )
    }

    #[test]
    fn a_credential_replayed_against_one_challenge_is_the_loop() {
        let challenge = "Basic realm=\"Access\"";
        let v = judge(
            &refused(challenge),
            vec![refused(challenge), refused(challenge), refused(challenge)],
        )
        .expect("a finding");
        assert_eq!(v.violation, "status_401_ignored");
        assert!(v.message.contains("4 consecutive"), "{}", v.message);
        // The finding names the challenge that kept coming back, because that
        // is the value § 15.5.2's first term is about.
        assert!(v.message.contains("realm="), "{}", v.message);
    }

    /// § 15.5.2's second term. Four bare requests to a protected resource are
    /// the first four rounds of an authentication that never started, and the
    /// entry is about a client that *replays credentials*.
    #[test]
    fn a_client_that_sent_no_credentials_has_attempted_nothing() {
        let challenge = "Basic realm=\"Access\"";
        let bare = || exchange(401, None, Some(challenge));
        assert!(judge(&bare(), vec![bare(), bare(), bare()]).is_none());
    }

    /// The same term, one message in: the run is credentials refused four
    /// times, so an earlier exchange that carried none ends it.
    #[test]
    fn an_earlier_request_without_credentials_ends_the_run() {
        let challenge = "Basic realm=\"Access\"";
        assert!(judge(
            &refused(challenge),
            vec![
                refused(challenge),
                exchange(401, None, Some(challenge)),
                refused(challenge),
            ],
        )
        .is_none());
    }

    /// § 15.5.2's first term. Four realms are four protection spaces, and a
    /// client answering one it has not been refused by yet is doing what the
    /// section sanctions rather than ignoring it.
    #[test]
    fn a_challenge_that_changes_is_not_the_same_challenge() {
        let v = judge(
            &refused("Basic realm=\"r3\""),
            vec![
                refused("Basic realm=\"r2\""),
                refused("Basic realm=\"r1\""),
                refused("Basic realm=\"r0\""),
            ],
        );
        assert!(v.is_none());
    }

    /// Absence is not agreement: two 401s that carry no challenge do not
    /// "contain the same challenge", and a 401 without one is its own finding.
    #[test]
    fn two_responses_with_no_challenge_do_not_match_each_other() {
        let no_challenge = || exchange(401, Some("Basic dXNlcjpwYXNz"), None);
        assert!(judge(
            &no_challenge(),
            vec![no_challenge(), no_challenge(), no_challenge()],
        )
        .is_none());
    }

    #[test]
    fn a_non_401_between_them_ends_the_run() {
        let challenge = "Basic realm=\"Access\"";
        assert!(judge(
            &refused(challenge),
            vec![
                refused(challenge),
                exchange(200, Some("Basic dXNlcjpwYXNz"), None),
                refused(challenge),
                refused(challenge),
            ],
        )
        .is_none());
    }

    #[test]
    fn three_refusals_are_below_the_threshold() {
        let challenge = "Basic realm=\"Access\"";
        assert!(judge(
            &refused(challenge),
            vec![refused(challenge), refused(challenge)]
        )
        .is_none());
    }

    #[test]
    fn a_response_that_is_not_401_is_not_read() {
        let challenge = "Basic realm=\"Access\"";
        let tx = exchange(200, Some("Basic dXNlcjpwYXNz"), None);
        assert!(judge(
            &tx,
            vec![refused(challenge), refused(challenge), refused(challenge)]
        )
        .is_none());
    }

    #[test]
    fn validate_rules_with_valid_config() {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "authentication_failure_loop");
        crate::rules::validate_rules(&cfg).unwrap();
    }
}
