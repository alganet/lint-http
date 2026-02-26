// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// Stateful tracking of Digest authentication nonce/opaque lifecycle.
///
/// "Digest" authentication uses a server-supplied `nonce` (and optional
/// `opaque`) and a client-supplied `nc` (nonce-count) to guard against replay.
/// RFC 7616 requires clients to never reuse the same nonce-count for a given
/// nonce, and servers to reject stale nonces (typically indicated by a
/// subsequent `WWW-Authenticate` challenge with `stale=true`).  The `opaque`
/// value, if present in the challenge, must be returned unchanged by the client.
///
/// This rule watches both sides of the transaction history (client requests and
/// server challenges) and flags the following mistakes:
///
/// * Authorization header using a nonce for which no previous challenge was
///   seen.
/// * Client sends a different `opaque` value than the most recent challenge.
/// * `nc` value is not strictly greater than any previously-observed count for
///   the same nonce.
/// * When a challenge includes `stale=true` and the client switches to a new
///   nonce, the first request must reset `nc` to `00000001`.
///
/// Implementing this rule requires history spanning an entire origin (not just
/// the same resource) because nonces are shared across a protection space.  The
/// engine therefore queries transactions `ByOrigin` for this rule.
pub struct StatefulDigestAuthNonceHandling;

impl Rule for StatefulDigestAuthNonceHandling {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "stateful_digest_auth_nonce_handling"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        history: &crate::transaction_history::TransactionHistory,
        config: &Self::Config,
    ) -> Option<Violation> {
        // only care about client-side requests with Digest Authorization
        for hv in tx.request.headers.get_all("authorization").iter() {
            let s = match hv.to_str() {
                Ok(v) => v,
                Err(_) => continue, // non-UTF8 header; other rules may catch this
            };
            let mut parts = s.trim().splitn(2, char::is_whitespace);
            let scheme = parts.next().unwrap_or("");
            if !scheme.eq_ignore_ascii_case("digest") {
                continue;
            }
            let rest = parts.next().unwrap_or("").trim();
            if rest.is_empty() {
                continue;
            }

            let params = match crate::helpers::auth::parse_auth_params(rest) {
                Ok(m) => m,
                Err(_) => {
                    // syntax errors are caught by message_digest_auth_validity,
                    // so just bail out here rather than reporting again.
                    continue;
                }
            };

            let nonce = params.get("nonce").map(|v| v.trim_matches('"').to_string());
            let opaque = params
                .get("opaque")
                .map(|v| v.trim_matches('"').to_string());
            let nc_str = params.get("nc").map(|v| v.as_str());

            // find the most recent Digest challenge in history
            let mut last_challenge_nonce: Option<String> = None;
            let mut last_challenge_opaque: Option<String> = None;
            let mut last_challenge_stale: Option<String> = None;

            for prev in history.iter() {
                if let Some(resp) = &prev.response {
                    if resp.status == 401 {
                        for hv2 in resp.headers.get_all("www-authenticate").iter() {
                            if let Ok(val2) = hv2.to_str() {
                                if let Ok(challs) =
                                    crate::helpers::auth::split_and_group_challenges(val2)
                                {
                                    for chall in challs {
                                        let mut parts2 = chall.splitn(2, char::is_whitespace);
                                        let scheme2 = parts2.next().unwrap_or("");
                                        if !scheme2.eq_ignore_ascii_case("digest") {
                                            continue;
                                        }
                                        let rest2 = parts2.next().unwrap_or("").trim();
                                        if let Ok(map2) =
                                            crate::helpers::auth::parse_auth_params(rest2)
                                        {
                                            if last_challenge_nonce.is_none() {
                                                if let Some(n) = map2.get("nonce") {
                                                    last_challenge_nonce =
                                                        Some(n.trim_matches('"').to_string());
                                                }
                                                if let Some(o) = map2.get("opaque") {
                                                    last_challenge_opaque =
                                                        Some(o.trim_matches('"').to_string());
                                                }
                                                if let Some(st) = map2.get("stale") {
                                                    last_challenge_stale =
                                                        Some(st.trim_matches('"').to_string());
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        if last_challenge_nonce.is_some() {
                            break; // we only need the most recent challenge
                        }
                    }
                }
            }

            // 1. nonce must have been offered in a challenge
            if nonce.is_some() && last_challenge_nonce.is_none() {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Digest Authorization used without prior Digest challenge".into(),
                });
            }

            // 2. opaque must match challenge if present
            if let (Some(ref o), Some(ref expected)) =
                (opaque.as_ref(), last_challenge_opaque.as_ref())
            {
                if o != expected {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Digest Authorization opaque does not match most recent challenge"
                            .into(),
                    });
                }
            } else if opaque.is_none() && last_challenge_opaque.is_some() {
                // Challenge included opaque, but client omitted it
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Digest Authorization missing opaque from most recent challenge"
                        .into(),
                });
            }

            // 3. nonce must correspond to the most recent challenge value.
            // `stale=true` does **not** relax this requirement; it only affects
            // the expected nonce-count reset behaviour which is checked later.
            if let (Some(ref n), Some(ref expected)) =
                (nonce.as_ref(), last_challenge_nonce.as_ref())
            {
                if n != expected {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Digest Authorization nonce differs from most recent challenge"
                            .into(),
                    });
                }
            }

            // 4. nonce-count progression and reset behavior
            if let Some(nc_val) = nc_str {
                let current_nc = match crate::helpers::auth::parse_nc_hex(nc_val) {
                    Ok(v) => v,
                    Err(msg) => {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!("Invalid nc (nonce-count) value: {}", msg),
                        });
                    }
                };

                // find highest previous nc for same nonce
                let mut highest = 0u64;
                for prev in history.iter() {
                    for hv3 in prev.request.headers.get_all("authorization").iter() {
                        if let Ok(val3) = hv3.to_str() {
                            let mut parts3 = val3.trim().splitn(2, char::is_whitespace);
                            let scheme3 = parts3.next().unwrap_or("");
                            if !scheme3.eq_ignore_ascii_case("digest") {
                                continue;
                            }
                            let rest3 = parts3.next().unwrap_or("").trim();
                            if let Ok(map3) = crate::helpers::auth::parse_auth_params(rest3) {
                                if let (Some(prev_nonce), Some(this_nonce)) =
                                    (map3.get("nonce"), nonce.as_ref())
                                {
                                    if prev_nonce.trim_matches('"') == this_nonce.as_str() {
                                        if let Some(prev_nc) = map3.get("nc") {
                                            if let Ok(prev_nc_val) =
                                                crate::helpers::auth::parse_nc_hex(prev_nc)
                                            {
                                                highest = highest.max(prev_nc_val);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                if current_nc <= highest {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Digest Authorization nonce-count did not increase".into(),
                    });
                }

                // when the most recent challenge has stale=true, ensure the nonce-count
                // resets if this is the first request for that nonce.  (Nonce equality is
                // already enforced above.)
                if last_challenge_stale.as_deref() == Some("true")
                    && highest == 0
                    && current_nc != 1
                {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Digest Authorization with new nonce after stale challenge must reset nc to 00000001".into(),
                    });
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tx_resp_with_challenge(challenge: &str) -> crate::http_transaction::HttpTransaction {
        crate::test_helpers::make_test_transaction_with_response(
            401,
            &[("www-authenticate", challenge)],
        )
    }

    /// Generate a random nonce string suitable for tests (32 hex digits) using
    /// a UUID v4.  This avoids hard-coded values and relies on an existing
    /// dependency (`uuid`).
    fn random_nonce() -> String {
        // `Uuid::new_v4()` produces 16 random bytes which we render as lowercase
        // hex without hyphens (32 chars).
        uuid::Uuid::new_v4().simple().to_string()
    }

    fn make_challenge(nonce: &str, opaque: Option<&str>, stale: Option<&str>) -> String {
        let mut v = format!("Digest realm=\"r\", nonce=\"{}\"", nonce);
        if let Some(o) = opaque {
            v.push_str(&format!(", opaque=\"{}\"", o));
        }
        if let Some(s) = stale {
            v.push_str(&format!(", stale={}", s));
        }
        v
    }

    fn make_auth(nonce: &str, nc: Option<&str>, opaque: Option<&str>) -> String {
        let mut v = format!(
            "Digest username=U, realm=\"r\", nonce=\"{}\", uri=/, response=d",
            nonce
        );
        if let Some(nc_val) = nc {
            v.push_str(&format!(", nc={}", nc_val));
        }
        if let Some(o) = opaque {
            v.push_str(&format!(", opaque=\"{}\"", o));
        }
        v
    }

    fn tx_req_with_auth(auth: &str) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("authorization", auth)]);
        tx
    }

    #[test]
    fn no_challenge_before_auth_is_reported() {
        let nonce1 = random_nonce();
        let tx = tx_req_with_auth(&make_auth(&nonce1, Some("00000001"), None));
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = StatefulDigestAuthNonceHandling.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v
            .unwrap()
            .message
            .contains("without prior Digest challenge"));
    }

    #[test]
    fn opaque_mismatch() {
        let nonce1 = random_nonce();
        let history =
            crate::transaction_history::TransactionHistory::new(vec![tx_resp_with_challenge(
                &make_challenge(&nonce1, Some("o1"), None),
            )]);
        let tx = tx_req_with_auth(&make_auth(&nonce1, Some("00000001"), Some("o2")));
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = StatefulDigestAuthNonceHandling.check_transaction(&tx, &history, &cfg);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("opaque does not match"));
    }

    #[test]
    fn missing_opaque_reports() {
        let nonce1 = random_nonce();
        let history =
            crate::transaction_history::TransactionHistory::new(vec![tx_resp_with_challenge(
                &make_challenge(&nonce1, Some("o1"), None),
            )]);
        let tx = tx_req_with_auth(&make_auth(&nonce1, Some("00000001"), None));
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = StatefulDigestAuthNonceHandling.check_transaction(&tx, &history, &cfg);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("missing opaque"));
    }

    #[test]
    fn non_digest_auth_header_ignored() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("authorization", "Basic abc")]);
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = StatefulDigestAuthNonceHandling.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn digest_without_nonce_is_ignored() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "authorization",
            "Digest realm=\"r\"",
        )]);
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = StatefulDigestAuthNonceHandling.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn parse_error_in_auth_is_ignored() {
        let mut tx = crate::test_helpers::make_test_transaction();
        // malformed auth-param list will make parse_auth_params return Err
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "authorization",
            "Digest bogus=\"x\", =bad",
        )]);
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = StatefulDigestAuthNonceHandling.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn nonce_count_must_increase() {
        let nonce1 = random_nonce();
        // include an initial challenge so the missing-challenge check doesn't
        // short-circuit the nc validation
        let auth1 = make_auth(&nonce1, Some("00000005"), None);
        let auth2 = make_auth(&nonce1, Some("00000004"), None);
        let history = crate::transaction_history::TransactionHistory::new(vec![
            tx_resp_with_challenge(&make_challenge(&nonce1, None, None)),
            tx_req_with_auth(&auth1),
        ]);
        let tx = tx_req_with_auth(&auth2);
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = StatefulDigestAuthNonceHandling.check_transaction(&tx, &history, &cfg);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("nonce-count did not increase"));
    }

    #[test]
    fn new_nonce_after_stale_must_reset_nc() {
        let nonce = random_nonce();
        // challenge with stale=true provides a new nonce value, which the client
        // must then reuse but reset nc to 1
        let history =
            crate::transaction_history::TransactionHistory::new(vec![tx_resp_with_challenge(
                &make_challenge(&nonce, None, Some("true")),
            )]);
        // client correctly uses same nonce but wrong nc
        let tx = tx_req_with_auth(&make_auth(&nonce, Some("00000005"), None));
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = StatefulDigestAuthNonceHandling.check_transaction(&tx, &history, &cfg);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("must reset nc"));
    }

    #[test]
    fn valid_sequence_passes() {
        let nonce1 = random_nonce();
        let history = crate::transaction_history::TransactionHistory::new(vec![
            tx_resp_with_challenge(&make_challenge(&nonce1, Some("o1"), None)),
            tx_req_with_auth(&make_auth(&nonce1, Some("00000001"), Some("o1"))),
        ]);
        let tx = tx_req_with_auth(&make_auth(&nonce1, Some("00000002"), Some("o1")));
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = StatefulDigestAuthNonceHandling.check_transaction(&tx, &history, &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn nonce_mismatch_without_stale_reports() {
        let nonce1 = random_nonce();
        let nonce2 = random_nonce();
        let history =
            crate::transaction_history::TransactionHistory::new(vec![tx_resp_with_challenge(
                &make_challenge(&nonce1, None, None),
            )]);
        let tx = tx_req_with_auth(&make_auth(&nonce2, Some("00000001"), None));
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = StatefulDigestAuthNonceHandling.check_transaction(&tx, &history, &cfg);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("nonce differs"));
    }

    #[test]
    fn missing_opaque_reports_violation() {
        let nonce1 = random_nonce();
        let history =
            crate::transaction_history::TransactionHistory::new(vec![tx_resp_with_challenge(
                &make_challenge(&nonce1, Some("o123"), None),
            )]);
        // request omits opaque entirely
        let tx = tx_req_with_auth(&make_auth(&nonce1, Some("00000001"), None));
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = StatefulDigestAuthNonceHandling.check_transaction(&tx, &history, &cfg);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("missing opaque"));
    }

    #[test]
    fn stale_challenge_with_wrong_nonce_reports() {
        let nonce1 = random_nonce();
        let nonce2 = random_nonce();
        let history =
            crate::transaction_history::TransactionHistory::new(vec![tx_resp_with_challenge(
                &make_challenge(&nonce1, None, Some("true")),
            )]);
        // client uses different nonce entirely
        let tx = tx_req_with_auth(&make_auth(&nonce2, Some("00000001"), None));
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = StatefulDigestAuthNonceHandling.check_transaction(&tx, &history, &cfg);
        assert!(v.is_some());
        assert!(v
            .unwrap()
            .message
            .contains("nonce differs from most recent challenge"));
    }

    #[test]
    fn request_without_nc_is_allowed() {
        let nonce1 = random_nonce();
        let history =
            crate::transaction_history::TransactionHistory::new(vec![tx_resp_with_challenge(
                &make_challenge(&nonce1, None, None),
            )]);
        let tx = tx_req_with_auth(&make_auth(&nonce1, None, None));
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = StatefulDigestAuthNonceHandling.check_transaction(&tx, &history, &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn invalid_nc_value_reports() {
        let nonce1 = random_nonce();
        let history =
            crate::transaction_history::TransactionHistory::new(vec![tx_resp_with_challenge(
                &make_challenge(&nonce1, None, None),
            )]);
        let tx = tx_req_with_auth(&make_auth(&nonce1, Some("GARBAGE"), None));
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = StatefulDigestAuthNonceHandling.check_transaction(&tx, &history, &cfg);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Invalid nc"));
    }

    #[test]
    fn stale_nonce_mismatch_reports() {
        let nonce1 = random_nonce();
        let nonce2 = random_nonce();
        let history =
            crate::transaction_history::TransactionHistory::new(vec![tx_resp_with_challenge(
                &make_challenge(&nonce1, None, Some("true")),
            )]);
        let tx = tx_req_with_auth(&make_auth(&nonce2, Some("00000001"), None));
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = StatefulDigestAuthNonceHandling.check_transaction(&tx, &history, &cfg);
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("nonce differs"), "got message: {}", msg);
    }

    #[test]
    fn stale_correct_reset_passes() {
        let nonce = random_nonce();
        let history =
            crate::transaction_history::TransactionHistory::new(vec![tx_resp_with_challenge(
                &make_challenge(&nonce, None, Some("true")),
            )]);
        // correct reset
        let tx = tx_req_with_auth(&make_auth(&nonce, Some("00000001"), None));
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = StatefulDigestAuthNonceHandling.check_transaction(&tx, &history, &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn stale_quoted_true_correct_reset_passes() {
        let nonce = random_nonce();
        // Explicitly use quoted-string form for stale: stale="true"
        let header = format!("Digest realm=\"r\", nonce=\"{}\", stale=\"true\"", nonce);
        let txh = crate::test_helpers::make_test_transaction_with_response(
            401,
            &[("www-authenticate", &header)],
        );
        let history = crate::transaction_history::TransactionHistory::new(vec![txh]);
        let tx = tx_req_with_auth(&make_auth(&nonce, Some("00000001"), None));
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = StatefulDigestAuthNonceHandling.check_transaction(&tx, &history, &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn no_nc_produced_no_violation() {
        let nonce = random_nonce();
        let history =
            crate::transaction_history::TransactionHistory::new(vec![tx_resp_with_challenge(
                &make_challenge(&nonce, None, None),
            )]);
        let tx = tx_req_with_auth(&make_auth(&nonce, None, None));
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = StatefulDigestAuthNonceHandling.check_transaction(&tx, &history, &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn digest_after_non_digest_challenge() {
        let nonce = random_nonce();
        // header contains Basic then Digest; processing should skip Basic and
        // pick Digest challenge
        let mixed = format!("Basic realm=\"r\", Digest realm=\"r\", nonce=\"{}\"", nonce);
        let txh = crate::test_helpers::make_test_transaction_with_response(
            401,
            &[("www-authenticate", &mixed)],
        );
        let history = crate::transaction_history::TransactionHistory::new(vec![txh]);
        let tx = tx_req_with_auth(&make_auth(&nonce, Some("00000001"), None));
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = StatefulDigestAuthNonceHandling.check_transaction(&tx, &history, &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn non_utf8_challenge_header_is_ignored() {
        // create response with invalid bytes in WWW-Authenticate
        use hyper::header::HeaderValue;
        let mut headers = crate::test_helpers::make_headers_from_pairs(&[]);
        headers.insert(
            "www-authenticate",
            HeaderValue::from_bytes(&[0xff, 0xff]).unwrap(),
        );
        let mut txh = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        txh.response.as_mut().unwrap().headers = headers;
        let history = crate::transaction_history::TransactionHistory::new(vec![txh]);
        let nonce = random_nonce();
        let tx = tx_req_with_auth(&make_auth(&nonce, Some("00000001"), None));
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = StatefulDigestAuthNonceHandling.check_transaction(&tx, &history, &cfg);
        // no digest challenge seen -> violation for missing challenge
        assert!(v.is_some());
        assert!(v
            .unwrap()
            .message
            .contains("without prior Digest challenge"));
    }

    #[test]
    fn digest_scheme_no_credentials_ignored() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("authorization", "Digest")]);
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = StatefulDigestAuthNonceHandling.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn non_utf8_authorization_header_ignored() {
        use hyper::header::HeaderValue;
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut headers = crate::test_helpers::make_headers_from_pairs(&[]);
        headers.insert(
            "authorization",
            HeaderValue::from_bytes(&[0xff, 0xff]).unwrap(),
        );
        tx.request.headers = headers;
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = StatefulDigestAuthNonceHandling.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn validate_rules_with_valid_config() {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "stateful_digest_auth_nonce_handling");
        let _engine = crate::rules::validate_rules(&cfg).unwrap();
    }
}
