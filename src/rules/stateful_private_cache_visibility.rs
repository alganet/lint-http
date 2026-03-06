// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// Ensure responses marked `Cache-Control: private` are not reused by a
/// different client, which would indicate a shared cache has stored the
/// representation in violation of RFC 9111 §5.2.
///
/// The rule watches conditional requests and looks back through the history
/// for the same resource across all clients.  If the current request carries a
/// validator (ETag or Last-Modified) that was previously seen in the response
/// to a *different* client and that response included a `private` directive,
/// we report a violation.  Such a conditional request is strong evidence that
/// a shared cache has handed off a private response to another client.
pub struct StatefulPrivateCacheVisibility;

impl Rule for StatefulPrivateCacheVisibility {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "stateful_private_cache_visibility"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        // need to observe both the current request and past responses
        crate::rules::RuleScope::Both
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        history: &crate::transaction_history::TransactionHistory,
        config: &Self::Config,
    ) -> Option<Violation> {
        // only interested in conditional requests; nothing to do otherwise
        let has_if_none_match = tx.request.headers.contains_key("if-none-match");
        let has_if_modified_since = tx.request.headers.contains_key("if-modified-since");
        if !has_if_none_match && !has_if_modified_since {
            return None;
        }

        // helper to detect private directive in a response
        fn header_has_private(headers: &hyper::HeaderMap) -> bool {
            for hv in headers.get_all("cache-control").iter() {
                if let Ok(s) = hv.to_str() {
                    for directive in s.split(|c| [',', ';'].contains(&c)) {
                        if directive.trim().eq_ignore_ascii_case("private") {
                            return true;
                        }
                    }
                }
            }
            false
        }

        // check If-None-Match members
        for hv in tx.request.headers.get_all("if-none-match").iter() {
            if let Ok(s) = hv.to_str() {
                for member in crate::helpers::headers::parse_list_header(s) {
                    let member = member.trim();
                    let normalized = crate::helpers::headers::normalize_etag(member);

                    for past in history.iter() {
                        if past.client == tx.client {
                            continue;
                        }
                        if let Some(resp) = &past.response {
                            if header_has_private(&resp.headers) {
                                if let Some(hv2) = resp.headers.get("etag") {
                                    if let Ok(val) = hv2.to_str() {
                                        let val_norm = crate::helpers::headers::normalize_etag(val);
                                        if val_norm == normalized {
                                            return Some(Violation {
                                                rule: self.id().into(),
                                                severity: config.severity,
                                                message: format!(
                                                    "Validator '{}' from a private response seen by a different client",
                                                    member
                                                ),
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // check If-Modified-Since headers
        for hv in tx.request.headers.get_all("if-modified-since").iter() {
            if let Ok(s) = hv.to_str() {
                let candidate = s.trim();
                if let Ok(candidate_dt) = crate::http_date::parse_http_date_to_datetime(candidate) {
                    for past in history.iter() {
                        if past.client == tx.client {
                            continue;
                        }
                        if let Some(resp) = &past.response {
                            if header_has_private(&resp.headers) {
                                if let Some(hv2) = resp.headers.get("last-modified") {
                                    if let Ok(val) = hv2.to_str() {
                                        if let Ok(val_dt) =
                                            crate::http_date::parse_http_date_to_datetime(val)
                                        {
                                            if val_dt == candidate_dt {
                                                return Some(Violation {
                                                    rule: self.id().into(),
                                                    severity: config.severity,
                                                    message: format!(
                                                        "Validator '{}' from a private response seen by a different client",
                                                        candidate
                                                    ),
                                                });
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn make_prev(
        client: crate::state::ClientIdentifier,
        cc: Option<&str>,
        etag: Option<&str>,
        last_mod: Option<&str>,
        ts: chrono::DateTime<chrono::Utc>,
    ) -> crate::http_transaction::HttpTransaction {
        let mut prev = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        prev.request.method = "GET".to_string();
        prev.request.uri = "/resource".to_string();
        prev.client = client;
        prev.timestamp = ts;
        if let Some(ccv) = cc {
            prev.response
                .as_mut()
                .unwrap()
                .headers
                .append("cache-control", ccv.parse().unwrap());
        }
        if let Some(et) = etag {
            prev.response
                .as_mut()
                .unwrap()
                .headers
                .append("etag", et.parse().unwrap());
        }
        if let Some(lm) = last_mod {
            prev.response
                .as_mut()
                .unwrap()
                .headers
                .append("last-modified", lm.parse().unwrap());
        }
        prev
    }

    #[test]
    fn no_violation_without_history() {
        let rule = StatefulPrivateCacheVisibility;
        let cfg = crate::test_helpers::make_test_rule_config();
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request
            .headers
            .append("if-none-match", "\"a\"".parse().unwrap());
        let history = crate::transaction_history::TransactionHistory::empty();
        assert!(rule.check_transaction(&tx, &history, &cfg).is_none());
    }

    #[test]
    fn same_client_private_not_flagged() {
        let rule = StatefulPrivateCacheVisibility;
        let cfg = crate::test_helpers::make_test_rule_config();
        let ts = Utc::now();
        let client = crate::test_helpers::make_test_client();

        let prev = make_prev(client.clone(), Some("private"), Some("\"a\""), None, ts);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = client.clone();
        tx.request
            .headers
            .append("if-none-match", "\"a\"".parse().unwrap());
        let history = crate::transaction_history::TransactionHistory::new(vec![prev]);
        assert!(rule.check_transaction(&tx, &history, &cfg).is_none());
    }

    #[test]
    fn private_from_other_client_flagged_etag() {
        let rule = StatefulPrivateCacheVisibility;
        let cfg = crate::test_helpers::make_test_rule_config();
        let ts = Utc::now();
        let client1 = crate::test_helpers::make_test_client();
        let mut client2 = client1.clone();
        client2.user_agent = "other".to_string();

        let prev = make_prev(client2.clone(), Some("private"), Some("\"a\""), None, ts);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = client1.clone();
        tx.request
            .headers
            .append("if-none-match", "\"a\"".parse().unwrap());
        let history = crate::transaction_history::TransactionHistory::new(vec![prev]);
        let v = rule.check_transaction(&tx, &history, &cfg);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Validator '"));
    }

    #[test]
    fn private_from_other_client_flagged_last_modified() {
        let rule = StatefulPrivateCacheVisibility;
        let cfg = crate::test_helpers::make_test_rule_config();
        let ts = Utc::now();
        let client1 = crate::test_helpers::make_test_client();
        let mut client2 = client1.clone();
        client2.user_agent = "other".to_string();

        let lm = "Wed, 21 Oct 2015 07:28:00 GMT";
        let prev = make_prev(client2.clone(), Some("private"), None, Some(lm), ts);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = client1.clone();
        tx.request
            .headers
            .append("if-modified-since", lm.parse().unwrap());
        let history = crate::transaction_history::TransactionHistory::new(vec![prev]);
        let v = rule.check_transaction(&tx, &history, &cfg);
        assert!(v.is_some());
    }

    #[test]
    fn non_private_from_other_client_not_flagged() {
        let rule = StatefulPrivateCacheVisibility;
        let cfg = crate::test_helpers::make_test_rule_config();
        let ts = Utc::now();
        let client1 = crate::test_helpers::make_test_client();
        let mut client2 = client1.clone();
        client2.user_agent = "other".to_string();

        let prev = make_prev(client2.clone(), None, Some("\"a\""), None, ts);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = client1.clone();
        tx.request
            .headers
            .append("if-none-match", "\"a\"".parse().unwrap());
        let history = crate::transaction_history::TransactionHistory::new(vec![prev]);
        assert!(rule.check_transaction(&tx, &history, &cfg).is_none());
    }
}
