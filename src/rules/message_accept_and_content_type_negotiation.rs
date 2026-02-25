// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageAcceptAndContentTypeNegotiation;

impl Rule for MessageAcceptAndContentTypeNegotiation {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_accept_and_content_type_negotiation"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        config: &Self::Config,
    ) -> Option<Violation> {
        // Only check when request has Accept and response has Content-Type
        let accept = crate::helpers::headers::get_header_str(&tx.request.headers, "accept");
        let resp = match &tx.response {
            Some(r) => r,
            None => return None,
        };
        let content_type = crate::helpers::headers::get_header_str(&resp.headers, "content-type")?;

        // If server already returned 406 Not Acceptable, don't flag
        if resp.status == 406 {
            return None;
        }

        let accept = accept?;

        // Parse response Content-Type media-type
        let parsed_ct = match crate::helpers::headers::parse_media_type(content_type) {
            Ok(p) => p,
            Err(_) => return None, // content-type parsing is handled by other rules
        };

        // Iterate Accept members and see if any non-zero-q member matches the response Content-Type
        let mut matched = false;
        for member in crate::helpers::headers::parse_list_header(accept) {
            let mut parts = member.split(';').map(|s| s.trim());
            let media = match parts.next() {
                Some(m) => m,
                None => continue,
            };
            if media == "*" {
                // invalid per syntax rule; treat as non-matching
                continue;
            }

            // find q param if present
            let mut qval: Option<&str> = None;
            for p in parts {
                let mut kv = p.splitn(2, '=');
                let k = kv.next().unwrap().trim();
                if k.eq_ignore_ascii_case("q") {
                    if let Some(v) = kv.next() {
                        qval = Some(v.trim());
                    }
                }
            }

            // If q is present and equals 0 (or numerically zero), this member is unacceptable
            if let Some(q) = qval {
                // Use simple numeric parse; valid_qvalue should have been checked elsewhere
                if let Ok(n) = q.parse::<f32>() {
                    if n <= 0.0 {
                        continue;
                    }
                }
            }

            // wildcard '*/*'
            if media == "*/*" {
                matched = true;
                break;
            }

            // try parsing media-range as media-type (type/* or type/subtype)
            match crate::helpers::headers::parse_media_type(media) {
                Ok(mr) => {
                    if mr.type_.eq_ignore_ascii_case(parsed_ct.type_)
                        && (mr.subtype == "*" || mr.subtype.eq_ignore_ascii_case(parsed_ct.subtype))
                    {
                        matched = true;
                        break;
                    }
                }
                Err(_) => {
                    // invalid media-range syntax -> ignore conservatively
                    continue;
                }
            }
        }

        if !matched {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!(
                    "Response Content-Type '{}' does not match request Accept header '{}', consider returning 406 Not Acceptable",
                    content_type, accept
                ),
            });
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(Some("application/json"), Some("application/json"), 200, false)]
    #[case(Some("application/json"), Some("text/html"), 200, true)]
    #[case(Some("text/*"), Some("text/html; charset=utf-8"), 200, false)]
    #[case(Some("*/*"), Some("image/png"), 200, false)]
    #[case(Some("application/json;q=0"), Some("application/json"), 200, true)]
    #[case(Some("application/json;q=0"), Some("application/json"), 406, false)]
    #[case(None, Some("application/json"), 200, false)]
    #[case(Some("application/json, text/html;q=0"), Some("text/html"), 200, true)]
    fn negotiation_cases(
        #[case] accept: Option<&str>,
        #[case] content_type: Option<&str>,
        #[case] status: u16,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageAcceptAndContentTypeNegotiation;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(status, &[]);
        if let Some(a) = accept {
            tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[("accept", a)]);
        }
        if let Some(ct) = content_type {
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[("content-type", ct)]);
        }

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(
                v.is_some(),
                "expected violation for accept={:?} ct={:?}",
                accept,
                content_type
            );
        } else {
            assert!(v.is_none());
        }
        Ok(())
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_accept_and_content_type_negotiation",
        ]);
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn message_and_id() {
        let rule = MessageAcceptAndContentTypeNegotiation;
        assert_eq!(rule.id(), "message_accept_and_content_type_negotiation");
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }

    #[test]
    fn invalid_response_content_type_parsing_is_ignored() {
        // If the response Content-Type cannot be parsed, the rule conservatively does nothing
        let rule = MessageAcceptAndContentTypeNegotiation;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("accept", "text/plain")]);
        // invalid content-type (no slash) -> parse_media_type should fail
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-type", "text")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn invalid_accept_member_is_ignored_but_may_cause_violation() {
        // An invalid media-range in Accept is ignored; if it is the only member, the response may be unacceptable
        let rule = MessageAcceptAndContentTypeNegotiation;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("accept", "not-a-media-range")]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-type", "text/plain")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn star_in_accept_is_treated_as_invalid_member() {
        // A literal '*' is invalid per media-range syntax and is ignored; without other members this leads to violation
        let rule = MessageAcceptAndContentTypeNegotiation;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[("accept", "*")]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-type", "text/plain")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn invalid_q_value_is_ignored_and_does_not_make_member_unacceptable() {
        // If q value is malformed, we conservatively treat the member as acceptable unless q parses to 0
        let rule = MessageAcceptAndContentTypeNegotiation;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("accept", "text/plain;q=notnum")]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-type", "text/plain")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn empty_q_value_is_ignored_and_member_is_accepted() {
        // q= with empty RHS should not make member unacceptable
        let rule = MessageAcceptAndContentTypeNegotiation;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("accept", "application/json;q=")]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-type", "application/json")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn no_response_is_ignored() {
        let rule = MessageAcceptAndContentTypeNegotiation;
        let cfg = crate::test_helpers::make_test_rule_config();

        let tx = crate::test_helpers::make_test_transaction();
        // tx.response is None
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }
}
