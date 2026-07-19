// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ClientPreferHeaderAndPreferenceApplied;

impl Rule for ClientPreferHeaderAndPreferenceApplied {
    fn id(&self) -> &'static str {
        "client_prefer_header_and_preference_applied"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
        // Only meaningful when request includes Prefer and response is present
        let saw_prefer = tx
            .request
            .headers
            .get_all("prefer")
            .iter()
            // If the Prefer header contains at least one non-empty UTF-8 member, consider it present
            .any(|h| h.to_str().map(|s| !s.trim().is_empty()).unwrap_or(false));

        // cite(RFC 7240 § 3): "The Preference-Applied response header MAY be included within a response message as an indication as to which Prefer tokens were honored by the server"
        if !saw_prefer {
            return None;
        }

        let resp = tx.response.as_ref()?;

        // If a Preference-Applied header exists (even if non-UTF8), treat as present
        if resp
            .headers
            .get_all("preference-applied")
            .iter()
            .next()
            .is_some()
        {
            return None;
        }

        // If Prefer present but no Preference-Applied in response, warn
        Some(Violation {
            rule: self.id().into(),
            severity: config.severity,
            message: "Request included Prefer header but response did not include Preference-Applied to indicate which preferences were applied".into(),
        })
    }

    fn title(&self) -> Option<&'static str> {
        Some("Client Prefer Header and Preference-Applied Presence")
    }

    fn description(&self) -> &'static str {
        "When a client sends a `Prefer` request header, servers MAY include a `Preference-Applied` response header to indicate which preferences were applied. This rule warns when a request included `Prefer` but the response did not include `Preference-Applied`, which makes it harder for clients to know which preferences the server applied. This is a best-practice suggestion; servers are not strictly required to include `Preference-Applied`."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[crate::rules::SpecRef {
            spec: "RFC 7240",
            section: Some("3"),
            url: "https://www.rfc-editor.org/rfc/rfc7240.html#section-3",
            note: "`Preference-Applied` header and ABNF",
        }]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "GET / HTTP/1.1\nPrefer: return=representation\n\nHTTP/1.1 200 OK\nPreference-Applied: return=representation",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(response omits Preference-Applied)"),
                snippet: "GET / HTTP/1.1\nPrefer: return=representation\n\nHTTP/1.1 200 OK",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ClientPreferHeaderAndPreferenceApplied;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("Prefer: return=representation", None, true)]
    #[case(
        "Prefer: return=representation",
        Some("Preference-Applied: return=representation"),
        false
    )]
    #[case("", None, false)]
    #[case(
        "Prefer: handling=lenient",
        Some("Preference-Applied: handling=lenient"),
        false
    )]
    fn check_cases(
        #[case] prefer_hdr: &str,
        #[case] applied_hdr: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = ClientPreferHeaderAndPreferenceApplied;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);

        if !prefer_hdr.is_empty() {
            let parts: Vec<&str> = prefer_hdr.splitn(2, ':').collect();
            tx.request.headers =
                crate::test_helpers::make_headers_from_pairs(&[(parts[0].trim(), parts[1].trim())]);
        }

        if let Some(a) = applied_hdr {
            let parts2: Vec<&str> = a.splitn(2, ':').collect();
            tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(
                &[(parts2[0].trim(), parts2[1].trim())],
            );
        }

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
    fn preference_applied_non_utf8_counts_as_present() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;

        let rule = ClientPreferHeaderAndPreferenceApplied;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("Prefer", "respond-async")]);

        // Create non-utf8 Preference-Applied value
        let mut hm = hyper::HeaderMap::new();
        hm.insert(
            "preference-applied",
            HeaderValue::from_bytes(&[0xff]).unwrap(),
        );
        tx.response.as_mut().unwrap().headers = hm;

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        // treat non-utf8 header as present -> no violation from this rule
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn rule_id_and_scope() {
        let rule = ClientPreferHeaderAndPreferenceApplied;
        assert_eq!(rule.id(), "client_prefer_header_and_preference_applied");
        assert_eq!(rule.scope(), crate::rules::RuleScope::Client);
    }

    #[test]
    fn prefer_non_utf8_request_is_ignored() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;

        let rule = ClientPreferHeaderAndPreferenceApplied;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        // non-utf8 Prefer header should be ignored and not cause a missing Preference-Applied warning
        let mut hm = hyper::HeaderMap::new();
        hm.insert("prefer", HeaderValue::from_bytes(&[0xff]).unwrap());
        tx.request.headers = hm;

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn multiple_prefer_headers_some_empty_some_valid() -> anyhow::Result<()> {
        let rule = ClientPreferHeaderAndPreferenceApplied;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("Prefer", ""),
            ("Prefer", "respond-async"),
        ]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn empty_prefer_header_only_is_ignored() -> anyhow::Result<()> {
        let rule = ClientPreferHeaderAndPreferenceApplied;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[("Prefer", "")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "client_prefer_header_and_preference_applied");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
