// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// If a previous response advertises `Accept-Patch`, PATCH requests SHOULD use a
/// `Content-Type` matching one of the advertised patch media types (RFC 5789).
pub struct ClientPatchMethodContentTypeMatch;

impl Rule for ClientPatchMethodContentTypeMatch {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "client_patch_method_content_type_match"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        previous: Option<&crate::http_transaction::HttpTransaction>,
        config: &Self::Config,
    ) -> Option<Violation> {
        // Only applies to PATCH requests
        if !tx.request.method.eq_ignore_ascii_case("PATCH") {
            return None;
        }

        // Need a previous response to discover Accept-Patch advertisement
        let prev = previous?;
        let resp = match &prev.response {
            Some(r) => r,
            None => return None,
        };

        // Collect valid media-types advertised in Accept-Patch
        let mut advertised: Vec<String> = Vec::new();
        let mut any_accept_patch_present = false;

        for hv in resp.headers.get_all("accept-patch").iter() {
            any_accept_patch_present = true;
            let s = match hv.to_str() {
                Ok(s) => s,
                Err(_) => {
                    // Non-UTF8 Accept-Patch; let server rule report this. Treat as missing here.
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Previous response contains non-UTF8 Accept-Patch header".into(),
                    });
                }
            };

            // Detect empty or whitespace-only tokens (trailing commas etc.)
            for raw in s.split(',') {
                if raw.trim().is_empty() {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Accept-Patch contains empty media-type token (e.g., trailing or consecutive commas)".into(),
                    });
                }
            }

            for part in crate::helpers::headers::parse_list_header(s) {
                match crate::helpers::headers::parse_media_type(part) {
                    Ok(parsed) => {
                        let t = parsed.type_.to_ascii_lowercase();
                        let s = parsed.subtype.to_ascii_lowercase();
                        advertised.push(format!("{}/{}", t, s));
                    }
                    Err(_) => {
                        // Let the server-side Accept-Patch rule handle malformed entries. Ignore here.
                        continue;
                    }
                }
            }
        }

        // If no Accept-Patch present in previous response, nothing to check
        if !any_accept_patch_present {
            return None;
        }

        // If Accept-Patch present but no valid entries parsed, treat as server misconfiguration; report violation
        if advertised.is_empty() {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Previous Accept-Patch header did not contain any valid media-types"
                    .into(),
            });
        }

        // Get request Content-Type
        let ct_val = crate::helpers::headers::get_header_str(&tx.request.headers, "content-type");
        if ct_val.is_none() {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "PATCH request missing Content-Type while server advertised Accept-Patch"
                    .into(),
            });
        }
        let ct_val = ct_val.unwrap();

        let parsed = match crate::helpers::headers::parse_media_type(ct_val) {
            Ok(p) => p,
            Err(_) => {
                // Let Content-Type well-formedness rules report this; avoid double reporting
                return None;
            }
        };

        let t = parsed.type_.to_ascii_lowercase();
        let s = parsed.subtype.to_ascii_lowercase();
        let full = format!("{}/{}", t, s);

        // Check if full type matches any advertised entry directly
        if advertised.iter().any(|a| a == &full) {
            return None;
        }

        // Also support type/* advertised entries and +suffix forms (e.g., +json)
        // Check each advertised entry for patterns: type/* or +suffix (though Accept-Patch usually lists full types).
        for pat in advertised.iter() {
            if pat == "*/*" || pat == &full {
                return None;
            }
            if pat.ends_with("/*") {
                if let Some(idx) = pat.find('/') {
                    let ptype = &pat[..idx];
                    if ptype == t {
                        return None;
                    }
                }
            }
            if let Some(suff) = pat.strip_prefix('+') {
                if s.ends_with(suff) {
                    return None;
                }
            }
        }

        Some(Violation {
            rule: self.id().into(),
            severity: config.severity,
            message: format!("PATCH request Content-Type '{}' does not match any media-type advertised in previous Accept-Patch", full),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn make_prev_with_accept_patch(h: Option<&str>) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        if let Some(hv) = h {
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[("accept-patch", hv)]);
        }
        tx
    }

    #[rstest]
    #[case(
        Some("application/example-patch+json"),
        Some("application/example-patch+json"),
        false
    )]
    #[case(
        Some("application/example-patch+json"),
        Some("application/merge-patch+json"),
        true
    )]
    #[case(
        Some("application/example-patch+json, application/merge-patch+json"),
        Some("application/merge-patch+json; charset=utf-8"),
        false
    )]
    #[case(Some("application/example-patch+json"), None, true)]
    #[case(None, Some("application/example-patch+json"), false)]
    // Edge cases: malformed Accept-Patch, trailing commas, mixture of bad+good, wildcard
    #[case(Some("badmedia"), Some("application/example-patch+json"), true)]
    #[case(Some("application/json,"), Some("application/json"), true)]
    #[case(
        Some("badmedia, application/merge-patch+json"),
        Some("application/merge-patch+json"),
        false
    )]
    #[case(Some("application/*"), Some("application/example+json"), false)]
    fn check_cases(
        #[case] accept_patch: Option<&str>,
        #[case] content_type: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = ClientPatchMethodContentTypeMatch;
        let cfg = crate::test_helpers::make_test_rule_config();

        // Build current PATCH request
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "PATCH".into();
        if let Some(ct) = content_type {
            tx.request.headers =
                crate::test_helpers::make_headers_from_pairs(&[("content-type", ct)]);
        }

        let mut prev = None;
        if let Some(ap) = accept_patch {
            let mut p = make_prev_with_accept_patch(Some(ap));
            // ensure resource matches
            p.request.uri = tx.request.uri.clone();
            prev = Some(p);
        }

        let prev_ref = prev.as_ref();
        let v = rule.check_transaction(&tx, prev_ref, &cfg);
        if expect_violation {
            assert!(v.is_some());
        } else {
            assert!(v.is_none());
        }
        Ok(())
    }

    #[test]
    fn multiple_accept_patch_fields_are_merged() -> anyhow::Result<()> {
        let rule = ClientPatchMethodContentTypeMatch;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "PATCH".into();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-type",
            "application/merge-patch+json",
        )]);

        use hyper::header::HeaderValue;
        use hyper::HeaderMap;
        let mut hm = HeaderMap::new();
        hm.append(
            "accept-patch",
            HeaderValue::from_static("application/example-patch+json"),
        );
        hm.append(
            "accept-patch",
            HeaderValue::from_static("application/merge-patch+json"),
        );

        let mut prev = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        prev.request.uri = tx.request.uri.clone();
        prev.response.as_mut().unwrap().headers = hm;

        let v = rule.check_transaction(&tx, Some(&prev), &cfg);
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn malformed_accept_patch_reports_violation() -> anyhow::Result<()> {
        let rule = ClientPatchMethodContentTypeMatch;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut prev = make_prev_with_accept_patch(Some("badmedia"));
        prev.request.uri = crate::test_helpers::make_test_transaction()
            .request
            .uri
            .clone();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "PATCH".into();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-type",
            "application/example-patch+json",
        )]);

        let v = rule.check_transaction(&tx, Some(&prev), &cfg);
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("did not contain any valid media-types"));
        Ok(())
    }

    #[test]
    fn trailing_comma_in_accept_patch_is_violation() -> anyhow::Result<()> {
        let rule = ClientPatchMethodContentTypeMatch;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut prev = make_prev_with_accept_patch(Some("application/json,"));
        prev.request.uri = crate::test_helpers::make_test_transaction()
            .request
            .uri
            .clone();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "PATCH".into();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-type", "application/json")]);

        let v = rule.check_transaction(&tx, Some(&prev), &cfg);
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("empty media-type token"));
        Ok(())
    }

    #[test]
    fn bad_and_good_accept_patch_accepts_if_one_valid() -> anyhow::Result<()> {
        let rule = ClientPatchMethodContentTypeMatch;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut prev = make_prev_with_accept_patch(Some("badmedia, application/merge-patch+json"));
        prev.request.uri = crate::test_helpers::make_test_transaction()
            .request
            .uri
            .clone();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "PATCH".into();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-type",
            "application/merge-patch+json",
        )]);

        let v = rule.check_transaction(&tx, Some(&prev), &cfg);
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn wildcard_accept_patch_matches_type_star() -> anyhow::Result<()> {
        let rule = ClientPatchMethodContentTypeMatch;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut prev = make_prev_with_accept_patch(Some("application/*"));
        prev.request.uri = crate::test_helpers::make_test_transaction()
            .request
            .uri
            .clone();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "PATCH".into();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-type",
            "application/example+json",
        )]);

        let v = rule.check_transaction(&tx, Some(&prev), &cfg);
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn accept_patch_with_params_is_accepted() -> anyhow::Result<()> {
        let rule = ClientPatchMethodContentTypeMatch;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut prev = make_prev_with_accept_patch(Some("application/merge-patch+json; version=1"));
        prev.request.uri = crate::test_helpers::make_test_transaction()
            .request
            .uri
            .clone();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "PATCH".into();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-type",
            "application/merge-patch+json",
        )]);

        let v = rule.check_transaction(&tx, Some(&prev), &cfg);
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn star_star_accept_patch_matches_any() -> anyhow::Result<()> {
        let rule = ClientPatchMethodContentTypeMatch;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut prev = make_prev_with_accept_patch(Some("*/*"));
        prev.request.uri = crate::test_helpers::make_test_transaction()
            .request
            .uri
            .clone();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "PATCH".into();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-type",
            "application/merge-patch+json",
        )]);

        let v = rule.check_transaction(&tx, Some(&prev), &cfg);
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn whitespace_only_accept_patch_reports_violation() -> anyhow::Result<()> {
        let rule = ClientPatchMethodContentTypeMatch;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut prev = make_prev_with_accept_patch(Some("   "));
        prev.request.uri = crate::test_helpers::make_test_transaction()
            .request
            .uri
            .clone();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "PATCH".into();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-type",
            "application/merge-patch+json",
        )]);

        let v = rule.check_transaction(&tx, Some(&prev), &cfg);
        // whitespace-only header triggers empty token detection and thus a violation
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn request_content_type_non_utf8_is_treated_as_missing() -> anyhow::Result<()> {
        let rule = ClientPatchMethodContentTypeMatch;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut prev = make_prev_with_accept_patch(Some("application/merge-patch+json"));
        prev.request.uri = crate::test_helpers::make_test_transaction()
            .request
            .uri
            .clone();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "PATCH".into();
        // create non-utf8 content-type value -> should be treated as missing and cause violation
        let mut hm = tx.request.headers.clone();
        use hyper::header::HeaderValue;
        hm.insert("content-type", HeaderValue::from_bytes(&[0xff]).unwrap());
        tx.request.headers = hm;

        let v = rule.check_transaction(&tx, Some(&prev), &cfg);
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn malformed_request_content_type_is_ignored_and_no_violation() -> anyhow::Result<()> {
        let rule = ClientPatchMethodContentTypeMatch;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut prev = make_prev_with_accept_patch(Some("application/merge-patch+json"));
        prev.request.uri = crate::test_helpers::make_test_transaction()
            .request
            .uri
            .clone();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "PATCH".into();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-type", "bad")]);

        let v = rule.check_transaction(&tx, Some(&prev), &cfg);
        // malformed Content-Type is delegated to other rules; this rule should not emit a violation
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn non_utf8_accept_patch_is_violation() -> anyhow::Result<()> {
        let rule = ClientPatchMethodContentTypeMatch;
        let cfg = crate::test_helpers::make_test_rule_config();
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;

        let mut hm = HeaderMap::new();
        let bad = HeaderValue::from_bytes(&[0xff]).unwrap();
        hm.insert("accept-patch", bad);

        let mut prev = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        prev.request.uri = crate::test_helpers::make_test_transaction()
            .request
            .uri
            .clone();
        prev.response.as_mut().unwrap().headers = hm;

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "PATCH".into();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-type",
            "application/example-patch+json",
        )]);

        let v = rule.check_transaction(&tx, Some(&prev), &cfg);
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "client_patch_method_content_type_match");
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn non_patch_requests_are_ignored() -> anyhow::Result<()> {
        let rule = ClientPatchMethodContentTypeMatch;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "GET".into();
        // even if previous response advertises Accept-Patch, non-PATCH should be ignored
        let mut prev = make_prev_with_accept_patch(Some("application/merge-patch+json"));
        prev.request.uri = tx.request.uri.clone();

        let v = rule.check_transaction(&tx, Some(&prev), &cfg);
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn previous_without_response_is_ignored() -> anyhow::Result<()> {
        let rule = ClientPatchMethodContentTypeMatch;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "PATCH".into();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-type",
            "application/merge-patch+json",
        )]);

        // previous transaction exists but has no response -> rule should ignore
        let mut prev = crate::test_helpers::make_test_transaction();
        prev.request.uri = tx.request.uri.clone();

        let v = rule.check_transaction(&tx, Some(&prev), &cfg);
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn scope_is_client() {
        let rule = ClientPatchMethodContentTypeMatch;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Client);
    }
}
