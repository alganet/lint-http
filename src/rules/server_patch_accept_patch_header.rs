// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// Servers SHOULD include `Accept-Patch` in responses to `PATCH` to advertise supported patch media types.
/// This rule flags `PATCH` requests whose responses do not include a valid `Accept-Patch` header.
pub struct ServerPatchAcceptPatchHeader;

impl Rule for ServerPatchAcceptPatchHeader {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "server_patch_accept_patch_header"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _previous: Option<&crate::http_transaction::HttpTransaction>,
        config: &Self::Config,
    ) -> Option<Violation> {
        // Only applies when the request method is PATCH and a response exists
        if !tx.request.method.eq_ignore_ascii_case("PATCH") {
            return None;
        }

        let resp = match &tx.response {
            Some(r) => r,
            None => return None,
        };

        // If Accept-Patch header absent -> warn
        let mut found = false;
        for hv in resp.headers.get_all("accept-patch").iter() {
            let s = match hv.to_str() {
                Ok(s) => s,
                Err(_) => {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Accept-Patch header contains non-UTF8 value".into(),
                    })
                }
            };

            // Header must contain at least one valid media-type
            let mut any_valid = false;
            // Detect empty/empty-after-trim media-type tokens such as trailing commas or consecutive commas
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
                    Ok(_) => any_valid = true,
                    Err(e) => {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!(
                                "Accept-Patch contains invalid media-type '{}': {}",
                                part, e
                            ),
                        });
                    }
                }
            }

            if any_valid {
                found = true;
                break;
            }
        }

        if !found {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "PATCH response is missing a valid Accept-Patch header declaring supported patch media types".into(),
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
    // (method, header_opt, expect_violation)
    #[case("PATCH", None, true)]
    #[case("PATCH", Some("application/example-patch+json"), false)]
    #[case(
        "PATCH",
        Some("application/example-patch+json, application/merge-patch+json"),
        false
    )]
    #[case("PATCH", Some("badmedia"), true)]
    #[case("PATCH", Some(""), true)]
    // Edge-cases: trailing, leading, consecutive commas, whitespace-only, single comma
    #[case("PATCH", Some("application/json,"), true)]
    #[case("PATCH", Some(",application/json"), true)]
    #[case("PATCH", Some("application/json,,text/plain"), true)]
    #[case("PATCH", Some("   "), true)]
    #[case("PATCH", Some(","), true)]
    #[case("GET", None, false)]
    fn check_cases(
        #[case] method: &str,
        #[case] header: Option<&str>,
        #[case] expect_violation: bool,
    ) {
        let rule = ServerPatchAcceptPatchHeader;

        let tx = match header {
            Some(h) => crate::test_helpers::make_test_transaction_with_response(
                200,
                &[("accept-patch", h), ("x-foo", "bar")],
            ),
            None => {
                let mut tx = crate::test_helpers::make_test_transaction();
                tx.request.method = method.into();
                tx.response = Some(crate::http_transaction::ResponseInfo {
                    status: 200,
                    version: "HTTP/1.1".into(),
                    headers: crate::test_helpers::make_headers_from_pairs(&[]),
                });
                tx
            }
        };

        // Ensure request method is set for cases where header was provided via helper
        let mut tx = tx;
        tx.request.method = method.into();

        let config = crate::test_helpers::make_test_rule_config();

        let v = rule.check_transaction(&tx, None, &config);
        if expect_violation {
            assert!(
                v.is_some(),
                "expected violation for method={} header={:?}",
                method,
                header
            );
        } else {
            assert!(
                v.is_none(),
                "unexpected violation for method={} header={:?}: {:?}",
                method,
                header,
                v
            );
        }
    }

    #[test]
    fn multiple_header_fields_merged() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;

        let rule = ServerPatchAcceptPatchHeader;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "PATCH".into();

        let mut hm = HeaderMap::new();
        hm.append(
            "accept-patch",
            HeaderValue::from_static("application/example-patch+json"),
        );
        hm.append(
            "accept-patch",
            HeaderValue::from_static("application/merge-patch+json"),
        );
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,
        });

        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn non_utf8_header_value_is_violation() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;

        let rule = ServerPatchAcceptPatchHeader;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "PATCH".into();

        let mut hm = HeaderMap::new();
        let bad = HeaderValue::from_bytes(&[0xff]).expect("should construct non-utf8 header");
        hm.insert("accept-patch", bad);
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,
        });

        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "server_patch_accept_patch_header");
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
