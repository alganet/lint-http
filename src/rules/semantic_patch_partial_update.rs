// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// PATCH applies partial modifications; the request body is a "patch document" whose
/// media type identifies the format.  A PATCH request containing content MUST include a
/// `Content-Type` header and the media type should indicate a patch format (e.g. the
/// subtype contains "patch" or begins with "patch").  Otherwise, the request is
/// unlikely to be interpretable by a server.  (RFC 5789 §2)
pub struct SemanticPatchPartialUpdate;

impl Rule for SemanticPatchPartialUpdate {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "semantic_patch_partial_update"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _previous: Option<&crate::http_transaction::HttpTransaction>,
        config: &Self::Config,
    ) -> Option<Violation> {
        if !tx.request.method.eq_ignore_ascii_case("PATCH") {
            return None;
        }

        // Determine whether the request has a body.  In addition to the
        // traditional framing headers we also look at the captured body length
        // or actual bytes, which may be populated for HTTP/2 where no content-
        // length or transfer-encoding exists.
        let mut has_body = false;
        if tx.request.headers.contains_key("transfer-encoding") {
            has_body = true;
        } else if let Some(cl_raw) =
            crate::helpers::headers::get_header_str(&tx.request.headers, "content-length")
        {
            let cl = cl_raw.trim();
            if !cl.is_empty() && cl.chars().all(|c| c.is_ascii_digit()) {
                if let Ok(n) = cl.parse::<u128>() {
                    has_body = n > 0;
                }
            }
        }
        if !has_body {
            if let Some(n) = tx.request.body_length {
                has_body = n > 0;
            }
        }
        if !has_body {
            if let Some(ref bytes) = tx.request_body {
                has_body = !bytes.is_empty();
            }
        }

        if !has_body {
            // If there's no body, nothing to validate for patch semantics.
            return None;
        }

        // Check for the presence of a Content-Type header first.  `get_header_str`
        // returns `None` when the header is missing *or* when the value contains
        // non-visible ASCII (including invalid UTF-8).  We need to treat those
        // cases differently: a missing header should yield a violation, whereas an
        // unparseable value is handled by other rules and should not trigger us.
        let has_ct = tx.request.headers.contains_key("content-type");
        if !has_ct {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "PATCH request with message body is missing Content-Type header".into(),
            });
        }

        let ct_val_opt =
            crate::helpers::headers::get_header_str(&tx.request.headers, "content-type");

        // If the header was present but `get_header_str` returned `None`, it means
        // the bytes were not visible ASCII / not valid UTF-8.  Other rules will
        // report the malformed header; we intentionally ignore it here.
        let ct_val = match ct_val_opt {
            Some(v) => v,
            None => {
                return None;
            }
        };

        let parsed = match crate::helpers::headers::parse_media_type(ct_val) {
            Ok(p) => p,
            Err(_) => {
                // invalid media type is reported by other rules; ignore here
                return None;
            }
        };

        let t = parsed.type_.to_ascii_lowercase();
        let s = parsed.subtype.to_ascii_lowercase();

        let is_patch = s.contains("patch") || t.contains("patch");
        if !is_patch {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!(
                    "PATCH request Content-Type '{}' does not indicate a patch document media type",
                    ct_val
                ),
            });
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use rstest::rstest;

    fn make_tx_with_req(headers: Vec<(&str, &str)>) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "PATCH".to_string();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&headers);
        tx
    }

    #[rstest]
    #[case(vec![("content-type", "application/json-patch+json"), ("content-length", "5")], false)]
    #[case(vec![("content-type", "application/merge-patch+json"), ("content-length", "1")], false)]
    #[case(vec![("content-type", "application/patch+xml"), ("content-length", "2")], false)]
    #[case(vec![("content-type", "patch/foo"), ("content-length", "1")], false)] // patch token in type
    #[case(vec![("content-type", "text/plain"), ("content-length", "3")], true)]
    #[case(vec![("content-type", "*/*"), ("content-length", "2")], true)] // wildcard not a patch
    #[case(vec![("content-length", "10")], true)]
    #[case(vec![], false)] // no body
    #[case(vec![("transfer-encoding", "chunked")], true)]
    #[case(vec![("content-type", "   text/plain  "), ("content-length", "1")], true)]
    #[case(vec![("content-type", "bad/type"), ("content-length", "1")], true)] // media type not indicating patch
    fn patch_content_type_cases(
        #[case] headers: Vec<(&str, &str)>,
        #[case] expect_violation: bool,
    ) {
        let rule = SemanticPatchPartialUpdate;
        let tx = make_tx_with_req(headers);
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        if expect_violation {
            assert!(
                v.is_some(),
                "expected violation for headers {:?}",
                tx.request.headers
            );
        } else {
            assert!(v.is_none(), "unexpected violation: {:?}", v);
        }
    }

    #[test]
    fn non_utf8_content_type_is_ignored() {
        use hyper::header::HeaderValue;
        let rule = SemanticPatchPartialUpdate;
        let mut tx = make_tx_with_req(vec![("content-length", "1")]);
        tx.request.method = "PATCH".into();
        // header name present but invalid bytes
        tx.request.headers.append(
            "content-type",
            HeaderValue::from_bytes(b"text/plain\xFF").unwrap(),
        );
        tx.request.body_length = Some(1);
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        // rule should not produce a violation; malformed header handled elsewhere
        assert!(v.is_none());
    }

    #[test]
    fn body_length_without_headers_triggers_violation() {
        let rule = SemanticPatchPartialUpdate;
        let mut tx = make_tx_with_req(vec![]);
        tx.request.method = "PATCH".into();
        tx.request.body_length = Some(5);
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(
            v.is_some(),
            "expected violation when body_length>0 without header"
        );
    }

    #[test]
    fn request_body_bytes_without_headers_triggers_violation() {
        let rule = SemanticPatchPartialUpdate;
        let mut tx = make_tx_with_req(vec![]);
        tx.request.method = "PATCH".into();
        tx.request_body = Some(Bytes::from("hello"));
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(
            v.is_some(),
            "expected violation when request_body present without header"
        );
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "semantic_patch_partial_update");
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn validate_rules_with_invalid_config() {
        // missing severity should fail validation
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "semantic_patch_partial_update");
        // remove severity field from table
        if let Some(toml::Value::Table(ref mut table)) =
            cfg.rules.get_mut("semantic_patch_partial_update")
        {
            table.remove("severity");
        }

        let err = crate::rules::validate_rules(&cfg).expect_err("expected validation to fail");
        assert!(err.to_string().contains("Missing required 'severity'"));
    }
}
