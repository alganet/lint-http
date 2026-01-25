// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageCompressionAndTransferEncodingConsistency;

impl Rule for MessageCompressionAndTransferEncodingConsistency {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_compression_and_transfer_encoding_consistency"
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
        // Only applies to responses
        let resp = match &tx.response {
            Some(r) => r,
            None => return None,
        };

        // Collect tokens from ALL header fields (multiple header fields should be considered)
        let mut ce_set = std::collections::HashSet::new();
        for hv in resp.headers.get_all("content-encoding").iter() {
            if let Ok(s) = hv.to_str() {
                for part in crate::helpers::headers::parse_list_header(s) {
                    let token = part.split(';').next().unwrap().trim().to_ascii_lowercase();
                    if token.is_empty() {
                        continue;
                    }
                    ce_set.insert(token);
                }
            }
        }

        let mut te_set = std::collections::HashSet::new();
        for hv in resp.headers.get_all("transfer-encoding").iter() {
            if let Ok(s) = hv.to_str() {
                for part in crate::helpers::headers::parse_list_header(s) {
                    let token = part.split(';').next().unwrap().trim().to_ascii_lowercase();
                    if token.is_empty() {
                        continue;
                    }
                    te_set.insert(token);
                }
            }
        }

        // If either header is absent or no valid tokens present, nothing to check
        if ce_set.is_empty() || te_set.is_empty() {
            return None;
        }

        // Find overlapping tokens between Content-Encoding and Transfer-Encoding
        let mut overlap: Vec<String> = ce_set
            .intersection(&te_set)
            .map(|s| s.to_string())
            .collect();
        overlap.sort();

        if !overlap.is_empty() {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!(
                    "Compression coding(s) '{}' appear in both Content-Encoding and Transfer-Encoding; prefer using Content-Encoding for end-to-end compression (RFC 9110 §5.3)",
                    overlap.join(", ")
                ),
            });
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;
    use rstest::rstest;

    fn make_tx_with_headers(
        ce: Option<&str>,
        te: Option<&str>,
    ) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        if let Some(v) = ce {
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[("content-encoding", v)]);
        }
        if let Some(v) = te {
            // Merge TE header without clobbering CE
            let mut hm = tx.response.as_mut().unwrap().headers.clone();
            hm.extend(crate::test_helpers::make_headers_from_pairs(&[(
                "transfer-encoding",
                v,
            )]));
            tx.response.as_mut().unwrap().headers = hm;
        }
        tx
    }

    #[rstest]
    // Added coverage for params, case-insensitive tokens, trailing commas
    #[case(Some("gzip"), Some("chunked, gzip"), true)]
    #[case(Some("gzip"), Some("chunked"), false)]
    #[case(Some("br, gzip"), Some("gzip, chunked"), true)]
    #[case(Some("gzip"), None, false)]
    #[case(None, Some("gzip"), false)]
    #[case(Some("gzip;q=1.0"), Some("gzip"), true)]
    #[case(Some("GZip"), Some("gzip"), true)]
    #[case(Some("gzip, "), Some("gzip"), true)]
    fn overlap_cases(
        #[case] ce: Option<&str>,
        #[case] te: Option<&str>,
        #[case] expect_violation: bool,
    ) {
        let tx = make_tx_with_headers(ce, te);
        let rule = MessageCompressionAndTransferEncodingConsistency;
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        if expect_violation {
            assert!(
                v.is_some(),
                "expected violation for ce={:?} te={:?}",
                ce,
                te
            );
        } else {
            assert!(
                v.is_none(),
                "unexpected violation for ce={:?} te={:?}: {:?}",
                ce,
                te,
                v
            );
        }
    }

    #[test]
    fn multiple_header_fields_detected() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        // Append multiple Content-Encoding fields
        let mut hm = hyper::HeaderMap::new();
        hm.append("content-encoding", HeaderValue::from_static("gzip"));
        hm.append("content-encoding", HeaderValue::from_static("br"));
        hm.append("transfer-encoding", HeaderValue::from_static("br, chunked"));
        tx.response.as_mut().unwrap().headers = hm;

        let rule = MessageCompressionAndTransferEncodingConsistency;
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
    }

    #[test]
    fn non_utf8_header_values_are_ignored() {
        use crate::test_helpers::make_test_transaction;
        let mut tx = make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hyper::HeaderMap::new(),

            body_length: None,
        });

        tx.response.as_mut().unwrap().headers.append(
            "content-encoding",
            HeaderValue::from_bytes(&[0xff]).unwrap(),
        );
        tx.response.as_mut().unwrap().headers.append(
            "transfer-encoding",
            HeaderValue::from_static("gzip, chunked"),
        );

        let rule = MessageCompressionAndTransferEncodingConsistency;
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        // Non-UTF8 content-encoding should be ignored and not cause a panic or violation
        assert!(v.is_none());
    }

    #[test]
    fn overlapping_multiple_tokens_message_contains_both_sorted() {
        let tx = make_tx_with_headers(Some("gzip, br"), Some("br, gzip"));
        let rule = MessageCompressionAndTransferEncodingConsistency;
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("br, gzip"));
    }

    #[test]
    fn scope_is_server() {
        let rule = MessageCompressionAndTransferEncodingConsistency;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        // Use the project test helper to enable the rule and validate full engine path
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_compression_and_transfer_encoding_consistency",
        ]);
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn validate_rules_missing_severity_errors() {
        // When rule is enabled but missing required 'severity', validation should fail
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_compression_and_transfer_encoding_consistency",
        ]);
        // Remove severity key from the rule table
        if let Some(toml::Value::Table(table)) = cfg
            .rules
            .get_mut("message_compression_and_transfer_encoding_consistency")
        {
            table.remove("severity");
        }

        let res = crate::rules::validate_rules(&cfg);
        assert!(res.is_err());
    }
}
