// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessagePreferenceAppliedHeaderValid;

impl Rule for MessagePreferenceAppliedHeaderValid {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_preference_applied_header_valid"
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
        // Only meaningful when a response is present
        let resp = match &tx.response {
            Some(r) => r,
            None => return None,
        };

        // Build a map of preferences from the request (name -> optional value)
        let mut req_prefs = std::collections::HashMap::<String, Option<String>>::new();
        for hv in tx.request.headers.get_all("prefer").iter() {
            let s = match hv.to_str() {
                Ok(s) => s,
                Err(_) => {
                    // Prefer header malformed - prefer parsing rule already covers this; ignore here
                    continue;
                }
            };
            for member in crate::helpers::headers::parse_list_header(s) {
                // take first semicolon-delimited part (preference = token [= word])
                let first = member.split(';').next().unwrap_or("").trim();
                if first.is_empty() {
                    continue;
                }
                let mut kv = first.splitn(2, '=');
                let name = kv.next().unwrap().trim();
                if name.is_empty() {
                    continue;
                }
                // Only first occurrence is significant per RFC 7240
                let lname = name.to_ascii_lowercase();
                if req_prefs.contains_key(&lname) {
                    continue;
                }
                let val = kv.next().map(|v| v.trim().to_string());
                req_prefs.insert(lname, val);
            }
        }

        for hv in resp.headers.get_all("preference-applied").iter() {
            let s = match hv.to_str() {
                Ok(s) => s.trim(),
                Err(_) => {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Preference-Applied header contains non-UTF8 value".into(),
                    })
                }
            };

            if s.is_empty() {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Preference-Applied header must not be empty".into(),
                });
            }

            for member in crate::helpers::headers::parse_list_header(s) {
                // ABNF: applied-pref = token [ BWS "=" BWS word ]
                // Disallow parameters (semicolon) in Preference-Applied
                if member.contains(';') {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Preference-Applied must not include parameters".into(),
                    });
                }

                let mut kv = member.splitn(2, '=');
                let name = kv.next().unwrap().trim();
                if name.is_empty() {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Preference-Applied contains empty member".into(),
                    });
                }

                if let Some(ch) = crate::helpers::token::find_invalid_token_char(name) {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!(
                            "Preference-Applied token contains invalid character: '{}'",
                            ch
                        ),
                    });
                }

                let lname = name.to_ascii_lowercase();

                // parse optional value
                let applied_val = kv.next().map(|v| v.trim().to_string());
                if let Some(av) = &applied_val {
                    if av.starts_with('"') {
                        if let Err(e) = crate::helpers::headers::validate_quoted_string(av) {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: format!(
                                    "Preference-Applied value quoted-string error: {}",
                                    e
                                ),
                            });
                        }
                    } else if let Some(ch) = crate::helpers::token::find_invalid_token_char(av) {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!(
                                "Preference-Applied value contains invalid character: '{}'",
                                ch
                            ),
                        });
                    }
                }

                // Now check that request included this preference name
                if !req_prefs.contains_key(&lname) {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!("Preference-Applied contains token '{}' not present in Prefer request header", name),
                    });
                }

                // If applied value present and request had a value, ensure they match
                if let Some(av) = &applied_val {
                    if let Some(Some(reqv)) = req_prefs.get(&lname) {
                        if reqv != av {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: format!("Preference-Applied value '{}' for '{}' does not match request value '{}'", av, name, reqv),
                            });
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
    use rstest::rstest;

    #[test]
    fn scope_is_both() {
        let rule = MessagePreferenceAppliedHeaderValid;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }

    #[rstest]
    #[case(
        "Prefer: return=representation",
        "Preference-Applied: return=representation",
        false
    )]
    #[case("Prefer: return=representation", "Preference-Applied: return", false)]
    #[case(
        "Prefer: handling=lenient",
        "Preference-Applied: handling=lenient",
        false
    )]
    #[case("", "Preference-Applied: respond-async", true)]
    #[case(
        "Prefer: return=minimal",
        "Preference-Applied: return=representation",
        true
    )]
    #[case(
        "Prefer: return=representation",
        "Preference-Applied: return;foo=bar",
        true
    )]
    fn check_cases(
        #[case] prefer_hdr: &str,
        #[case] applied_hdr: &str,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessagePreferenceAppliedHeaderValid;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);

        if !prefer_hdr.is_empty() {
            // Prefer: header string like "Prefer: ..." - build headers map
            let parts: Vec<&str> = prefer_hdr.splitn(2, ':').collect();
            tx.request.headers =
                crate::test_helpers::make_headers_from_pairs(&[(parts[0].trim(), parts[1].trim())]);
        }

        let parts2: Vec<&str> = applied_hdr.splitn(2, ':').collect();
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[(parts2[0].trim(), parts2[1].trim())]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        if expect_violation {
            assert!(
                v.is_some(),
                "expected violation for {} / {}",
                prefer_hdr,
                applied_hdr
            );
        } else {
            assert!(
                v.is_none(),
                "did not expect violation for {} / {}: {:?}",
                prefer_hdr,
                applied_hdr,
                v
            );
        }
        Ok(())
    }

    #[test]
    fn non_utf8_value_is_violation() {
        use hyper::header::HeaderValue;
        let rule = MessagePreferenceAppliedHeaderValid;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = hyper::HeaderMap::new();
        let bad = HeaderValue::from_bytes(&[0xff]).expect("should construct non-utf8 header");
        hm.insert("preference-applied", bad);
        tx.response.as_mut().unwrap().headers = hm;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
    }

    #[test]
    fn empty_header_is_violation() {
        let rule = MessagePreferenceAppliedHeaderValid;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("preference-applied", "")]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
    }

    #[test]
    fn quoted_value_validation() -> anyhow::Result<()> {
        let rule = MessagePreferenceAppliedHeaderValid;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("prefer", "foo=\"bar\"")]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("preference-applied", "foo=\"bar\"")]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn applied_name_invalid_char_is_reported() {
        let rule = MessagePreferenceAppliedHeaderValid;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[("prefer", "foo")]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("preference-applied", "f@o")]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("'@'"));
    }

    #[test]
    fn applied_value_invalid_char_is_reported() {
        let rule = MessagePreferenceAppliedHeaderValid;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[("prefer", "foo")]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("preference-applied", "foo=bad@")]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        let m = v.unwrap().message;
        assert!(m.contains("contains invalid character") && m.contains("'@'"));
    }

    #[test]
    fn applied_quoted_value_invalid_is_reported() {
        let rule = MessagePreferenceAppliedHeaderValid;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("prefer", "foo=\"bar\"")]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("preference-applied", "foo=\"bar")]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("quoted-string error"));
    }

    #[test]
    fn applied_value_present_but_request_had_no_value_is_ok() {
        // If request has 'foo' (no '=value') and response indicates 'foo=bar', accept it
        let rule = MessagePreferenceAppliedHeaderValid;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[("prefer", "foo")]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("preference-applied", "foo=bar")]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }
}
