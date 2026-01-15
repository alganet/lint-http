// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

#[derive(Debug, Clone)]
pub struct MessageTeHeaderConstraints;

impl Rule for MessageTeHeaderConstraints {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_te_header_constraints"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _previous: Option<&crate::http_transaction::HttpTransaction>,
        config: &Self::Config,
    ) -> Option<Violation> {
        // TE should not appear in responses
        if let Some(resp) = &tx.response {
            if let Some(val) = crate::helpers::headers::get_header_str(&resp.headers, "te") {
                return Some(Violation {
                    rule: self.id().to_string(),
                    severity: config.severity,
                    message: format!(
                        "Response contains TE header which is only defined for requests: '{}'",
                        val
                    ),
                });
            }
        }

        // If request has TE header, validate members and ensure Connection contains TE
        if let Some(val) = crate::helpers::headers::get_header_str(&tx.request.headers, "te") {
            // Validate each comma-separated member
            for part in crate::helpers::headers::parse_list_header(val) {
                // each part: transfer-coding [ params ] OR "trailers"
                let mut iter = part.split(';').map(|s| s.trim());
                if let Some(primary) = iter.next() {
                    if primary.eq_ignore_ascii_case("trailers") {
                        // trailers has no parameters per spec; any params are an error
                        if iter.next().is_some() {
                            return Some(Violation {
                                rule: self.id().to_string(),
                                severity: config.severity,
                                message: format!(
                                    "Invalid parameters on 'trailers' member in TE header: '{}'",
                                    part
                                ),
                            });
                        }
                    } else {
                        // Validate token form using TE-restricted token characters (alphanum and hyphen)
                        if let Some(c) = find_invalid_te_token_char(primary) {
                            return Some(Violation {
                                rule: self.id().to_string(),
                                severity: config.severity,
                                message: format!(
                                    "Invalid character '{}' in TE transfer-coding '{}'",
                                    c, primary
                                ),
                            });
                        }

                        // validate parameters (optional): transfer-parameter = token BWS "=" BWS ( token / quoted-string )
                        for param in iter {
                            if param.is_empty() {
                                continue;
                            }
                            let mut nv = param.splitn(2, '=').map(|s| s.trim());
                            let name = nv.next().unwrap();
                            let val = nv.next();
                            if crate::helpers::token::find_invalid_token_char(name).is_some() {
                                return Some(Violation {
                                    rule: self.id().to_string(),
                                    severity: config.severity,
                                    message: format!(
                                        "Invalid parameter name '{}' in TE header member '{}'",
                                        name, part
                                    ),
                                });
                            }

                            if val.is_none() {
                                return Some(Violation {
                                    rule: self.id().to_string(),
                                    severity: config.severity,
                                    message: format!(
                                        "Missing parameter value for '{}' in TE header member '{}'",
                                        name, part
                                    ),
                                });
                            }
                            let v = val.unwrap();
                            // q special-case: validate qvalue format 0..1 with up to three decimals
                            if name.eq_ignore_ascii_case("q") {
                                if !valid_qvalue(v) {
                                    return Some(Violation {
                                        rule: self.id().to_string(),
                                        severity: config.severity,
                                        message: format!(
                                            "Invalid qvalue '{}' in TE header member '{}'",
                                            v, part
                                        ),
                                    });
                                }
                            } else {
                                // value must be token or quoted-string
                                if v.starts_with('"') {
                                    if let Err(e) =
                                        crate::helpers::headers::validate_quoted_string(v)
                                    {
                                        return Some(Violation {
                                            rule: self.id().to_string(),
                                            severity: config.severity,
                                            message: format!("Invalid quoted-string parameter value '{}' in TE header: {}", v, e),
                                        });
                                    }
                                } else if crate::helpers::token::find_invalid_token_char(v)
                                    .is_some()
                                {
                                    return Some(Violation {
                                        rule: self.id().to_string(),
                                        severity: config.severity,
                                        message: format!("Invalid parameter value '{}' for '{}' in TE header member '{}'", v, name, part),
                                    });
                                }
                            }
                        }
                    }
                }
            }

            // Ensure Connection header contains TE token (case-insensitive)
            let mut found_te = false;
            if let Some(conn) =
                crate::helpers::headers::get_header_str(&tx.request.headers, "connection")
            {
                for tok in crate::helpers::headers::parse_list_header(conn) {
                    if tok.eq_ignore_ascii_case("te") {
                        found_te = true;
                        break;
                    }
                }
            }
            if !found_te {
                return Some(Violation {
                    rule: self.id().to_string(),
                    severity: config.severity,
                    message: "Request contains TE header but Connection header missing 'TE' token"
                        .into(),
                });
            }
        }

        None
    }
}

/// Validate qvalue syntax: 0, 1, 0.5, 0.123, 1.0, 0.000, etc. up to 3 decimals
fn valid_qvalue(s: &str) -> bool {
    let s = s.trim();
    // Must match either 1 or 1.0{0,3} or 0(.xxx){0,3}
    if s == "1" || s == "1.0" || s == "1.00" || s == "1.000" {
        return true;
    }
    if s.starts_with("0") {
        if s == "0" {
            return true;
        }
        if let Some(rest) = s.strip_prefix("0.") {
            if !rest.is_empty() && rest.len() <= 3 && rest.chars().all(|c| c.is_ascii_digit()) {
                return true;
            }
        }
    }
    false
}

// Find the first invalid character in a TE transfer-coding token per rule's stricter policy.
// Accept only ASCII alphanumeric characters and hyphen/minus '-'.
fn find_invalid_te_token_char(s: &str) -> Option<char> {
    s.chars()
        .find(|&c| !(c.is_ascii_alphanumeric() || c == '-'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(Some(("te","trailers")), Some(("connection","TE")), false)]
    #[case(Some(("te","chunked;q=0.8")), Some(("connection","TE")), false)]
    #[case(Some(("te","chunked;q=0.8")), None, true)]
    #[case(Some(("te","x!bad")), Some(("connection","TE")), true)]
    #[case(Some(("te","chunked;q=1.0000")), Some(("connection","TE")), true)]
    fn check_request_cases(
        #[case] te_hdr: Option<(&str, &str)>,
        #[case] conn: Option<(&str, &str)>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageTeHeaderConstraints;
        let cfg = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };

        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some((k, v)) = te_hdr {
            tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(k, v)]);
        }
        if let Some((k, v)) = conn {
            // merge with any existing headers
            let mut pairs = vec![];
            if let Some((k0, v0)) = te_hdr {
                pairs.push((k0, v0));
            }
            pairs.push((k, v));
            tx.request.headers = crate::test_helpers::make_headers_from_pairs(&pairs);
        }

        let v = rule.check_transaction(&tx, None, &cfg);
        if expect_violation {
            assert!(v.is_some(), "expected violation but got none");
        } else {
            assert!(v.is_none(), "expected no violation but got one: {:?}", v);
        }
        Ok(())
    }

    #[test]
    fn te_in_response_is_violation() -> anyhow::Result<()> {
        let rule = MessageTeHeaderConstraints;
        let cfg = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("te", "trailers")]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        Ok(())
    }

    #[rstest]
    #[case(Some(("te","trailers;foo=bar")), Some(("connection","TE")), true)]
    #[case(Some(("te","chunked;bad name=1")), Some(("connection","TE")), true)]
    #[case(Some(("te","chunked;q")), Some(("connection","TE")), true)]
    #[case(Some(("te","chunked;foo=\"bad")), Some(("connection","TE")), true)]
    #[case(Some(("te","chunked;foo=bad@")), Some(("connection","TE")), true)]
    #[case(Some(("te","chunked;")), Some(("connection","TE")), false)]
    #[case(Some(("te","chunked;q=1.000")), Some(("connection","TE")), false)]
    fn check_parameter_cases(
        #[case] te_hdr: Option<(&str, &str)>,
        #[case] conn: Option<(&str, &str)>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageTeHeaderConstraints;
        let cfg = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };

        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some((k, v)) = te_hdr {
            tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(k, v)]);
        }
        if let Some((k, v)) = conn {
            // merge with any existing headers
            let mut pairs = vec![];
            if let Some((k0, v0)) = te_hdr {
                pairs.push((k0, v0));
            }
            pairs.push((k, v));
            tx.request.headers = crate::test_helpers::make_headers_from_pairs(&pairs);
        }

        let v = rule.check_transaction(&tx, None, &cfg);
        if expect_violation {
            assert!(v.is_some(), "expected violation but got none");
        } else {
            assert!(v.is_none(), "expected no violation but got one: {:?}", v);
        }
        Ok(())
    }

    #[rstest]
    #[case(Some(("te","chunked;q=0.0")), Some(("connection","TE")), false)]
    #[case(Some(("te","chunked;q=0.")), Some(("connection","TE")), true)]
    #[case(Some(("te","chunked;q=.5")), Some(("connection","TE")), true)]
    #[case(Some(("te","chunked;q=0.123")), Some(("connection","TE")), false)]
    #[case(Some(("te","chunked;foo=\"ok\"")), Some(("connection","TE")), false)]
    #[case(Some(("te","chunked;q=0.5, x!bad")), Some(("connection","TE")), true)]
    #[case(Some(("te","chunked, trailers")), Some(("connection","TE")), false)]
    #[case(Some(("te","chunked, trailers;foo=1")), Some(("connection","TE")), true)]
    #[case(Some(("te","chunked;q=0.8")), Some(("connection","keep-alive, Upgrade")), true)]
    #[case(Some(("te","chunked;q=0.8")), Some(("connection","kEeP-aLiVe, tE")), false)]
    fn check_additional_cases(
        #[case] te_hdr: Option<(&str, &str)>,
        #[case] conn: Option<(&str, &str)>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageTeHeaderConstraints;
        let cfg = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };

        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some((k, v)) = te_hdr {
            tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(k, v)]);
        }
        if let Some((k, v)) = conn {
            // merge with any existing headers
            let mut pairs = vec![];
            if let Some((k0, v0)) = te_hdr {
                pairs.push((k0, v0));
            }
            pairs.push((k, v));
            tx.request.headers = crate::test_helpers::make_headers_from_pairs(&pairs);
        }

        let v = rule.check_transaction(&tx, None, &cfg);
        if expect_violation {
            assert!(v.is_some(), "expected violation but got none");
        } else {
            assert!(v.is_none(), "expected no violation but got one: {:?}", v);
        }
        Ok(())
    }

    #[rstest]
    #[case("1", true)]
    #[case("1.000", true)]
    #[case("1.0000", false)]
    #[case("0", true)]
    #[case("0.0", true)]
    #[case("0.", false)]
    #[case("0.123", true)]
    #[case("0.1234", false)]
    #[case(" 0.5 ", true)]
    fn check_qvalue_cases(#[case] s: &str, #[case] expected: bool) {
        assert_eq!(valid_qvalue(s), expected);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_te_header_constraints");
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn scope_is_both() {
        let rule = MessageTeHeaderConstraints;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }
}
