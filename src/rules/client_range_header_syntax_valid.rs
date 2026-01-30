// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ClientRangeHeaderSyntaxValid;

impl Rule for ClientRangeHeaderSyntaxValid {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "client_range_header_syntax_valid"
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
        use hyper::header::RANGE;

        let hdrs = tx.request.headers.get_all(RANGE);
        let _ = hdrs.iter().next()?;

        for hv in hdrs.iter() {
            match hv.to_str() {
                Ok(s) => {
                    if let Err(e) = validate_range_header(s) {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!("Invalid Range header '{}': {}", s, e),
                        });
                    }
                }
                Err(_) => {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Range header contains non-UTF8 value".into(),
                    });
                }
            }
        }
        None
    }
}

fn validate_range_header(s: &str) -> Result<(), String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty header value".into());
    }

    // Expect unit=ranges
    let parts: Vec<&str> = s.splitn(2, '=').collect();
    if parts.len() != 2 {
        return Err("missing '=' after unit".into());
    }
    let unit = parts[0].trim();
    if !unit.eq_ignore_ascii_case("bytes") {
        return Err(format!("unsupported unit '{}', expected 'bytes'", unit));
    }
    let ranges = parts[1].trim();
    if ranges.is_empty() {
        return Err("no byte-range-spec found".into());
    }

    for spec in ranges.split(',') {
        let spec = spec.trim();
        if spec.is_empty() {
            return Err("empty byte-range-spec".into());
        }

        // Suffix form: -<suffix-length>
        if let Some(num) = spec.strip_prefix('-') {
            if num.is_empty() {
                return Err("invalid suffix-byte-range (missing digits)".into());
            }
            if !num.chars().all(|c| c.is_ascii_digit()) {
                return Err("suffix-byte-range contains non-digit".into());
            }
            continue;
        }

        // Otherwise expect <first>-<last?> where last may be empty
        let dash_idx = spec
            .find('-')
            .ok_or_else(|| "byte-range-spec missing '-'".to_string())?;
        let first = spec[..dash_idx].trim();
        let last = spec[dash_idx + 1..].trim();

        if first.is_empty() {
            return Err("byte-range-spec missing first position".into());
        }
        if !first.chars().all(|c| c.is_ascii_digit()) {
            return Err("first byte-pos contains non-digit".into());
        }

        if !last.is_empty() {
            if !last.chars().all(|c| c.is_ascii_digit()) {
                return Err("last byte-pos contains non-digit".into());
            }
            // check ordering first <= last
            let first_v: u128 = first
                .parse()
                .map_err(|_| "first byte-pos overflow".to_string())?;
            let last_v: u128 = last
                .parse()
                .map_err(|_| "last byte-pos overflow".to_string())?;
            if first_v > last_v {
                return Err("first byte-pos greater than last".into());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::make_test_transaction;
    use hyper::header::HeaderValue;
    use rstest::rstest;

    #[rstest]
    #[case("bytes=0-499", false)]
    #[case("bytes=500-999,1000-1499", false)]
    #[case("bytes=-500", false)]
    #[case("bytes=9500-", false)]
    #[case("bytes=0-0,-1", false)]
    #[case("items=0-1", true)]
    #[case("bytes=abc", true)]
    #[case("bytes=5-3", true)]
    #[case("bytes=", true)]
    #[case("bytes= ,1-2", true)]
    #[case("bytes=-", true)]
    #[case("bytes=500", true)]
    #[case("bytes=1-2,", true)]
    #[case("bytes=5-a", true)]
    #[case("bytes=a-5", true)]
    #[case(
        "bytes=340282366920938463463374607431768211456-340282366920938463463374607431768211457",
        true
    )]
    fn check_range_cases(
        #[case] value: &str,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let mut tx = make_test_transaction();
        tx.request.headers.insert("range", value.parse()?);

        let rule = ClientRangeHeaderSyntaxValid;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());

        if expect_violation {
            assert!(v.is_some(), "expected violation for '{}', got none", value);
        } else {
            assert!(
                v.is_none(),
                "didn't expect violation for '{}', got some: {:?}",
                value,
                v
            );
        }
        Ok(())
    }

    #[test]
    fn multiple_values_all_checked() -> anyhow::Result<()> {
        let mut tx = make_test_transaction();
        // Append two Range header values; one is invalid
        tx.request
            .headers
            .append("range", "bytes=0-1".parse::<HeaderValue>()?);
        tx.request
            .headers
            .append("range", "items=0-1".parse::<HeaderValue>()?);

        let rule = ClientRangeHeaderSyntaxValid;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn header_absent_no_violation() -> anyhow::Result<()> {
        let tx = make_test_transaction();
        let rule = ClientRangeHeaderSyntaxValid;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn non_utf8_header_reports_violation() -> anyhow::Result<()> {
        let mut tx = make_test_transaction();
        // Non-UTF8 header value should be treated as violation
        let bad = HeaderValue::from_bytes(&[0xff]).expect("should construct non-utf8 header");
        tx.request.headers.insert("range", bad);

        let rule = ClientRangeHeaderSyntaxValid;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("non-UTF8"));
        Ok(())
    }

    #[test]
    fn scope_is_client() {
        let rule = ClientRangeHeaderSyntaxValid;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Client);
    }
}
