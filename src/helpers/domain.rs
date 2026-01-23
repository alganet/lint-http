// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Helpers for domain validation used by cookie/host related rules.

/// Validate a domain name suitable for a cookie `Domain` attribute.
/// Returns Ok(()) when syntactically valid, or Err(reason) describing why invalid.
pub fn validate_cookie_domain(s: &str) -> Result<(), String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty domain".into());
    }

    // Leading dot is historically allowed; tolerate and remove it for validation
    let s = if let Some(stripped) = s.strip_prefix('.') {
        stripped
    } else {
        s
    };

    if s.is_empty() {
        return Err("domain empty after removing leading dot".into());
    }

    // No whitespace or control characters
    if s.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("domain contains whitespace or control characters".into());
    }

    // Reject bracketed IPv6 literal
    if s.starts_with('[') && s.ends_with(']') {
        return Err("domain must not be an IPv6 literal".into());
    }

    // Quick IPv4-like check: only digits and dots and at least one dot
    let maybe_ipv4 = s.chars().all(|c| c.is_ascii_digit() || c == '.') && s.contains('.');
    if maybe_ipv4 {
        // To avoid false positives like '1.2', require at least 4 dot-separated labels
        if s.split('.').count() >= 4 {
            return Err("domain must not be an IPv4 address".into());
        }
    }

    // Validate labels
    if s.len() > 255 {
        return Err("domain total length exceeds 255 characters".into());
    }

    for label in s.split('.') {
        if label.is_empty() {
            return Err("domain contains empty label".into());
        }
        if label.len() > 63 {
            return Err("domain label exceeds 63 characters".into());
        }
        let first = label.chars().next().unwrap();
        let last = label.chars().next_back().unwrap();
        if first == '-' || last == '-' {
            return Err("domain label must not start or end with '-'".into());
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err("domain label contains invalid character".into());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("example.com", true)]
    #[case(".example.com", true)]
    #[case("sub.domain.example", true)]
    #[case("", false)]
    #[case(" ", false)]
    #[case(".", false)]
    #[case("ex ample.com", false)]
    #[case("192.168.0.1", false)]
    #[case("[::1]", false)]
    #[case("exa_mple.com", false)]
    #[case("-badlabel.example", false)]
    #[case(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example",
        false
    )]
    fn domain_cases(#[case] input: &str, #[case] expected_ok: bool) {
        let res = validate_cookie_domain(input);
        if expected_ok {
            assert!(res.is_ok(), "expected '{}' to be valid", input);
        } else {
            assert!(res.is_err(), "expected '{}' to be invalid", input);
        }
    }

    #[test]
    fn domain_total_length_exceeds_255_is_error() {
        // Build a domain with multiple labels each under 64 chars, but total > 255
        let label = "a".repeat(50);
        let parts: Vec<String> = (0..6).map(|_| label.clone()).collect();
        let domain = parts.join("."); // length = 6*50 + 5 = 305 > 255
        let res = validate_cookie_domain(&domain);
        assert!(res.is_err(), "expected long domain to be invalid");
    }
}
