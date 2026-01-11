// SPDX-FileCopyrightText: 2026 GitHub Copilot <copilot@example.com>
//
// SPDX-License-Identifier: ISC

//! Utilities for parsing and validating IPv6 bracketed literals used in headers.
//!
//! These helpers focus on safely handling syntax like "[::1]" and "[::1]:443" and
//! small utilities to detect problematic unbracketed IPv6+port patterns.

/// Given a string starting at an IPv6 bracket '[', parse the bracketed content and
/// optional trailing port.
///
/// Returns `Some((inner, port_opt))` when the bracketed section is syntactically valid
/// and the trailing part is either empty or a `:port` sequence (port as a &str) —
/// it does not validate the numeric range of the port.
///
/// Returns `None` when the bracket is unmatched, the inner part is empty, or the
/// trailing part is present but not in the form `:digits`.
pub fn parse_bracketed_ipv6(s: &str) -> Option<(&str, Option<&str>)> {
    if !s.starts_with('[') {
        return None;
    }
    let closing = s.find(']')?;
    // require at least one char inside the brackets
    if closing <= 1 {
        return None;
    }
    let inner = &s[1..closing];
    let tail = &s[closing + 1..];
    if tail.is_empty() {
        return Some((inner, None));
    }
    // tail must start with ':' followed by at least one digit
    if !tail.starts_with(':') {
        return None;
    }
    let port = &tail[1..];
    if port.is_empty() || !port.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some((inner, Some(port)))
}

/// Parse a port string (only digits) into `u16` and ensure it is in 1..=65535.
pub fn parse_port_str(port: &str) -> Option<u16> {
    if port.is_empty() {
        return None;
    }
    // Reject leading '+' or '-' signs; only digits allowed.
    if !port.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    match port.parse::<u32>() {
        Ok(n) if (1..=65535).contains(&n) => Some(n as u16),
        _ => None,
    }
}

/// Detects an unbracketed IPv6-ish string that contains a port-like suffix,
/// e.g., `fe80::1:80` — callers should treat these as violations for headers
/// where IPv6+port must be bracketed.
pub fn looks_like_unbracketed_ipv6_with_port(s: &str) -> bool {
    // Conservative check: ensure trailing ':<digits>' exists and the part before the last ':'
    // parses as an IPv6 address. This avoids misclassifying strings like "::1" as having a
    // port.
    let colons = s.chars().filter(|&c| c == ':').count();
    if colons < 2 {
        return false;
    }
    if let Some(pos) = s.rfind(':') {
        let port = &s[pos + 1..];
        if port.is_empty() || !port.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }
        let maybe_host = &s[..pos];
        if let Ok(ip) = maybe_host.parse::<std::net::IpAddr>() {
            return matches!(ip, std::net::IpAddr::V6(_));
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bracketed_ipv6_ok_without_port() {
        assert_eq!(parse_bracketed_ipv6("[::1]"), Some(("::1", None)));
        assert_eq!(parse_bracketed_ipv6("[::1]:"), None);
    }

    #[test]
    fn parse_bracketed_ipv6_ok_with_port() {
        assert_eq!(
            parse_bracketed_ipv6("[::1]:443"),
            Some(("::1", Some("443")))
        );
        assert_eq!(
            parse_bracketed_ipv6("[fe80::1]:80"),
            Some(("fe80::1", Some("80")))
        );
    }

    #[test]
    fn parse_bracketed_ipv6_rejects_malformed() {
        assert_eq!(parse_bracketed_ipv6("[::1"), None);
        assert_eq!(parse_bracketed_ipv6("[]"), None);
        assert_eq!(parse_bracketed_ipv6("[::1]extra"), None);
        assert_eq!(parse_bracketed_ipv6("[::1]:notnum"), None);
    }

    #[test]
    fn parse_port_str_ok_and_bounds() {
        assert_eq!(parse_port_str("1"), Some(1));
        assert_eq!(parse_port_str("65535"), Some(65535));
        assert_eq!(parse_port_str("0"), None);
        assert_eq!(parse_port_str("65536"), None);
        assert_eq!(parse_port_str("+80"), None);
        assert_eq!(parse_port_str("080"), Some(80));
    }

    #[test]
    fn looks_like_unbracketed_ipv6_with_port_cases() {
        assert!(looks_like_unbracketed_ipv6_with_port("fe80::1:80"));
        assert!(!looks_like_unbracketed_ipv6_with_port("example.com:80"));
        assert!(!looks_like_unbracketed_ipv6_with_port("::1"));
    }
}
