// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Small reusable helpers for URI-ish checks used by several rules.

/// Check percent-encoding runs inside a string. Returns `Some(msg)` describing the
/// first problem found, or `None` if all percent-encodings look well-formed.
pub fn check_percent_encoding(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let len = bytes.len();
    let mut i = 0usize;

    while i < len {
        if bytes[i] == b'%' {
            if i + 2 >= len {
                return Some(
                    "Percent-encoding incomplete: '%' must be followed by two hex digits".into(),
                );
            }
            let hi = bytes[i + 1];
            let lo = bytes[i + 2];
            if !hi.is_ascii_hexdigit() || !lo.is_ascii_hexdigit() {
                let seq = &s[i..i + 3.min(len - i)];
                return Some(format!("Invalid percent-encoding '{}'", seq));
            }
            i += 3;
        } else {
            i += 1;
        }
    }

    None
}

/// Return `true` if the string contains any ASCII whitespace characters.
pub fn contains_whitespace(s: &str) -> bool {
    s.chars().any(|c| c.is_ascii_whitespace())
}

/// Validate a potential scheme (characters before the first ':').
/// Returns `Some(msg)` on invalid scheme, `None` if OK or no scheme present.
pub fn validate_scheme_if_present(s: &str) -> Option<String> {
    if let Some(colon) = s.find(':') {
        let scheme = &s[..colon];
        let mut chars = scheme.chars();
        if let Some(first) = chars.next() {
            if !first.is_ascii_alphabetic() {
                return Some(format!("Invalid scheme in value: '{}'", scheme));
            }
        }
        for c in chars {
            if !(c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.') {
                return Some(format!("Invalid character '{}' in scheme '{}'", c, scheme));
            }
        }
    }
    None
}

/// If `s` is an absolute-form request-target or full URI, return the origin
/// component as `scheme://host[:port]`. Returns `None` if input is not absolute
/// or if it does not contain a valid origin.
pub fn extract_origin_if_absolute(s: &str) -> Option<String> {
    let marker = "://";
    let idx = s.find(marker)?;
    let after = &s[idx + marker.len()..];
    // find end of authority (first '/')
    let end = after
        .find('/')
        .map(|p| idx + marker.len() + p)
        .unwrap_or(s.len());
    let origin = &s[..end];

    // Basic validation: scheme valid, no whitespace, authority part present
    if validate_scheme_if_present(origin).is_some() {
        return None;
    }
    if contains_whitespace(origin) {
        return None;
    }
    let authority = &origin[idx + marker.len()..];
    if authority.is_empty() {
        return None;
    }
    Some(origin.to_string())
}

/// Validate an `Origin` header value. Accepts `null` or a serialized origin
/// of the form `scheme://host[:port]`. Returns `None` if valid or
/// `Some(msg)` describing the problem.
pub fn validate_origin_value(s: &str) -> Option<String> {
    let s_trim = s.trim();
    if s_trim.eq_ignore_ascii_case("null") {
        return None;
    }
    // Must be an origin (absolute with no path)
    if let Some(colon_pos) = s_trim.find("://") {
        // no path allowed
        if s_trim[colon_pos + 3..].contains('/') {
            return Some("Origin must not include a path".into());
        }
        if validate_scheme_if_present(s_trim).is_some() {
            return Some("Invalid scheme in Origin".into());
        }
        if contains_whitespace(s_trim) {
            return Some("Origin contains whitespace".into());
        }
        // ensure authority (host:port) present
        let authority = &s_trim[colon_pos + 3..];
        if authority.is_empty() {
            return Some("Origin missing host".into());
        }
        return None;
    }

    Some("Origin is not a valid serialized origin".into())
}

/// Extract the path component from a request-target or absolute URI.
///
/// - If `s` is an absolute URI (`scheme://host[:port]/path...`), returns the
///   serialized path (including leading `/`), or `/` if none present.
/// - If `s` is an origin-form request-target (starts with `/`), returns the
///   path portion up to, but not including, the `?` or `#` characters.
/// - For authority-form (CONNECT) or asterisk-form (`*`) request-targets,
///   returns `None` since they do not carry a path to validate.
pub fn extract_path_from_request_target(s: &str) -> Option<String> {
    let s_trim = s.trim();

    if s_trim == "*" {
        return None;
    }

    // Absolute-form: find scheme marker '://', then the first '/' after authority
    if let Some(idx) = s_trim.find("://") {
        let after = &s_trim[idx + 3..];
        // find first '/' which marks start of path
        if let Some(pos) = after.find('/') {
            let path = &after[pos..];
            // strip query and fragment
            let end = path.find(&['?', '#'][..]).unwrap_or(path.len());
            return Some(path[..end].to_string());
        } else {
            // no '/', path is root
            return Some("/".into());
        }
    }

    // Origin-form: must start with '/'
    if s_trim.starts_with('/') {
        // strip query and fragment
        let end_idx = s_trim.find(&['?', '#'][..]).unwrap_or(s_trim.len());
        return Some(s_trim[..end_idx].to_string());
    }

    // authority-form (host:port) or unknown forms are not path-bearing
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_encoding_good_and_bad() {
        assert!(check_percent_encoding("/path%20ok").is_none());
        assert_eq!(
            check_percent_encoding("/incomplete%2"),
            Some("Percent-encoding incomplete: '%' must be followed by two hex digits".into())
        );
        let m = check_percent_encoding("/bad%2G").unwrap();
        assert!(m.contains("Invalid percent-encoding") && m.contains("%2G"));
    }

    #[test]
    fn whitespace_detection() {
        assert!(contains_whitespace("hello world"));
        assert!(!contains_whitespace("/path/no-space"));
    }

    #[test]
    fn scheme_validation() {
        assert!(validate_scheme_if_present("1http://ex").is_some());
        assert!(validate_scheme_if_present("ht!tp://ex").is_some());
        assert!(validate_scheme_if_present("/relative").is_none());
        assert!(validate_scheme_if_present("https://ex").is_none());
    }

    #[test]
    fn extract_origin_if_absolute_cases() {
        assert_eq!(extract_origin_if_absolute("/relative"), None);
        assert_eq!(
            extract_origin_if_absolute("http://example.com/path"),
            Some("http://example.com".into())
        );
        assert_eq!(
            extract_origin_if_absolute("https://example.com:8080"),
            Some("https://example.com:8080".into())
        );
        assert_eq!(extract_origin_if_absolute("not-a-scheme//no"), None);
    }

    #[test]
    fn extract_path_from_request_target_cases() {
        assert_eq!(extract_path_from_request_target("/"), Some("/".into()));
        assert_eq!(
            extract_path_from_request_target("/foo/bar?x=1#z"),
            Some("/foo/bar".into())
        );
        assert_eq!(
            extract_path_from_request_target("http://example.com/.well-known/foo?x=1"),
            Some("/.well-known/foo".into())
        );
        assert_eq!(
            extract_path_from_request_target("https://example.com"),
            Some("/".into())
        );
        assert_eq!(extract_path_from_request_target("*"), None);
        assert_eq!(extract_path_from_request_target("example.com:443"), None);
    }

    #[test]
    fn validate_origin_value_cases() {
        assert!(validate_origin_value("null").is_none());
        assert!(validate_origin_value("https://example.com").is_none());
        assert!(validate_origin_value("http:///bad").is_some());
        assert!(validate_origin_value("https://exa mple").is_some());
        assert!(validate_origin_value("invalid-origin").is_some());
        // invalid scheme in Origin
        let m = validate_origin_value("1http://example.com").unwrap();
        assert!(m.contains("Invalid scheme"));
    }

    #[test]
    fn extract_origin_invalid_scheme_whitespace_and_missing_authority() {
        // invalid scheme (does not start with alphabetic)
        assert_eq!(extract_origin_if_absolute("1http://example.com"), None);
        // whitespace in authority
        assert_eq!(extract_origin_if_absolute("http://exa mple"), None);
        // missing authority (empty after scheme)
        assert_eq!(extract_origin_if_absolute("http://"), None);
    }

    #[test]
    fn validate_origin_missing_host_reports_missing() {
        let m = validate_origin_value("http://").unwrap();
        assert!(m.contains("Origin missing host"));
    }
}
