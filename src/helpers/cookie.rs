// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Cookie-related helpers used by cookie-related rules.

/// Validate a `Path` attribute value from a `Set-Cookie` header.
///
/// Rules enforced:
/// - Must not be empty
/// - Must start with `/`
/// - Must not contain ASCII control characters (0x00-0x1F or 0x7F)
/// - Must not contain literal whitespace characters (space, tab)
/// - Percent-encodings ("%" followed by two hex digits) are accepted
pub fn validate_cookie_path(s: &str) -> Result<(), String> {
    let v = s.trim();
    if v.is_empty() {
        return Err("Path attribute is empty".into());
    }
    if !v.starts_with('/') {
        return Err(format!("Path should start with '/': '{}'", s));
    }

    // Validate percent-encodings using shared helper to avoid duplicate logic
    if let Some(msg) = crate::helpers::uri::check_percent_encoding(v) {
        return Err(msg);
    }

    let bytes = v.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        // Reject non-ASCII bytes (require percent-encoding for non-ASCII)
        if b >= 0x80 {
            return Err(format!("Path contains non-ASCII character at byte {}", i));
        }
        // Reject control chars and DEL
        if b <= 0x1f || b == 0x7f {
            return Err(format!("Path contains control character at byte {}", i));
        }
        // Reject ASCII space and horizontal tab explicitly
        if b == b' ' || b == b'\t' {
            return Err(format!("Path contains whitespace character at byte {}", i));
        }
        i += 1;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_paths() {
        assert!(validate_cookie_path("/").is_ok());
        assert!(validate_cookie_path("/login").is_ok());
        assert!(validate_cookie_path("/foo/bar").is_ok());
        assert!(validate_cookie_path("/foo%20bar").is_ok());
        assert!(validate_cookie_path("/a%2Fb").is_ok());
    }

    #[test]
    fn invalid_paths() {
        assert!(validate_cookie_path("").is_err());
        assert!(validate_cookie_path("login").is_err());
        assert!(validate_cookie_path("/has space").is_err());
        assert!(validate_cookie_path("/has\tTab").is_err());
        assert!(validate_cookie_path("/%ZZ").is_err());
        assert!(validate_cookie_path("/%2").is_err());
        assert!(validate_cookie_path("/%2G").is_err());
        assert!(validate_cookie_path("/a\x00b").is_err());
        // Non-ASCII characters should be rejected (require percent-encoding)
        assert!(validate_cookie_path("/café").is_err());
        assert!(validate_cookie_path("/ünicode").is_err());
    }
}
