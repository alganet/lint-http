// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use hyper::HeaderMap;

/// Retrieve a header value as a string, if it exists and contains only visible ASCII.
///
/// Returns `None` if the header is missing or contains non-visible ASCII characters
/// (control characters) or non-ASCII bytes.
pub fn get_header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// Parse a comma-separated list of header values (e.g., Connection, Transfer-Encoding).
///
/// This iterator splits by comma, trims whitespace, and skips empty parts.
pub fn parse_list_header(val: &str) -> impl Iterator<Item = &str> {
    val.split(',').map(|s| s.trim()).filter(|s| !s.is_empty())
}

/// Validate a quoted-string per HTTP rules: must start and end with DQUOTE, support backslash escapes,
/// must not contain unescaped control characters (except HTAB). Returns Ok(()) on success, Err(msg)
/// on failure.
pub fn validate_quoted_string(val: &str) -> Result<(), String> {
    let bytes = val.as_bytes();
    if bytes.len() < 2 || bytes[0] != b'"' || bytes[bytes.len() - 1] != b'"' {
        return Err(format!("Quoted-string not properly quoted: '{}'", val));
    }

    // Walk the interior checking for unescaped control chars and ensuring proper escaping
    let mut i = 1usize;
    let mut prev_backslash = false;
    while i + 1 < bytes.len() {
        let b = bytes[i];
        if prev_backslash {
            // escaped char allowed
            prev_backslash = false;
        } else if b == b'\\' {
            prev_backslash = true;
        } else if b == b'"' {
            // unescaped quote before the terminating one -> invalid
            return Err(format!("Unescaped quote in quoted-string: '{}'", val));
        } else if (b < 0x20 && b != b'\t') || b == 0x7f {
            return Err(format!("Control character in quoted-string: '{}'", val));
        }
        i += 1;
    }

    if prev_backslash {
        return Err(format!(
            "Quoted-string ends with escape character: '{}'",
            val
        ));
    }

    Ok(())
}

/// Validate an entity-tag (ETag) value per RFC 9110 §7.6 and §7.8. Accepts '*' or an entity-tag
/// which may be weak (prefix 'W/'). Returns Ok(()) on success or Err(msg) describing the problem.
pub fn validate_entity_tag(val: &str) -> Result<(), String> {
    let s = val.trim();
    if s == "*" {
        return Ok(());
    }

    let rest = if let Some(stripped) = s.strip_prefix("W/") {
        stripped
    } else {
        s
    };
    // rest must be a quoted-string
    validate_quoted_string(rest)
}

/// Represents a parsed Media Type (e.g. "text/html; charset=utf-8").
#[derive(Debug, PartialEq, Eq)]
pub struct ParsedMediaType<'a> {
    pub type_: &'a str,
    pub subtype: &'a str,
    pub params: Option<&'a str>,
}

/// Parse a Media Type string into type, subtype, and optional params.
///
/// This does NOT fully validate the tokens (e.g. wildcards or invalid chars),
/// but it separates the structure.
/// Returns an error message if the structure is invalid (missing slash, empty parts).
pub fn parse_media_type(val: &str) -> Result<ParsedMediaType<'_>, String> {
    let trimmed = val.trim();
    if trimmed.is_empty() {
        return Err("Empty media-type".into());
    }

    let mut parts = trimmed.splitn(2, ';');
    let media = parts.next().unwrap().trim();
    let params = parts.next().map(|p| p.trim()).filter(|p| !p.is_empty());

    if !media.contains('/') {
        return Err(format!(
            "Invalid media-type '{}': missing '/' between type and subtype",
            val
        ));
    }

    let mut ts = media.splitn(2, '/');
    let type_ = ts.next().unwrap_or("").trim();
    let subtype = ts.next().unwrap_or("").trim();

    if type_.is_empty() || subtype.is_empty() {
        return Err(format!(
            "Invalid media-type '{}': empty type or subtype",
            val
        ));
    }

    Ok(ParsedMediaType {
        type_,
        subtype,
        params,
    })
}

/// Validate a serialized-origin as defined by RFC 6454: scheme "://" host [":" port]
/// Accepts an optional trailing slash (examples in RFC 7034 include it).
/// This is a conservative validator: it ensures scheme chars, presence of host,
/// and numeric port (if present). It does not attempt full IDNA or host label validation.
pub fn is_valid_serialized_origin(val: &str) -> bool {
    let s = val.trim();
    if s.is_empty() {
        return false;
    }

    // Split scheme://rest
    let parts: Vec<&str> = s.splitn(2, "://").collect();
    if parts.len() != 2 {
        return false;
    }
    let scheme = parts[0];
    let mut rest = parts[1];

    // If a path or any data after '/', ignore it per RFC 7034 examples and advice
    if let Some(idx) = rest.find('/') {
        rest = &rest[..idx];
    }

    // Scheme: ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ) per RFC3986
    let mut chars = scheme.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() => (),
        _ => return false,
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.') {
        return false;
    }

    // rest should be host[:port] and must not contain '/', whitespace or userinfo '@'
    if rest.is_empty()
        || rest.contains('/')
        || rest.contains('\t')
        || rest.contains(' ')
        || rest.contains('@')
    {
        return false;
    }

    if let Some(colon_pos) = rest.rfind(':') {
        // If colon exists, treat as host:port candidate. But IPv6 address may contain ':' and be bracketed.
        if rest.starts_with('[') {
            // Use the ipv6 helper to parse bracketed IPv6 and optional port
            if let Some((_, port_opt)) = crate::helpers::ipv6::parse_bracketed_ipv6(rest) {
                if let Some(port_str) = port_opt {
                    return crate::helpers::ipv6::parse_port_str(port_str).is_some();
                }
                return true;
            } else {
                return false; // malformed or unmatched '['
            }
        } else {
            let host = &rest[..colon_pos];
            let port = &rest[colon_pos + 1..];
            if host.is_empty() || port.is_empty() {
                return false;
            }
            // Parse and validate port using helper
            return crate::helpers::ipv6::parse_port_str(port).is_some();
        }
    }

    // No port: ensure host is non-empty
    !rest.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;

    #[test]
    fn test_get_header_str() {
        let mut map = HeaderMap::new();
        map.insert("x-foo", HeaderValue::from_static("bar"));
        map.insert("x-bin", HeaderValue::from_bytes(b"\xff").unwrap());

        assert_eq!(get_header_str(&map, "x-foo"), Some("bar"));
        assert_eq!(get_header_str(&map, "x-bin"), None);
        assert_eq!(get_header_str(&map, "x-missing"), None);
    }

    #[test]
    fn test_parse_list_header() {
        let input = " foo, bar , , baz ";
        let tokens: Vec<_> = parse_list_header(input).collect();
        assert_eq!(tokens, vec!["foo", "bar", "baz"]);
    }

    #[test]
    fn test_parse_media_type() {
        let res = parse_media_type("text/html; charset=utf-8").unwrap();
        assert_eq!(res.type_, "text");
        assert_eq!(res.subtype, "html");
        assert_eq!(res.params, Some("charset=utf-8"));

        let res = parse_media_type(" application/json ").unwrap();
        assert_eq!(res.type_, "application");
        assert_eq!(res.subtype, "json");
        assert_eq!(res.params, None);

        assert!(parse_media_type("text").is_err());
        assert!(parse_media_type("/html").is_err());
        assert!(parse_media_type("text/").is_err());
    }

    #[test]
    fn test_is_valid_serialized_origin() {
        assert!(is_valid_serialized_origin("https://example.com"));
        assert!(is_valid_serialized_origin("https://example.com/"));
        assert!(is_valid_serialized_origin("http://example.com:8080"));
        assert!(is_valid_serialized_origin("https://localhost"));
        assert!(is_valid_serialized_origin("https://[::1]:8080"));
        assert!(is_valid_serialized_origin("https://[::1]"));

        // Port range & formatting checks
        assert!(is_valid_serialized_origin("http://example.com:1"));
        assert!(is_valid_serialized_origin("http://example.com:65535"));
        assert!(is_valid_serialized_origin("http://example.com:080")); // leading zero allowed -> 80

        assert!(!is_valid_serialized_origin("http://example.com:0")); // port 0 invalid
        assert!(!is_valid_serialized_origin("http://example.com:65536")); // out of range
        assert!(!is_valid_serialized_origin(
            "http://example.com:999999999999"
        )); // too large

        assert!(!is_valid_serialized_origin("example.com"));
        assert!(!is_valid_serialized_origin("https:///foo"));
        assert!(!is_valid_serialized_origin("https://"));
        assert!(!is_valid_serialized_origin("http://host:notaport"));
        assert!(!is_valid_serialized_origin("https://user@example.com"));
        assert!(!is_valid_serialized_origin("https://[::1"));
        assert!(!is_valid_serialized_origin(""));
    }

    use rstest::rstest;

    #[rstest]
    #[case("ht$tp://example.com")]
    #[case("http://example.com:")]
    #[case("http://:80")]
    fn invalid_serialized_origin_cases(#[case] input: &str) {
        assert!(!is_valid_serialized_origin(input));
    }

    #[test]
    fn scheme_first_char_not_alpha_is_invalid() {
        assert!(!is_valid_serialized_origin("1http://example.com"));
    }

    // Quoted-string helper tests
    #[test]
    fn validate_quoted_string_control_char_reports_violation() {
        let s = "\"bad\x01str\"";
        let res = validate_quoted_string(s);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("Control character"));
    }

    #[test]
    fn validate_quoted_string_unterminated_reports_violation() {
        let s = "\"unfinished";
        let res = validate_quoted_string(s);
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .contains("Quoted-string not properly quoted"));
    }

    #[test]
    fn validate_quoted_string_extra_chars_reports_violation() {
        let s = "\"abc\"x";
        let res = validate_quoted_string(s);
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .contains("Quoted-string not properly quoted"));
    }

    #[test]
    fn validate_quoted_string_with_escaped_quote_is_valid() {
        let s = "\"a\\\"b\""; // "a\"b"
        let res = validate_quoted_string(s);
        assert!(res.is_ok());
    }

    #[test]
    fn validate_quoted_string_ends_with_escape_reports_violation() {
        let s = "\"abc\\\""; // ends with escaped state before final quote
        let res = validate_quoted_string(s);
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .contains("Quoted-string ends with escape character"));
    }

    // Entity-tag helper tests
    #[test]
    fn validate_entity_tag_cases() {
        assert!(validate_entity_tag("*").is_ok());
        assert!(validate_entity_tag("\"abc\"").is_ok());
        assert!(validate_entity_tag("W/\"abc\"").is_ok());
        assert!(validate_entity_tag(" W/\"abc\" ").is_ok()); // leading/trailing whitespace tolerated
        assert!(validate_entity_tag("abc").is_err()); // missing quotes
        assert!(validate_entity_tag("W/abc").is_err()); // weak prefix without quoted-string
    }
}
