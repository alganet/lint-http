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
}
