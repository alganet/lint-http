// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use hyper::HeaderMap;

/// Errors returned by `validate_content_length`.
#[derive(Debug, PartialEq, Eq)]
pub enum ContentLengthError {
    InvalidCharacter(String),
    TooLarge(String),
    MultipleValuesDiffer(String, String),
    NonUtf8,
}

/// Validate `Content-Length` headers in a `HeaderMap`.
///
/// Checks:
/// 1. Values must be valid UTF-8 digits.
/// 2. Values must be parseable as u128.
/// 3. If multiple values are present, they must be identical.
///
/// Returns `Ok(None)` if no Content-Length header is present,
/// `Ok(Some(n))` if valid, or `Err(ContentLengthError)`.
pub fn validate_content_length(headers: &HeaderMap) -> Result<Option<u128>, ContentLengthError> {
    let entries: Vec<_> = headers
        .get_all(hyper::header::CONTENT_LENGTH)
        .iter()
        .collect();

    if entries.is_empty() {
        return Ok(None);
    }

    let mut first_val: Option<u128> = None;
    let mut first_raw: String = String::new();

    for (i, hv) in entries.iter().enumerate() {
        let s = hv.to_str().map_err(|_| ContentLengthError::NonUtf8)?;
        let t = s.trim();

        if t.is_empty() || !t.chars().all(|c| c.is_ascii_digit()) {
            return Err(ContentLengthError::InvalidCharacter(s.to_string()));
        }

        let n = t
            .parse::<u128>()
            .map_err(|_| ContentLengthError::TooLarge(s.to_string()))?;

        if i == 0 {
            first_val = Some(n);
            first_raw = s.to_string();
        } else if Some(n) != first_val {
            return Err(ContentLengthError::MultipleValuesDiffer(
                first_raw,
                s.to_string(),
            ));
        }
    }

    Ok(first_val)
}

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

/// Parse a semicolon-separated list of directive values.
///
/// This iterator splits by semicolon, trims whitespace, and skips empty parts.
/// Similar to `parse_list_header` but for semicolon-delimited lists.
pub fn parse_semicolon_list(val: &str) -> impl Iterator<Item = &str> {
    val.split(';').map(|s| s.trim()).filter(|s| !s.is_empty())
}

/// Check whether a header name is a hop-by-hop header.
///
/// Returns `true` if `name` matches a known hop-by-hop header (case-insensitive)
/// or if it is nominated by the optional `Connection` header value.
/// This mirrors the hop-by-hop semantics in RFC 7230 §4.1.2 and §6.1.
pub fn is_hop_by_hop_header(name: &str, connection_header_value: Option<&str>) -> bool {
    let name_l = name.trim().to_ascii_lowercase();
    static HOP_BY_HOP: &[&str] = &[
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ];

    if HOP_BY_HOP.contains(&name_l.as_str()) {
        return true;
    }

    if let Some(conn) = connection_header_value {
        for tok in parse_list_header(conn) {
            if tok.eq_ignore_ascii_case(name_l.as_str()) {
                return true;
            }
        }
    }

    false
}

/// Remove top-level parenthesized comments from a header value.
///
/// This supports simple comment removal as used in headers like `User-Agent`.
/// It handles backslash escapes and nested parentheses. Returns `Err` if
/// comments are unbalanced or the input contains control characters.
pub fn strip_comments(val: &str) -> Result<String, String> {
    let bytes = val.as_bytes();
    let mut res = String::with_capacity(val.len());
    let mut i = 0usize;
    let mut depth = 0i32;
    let mut prev_backslash = false;

    while i < bytes.len() {
        let b = bytes[i];
        if prev_backslash {
            // include escaped char regardless of whether in comment
            if depth == 0 {
                res.push(b as char);
            }
            prev_backslash = false;
            i += 1;
            continue;
        }

        if b == b'\\' {
            prev_backslash = true;
            i += 1;
            continue;
        }

        if b == b'(' {
            depth += 1;
            i += 1;
            continue;
        }

        if b == b')' {
            if depth == 0 {
                return Err("Unmatched closing parenthesis in comment".into());
            }
            depth -= 1;
            i += 1;
            continue;
        }

        if depth == 0 {
            // outside comment: ensure visible ascii
            if (b < 0x20 && b != b'\t') || b == 0x7f {
                return Err("Control character in header value".into());
            }
            res.push(b as char);
        }

        i += 1;
    }

    if depth != 0 {
        return Err("Unterminated parenthesized comment".into());
    }

    Ok(res)
}

/// Split a comma-separated header value into top-level members while respecting quoted-strings
/// and backslash escapes. Returns a Vec of slices referencing the original string.
///
/// This is useful for header grammars like `Cache-Control` and `Pragma` where members
/// may contain quoted-strings with commas that must not be treated as separators.
pub fn split_commas_respecting_quotes(s: &str) -> Vec<&str> {
    let bytes = s.as_bytes();
    let mut res = Vec::new();
    let mut start = 0usize;
    let mut i = 0usize;
    let mut in_quote = false;
    let mut prev_backslash = false;

    while i < bytes.len() {
        let b = bytes[i];
        if prev_backslash {
            prev_backslash = false;
        } else if b == b'\\' {
            prev_backslash = true;
        } else if b == b'"' {
            in_quote = !in_quote;
        } else if b == b',' && !in_quote {
            res.push(&s[start..i]);
            start = i + 1;
        }
        i += 1;
    }
    // push remaining
    if start <= s.len() {
        res.push(&s[start..]);
    }
    res
}

/// Split a semicolon-separated header value into top-level members while respecting quoted-strings
/// and backslash escapes. Returns a Vec of slices referencing the original string.
///
/// Useful for header grammars like `Strict-Transport-Security` where directives are separated
/// with `;` and may include quoted-strings (rare but defensive).
pub fn split_semicolons_respecting_quotes(s: &str) -> Vec<&str> {
    let bytes = s.as_bytes();
    let mut res = Vec::new();
    let mut start = 0usize;
    let mut i = 0usize;
    let mut in_quote = false;
    let mut prev_backslash = false;

    while i < bytes.len() {
        let b = bytes[i];
        if prev_backslash {
            prev_backslash = false;
        } else if b == b'\\' {
            prev_backslash = true;
        } else if b == b'"' {
            in_quote = !in_quote;
        } else if b == b';' && !in_quote {
            res.push(&s[start..i]);
            start = i + 1;
        }
        i += 1;
    }
    // push remaining
    if start <= s.len() {
        res.push(&s[start..]);
    }
    res
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

/// Check whether a quoted-string's unescaped inner content, after trimming,
/// is empty. Returns Ok(true) if the inner content is empty after trimming,
/// Ok(false) if it contains any non-whitespace character, or Err(msg) if the
/// input is not a well-formed quoted-string. This is useful for treating
/// quoted-empty values (e.g., `""` or `"   "`) as empty for presence checks.
pub fn quoted_string_inner_trimmed_is_empty(val: &str) -> Result<bool, String> {
    // Reuse `unescape_quoted_string` to perform unescaping and validation
    match unescape_quoted_string(val) {
        Ok(s) => Ok(s.trim().is_empty()),
        Err(e) => Err(e),
    }
}

/// Unescape a well-formed HTTP `quoted-string` value and return its inner contents.
/// - Input must include surrounding DQUOTE characters (e.g., `"a\"b"`).
/// - Returns `Ok(inner_string)` on success or `Err(msg)` if the input is not a valid quoted-string.
///
/// This helper centralizes quoted-string unescaping to avoid duplication across rules.
pub fn unescape_quoted_string(val: &str) -> Result<String, String> {
    validate_quoted_string(val)?;
    let bytes = val.as_bytes();
    let mut out = String::with_capacity(bytes.len());
    let mut i = 1usize; // skip leading DQUOTE
    let mut prev_backslash = false;
    while i + 1 < bytes.len() {
        let b = bytes[i];
        if prev_backslash {
            out.push(b as char);
            prev_backslash = false;
        } else if b == b'\\' {
            prev_backslash = true;
        } else {
            out.push(b as char);
        }
        i += 1;
    }

    if prev_backslash {
        return Err(format!(
            "Quoted-string ends with escape character: '{}'",
            val
        ));
    }

    Ok(out)
}

/// Validate qvalue syntax: 0, 1, 0.5, 0.123, 1.0, 0.000, etc. up to 3 decimals
pub fn valid_qvalue(s: &str) -> bool {
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

/// Validate an RFC 5987 `ext-value` (e.g. `UTF-8''%e2%82%ac%20rates`).
/// Returns Ok(()) if the value matches the expected pattern and contains
/// only allowed characters/percent-escapes, or Err(msg) describing the
/// problem.
pub fn validate_ext_value(val: &str) -> Result<(), String> {
    // Must contain at least two single quotes separating charset, optional language, and value-chars
    let first_quote = val
        .find('\'')
        .ok_or_else(|| "ext-value missing charset separator".to_string())?;
    let rest = &val[first_quote + 1..];
    let second_quote = rest
        .find('\'')
        .ok_or_else(|| "ext-value missing language separator".to_string())?
        + first_quote
        + 1;

    let charset = &val[..first_quote];
    if charset.is_empty() {
        return Err("charset in ext-value must not be empty".into());
    }
    // Basic charset sanity: must be ASCII and not contain quote
    if !charset.is_ascii() || charset.contains('\'') {
        return Err("invalid charset in ext-value".into());
    }

    // Language part may be empty; we don't strictly validate language tags here
    let value_chars = &val[second_quote + 1..];
    if value_chars.is_empty() {
        // empty value is allowed
        return Ok(());
    }

    let mut i = 0usize;
    let bytes = value_chars.as_bytes();
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%' {
            // Expect two hex digits
            if i + 2 >= bytes.len() {
                return Err("incomplete percent-encoding in ext-value".into());
            }
            let hi = bytes[i + 1];
            let lo = bytes[i + 2];
            if !((hi as char).is_ascii_hexdigit() && (lo as char).is_ascii_hexdigit()) {
                return Err("invalid percent-encoding in ext-value".into());
            }
            i += 3;
            continue;
        }
        let ch = bytes[i] as char;
        // attr-char per RFC 5987: ALPHA / DIGIT / "!" / "#" / "$" / "%" / "&" / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~"
        if ch.is_ascii_alphanumeric()
            || matches!(
                ch,
                '!' | '#' | '$' | '%' | '&' | '+' | '-' | '.' | '^' | '_' | '`' | '|' | '~'
            )
        {
            i += 1;
            continue;
        }
        return Err(format!("invalid character '{}' in ext-value", ch));
    }

    Ok(())
}

/// Validate a mailbox-list per RFC 5322-ish syntax. This is a conservative validator
/// that accepts common mailbox forms used in `From` headers: a comma-separated list
/// of either `addr-spec` (user@example.com) or `display-name <addr-spec>` entries.
/// It does not implement full RFC 5322 parsing (which is complex), but it rejects
/// obvious invalid values such as missing `@`, empty local-part or domain, unbalanced
/// angle brackets, or control characters. Returns Ok(()) on success or Err(msg).
pub fn validate_mailbox_list(val: &str) -> Result<(), String> {
    let s = val.trim();
    if s.is_empty() {
        return Err("From header must not be empty".into());
    }

    // We need to split on top-level commas, respecting quoted-strings and angle-bracketed addr-specs
    let mut parts: Vec<&str> = Vec::new();
    let mut start = 0usize;
    let mut in_quote = false;
    let mut prev_backslash = false;
    let mut angle_depth = 0usize;

    for (i, b) in s.as_bytes().iter().enumerate() {
        match *b {
            b'"' if !prev_backslash => in_quote = !in_quote,
            b'\\' if in_quote && !prev_backslash => prev_backslash = true,
            b',' if !in_quote && angle_depth == 0 => {
                // split here
                let part = s[start..i].trim();
                if !part.is_empty() {
                    parts.push(part);
                }
                start = i + 1;
            }
            b'<' if !in_quote => angle_depth += 1,
            b'>' if !in_quote && angle_depth > 0 => angle_depth -= 1,
            _ => prev_backslash = false,
        }
    }

    // last part
    if start < s.len() {
        let part = s[start..].trim();
        if !part.is_empty() {
            parts.push(part);
        }
    }

    if parts.is_empty() {
        return Err("From header contains no mailboxes".into());
    }

    for p in parts {
        // Validate each mailbox: either contains '<' '>' with addr-spec inside or is addr-spec directly
        if let Some(open) = p.find('<') {
            let close = p.rfind('>');
            let end = match close {
                Some(idx) if idx > open => idx,
                _ => return Err(format!("Malformed angle-addr in mailbox: '{}'", p)),
            };
            let addr = p[open + 1..end].trim();
            if let Err(e) = validate_addr_spec(addr) {
                return Err(format!("Invalid addr-spec '{}': {}", addr, e));
            }
        } else {
            // Bare addr-spec
            if let Err(e) = validate_addr_spec(p) {
                return Err(format!("Invalid addr-spec '{}': {}", p, e));
            }
        }
    }

    Ok(())
}

fn validate_addr_spec(addr: &str) -> Result<(), String> {
    if addr.is_empty() {
        return Err("empty addr-spec".into());
    }

    if addr.starts_with('"') {
        // quoted local-part style: "local"@domain
        if let Some(at_pos) = addr.rfind('@') {
            let local = addr[..at_pos].trim();
            let domain = addr[at_pos + 1..].trim();
            if validate_quoted_string(local).is_err() {
                return Err("invalid quoted local-part".into());
            }
            if domain.is_empty() {
                return Err("empty domain".into());
            }
            if !validate_domain(domain) {
                return Err("invalid domain".into());
            }
            return Ok(());
        }

        return Err("missing '@' in addr-spec".into());
    }

    // Non-quoted local-part
    let parts: Vec<&str> = addr.split('@').collect();
    if parts.len() != 2 {
        return Err("addr-spec must contain a single '@'".into());
    }
    let local = parts[0].trim();
    let domain = parts[1].trim();

    if local.is_empty() {
        return Err("empty local-part".into());
    }
    // local-part must not contain spaces or control chars
    if local.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("invalid characters in local-part".into());
    }
    // disallow leading or trailing dot and consecutive dots
    if local.starts_with('.') || local.ends_with('.') || local.contains("..") {
        return Err("invalid dot placement in local-part".into());
    }

    if domain.is_empty() {
        return Err("empty domain".into());
    }

    if !validate_domain(domain) {
        return Err("invalid domain".into());
    }

    Ok(())
}

fn validate_domain(domain: &str) -> bool {
    let d = domain;
    if d.starts_with('[') && d.ends_with(']') {
        // address-literal - accept without deep validation
        return true;
    }

    // labels separated by '.'
    let labels: Vec<&str> = d.split('.').collect();
    if labels.iter().any(|l| l.is_empty()) {
        return false;
    }
    for lbl in labels {
        // labels may contain letters, digits and hyphen, can't start or end with '-'
        if lbl.starts_with('-') || lbl.ends_with('-') {
            return false;
        }
        if !lbl.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }
    }
    true
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
    let media = parts
        .next()
        .expect("splitn always yields at least one element")
        .trim();
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

/// Return the structured-syntax suffix part of a subtype if present (the part after the last `+`).
/// For example, `ld+json` -> `json`. This is a small helper for rules that need to inspect
/// subtype suffixes. Returns `None` for subtypes with no `+`.
pub fn media_type_subtype_suffix(subtype: &str) -> Option<&str> {
    if let Some(pos) = subtype.rfind('+') {
        Some(&subtype[pos + 1..])
    } else {
        None
    }
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
        }

        let host = &rest[..colon_pos];
        let port = &rest[colon_pos + 1..];
        if host.is_empty() || port.is_empty() {
            return false;
        }
        // Parse and validate port using helper
        return crate::helpers::ipv6::parse_port_str(port).is_some();
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
    fn test_media_type_subtype_suffix() {
        // No suffix
        assert_eq!(media_type_subtype_suffix("html"), None);
        // Common suffix
        assert_eq!(media_type_subtype_suffix("ld+json"), Some("json"));
        // Vendor with suffix
        assert_eq!(media_type_subtype_suffix("vnd.foo+xml"), Some("xml"));
        // Trailing plus (empty suffix)
        assert_eq!(media_type_subtype_suffix("foo+"), Some(""));
        // Multiple plus (take last)
        assert_eq!(media_type_subtype_suffix("a+b+json"), Some("json"));
    }

    #[test]
    fn test_valid_qvalue() {
        assert!(valid_qvalue("1"));
        assert!(valid_qvalue("1.0"));
        assert!(valid_qvalue("1.00"));
        assert!(valid_qvalue("1.000"));
        assert!(valid_qvalue("0"));
        assert!(valid_qvalue("0.5"));
        assert!(valid_qvalue("0.123"));
        assert!(!valid_qvalue("1.0000"));
        assert!(!valid_qvalue("0.1234"));
        assert!(!valid_qvalue("abc"));
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
    fn validate_quoted_string_unescaped_quote_reports_violation() {
        // inner unescaped quote before the terminating quote
        let s = "\"a\"b\""; // "a"b"
        let res = validate_quoted_string(s);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("Unescaped quote"));
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

    #[test]
    fn quoted_string_inner_trimmed_is_empty_true_cases() {
        assert!(quoted_string_inner_trimmed_is_empty("\"\"").unwrap());
        assert!(quoted_string_inner_trimmed_is_empty("\"   \"").unwrap());
    }

    #[test]
    fn unescape_quoted_string_basic_cases() {
        assert_eq!(unescape_quoted_string("\"\"").unwrap(), "");
        assert_eq!(unescape_quoted_string("\"a\"").unwrap(), "a");
        assert_eq!(unescape_quoted_string("\"a\\\"b\"").unwrap(), "a\"b");
        assert_eq!(unescape_quoted_string("\"a\\\\b\"").unwrap(), "a\\b");
    }

    #[test]
    fn unescape_quoted_string_invalid_cases() {
        assert!(unescape_quoted_string("\"unterminated").is_err());
        assert!(unescape_quoted_string("\"bad\x01\"").is_err()); // control char
        assert!(unescape_quoted_string("\"a\"b\"").is_err()); // unescaped quote
    }

    #[test]
    fn quoted_string_inner_trimmed_is_empty_false_and_invalid_cases() {
        assert!(!quoted_string_inner_trimmed_is_empty("\"a\"").unwrap());
        // escaped quote inside is a non-empty inner
        assert!(!quoted_string_inner_trimmed_is_empty("\"\\\"\"").unwrap());
        // unterminated quoted-string is an error
        assert!(quoted_string_inner_trimmed_is_empty("\"unterminated").is_err());
    }

    #[test]
    fn quoted_string_inner_unescaped_quote_reports_error() {
        let s = "\"a\"b\""; // inner unescaped quote before terminating quote
        let r = quoted_string_inner_trimmed_is_empty(s);
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("Unescaped quote"));
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

    #[test]
    fn validate_mailbox_list_common_cases() {
        assert!(validate_mailbox_list("alice@example.com").is_ok());
        assert!(validate_mailbox_list("Alice <alice@example.com>").is_ok());
        assert!(validate_mailbox_list("Alice <alice@example.com>, bob@example.org").is_ok());
        assert!(validate_mailbox_list("\"Quoted\" <\"q\\\"u\"@exa.com>").is_ok());

        assert!(validate_mailbox_list("").is_err());
        assert!(validate_mailbox_list("not-an-email").is_err());
        assert!(validate_mailbox_list("alice@").is_err());
        assert!(validate_mailbox_list("@example.com").is_err());
        assert!(validate_mailbox_list("Alice <alice@example.com").is_err());
    }

    #[test]
    fn validate_addr_spec_quoted_missing_at_reports_violation() {
        // quoted local-part but no '@' should be rejected
        let res = validate_addr_spec("\"local\"");
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("missing '@'"));
    }

    #[test]
    fn validate_addr_spec_quoted_local_with_control_char_reports_violation() {
        // quoted local-part with control character should trigger invalid quoted local-part
        let res = validate_addr_spec("\"bad\x01\"@example.com");
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("invalid quoted local-part"));
    }

    #[test]
    fn validate_addr_spec_invalid_domain_reports_violation() {
        // domain labels can't be empty or start with hyphen
        let res = validate_addr_spec("local@-example.com");
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("invalid domain"));
    }

    #[test]
    fn test_validate_ext_value() {
        // Valid ext-values
        assert!(validate_ext_value("UTF-8''%e2%82%ac%20rates").is_ok());
        assert!(validate_ext_value("iso-8859-1'en'%A3%20rates").is_ok());
        assert!(validate_ext_value("UTF-8''simple-ascii").is_ok());
        assert!(validate_ext_value("UTF-8''").is_ok()); // empty value-chars allowed

        // Invalid: missing quotes
        assert!(validate_ext_value("UTF-8%e2%82%ac").is_err());
        // Invalid: incomplete percent
        assert!(validate_ext_value("UTF-8''%e2%2").is_err());
        // Invalid: bad hex
        assert!(validate_ext_value("UTF-8''%ZZ").is_err());
        // Invalid: invalid attr-char
        assert!(validate_ext_value("UTF-8''hello@world").is_err());
    }

    #[test]
    fn test_split_commas_respecting_quotes() {
        let cases = vec![
            ("a, b, c", vec!["a", "b", "c"]),
            ("token=\"a,b\", other", vec!["token=\"a,b\"", "other"]),
            (r#"token="a\"b",c"#, vec![r#"token="a\"b""#, "c"]),
            (
                "no-cache, foo=bar, token=\"quoted,comma\",baz",
                vec!["no-cache", "foo=bar", "token=\"quoted,comma\"", "baz"],
            ),
            ("", vec![""]),
            ("a,b,", vec!["a", "b", ""]),
            (",,", vec!["", "", ""]),
        ];

        for (input, expected) in cases {
            let got: Vec<String> = split_commas_respecting_quotes(input)
                .iter()
                .map(|s| s.trim().to_string())
                .collect();
            let exp: Vec<String> = expected.iter().map(|s| s.to_string()).collect();
            assert_eq!(got, exp, "input: {:?}", input);
        }
    }

    #[test]
    fn strip_comments_basic_and_nested() {
        // basic comment removal
        let v = "Mozilla/5.0 (compatible; Bot/1.0; +http://example.com)";
        let s = strip_comments(v).unwrap();
        assert_eq!(s.trim(), "Mozilla/5.0");

        // nested comments
        let v2 = "A(B(C)D)E";
        let s2 = strip_comments(v2).unwrap();
        assert_eq!(s2, "AE");
    }

    #[test]
    fn strip_comments_unterminated_reports_error() {
        let v = "Agent (incomplete";
        let res = strip_comments(v);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("Unterminated"));
    }

    #[test]
    fn strip_comments_unmatched_closing_reports_error() {
        let v = "Bad )extra";
        let res = strip_comments(v);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("Unmatched closing"));
    }

    #[test]
    fn strip_comments_escaped_parentheses_outside_comment_are_preserved() {
        // backslash-escaped parentheses should be preserved and not treated as comment delimiters
        let s = strip_comments("Agent\\(1.0\\)").unwrap();
        assert_eq!(s, "Agent(1.0)");
    }

    #[test]
    fn test_split_semicolons_respecting_quotes() {
        let cases = vec![
            ("a; b; c", vec!["a", "b", "c"]),
            (
                "max-age=63072000; includeSubDomains; preload",
                vec!["max-age=63072000", " includeSubDomains", " preload"],
            ),
            ("token=\"a;b\";x", vec!["token=\"a;b\"", "x"]),
            ("a;;b", vec!["a", "", "b"]),
            ("", vec![""]),
            ("a;", vec!["a", ""]),
        ];

        for (input, expected) in cases {
            let got: Vec<String> = split_semicolons_respecting_quotes(input)
                .iter()
                .map(|s| s.trim().to_string())
                .collect();
            let exp: Vec<String> = expected.iter().map(|s| s.trim().to_string()).collect();
            assert_eq!(got, exp, "input: {:?}", input);
        }
    }

    #[test]
    fn test_is_hop_by_hop_header() {
        // builtin hop-by-hop headers (case-insensitive)
        assert!(is_hop_by_hop_header("Connection", None));
        assert!(is_hop_by_hop_header("connection", None));
        assert!(is_hop_by_hop_header("keep-alive", None));
        assert!(!is_hop_by_hop_header("x-foo", None));

        // connection nominates an additional hop-by-hop header
        assert!(is_hop_by_hop_header(
            "X-Special",
            Some("keep-alive, X-Special")
        ));
        // not nominated if not listed
        assert!(!is_hop_by_hop_header("X-Special", Some("keep-alive")));
        // nomination is case-insensitive
        assert!(is_hop_by_hop_header(
            "x-special",
            Some("KEEP-ALIVE, x-special")
        ));
    }

    #[test]
    fn strip_comments_escaped_paren_inside_comment_does_not_end_comment() {
        // an escaped ')' inside a comment should not terminate the comment
        let s = strip_comments("A(B\\)C)D").unwrap();
        assert_eq!(s, "AD");
    }

    #[test]
    fn strip_comments_control_chars_report_error() {
        // control characters (except HTAB) should cause an error
        let v = "Bad\x01Char";
        assert!(strip_comments(v).is_err());
        let v2 = "Bad\x7fChar";
        assert!(strip_comments(v2).is_err());
    }

    #[test]
    fn strip_comments_tabs_allowed() {
        // tabs are allowed in header values
        let s = strip_comments("Agent\t1.0").unwrap();
        assert_eq!(s, "Agent\t1.0");
    }

    #[test]
    fn strip_comments_escaped_backslash_is_preserved() {
        // double backslash should become a single literal backslash and subsequent '(' starts a comment
        let s = strip_comments("Agent\\\\(x)").unwrap();
        assert_eq!(s, "Agent\\");
    }

    #[test]
    fn validate_quoted_string_cases() {
        // valid
        assert!(validate_quoted_string("\"ok\"").is_ok());
        // not quoted
        assert!(validate_quoted_string("noquotes").is_err());
        // unescaped quote inside
        assert!(validate_quoted_string("\"bad\"inner\"").is_err());
        // control character inside
        assert!(validate_quoted_string("\"a\x01b\"").is_err());
        // ends with escape char
        assert!(validate_quoted_string("\"abc\\\"").is_err());
    }

    #[test]
    fn validate_mailbox_list_examples() {
        // valid list
        assert!(validate_mailbox_list("User <user@example.com>, other@example.com").is_ok());
        // missing '@'
        assert!(validate_mailbox_list("userexample.com").is_err());
        // unbalanced angle brackets
        assert!(validate_mailbox_list("Name <user@example.com").is_err());
    }
}
