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
}
