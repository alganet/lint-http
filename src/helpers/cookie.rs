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

/// Representation of a parsed `Set-Cookie` value and some derived metadata.
#[derive(Debug, Clone)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    /// Effective cookie domain (host-only, lowercased, no leading dot)
    pub domain: String,
    /// Effective path attribute
    pub path: String,
    pub secure: bool,
    /// Expiration time, if known (computed from Max-Age or Expires).  A value
    /// less-or-equal to the transaction timestamp is treated as expired.
    pub expiration: Option<chrono::DateTime<chrono::Utc>>,
}

impl Cookie {
    /// Returns `true` if the cookie is considered expired at `when`.
    pub fn is_expired_at(&self, when: chrono::DateTime<chrono::Utc>) -> bool {
        if let Some(exp) = self.expiration {
            exp <= when
        } else {
            false
        }
    }

    /// Simple domain-match check following RFC 6265 §5.1.3.  Only the host
    /// portion of the request URI should be supplied (no port).
    pub fn domain_matches(&self, request_host: &str) -> bool {
        let req = request_host.to_ascii_lowercase();
        let dom = self.domain.as_str();
        if req == dom {
            true
        } else {
            req.ends_with(&format!(".{}", dom))
        }
    }

    /// Path-match per RFC 6265 §5.1.4.  `request_path` should be the path
    /// component extracted from the request-target (leading '/' or "/").
    pub fn path_matches(&self, request_path: &str) -> bool {
        let cookie_path = self.path.as_str();
        // RFC 6265 §5.1.4:
        // 1. If the cookie-path and the request-path are identical, the
        //    path-matches.
        if request_path == cookie_path {
            return true;
        }
        // 2. If the cookie-path is a prefix of the request-path, and either
        //    the last character of the cookie-path is %x2F ("/") or the
        //    character following the cookie-path in the request-path is %x2F
        //    ("/"), then the path-matches.
        if !request_path.starts_with(cookie_path) {
            return false;
        }
        if cookie_path.ends_with('/') {
            return true;
        }
        matches!(request_path.as_bytes().get(cookie_path.len()), Some(b'/'))
    }
}

/// Parse a `Set-Cookie` header value into a `Cookie` struct, using the
/// request URI and timestamp to derive default domain/path and compute
/// expiration.  Returns `None` if the value cannot be parsed at all.
pub fn parse_set_cookie(
    header_value: &str,
    request_uri: &str,
    timestamp: chrono::DateTime<chrono::Utc>,
) -> Option<Cookie> {
    let parts: Vec<&str> = header_value.split(';').map(|p| p.trim()).collect();
    if parts.is_empty() || parts[0].is_empty() {
        return None;
    }

    let pair = parts[0];
    let mut kv = pair.splitn(2, '=');
    let name = kv.next()?.trim().to_string();
    let value = kv.next().unwrap_or("").trim().to_string();

    let mut domain_attr: Option<String> = None;
    let mut path_attr: Option<String> = None;
    let mut secure = false;
    let mut max_age: Option<i64> = None;
    let mut expires_attr: Option<chrono::DateTime<chrono::Utc>> = None;

    for attr in parts.iter().skip(1) {
        if attr.is_empty() {
            continue;
        }
        let mut av = attr.splitn(2, '=');
        let key = av.next().unwrap().trim().to_ascii_lowercase();
        let val_opt = av.next().map(|v| v.trim());
        match key.as_str() {
            "domain" => {
                if let Some(v) = val_opt {
                    // cookie domains ignore leading dot per modern spec
                    let d = v.trim_start_matches('.').to_ascii_lowercase();
                    domain_attr = Some(d);
                }
            }
            "path" => {
                if let Some(v) = val_opt {
                    // RFC 6265 §5.2.4: if the attribute-value does not start
                    // with "/", the user agent SHOULD ignore the attribute and
                    // use the default-path instead.  We mirror that behaviour by
                    // only assigning when the value is syntactically valid.
                    if v.starts_with('/') {
                        path_attr = Some(v.to_string());
                    }
                }
            }
            "secure" => {
                secure = true;
            }
            "max-age" => {
                if let Some(v) = val_opt {
                    if let Ok(n) = v.parse::<i64>() {
                        max_age = Some(n);
                    }
                }
            }
            "expires" => {
                if let Some(v) = val_opt {
                    if let Ok(dt) = crate::http_date::parse_http_date_to_datetime(v) {
                        expires_attr = Some(dt);
                    }
                }
            }
            _ => {}
        }
    }

    // Determine default domain from request URI (host portion)
    let default_domain = if let Some(idx) = request_uri.find("://") {
        let after = &request_uri[idx + 3..];
        let hostport = after.split('/').next().unwrap_or("");
        hostport
            .split(':')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase()
    } else {
        // if we can't parse the URI, fall back to empty so rule later will
        // not match anything
        "".to_string()
    };

    let domain = domain_attr.unwrap_or(default_domain);

    // determine default path per RFC 6265 §5.1.4
    let default_path =
        if let Some(p) = crate::helpers::uri::extract_path_from_request_target(request_uri) {
            if !p.starts_with('/') {
                "/".into()
            } else {
                // if path contains no more than one '/', default is '/'
                let slash_count = p.matches('/').count();
                if slash_count <= 1 {
                    "/".into()
                } else {
                    // strip everything after the right-most '/'
                    if let Some(pos) = p.rfind('/') {
                        if pos == 0 {
                            "/".into()
                        } else {
                            p[..pos].to_string()
                        }
                    } else {
                        "/".into()
                    }
                }
            }
        } else {
            "/".into()
        };

    let path = path_attr.unwrap_or(default_path);

    // compute expiration time from Max-Age or Expires
    let expiration = if let Some(n) = max_age {
        // treat non-positive as already expired
        if n <= 0 {
            Some(timestamp)
        } else {
            Some(timestamp + chrono::Duration::seconds(n))
        }
    } else {
        expires_attr
    };

    Some(Cookie {
        name,
        value,
        domain,
        path,
        secure,
        expiration,
    })
}

/// Parse a `Cookie` request header value into name/value pairs.
/// Does not attempt to enforce stronger syntax rules; caller should trim.
pub fn parse_cookie_header(s: &str) -> Vec<(String, String)> {
    s.split(';')
        .filter_map(|piece| {
            let mut kv = piece.splitn(2, '=');
            let name = kv.next()?.trim().to_string();
            let value = kv.next().unwrap_or("").trim().to_string();
            Some((name, value))
        })
        .collect()
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
    #[test]
    fn parse_cookie_header_basic() {
        let vals = parse_cookie_header("a=1; b=two;empty=");
        assert_eq!(
            vals,
            vec![
                ("a".into(), "1".into()),
                ("b".into(), "two".into()),
                ("empty".into(), "".into()),
            ]
        );
    }

    #[test]
    fn parse_set_cookie_defaults_and_attributes() {
        // basic name/value and default domain/path from a multi-segment URI
        let ts = chrono::Utc::now();
        let c = parse_set_cookie("SID=abc123", "https://example.com/foo/bar", ts).unwrap();
        assert_eq!(c.name, "SID");
        assert_eq!(c.value, "abc123");
        assert_eq!(c.domain, "example.com");
        assert_eq!(c.path, "/foo".to_string());
        assert!(!c.secure);
        assert!(c.expiration.is_none());

        // default path when request path has only root
        let c0 = parse_set_cookie("x=1", "https://example.com/", ts).unwrap();
        assert_eq!(c0.path, "/");

        // explicit domain and path, secure, max-age
        let c2 = parse_set_cookie(
            "id=1; Domain=EXAMPLE.com; Path=/; Secure; Max-Age=10",
            "https://example.com/anything",
            ts,
        )
        .unwrap();
        assert_eq!(c2.domain, "example.com");
        assert_eq!(c2.path, "/");
        assert!(c2.secure);
        assert!(c2.expiration.is_some());
        assert!(c2.expiration.unwrap() > ts);

        // path attribute that doesn't start with slash should be ignored and
        // default-path applied instead (RFC 6265 §5.2.4).
        let c3 = parse_set_cookie(
            "foo=bar; Path=not/a/slash",
            "https://example.com/some/path",
            ts,
        )
        .unwrap();
        // default-path of /some
        assert_eq!(c3.path, "/some");
    }

    #[test]
    fn cookie_domain_path_matching() {
        let ts = chrono::Utc::now();
        let base = parse_set_cookie(
            "a=1; Domain=example.com; Path=/sub",
            "https://example.com/",
            ts,
        )
        .unwrap();
        // hostname equal
        assert!(base.domain_matches("example.com"));
        // subdomain suffix
        assert!(base.domain_matches("foo.example.com"));
        assert!(!base.domain_matches("other.com"));
        // path prefix
        assert!(base.path_matches("/sub/page"));
        assert!(!base.path_matches("/other"));
    }

    #[test]
    fn cookie_expiration_checks() {
        let ts = chrono::Utc::now();
        let c = parse_set_cookie("x=1; Max-Age=1", "https://example.com/", ts).unwrap();
        assert!(!c.is_expired_at(ts));
        assert!(c.is_expired_at(ts + chrono::Duration::seconds(2)));
        let c2 = parse_set_cookie("y=1; Max-Age=0", "https://example.com/", ts).unwrap();
        assert!(c2.is_expired_at(ts));
        // expires attribute parsing using httpdate formatting
        let exp_str = httpdate::fmt_http_date(std::time::SystemTime::now());
        let header = format!("z=1; Expires={}", exp_str);
        let c3 = parse_set_cookie(&header, "https://example.com/", ts).unwrap();
        assert!(c3.expiration.is_some());
    }

    #[test]
    fn parse_set_cookie_bad_uri_domain() {
        let ts = chrono::Utc::now();
        let c = parse_set_cookie("n=1", "not-a-uri", ts).unwrap();
        // domain falls back to empty string
        assert_eq!(c.domain, "");
    }
}
