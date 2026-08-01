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

/// Validate a potential scheme (the characters before a scheme-delimiting ':').
/// Returns `Some(msg)` on invalid scheme, `None` if OK or no scheme present.
pub fn validate_scheme_if_present(s: &str) -> Option<String> {
    // Only a colon in the *first* component can delimit a scheme. A colon is an
    // ordinary path or query character, so the scan stops at the first "/", "?"
    // or "#": past those delimiters a colon is data, not a scheme separator.
    // cite(RFC 3986 § 3.3): "pchar         = unreserved / pct-encoded / sub-delims / ":" / "@""
    // cite(RFC 3986 § 4.2): "A path segment that contains a colon character (e.g., "this:that") cannot be used as the first segment of a relative-path reference, as it would be mistaken for a scheme name."
    let first_component = &s[..s.find(['/', '?', '#']).unwrap_or(s.len())];
    let colon = first_component.find(':')?;

    let scheme = &s[..colon];
    // cite(RFC 3986 § 3.1): "scheme      = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )"
    let mut chars = scheme.chars();
    // `1*` — the production requires a leading ALPHA, so an empty scheme (a
    // value opening with ':') satisfies neither it nor `segment-nz-nc`, which
    // excludes ':' and so cannot start a relative-path reference either.
    let Some(first) = chars.next() else {
        return Some("Invalid scheme in value: scheme must not be empty".into());
    };
    if !first.is_ascii_alphabetic() {
        return Some(format!("Invalid scheme in value: '{}'", scheme));
    }
    for c in chars {
        if !(c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.') {
            return Some(format!("Invalid character '{}' in scheme '{}'", c, scheme));
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
    // The `%x6E %x75 %x6C %x6C` hex literals spell lowercase `null` byte-for-byte,
    // so the comparison is case-sensitive.
    // cite(RFC 6454 § 7.1): "origin-list-or-null = %x6E %x75 %x6C %x6C / origin-list"
    if s_trim == "null" {
        return None;
    }
    // Must be an origin (absolute with no path). The grammar has no path component,
    // which is the whole point of the header: an origin reveals where a request came
    // from without revealing what it was reading.
    // cite(RFC 6454 § 7.1): "serialized-origin = scheme "://" host [ ":" port ]"
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
        // The authority itself — host present, bracketed IPv6 well formed, port
        // numeric and in range, no userinfo — is checked by the shared
        // serialized-origin predicate rather than a second hand-written copy, so
        // the two validators cannot drift apart on what an origin is. A lack of
        // host reports the same generic reason, so callers that inspect the
        // string do not need to handle multiple error forms.
        if !crate::helpers::headers::is_valid_serialized_origin(s_trim) {
            return Some("Origin is not a valid serialized origin".into());
        }
        return None;
    }

    Some("Origin is not a valid serialized origin".into())
}

/// Extract the authority component (host\[:port\]) from a request-target.
///
/// Handles all four request-target forms (RFC 9112 §3.2):
/// - **Absolute-form** (`scheme://host[:port]/path`): returns the authority
///   portion between `://` and the first `/`, `?`, or `#`.
/// - **Authority-form** (`host:port`, used by CONNECT): returns the entire
///   target, since it *is* the authority.
/// - **Origin-form** (`/path`): returns `None` (no authority present).
/// - **Asterisk-form** (`*`): returns `None`.
///
/// The returned value preserves the original casing and includes the port
/// when present (e.g. `"example.com:8080"`).  Userinfo (`user@`) is included
/// if present, since consistency checks must compare the raw values.
pub fn extract_authority_from_request_target(s: &str) -> Option<String> {
    let s_trim = s.trim();

    // cite(RFC 9112 § 3.2, label: request-target forms): "request-target = origin-form / absolute-form / authority-form / asterisk-form"
    if s_trim.is_empty() || s_trim == "*" || s_trim.starts_with('/') {
        return None;
    }

    // Absolute-form: scheme://authority/path...
    if let Some(idx) = s_trim.find("://") {
        let after = &s_trim[idx + 3..];
        // Authority ends at first '/', '?', or '#'
        let end = after.find(&['/', '?', '#'][..]).unwrap_or(after.len());
        let authority = &after[..end];
        if authority.is_empty() {
            None
        } else {
            Some(authority.to_string())
        }
    } else {
        // Authority-form: the entire target is the authority (e.g. CONNECT host:port).
        Some(s_trim.to_string())
    }
}

/// Extract the host portion (without port) from an absolute URI or
/// request-target. Only absolute-form URIs (`scheme://host...`) contain a
/// host; origin-form targets (starting with `/`) and the special `*` or
/// authority-form have no host and will return `None`.
///
/// The returned value is lowercased.  Ports are stripped off, since cookie
/// matching and other rules operate on the hostname alone.
///
/// This helper is primarily used by cookie-related stateful rules and keeps
/// the shared parsing logic in one place.
pub fn extract_host_from_request_target(s: &str) -> Option<String> {
    if let Some(idx) = s.find("://") {
        let after = &s[idx + 3..];
        let host = after
            .split('/')
            .next()
            .unwrap_or("")
            .split(':')
            .next()
            .unwrap_or("");
        if host.is_empty() {
            None
        } else {
            Some(host.to_ascii_lowercase())
        }
    } else {
        None
    }
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

    // cite(RFC 9112 § 3.2, label: request-target forms): "request-target = origin-form / absolute-form / authority-form / asterisk-form"
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

/// Extract the path and query component from a request-target or absolute URI,
/// preserving the query string (but ignoring any fragment).
///
/// - If `s` is an absolute URI (`scheme://host[:port]/path?...`), returns the
///   serialized path and query (e.g., `/foo?x=1`), or `/` (or `/?q=...`) if no
///   path segment is present but a query exists.
/// - If `s` is an origin-form request-target (starts with `/`), returns the
///   path and query portion up to, but not including, the `#` character.
/// - For authority-form (CONNECT) or asterisk-form (`*`) request-targets,
///   returns `None` since they do not carry a path to validate.
pub fn extract_path_and_query_from_request_target(s: &str) -> Option<String> {
    let s_trim = s.trim();

    if s_trim == "*" {
        return None;
    }

    // Absolute-form: find scheme marker '://', then the first '/' after authority
    if let Some(idx) = s_trim.find("://") {
        let after = &s_trim[idx + 3..];
        // find first '/' which marks start of path
        if let Some(pos) = after.find('/') {
            let pathq = &after[pos..];
            // strip fragment only, keep query
            let end = pathq.find('#').unwrap_or(pathq.len());
            return Some(pathq[..end].to_string());
        } else {
            // no '/', path is root, but there still might be a query after authority
            if let Some(qpos) = after.find('?') {
                // include leading '/' plus query
                let q = &after[qpos..];
                let end = q.find('#').unwrap_or(q.len());
                // keep leading '?', so prefix with '/' to yield '/?x=1'
                return Some(format!("/{}", &q[..end]));
            }
            return Some("/".into());
        }
    }

    // Origin-form: must start with '/'
    if s_trim.starts_with('/') {
        // keep query, strip fragment
        let end_idx = s_trim.find('#').unwrap_or(s_trim.len());
        return Some(s_trim[..end_idx].to_string());
    }

    // authority-form (host:port) or unknown forms are not path-bearing
    None
}

/// Parse a query string (the portion after `?`) into a vector of
/// `(name,value)` pairs.  Percent-encoding is **not** decoded; callers can
/// compare values verbatim.  Empty names are permitted (they may appear in
/// malformed URIs) and missing values are treated as empty strings.
///
/// This simple helper is useful when rules need to examine specific
/// parameters without importing a full URI parser dependency.
pub fn parse_query_string(s: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for pair in s.split('&') {
        if pair.is_empty() {
            continue;
        }
        let mut kv = pair.splitn(2, '=');
        let name = kv.next().unwrap_or("").to_string();
        let value = kv.next().unwrap_or("").to_string();
        out.push((name, value));
    }
    out
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
    fn colon_inside_a_path_or_query_is_not_a_scheme_delimiter() {
        // `pchar` admits ':' inside a segment, so these are all well-formed
        // absolute-path references with no scheme at all.
        assert_eq!(validate_scheme_if_present("/foo:bar"), None);
        assert_eq!(validate_scheme_if_present("/v1/entities/x:batchGet"), None);
        assert_eq!(validate_scheme_if_present("/users/urn:uuid:1"), None);
        assert_eq!(validate_scheme_if_present("/a?x=b:c"), None);
        assert_eq!(validate_scheme_if_present("/a#f:g"), None);
        // A colon in the first segment of a relative-path reference *is* read
        // as a scheme, which is why RFC 3986 forbids it there.
        assert!(validate_scheme_if_present("this:that").is_none());
        assert!(validate_scheme_if_present("1this:that").is_some());
    }

    #[test]
    fn empty_scheme_is_rejected() {
        let m = validate_scheme_if_present(":foo").expect("empty scheme must be flagged");
        assert!(m.contains("must not be empty"));
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
    fn extract_host_from_request_target_cases() {
        assert_eq!(
            extract_host_from_request_target("https://Example.COM/path"),
            Some("example.com".into())
        );
        assert_eq!(
            extract_host_from_request_target("http://foo.example.com:8080/"),
            Some("foo.example.com".into())
        );
        assert_eq!(extract_host_from_request_target("/relative/path"), None);
        assert_eq!(extract_host_from_request_target("*"), None);
        assert_eq!(extract_host_from_request_target("example.com:443"), None);
    }

    #[test]
    fn extract_path_and_query_from_request_target_cases() {
        assert_eq!(
            extract_path_and_query_from_request_target("/"),
            Some("/".into())
        );
        assert_eq!(
            extract_path_and_query_from_request_target("/foo/bar?x=1#z"),
            Some("/foo/bar?x=1".into())
        );
        assert_eq!(
            extract_path_and_query_from_request_target("http://example.com/.well-known/foo?x=1"),
            Some("/.well-known/foo?x=1".into())
        );
        assert_eq!(
            extract_path_and_query_from_request_target("https://example.com"),
            Some("/".into())
        );
        assert_eq!(
            extract_path_and_query_from_request_target("https://example.com?x=1"),
            Some("/?x=1".into())
        );
        assert_eq!(extract_path_and_query_from_request_target("*"), None);
        assert_eq!(
            extract_path_and_query_from_request_target("example.com:443"),
            None
        );
    }

    #[test]
    fn parse_query_string_basic() {
        let v = parse_query_string("");
        assert!(v.is_empty());
        let v = parse_query_string("a=1&b=2");
        assert_eq!(
            v,
            vec![
                ("a".to_string(), "1".to_string()),
                ("b".to_string(), "2".to_string())
            ]
        );
        let v = parse_query_string("foo");
        assert_eq!(v, vec![("foo".to_string(), "".to_string())]);
        let v = parse_query_string("x=&=y&z=3");
        assert_eq!(
            v,
            vec![
                ("x".to_string(), "".to_string()),
                ("".to_string(), "y".to_string()),
                ("z".to_string(), "3".to_string()),
            ]
        );
    }
    #[test]
    fn validate_origin_value_cases() {
        assert!(validate_origin_value("null").is_none());
        assert!(validate_origin_value("NULL").is_some());
        assert!(validate_origin_value("https://example.com").is_none());
        assert!(validate_origin_value("http:///bad").is_some());
        assert!(validate_origin_value("https://exa mple").is_some());
        assert!(validate_origin_value("invalid-origin").is_some());
        // The authority is validated too, not merely required to be non-empty.
        assert!(validate_origin_value("http://host:notaport").is_some());
        assert!(validate_origin_value("https://user@example.com").is_some());
        assert!(validate_origin_value("http://example.com:0").is_some());
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
    fn extract_authority_from_request_target_cases() {
        assert_eq!(
            extract_authority_from_request_target("https://example.com/path"),
            Some("example.com".into())
        );
        assert_eq!(
            extract_authority_from_request_target("http://example.com:8080/"),
            Some("example.com:8080".into())
        );
        assert_eq!(
            extract_authority_from_request_target("https://Example.COM:443/path"),
            Some("Example.COM:443".into())
        );
        assert_eq!(
            extract_authority_from_request_target("https://example.com"),
            Some("example.com".into())
        );
        assert_eq!(
            extract_authority_from_request_target("https://example.com?q=1"),
            Some("example.com".into())
        );
        assert_eq!(
            extract_authority_from_request_target("https://[::1]:8080/path"),
            Some("[::1]:8080".into())
        );
        assert_eq!(
            extract_authority_from_request_target("/relative/path"),
            None
        );
        assert_eq!(extract_authority_from_request_target("*"), None);
        // Authority-form (CONNECT): the entire target IS the authority.
        assert_eq!(
            extract_authority_from_request_target("example.com:443"),
            Some("example.com:443".into())
        );
        assert_eq!(
            extract_authority_from_request_target("[::1]:8080"),
            Some("[::1]:8080".into())
        );
        assert_eq!(extract_authority_from_request_target("http://"), None);
        assert_eq!(extract_authority_from_request_target(""), None);
        assert_eq!(extract_authority_from_request_target("  "), None);
    }

    #[test]
    fn validate_origin_missing_host_reports_missing() {
        let m = validate_origin_value("http://").unwrap();
        // we now return the generic "not a valid serialized origin" message for
        // missing authority, rather than a specialized one; callers that care
        // about details should inspect the string content appropriately.
        assert!(m.contains("not a valid serialized origin"));
    }
}
