// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! A request-target: what the four forms name, and what has to be reconstructed
//! because the form does not carry it.
//!
//! **`request-target = origin-form / absolute-form / authority-form /
//! asterisk-form` is why these readers exist at all.** Two of the four forms
//! carry an authority and two do not; three carry a path and one does not. A
//! caller that reaches for a URI parser here gets an answer about a *string*
//! when the question was about a *message*, which is the difference
//! [`target_uri_authority`] exists to make: the authority of the target URI is
//! in the target when the form has one and in `Host` when it does not, and that
//! is the entire reason that field exists.
//!
//! **Nothing here transcribes a component's grammar.** Where an authority ends
//! is [`super::authority::authority_component`]'s § 3.2 sentence, which form a
//! value is in is [`super::scheme::scheme_authority_marker`]'s question, and
//! what a host may hold is the host production's. What this module owns is the
//! reading *per form* — and the one mistake that reading keeps inviting, which
//! every test below is about: a URL carried in a query parameter
//! (`?redirect_uri=`, `?next=`, `?url=`) has a `://` in it, and reading an
//! authority, a host or a path out of that invents an origin the message never
//! had. Those values are attacker-supplied.

use crate::helpers::authority::{authority_component, split_host_and_port, split_userinfo};
use crate::helpers::headers::trim_ows;
use crate::helpers::scheme::scheme_authority_marker;
/// The authority component of the **target URI**, which is not always in the
/// request-target.
///
/// [`extract_authority_from_request_target`] answers the narrower question of
/// what the target *string* carries; only two of its four forms carry an
/// authority at all. The reconstruction is where the missing one comes from:
/// an origin-form or asterisk-form target leaves the authority in `Host`, which
/// is the entire reason that field exists.
///
/// Returns `None` when neither source has one — a target with no authority and
/// no usable `Host` field, where nothing about *which* host was addressed can be
/// concluded and a caller comparing authorities has to say so. Over HTTP/2 and
/// HTTP/3 the question does not arise: `:authority` reaches the capture inside
/// the request-target, so the first branch answers.
///
/// `Host` is a singleton, and §3.3's *"empty or invalid"* is where two field
/// lines land: a message carrying them is one a server must answer with a 400,
/// and reading the first of the two would pick a host by position rather than by
/// anything the sender said. `host_header` reports the message; this
/// helper reports that the authority is unknown, which is what it is.
// cite(RFC 9110 § 7.1): "A URI reference is resolved to its absolute form in order to obtain the "target URI"."
// cite(RFC 9110 § 7.2): "The "Host" header field in a request provides the host and port information from the target URI, enabling the origin server to distinguish among resources while servicing requests for multiple host names."
// cite(RFC 9110 § 7.2): "In HTTP/2 [HTTP/2] and HTTP/3 [HTTP/3], the Host header field is, in some cases, supplanted by the ":authority" pseudo-header field of a request's control data."
// cite(RFC 9112 § 3.3): "The target URI is the request-target when the request-target is in absolute-form."
// cite(RFC 9112 § 3.3): "If the request-target is in authority-form, the target URI's authority component is the request-target.  Otherwise, the target URI's authority component is the field value of the Host header field."
// cite(RFC 9112 § 3.3): "If there is no Host header field or if its field value is empty or invalid, the target URI's authority component is empty."
// cite(RFC 9112 § 3.2): "A server MUST respond with a 400 (Bad Request) status code to any HTTP/1.1 request message that lacks a Host header field and to any request message that contains more than one Host header field line or a Host header field with an invalid field value."
pub fn target_uri_authority(
    request_target: &str,
    request_headers: &hyper::HeaderMap,
) -> Option<String> {
    if let Some(from_target) = extract_authority_from_request_target(request_target) {
        return Some(from_target);
    }
    if request_headers.get_all("host").iter().count() != 1 {
        return None;
    }
    crate::helpers::headers::get_header_str(request_headers, "host")
        .map(|h| trim_ows(h).to_string())
        .filter(|h| !h.is_empty())
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
    let s_trim = trim_ows(s);

    // cite(RFC 9112 § 3.2, label: request-target forms): "request-target = origin-form / absolute-form / authority-form / asterisk-form"
    if s_trim.is_empty() || s_trim == "*" || s_trim.starts_with('/') {
        return None;
    }

    // Absolute-form: scheme://authority/path... Where the authority ends is
    // § 3.2's sentence and [`authority_component`]'s question; a value whose
    // authority is empty names no host, which is what this function's `None`
    // says and what the origin-form and asterisk-form returns above say too.
    //
    // The two readings of the scheme are both wanted here, and they answer
    // different questions. [`scheme_authority_marker`] decides which *form* the
    // target is in, which is all four forms' shared question and the one this
    // branch is selecting on; [`authority_component`] then asks whether the
    // value in that form carries an authority at all. They part on `a:b://c`,
    // where the scheme is `a` and `b://c` is a `path-rootless` — a target in
    // absolute form carrying no authority, which is `None` and not an
    // authority-form target named `a:b://c`.
    if scheme_authority_marker(s_trim).is_some() {
        return authority_component(s_trim)
            .filter(|authority| !authority.is_empty())
            .map(str::to_string);
    }

    // Authority-form: the entire target is the authority (e.g. CONNECT host:port).
    Some(s_trim.to_string())
}

/// Extract the host portion (without port) from an absolute URI or
/// request-target. Only absolute-form URIs (`scheme://host...`) contain a
/// host; origin-form targets (starting with `/`) and the special `*` or
/// authority-form have no host and will return `None`.
///
/// The returned value is lowercased, which is § 6.2.2.1's case normalization
/// and applies to the host and to nothing else in a URI. Ports are stripped
/// off, since cookie matching and other rules operate on the hostname alone.
///
/// **The host is the authority's, and each of the three steps between them is a
/// separate reading.** Where the authority ends is [`authority_component`]'s
/// question and § 3.2's sentence; where the userinfo ends is
/// [`split_userinfo`]'s; where the port begins is [`split_host_and_port`]'s, and
/// that one is why the colon cannot simply be searched for — an `IP-literal` is
/// bracketed and holds colons of its own.
///
/// This helper is primarily used by cookie-related stateful rules and keeps
/// the shared parsing logic in one place.
// cite(RFC 3986 § 3.2.2, label: host grammar): "host        = IP-literal / IPv4address / reg-name"
// cite(RFC 3986 § 6.2.2.1): "the scheme and host are case-insensitive and therefore should be normalized to lowercase"
pub fn extract_host_from_request_target(s: &str) -> Option<String> {
    // Absolute form and only absolute form, which is what the doc above
    // promises: `//host/p` carries an authority to [`authority_component`] and
    // is an origin-form request-target whose path happens to open with two
    // slashes, so the marker is asked first and its offset is not wanted.
    scheme_authority_marker(s)?;
    let (_, host_and_port) = split_userinfo(authority_component(s)?);
    let (host, _) = split_host_and_port(host_and_port);
    if host.is_empty() {
        return None;
    }
    Some(host.to_ascii_lowercase())
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
    let s_trim = trim_ows(s);

    // cite(RFC 9112 § 3.2, label: request-target forms): "request-target = origin-form / absolute-form / authority-form / asterisk-form"
    if s_trim == "*" {
        return None;
    }

    // Absolute-form: find scheme marker '://', then the first '/' after authority
    if let Some(idx) = scheme_authority_marker(s_trim) {
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
    let s_trim = trim_ows(s);

    if s_trim == "*" {
        return None;
    }

    // Absolute-form: find scheme marker '://', then the first '/' after authority
    if let Some(idx) = scheme_authority_marker(s_trim) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::origin::extract_origin_if_absolute;

    #[test]
    fn a_url_in_a_query_parameter_is_not_an_authority() {
        // `?redirect_uri=`, `?next=`, `?url=` carry a whole URL as data. Reading
        // an authority, host or path out of it invents an origin the message
        // never had — and these values are attacker-supplied.
        for target in [
            "/redirect?url=http://evil.example",
            "/a?next=https://evil.example/cb",
            "/oauth/authorize?redirect_uri=https://client.example/cb",
        ] {
            assert_eq!(extract_origin_if_absolute(target), None, "{target}");
            assert_eq!(extract_host_from_request_target(target), None, "{target}");
        }
        // The path extractors must read the real path, not the one inside the
        // query parameter.
        assert_eq!(
            extract_path_from_request_target("/oauth/authorize?redirect_uri=https://c.example/cb"),
            Some("/oauth/authorize".into())
        );
        assert_eq!(
            extract_path_and_query_from_request_target(
                "/oauth/authorize?redirect_uri=https://c.example/cb"
            ),
            Some("/oauth/authorize?redirect_uri=https://c.example/cb".into())
        );
        // A genuine absolute-form target still resolves, query URL and all.
        assert_eq!(
            extract_origin_if_absolute("http://a.example/p?u=http://b.example"),
            Some("http://a.example".into())
        );
        // `path-abempty` may be empty, so the query can follow the authority
        // directly. The origin stops before it.
        assert_eq!(
            extract_origin_if_absolute("http://example.com?x=1"),
            Some("http://example.com".into())
        );
        assert_eq!(
            extract_origin_if_absolute("http://example.com#f"),
            Some("http://example.com".into())
        );
        // The two authority readers must agree on where an authority ends.
        for target in [
            "http://example.com?x=1",
            "http://example.com#f",
            "http://example.com/p?x=1",
            "http://example.com:8080?x=1",
        ] {
            let origin = extract_origin_if_absolute(target).expect(target);
            let authority = extract_authority_from_request_target(target).expect(target);
            assert_eq!(origin, format!("http://{authority}"), "{target}");
        }
        // "://" with nothing before it is not a scheme.
        assert_eq!(extract_origin_if_absolute("://example.com"), None);
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

    /// The four values the `/`-terminated, first-colon reading answered wrongly.
    /// Each is what a cookie rule compares a `Domain` attribute against, so each
    /// was a host the message never named.
    #[test]
    fn the_host_is_the_authoritys_and_stops_where_section_3_2_says() {
        // `path-abempty` may be empty, so the authority can end at a '?' or a
        // '#'; terminating on '/' alone glued the query onto the host.
        assert_eq!(
            extract_host_from_request_target("http://example.com?x=1"),
            Some("example.com".into())
        );
        assert_eq!(
            extract_host_from_request_target("http://example.com#f"),
            Some("example.com".into())
        );
        // An `IP-literal` is bracketed and holds colons of its own, so the port
        // is not at the first one. This used to be the host `[`.
        assert_eq!(
            extract_host_from_request_target("http://[2001:db8::1]:8080/p"),
            Some("[2001:db8::1]".into())
        );
        assert_eq!(
            extract_host_from_request_target("http://[::1]/p"),
            Some("[::1]".into())
        );
        // A userinfo is a subcomponent of the authority and not of the host; its
        // own colon used to be read as the port delimiter, making the host
        // `user`.
        assert_eq!(
            extract_host_from_request_target("http://user:pass@example.com/p"),
            Some("example.com".into())
        );
        assert_eq!(
            extract_host_from_request_target("http://user@Example.com/p"),
            Some("example.com".into())
        );
        // An empty authority carries no host to compare, and neither does a
        // value whose authority is absent.
        assert_eq!(extract_host_from_request_target("http:///p"), None);
        assert_eq!(extract_host_from_request_target("http:/p"), None);
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
    fn target_uri_authority_reconstructs_from_host_when_the_target_has_none() {
        let host = |lines: &[&str]| {
            let mut h = hyper::HeaderMap::new();
            for l in lines {
                h.append(
                    hyper::header::HeaderName::from_static("host"),
                    hyper::header::HeaderValue::from_str(l).expect("a test Host value"),
                );
            }
            h
        };

        // Origin-form and asterisk-form carry no authority; Host does.
        assert_eq!(
            target_uri_authority("/path", &host(&["example.com:8080"])),
            Some("example.com:8080".into())
        );
        assert_eq!(
            target_uri_authority("*", &host(&["example.com"])),
            Some("example.com".into())
        );

        // The request-target wins when it has one, whatever Host says — that is
        // the order §3.3 states, and it is how an HTTP/2 `:authority` arrives.
        assert_eq!(
            target_uri_authority("http://origin.example/path", &host(&["other.example"])),
            Some("origin.example".into())
        );

        // Nothing to reconstruct from.
        assert_eq!(target_uri_authority("/path", &host(&[])), None);
        assert_eq!(target_uri_authority("/path", &host(&[""])), None);
        assert_eq!(target_uri_authority("/path", &host(&["   "])), None);

        // A singleton written twice: §3.2 makes the message one a server answers
        // with a 400, and neither line is the authority.
        assert_eq!(
            target_uri_authority("/path", &host(&["a.example", "b.example"])),
            None
        );
    }
}
