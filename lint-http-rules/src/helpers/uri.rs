// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Small reusable helpers for URI-ish checks used by several rules.

/// Check percent-encoding runs inside a string. Returns `Some(msg)` describing the
/// first problem found, or `None` if all percent-encodings look well-formed.
///
/// The triplet is the whole production: a '%' obliges exactly two hex digits,
/// which is why a short run at the end of the string and a run with a non-hex
/// digit are reported separately rather than as one "malformed" verdict.
// cite(RFC 3986 § 2.1): "pct-encoded = "%" HEXDIG HEXDIG"
// cite(RFC 3986 § 2.1): "A percent-encoded octet is encoded as a character triplet, consisting of the percent character "%" followed by the two hexadecimal digits representing that octet's numeric value."
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
            // Both cases of the six letter digits derive from `HEXDIG`, whose
            // alternatives are quoted strings and so case-insensitive, and § 2.1
            // says the same of these digits directly -- two URIs differing only
            // in that case are one URI. The recommendation beside it, to prefer
            // uppercase, is a consistency one and is declined where a caller
            // publishes its findings.
            // cite(RFC 5234 § 2.3): "ABNF strings are case insensitive and the character set for these strings is US-ASCII."
            // cite(RFC 3986 § 2.1): "The uppercase hexadecimal digits 'A' through 'F' are equivalent to the lowercase digits 'a' through 'f', respectively."
            // cite(RFC 3986 § 2.1): "If two URIs differ only in the case of hexadecimal digits used in percent-encoded octets, they are equivalent."
            if !hi.is_ascii_hexdigit() || !lo.is_ascii_hexdigit() {
                // Take three *characters*, not three bytes. The bytes after '%'
                // are non-hex precisely here, which is when they may be the lead
                // or continuation bytes of a multi-byte character — slicing to
                // `i + 3` would cut one in half and panic. `i` is always at a '%'
                // and so always on a character boundary.
                let seq: String = s[i..].chars().take(3).collect();
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

/// The first character of `s` that no `URI-reference` admits, or `None` when
/// every character is one a URI may be written with.
///
/// The set is the union of `unreserved`, `gen-delims` and `sub-delims` plus the
/// `"%"` that opens a `pct-encoded` triplet — every terminal reachable from
/// `URI-reference`, since each component rule of the generic syntax lists a
/// subset of those characters and nothing outside them. So this answers only the
/// *alphabet* question; whether a character sits where its component allows it,
/// and whether a `%` is followed by two `HEXDIG`, are
/// [`check_percent_encoding`]'s and the component rules' questions.
///
/// Deliberately narrower than "is this visible US-ASCII": `<`, `>`, `"`, `{`,
/// `}`, `|`, `\`, `^`, `` ` `` and SP are all VCHAR or SP and none of them is a
/// URI character. Every octet outside the set has to be percent-encoded before
/// the URI is formed, which is what makes the finding actionable.
// cite(RFC 3986 § 2): "A URI is composed from a limited set of characters consisting of digits, letters, and a few graphic symbols."
// cite(RFC 3986 § 2.1): "A percent-encoding mechanism is used to represent a data octet in a component when that octet's corresponding character is outside the allowed set or is being used as a delimiter of, or within, the component."
// cite(RFC 3986 § 2.2): "A component's ABNF syntax rule will not use the reserved or gen-delims rule names directly; instead, each syntax rule lists the characters allowed within that component (i.e., not delimiting it), and any of those characters that are also in the reserved set are "reserved" for use as subcomponent delimiters within the component."
pub fn find_non_uri_char(s: &str) -> Option<char> {
    s.chars().find(|&c| !is_uri_char(c))
}

/// Whether `c` is one of the characters a URI is composed from.
// cite(RFC 3986 § 2.3): "unreserved  = ALPHA / DIGIT / "-" / "." / "_" / "~""
// cite(RFC 3986 § 2.2): "gen-delims  = ":" / "/" / "?" / "#" / "[" / "]" / "@""
// cite(RFC 3986 § 2.2): "sub-delims  = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "=""
// cite(RFC 3986 § 2.1): "pct-encoded = "%" HEXDIG HEXDIG"
fn is_uri_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(c, '-' | '.' | '_' | '~')
        || matches!(c, ':' | '/' | '?' | '#' | '[' | ']' | '@')
        || matches!(
            c,
            '!' | '$' | '&' | '\'' | '(' | ')' | '*' | '+' | ',' | ';' | '='
        )
        || c == '%'
}

/// The characters a value offers as its scheme — everything before the colon
/// that delimits one — or `None` when the value offers none.
///
/// Only a colon in the *first* component can delimit a scheme. A colon is an
/// ordinary path or query character, so the scan stops at the first "/", "?"
/// or "#": past those delimiters a colon is data, not a scheme separator.
///
/// Whether what it returns *is* a scheme name is [`validate_scheme_name`]'s
/// question, and the two are separate because a caller often needs the name
/// itself — which of the two alternatives of a grammar the value took, or
/// which scheme's rules apply to the authority beside it.
// cite(RFC 3986 § 3.3): "pchar         = unreserved / pct-encoded / sub-delims / ":" / "@""
// cite(RFC 3986 § 4.2): "A path segment that contains a colon character (e.g., "this:that") cannot be used as the first segment of a relative-path reference, as it would be mistaken for a scheme name."
pub fn scheme_prefix(s: &str) -> Option<&str> {
    let first_component = &s[..s.find(['/', '?', '#']).unwrap_or(s.len())];
    let colon = first_component.find(':')?;
    Some(&s[..colon])
}

/// Validate a potential scheme (the characters before a scheme-delimiting ':').
/// Returns `Some(msg)` on invalid scheme, `None` if OK or no scheme present.
pub fn validate_scheme_if_present(s: &str) -> Option<String> {
    // The production itself is [`validate_scheme_name`]'s and finding the
    // candidate is [`scheme_prefix`]'s. This function is only the pairing of
    // the two; what a scheme name may be made of is one question with one
    // answer, and it was written out twice here before that function existed.
    //
    // An empty scheme (a value opening with ':') satisfies neither `scheme`, whose
    // `ALPHA` is not optional, nor `segment-nz-nc`, which excludes ':' and so
    // cannot start a relative-path reference either.
    validate_scheme_name(scheme_prefix(s)?)
        .err()
        .map(|e| format!("Invalid scheme in value: {}", e))
}

/// Split an authority into its `userinfo` subcomponent and the `host [ ":" port ]`
/// that follows the `@`, with the delimiter itself discarded.
///
/// The split is at the **last** `@`, and that is not a tolerance: neither
/// `userinfo` nor `reg-name` admits an at-sign, so an authority the grammar
/// generates holds at most one. Taking the last leaves the host half — the one
/// a caller goes on to measure — as short as the value allows, so a second
/// at-sign is reported as part of the userinfo rather than as a host character.
// cite(RFC 3986 § 3.2, label: authority grammar): "authority   = [ userinfo "@" ] host [ ":" port ]"
// cite(RFC 3986 § 3.2.1): "userinfo    = *( unreserved / pct-encoded / sub-delims / ":" )"
// cite(RFC 3986 § 3.2.1): "The user information, if present, is followed by a commercial at-sign ("@") that delimits it from the host."
pub fn split_userinfo(authority: &str) -> (Option<&str>, &str) {
    match authority.rfind('@') {
        Some(at) => (Some(&authority[..at]), &authority[at + 1..]),
        None => (None, authority),
    }
}

/// The `authority` a URI reference carries, or `None` when it carries none.
///
/// § 3.2's sentence is the whole of this function, in both directions: the
/// component is *preceded* by a double slash and *terminated* by the next "/",
/// "?" or "#" character, or by the end of the value. The two slashes are what
/// the search is for, and a scheme in front of them is optional — both
/// alternatives of the generic syntax that reach an authority open with them
/// and only with them, `hier-part` and `relative-part` each writing
/// `"//" authority path-abempty`.
///
/// **`Some("")` is an authority; `None` is the absence of one.** `host` may be
/// a `reg-name`, which is `*( ... )`, so `http://` carries an empty authority
/// where `http:/path` carries none — and RFC 9110 § 4.2.1's and § 4.2.2's MUST
/// NOTs are about exactly the first of those, which is why the empty one is
/// returned rather than folded away here. A caller that compares one authority
/// against another has nothing to compare in that case and folds it itself;
/// [`reference_authority`] is that caller, and says so at its own site.
///
/// The `//` must follow the scheme's colon immediately, which is why the scheme
/// is taken with [`scheme_prefix`] rather than by looking for a `://`: in
/// `a:b://c` the scheme is `a` and `b://c` is a `path-rootless`, so the value
/// carries no authority at all.
// cite(RFC 3986 § 4.3, label: absolute-URI): "absolute-URI  = scheme ":" hier-part [ "?" query ]"
// cite(RFC 3986 § 3): "hier-part   = "//" authority path-abempty / path-absolute / path-rootless / path-empty"
// cite(RFC 3986 § 4.2, label: relative-part): "relative-part = "//" authority path-abempty / path-absolute / path-noscheme / path-empty"
// cite(RFC 3986 § 3.2): "The authority component is preceded by a double slash ("//") and is terminated by the next slash ("/"), question mark ("?"), or number sign ("#") character, or by the end of the URI."
// cite(RFC 3986 § 3.2.2): "reg-name    = *( unreserved / pct-encoded / sub-delims )"
pub fn authority_component(value: &str) -> Option<&str> {
    let after_slashes = match scheme_prefix(value) {
        Some(scheme) => value[scheme.len() + 1..].strip_prefix("//")?,
        None => value.strip_prefix("//")?,
    };
    let end = after_slashes
        .find(['/', '?', '#'])
        .unwrap_or(after_slashes.len());
    Some(&after_slashes[..end])
}

/// Byte offset of the `://` that separates a scheme from an authority, or
/// `None` when the value is not in absolute form.
///
/// A bare `s.find("://")` is not that test. `://` occurring later in a value is
/// ordinary data — a URL carried in a query parameter (`?redirect_uri=`,
/// `?next=`, `?url=`) is the everyday case — and reading an authority out of it
/// invents an origin the message never had. Everything before a real marker is
/// the scheme, which admits no component delimiter and is never empty.
///
/// Public because a caller that wants the *question* — is this value in
/// absolute form — and not the origin cannot ask
/// [`extract_origin_if_absolute`]: that function answers `None` both for a
/// value with no scheme and for an absolute-form value whose scheme or
/// authority is the finding, and the two need opposite treatment. Reaching for
/// `contains("://")` instead is what the paragraph above is about, and it was
/// written twice in one rule before this was exposed.
// cite(RFC 3986 § 3.1): "scheme      = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )"
pub fn scheme_authority_marker(s: &str) -> Option<usize> {
    let idx = s.find("://")?;
    if idx == 0 || s[..idx].contains(['/', '?', '#']) {
        return None;
    }
    Some(idx)
}

/// If `s` is an absolute-form request-target or full URI, return the origin
/// component as `scheme://host[:port]`. Returns `None` if input is not absolute
/// or if it does not contain a valid origin.
pub fn extract_origin_if_absolute(s: &str) -> Option<String> {
    // An origin is a scheme, the `://` between them, and an authority — so it is
    // rebuilt from its two parts rather than sliced out of the value by
    // arithmetic over their lengths. Where the authority ends is
    // [`authority_component`]'s question and § 3.2's sentence: `path-abempty`
    // may be empty, so `http://example.com?x=1` is a legal absolute-form target
    // whose authority ends before the query.
    //
    // Requiring a scheme is what makes this *absolute*-form only. A network-path
    // reference carries an authority and no scheme, and it has no origin.
    let scheme = scheme_prefix(s)?;
    let authority = authority_component(s)?;
    if authority.is_empty() {
        return None;
    }
    let origin = format!("{scheme}://{authority}");

    // Basic validation: scheme valid, no whitespace
    if validate_scheme_if_present(&origin).is_some() {
        return None;
    }
    if contains_whitespace(&origin) {
        return None;
    }
    Some(origin)
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
    if let Some(colon_pos) = scheme_authority_marker(s_trim) {
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
/// anything the sender said. `client_host_header` reports the message; this
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
        .map(|h| h.trim().to_string())
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
    let s_trim = s.trim();

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
    let s_trim = s.trim();

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
    let s_trim = s.trim();

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

/// Split a path-and-query string into its path and its query, where the query
/// keeps its leading `?`. An absent query is `""`, distinguishing it from a
/// present-but-empty one (`"?"`), which reference resolution treats differently.
fn split_at_query(path_and_query: &str) -> (&str, &str) {
    match path_and_query.find('?') {
        Some(i) => (&path_and_query[..i], &path_and_query[i..]),
        None => (path_and_query, ""),
    }
}

/// Drop the last segment of an already-emitted output buffer, per step 2C of
/// the `remove_dot_segments` routine.
fn pop_last_segment(output: &mut String) {
    match output.rfind('/') {
        Some(pos) => output.truncate(pos),
        None => output.clear(),
    }
}

/// Remove the complete `.` and `..` path segments from `path`.
///
/// This is RFC 3986 §5.2.4's `remove_dot_segments` routine, transcribed
/// step for step; the input buffer is `input` and the output buffer is `output`.
// cite(RFC 3986 § 5.2.4): "This is done after the path is extracted from a reference, whether or not the path was relative, in order to remove any invalid or extraneous dot-segments prior to forming the target URI."
pub fn remove_dot_segments(path: &str) -> String {
    let mut input = path.to_string();
    let mut output = String::new();

    while !input.is_empty() {
        // 2A — a leading "../" or "./" on a relative path resolves above the
        // root and is simply dropped.
        if let Some(rest) = input.strip_prefix("../") {
            input = rest.to_string();
        } else if let Some(rest) = input.strip_prefix("./") {
            input = rest.to_string();
        // 2B — "/./" and a trailing "/." collapse to "/".
        } else if let Some(rest) = input.strip_prefix("/./") {
            input = format!("/{rest}");
        } else if input == "/." {
            input = "/".to_string();
        // 2C — "/../" and a trailing "/.." collapse to "/" and additionally
        // remove the last segment already written out.
        } else if let Some(rest) = input.strip_prefix("/../") {
            input = format!("/{rest}");
            pop_last_segment(&mut output);
        } else if input == "/.." {
            input = "/".to_string();
            pop_last_segment(&mut output);
        // 2D — a bare "." or ".." is the whole remaining path; drop it.
        } else if input == "." || input == ".." {
            input.clear();
        // 2E — move the first path segment, including its leading "/" if any,
        // to the output buffer.
        } else {
            let after_leading_slash = usize::from(input.starts_with('/'));
            let seg_end = input[after_leading_slash..]
                .find('/')
                .map(|p| p + after_leading_slash)
                .unwrap_or(input.len());
            output.push_str(&input[..seg_end]);
            input = input[seg_end..].to_string();
        }
    }

    output
}

/// One URI component with § 6.2.2's two percent-encoding normalizations applied:
/// every triplet standing for an `unreserved` character written as that
/// character, and the hexadecimal of every triplet that stays encoded in upper
/// case.
///
/// **Only `unreserved`, and § 2.4 is why.** Decoding a `gen-delims` or a
/// `sub-delims` octet moves where the component boundaries are — `%2F` inside a
/// segment is data, and `/` between two segments is not the same thing — so a
/// caller handing a whole path to a decoder that took every triplet would get
/// back a string whose structure the sender never wrote. That is the exact
/// inverse of the decision at
/// `server_alt_svc_protocol_iana_registered::alpn_protocol_name`, which decodes
/// **every** triplet because RFC 7301 § 3.1 makes an ALPN protocol name an
/// opaque octet sequence with no components for a delimiter to bound. One
/// question, two answers, both cited; the two functions must not be folded.
///
/// **The second normalization is free here and required at one caller.** A
/// triplet this leaves encoded is still put in one form, which is what lets two
/// authorities that differ only in `%2f` versus `%2F` compare equal. The other
/// caller compares against a literal made of `unreserved` characters, where a
/// surviving triplet can never match whatever its case — so applying § 6.2.2.1
/// cannot change its verdict, and having one function is worth more than having
/// two that differ by a `format!`.
///
/// The walk is over `char`s and not over `str::as_bytes`, because callers hand
/// this a value carrying one `char` per octet: an octet at or above %x80 is a
/// single `char` here and two UTF-8 bytes, and a byte walk would take it apart
/// into two octets that were never on the wire. The two characters after a `%`
/// are tested for being hexadecimal before they are read as a number, because
/// `from_str_radix` accepts a leading `+` and no `pct-encoded` does.
///
/// **Not part of [`normalize_path_and_query`], which is § 6.2.2's *third*
/// normalization and named for all of them.** Folding this into it would widen
/// what every one of that function's callers compares.
// cite(RFC 3986 § 2.3): "unreserved  = ALPHA / DIGIT / "-" / "." / "_" / "~""
// cite(RFC 3986 § 2.3): "URIs that differ in the replacement of an unreserved character with its corresponding percent-encoded US-ASCII octet are equivalent"
// cite(RFC 3986 § 6.2.2.2): "These URIs should be normalized by decoding any percent-encoded octet that corresponds to an unreserved character, as described in Section 2.3."
// cite(RFC 3986 § 6.2.2.1): "For all URIs, the hexadecimal digits within a percent-encoding triplet (e.g., "%3a" versus "%3A") are case-insensitive and therefore should be normalized to use uppercase letters for the digits A-F."
// cite(RFC 3986 § 2.4): "When a URI is dereferenced, the components and subcomponents significant to the scheme-specific dereferencing process (if any) must be parsed and separated before the percent-encoded octets within those components can be safely decoded, as otherwise the data may be mistaken for component delimiters."
pub fn decode_unreserved(component: &str) -> String {
    let chars: Vec<char> = component.chars().collect();
    let mut out = String::with_capacity(component.len());
    let mut i = 0;

    while i < chars.len() {
        let octet = (chars[i] == '%' && i + 2 < chars.len())
            .then(|| {
                let hex: String = chars[i + 1..i + 3].iter().collect();
                hex.chars()
                    .all(|c| c.is_ascii_hexdigit())
                    .then(|| u8::from_str_radix(&hex, 16).ok())
                    .flatten()
            })
            .flatten();

        match octet {
            Some(octet)
                if octet.is_ascii_alphanumeric() || matches!(octet, b'-' | b'.' | b'_' | b'~') =>
            {
                out.push(octet as char);
                i += 3;
            }
            Some(octet) => {
                out.push('%');
                out.push_str(&format!("{:02X}", octet));
                i += 3;
            }
            None => {
                out.push(chars[i]);
                i += 1;
            }
        }
    }

    out
}

/// Apply syntax-based normalization to a path-and-query string: dot-segments
/// go, the query is carried through untouched.
///
/// Comparing two URIs that differ only in dot-segments as if they were
/// different resources is the mistake §6.2.2.3 calls out by name.
// cite(RFC 3986 § 6.2.2.3): "URI normalizers should remove dot-segments by applying the remove_dot_segments algorithm to the path, as described in Section 5.2.4."
pub fn normalize_path_and_query(path_and_query: &str) -> String {
    let (path, query) = split_at_query(path_and_query);
    format!("{}{}", remove_dot_segments(path), query)
}

/// Merge a relative-path reference with the path of the base URI, per RFC 3986
/// §5.2.3.
fn merge_paths(base_path: &str, ref_path: &str) -> String {
    // cite(RFC 3986 § 5.2.3): "If the base URI has a defined authority component and an empty path, then return a string consisting of "/" concatenated with the reference's path"
    if base_path.is_empty() {
        return format!("/{ref_path}");
    }
    // cite(RFC 3986 § 5.2.3): "return a string consisting of the reference's path component appended to all but the last segment of the base URI's path"
    match base_path.rfind('/') {
        Some(i) => format!("{}{}", &base_path[..=i], ref_path),
        None => ref_path.to_string(),
    }
}

/// The authority a URI reference defines *for itself*, or `None` when it
/// inherits the base URI's.
///
/// Only two reference forms carry one: an absolute URI with an authority
/// (`scheme://authority/…`) and a network-path reference (`//authority/…`).
/// Every other form — absolute-path, relative-path, empty, query-only — resolves
/// against the base and takes the base's authority.
///
/// **The empty authority is folded into `None` here, and that is this function's
/// own decision rather than [`authority_component`]'s.** Every caller is
/// comparing this reference's authority against another one, and an empty
/// authority defines nothing to compare: a reference carrying one names no host,
/// so the honest answer to *"which authority does this reference define"* is that
/// it defines none. A caller asking whether the component is **present** — which
/// is what RFC 9110 § 4.2.1's empty-host MUST NOT is about — has to ask
/// [`authority_component`] instead, and the two answers stay apart for that
/// reason.
// cite(RFC 3986 § 4.2): "A relative reference that begins with two slash characters is termed a network-path reference; such references are rarely used."
pub fn reference_authority(reference: &str) -> Option<String> {
    authority_component(reference.trim())
        .filter(|authority| !authority.is_empty())
        .map(str::to_string)
}

/// Resolve a URI reference against a base path-and-query and return the
/// reference's effective path and query — the "conversion to absolute form"
/// that comparing a reference against a target URI requires.
///
/// This is RFC 3986 §5.2.2's transform, restricted to the two components this
/// helper compares. Callers that also care *which* authority the result belongs
/// to must ask [`reference_authority`]: a reference can name a path identical to
/// the base's while pointing at an entirely different host.
///
/// Returns `None` for a **non-hierarchical absolute URI** (`mailto:`, `urn:`),
/// which has no path component in the generic-syntax sense and so has nothing
/// comparable.
pub fn resolve_reference_path_and_query(
    base_path_and_query: &str,
    reference: &str,
) -> Option<String> {
    let r = reference.trim();
    // §5.2.2 carries the reference's fragment into the target untouched; it
    // identifies a secondary resource and is not part of the URI being compared.
    let r = &r[..r.find('#').unwrap_or(r.len())];

    // A network-path reference supplies its own authority, so §5.2.2 takes its
    // path verbatim; only the scheme is inherited from the base.
    //
    // This is the far side of the same boundary and not a copy of
    // [`authority_component`]: what is wanted is everything *after* the
    // authority, and the fragment was already taken off two lines above — which
    // is why the terminator set here is two characters rather than § 3.2's
    // three, and why converting this to the shared reader would need the
    // authority's length back out of it for no gain.
    if let Some(after_slashes) = r.strip_prefix("//") {
        let rest = match after_slashes.find(['/', '?']) {
            Some(i) => &after_slashes[i..],
            None => "",
        };
        // `path-abempty` may be empty, in which case the effective path is "/".
        if rest.is_empty() || rest.starts_with('?') {
            return Some(format!("/{rest}"));
        }
        return Some(normalize_path_and_query(rest));
    }

    // A reference whose first component holds a ':' defines a scheme, so it is
    // already absolute: §5.2.2 takes its path verbatim and inherits nothing.
    let first_component = &r[..r.find(['/', '?']).unwrap_or(r.len())];
    if first_component.contains(':') {
        return extract_path_and_query_from_request_target(r).map(|p| normalize_path_and_query(&p));
    }

    let (base_path, base_query) = split_at_query(base_path_and_query);
    let (ref_path, ref_query) = split_at_query(r);

    // R.path is empty: the base's path stands, and the query comes from the
    // reference only when the reference defines one.
    if ref_path.is_empty() {
        let query = if ref_query.is_empty() {
            base_query
        } else {
            ref_query
        };
        return Some(format!("{}{}", remove_dot_segments(base_path), query));
    }

    let merged = if ref_path.starts_with('/') {
        ref_path.to_string()
    } else {
        merge_paths(base_path, ref_path)
    };
    Some(format!("{}{}", remove_dot_segments(&merged), ref_query))
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

/// Validate a bare scheme name — the production alone, with no ':' to find it by.
///
/// [`validate_scheme_if_present`] locates a scheme inside a larger value and then
/// asks this question of what it found; a field whose whole value *is* a scheme
/// name (`Forwarded`'s `proto`) asks it directly. The production was written out
/// twice before this function existed, and the two copies are the shape three of
/// this tree's bugs already have.
///
/// The leading `ALPHA` is the half a character-set loop drops: `1*` is not what
/// the production says, and `+`, `-`, `.` and every DIGIT are admitted only
/// *after* a letter, so `9x` and `+http` are not scheme names.
// cite(RFC 3986 § 3.1): "scheme      = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )"
// cite(RFC 3986 § 3.1): "Scheme names consist of a sequence of characters beginning with a letter and followed by any combination of letters, digits, plus ("+"), period ("."), or hyphen ("-")."
pub fn validate_scheme_name(scheme: &str) -> Result<(), String> {
    let mut chars = scheme.chars();
    let Some(first) = chars.next() else {
        return Err("scheme must not be empty".into());
    };
    if !first.is_ascii_alphabetic() {
        return Err(format!("scheme '{}' must begin with a letter", scheme));
    }
    for c in chars {
        if !(c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.') {
            return Err(format!("invalid character '{}' in scheme '{}'", c, scheme));
        }
    }
    Ok(())
}

/// Validate a `uri-host`: an IP literal in brackets, or a registered name.
///
/// The three alternatives are not three checks. `IPv4address` generates nothing
/// `reg-name` does not also generate — every `dec-octet` is DIGIT and `.` is
/// `unreserved` — so a dotted quad that is out of range is a perfectly good
/// registered name and is not a syntax finding here. What separates the
/// alternatives is the brackets, which appear in no other host form.
// cite(RFC 3986 § 3.2.2): "host        = IP-literal / IPv4address / reg-name"
// cite(RFC 3986 § 3.2.2): "reg-name    = *( unreserved / pct-encoded / sub-delims )"
// cite(RFC 3986 § 2.3): "unreserved  = ALPHA / DIGIT / "-" / "." / "_" / "~""
// cite(RFC 3986 § 2.2): "sub-delims  = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "=""
pub fn validate_uri_host(host: &str) -> Result<(), String> {
    if let Some(rest) = host.strip_prefix('[') {
        // cite(RFC 3986 § 3.2.2): "IP-literal = "[" ( IPv6address / IPvFuture  ) "]""
        let Some(inner) = rest.strip_suffix(']') else {
            return Err(format!("IP literal '{}' is missing its ']'", host));
        };
        if inner.parse::<std::net::Ipv6Addr>().is_ok() || is_ipvfuture(inner) {
            return Ok(());
        }
        return Err(format!("'{}' is not an IPv6 address", inner));
    }

    if host.contains([']', '[']) {
        return Err(format!(
            "'{}' holds a bracket, which appears in no host form but an IP literal",
            host
        ));
    }

    // The triplet is the whole of `pct-encoded`, and it is checked where every
    // other percent-encoding in this module is. Its two hex digits are DIGIT and
    // ALPHA, so the character walk below has nothing left to say about them.
    if let Some(msg) = check_percent_encoding(host) {
        return Err(msg);
    }
    for c in host.chars() {
        if !(c.is_ascii_alphanumeric()
            || c == '%'
            || matches!(c, '-' | '.' | '_' | '~')
            || matches!(
                c,
                '!' | '$' | '&' | '\'' | '(' | ')' | '*' | '+' | ',' | ';' | '='
            ))
        {
            return Err(format!("invalid character '{}' in host '{}'", c, host));
        }
    }
    Ok(())
}

/// `IPvFuture = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )`
///
/// Nothing has ever been registered under it, which is the reason to read it
/// rather than to leave a bracketed literal that is not an IPv6 address as a
/// finding: the production exists, and a rule that reports what a grammar
/// generates is wrong however unlikely the value.
// cite(RFC 3986 § 3.2.2): "IPvFuture  = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )"
fn is_ipvfuture(s: &str) -> bool {
    let Some(rest) = s.strip_prefix(['v', 'V']) else {
        return false;
    };
    let Some(dot) = rest.find('.') else {
        return false;
    };
    let (version, tail) = (&rest[..dot], &rest[dot + 1..]);
    if version.is_empty() || !version.chars().all(|c| c.is_ascii_hexdigit()) {
        return false;
    }
    !tail.is_empty()
        && tail.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(c, '-' | '.' | '_' | '~' | ':')
                || matches!(
                    c,
                    '!' | '$' | '&' | '\'' | '(' | ')' | '*' | '+' | ',' | ';' | '='
                )
        })
}

/// Where the `uri-host` ends and `":" port` begins, with neither half examined.
///
/// Only a colon after the closing bracket separates a port: every colon inside an
/// IP literal belongs to the address, and the brackets are the only thing marking
/// where it stopped.
///
/// The port half is `Some("")` for a value ending in its delimiter, because that
/// is a real distinction: `port` is `*DIGIT`, so `example.com:` carries a port of
/// no digits and `example.com` carries no port at all. Two productions one bracket
/// apart tell those cases apart -- `Host = uri-host [ ":" port ]` generates both,
/// `authority-form = uri-host ":" port` only the first -- so a caller reading the
/// stricter one asks for the `Some` and a caller reading `Host` does not care.
// cite(RFC 3986 § 3.2.2): "A host identified by an Internet Protocol literal address, version 6 [RFC3513] or later, is distinguished by enclosing the IP literal within square brackets ("[" and "]")."
// cite(RFC 3986 § 3.2.2): "This is the only place where square bracket characters are allowed in the URI syntax."
// cite(RFC 3986 § 3.2.3): "The port subcomponent of authority is designated by an optional port number in decimal following the host and delimited from it by a single colon (":") character."
pub fn split_host_and_port(value: &str) -> (&str, Option<&str>) {
    let colon = match value.starts_with('[') {
        true => value.find(']').and_then(|close| {
            value[close + 1..]
                .find(':')
                .map(|offset| close + 1 + offset)
        }),
        false => value.find(':'),
    };

    match colon {
        Some(i) => (&value[..i], Some(&value[i + 1..])),
        None => (value, None),
    }
}

/// The port a run of digits designates, or `None` when it designates none.
///
/// **This is not `port`'s grammar and must never be confused for it.**
/// `port = *DIGIT` bounds nothing at either end, which is why
/// [`validate_host_and_optional_port`] declines the range and why
/// `client_host_header` reports no port for being out of range. What this
/// answers is the *other* question — whether the number lands in the sixteen-bit
/// namespace a transport registers its ports in — and **the licence to ask it is
/// the caller's**, because it takes a sentence naming the transport or the type.
/// Its three callers each carry their own: RFC 9113 § 8.5's TCP connection for a
/// CONNECT `:authority`, RFC 7838 § 2's ALPN-name-includes-TLS for an
/// `alt-authority`, and the URL Standard's *16-bit unsigned integer* for a
/// serialized origin, which is the only one of the three where the width is
/// stated of the value itself rather than reached through the transport.
///
/// **`0` is a port.** It is inside the namespace — a reserved value at the edge
/// of a range, held back for extending the ranges later — and reserved is not
/// invalid. Two of the three callers already read it that way after their own
/// audits; the third rejected it, so `Origin: https://example.com:0` was not a
/// serialized origin.
///
/// Empty and non-digit inputs are `None` too, which is the same answer for a
/// different reason: they derive from no `port` at all. A caller wanting to tell
/// the two apart measures the characters first, and all three do.
// cite(RFC 3986 § 3.2.3): "The port subcomponent of authority is designated by an optional port number in decimal following the host and delimited from it by a single colon (":") character."
// cite(RFC 6335 § 6): "TCP, UDP, UDP-Lite, SCTP, and DCCP use 16-bit namespaces for their port number registries."
// cite(RFC 6335 § 6): "Reserved port numbers include values at the edges of each range, e.g., 0, 1023, 1024, etc., which may be used to extend these ranges or the overall port number space in the future."
pub fn port_number(digits: &str) -> Option<u16> {
    if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    // Sixteen bits, written as sixteen bits rather than as the literal 65535:
    // the width is the whole of what the cited sentence says, and a type cannot
    // be spelled wrong. A `*DIGIT` of any length either fits or overflows, and
    // both mean the same thing here — a number outside the namespace — so the
    // overflow is the answer rather than an early return.
    //
    // The digit scan above is what makes this parser safe to reach for: on its
    // own, `u16::from_str` accepts a leading '+', which no `*DIGIT` writes.
    digits.parse::<u16>().ok()
}

/// Validate a `Host` field value: a `uri-host` and, optionally, a port.
///
/// The port is `*DIGIT` — no upper bound and no lower one. A number no
/// transport could carry is a syntax question for nobody, and a colon with
/// nothing after it is a port of no digits, which is what the second sentence
/// below is addressing when it asks a URI producer to leave the delimiter off
/// as well. A rule wanting the TCP range wants a different sentence than these.
// cite(RFC 9110 § 7.2, label: Host grammar): "Host = uri-host [ ":" port ]"
// cite(RFC 3986 § 3.2.3): "The port subcomponent of authority is designated by an optional port number in decimal following the host and delimited from it by a single colon (":") character."
// cite(RFC 3986 § 3.2.3): "URI producers and normalizers should omit the port component and its ":" delimiter if port is empty or if its value would be the same as that of the scheme's default."
pub fn validate_host_and_optional_port(value: &str) -> Result<(), String> {
    let (host, port) = split_host_and_port(value);

    validate_uri_host(host)?;

    if let Some(port) = port {
        if let Some(c) = port.chars().find(|c| !c.is_ascii_digit()) {
            return Err(format!("invalid character '{}' in port '{}'", c, port));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {

    /// The two normalizations § 6.2.2 asks for on percent-encoding, and the one
    /// § 2.4 forbids.
    #[test]
    fn decode_unreserved_leaves_delimiters_encoded() {
        // `%2F` is a `gen-delims` octet: decoding it would move a component
        // boundary, which is the mistake RFC 3986 § 2.4 names.
        assert_eq!(decode_unreserved("a%2Fb"), "a%2Fb");
        assert_eq!(decode_unreserved("a%2Cb"), "a%2Cb");
        // An `unreserved` octet is decoded, in either hexadecimal case.
        assert_eq!(decode_unreserved("%2Ewell%2dknown"), ".well-known");
        // A triplet that stays encoded is still put in one form, which is what
        // lets two authorities differing only in the case of their hexadecimal
        // compare equal (§ 6.2.2.1).
        assert_eq!(decode_unreserved("a%2fb"), "a%2Fb");
        // A truncated or non-hexadecimal run is left exactly as written; whether
        // it is well formed is another rule's finding.
        assert_eq!(decode_unreserved("%2"), "%2");
        assert_eq!(decode_unreserved("%zz"), "%zz");
        assert_eq!(decode_unreserved("%%41"), "%A");
        // `from_str_radix` would read this as %x0A; no `pct-encoded` writes a
        // sign, so the two characters are measured against `HEXDIG` first.
        assert_eq!(decode_unreserved("%+A"), "%+A");
        // A captured target read back through `lint` is an arbitrary string:
        // the two positions after a `%` can be inside a multi-byte code point,
        // and slicing them would panic.
        assert_eq!(decode_unreserved("%é4"), "%é4");
        assert_eq!(decode_unreserved("café"), "café");
    }
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
    fn percent_followed_by_a_multibyte_character_does_not_panic() {
        // A '%' whose next bytes are the lead/continuation bytes of a multi-byte
        // character used to be reported by slicing three *bytes*, splitting the
        // character and panicking. Request targets are not guaranteed ASCII.
        let m = check_percent_encoding("/p%\u{20AC}x").expect("must be reported, not panic");
        assert!(m.contains("Invalid percent-encoding"), "{m}");
        assert!(check_percent_encoding("%\u{20AC}").is_some());
        assert!(check_percent_encoding("\u{20AC}%2G").is_some());
        assert!(check_percent_encoding("/caf\u{e9}/ok%20").is_none());
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
    fn scheme_name_needs_a_leading_letter() {
        assert!(validate_scheme_name("http").is_ok());
        assert!(validate_scheme_name("coap+ws").is_ok());
        assert!(validate_scheme_name("a").is_ok());
        // Every one of these is a `token`, which is why a rule reaching for
        // `tchar` where the sentence says "URI scheme name" accepts them.
        assert!(validate_scheme_name("9foo").is_err());
        assert!(validate_scheme_name("+http").is_err());
        assert!(validate_scheme_name("ht_tp").is_err());
        assert!(validate_scheme_name("ht%tp").is_err());
        assert!(validate_scheme_name("").is_err());
    }

    #[test]
    fn uri_host_accepts_what_reg_name_generates() {
        for host in [
            "example.com",
            "EXAMPLE.com",
            "a(b)c",
            "a,b;c=d",
            "%41%42",
            "192.0.2.1",
            // A dotted quad out of range is still a registered name.
            "999.999.999.999",
            "",
            "[2001:db8::1]",
            "[::ffff:192.0.2.1]",
            "[v7.host:name]",
        ] {
            assert!(validate_uri_host(host).is_ok(), "{host}");
        }
        for host in [
            "exa mple",
            "user@host",
            "a^b",
            "a|b",
            "a\"b",
            "%4",
            "%zz",
            "[2001:db8::1",
            "[not-an-address]",
            "2001:db8::1]",
        ] {
            assert!(validate_uri_host(host).is_err(), "{host}");
        }
    }

    #[test]
    fn a_delimiter_with_nothing_after_it_is_not_the_same_as_no_delimiter() {
        // The distinction `validate_host_and_optional_port` discards, and the
        // reason this split is its own function: `Host = uri-host [ ":" port ]`
        // generates both, `authority-form = uri-host ":" port` only the first.
        assert_eq!(
            split_host_and_port("example.com:"),
            ("example.com", Some(""))
        );
        assert_eq!(split_host_and_port("example.com"), ("example.com", None));
        assert_eq!(split_host_and_port(":80"), ("", Some("80")));
        assert_eq!(split_host_and_port(":"), ("", Some("")));
        assert_eq!(split_host_and_port(""), ("", None));
        // Every colon inside the brackets belongs to the address; only one after
        // the closing bracket separates a port.
        assert_eq!(split_host_and_port("[::1]:443"), ("[::1]", Some("443")));
        assert_eq!(split_host_and_port("[::1]"), ("[::1]", None));
        assert_eq!(split_host_and_port("2001:db8::1"), ("2001", Some("db8::1")));
    }

    #[test]
    fn host_port_is_star_digit() {
        // `port = *DIGIT` bounds nothing: no minimum, so a colon with nothing
        // after it is a port, and no maximum, so a number no transport could
        // carry is not a syntax question.
        for value in [
            "example.com",
            "example.com:80",
            "example.com:",
            "example.com:0",
            "example.com:99999",
            "[2001:db8::1]:8080",
            "[2001:db8::1]",
        ] {
            assert!(validate_host_and_optional_port(value).is_ok(), "{value}");
        }
        for value in ["example.com:8o8", "exa mple:80", "2001:db8::1", "[::1]x:80"] {
            assert!(validate_host_and_optional_port(value).is_err(), "{value}");
        }
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
    fn remove_dot_segments_matches_the_rfc_worked_examples() {
        // The two examples RFC 3986 §5.2.4 works through itself.
        assert_eq!(remove_dot_segments("/a/b/c/./../../g"), "/a/g");
        assert_eq!(remove_dot_segments("mid/content=5/../6"), "mid/6");
        // Degenerate inputs: ".." above the root is dropped, not carried.
        assert_eq!(remove_dot_segments("/../foo"), "/foo");
        assert_eq!(remove_dot_segments("/a/.."), "/");
        assert_eq!(remove_dot_segments("/a/."), "/a/");
        assert_eq!(remove_dot_segments("."), "");
        assert_eq!(remove_dot_segments(""), "");
        assert_eq!(remove_dot_segments("/foo"), "/foo");
    }

    #[test]
    fn resolve_reference_relative_forms() {
        // A relative-path reference naming the target itself.
        assert_eq!(
            resolve_reference_path_and_query("/dir/foo.html", "foo.html"),
            Some("/dir/foo.html".into())
        );
        assert_eq!(
            resolve_reference_path_and_query("/dir/foo.html", "./foo.html"),
            Some("/dir/foo.html".into())
        );
        assert_eq!(
            resolve_reference_path_and_query("/dir/sub/foo", "../foo"),
            Some("/dir/foo".into())
        );
        // An absolute-path reference ignores the base path but still normalizes.
        assert_eq!(
            resolve_reference_path_and_query("/foo", "/a/../foo"),
            Some("/foo".into())
        );
        // An empty reference is the base URI; a bare query replaces only the query.
        assert_eq!(
            resolve_reference_path_and_query("/foo?x=1", ""),
            Some("/foo?x=1".into())
        );
        assert_eq!(
            resolve_reference_path_and_query("/foo?x=1", "?y=2"),
            Some("/foo?y=2".into())
        );
        // A fragment-only reference resolves to the base, fragment discarded.
        assert_eq!(
            resolve_reference_path_and_query("/foo", "#frag"),
            Some("/foo".into())
        );
    }

    #[test]
    fn resolve_reference_absolute_and_uncomparable_forms() {
        assert_eq!(
            resolve_reference_path_and_query("/foo", "http://example.com/a/../foo?x=1"),
            Some("/foo?x=1".into())
        );
        // No path component to compare.
        assert_eq!(resolve_reference_path_and_query("/foo", "mailto:a@b"), None);
        assert_eq!(resolve_reference_path_and_query("/foo", "urn:x:y"), None);
        // A network-path reference takes its path verbatim; the authority it
        // also carries is `reference_authority`'s to report.
        assert_eq!(
            resolve_reference_path_and_query("/foo", "//other.example/foo"),
            Some("/foo".into())
        );
        assert_eq!(
            resolve_reference_path_and_query("/foo", "//other.example/a/../foo?x=1"),
            Some("/foo?x=1".into())
        );
        assert_eq!(
            resolve_reference_path_and_query("/foo", "//other.example"),
            Some("/".into())
        );
        assert_eq!(
            resolve_reference_path_and_query("/foo", "//other.example?x=1"),
            Some("/?x=1".into())
        );
    }

    /// The three axes the four readers of this question used to disagree on:
    /// which characters terminate the component, whether an empty authority is
    /// an authority, and how close the `//` has to sit to the scheme's colon.
    #[test]
    fn authority_component_reads_section_3_2s_sentence_and_nothing_else() {
        // All three terminators, and the end of the value.
        assert_eq!(
            authority_component("http://example.com/p"),
            Some("example.com")
        );
        assert_eq!(
            authority_component("http://example.com?x=1"),
            Some("example.com")
        );
        assert_eq!(
            authority_component("http://example.com#f"),
            Some("example.com")
        );
        assert_eq!(
            authority_component("http://example.com"),
            Some("example.com")
        );
        // The `//` is what the search is for; a scheme in front of it is
        // optional, and a network-path reference carries one without any.
        assert_eq!(authority_component("//example.com/p"), Some("example.com"));
        // Every subcomponent stays in: this function answers where the
        // component ends and nothing about what is inside it.
        assert_eq!(
            authority_component("http://user:pass@[::1]:8080/p"),
            Some("user:pass@[::1]:8080")
        );
        // `Some("")` and `None` are different answers — `reg-name` is
        // `*( ... )`, so the first value carries an empty authority and the
        // second carries none.
        assert_eq!(authority_component("http://"), Some(""));
        assert_eq!(authority_component("http:///p"), Some(""));
        assert_eq!(authority_component("http:/p"), None);
        // No `//` at all, in each of the forms that reach this.
        for none in ["/p", "p", "", "mailto:a@b", "example.com:443", "*", "?x"] {
            assert_eq!(authority_component(none), None, "{none}");
        }
        // The `//` must follow the scheme's colon immediately. Here the scheme
        // is `a` and `b://c` is a `path-rootless`, so the value carries no
        // authority — which a bare search for `://` reads the other way.
        assert_eq!(authority_component("a:b://c"), None);
        assert!(scheme_authority_marker("a:b://c").is_some());
    }

    #[test]
    fn reference_authority_reports_only_a_self_defined_authority() {
        // Forms that carry their own authority.
        assert_eq!(
            reference_authority("https://evil.example/foo"),
            Some("evil.example".into())
        );
        assert_eq!(
            reference_authority("//evil.example/foo"),
            Some("evil.example".into())
        );
        assert_eq!(
            reference_authority("http://example.com:8080?x=1"),
            Some("example.com:8080".into())
        );
        // Forms that inherit the base's.
        for inheriting in ["/foo", "foo.html", "../foo", "", "?x=1", "#f", "mailto:a@b"] {
            assert_eq!(reference_authority(inheriting), None, "{inheriting}");
        }
    }

    /// The axis the three copies of this predicate disagreed on was `0`, and
    /// the ones either side of the namespace are what it is not.
    #[test]
    fn port_number_holds_the_sixteen_bit_namespace_including_its_reserved_edge() {
        assert_eq!(port_number("0"), Some(0));
        assert_eq!(port_number("1"), Some(1));
        assert_eq!(port_number("443"), Some(443));
        assert_eq!(port_number("65535"), Some(65535));
        assert_eq!(port_number("65536"), None);
        // A `*DIGIT` has no length bound, so an overflow is an answer rather
        // than an early return.
        assert_eq!(port_number("999999999999999999999999"), None);
        // Leading zeros are digits: `port = *DIGIT` writes no canonical form,
        // and the number is what it is.
        assert_eq!(port_number("080"), Some(80));
        assert_eq!(port_number("00000"), Some(0));
        // Not a run of digits at all, which is a different reason for the same
        // answer — `u16::from_str` would have taken the sign.
        assert_eq!(port_number(""), None);
        assert_eq!(port_number("+80"), None);
        assert_eq!(port_number("-1"), None);
        assert_eq!(port_number("8o8"), None);
        assert_eq!(port_number(" 80"), None);
    }

    #[test]
    fn scheme_prefix_names_the_candidate_without_judging_it() {
        assert_eq!(scheme_prefix("https://ex"), Some("https"));
        assert_eq!(scheme_prefix("about:blank"), Some("about"));
        // Not a scheme name, but it is what the value offered as one — saying so
        // is the caller's, which is the whole reason this is separate.
        assert_eq!(scheme_prefix("1http://ex"), Some("1http"));
        assert_eq!(scheme_prefix(":foo"), Some(""));
        // Past a component delimiter a colon is data.
        assert_eq!(scheme_prefix("/foo:bar"), None);
        assert_eq!(scheme_prefix("/a?x=b:c"), None);
        assert_eq!(scheme_prefix("/a#f:g"), None);
        assert_eq!(scheme_prefix("//host/p"), None);
        assert_eq!(scheme_prefix(""), None);
    }

    #[test]
    fn userinfo_is_split_at_the_last_at_sign() {
        assert_eq!(split_userinfo("example.com"), (None, "example.com"));
        assert_eq!(
            split_userinfo("user@example.com"),
            (Some("user"), "example.com")
        );
        assert_eq!(
            split_userinfo("user:pass@example.com:8080"),
            (Some("user:pass"), "example.com:8080")
        );
        // No `userinfo` and no `reg-name` holds an at-sign, so a second one
        // derives from nothing; the host half stays the short one.
        assert_eq!(
            split_userinfo("a@b@example.com"),
            (Some("a@b"), "example.com")
        );
        // The delimiter with nothing before it is a present-but-empty userinfo,
        // which `*( ... )` generates.
        assert_eq!(split_userinfo("@example.com"), (Some(""), "example.com"));
        assert_eq!(split_userinfo(""), (None, ""));
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
        // A port outside the sixteen-bit namespace is the finding; `0` is
        // inside it, reserved rather than invalid.
        assert!(validate_origin_value("http://example.com:65536").is_some());
        assert!(validate_origin_value("http://example.com:0").is_none());
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

    #[test]
    fn validate_origin_missing_host_reports_missing() {
        let m = validate_origin_value("http://").unwrap();
        // we now return the generic "not a valid serialized origin" message for
        // missing authority, rather than a specialized one; callers that care
        // about details should inspect the string content appropriately.
        assert!(m.contains("not a valid serialized origin"));
    }
}
