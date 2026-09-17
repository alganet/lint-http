// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Small reusable helpers for URI-ish checks used by several rules.
//!
//! **Every trim in this module is `OWS` and not `str::trim`, because the values
//! that reach it are read as the octets a sender wrote.** A caller holding one
//! `char` per octet has `%xA0` in hand where a UTF-8 decode would have had
//! U+00A0, and `str::trim` removes the second — so a `Location`, an `Origin` or
//! a request-target with an `obs-text` octet at its edge would arrive here
//! *shorter than the sender wrote it* and be pronounced valid. The octet is
//! `obs-text`, no URI character admits it, and the finding is the caller's;
//! taking it off first is how the finding stops being made. `SP` and `HTAB` are
//! the only whitespace a field value can carry beside its content, and
//! [`trim_ows`] is exactly them.

use crate::helpers::authority::{authority_component, split_host_and_port, split_userinfo};
use crate::helpers::headers::trim_ows;
use crate::helpers::percent_encoding::decode_unreserved;
use crate::helpers::scheme::scheme_authority_marker;

/// The first character of `s` that no `URI-reference` admits, or `None` when
/// every character is one a URI may be written with.
///
/// The set is the union of `unreserved`, `gen-delims` and `sub-delims` plus the
/// `"%"` that opens a `pct-encoded` triplet — every terminal reachable from
/// `URI-reference`, since each component rule of the generic syntax lists a
/// subset of those characters and nothing outside them. So this answers only the
/// *alphabet* question; whether a character sits where its component allows it,
/// and whether a `%` is followed by two `HEXDIG`, are
/// [`super::percent_encoding::check_percent_encoding`]'s and the component rules' questions.
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

/// Whether `c` is in RFC 3986's `unreserved` set.
///
/// One of the two character sets RFC 3986 builds its general component
/// alphabets out of. Five of its productions name the pair and then add
/// something different beside it — `userinfo`, `IPvFuture`, `reg-name`,
/// `segment-nz-nc`, `pchar` — which is why this is a predicate and not a
/// transcription per site: the set is the shared answer and the divergence is
/// each caller's own line. Five sites in this crate read it (`reg-name`,
/// `pchar`, `IPvFuture`, the URI-wide alphabet, and [`super::percent_encoding::decode_unreserved`], which
/// asks it of a decoded octet rather than of a written character).
// cite(RFC 3986 § 2.3): "unreserved  = ALPHA / DIGIT / "-" / "." / "_" / "~""
pub fn is_unreserved(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~')
}

/// Whether `c` is in RFC 3986's `sub-delims` set.
///
/// The other of the two, and it never travels alone: every component rule of
/// the generic syntax that names this set names [`is_unreserved`]'s beside it.
/// The one place `sub-delims` appears without it is `reserved = gen-delims /
/// sub-delims`, which is a set definition rather than a component's alphabet —
/// and §2.2 says a component rule never names *that* one at all. Four sites in
/// this crate read it, one fewer than its partner, because a decoder asks which
/// octets it may write out and no `sub-delims` octet is one of them.
// cite(RFC 3986 § 2.2): "sub-delims  = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "=""
pub fn is_sub_delim(c: char) -> bool {
    matches!(
        c,
        '!' | '$' | '&' | '\'' | '(' | ')' | '*' | '+' | ',' | ';' | '='
    )
}

/// Whether `c` is one of the characters a URI is composed from.
///
/// `gen-delims` stays written out here because this is the only reading in the
/// tree that wants it: §2.2 says a component rule never names the set directly,
/// so a *component* alphabet borrows characters from it one at a time — `pchar`
/// takes `:` and `@`, `IPvFuture` takes `:` — and only a question asked of the
/// whole URI takes all seven.
// cite(RFC 3986 § 2.2): "gen-delims  = ":" / "/" / "?" / "#" / "[" / "]" / "@""
// cite(RFC 3986 § 2.2): "A component's ABNF syntax rule will not use the reserved or gen-delims rule names directly; instead, each syntax rule lists the characters allowed within that component (i.e., not delimiting it), and any of those characters that are also in the reserved set are "reserved" for use as subcomponent delimiters within the component."
// cite(RFC 3986 § 2.1): "pct-encoded = "%" HEXDIG HEXDIG"
fn is_uri_char(c: char) -> bool {
    is_unreserved(c)
        || is_sub_delim(c)
        || matches!(c, ':' | '/' | '?' | '#' | '[' | ']' | '@')
        || c == '%'
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

/// Apply § 6.2.2's syntax-based normalization to a path-and-query string.
///
/// **Three normalizations, three decisions, and the third one is a decline.**
/// The section names all three in one sentence and this function owes an answer
/// to each of them:
///
/// - **§ 6.2.2.2, percent-encoding.** Every triplet standing for an
///   `unreserved` character is written as that character, by
///   [`super::percent_encoding::decode_unreserved`]; § 2.3 names the octets a normalizer should decode
///   and `%2E` is one of them, spelled out.
/// - **§ 6.2.2.3, dot segments.** `remove_dot_segments`, which is the mistake
///   that section calls out by name: comparing two URIs that differ only in
///   dot-segments as if they named different resources.
/// - **§ 6.2.2.1, case.** Its two halves land differently here. The
///   hexadecimal of a triplet that stays encoded is uppercased, by the same
///   decoder; the scheme-and-host half reaches nothing, because a
///   path-and-query holds neither — and the section's last sentence is what
///   keeps the rest of the value case-sensitive, so `/A` and `/a` stay two
///   paths. The decline is the decision.
///
/// **The decode runs first, and § 2.4 is why it may.** Its exception says an
/// `unreserved` octet can be decoded at any time — no component boundary has to
/// be established for it, which is the whole reason [`super::percent_encoding::decode_unreserved`] stops
/// where it does. The consequence is the one worth stating: `%2E%2E` is a
/// complete `..` segment once decoded, so `/a/%2E%2E/b` and `/a/../b` reach
/// § 6.2.2.3 as the same path and leave it as `/b`. Removing the dot segments
/// first would leave the encoded spelling standing, which is the direction a
/// path-confusion trick is written in.
///
/// **The query is split off first, and only the dot segments need it.** § 5.4.2
/// names failing to separate it as a deployed error, and the reason is one-sided:
/// `remove_dot_segments` is a *path* routine, so leaving the query attached
/// would collapse a `../` written inside a parameter value. The decoding runs on
/// both halves, because § 6.2.2.2 is about a URI and not about a path — and it
/// cannot move a boundary either way round, since no delimiter of either
/// component is `unreserved`.
///
/// What keeps the decode-first order from over-reaching is the other § 5.4.2
/// sentence: a period is only a dot segment when it is the **complete** segment,
/// so `/a/b%2E/c` normalizes to `/a/b./c` and stays four segments long.
// cite(RFC 3986 § 6.2.2): "Syntax-based normalization includes such techniques as case normalization, percent-encoding normalization, and removal of dot-segments."
// cite(RFC 3986 § 5.4.2): "Some applications fail to separate the reference's query and/or fragment components from the path component before merging it with the base path and removing dot-segments."
// cite(RFC 3986 § 2.4): "The only exception is for percent-encoded octets corresponding to characters in the unreserved set, which can be decoded at any time."
// cite(RFC 3986 § 2.3): "percent-encoded octets in the ranges of ALPHA (%41-%5A and %61-%7A), DIGIT (%30-%39), hyphen (%2D), period (%2E), underscore (%5F), or tilde (%7E) should not be created by URI producers and, when found in a URI, should be decoded to their corresponding unreserved characters by URI normalizers"
// cite(RFC 3986 § 6.2.2.3): "URI normalizers should remove dot-segments by applying the remove_dot_segments algorithm to the path, as described in Section 5.2.4."
// cite(RFC 3986 § 5.4.2): "parsers must remove the dot-segments "." and ".." when they are complete components of a path, but not when they are only part of a segment."
// cite(RFC 3986 § 6.2.2.1): "The other generic syntax components are assumed to be case-sensitive unless specifically defined otherwise by the scheme (see Section 6.2.3)."
pub fn normalize_path_and_query(path_and_query: &str) -> String {
    let (path, query) = split_at_query(path_and_query);
    format!(
        "{}{}",
        remove_dot_segments(&decode_unreserved(path)),
        decode_unreserved(query)
    )
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
    authority_component(trim_ows(reference))
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
///
/// **The normalization is applied once, to the result**, rather than inside the
/// transform: §5.2.2 resolves and §6.2.2 compares, and they are two documents'
/// steps. Two of the five branches used to call the normalizer and three spelled
/// `remove_dot_segments` out inline — a distinction with no consequence while
/// that was all normalizing meant, and a silent hole in three branches the day
/// §6.2.2.2 joined it. Every caller here holds a base it normalized itself and
/// is about to compare two strings, so a branch that normalized less than the
/// others would be comparing one side against the other's spelling.
pub fn resolve_reference_path_and_query(
    base_path_and_query: &str,
    reference: &str,
) -> Option<String> {
    resolve_reference_transform(base_path_and_query, reference)
        .map(|resolved| normalize_path_and_query(&resolved))
}

/// RFC 3986 §5.2.2's transform alone, restricted to the path and query. The
/// `remove_dot_segments` calls below are the transform's own — §5.2.2 writes one
/// into three of its four path-producing branches — and not §6.2.2.3's
/// normalization, which [`resolve_reference_path_and_query`] applies to the
/// result. The fourth, where the reference's path is empty, takes the base's
/// path as it stands and is left doing exactly that.
fn resolve_reference_transform(base_path_and_query: &str, reference: &str) -> Option<String> {
    let r = trim_ows(reference);
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
        let (rest_path, rest_query) = split_at_query(rest);
        return Some(format!("{}{}", remove_dot_segments(rest_path), rest_query));
    }

    // A reference whose first component holds a ':' defines a scheme, so it is
    // already absolute: §5.2.2 takes its path verbatim and inherits nothing.
    let first_component = &r[..r.find(['/', '?']).unwrap_or(r.len())];
    if first_component.contains(':') {
        return extract_path_and_query_from_request_target(r).map(|p| {
            let (path, query) = split_at_query(&p);
            format!("{}{}", remove_dot_segments(path), query)
        });
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
        return Some(format!("{base_path}{query}"));
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

#[cfg(test)]
mod tests {
    use crate::helpers::authority::validate_uri_host;
    use crate::helpers::origin::extract_origin_if_absolute;

    /// Both sets, spelled out from the productions rather than composed from the
    /// predicates, and asserted over the whole US-ASCII range — four component
    /// alphabets and one decoder now rest on these two functions, so a character
    /// added or dropped here is added or dropped in all five.
    #[test]
    fn the_two_character_sets_are_what_their_productions_print() {
        // unreserved  = ALPHA / DIGIT / "-" / "." / "_" / "~"
        let unreserved: Vec<char> = ('a'..='z')
            .chain('A'..='Z')
            .chain('0'..='9')
            .chain("-._~".chars())
            .collect();
        // sub-delims  = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="
        let sub_delims: Vec<char> = "!$&'()*+,;=".chars().collect();
        assert_eq!(sub_delims.len(), 11);

        for c in (0u8..=0x7F).map(char::from) {
            assert_eq!(
                is_unreserved(c),
                unreserved.contains(&c),
                "unreserved disagrees about {c:?}"
            );
            assert_eq!(
                is_sub_delim(c),
                sub_delims.contains(&c),
                "sub-delims disagrees about {c:?}"
            );
        }

        // Neither set reaches past US-ASCII: every octet at or above %x80 has to
        // be percent-encoded before the URI is formed.
        for c in (0x80u8..=0xFF).map(char::from) {
            assert!(!is_unreserved(c) && !is_sub_delim(c), "{c:?}");
        }
    }

    /// The four alphabets built on those sets differ exactly where their
    /// productions differ, and nowhere else. This is the property the extraction
    /// was for: the divergence is one line per caller, and it is this one.
    #[test]
    fn the_component_alphabets_differ_only_by_what_their_productions_add() {
        for c in (0u8..=0x7F).map(char::from) {
            let shared = is_unreserved(c) || is_sub_delim(c);

            // reg-name = *( unreserved / pct-encoded / sub-delims ). Asked of a
            // character standing between two others, and with `%` left out of
            // the sweep: a lone `%` is not the alphabet's answer but
            // `pct-encoded`'s, which `validate_uri_host` asks separately and
            // first. The two assertions below the loop are that half.
            let reg_name = c == '%' || validate_uri_host(&format!("a{c}b")).is_ok();
            assert_eq!(reg_name, shared || c == '%', "reg-name: {c:?}");

            // pchar = unreserved / pct-encoded / sub-delims / ":" / "@"
            let pchar = is_unreserved(c) || is_sub_delim(c) || matches!(c, ':' | '@' | '%');
            assert_eq!(pchar, reg_name || matches!(c, ':' | '@'), "pchar: {c:?}");

            // IPvFuture's tail = 1*( unreserved / sub-delims / ":" ) — the one
            // of the four that admits no `pct-encoded`, so no `%`. Asked through
            // the bracketed literal, which is the only way a host reader reaches
            // that production and the only door this module has to it.
            assert_eq!(
                validate_uri_host(&format!("[v1.{c}]")).is_ok(),
                shared || c == ':',
                "IPvFuture: {c:?}"
            );

            // The URI-wide alphabet adds all seven `gen-delims` at once, which
            // §2.2 says no component rule does.
            assert_eq!(
                is_uri_char(c),
                shared || c == '%' || matches!(c, ':' | '/' | '?' | '#' | '[' | ']' | '@'),
                "URI alphabet: {c:?}"
            );
        }

        // `pct-encoded` is the triplet and not the `%`, and it is a separate
        // question from the alphabet at every one of the four sites.
        assert!(validate_uri_host("a%41b").is_ok());
        assert!(validate_uri_host("a%zzb").is_err());
        assert!(validate_uri_host("a%4").is_err());
    }

    use super::*;

    /// What `contains_whitespace` used to assert, asked of the function that
    /// replaced it — and the five characters beside the space, which that
    /// predicate answered `false` for at every one of its three callers.
    #[test]
    fn whitespace_detection() {
        assert!(find_non_uri_char("hello world").is_some());
        assert!(find_non_uri_char("/path/no-space").is_none());
        for c in [
            '<', '>', '"', '{', '}', '|', '\\', '^', '`', '\u{80}', '\u{ff}',
        ] {
            assert_eq!(
                find_non_uri_char(&format!("/p{c}ath")),
                Some(c),
                "for {c:?}"
            );
        }
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

    /// § 6.2.2 names three normalizations in one sentence and this function owes
    /// an answer to each. Every pair below fails if its own step is dropped, and
    /// the `%2E%2E` pair fails if the two that run swap order.
    #[test]
    fn normalize_path_and_query_answers_all_three_of_section_6_2_2() {
        // § 6.2.2's own worked example, path-and-query half: the two URIs it
        // calls equivalent normalize to one string.
        assert_eq!(
            normalize_path_and_query("/./b/../b/%63/%7bfoo%7d"),
            "/b/c/%7Bfoo%7D"
        );
        assert_eq!(normalize_path_and_query("/b/c/%7Bfoo%7D"), "/b/c/%7Bfoo%7D");

        // § 6.2.2.2, in the path and in the query alike — the query is part of
        // the URI the section is about, and only the *dot segments* are the
        // path's alone.
        assert_eq!(normalize_path_and_query("/a%2Db"), "/a-b");
        assert_eq!(normalize_path_and_query("/p?q=%7Ejane"), "/p?q=~jane");
        assert_eq!(normalize_path_and_query("/a?p=/x/../y"), "/a?p=/x/../y");

        // § 6.2.2.1, first half: a triplet that stays encoded keeps its octet
        // and gains upper-case hexadecimal. Last sentence: everything else in a
        // path or a query is case-sensitive and is left alone.
        assert_eq!(normalize_path_and_query("/a%2fb?x=%3a"), "/a%2Fb?x=%3A");
        assert_eq!(normalize_path_and_query("/A/b?X=Y"), "/A/b?X=Y");

        // § 6.2.2.3, applied to the *decoded* path: `%2E` is the period § 2.3
        // names among the octets a normalizer decodes, so `%2E%2E` arrives as a
        // complete `..` segment. Removing the dot segments first would leave the
        // second spelling standing.
        assert_eq!(normalize_path_and_query("/a/../b"), "/b");
        assert_eq!(normalize_path_and_query("/a/%2E%2E/b"), "/b");

        // A dot that is only part of a segment is not a dot segment, however it
        // is spelled (§ 5.4.2).
        assert_eq!(normalize_path_and_query("/a/b%2E/c"), "/a/b./c");
    }

    /// Every branch of the transform hands back a normalized result, because
    /// every caller compares it against a base it normalized itself. Each
    /// assertion below names the branch it covers.
    #[test]
    fn resolve_reference_normalizes_on_every_branch() {
        // Relative-path merge.
        assert_eq!(
            resolve_reference_path_and_query("/dir/foo.html", "%66oo.html"),
            Some("/dir/foo.html".into())
        );
        // Empty reference path, query from the reference.
        assert_eq!(
            resolve_reference_path_and_query("/foo", "?y=%7E2"),
            Some("/foo?y=~2".into())
        );
        // Absolute-path reference.
        assert_eq!(
            resolve_reference_path_and_query("/foo", "/a/%2E%2E/%66oo"),
            Some("/foo".into())
        );
        // Network-path reference, both of its shapes: a path, and a query with
        // an empty `path-abempty`.
        assert_eq!(
            resolve_reference_path_and_query("/foo", "//other.example/a/%2E%2E/%66oo"),
            Some("/foo".into())
        );
        assert_eq!(
            resolve_reference_path_and_query("/foo", "//other.example?x=%7E"),
            Some("/?x=~".into())
        );
        // Absolute reference.
        assert_eq!(
            resolve_reference_path_and_query("/foo", "http://example.com/a/../%66oo?x=%7E1"),
            Some("/foo?x=~1".into())
        );
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
