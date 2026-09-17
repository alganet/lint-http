// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! A URI reference resolved against a base, and two references compared: what
//! § 5.2's transform produces and what § 6.2.2's normalization then makes
//! comparable.
//!
//! **Resolving and normalizing are two documents' steps and they are applied in
//! that order, once each.** § 5.2.2's transform writes `remove_dot_segments`
//! into three of its four path-producing branches, and those calls are the
//! transform's own; § 6.2.2.3's removal is a *comparison* step and is applied to
//! the result. The two used to be mixed — two branches normalized and three
//! spelled the dot-segment routine out inline, a distinction with no consequence
//! until § 6.2.2.2 joined the normalizer and three branches silently stopped
//! doing what the other two did.
//!
//! **Every caller here is comparing one reference against another**, which is
//! what makes normalization part of the answer rather than a service offered
//! beside it: a branch that normalized less than its neighbours would be
//! comparing one side against the other's spelling.
//!
//! **The query is split off before the dot segments and not before the
//! decoding.** § 5.4.2 names failing to separate it as a deployed error, and the
//! reason is one-sided — `remove_dot_segments` is a *path* routine, so a `../`
//! written inside a parameter value would be collapsed. Percent-decoding runs on
//! both halves, because no delimiter of either component is `unreserved` and so
//! nothing it decodes can move a boundary.
//!
//! What a reference is *made of* is elsewhere: the alphabet is [`super::uri`]'s,
//! the components' boundaries are [`super::authority`]'s and
//! [`super::scheme`]'s, and the triplet is [`super::percent_encoding`]'s.

use crate::helpers::authority::authority_component;
use crate::helpers::headers::trim_ows;
use crate::helpers::percent_encoding::decode_unreserved;
use crate::helpers::request_target::extract_path_and_query_from_request_target;

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
