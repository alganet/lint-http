// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Cache-Control` read as the list of directives it is.
//!
//! Eleven rules asked this field a question and each one re-derived the list
//! first, with **five different answers about where a directive ends**: some
//! split on `,` alone, some on `,` or `;`, some respected quoting and some did
//! not, and two decided `no-store` was present by searching the whole field
//! value for that text — which finds it inside `private="no-store"`. A reader
//! that disagrees with its neighbours about the member boundary disagrees about
//! the finding, so the divergence was never only a matter of style.
//!
//! The single answer here: directives come off every `Cache-Control` field line
//! in the section (they are one list however many lines carry it, § 5.2), split
//! at a top-level `,` — or `;`, the tolerance the rules had already converged
//! on for the malformed form some senders write — never inside a quoted-string,
//! and matched by name case-insensitively.
//!
//! Argument-carrying directives are the reason the member has to be *parsed*
//! rather than compared whole: `no-cache` and `private` mean one thing bare and
//! a weaker thing with an argument, so [`Directive::is_unqualified`] is a
//! distinct question from [`Directive::is`] and the caller has to say which it
//! means.
//!
// cite(RFC 9111 § 5.2): "Cache directives are identified by a token, to be compared case-insensitively"
// cite(RFC 9111 § 5.2): "cache-directive  = token [ "=" ( token / quoted-string ) ]"

use crate::helpers::headers::{split_top_level, trim_ows};
use hyper::HeaderMap;

/// One `cache-directive`: a name, and the argument it carries if any.
///
/// `argument` distinguishes "no `=` was written" (`None`) from "an `=` was
/// written with nothing after it" (`Some("")`); no directive is defined with an
/// empty argument, so the qualified/unqualified questions below treat the
/// second as the bare form rather than inventing a member the sender did not
/// name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Directive<'a> {
    pub name: &'a str,
    pub argument: Option<&'a str>,
}

impl<'a> Directive<'a> {
    /// Parse one already-delimited list member.
    fn parse(member: &'a str) -> Self {
        match member.split_once('=') {
            Some((name, argument)) => Self {
                name: trim_ows(name),
                argument: Some(trim_ows(argument)),
            },
            None => Self {
                name: trim_ows(member),
                argument: None,
            },
        }
    }

    /// Whether this is the named directive, whatever argument it carries.
    // cite(RFC 9111 § 5.2): "Cache directives are identified by a token, to be compared case-insensitively"
    pub fn is(&self, name: &str) -> bool {
        self.name.eq_ignore_ascii_case(name)
    }

    /// Whether this is the named directive in its bare form.
    ///
    /// The qualified forms of `no-cache` and `private` license what their bare
    /// forms forbid, so a rule enforcing the bare form must not fire on them.
    // cite(RFC 9111 § 5.2.2.4): "The qualified form of the no-cache response directive, with an argument that lists one or more field names, indicates that a cache MAY use the response to satisfy a subsequent request"
    pub fn is_unqualified(&self, name: &str) -> bool {
        self.is(name) && self.argument.is_none_or(str::is_empty)
    }

    /// The argument read as `delta-seconds`, if it is one.
    ///
    /// Returned as written, negative values included: a negative
    /// `delta-seconds` is not a value the grammar admits, and the rules that
    /// report *that* need to see it. Callers wanting only a lifetime filter for
    /// non-negative themselves.
    // cite(RFC 9111 § 1.2.2, label: delta-seconds): "delta-seconds  = 1*DIGIT"
    pub fn delta_seconds(&self) -> Option<i64> {
        self.argument?.parse::<i64>().ok()
    }
}

/// Every list member in the section's `Cache-Control` field lines, in order and
/// as written — **including the empty ones**.
///
/// [`directives`] drops an empty member because a caller asking what the sender
/// requested has nothing to read in one. A caller reporting on the sender's
/// syntax has the opposite need: an empty element is precisely its finding, and
/// before this existed those callers reached past the reader and re-split the
/// field themselves to see it.
///
/// **A field line that is empty contributes no members at all**, and that is
/// the one exemption every caller of this needs: an entirely empty
/// `Cache-Control` value is a zero-element list, which `#element` permits,
/// while an empty element *within* a list is forbidden. Three rules wrote that
/// distinction out separately — skipping the empty value at the call site and
/// reporting the empty member in a function two levels down — which is two
/// places to get one sentence right.
///
/// Field lines that are not readable as text are skipped by both readers.
/// Naming *that* defect belongs to the rule that owns the field and needs the
/// field line rather than the member, so it asks
/// [`crate::helpers::headers::has_unreadable_line`].
// cite(RFC 9110 § 5.2): "When a field name is repeated within a section, its combined field value consists of the list of corresponding field line values within that section, concatenated in order, with each field line value separated by a comma."
// cite(RFC 9110 § 5.6.1.1): "In any production that uses the list construct, a sender MUST NOT generate empty list elements."
// cite(RFC 9110 § 5.6.1): "#element => [ element ] *( OWS "," OWS [ element ] )"
pub fn members(headers: &HeaderMap) -> impl Iterator<Item = &str> {
    crate::helpers::headers::field_lines(headers, "cache-control").flat_map(members_of)
}

/// The list members of one `Cache-Control` field line, as written.
///
/// [`members`] over a whole section is this applied to each readable line. A
/// caller reaches for this one when it reports per line — because the field
/// line, not the member, is what its finding is about — and the two must agree
/// about the member boundary, which is why the split lives here once.
pub fn members_of(line: &str) -> Vec<&str> {
    if line.trim().is_empty() {
        return Vec::new();
    }
    // `,` is the list separator the grammar prints; `;` is a tolerance for the
    // malformed `a;b` form some senders write. Accepting it only ever widens
    // what a directive search finds, never narrows it.
    split_top_level(line, b",;")
}

/// Every directive in the section's `Cache-Control` field lines, in order.
///
/// Empty members are dropped: every caller here is asking what the sender
/// *asked for*, not whether they wrote it correctly. Use [`members`] to see
/// them.
pub fn directives(headers: &HeaderMap) -> impl Iterator<Item = Directive<'_>> {
    members(headers)
        .filter(|member| !member.is_empty())
        .map(Directive::parse)
}

/// Read one list member strictly, as a rule reporting on this field's syntax
/// must: a defect comes back as the sentence that names it.
///
/// The three defects below were transcribed twice, once in each of the two
/// rules that check this field's grammar, down to the wording — which is what
/// made them worth moving rather than merely sharing a splitter. What the two
/// rules do *after* the name is read is genuinely different, and stays theirs.
// cite(RFC 9111 § 5.2): "cache-directive = token [ "=" ( token / quoted-string ) ]"
// cite(RFC 9110 § 5.6.1.1): "In any production that uses the list construct, a sender MUST NOT generate empty list elements."
pub fn read_member(member: &str) -> Result<Directive<'_>, String> {
    if member.is_empty() {
        return Err("Empty directive in Cache-Control header".into());
    }
    let directive = Directive::parse(member);
    if directive.name.is_empty() {
        return Err(format!(
            "Empty directive name in Cache-Control member: '{}'",
            member
        ));
    }
    if let Some(c) = crate::helpers::token::find_invalid_token_char(directive.name) {
        return Err(format!(
            "Directive name contains invalid character: '{}'",
            c
        ));
    }
    Ok(directive)
}

/// Whether the section carries the named directive at all.
pub fn has(headers: &HeaderMap, name: &str) -> bool {
    directives(headers).any(|d| d.is(name))
}

/// Whether the section carries the named directive in its bare form.
pub fn has_unqualified(headers: &HeaderMap, name: &str) -> bool {
    directives(headers).any(|d| d.is_unqualified(name))
}

/// The first non-negative `delta-seconds` given for the named directive.
///
/// A malformed or negative argument does not end the search: the sentence
/// defining these directives describes what a *value* means, so a member that
/// carries none is not the answer to "what lifetime was advertised" and the
/// next member still might be.
pub fn delta_seconds(headers: &HeaderMap, name: &str) -> Option<i64> {
    directives(headers)
        .filter(|d| d.is(name))
        .filter_map(|d| d.delta_seconds())
        .find(|seconds| *seconds >= 0)
}

/// Whether the section forbids storing the response or reusing it unvalidated.
///
/// The two directives are asked together because every caller wants the same
/// thing from them — "there is no usable stored entry to reason about" — and
/// each was previously deciding it with a substring search over the raw field
/// value, which answers yes to `private="no-store"`.
///
/// **Both are asked in their bare form, and for `no-cache` that is the whole
/// difference.** The qualified form licenses exactly what the bare form
/// forbids: a cache may reuse the response, revalidating or excluding only the
/// fields named in the argument. So `no-cache="Set-Cookie", max-age=600` is a
/// response that is fresh for ten minutes, and reading it as forbidden made
/// every freshness question built on this one answer zero. The substring search
/// this replaced had the same defect, and [`has_unqualified`] is what the rules
/// asking directly already use — the two readings must not disagree.
// cite(RFC 9111 § 5.2.2.5): "The no-store response directive indicates that a cache MUST NOT store any part of either the immediate request or the response and MUST NOT use the response to satisfy any other request."
// cite(RFC 9111 § 5.2.2.4): "The no-cache response directive, in its unqualified form (without an argument), indicates that the response MUST NOT be used to satisfy any other request without forwarding it for validation and receiving a successful response"
// cite(RFC 9111 § 5.2.2.4): "The qualified form of the no-cache response directive, with an argument that lists one or more field names, indicates that a cache MAY use the response to satisfy a subsequent request"
pub fn forbids_storage_or_reuse(headers: &HeaderMap) -> bool {
    directives(headers).any(|d| d.is_unqualified("no-store") || d.is_unqualified("no-cache"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;

    fn headers(values: &[&str]) -> HeaderMap {
        let mut hm = HeaderMap::new();
        for v in values {
            hm.append("cache-control", HeaderValue::from_str(v).unwrap());
        }
        hm
    }

    #[test]
    fn directives_come_off_every_field_line_in_order() {
        let hm = headers(&["max-age=60, private", "no-store"]);
        let names: Vec<&str> = directives(&hm).map(|d| d.name).collect();
        assert_eq!(names, ["max-age", "private", "no-store"]);
    }

    #[test]
    fn a_member_is_parsed_into_name_and_argument() {
        let hm = headers(&["no-cache=\"set-cookie\""]);
        let d = directives(&hm).next().unwrap();
        assert_eq!(d.name, "no-cache");
        assert_eq!(d.argument, Some("\"set-cookie\""));
        assert!(d.is("no-cache"));
        assert!(!d.is_unqualified("no-cache"));
    }

    /// An `=` with nothing after it names no field, so the bare reading is the
    /// only one left.
    #[test]
    fn an_empty_argument_reads_as_the_bare_form() {
        let hm = headers(&["no-cache="]);
        assert!(has_unqualified(&hm, "no-cache"));
    }

    /// The separator the grammar prints, and the one senders write anyway.
    #[test]
    fn both_separators_delimit_a_member() {
        assert!(has(&headers(&["immutable, max-age=0"]), "immutable"));
        assert!(has(&headers(&["immutable; max-age=0"]), "immutable"));
    }

    /// **The finding a substring search invented.** Neither separator is a
    /// separator inside a quoted-string, so the argument below names a field
    /// and does not add a directive.
    #[test]
    fn a_quoted_argument_hides_neither_separator_nor_directive_name() {
        let hm = headers(&["private=\"no-store,x-secret\""]);
        assert!(!forbids_storage_or_reuse(&hm));
        assert_eq!(directives(&hm).count(), 1);
    }

    /// **The qualified form licenses what the bare form forbids**, so a
    /// response carrying it still advertises the freshness written beside it.
    #[test]
    fn a_qualified_no_cache_does_not_forbid_reuse() {
        let hm = headers(&["no-cache=\"set-cookie\", max-age=600"]);
        assert!(!forbids_storage_or_reuse(&hm));
        assert!(forbids_storage_or_reuse(&headers(&[
            "no-cache, max-age=600"
        ])));
    }

    #[test]
    fn names_are_matched_case_insensitively() {
        assert!(has(&headers(&["ImMuTaBlE"]), "immutable"));
    }

    #[test]
    fn a_field_line_that_is_not_text_is_skipped_not_reported() {
        let mut hm = headers(&["max-age=60"]);
        hm.append("cache-control", HeaderValue::from_bytes(&[0xff]).unwrap());
        assert_eq!(delta_seconds(&hm, "max-age"), Some(60));
    }

    #[test]
    fn delta_seconds_skips_members_that_carry_no_value() {
        let hm = headers(&["max-age=abc, max-age=-1, max-age=5"]);
        assert_eq!(delta_seconds(&hm, "max-age"), Some(5));
        assert_eq!(delta_seconds(&hm, "s-maxage"), None);
    }

    /// A rule reporting the malformed value has to see it; only the lifetime
    /// question filters.
    #[test]
    fn a_directive_reports_its_argument_as_written() {
        let hm = headers(&["max-age=-1"]);
        let d = directives(&hm).next().unwrap();
        assert_eq!(d.delta_seconds(), Some(-1));
        assert_eq!(delta_seconds(&hm, "max-age"), None);
    }

    /// The syntax rules see what the question-asking readers filter away.
    #[test]
    fn members_keeps_the_empty_elements_directives_drops() {
        let hm = headers(&["max-age=1, ,public"]);
        assert_eq!(
            members(&hm).collect::<Vec<_>>(),
            ["max-age=1", "", "public"]
        );
        assert_eq!(directives(&hm).count(), 2);
    }

    /// An empty *value* is a zero-element list and contributes no member; an
    /// empty *element* inside a list is a member, and a defect.
    #[test]
    fn an_empty_field_value_is_a_zero_element_list() {
        assert_eq!(members(&headers(&[""])).count(), 0);
        assert_eq!(members(&headers(&["   "])).count(), 0);
        assert_eq!(members(&headers(&[","])).collect::<Vec<_>>(), ["", ""]);
        assert_eq!(
            members(&headers(&["", "max-age=1"])).collect::<Vec<_>>(),
            ["max-age=1"]
        );
    }

    #[test]
    fn read_member_names_each_defect_in_the_directive_name() {
        assert_eq!(
            read_member("").unwrap_err(),
            "Empty directive in Cache-Control header"
        );
        assert_eq!(
            read_member("=1").unwrap_err(),
            "Empty directive name in Cache-Control member: '=1'"
        );
        assert_eq!(
            read_member("no cache").unwrap_err(),
            "Directive name contains invalid character: ' '"
        );
        let directive = read_member("max-age=60").unwrap();
        assert_eq!(directive.name, "max-age");
        assert_eq!(directive.argument, Some("60"));
    }

    #[test]
    fn empty_members_are_not_directives() {
        let hm = headers(&[", ,max-age=1,"]);
        assert_eq!(directives(&hm).count(), 1);
    }
}
