// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! The `parameters` production: `*( OWS ";" OWS [ parameter ] )`.
//!
//! General, and shelved as such rather than under the grammar that reads it
//! most. A `media-type` carries parameters, and so does `Content-Disposition`,
//! and so does `Expect` — [`parameters`] takes any `;`-separated tail and knows
//! nothing about what preceded it. Filing it under `media_type` would have named
//! it for its busiest caller and left `expect_header_valid` importing a media
//! type to read an `Expect` parameter.
//!
//! [`ParameterDefect`] is the typed defect: a parameter can fail as a whole
//! segment, as a name, or as a value, and each carries the borrowed text that
//! failed so the caller can name it without re-splitting. Splitting is
//! `helpers::headers`' quote-aware splitter, because a parameter value may be a
//! `quoted-string` holding the very `;` that would otherwise end it.
//!
// cite(RFC 9110 § 5.6.6): "parameters      = *( OWS ";" OWS [ parameter ] )"

use crate::helpers::headers::{split_semicolons_respecting_quotes, trim_ows};

/// One `parameter` of a `parameters` group, split but not judged.
///
/// `value` is **as written** — a `quoted-string` still carries its DQUOTEs.
/// Whether this field's value half is § 5.6.6's `( token / quoted-string )`, a
/// narrower production, or one literal is the caller's grammar and not this
/// walk's, and [`token_or_quoted_string`](crate::helpers::headers::token_or_quoted_string) is what reads it where it is the
/// former.
pub struct Parameter<'a> {
    /// The `parameter-name` as written. Case folding is the caller's — § 5.6.6
    /// makes the name case-insensitive, but a rule reporting *what a sender
    /// wrote* often wants the spelling back.
    pub name: &'a str,
    /// The `parameter-value` as written, DQUOTEs included.
    pub value: &'a str,
    /// Whether whitespace sat beside the `=`.
    ///
    /// **This is the "Known leniency" six rules describe in prose, returned as a
    /// fact instead.** § 5.6.6's Note forbids whitespace there in as many words
    /// — *"not even 'bad' whitespace"* — and six rules trim it and say so in
    /// their `description()`, while `expect_header_valid` reports it. A
    /// walk that trimmed silently would have to pick one of those; a walk that
    /// hands back what it found lets each caller keep the answer its own audit
    /// reached, and turns a paragraph of prose into a branch a reader can see.
    pub whitespace_beside_equals: bool,
}

/// Why a segment of a `parameters` group is not a `parameter`.
pub enum ParameterDefect<'a> {
    /// The segment carries no `=`. `parameter = parameter-name "="
    /// parameter-value` makes neither the delimiter nor the value optional, so a
    /// bare token among the parameters is not a valueless flag — it is not a
    /// `parameter` at all. Carries the segment as written.
    NoEquals(&'a str),
}

/// Walk `parameters = *( OWS ";" OWS [ parameter ] )`.
///
/// Four decisions, and they are the four every hand copy of this production in
/// the tree had to make: split at the top-level semicolons only (a `;` inside a
/// `quoted-string` parameter value starts no new parameter), drop the `OWS` the
/// production prints beside them, **skip an empty segment** — `[ parameter ]` is
/// bracketed, so `text/plain; charset=utf-8;` is a conforming zero-parameter
/// repetition rather than a defect — and cut each remaining segment at its
/// **first** `=`, because `parameter-name` is a `token` and `=` is no `tchar`,
/// so no name can hold one and every later `=` belongs to the value.
///
/// What is *not* decided here: whether the name is a `token`, whether the value
/// derives from this field's value production, whether an empty name is a
/// finding, and what whitespace beside the `=` means. Those are four different
/// answers across the callers, which is why the walk stops where it does.
///
/// The input is the run *after* the media type — what [`parse_media_type`](crate::helpers::media_type::parse_media_type) puts
/// in `params` — not the whole field value.
///
// cite(RFC 9110 § 5.6.6): "parameters      = *( OWS ";" OWS [ parameter ] )"
// cite(RFC 9110 § 5.6.6): "parameter       = parameter-name "=" parameter-value"
// cite(RFC 9110 § 5.6.6): "parameter-name  = token"
// cite(RFC 9110 § 5.6.3, label: OWS grammar): "OWS            = *( SP / HTAB )"
pub fn parameters(
    params: &str,
) -> impl Iterator<Item = Result<Parameter<'_>, ParameterDefect<'_>>> {
    split_semicolons_respecting_quotes(params)
        .into_iter()
        .filter_map(parameter_of)
        .collect::<Vec<_>>()
        .into_iter()
}

/// One already-split segment of a `parameters` group, read as a `parameter`.
///
/// `None` for an empty segment: `[ parameter ]` is bracketed, so a repetition
/// that generated a semicolon and nothing after it has still conformed.
///
/// Separate from [`parameters`] because two rules reach their parameters through
/// a split they have already made for another reason — `media-range` and
/// `expectation` both put the thing the field is *about* in the first segment
/// and the parameters in the rest — and joining the tail back together only to
/// split it again would be a second parse of a value already parsed.
///
/// The cut is at the **first** `=`: `parameter-name` is a `token` and `=` is no
/// `tchar`, so no name can hold one and every later `=` belongs to the value.
///
// cite(RFC 9110 § 5.6.6): "parameter       = parameter-name "=" parameter-value"
// cite(RFC 9110 § 5.6.6): "parameter-name  = token"
pub fn parameter_of(segment: &str) -> Option<Result<Parameter<'_>, ParameterDefect<'_>>> {
    if segment.is_empty() {
        return None;
    }
    Some(match segment.find('=') {
        None => Err(ParameterDefect::NoEquals(segment)),
        Some(eq) => {
            let (name_written, rest) = segment.split_at(eq);
            let value_written = &rest[1..];
            let name = trim_ows(name_written);
            let value = trim_ows(value_written);
            Ok(Parameter {
                name,
                value,
                whitespace_beside_equals: name.len() != name_written.len()
                    || value.len() != value_written.len(),
            })
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The four decisions the walk makes, and the one it deliberately does not.
    #[test]
    fn parameters_splits_skips_and_cuts_at_the_first_equals() {
        let read: Vec<_> = parameters("charset=utf-8; foo=\"a;b\"")
            .map(|p| p.ok().map(|p| (p.name, p.value)))
            .collect();
        assert_eq!(
            read,
            vec![Some(("charset", "utf-8")), Some(("foo", "\"a;b\""))],
            "a `;` inside a quoted-string starts no new parameter, and the value keeps its DQUOTEs"
        );

        // `[ parameter ]` is bracketed, so a trailing or doubled semicolon is a
        // conforming zero-parameter repetition and yields nothing at all.
        assert_eq!(parameters("a=b;").count(), 1);
        assert_eq!(parameters("a=b;;c=d").count(), 2);
        assert_eq!(parameters(";").count(), 0);

        // The first `=` is the delimiter: `parameter-name` is a `token` and `=`
        // is no `tchar`, so no name holds one.
        let base64ish: Vec<_> = parameters("v=a=b=")
            .map(|p| p.ok().map(|p| (p.name, p.value)))
            .collect();
        assert_eq!(base64ish, vec![Some(("v", "a=b="))]);

        // A segment with no `=` is a defect and not a valueless flag -- named,
        // so each caller can decide whether it is its finding.
        assert!(matches!(
            parameters("charset").next(),
            Some(Err(ParameterDefect::NoEquals("charset")))
        ));
    }

    /// § 5.6.6's Note forbids whitespace beside the `=` and six rules tolerate
    /// it anyway. The walk reports the fact rather than picking a side, which is
    /// what lets `expect_header_valid` enforce the Note while the media
    /// type readers keep the leniency their descriptions publish.
    #[test]
    fn parameters_returns_the_whitespace_beside_the_equals_rather_than_deciding_it() {
        let ws = |s: &str| {
            parameters(s)
                .next()
                .expect("one parameter")
                .ok()
                .expect("well formed")
                .whitespace_beside_equals
        };
        assert!(!ws("a=b"));
        assert!(ws("a =b"));
        assert!(ws("a= b"));
        assert!(ws("a =\tb"));
        // The name and value still come back trimmed, so a caller that drops the
        // flag reads exactly what it read before the flag existed.
        let p = parameters("a = b").next().unwrap().ok().unwrap();
        assert_eq!((p.name, p.value), ("a", "b"));
    }
}
