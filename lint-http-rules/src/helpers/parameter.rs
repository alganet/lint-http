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

use crate::helpers::headers::trim_ows;
use crate::helpers::list::split_semicolons_respecting_quotes;

/// One `parameter` of a `parameters` group, split but not judged.
///
/// `value` is **as written** — a `quoted-string` still carries its DQUOTEs.
/// Whether this field's value half is § 5.6.6's `( token / quoted-string )`, a
/// narrower production, or one literal is the caller's grammar and not this
/// walk's, and [`token_or_quoted_string`](crate::helpers::word::token_or_quoted_string) is what reads it where it is the
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
    /// **Every caller reports it, and this flag is why they could.** § 5.6.6's
    /// Note forbids whitespace there in as many words — *"not even 'bad'
    /// whitespace"* — but for a while only `expect_header_valid` acted on it
    /// and the rules reading a media type trimmed it and published a "Known
    /// leniency" paragraph instead. A walk that trimmed silently would have
    /// settled that question for all of them and left no branch to change; a
    /// walk that hands back what it found let the answer be revisited where it
    /// was made.
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

// ── `ext-value`, the other form a parameter value takes ──────────────
//
// RFC 8187's `filename*=UTF-8''...`. Not a separate question and so not a
// separate module: it is what a parameter value may be when the parameter name
// ends in `*`, and every reader of it is already reading parameters.

/// Validate an RFC 8187 `ext-value` (e.g. `UTF-8''%e2%82%ac%20rates`).
/// Returns Ok(()) if the value matches the expected pattern and contains
/// only allowed characters/percent-escapes, or Err(msg) describing the
/// problem.
///
/// This said RFC 5987, which RFC 8187 obsoletes and moved to Historic. The
/// pointer is worth correcting and worth not overstating: the two documents'
/// `ext-value`, `value-chars`, `pct-encoded` and `attr-char` productions are
/// byte-for-byte identical, so nothing here changed meaning when the reference
/// did. What 8187 changed is elsewhere -- the ISO-8859-1 requirement is gone,
/// and it stopped trying to define a generic `parameter` rule.
///
/// The `charset` is `"UTF-8" / mime-charset`, and both alternatives are read
/// here as the second one: `mime-charset = 1*mime-charsetc` derives `UTF-8`
/// itself, so one walk answers the production. This said the charset was
/// checked "only for being ASCII and quote-free, which is far looser than
/// `mime-charset`", and it was -- `UTF-8.1''x` and `iso 8859-1''x` passed a
/// reader that then quoted every other production in the value. What the walk
/// does *not* decide is which charset a producer may choose, because that is
/// not the grammar: `iso-8859-1` derives from `mime-charset` and § 3.2.1
/// forbids a producer to use it in the next paragraph, which is a different
/// claim about a value this function calls well-formed.
///
// cite(RFC 8187 § 3.2.1): "ext-value = charset  "'" [ language ] "'" value-chars"
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
    // `1*mime-charsetc`, transcribed. The production is RFC 2978 § 2.3's with
    // the single quote taken out -- which the section says in as many words,
    // and which the delimiter above already made true here -- and it is
    // narrower than `token` in both directions: it admits `{` and `}`, which
    // `tchar` does not, and refuses `.`, `*`, `|` and `'`, which `tchar`
    // admits. So a charset is not "a word that is not the delimiter", and
    // `UTF-8.1` is not one.
    //
    // cite(RFC 8187 § 3.2.1, label: mime-charset): "mime-charset  = 1*mime-charsetc"
    // cite(RFC 8187 § 3.2.1, label: mime-charsetc): "mime-charsetc = ALPHA / DIGIT"
    // cite(RFC 8187 § 3.2.2): "The <mime-charset> ABNF defined here differs from the one in Section 2.3 of [RFC2978] in that it does not allow the single quote character"
    if let Some(c) = charset.chars().find(|c| {
        !(c.is_ascii_alphanumeric()
            || matches!(
                c,
                '!' | '#' | '$' | '%' | '&' | '+' | '-' | '^' | '_' | '`' | '{' | '}' | '~'
            ))
    }) {
        return Err(format!(
            "charset '{charset}' in ext-value holds {}, which mime-charset does not admit",
            crate::helpers::shown::describe_char(c)
        ));
    }

    // Language part may be empty; we don't strictly validate language tags here
    let value_chars = &val[second_quote + 1..];
    if value_chars.is_empty() {
        // empty value is allowed
        return Ok(());
    }

    let mut i = 0usize;
    let bytes = value_chars.as_bytes();
    // cite(RFC 8187 § 3.2.1): "value-chars   = *( pct-encoded / attr-char )"
    while i < bytes.len() {
        let b = bytes[i];
        // This branch is why `%` is absent from the attr-char table below rather
        // than merely unreachable in it: a `%` here is always the start of an
        // escape, and the two productions do not overlap.
        //
        // cite(RFC 8187 § 3.2.1): "pct-encoded   = "%" HEXDIG HEXDIG"
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
        // The table carried a `'%'` for as long as it has existed, under a comment
        // claiming it was RFC 5987's attr-char. It was not: both documents spell
        // this production identically and both exclude `%`, along with `*` and `'`.
        // It was dead as well as wrong -- the branch above consumes every `%` before
        // this arm is reached -- so removing it moved no test.
        //
        // cite(RFC 8187 § 3.2.1): "attr-char     = ALPHA / DIGIT / "!" / "#" / "$" / "&" / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~" ; token except ( "*" / "'" / "%" )"
        if ch.is_ascii_alphanumeric()
            || matches!(
                ch,
                '!' | '#' | '$' | '&' | '+' | '-' | '.' | '^' | '_' | '`' | '|' | '~'
            )
        {
            i += 1;
            continue;
        }
        return Err(format!("invalid character '{}' in ext-value", ch));
    }

    Ok(())
}

/// The `charset` an `ext-value` names, when it is not `UTF-8`.
///
/// The second of § 3.2.1's two claims about the value, and it is asked only of
/// a value [`validate_ext_value`] has accepted: the sentence forbidding an
/// encoding is about a *choice* the producer made, and a value that derives
/// from no `ext-value` chose nothing. Callers judge in that order for the same
/// reason.
///
/// Folded, because the section says character encoding names are matched
/// case-insensitively — so `utf-8` is `UTF-8` and neither is reported.
///
// cite(RFC 8187 § 3.2.1, label: producers): "Producers MUST use the "UTF-8" ([RFC3629]) character encoding."
// cite(RFC 8187 § 3.2.1, label: folding): "Note that both character encoding names and language tags are restricted to the US-ASCII coded character set and are matched case-insensitively"
pub fn ext_value_charset_reserved(val: &str) -> Option<&str> {
    let charset = &val[..val.find('\'')?];
    (!charset.eq_ignore_ascii_case("UTF-8")).then_some(charset)
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

    /// `%` is not an attr-char. It reaches this function only as the opening of a
    /// `pct-encoded`, and the branch handling that runs first -- so a `%` that is
    /// not two hex digits is an incomplete escape, never a literal.
    #[test]
    fn percent_is_only_ever_an_escape() {
        assert!(validate_ext_value("UTF-8''%41").is_ok());
        assert!(validate_ext_value("UTF-8''a%20b").is_ok());
        assert!(validate_ext_value("UTF-8''%").is_err());
        assert!(validate_ext_value("UTF-8''a%b").is_err());
        assert!(validate_ext_value("UTF-8''100%").is_err());
    }

    /// The three characters `token` has and `attr-char` does not.
    #[test]
    fn attr_char_excludes_star_quote_and_percent() {
        assert!(validate_ext_value("UTF-8''a*b").is_err());
        assert!(validate_ext_value("UTF-8''a{b").is_err());
        assert!(validate_ext_value("UTF-8''ok-name.ext~1").is_ok());
    }

    /// The charset a value names, and the fold § 3.2.1 requires of the
    /// comparison. `None` is the answer for `UTF-8` in any case, and for a
    /// value with no separator at all — which is not this reader's verdict to
    /// give, since the grammar refused it first.
    #[test]
    fn the_reserved_charset_is_read_case_insensitively() {
        assert_eq!(ext_value_charset_reserved("UTF-8''x"), None);
        assert_eq!(ext_value_charset_reserved("utf-8'en'x"), None);
        assert_eq!(
            ext_value_charset_reserved("iso-8859-1'en'%A3"),
            Some("iso-8859-1")
        );
        assert_eq!(
            ext_value_charset_reserved("Shift_JIS''x"),
            Some("Shift_JIS")
        );
        assert_eq!(ext_value_charset_reserved("UTF-8x"), None);
    }

    /// `mime-charset` crosses `token` rather than sitting inside it, and each
    /// row is one of the four places the two productions disagree. The last is
    /// the one this reader used to admit: `UTF-8.1` is a `token`, is ASCII, and
    /// carries no quote, so every test the charset had passed on it.
    #[test]
    fn mime_charset_is_not_the_token_production() {
        // Registered spellings, which is what the alternation is for.
        assert!(validate_ext_value("UTF-8''x").is_ok());
        assert!(validate_ext_value("iso-8859-1''x").is_ok());
        // `{` and `}` are `mime-charsetc` and no `tchar`.
        assert!(validate_ext_value("a{b}''x").is_ok());
        // `.`, `*` and `|` are `tchar` and no `mime-charsetc`.
        assert!(validate_ext_value("UTF-8.1''x").is_err());
        assert!(validate_ext_value("UTF*8''x").is_err());
        assert!(validate_ext_value("UTF|8''x").is_err());
        // And a charset is one word: the space is nothing either production
        // admits, and it was the plainest of the values that used to pass.
        assert!(validate_ext_value("iso 8859-1''x").is_err());
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
}
