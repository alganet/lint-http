// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! The `media-type` production: `type "/" subtype parameters`.
//!
//! Built on `helpers::parameter`, which is the tail of this grammar and is its
//! own module because `Content-Disposition` and `Expect` carry parameters
//! without carrying a media type. What is left here is what makes a media type
//! one: the slash, the two halves either side of it, the `+suffix` convention
//! on the subtype, and the `boundary` parameter a `multipart/*` body is framed
//! by.
//!
//! [`parse_media_type`] returns the parts as written and refuses only what the
//! shape refuses — an absent slash, an empty half. Whether those halves are
//! *good tokens* is [`media_type_parts_defect`]'s separate question, kept
//! separate because a caller reporting on a registered type and a caller
//! reporting on a malformed one want different sentences from the same value.

use crate::helpers::headers::{token_or_quoted_string, trim_ows, WordDefect};
use crate::helpers::parameter::{parameters, ParameterDefect};

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
/// but it separates the structure. [`media_type_parts_defect`] below is the
/// other half.
/// Returns an error message if the structure is invalid (missing slash, empty parts).
///
/// Every trim here is [`trim_ows`] and none of them is `str::trim`, which trims
/// Unicode whitespace: a caller reading a field through
/// [`combined_field_value_as_written`](crate::helpers::headers::combined_field_value_as_written) hands this one `char` per octet, so %xA0
/// arrives as U+00A0 and %x85 as U+0085 — both `obs-text`, which no part of
/// `media-type` admits and both of which `str::trim` silently removed. That
/// erased the one unambiguous defect in `application/example%xA0`, which came
/// back as a clean `subtype` of `example`. The same reasoning is written out at
/// [`split_semicolons_respecting_quotes`](crate::helpers::headers::split_semicolons_respecting_quotes), which had already been fixed.
///
/// The two halves of `type "/" subtype` are **not** trimmed at all, because the
/// production prints no `OWS` between them: `application / example` derives from
/// nothing, and trimming each side handed the character scan two clean tokens.
/// What is trimmed is the whole value (§ 5.5) and the run before the first
/// semicolon, where `parameters` does print `OWS`.
///
// cite(RFC 9110 § 5.6.6): "parameters      = *( OWS ";" OWS [ parameter ] )"
// cite(RFC 9110 § 5.5): "A field value does not include leading or trailing whitespace.  When a specific version of HTTP allows such whitespace to appear in a message, a field parsing implementation MUST exclude such whitespace prior to evaluating the field value."
pub fn parse_media_type(val: &str) -> Result<ParsedMediaType<'_>, String> {
    let trimmed = trim_ows(val);
    if trimmed.is_empty() {
        return Err("Empty media-type".into());
    }

    let mut parts = trimmed.splitn(2, ';');
    let media = trim_ows(
        parts
            .next()
            .expect("splitn always yields at least one element"),
    );
    let params = parts.next().map(trim_ows).filter(|p| !p.is_empty());

    // cite(RFC 9110 § 8.3.1, label: media-type grammar): "media-type = type "/" subtype parameters"
    if !media.contains('/') {
        return Err(format!(
            "Invalid media-type '{}': missing '/' between type and subtype",
            val
        ));
    }

    let mut ts = media.splitn(2, '/');
    let type_ = ts.next().unwrap_or("");
    let subtype = ts.next().unwrap_or("");

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

/// The half of `media-type` that `parse_media_type` above deliberately leaves:
/// having separated the parts, what each of them must *be*.
///
/// `None` where the parts derive from the production; otherwise the reason they
/// do not, phrased as a clause a caller prints after naming its own field. That
/// shape is what lets the two rules measuring a `media-type` — one reading
/// `Content-Type`, one reading each member of `Accept-Patch`'s `1#media-type` —
/// share one transcription of § 8.3.1 and § 5.6.6 while each says which field
/// the defect was found in. Written when the second caller arrived; before that
/// these four checks lived inside the first rule, where a second copy was the
/// only way to ask the same question of another field.
///
/// **The asterisk is not judged here.** `*` is a `tchar`, so `*/plain` and
/// `*/*` both derive from `media-type`; what an asterisk *means* is each
/// field's own question — `Content-Type` states one representation's media
/// type, while `Accept-Patch` is a list of them with no `media-range` anywhere
/// in its grammar — and the two rules answer it separately, at different
/// strengths, from different sentences.
///
/// **Every value this interpolates is escaped for display**, and it has to be:
/// the octets a `tchar` test rejects include the ones that print as nothing, so
/// a raw HTAB or CR reaching a finding breaks the line it is printed on rather
/// than appearing in it. `escape_debug` is not the `obs-text` answer — a
/// printable code point survives it, so %xC9 still shows as `É` — and naming an
/// octet is [`describe_octet`](crate::helpers::shown::describe_octet)'s job; the `#token` walks in this tree that do
/// name it are measuring a value whose every octet is one `char`, which a
/// `media-type` reaching this function is not guaranteed to be.
///
/// **One inherited leniency, and it is now a decision rather than an accident.**
/// `parameter` is `parameter-name "=" parameter-value` with no `OWS` anywhere in
/// it, and § 5.6.6 says so again in prose — *"Parameters do not allow whitespace
/// (not even 'bad' whitespace) around the '=' character"* — yet
/// `text/example; charset = utf-8` passes here. [`parameters`] hands back
/// `whitespace_beside_equals` rather than trimming in silence, and this function
/// reads it and drops it; that is what makes the "Known leniency" paragraph six
/// rules publish a true statement about the code rather than a plausible one.
/// Changing the answer changes those rules' verdicts, so it stays theirs.
/// `expect_header_valid` is the one caller in the tree that reports it.
///
/// cite(RFC 9110 § 8.3.1): "type       = token subtype    = token"
/// cite(RFC 9110 § 8.3.1): "The type and subtype tokens are case-insensitive."
pub fn media_type_parts_defect(parsed: &ParsedMediaType<'_>) -> Option<String> {
    // Case is not checked because there is nothing to check: both halves are
    // case-insensitive, so no spelling of them is wrong.
    if let Some(c) = crate::helpers::token::find_invalid_token_char(parsed.type_) {
        return Some(format!("invalid character '{}' in type", c.escape_debug()));
    }

    // Same production, other half; the quote above covers both lines of it.
    if let Some(c) = crate::helpers::token::find_invalid_token_char(parsed.subtype) {
        return Some(format!(
            "invalid character '{}' in subtype",
            c.escape_debug()
        ));
    }

    // A media type with no parameters is a media type: the term is `parameters`,
    // whose whole expansion is starred, so a value that stops after the subtype
    // has satisfied it and there is nothing below to run.
    // cite(RFC 9110 § 8.3.1): "The type/subtype MAY be followed by semicolon-delimited parameters (Section 5.6.6) in the form of name/value pairs."
    let params = parsed.params?;

    // Quote-aware, because a `;` inside a `quoted-string` parameter value does
    // not start the next parameter. Each segment comes back already trimmed of
    // the `OWS` the production prints beside its semicolons -- re-trimming it
    // with `str::trim` here undid that helper's own fix and put %xA0 and %x85
    // back out of reach.
    // The walk is `parameters`, which owns the split, the bracketed-empty skip
    // and the cut at the first `=`. Everything below is this function's: what a
    // name and a value have to be, and what its callers are told when they are
    // not.
    for parameter in parameters(params) {
        let parameter = match parameter {
            Ok(p) => p,
            // The "=" is not optional inside `parameter`, so a bare token among
            // the parameters is not a valueless flag.
            Err(ParameterDefect::NoEquals(segment)) => {
                return Some(format!(
                    "parameter '{}' missing '='",
                    segment.escape_debug()
                ))
            }
        };

        // The whitespace beside the `=` is the leniency named in this function's
        // doc comment, and it is declined *here* rather than absorbed by the
        // walk: § 5.6.6's Note forbids it, and five of the six rules reading a
        // media type through this function say in their `description()` that
        // they tolerate it. Reading the flag and dropping it is what makes that
        // paragraph true rather than merely plausible.
        let _ = parameter.whitespace_beside_equals;

        if parameter.name.is_empty() {
            return Some("empty parameter name".to_string());
        }
        // cite(RFC 9110 § 5.6.6): "parameter-name  = token"
        if let Some(c) = crate::helpers::token::find_invalid_token_char(parameter.name) {
            return Some(format!(
                "invalid character '{}' in parameter name '{}'",
                c.escape_debug(),
                parameter.name.escape_debug()
            ));
        }

        // `parameter-value = ( token / quoted-string )`, read by the function
        // that owns the alternation. This site was an eighth copy of it and was
        // missed when the other seven were converted, for the reason every stale
        // count in this campaign has had: the list was of *rules*, and this is a
        // helper.
        // cite(RFC 9110 § 5.6.6): "parameter-value = ( token / quoted-string )"
        match token_or_quoted_string(parameter.value) {
            Ok(_) => {}
            // `parameters` yields the value as written and does not judge it, so
            // an empty one arrives here. It derives from neither alternative.
            Err(WordDefect::Empty) => {
                return Some(format!(
                    "parameter '{}' has an empty value, and a parameter-value is a token or a quoted-string",
                    parameter.name.escape_debug()
                ))
            }
            Err(WordDefect::NotToken(c)) => {
                return Some(format!(
                    "invalid character '{}' in parameter value '{}'",
                    c.escape_debug(),
                    parameter.value.escape_debug()
                ))
            }
            // The reason quotes the value it was handed, so the escape goes
            // around the whole clause rather than around the name alone -- a
            // control octet inside the quoted-string is exactly what that reason
            // is about, and it arrived raw.
            Err(WordDefect::NotQuotedString(e)) => {
                return Some(format!(
                    "parameter '{}' has invalid quoted-string: {}",
                    parameter.name.escape_debug(),
                    e.escape_debug()
                ))
            }
        }
    }

    None
}

/// Extract the value of a `boundary` parameter from a `multipart/*` Content-Type header.
/// - Returns `Some(boundary)` unquoted/unescaped when present and well-structured, `None` otherwise.
/// - This helper is intentionally conservative: it returns `None` when the Content-Type cannot be
///   parsed or the boundary parameter is missing or not well-formed (e.g., invalid quoted-string).
///
/// **That contract used to hold for one alternative only.** "Not well-formed"
/// was honoured for a `quoted-string` and not for a `token`: an unquoted value
/// went back to the caller whatever octets it held, so `boundary=a b` — which
/// derives from no `parameter-value`, since SP is no `tchar` — was handed on as
/// the boundary `a b`, and the caller hunted a body for `--a b` delimiters on
/// the strength of a value the grammar does not generate. Both alternatives now
/// go through [`token_or_quoted_string`], so the function does what its own
/// second bullet says. What the sender meant by a malformed boundary is not
/// recoverable, and `multipart_boundary_syntax` is the rule that reports
/// it.
pub fn extract_multipart_boundary(val: &str) -> Option<String> {
    let parsed = parse_media_type(val).ok()?;
    if !parsed.type_.eq_ignore_ascii_case("multipart") {
        return None;
    }
    let params = parsed.params?;
    // The second `parameters` walk this module used to hold, and it disagreed
    // with the first in two places: it split with the same quote-aware splitter
    // but then re-trimmed each segment with `str::trim`, putting the %xA0 and
    // %x85 that splitter had deliberately left alone back out of reach, and it
    // read a segment with no `=` as something to skip rather than as a defect
    // -- which is right *here*, because a value that names no boundary is this
    // function's `None` rather than a finding.
    for parameter in parameters(params) {
        // A malformed segment names no boundary, and reporting is not this
        // function's job: `content_type_valid` reads the same
        // value through `media_type_parts_defect` and says so there.
        let Ok(parameter) = parameter else { continue };

        // cite(RFC 9110 § 5.6.6): "Parameter names are case-insensitive."
        if !parameter.name.eq_ignore_ascii_case("boundary") {
            continue;
        }

        // Deliberately conservative in one direction: every answer below that is
        // not a boundary is `None`, because a caller hunting a body for
        // `--<boundary>` delimiters must not be handed a guess.
        return match token_or_quoted_string(parameter.value) {
            Err(_) => None,
            Ok(content) => {
                let unquoted = content.into_owned();
                // A boundary of nothing delimits nothing. `trim_ows` and not
                // `str::trim`: RFC 2046's `bcharsnospace` admits no whitespace
                // of any kind, so an `obs-text` octet here is a defect the
                // boundary rule reports rather than padding to be removed.
                if trim_ows(&unquoted).is_empty() {
                    None
                } else {
                    Some(unquoted)
                }
            }
        };
    }
    None
}

/// Return the structured-syntax suffix part of a subtype if present (the part after the last `+`).
/// For example, `ld+json` -> `json`. This is a small helper for rules that need to inspect
/// subtype suffixes. Returns `None` for subtypes with no `+`.
pub fn media_type_subtype_suffix(subtype: &str) -> Option<&str> {
    if let Some(pos) = subtype.rfind('+') {
        Some(&subtype[pos + 1..])
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn test_media_type_subtype_suffix() {
        // No suffix
        assert_eq!(media_type_subtype_suffix("html"), None);
        // Common suffix
        assert_eq!(media_type_subtype_suffix("ld+json"), Some("json"));
        // Vendor with suffix
        assert_eq!(media_type_subtype_suffix("vnd.foo+xml"), Some("xml"));
        // Trailing plus (empty suffix)
        assert_eq!(media_type_subtype_suffix("foo+"), Some(""));
        // Multiple plus (take last)
        assert_eq!(media_type_subtype_suffix("a+b+json"), Some("json"));
    }

    #[test]
    fn extract_multipart_boundary_basic() {
        assert_eq!(
            extract_multipart_boundary("multipart/mixed; boundary=gc0p4Jq0M2Yt08j34c0p"),
            Some("gc0p4Jq0M2Yt08j34c0p".to_string())
        );
        assert_eq!(
            extract_multipart_boundary("multipart/mixed; boundary=\"a b\""),
            Some("a b".to_string())
        );
        assert_eq!(extract_multipart_boundary("text/plain; boundary=abc"), None);
        assert_eq!(extract_multipart_boundary("multipart/mixed"), None);
    }

    #[test]
    fn extract_multipart_boundary_edge_cases() {
        // quoted empty boundary -> treated as missing
        assert_eq!(
            extract_multipart_boundary("multipart/mixed; boundary=\"\""),
            None
        );
        // unquoted empty boundary -> treated as missing
        assert_eq!(
            extract_multipart_boundary("multipart/mixed; boundary="),
            None
        );
        // malformed quoted-string -> treated as missing
        assert_eq!(
            extract_multipart_boundary("multipart/mixed; boundary=\"unterminated"),
            None
        );
        // multiple params and surrounding whitespace
        assert_eq!(
            extract_multipart_boundary("multipart/mixed; foo=bar; boundary=abc ; baz=1"),
            Some("abc".to_string())
        );
        // A `;` inside a quoted value is not a parameter separator, so there is
        // no boundary parameter here. Returning one made the caller look for
        // delimiters the message never declared.
        assert_eq!(
            extract_multipart_boundary("multipart/mixed; foo=\"a; boundary=abc; b=1\""),
            None
        );
        // A quoted value carrying a `;` does not hide the real boundary after it.
        assert_eq!(
            extract_multipart_boundary("multipart/mixed; foo=\"a;b\"; boundary=abc"),
            Some("abc".to_string())
        );
    }
}
