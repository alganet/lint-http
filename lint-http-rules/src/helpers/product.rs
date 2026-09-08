// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! The `product *( RWS ( product / comment ) )` grammar, shared by `Server` and
//! `User-Agent`.
//!
//! RFC 9110 gives the two fields the same production and defines `product`
//! itself only once, under `User-Agent`; the `Server` section points back at it
//! rather than restating it. One implementation here follows the specification's
//! own structure -- and is the reason `Server` and `User-Agent` cannot drift
//! apart the way two hand-written copies of the same grammar did.
//!
// cite(RFC 9110 § A): "Server = product *( RWS ( product / comment ) )"
// cite(RFC 9110 § A): "User-Agent = product *( RWS ( product / comment ) )"
// cite(RFC 9110 § 10.2.4): "Each product identifier consists of a name and optional version, as defined in Section 10.1.5."

use crate::helpers::comment::{scan_comment, CommentDefect};
use crate::helpers::shown::describe_octet as describe;
use crate::helpers::token::is_tchar_byte;

/// Which half of a member the reader had just finished when the value stopped
/// deriving — the half a finding names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Part {
    /// The `token` a product opens with.
    Name,
    /// The `token` after the slash.
    Version,
    /// A parenthesised comment.
    Comment,
}

impl Part {
    /// The words a finding calls this half.
    fn label(self) -> &'static str {
        match self {
            Self::Name => "product token",
            Self::Version => "product version",
            Self::Comment => "comment",
        }
    }
}

/// Why a value is not `product *( RWS ( product / comment ) )`.
///
/// The list is longer than most readers' because the production is an assembly
/// of three things, and only one of them — the `token` both halves of a
/// `product` are — has a subject in the catalogue. What separates the arms is
/// therefore not severity but ownership: `NameEmpty`, `VersionEmpty` and
/// `Character` are `token = 1*tchar` failing, and the rest is this production
/// saying how its parts are put together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProductDefect {
    /// The whole field value, once trimmed, is empty.
    ValueEmpty,
    /// The value opens with something that is no `product` — a comment, most
    /// often, which the repetition only reaches *after* one.
    DoesNotOpenWithProduct,
    /// A `token` of no `tchar` at all where a product identifier was due,
    /// carrying the octet that was there instead (`None` at end of value).
    NameEmpty(Option<u8>),
    /// A slash with no `product-version` after it.
    VersionEmpty,
    /// An octet no `tchar` admits, in the half named.
    Character {
        /// The half the octet stopped.
        part: Part,
        /// The octet.
        byte: u8,
    },
    /// Two elements with no `RWS` between them, the second being a comment.
    SeparatorMissingBeforeComment(Part),
    /// Two elements with no `RWS` between them, the second being a product.
    SeparatorMissingBeforeProduct(Part),
    /// The comment reader's verdict, carried out whole.
    Comment(CommentDefect),
}

impl ProductDefect {
    /// The finding fragment. Callers name the field the value came from and put
    /// this after it.
    pub fn message(self) -> String {
        match self {
            Self::ValueEmpty => "value is empty".to_string(),
            Self::DoesNotOpenWithProduct => {
                "value does not begin with a product identifier".to_string()
            }
            Self::NameEmpty(None) => {
                "expected a product identifier, found end of value".to_string()
            }
            Self::NameEmpty(Some(b)) => {
                format!("expected a product identifier, found {}", describe(b))
            }
            Self::VersionEmpty => "product version is empty".to_string(),
            Self::Character { part, byte } => format!(
                "{} contains invalid character: {}",
                part.label(),
                describe(byte)
            ),
            Self::SeparatorMissingBeforeComment(part) => format!(
                "missing required whitespace before a comment, after the {}",
                part.label()
            ),
            Self::SeparatorMissingBeforeProduct(part) => format!(
                "missing required whitespace before a product identifier, after the {}",
                part.label()
            ),
            Self::Comment(defect) => defect.message(),
        }
    }
}

/// Consume the `product` starting at `start`.
///
/// Returns the offset just past it and whether a `product-version` was present,
/// so the caller can name the half a trailing invalid octet belongs to.
fn scan_product(v: &[u8], start: usize) -> Result<(usize, bool), ProductDefect> {
    // cite(RFC 9110 § A): "product = token [ "/" product-version ] product-version = token"
    let mut i = start;
    while i < v.len() && is_tchar_byte(v[i]) {
        i += 1;
    }
    if i == start {
        return Err(ProductDefect::NameEmpty(v.get(start).copied()));
    }

    if i < v.len() && v[i] == b'/' {
        let version_start = i + 1;
        let mut j = version_start;
        while j < v.len() && is_tchar_byte(v[j]) {
            j += 1;
        }
        // `product-version = token` and `token = 1*tchar`, so the slash cannot
        // be the last octet of a product and cannot be followed by a delimiter.
        if j == version_start {
            return match v.get(j) {
                None => Err(ProductDefect::VersionEmpty),
                Some(&b) => Err(ProductDefect::Character {
                    part: Part::Version,
                    byte: b,
                }),
            };
        }
        return Ok((j, true));
    }

    Ok((i, false))
}

/// Validate a whole `product *( RWS ( product / comment ) )` field value.
///
/// Takes the raw octets rather than a `&str`: `ctext` admits `obs-text`
/// (%x80-FF), so a conforming value need not be visible US-ASCII, and decoding
/// the value before parsing it would reject `Server: Apache (Ünix)` -- valid --
/// while saying nothing about where the octet actually sat.
pub fn check_product_list(value: &[u8]) -> Result<(), ProductDefect> {
    // cite(RFC 9110 § 5.5): "A field value does not include leading or trailing whitespace."
    let mut v = value;
    while let [b' ' | b'\t', rest @ ..] = v {
        v = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = v {
        v = rest;
    }

    if v.is_empty() {
        return Err(ProductDefect::ValueEmpty);
    }

    // The field value begins with a `product`; a comment is only reachable
    // through the repetition that follows one. So a value that opens with a
    // comment -- or holds nothing else -- does not match the grammar, however
    // much of a product identifier it appears to describe.
    // cite(RFC 9110 § 10.2.4): "The Server header field value consists of one or more product identifiers, each followed by zero or more comments (Section 5.6.5), which together identify the origin server software and its significant subproducts."
    // cite(RFC 9110 § 10.1.5): "The User-Agent field value consists of one or more product identifiers, each followed by zero or more comments (Section 5.6.5), which together identify the user agent software and its significant subproducts."
    if !is_tchar_byte(v[0]) {
        return Err(ProductDefect::DoesNotOpenWithProduct);
    }
    let (mut i, mut previous) = match scan_product(v, 0)? {
        (end, true) => (end, Part::Version),
        (end, false) => (end, Part::Name),
    };

    while i < v.len() {
        // Every element after the first is introduced by whitespace, so the
        // octet that stopped the previous element is an error either way -- but
        // which error depends on the octet. One that could open an element is a
        // missing separator; one that could not was never a separator question
        // and belongs to the element it interrupted.
        // cite(RFC 9110 § 5.6.3): "The RWS rule is used when at least one linear whitespace octet is required to separate field tokens."
        // cite(RFC 9110 § 5.6.3): "RWS = 1*( SP / HTAB )"
        if v[i] != b' ' && v[i] != b'\t' {
            return Err(if v[i] == b'(' {
                ProductDefect::SeparatorMissingBeforeComment(previous)
            } else if is_tchar_byte(v[i]) {
                ProductDefect::SeparatorMissingBeforeProduct(previous)
            } else {
                ProductDefect::Character {
                    part: previous,
                    byte: v[i],
                }
            });
        }
        while i < v.len() && (v[i] == b' ' || v[i] == b'\t') {
            i += 1;
        }
        // Trailing whitespace was removed above, so RWS is always followed by
        // an element here.
        debug_assert!(i < v.len());

        if v[i] == b'(' {
            i = scan_comment(v, i).map_err(ProductDefect::Comment)?;
            previous = Part::Comment;
        } else {
            let (end, version) = scan_product(v, i)?;
            i = end;
            previous = if version { Part::Version } else { Part::Name };
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    // The two examples RFC 9110 prints for these fields.
    #[case("CERN-LineMode/2.15 libwww/2.17b3")]
    #[case("CERN/3.0 libwww/2.17")]
    #[case("nginx")]
    #[case("nginx/1.18.0")]
    #[case("Apache/2.4.41 (Ubuntu)")]
    #[case("Mozilla/5.0 (compatible; Bot/1.0; +http://example.com)")]
    #[case("A/1 (outer (inner) still-outer) B/2")]
    #[case("A/1 (escaped \\) paren)")]
    #[case("A/1 (a)\t(b) C/3")]
    fn accepts_conforming_values(#[case] v: &str) {
        assert_eq!(check_product_list(v.as_bytes()), Ok(()), "{v}");
    }

    #[rstest]
    #[case("", "value is empty")]
    #[case("   ", "value is empty")]
    #[case("/1.0", "does not begin with a product identifier")]
    #[case("(Apache)", "does not begin with a product identifier")]
    #[case("(test) nginx/1.18.0", "does not begin with a product identifier")]
    #[case("Bad@Srv/1.0", "product token contains invalid character: '@'")]
    #[case("Srv/1@0", "product version contains invalid character: '@'")]
    #[case("Srv//1.0", "product version contains invalid character: '/'")]
    #[case("Srv/", "product version is empty")]
    #[case("Agent  /1.0", "expected a product identifier, found '/'")]
    #[case("Bad (unbalanced", "unterminated parenthesized comment")]
    #[case("Bad )extra", "expected a product identifier, found ')'")]
    #[case(
        "nginx/1.0(Ubuntu)",
        "missing required whitespace before a comment, after the product version"
    )]
    #[case(
        "nginx(Ubuntu)",
        "missing required whitespace before a comment, after the product token"
    )]
    #[case(
        "nginx/1.0 (Ubuntu)mod_x/2",
        "missing required whitespace before a product identifier, after the comment"
    )]
    #[case("Agent\\(1.0\\)", "product token contains invalid character: '\\'")]
    fn rejects_non_conforming_values(#[case] v: &str, #[case] expected: &str) {
        let err = check_product_list(v.as_bytes()).expect_err(v).message();
        assert!(err.contains(expected), "{v}: got {err}");
    }

    /// `ctext` admits `obs-text`, so a comment may legally hold octets that are
    /// not visible US-ASCII -- and the same octet outside a comment is not a
    /// `tchar` and must still be reported.
    #[test]
    fn obs_text_is_a_comment_only_licence() {
        let mut inside = b"Apache (U".to_vec();
        inside.push(0xdc);
        inside.extend_from_slice(b"nix)");
        assert_eq!(check_product_list(&inside), Ok(()));

        let mut outside = b"Apac".to_vec();
        outside.push(0xdc);
        outside.extend_from_slice(b"he");
        assert!(check_product_list(&outside)
            .expect_err("obs-text is not a tchar")
            .message()
            .contains("0xDC"));
    }

    /// A backslash is a `quoted-pair` inside a comment and an ordinary octet
    /// outside one, where it is not a `tchar` -- the two constructs §5.6.4 names
    /// are the whole of the escape's reach.
    #[test]
    fn backslash_escapes_only_inside_a_comment() {
        assert_eq!(check_product_list(b"A/1 (\\(unclosed-looking)"), Ok(()));
        assert!(check_product_list(b"Agent\\ Foo")
            .expect_err("a backslash outside a comment is not an escape")
            .message()
            .contains("invalid character: '\\'"));
    }

    /// A CTL is not `ctext`, so a comment cannot launder one into a field value.
    #[test]
    fn control_characters_are_rejected_inside_comments() {
        assert!(check_product_list(b"A/1 (a\x00b)")
            .expect_err("NUL is not ctext")
            .message()
            .contains("0x00"));
    }
}
