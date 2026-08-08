// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! The `comment` production, shared by every field whose definition names it.
//!
//! RFC 9110 defines `comment` once, in §5.6.5, and the fields that admit one
//! reach it by naming it in their own grammar -- `Server` and `User-Agent`
//! through `product *( RWS ( product / comment ) )`, `Via` through
//! `[ RWS comment ]`. So the scanner belongs here rather than inside any one of
//! them: a second hand-written copy is the shape behind several of this tree's
//! past defects, and the naive one (count parentheses, ignore the backslash) is
//! wrong on a value the RFC itself prints.

use crate::helpers::headers::describe_octet;

/// `ctext` -- the text a comment may hold directly.
///
/// The ranges stop either side of the parentheses (%x21-27 ends before `(` at
/// %x28, %x2A-5B resumes after `)` at %x29) and skip the backslash at %x5C,
/// which `quoted-pair` covers instead. That exclusion is what makes the
/// depth counting in [`scan_comment`] sound: an unescaped parenthesis inside a
/// comment can only ever be structure, never text.
fn is_ctext(b: u8) -> bool {
    // cite(RFC 9110 § 5.6.5): "ctext          = HTAB / SP / %x21-27 / %x2A-5B / %x5D-7E / obs-text"
    b == b'\t'
        || b == b' '
        || (0x21..=0x27).contains(&b)
        || (0x2a..=0x5b).contains(&b)
        || (0x5d..=0x7e).contains(&b)
        || b >= 0x80
}

/// Consume the `comment` starting at `start` (which must be `(`) and return the
/// offset just past its closing `)`.
///
/// `depth` is not a convenience for tracking parentheses -- it is the production
/// being self-referential. `comment` appears inside its own definition, so a
/// comment may contain a comment, and a single "seen an open paren" flag would
/// be wrong rather than merely coarse: `(a (b) c)` would end at the first `)`
/// and leave ` c)` to be parsed as products.
///
/// Takes octets rather than a `&str` because `ctext` admits `obs-text`
/// (%x80-FF): a conforming comment need not be visible US-ASCII.
pub fn scan_comment(v: &[u8], start: usize) -> Result<usize, String> {
    // cite(RFC 9110 § 5.6.5): "comment        = "(" *( ctext / quoted-pair / comment ) ")""
    let mut i = start + 1;
    let mut depth = 1usize;

    while i < v.len() {
        let b = v[i];

        if b == b'\\' {
            // cite(RFC 9110 § 5.6.4): "The backslash octet ("\") can be used as a single-octet quoting mechanism within quoted-string and comment constructs."
            // cite(RFC 9110 § A): "quoted-pair = "\" ( HTAB / SP / VCHAR / obs-text )"
            let Some(&next) = v.get(i + 1) else {
                return Err("comment ends with a dangling backslash".into());
            };
            if !(next == b'\t' || (0x20..=0x7e).contains(&next) || next >= 0x80) {
                return Err(format!(
                    "comment contains an invalid quoted-pair: {}",
                    describe_octet(next)
                ));
            }
            i += 2;
            continue;
        }

        if b == b'(' {
            depth += 1;
        } else if b == b')' {
            depth -= 1;
            if depth == 0 {
                return Ok(i + 1);
            }
        } else if !is_ctext(b) {
            return Err(format!(
                "comment contains invalid character: {}",
                describe_octet(b)
            ));
        }

        i += 1;
    }

    Err("unterminated parenthesized comment".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The end offset is what tells a caller where the rest of the value
    /// starts, so it is asserted rather than only the success.
    #[test]
    fn a_comment_ends_at_its_own_closing_paren() {
        assert_eq!(scan_comment(b"(a (b) c) rest", 0), Ok(9));
    }

    /// An escaped closing parenthesis does not end the comment. A splitter that
    /// tracks depth without reading `quoted-pair` cuts `(a\), b)` in two, and
    /// nothing about the parentheses says it was wrong to.
    #[test]
    fn an_escaped_paren_does_not_close_a_comment() {
        assert_eq!(scan_comment(b"(a\\), b) rest", 0), Ok(8));
    }

    #[test]
    fn an_unterminated_comment_is_an_error() {
        assert!(scan_comment(b"(a b", 0)
            .expect_err("no closing paren")
            .contains("unterminated"));
    }
}
