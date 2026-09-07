// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

/// Helpers for RFC `token` (tchar) validation used by multiple rules.
pub fn is_tchar(c: char) -> bool {
    // cite(RFC 9110 § 5.6.2): "token = 1*tchar tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA"
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            '!' | '#'
                | '$'
                | '%'
                | '&'
                | '\''
                | '*'
                | '+'
                | '-'
                | '.'
                | '^'
                | '_'
                | '`'
                | '|'
                | '~'
        )
}

/// `tchar`, over a single octet.
///
/// [`is_tchar`] stays the sole transcription of the character set: every byte at
/// or above %x80 maps to a `char` outside the ASCII range, which it already
/// rejects, so `obs-text` is excluded here without a second copy of the list.
pub fn is_tchar_byte(b: u8) -> bool {
    is_tchar(b as char)
}

/// Return the first invalid character in `s` according to the `token` grammar,
/// or `None` if the entire string is valid.
pub fn find_invalid_token_char(s: &str) -> Option<char> {
    s.chars().find(|&c| !is_tchar(c))
}

/// The byte index at which the leading `token` in `s` ends -- `s.len()` when the
/// whole string is one.
///
/// A grammar that writes `token` followed by a delimiter (`expectation`'s `"="`,
/// a media type's `"/"`) has to cut the token off before it can judge either
/// half, and the cut and the character class have to be the same decision.
/// Asking [`find_invalid_token_char`] instead answers a different question: it
/// says the string is not *entirely* a token, which is the wrong verdict when
/// the grammar expects it not to be.
///
/// Every `tchar` is one octet, so the index is a `char` boundary and safe to
/// slice on.
pub fn token_run_end(s: &str) -> usize {
    s.find(|c| !is_tchar(c)).unwrap_or(s.len())
}

/// RFC 2045's `token`, over a single character — **not** `tchar`.
///
/// MIME subtracts a list of delimiters from the visible US-ASCII where HTTP
/// enumerates the characters it keeps, and the two alphabets come out one pair
/// apart. Counting them: the visible range holds 94 characters, MIME's fifteen
/// `tspecials` leave 79, and `tchar` names 77 (52 ALPHA, 10 DIGIT, 15
/// punctuation marks). The two the MIME alphabet has and this one does not are
/// `{` and `}` — RFC 2068's `tspecials` list them and RFC 2045's does not — so
/// those two octets derive from a MIME token and from no HTTP one. Nothing else
/// separates the pair: SPACE and the CTLs are excluded by both, and both stop
/// at US-ASCII.
///
/// That is why this is written as [`is_tchar`] plus two characters rather than
/// as a second transcription of the class, which could drift from the first.
/// The difference is reachable in one rule only — a `Content-Transfer-Encoding`
/// value is § 5.1's `token`, and using [`is_tchar`] on it reports `{` and `}`
/// as defects of a production that admits them. `multipart_boundary_syntax`
/// reads the same difference and is right to ignore it, because a `bchars`
/// admits neither character either way.
pub fn is_mime_token_char(c: char) -> bool {
    // The `tspecials` production is uncitable here for the same reason it is in
    // `keep_alive_header_valid`: its `<">` alternative leaves the quotation
    // marks in the line unpaired, and this cite grammar has no escape for that.
    // The list is transcribed in the note on the rule's `SpecRef` instead.
    // cite(RFC 2045 § 5.1): "token := 1*<any (US-ASCII) CHAR except SPACE, CTLs, or tspecials>"
    is_tchar(c) || matches!(c, '{' | '}')
}

/// Return the first character of `s` that RFC 2045's `token` does not admit, or
/// `None` when the whole string is one.
///
/// The MIME twin of [`find_invalid_token_char`]; [`is_mime_token_char`] carries
/// the reading of how far the two alphabets differ.
pub fn find_invalid_mime_token_char(s: &str) -> Option<char> {
    s.chars().find(|&c| !is_mime_token_char(c))
}

/// Return the first ASCII lowercase alphabetic character in `s` if any.
pub fn find_first_lowercase(s: &str) -> Option<char> {
    s.chars()
        .find(|&c| c.is_ascii_alphabetic() && c.is_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case('a', true)]
    #[case('Z', true)]
    #[case('3', true)]
    #[case('!', true)]
    #[case(' ', false)]
    #[case('\n', false)]
    #[case('@', false)]
    fn test_is_tchar(#[case] c: char, #[case] expected: bool) {
        assert_eq!(is_tchar(c), expected);
    }

    #[rstest]
    #[case("host", None)]
    #[case("bad header", Some(' '))]
    #[case("G@T", Some('@'))]
    fn test_find_invalid_token_char(#[case] s: &str, #[case] expected: Option<char>) {
        assert_eq!(find_invalid_token_char(s), expected);
    }

    #[rstest]
    #[case("100-continue", 12)]
    #[case("a=b", 1)]
    #[case("=b", 0)]
    #[case("", 0)]
    #[case("wait;level", 4)]
    // `obs-text` is not a `tchar`, and the index is still a `char` boundary to
    // slice on because everything before it was one octet each.
    #[case("caf\u{E9}", 3)]
    fn test_token_run_end(#[case] s: &str, #[case] expected: usize) {
        assert_eq!(token_run_end(s), expected);
        assert!(s.is_char_boundary(token_run_end(s)));
    }

    /// The whole of the difference between the two alphabets, asserted from
    /// both sides so neither reader can quietly widen: `{` and `}` are a MIME
    /// token and are not an HTTP one, and every other octet answers the same
    /// way to both.
    #[rstest]
    #[case('{')]
    #[case('}')]
    fn the_two_alphabets_differ_by_exactly_these(#[case] c: char) {
        assert!(is_mime_token_char(c) && !is_tchar(c));
        for other in (0u8..=0x7f)
            .map(char::from)
            .filter(|&o| o != '{' && o != '}')
        {
            assert_eq!(
                is_mime_token_char(other),
                is_tchar(other),
                "{other:?} separates the two alphabets"
            );
        }
    }

    #[rstest]
    #[case("x-my-new-encoding", None)]
    // The two characters HTTP's reader reports and MIME's does not.
    #[case("x-my{new}encoding", None)]
    #[case("quoted-printable", None)]
    // SPACE and the fifteen `tspecials` are refused by both.
    #[case("7bit 8bit", Some(' '))]
    #[case("base64;q=1", Some(';'))]
    fn test_find_invalid_mime_token_char(#[case] s: &str, #[case] expected: Option<char>) {
        assert_eq!(find_invalid_mime_token_char(s), expected);
    }

    #[rstest]
    #[case("GET", None)]
    #[case("gEt", Some('g'))]
    #[case("get", Some('g'))]
    #[case("123", None)]
    fn test_find_first_lowercase(#[case] s: &str, #[case] expected: Option<char>) {
        assert_eq!(find_first_lowercase(s), expected);
    }
}
