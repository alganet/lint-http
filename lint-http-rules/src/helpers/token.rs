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

    #[rstest]
    #[case("GET", None)]
    #[case("gEt", Some('g'))]
    #[case("get", Some('g'))]
    #[case("123", None)]
    fn test_find_first_lowercase(#[case] s: &str, #[case] expected: Option<char>) {
        assert_eq!(find_first_lowercase(s), expected);
    }
}
