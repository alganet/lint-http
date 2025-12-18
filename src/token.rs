// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

/// Helpers for RFC `token` (tchar) validation used by multiple rules.
pub fn is_tchar(c: char) -> bool {
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

/// Return the first invalid character in `s` according to the `token` grammar,
/// or `None` if the entire string is valid.
pub fn find_invalid_token_char(s: &str) -> Option<char> {
    s.chars().find(|&c| !is_tchar(c))
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
    #[case("GET", None)]
    #[case("gEt", Some('g'))]
    #[case("get", Some('g'))]
    #[case("123", None)]
    fn test_find_first_lowercase(#[case] s: &str, #[case] expected: Option<char>) {
        assert_eq!(find_first_lowercase(s), expected);
    }
}
