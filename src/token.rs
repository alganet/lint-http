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

    #[test]
    fn is_tchar_basic() {
        assert!(is_tchar('a'));
        assert!(is_tchar('Z'));
        assert!(is_tchar('3'));
        assert!(is_tchar('!'));
        assert!(!is_tchar(' '));
        assert!(!is_tchar('\n'));
    }

    #[test]
    fn find_invalid_token_char_and_lowercase() {
        assert_eq!(find_invalid_token_char("host"), None);
        assert_eq!(find_invalid_token_char("bad header"), Some(' '));
        assert_eq!(find_first_lowercase("GET"), None);
        assert_eq!(find_first_lowercase("gEt"), Some('g'));
    }
}
