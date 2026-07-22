// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Conservative parsing helpers for Structured Fields and related header grammars.
//!
//! These helpers are shared across multiple rules that need to parse or
//! split tokens, lists, dictionaries and quoted/parenthesized parts while
//! ignoring separators inside quoted-strings or nested parentheses.

pub(crate) fn split_commas_outside_quotes(s: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut in_quote = false;
    let mut paren_depth = 0i32;
    let bytes = s.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'"' => in_quote = !in_quote,
            b'(' if !in_quote => paren_depth += 1,
            b')' if !in_quote && paren_depth > 0 => paren_depth -= 1,
            b',' if !in_quote && paren_depth == 0 => {
                parts.push(s[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(s[start..].trim());
    parts
}

pub(crate) fn split_semicolons_outside_quotes(s: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut in_quote = false;
    let mut paren_depth = 0i32;
    let bytes = s.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'"' => in_quote = !in_quote,
            b'(' if !in_quote => paren_depth += 1,
            b')' if !in_quote && paren_depth > 0 => paren_depth -= 1,
            b';' if !in_quote && paren_depth == 0 => {
                parts.push(s[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(s[start..].trim());
    parts
}

pub(crate) fn split_spaces_outside_quotes(s: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut in_quote = false;
    let bytes = s.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'"' => in_quote = !in_quote,
            b' ' if !in_quote => {
                if start <= i {
                    parts.push(s[start..i].trim());
                }
                start = i + 1;
                while start < bytes.len() && bytes[start] == b' ' {
                    start += 1;
                }
            }
            _ => {}
        }
    }
    if start >= bytes.len() {
        parts.push("");
    } else {
        parts.push(s[start..].trim());
    }
    parts
}

pub(crate) fn find_char_outside_quotes(s: &str, ch: char) -> Option<usize> {
    let mut in_quote = false;
    for (i, c) in s.chars().enumerate() {
        if c == '"' {
            in_quote = !in_quote;
        }
        if c == ch && !in_quote {
            return Some(i);
        }
    }
    None
}

pub(crate) fn is_quoted_string(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() < 2 || bytes[0] != b'"' {
        return false;
    }
    let mut i = 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                i += 1;
                if i >= bytes.len() || (bytes[i] != b'"' && bytes[i] != b'\\') {
                    return false;
                }
            }
            b'"' => return i == bytes.len() - 1,
            b if !(0x20..=0x7e).contains(&b) => return false,
            _ => {}
        }
        i += 1;
    }
    false
}

pub(crate) fn is_byte_sequence(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() < 2 || bytes[0] != b':' || bytes[bytes.len() - 1] != b':' {
        return false;
    }
    let inner = &s[1..s.len() - 1];
    inner
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
}

pub(crate) fn is_valid_sf_key(k: &str) -> bool {
    let mut chars = k.chars();
    let first = match chars.next() {
        Some(c) => c,
        None => return false,
    };
    if !(first.is_ascii_lowercase() || first == '*') {
        return false;
    }
    for c in chars {
        if !(c.is_ascii_lowercase()
            || c.is_ascii_digit()
            || c == '_'
            || c == '-'
            || c == '.'
            || c == '*')
        {
            return false;
        }
    }
    true
}

pub(crate) fn is_number(s: &str) -> bool {
    let magnitude = s.strip_prefix('-').unwrap_or(s);
    match magnitude.split_once('.') {
        Some((integer, fractional)) => {
            !integer.is_empty()
                && integer.len() <= 12
                && integer.chars().all(|c| c.is_ascii_digit())
                && (1..=3).contains(&fractional.len())
                && fractional.chars().all(|c| c.is_ascii_digit())
        }
        None => {
            !magnitude.is_empty()
                && magnitude.len() <= 15
                && magnitude.chars().all(|c| c.is_ascii_digit())
        }
    }
}

pub(crate) fn is_valid_token_like(v: &str) -> bool {
    let mut chars = v.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '*' => {}
        _ => return false,
    }
    for c in chars {
        if crate::helpers::token::is_tchar(c)
            || c == ':'
            || c == '/'
            || c == '.'
            || c == '-'
            || c == '_'
        {
            continue;
        }
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(":cHJldGVuZCB0aGlzIGlzIGJpbmFyeSBjb250ZW50Lg==:", true)]
    #[case(":YWJj:", true)]
    #[case("::", true)]
    #[case(":", false)]
    #[case(":YWJj", false)]
    #[case(":YW Jj:", false)]
    fn byte_sequence(#[case] input: &str, #[case] valid: bool) {
        assert_eq!(is_byte_sequence(input), valid, "{input:?}");
    }

    #[rstest]
    #[case("42", true)]
    #[case("999999999999999", true)]
    #[case("-999999999999999", true)]
    #[case("9999999999999999", false)]
    #[case("4.5", true)]
    #[case("123456789012.123", true)]
    #[case("1234567890123.1", false)]
    #[case("1.1234", false)]
    fn number(#[case] input: &str, #[case] valid: bool) {
        assert_eq!(is_number(input), valid, "{input:?}");
    }

    #[rstest]
    #[case("\"hello world\"", true)]
    #[case("\"\"", true)]
    #[case("\"a\\\"b\"", true)]
    #[case("\"a\tb\"", false)]
    #[case("\"é\"", false)]
    #[case("\"a\\b\"", false)]
    #[case("\"a\"b\"", false)]
    fn quoted_string(#[case] input: &str, #[case] valid: bool) {
        assert_eq!(is_quoted_string(input), valid, "{input:?}");
    }
}
