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
    if bytes.len() < 2 || bytes[0] != b'"' || bytes[bytes.len() - 1] != b'"' {
        return false;
    }
    let interior = &bytes[1..bytes.len() - 1];
    !interior
        .iter()
        .any(|b| *b < 0x20 && *b != b'\t' || *b == 0x7f)
}

pub(crate) fn is_byte_sequence(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() < 3 || bytes[0] != b':' || bytes[bytes.len() - 1] != b':' {
        return false;
    }
    let inner = &s[1..s.len() - 1];
    !inner.is_empty()
        && inner
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
    // conservative: allow optional leading '-', digits, optional '.' with digits
    let mut chars = s.chars();
    if let Some('-') = chars.clone().next() {
        chars.next();
    }
    let s2: String = chars.collect();
    if s2.is_empty() {
        return false;
    }
    if s2.contains('.') {
        let mut parts = s2.splitn(2, '.');
        let a = parts
            .next()
            .expect("splitn always returns at least one item");
        let b = parts.next().unwrap_or("");
        return !a.is_empty()
            && a.chars().all(|c| c.is_ascii_digit())
            && !b.is_empty()
            && b.chars().all(|c| c.is_ascii_digit());
    }
    s2.chars().all(|c| c.is_ascii_digit())
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
