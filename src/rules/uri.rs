// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Small reusable helpers for URI-ish checks used by several rules.

/// Check percent-encoding runs inside a string. Returns `Some(msg)` describing the
/// first problem found, or `None` if all percent-encodings look well-formed.
pub fn check_percent_encoding(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let len = bytes.len();
    let mut i = 0usize;

    while i < len {
        if bytes[i] == b'%' {
            if i + 2 >= len {
                return Some(
                    "Percent-encoding incomplete: '%' must be followed by two hex digits".into(),
                );
            }
            let hi = bytes[i + 1];
            let lo = bytes[i + 2];
            if !hi.is_ascii_hexdigit() || !lo.is_ascii_hexdigit() {
                let seq = &s[i..i + 3.min(len - i)];
                return Some(format!("Invalid percent-encoding '{}'", seq));
            }
            i += 3;
        } else {
            i += 1;
        }
    }

    None
}

/// Return `true` if the string contains any ASCII whitespace characters.
pub fn contains_whitespace(s: &str) -> bool {
    s.chars().any(|c| c.is_ascii_whitespace())
}

/// Validate a potential scheme (characters before the first ':').
/// Returns `Some(msg)` on invalid scheme, `None` if OK or no scheme present.
pub fn validate_scheme_if_present(s: &str) -> Option<String> {
    if let Some(colon) = s.find(':') {
        let scheme = &s[..colon];
        let mut chars = scheme.chars();
        if let Some(first) = chars.next() {
            if !first.is_ascii_alphabetic() {
                return Some(format!("Invalid scheme in value: '{}'", scheme));
            }
        }
        for c in chars {
            if !(c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.') {
                return Some(format!("Invalid character '{}' in scheme '{}'", c, scheme));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_encoding_good_and_bad() {
        assert!(check_percent_encoding("/path%20ok").is_none());
        assert_eq!(
            check_percent_encoding("/incomplete%2"),
            Some("Percent-encoding incomplete: '%' must be followed by two hex digits".into())
        );
        let m = check_percent_encoding("/bad%2G").unwrap();
        assert!(m.contains("Invalid percent-encoding") && m.contains("%2G"));
    }

    #[test]
    fn whitespace_detection() {
        assert!(contains_whitespace("hello world"));
        assert!(!contains_whitespace("/path/no-space"));
    }

    #[test]
    fn scheme_validation() {
        assert!(validate_scheme_if_present("1http://ex").is_some());
        assert!(validate_scheme_if_present("ht!tp://ex").is_some());
        assert!(validate_scheme_if_present("/relative").is_none());
        assert!(validate_scheme_if_present("https://ex").is_none());
    }
}
