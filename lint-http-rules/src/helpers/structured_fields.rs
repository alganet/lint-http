// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Conservative parsing helpers for Structured Fields and related header grammars.
//!
//! These helpers are shared across multiple rules that need to parse or
//! split tokens, lists, dictionaries and quoted/parenthesized parts while
//! ignoring separators inside quoted-strings or nested parentheses.
//!
//! The predicates below cite RFC 9651 § 4.2's parsing algorithms, and a reader
//! looking for the compact form of what they check -- `sf-integer = ["-"]
//! 1*15DIGIT` and its neighbours -- will not find it cited anywhere here. That
//! ABNF is Appendix C, which is non-normative, says the algorithms take
//! precedence over it where the two disagree, and disclaims itself for this
//! exact use: it cannot be used to validate syntax, because it does not capture
//! all the requirements. `is_byte_sequence` is where the disagreement turns out
//! to be real rather than theoretical.
//!
//! One shape difference is worth stating once. The § 4.2 algorithms consume a
//! prefix and hand the rest back, so they stop at the first character they do
//! not recognise rather than rejecting the input. These are whole-string
//! predicates, called on a value whose bounds the caller has already found, so
//! where an algorithm says "return output_string" they answer false.

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
    // cite(RFC 9651 § 4.2.5): "If the first character of input_string is not DQUOTE, fail parsing."
    if bytes.len() < 2 || bytes[0] != b'"' {
        return false;
    }
    let mut i = 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                i += 1;
                // cite(RFC 9651 § 4.2.5): "If next_char is not DQUOTE or "\", fail parsing."
                if i >= bytes.len() || (bytes[i] != b'"' && bytes[i] != b'\\') {
                    return false;
                }
            }
            // cite(RFC 9651 § 4.2.5): "Else, if char is DQUOTE, return output_string."
            b'"' => return i == bytes.len() - 1,
            // cite(RFC 9651 § 4.2.5): "Else, if char is in the range %x00-1f or %x7f-ff (i.e., it is not in VCHAR or SP), fail parsing."
            b if !(0x20..=0x7e).contains(&b) => return false,
            _ => {}
        }
        i += 1;
    }
    // cite(RFC 9651 § 4.2.5): "Reached the end of input_string without finding a closing DQUOTE; fail parsing."
    false
}

pub(crate) fn is_byte_sequence(s: &str) -> bool {
    let bytes = s.as_bytes();
    // cite(RFC 9651 § 4.2.7): "If the first character of input_string is not ":", fail parsing."
    // cite(RFC 9651 § 4.2.7): "If there is not a ":" character before the end of input_string, fail parsing."
    if bytes.len() < 2 || bytes[0] != b':' || bytes[bytes.len() - 1] != b':' {
        return false;
    }
    let inner = &s[1..s.len() - 1];
    // Nothing above requires `inner` to be non-empty, and nothing below rejects it
    // for being empty: `::` is a Byte Sequence carrying zero bytes.
    //
    // This is the one place where Appendix C's ABNF and the algorithm genuinely
    // disagree, and the algorithm wins by the appendix's own instruction. The ABNF
    // is `base64 = *( ALPHA / DIGIT / "+" / "/" ) *"="`, which admits "=" only as a
    // suffix; the sentence cited below admits it anywhere in the content, and that
    // is what this accepts. Padding is the caller's problem either way -- § 4.2.7
    // has parsers synthesize it rather than demand it.
    //
    // cite(RFC 9651 § 4.2.7): "If b64_content contains a character not included in ALPHA, DIGIT, "+", "/", and "=", fail parsing."
    inner
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
}

/// Validate an SF `key` -- a parameter key or a Dictionary member key.
///
/// `lcalpha` is spelled `is_ascii_lowercase` here. The RFC only expands the term
/// in Appendix C's ABNF, so what is cited for it instead is § 3.1.2's statement
/// of the consequence, which is the half a reader of this code needs.
pub(crate) fn is_valid_sf_key(k: &str) -> bool {
    let mut chars = k.chars();
    let first = match chars.next() {
        Some(c) => c,
        None => return false,
    };
    // cite(RFC 9651 § 3.1.2): "Note that parameters are ordered, and parameter keys cannot contain uppercase letters."
    // cite(RFC 9651 § 4.2.3.3): "If the first character of input_string is not lcalpha or "*", fail parsing."
    if !(first.is_ascii_lowercase() || first == '*') {
        return false;
    }
    // cite(RFC 9651 § 4.2.3.3): "If the first character of input_string is not one of lcalpha, DIGIT, "_", "-", ".", or "*", return output_string."
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

/// Validate an SF Integer or Decimal.
///
/// § 4.2.4 parses both with one algorithm and decides which it has by whether a
/// "." arrives, which is why one predicate answers for both types here.
pub(crate) fn is_number(s: &str) -> bool {
    // cite(RFC 9651 § 4.2.4): "If the first character of input_string is "-", consume it and set sign to -1."
    let magnitude = s.strip_prefix('-').unwrap_or(s);
    match magnitude.split_once('.') {
        Some((integer, fractional)) => {
            // cite(RFC 9651 § 4.2.4): "If input_number contains more than 12 characters, fail parsing."
            // cite(RFC 9651 § 4.2.4): "If the final character of input_number is ".", fail parsing."
            // cite(RFC 9651 § 4.2.4): "If the number of characters after "." in input_number is greater than three, fail parsing."
            !integer.is_empty()
                && integer.len() <= 12
                && integer.chars().all(|c| c.is_ascii_digit())
                && (1..=3).contains(&fractional.len())
                && fractional.chars().all(|c| c.is_ascii_digit())
        }
        None => {
            // cite(RFC 9651 § 4.2.4): "If the first character of input_string is not a DIGIT, fail parsing."
            // cite(RFC 9651 § 4.2.4): "If type is "integer" and input_number contains more than 15 characters, fail parsing."
            !magnitude.is_empty()
                && magnitude.len() <= 15
                && magnitude.chars().all(|c| c.is_ascii_digit())
        }
    }
}

/// Validate an SF Token.
///
/// This cannot simply ask `is_tchar`, and the sentence below is why: an SF Token
/// is narrower than RFC 9110's `token` at the front and wider than it afterwards.
/// The tchar set it names is the same one `helpers::token::is_tchar` transcribes,
/// which is what licenses the call.
///
// cite(RFC 9651 § 3.3.4): "Tokens are short textual words that begin with an alphabetic character or "*", followed by zero to many token characters, which are the same as those allowed by the "token" ABNF rule defined in [HTTP] plus the ":" and "/" characters."
pub(crate) fn is_valid_token_like(v: &str) -> bool {
    let mut chars = v.chars();
    // cite(RFC 9651 § 4.2.6): "If the first character of input_string is not ALPHA or "*", fail parsing."
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '*' => {}
        _ => return false,
    }
    // cite(RFC 9651 § 4.2.6): "If the first character of input_string is not in tchar, ":", or "/", return output_string."
    for c in chars {
        if crate::helpers::token::is_tchar(c) || c == ':' || c == '/' {
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
