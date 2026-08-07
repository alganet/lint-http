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

/// Byte offset of the first `ch` outside a quoted-string, or `None`.
///
/// `char_indices`, not `chars().enumerate()`: every caller feeds the answer to
/// `split_at`, which counts bytes. The two agree on the ASCII that § 4.2 step 1
/// admits and disagree the moment anything else reaches here, and disagreeing
/// with `split_at` is a panic rather than a wrong answer.
pub(crate) fn find_char_outside_quotes(s: &str, ch: char) -> Option<usize> {
    let mut in_quote = false;
    for (i, c) in s.char_indices() {
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

/// Validate an SF Date.
///
/// A Date is an Integer with a leading "@" and no fractional part, so the
/// bound on its magnitude is § 4.2.4's, which `is_number` already carries.
/// § 3.3.7's "all days in years 1 to 9999" is a floor under what a parser must
/// accept, not a range to enforce -- fifteen digits reach well past it.
///
// cite(RFC 9651 § 3.3.7): "Dates have a data model that is similar to Integers, representing a (possibly negative) delta in seconds from 1970-01-01T00:00:00Z, excluding leap seconds."
pub(crate) fn is_date(s: &str) -> bool {
    // cite(RFC 9651 § 4.2.9): "If the first character of input_string is not "@", fail parsing."
    let Some(rest) = s.strip_prefix('@') else {
        return false;
    };
    // cite(RFC 9651 § 4.2.9): "If output_date is a Decimal, fail parsing."
    !rest.contains('.') && is_number(rest)
}

/// Validate an SF Display String.
///
/// Percent-encoding is the escape here, where a String uses "\", and the two
/// are not interchangeable: a "\" is an ordinary character in a Display String
/// and a bare DQUOTE ends one. The bytes are decoded rather than merely
/// counted because the last step is a UTF-8 check on what they spell, and
/// `%c3` alone is well-formed percent-encoding of an ill-formed sequence.
///
// cite(RFC 9651 § 3.3.8): "In textual HTTP fields, Display Strings are represented in a manner similar to Strings, except that non-ASCII characters are percent-encoded; there is a leading "%" to distinguish them from Strings."
pub(crate) fn is_display_string(s: &str) -> bool {
    // cite(RFC 9651 § 4.2.10): "If the first two characters of input_string are not "%" followed by DQUOTE, fail parsing."
    let Some(rest) = s.strip_prefix("%\"") else {
        return false;
    };
    let bytes = rest.as_bytes();
    let mut decoded: Vec<u8> = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        // cite(RFC 9651 § 4.2.10): "If char is in the range %x00-1f or %x7f-ff (i.e., it is not in VCHAR or SP), fail parsing."
        if !(0x20..=0x7e).contains(&c) {
            return false;
        }
        if c == b'%' {
            // cite(RFC 9651 § 4.2.10): "Let octet_hex be the result of consuming two characters from input_string."
            if i + 2 >= bytes.len() {
                return false;
            }
            // Read as bytes, never as a `&str` slice: the two positions after a
            // "%" are only known to be ASCII once they have been checked, and
            // slicing `rest` at an offset inside a multi-byte character panics
            // rather than answering false.
            let mut octet = 0u8;
            for &b in &bytes[i + 1..i + 3] {
                // cite(RFC 9651 § 4.2.10): "If octet_hex contains characters outside the range %x30-39 or %x61-66 (i.e., it is not in 0-9 or lowercase a-f), fail parsing."
                let nibble = match b {
                    b'0'..=b'9' => b - b'0',
                    b'a'..=b'f' => b - b'a' + 10,
                    _ => return false,
                };
                octet = (octet << 4) | nibble;
            }
            decoded.push(octet);
            i += 3;
            continue;
        }
        if c == b'"' {
            // cite(RFC 9651 § 4.2.10): "Let unicode_sequence be the result of decoding byte_array as a UTF-8 string (Section 3 of [UTF8])."
            return i == bytes.len() - 1 && std::str::from_utf8(&decoded).is_ok();
        }
        decoded.push(c);
        i += 1;
    }
    false
}

/// Validate a bare Item -- any of the seven types § 4.2.3.1 dispatches on.
///
/// The algorithm chooses by first character and the seven leading characters
/// are disjoint, so asking each predicate in turn answers the same question
/// the dispatch does. What it buys is that a caller cannot enumerate six of
/// them: every place a bare Item is admitted -- a parameter value, an Item's
/// head, an Inner List member -- names this one function.
///
// cite(RFC 9651 § 4.2.3.1): "Otherwise, the item type is unrecognized; fail parsing."
pub(crate) fn is_bare_item(s: &str) -> bool {
    is_number(s)
        || is_quoted_string(s)
        || is_valid_token_like(s)
        || is_byte_sequence(s)
        || is_boolean(s)
        || is_date(s)
        || is_display_string(s)
}

/// Validate an SF Boolean.
// cite(RFC 9651 § 4.2.8): "If the first character of input_string is not "?", fail parsing."
// cite(RFC 9651 § 4.2.8): "No value has matched; fail parsing."
pub(crate) fn is_boolean(s: &str) -> bool {
    s == "?1" || s == "?0"
}

/// § 4.2 steps 1 and 2 -- what a field value must be before any type applies.
///
/// Two checks that precede the choice of Dictionary, List or Item, so they
/// belong to neither and are asked once by whoever is about to parse. `None`
/// means the bytes are admissible; the message names which half failed.
pub(crate) fn sf_field_bytes_invalid(s: &str) -> Option<&'static str> {
    // cite(RFC 9651 § 4.2): "Convert input_bytes into an ASCII string input_string; if conversion fails, fail parsing."
    if !s.is_ascii() {
        return Some("contains a byte outside ASCII");
    }
    // HTAB survives, and it is the one control character that should: joining
    // field lines is where one appears, and § 4.2 says so in as many words.
    // Everything else has no production that admits it -- a String rejects it
    // (§ 4.2.5), a Token has no tchar for it, and the whitespace the algorithms
    // discard is SP or OWS at named points, never inside a value.
    // cite(RFC 9651 § 4.2): "The parsing algorithms for both types allow tab characters, since these might be used to combine field lines by some implementations."
    if s.bytes().any(|b| (b < 0x20 && b != b'\t') || b == 0x7f) {
        return Some("contains control characters");
    }
    None
}

/// § 4.2.2 -- comma-separated `key` or `key=value` members, each parameterizable.
pub(crate) fn parse_dictionary(s: &str) -> Option<String> {
    for m in split_commas_outside_quotes(s) {
        let m = m.trim();
        // cite(RFC 9651 § 4.2.2): "If input_string is empty, there is a trailing comma; fail parsing."
        if m.is_empty() {
            return Some("empty dictionary member".into());
        }
        // The key is read first and the "=" has to be the character right after
        // it, which is why the head is isolated before looking for one. Reading
        // the member's first "=" instead finds the one in `flag;p=1` and blames
        // a key of `flag;p`, which is not a key and not what is wrong.
        // cite(RFC 9651 § 4.2.2): "Let this_key be the result of running Parsing a Key (Section 4.2.3.3) with input_string."
        let parts = split_semicolons_outside_quotes(m);
        let head = parts.first().map(|p| p.trim()).unwrap_or("");
        // cite(RFC 9651 § 4.2.2): "If the first character of input_string is "=":"
        let (key, value) = match find_char_outside_quotes(head, '=') {
            Some(eq) => {
                let (k, v) = head.split_at(eq);
                (k.trim(), Some(v[1..].trim()))
            }
            // cite(RFC 9651 § 4.2.2): "Let value be Boolean true."
            None => (head, None),
        };
        if !is_valid_sf_key(key) {
            return Some(format!("invalid dictionary key '{}'", key));
        }
        if let Some(value) = value {
            // cite(RFC 9651 § 4.2.2): "Let member be the result of running Parsing an Item or Inner List (Section 4.2.1.1) with input_string."
            if let Some(msg) = parse_member_value(value) {
                return Some(format!("invalid value for key '{}': {}", key, msg));
            }
        }
        if let Some(msg) = parse_parameters(&parts[1..]) {
            return Some(format!("{} on member '{}'", msg, key));
        }
    }
    None
}

/// § 4.2.1 -- a comma-separated sequence of Items or Inner Lists.
pub(crate) fn parse_list(s: &str) -> Option<String> {
    for m in split_commas_outside_quotes(s) {
        let m = m.trim();
        // Step 2.6 names the common way to reach this: a trailing comma leaves
        // an empty string where a member was expected. A doubled comma is the
        // same shape one step earlier.
        // cite(RFC 9651 § 4.2.1): "If input_string is empty, there is a trailing comma; fail parsing."
        if m.is_empty() {
            return Some("empty list member".into());
        }
        // cite(RFC 9651 § 4.2.1): "Append the result of running Parsing an Item or Inner List (Section 4.2.1.1) with input_string to members."
        if let Some(msg) = parse_item_or_inner_list(m) {
            return Some(format!("invalid list member '{}': {}", m, msg));
        }
    }
    None
}

/// § 4.2.1.1 -- an Item or an Inner List, either of them parameterized.
pub(crate) fn parse_item_or_inner_list(s: &str) -> Option<String> {
    let parts = split_semicolons_outside_quotes(s);
    let head = parts.first().map(|p| p.trim()).unwrap_or("");
    parse_member_value(head).or_else(|| parse_parameters(&parts[1..]))
}

/// The head of a § 4.2.1.1 member: a bare Item, or an Inner List.
// cite(RFC 9651 § 4.2.1.1): "If the first character of input_string is "(", return the result of running Parsing an Inner List (Section 4.2.1.2) with input_string."
pub(crate) fn parse_member_value(head: &str) -> Option<String> {
    if head.is_empty() {
        return Some("empty value".into());
    }
    if head.starts_with('(') {
        return parse_inner_list(head);
    }
    if !is_bare_item(head) {
        return Some(format!("invalid item '{}'", head));
    }
    None
}

/// § 4.2.1.2 -- space-separated Items between parentheses.
pub(crate) fn parse_inner_list(head: &str) -> Option<String> {
    // cite(RFC 9651 § 4.2.1.2): "The end of the Inner List was not found; fail parsing."
    if head.len() < 2 || !head.ends_with(')') {
        return Some(format!("unterminated inner list '{}'", head));
    }
    let inner = &head[1..head.len() - 1];

    // Space is the member separator here, but not every space separates. Where
    // one follows a ";" it belongs to the parameters of the member before it --
    // `("foo"; a=1;b=2)` is one String with two parameters, and it is the RFC's
    // own example -- so that part is rejoined rather than started as a member.
    // cite(RFC 9651 § 4.2.3.2): "Discard any leading SP characters from input_string."
    let mut members: Vec<String> = Vec::new();
    for part in split_spaces_outside_quotes(inner) {
        let part = part.trim();
        // A run of spaces, or a space before the closing paren, leaves an empty
        // string here and means nothing: the loop discards leading SP before
        // deciding whether the list has ended, so `(a  b)`, `( a)` and `(a )`
        // are all the same list. This used to report each of them.
        // cite(RFC 9651 § 4.2.1.2): "Discard any leading SP characters from input_string."
        if part.is_empty() {
            continue;
        }
        match members.last_mut() {
            Some(prev) if prev.ends_with(';') => prev.push_str(part),
            _ => members.push(part.to_string()),
        }
    }

    for m in &members {
        // An Item, not an Item-or-Inner-List: Inner Lists do not nest, and the
        // bare-item dispatch has no branch for "(".
        // cite(RFC 9651 § 4.2.1.2): "Let item be the result of running Parsing an Item (Section 4.2.3) with input_string."
        if let Some(msg) = parse_item(m) {
            return Some(format!("invalid inner-list member '{}': {}", m, msg));
        }
    }
    None
}

/// § 4.2.3 -- a bare Item and its Parameters.
pub(crate) fn parse_item(s: &str) -> Option<String> {
    let parts = split_semicolons_outside_quotes(s);
    let head = parts.first().map(|p| p.trim()).unwrap_or("");
    if head.is_empty() {
        return Some("empty item".into());
    }
    // cite(RFC 9651 § 4.2.3): "Let bare_item be the result of running Parsing a Bare Item (Section 4.2.3.1) with input_string."
    if !is_bare_item(head) {
        return Some(format!("invalid item '{}'", head));
    }
    // cite(RFC 9651 § 4.2.3): "Let parameters be the result of running Parsing Parameters (Section 4.2.3.2) with input_string."
    parse_parameters(&parts[1..])
}

/// § 4.2.3.2 -- `;key` or `;key=value`, where a value is any bare Item.
///
/// Every one of the seven types is admitted here, and the four that used to be
/// is the shorter list. A byte sequence was rejected outright, so `foo;bar=:YWJj:`
/// -- an ordinary parameterized token -- was reported as invalid.
///
// cite(RFC 9651 § 3.1.2): "The keys are unique within the scope of the Parameters they occur within, and the values are bare items (i.e., they themselves cannot be parameterized; see Section 3.3)."
pub(crate) fn parse_parameters(parts: &[&str]) -> Option<String> {
    for p in parts {
        let p = p.trim();
        if p.is_empty() {
            return Some("empty parameter".into());
        }
        match find_char_outside_quotes(p, '=') {
            Some(eq) => {
                let (k, v) = p.split_at(eq);
                let (k, v) = (k.trim(), v[1..].trim());
                // cite(RFC 9651 § 4.2.3.2): "Let param_key be the result of running Parsing a Key (Section 4.2.3.3) with input_string."
                if !is_valid_sf_key(k) {
                    return Some(format!("invalid parameter key '{}'", k));
                }
                // cite(RFC 9651 § 4.2.3.2): "Let param_value be the result of running Parsing a Bare Item (Section 4.2.3.1) with input_string."
                if !is_bare_item(v) {
                    return Some(format!("invalid parameter value '{}' for key '{}'", v, k));
                }
            }
            // A parameter with no "=" is the Boolean true, spelled the way § 3.1.2
            // requires it be spelled, so only the key is left to check.
            // cite(RFC 9651 § 4.2.3.2): "Let param_value be Boolean true."
            None => {
                if !is_valid_sf_key(p) {
                    return Some(format!("invalid parameter '{}'", p));
                }
            }
        }
    }
    None
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

    #[rstest]
    #[case("@1659578233", true)]
    #[case("@-62135596800", true)]
    #[case("@0", true)]
    #[case("@1659578233.5", false)]
    #[case("@", false)]
    #[case("1659578233", false)]
    fn date(#[case] input: &str, #[case] valid: bool) {
        assert_eq!(is_date(input), valid, "{input:?}");
    }

    #[rstest]
    #[case("%\"This is intended for display to %c3%bcsers.\"", true)]
    #[case("%\"\"", true)]
    #[case("%\"a\\b\"", true)]
    #[case("%\"unterminated", false)]
    #[case("%\"%C3%BC\"", false)]
    #[case("%\"%c3\"", false)]
    #[case("%\"%c\"", false)]
    #[case("\"plain\"", false)]
    #[case("%\"a\"b\"", false)]
    // A "%" whose next two bytes straddle a multi-byte character: answered,
    // not panicked on.
    #[case("%\"%a\u{e9}\"", false)]
    #[case("%\"%\u{e9}\"", false)]
    fn display_string(#[case] input: &str, #[case] valid: bool) {
        assert_eq!(is_display_string(input), valid, "{input:?}");
    }

    #[rstest]
    #[case("42", true)]
    #[case("\"s\"", true)]
    #[case("tok", true)]
    #[case(":YWJj:", true)]
    #[case("?1", true)]
    #[case("@1659578233", true)]
    #[case("%\"x\"", true)]
    #[case("(a b)", false)]
    #[case("", false)]
    fn bare_item(#[case] input: &str, #[case] valid: bool) {
        assert_eq!(is_bare_item(input), valid, "{input:?}");
    }
}
