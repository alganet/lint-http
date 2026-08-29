// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! The `qvalue` production — the weight on a list member.
//!
//! Small, and its own module for the same reason `status` is: it is one
//! question, and the answer is a production rather than a list of the strings
//! that production generates. The enumeration this replaced
//! (`s == "1" || s == "1.0" || ...`) missed `0.` and `1.`, which `0*3DIGIT` and
//! `0*3("0")` both admit at zero repetitions — two conforming values reported as
//! malformed by every rule that asked.

/// Validate qvalue syntax: `0`, `1`, `0.5`, `0.123`, `1.000` — up to three
/// digits after the point, and only zeroes after a leading `1`.
///
/// Written as the production reads rather than as a list of the strings it
/// generates. The enumeration this replaced (`s == "1" || s == "1.0" || ...`)
/// missed `0.` and `1.`, which `0*3DIGIT` and `0*3("0")` both admit at zero
/// repetitions — so two conforming values were reported as malformed by every
/// rule that asks this question.
///
/// The leading/trailing trim is a tolerance, not the grammar: a `qvalue` has no
/// whitespace in it anywhere. Every caller trims before asking, so it changes
/// no verdict today; it is kept because nothing depends on it being strict and
/// removing it would be a silent trap for a caller that does not trim.
pub fn valid_qvalue(s: &str) -> bool {
    let s = s.trim();
    // The three-decimal cap and the "1 may only be followed by zeroes" asymmetry are
    // both in the production; neither is arbitrary.
    // cite(RFC 9110 § 12.4.2, label: qvalue grammar): "qvalue = ( "0" [ "." 0*3DIGIT ] ) / ( "1" [ "." 0*3("0") ] )"
    let (rest, digit_ok): (&str, fn(u8) -> bool) = if let Some(rest) = s.strip_prefix('0') {
        (rest, |b| b.is_ascii_digit())
    } else if let Some(rest) = s.strip_prefix('1') {
        (rest, |b| b == b'0')
    } else {
        return false;
    };

    // `[ "." 0*3DIGIT ]` — the fraction is optional, and so is every digit in it.
    match rest.strip_prefix('.') {
        None => rest.is_empty(),
        Some(fraction) => fraction.len() <= 3 && fraction.bytes().all(digit_ok),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each row is a weight and whether the `qvalue` production admits it. A
    /// table rather than a run of `assert!` lines, so a failure names the value.
    #[test]
    fn test_valid_qvalue() {
        const CASES: &[(&str, bool)] = &[
            ("1", true),
            ("1.0", true),
            ("1.00", true),
            ("1.000", true),
            ("0", true),
            ("0.5", true),
            ("0.123", true),
            ("0.000", true),
            // `0*3DIGIT` and `0*3("0")` are satisfied by no digits at all, so a
            // point with nothing after it conforms. The enumeration this replaced
            // reported both as malformed.
            ("0.", true),
            ("1.", true),
            ("1.0000", false),
            ("0.1234", false),
            // Only zeroes may follow a leading 1: the weight is capped at 1.
            ("1.1", false),
            ("1.001", false),
            ("abc", false),
            ("", false),
            ("2", false),
            ("-1", false),
            ("0.5.5", false),
            ("00", false),
            ("0.a", false),
        ];

        for (value, is_qvalue) in CASES {
            assert_eq!(valid_qvalue(value), *is_qvalue, "for {value:?}");
        }
    }
}
