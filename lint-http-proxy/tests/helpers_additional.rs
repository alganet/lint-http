// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use lint_http::helpers::headers::{validate_ext_value, validate_mailbox_list};

#[test]
fn validate_ext_value_missing_language_separator_error() {
    // Missing second quote -> should report missing language separator
    let v = "UTF-8'en-only"; // only one quote present
    let res = validate_ext_value(v);
    assert!(res.is_err());
    let msg = res.as_ref().err().unwrap().to_lowercase();
    assert!(msg.contains("missing language separator") || msg.contains("language separator"));
}

#[test]
fn validate_ext_value_empty_charset_error() {
    // Leading quote -> empty charset should be rejected
    let v = "'en'%20"; // first quote at position 0 -> empty charset
    let res = validate_ext_value(v);
    assert!(res.is_err());
    assert!(res
        .as_ref()
        .err()
        .unwrap()
        .to_lowercase()
        .contains("charset"));
}

#[test]
fn validate_ext_value_invalid_charset_non_ascii() {
    // Non-ASCII charset should be rejected
    let v = "UT\u{2713}F'en'%20"; // contains non-ascii char in charset
    let res = validate_ext_value(v);
    assert!(res.is_err());
    assert!(res
        .as_ref()
        .err()
        .unwrap()
        .to_lowercase()
        .contains("invalid charset"));
}

#[test]
fn validate_mailbox_list_angle_addr_invalid_inside() {
    // Angle-addr with invalid addr-spec should be rejected
    let res = validate_mailbox_list("Alice <not-an-email>");
    assert!(res.is_err());
    let msg = res.as_ref().err().unwrap().to_lowercase();
    assert!(msg.contains("invalid addr-spec") || msg.contains("missing '@'"));
}
