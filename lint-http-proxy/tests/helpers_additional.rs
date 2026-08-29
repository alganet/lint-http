// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use lint_http::helpers::mailbox::{parse_mailbox, MailboxDefect};
use lint_http::helpers::parameter::validate_ext_value;

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

/// An `angle-addr` whose contents are not an `addr-spec` is refused, and the
/// finding names the construct the parse stopped at rather than the whole value.
#[test]
fn a_mailbox_whose_angle_addr_holds_no_addr_spec_is_refused() {
    match parse_mailbox("Alice <not-an-email>") {
        Err(MailboxDefect::Syntax(msg)) => {
            assert!(msg.contains("where the addr-spec has its \"@\""), "{msg}")
        }
        Err(MailboxDefect::ListSeparator) => panic!("read as a mailbox-list"),
        Ok(_) => panic!("accepted"),
    }
}
