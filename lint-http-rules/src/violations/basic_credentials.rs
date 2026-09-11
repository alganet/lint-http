// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Basic credentials defects — what the octets behind the base64 have to be.
//!
//! RFC 7617 § 2 builds one value out of two: `user-pass = userid ":" password`,
//! encoded with base64 into the `token68` of an `Authorization: Basic`. The two
//! defects here are what is left after the encoding is undone — the separator
//! that says where the user-id stops, and the control characters the section
//! forbids in either half.
//!
//! Everything else the value can fail at belongs to somebody else, and that is
//! most of it: an absent `token68` is [`credentials_missing`], because a scheme
//! with nothing after it is the framework's defect and not this scheme's, and a
//! value that does not decode is [`base64_malformed`], because RFC 4648's
//! sentence answers for every field that carries an encoding. What remains is
//! the two lines RFC 7617 writes itself.
//!
//! [`credentials_missing`]: crate::violations::credentials::CREDENTIALS_MISSING
//! [`base64_malformed`]: crate::violations::base64::BASE64_MALFORMED

use crate::helpers::auth::BasicCredentialsDefect;
use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::base64::BASE64_MALFORMED;
use crate::violations::credentials::CREDENTIALS_MISSING;
use crate::violations::{defects, ViolationDef};

/// The scheme's own section: how the value is built, and the one restriction it
/// places on what goes into it.
pub const RFC_7617_2: SpecRef = SpecRef {
    spec: "RFC 7617",
    section: Some("2"),
    url: "https://www.rfc-editor.org/rfc/rfc7617.html#section-2",
    note: "The 'Basic' Authentication Scheme — `user-pass = userid \":\" password`, base64-encoded, with control characters forbidden in either half",
};

defects! {
    /// Decoded octets with no `:` in them. Without the separator there is no
    /// telling where the user-id stops — and an empty user-id is a different
    /// thing from an absent one, which is why this is not read as "the user-id
    /// is missing".
    ///
    // cite(RFC 7617 § 2): "constructs the user-pass by concatenating the user-id, a single colon (":") character, and the password"
    BASIC_CREDENTIALS_SEPARATOR_MISSING = {
        id: "basic_credentials_separator_missing",
        title: "Basic credentials hold no ':' separator",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_7617_2],
    }

    /// A control octet in the user-id or in the password. One def for both
    /// halves, because one sentence forbids them in both and the fix is the
    /// same fix; the message still says which half it was in. `error` by
    /// default, the same reading every other subject's invisible defect gets —
    /// and here with a MUST NOT behind it rather than an inference.
    ///
    // cite(RFC 7617 § 2): "The user-id and password MUST NOT contain any control characters"
    BASIC_CREDENTIALS_CONTROL_CHARACTER_FORBIDDEN = {
        id: "basic_credentials_control_character_forbidden",
        title: "Basic credentials hold a control character",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_7617_2],
    }
}

/// The defect a parsed [`BasicCredentialsDefect`] reports as.
///
/// Two of the five arms leave this subject, which is the point: what is missing
/// after a scheme is the framework's defect, and what fails to decode is the
/// encoding's. Only the two that RFC 7617 writes sentences about are named
/// here.
///
/// By reference, because the decode arm carries `base64::DecodeError` and the
/// site needs the defect again for its message — the same shape `path_defect`
/// takes for the same reason.
pub fn basic_credentials_defect(defect: &BasicCredentialsDefect) -> &'static ViolationDef {
    match defect {
        BasicCredentialsDefect::Empty => &CREDENTIALS_MISSING,
        BasicCredentialsDefect::Base64(_) => &BASE64_MALFORMED,
        BasicCredentialsDefect::MissingColon => &BASIC_CREDENTIALS_SEPARATOR_MISSING,
        BasicCredentialsDefect::UserIdControlCharacter(_)
        | BasicCredentialsDefect::PasswordControlCharacter(_) => {
            &BASIC_CREDENTIALS_CONTROL_CHARACTER_FORBIDDEN
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Five variants, four ids — three of the mappings leave this subject or
    /// collapse two variants, and each of those is a decision rather than an
    /// oversight, so all five are spelled out.
    #[test]
    fn each_basic_credentials_defect_maps_to_its_own_id() {
        for (defect, id) in [
            (BasicCredentialsDefect::Empty, "credentials_missing"),
            (
                BasicCredentialsDefect::Base64(base64::DecodeError::InvalidPadding),
                "base64_malformed",
            ),
            (
                BasicCredentialsDefect::MissingColon,
                "basic_credentials_separator_missing",
            ),
            (
                BasicCredentialsDefect::UserIdControlCharacter(0x01),
                "basic_credentials_control_character_forbidden",
            ),
            (
                BasicCredentialsDefect::PasswordControlCharacter(0x01),
                "basic_credentials_control_character_forbidden",
            ),
        ] {
            assert_eq!(basic_credentials_defect(&defect).id, id);
        }
    }
}
