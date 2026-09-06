// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Base64 defects — a value that does not decode, wherever it was carried.
//!
//! RFC 4648's encoding is read in at least three places here: the
//! `basic-credentials` of an `Authorization`, the `Sec-WebSocket-Key` of a
//! handshake, and its `Sec-WebSocket-Accept` answer. The sentence that makes a
//! bad one a finding is one sentence — § 3.3's MUST — so the defect is one
//! defect and an operator who does not care about a mangled encoding says so
//! once.
//!
//! One entry today, and it is deliberately coarse: `base64::DecodeError` is
//! what the `Basic` reader has, and it distinguishes nothing this catalogue
//! could name. The WebSocket reader *does* split the same failure three ways —
//! alphabet, shape, and pad bits a conforming encoder zeroes — so when it
//! converts, its defects join this subject beside this one rather than
//! replacing it. A coarse def and a fine one in the same subject are two
//! readers, not two vocabularies.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// The instruction that makes a malformed encoding a finding rather than a
/// judgment call — and it is addressed to the *decoder*, which is what a proxy
/// reading someone else's credentials is.
pub const RFC_4648_3_3: SpecRef = SpecRef {
    spec: "RFC 4648",
    section: Some("3.3"),
    url: "https://www.rfc-editor.org/rfc/rfc4648.html#section-3.3",
    note: "Interpretation of non-alphabet characters — a MUST to reject data outside the base alphabet, unless the referring specification says otherwise",
};

defects! {
    /// A value that is not an encoding the alphabet and the quantum produce: an
    /// octet outside the sixty-four characters, a length no group of symbols
    /// accounts for, or padding somewhere other than the end.
    ///
    // cite(RFC 4648 § 3.3): "Implementations MUST reject the encoded data if it contains characters outside the base alphabet when interpreting base-encoded data, unless the specification referring to this document explicitly states otherwise."
    BASE64_MALFORMED = {
        id: "base64_malformed",
        title: "Value is not a base64 encoding",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_4648_3_3),
    }
}
