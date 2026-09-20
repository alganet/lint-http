// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Digest` challenge defects — what RFC 7616 § 3.3 asks of the parameters a
//! server offers.
//!
//! The mirror of [`digest_credentials`](crate::violations::digest_credentials),
//! and it exists because the two sections are not one section. § 3.4 describes
//! what a client sends back and § 3.3 describes what a server sends first;
//! they name overlapping parameters, give them different meanings, and — the
//! reason a second subject was unavoidable — write **different quoting lists**
//! over them.
//!
//! **Nothing about the parameter grammar is here**, for the same reason it is
//! not in the credentials subject: a member with no `=`, a name that is no
//! `token`, an unterminated `quoted-string` are
//! [`auth_param`](crate::violations::auth_param)'s and
//! [`quoted_string`](crate::violations::quoted_string)'s, reported out of this
//! field by the rule that reads § 11.3's framework. What is here is the layer
//! above, where a scheme's own document says how its parameters are spelled.

use crate::lint::Severity;
use crate::lint::Strength;
use crate::rules::SpecRef;
use crate::violations::defects;

/// The WWW-Authenticate header field for `Digest`: the parameters a challenge
/// may carry, and the two historical-reasons quoting rules over them.
pub const RFC_7616_3_3: SpecRef = SpecRef {
    spec: "RFC 7616",
    section: Some("3.3"),
    url: "https://www.rfc-editor.org/rfc/rfc7616.html#section-3.3",
    note: "The WWW-Authenticate Response Header Field — the parameters a Digest challenge may carry, and the two lists saying which of them must and must not be written as a quoted-string",
};

defects! {
    /// A challenge parameter written in the one syntax § 3.3 does not admit for
    /// it: an unquoted `realm`, `domain`, `nonce`, `opaque` or `qop`, or a
    /// quoted `stale` or `algorithm`.
    ///
    /// **The sibling of
    /// [`DIGEST_CREDENTIALS_QUOTING_INVALID`](crate::violations::digest_credentials::DIGEST_CREDENTIALS_QUOTING_INVALID),
    /// and a separate entry because the lists are separate.** `qop` is the
    /// value that makes it unmistakable: § 3.3 requires it quoted in a
    /// challenge and § 3.4 requires it unquoted in credentials, so one entry
    /// answering for both would have to hold two contradictory claims about one
    /// parameter name. A finding also names a different sender each way — the
    /// server that offered the challenge, and the client that answered it.
    ///
    /// **`_invalid` and not `_malformed`, because both spellings derive.**
    /// `auth-param` gives every parameter the choice of `token` or
    /// `quoted-string`; § 3.3 then removes the choice per parameter, for
    /// historical reasons it states outright. Recipients of these parameters
    /// were deployed against one spelling each, so the wrong one is a challenge
    /// some clients will not read.
    ///
    /// **One entry for two lists pointing opposite ways**, on the credentials
    /// entry's footing: a `MUST only generate` and a `MUST NOT generate` are
    /// the same instruction addressed to different parameters, a sender fixes
    /// either by changing the spelling of one value, and both sentences are in
    /// § 3.3. The message names which list the parameter is on.
    ///
    /// `realm` is the one parameter two documents bind at once — RFC 9110
    /// § 11.5 says it of every sender of a realm — and this entry keeps it in a
    /// Digest challenge, because § 3.3 is the more specific sentence there.
    ///
    // cite(RFC 7616 § 3.3): "For historical reasons, a sender MUST only generate the quoted string syntax values for the following parameters: realm, domain, nonce, opaque, and qop."
    // cite(RFC 7616 § 3.3): "For historical reasons, a sender MUST NOT generate the quoted string syntax values for the following parameters: stale and algorithm."
    DIGEST_CHALLENGE_QUOTING_INVALID = {
        id: "digest_challenge_quoting_invalid",
        title: "A Digest challenge parameter is written in the syntax its definition refuses",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_7616_3_3],
        strength: Strength::Must,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::violations::digest_credentials::DIGEST_CREDENTIALS_QUOTING_INVALID;

    /// The two entries say the same kind of thing about two sections, and the
    /// assertion is why they are two: `qop` is on the *quote* list in § 3.3 and
    /// on the *do not quote* list in § 3.4, so one id could not carry both.
    #[test]
    fn the_challenge_and_the_credential_are_two_entries() {
        assert_ne!(
            DIGEST_CHALLENGE_QUOTING_INVALID.id,
            DIGEST_CREDENTIALS_QUOTING_INVALID.id
        );
        let [challenge] = DIGEST_CHALLENGE_QUOTING_INVALID.spec else {
            panic!("one section")
        };
        let [credentials] = DIGEST_CREDENTIALS_QUOTING_INVALID.spec else {
            panic!("one section")
        };
        assert_ne!(challenge.section, credentials.section);
    }
}
