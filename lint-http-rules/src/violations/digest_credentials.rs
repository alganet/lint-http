// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Digest` credentials defects — what RFC 7616 asks of the parameters.
//!
//! [`credentials`](crate::violations::credentials) is the framework's shape and
//! says so: something is there, and the octets are ones a field value may
//! carry. What the credentials have to *be* is the scheme's own document's
//! question, and for `Digest` that document is RFC 7616. This subject is the
//! `Basic` one's counterpart —
//! [`basic_credentials`](crate::violations::basic_credentials) — for a scheme
//! whose credential is a parameter list rather than one base64 run.
//!
//! **Nothing about the parameter *grammar* is here.** A member with no `=`, a
//! name that is no `token`, a value that opens a `quoted-string` and never
//! closes it: those are [`auth_param`](crate::violations::auth_param)'s,
//! [`token`](crate::violations::token)'s and
//! [`quoted_string`](crate::violations::quoted_string)'s, reported the same way
//! out of a `WWW-Authenticate` challenge. What is here is the layer above the
//! grammar, where §3.4 says which parameters a credential owes and how each of
//! them must be spelled.
//!
//! **All three entries answer one section**, which is unusual enough to say out
//! loud: §3.4 lists the parameters, names the 4xx consequence for missing or
//! improper ones, marks two of them "MUST be used by all implementations", and
//! writes both historical-reasons quoting rules. So every finding here carries
//! a reference except the one whose antecedent RFC 2617 supplies as well.

use crate::lint::Severity;
use crate::lint::Strength;
use crate::rules::SpecRef;
use crate::violations::defects;

/// The Authorization header field: the parameter list, the 4xx consequence for
/// what is missing or improper, and the two quoting MUSTs.
pub const RFC_7616_3_4: SpecRef = SpecRef {
    spec: "RFC 7616",
    section: Some("3.4"),
    url: "https://www.rfc-editor.org/rfc/rfc7616.html#section-3.4",
    note: "The Authorization Header Field — the Digest credentials, their parameters, the 4xx consequence for missing or improper ones, the \"MUST be used by all implementations\" on cnonce and nc, and the two historical-reasons quoting MUSTs enforced in both directions",
};

/// The WWW-Authenticate challenge: where the `nonce`, `opaque` and `stale`
/// parameters this subject reads a credential against are defined.
pub const RFC_7616_3_3: SpecRef = SpecRef {
    spec: "RFC 7616",
    section: Some("3.3"),
    url: "https://www.rfc-editor.org/rfc/rfc7616.html#section-3.3",
    note: "The WWW-Authenticate Response Header Field — the server challenge, its `nonce` and `opaque` and the case-insensitive `stale` flag a client answers by restarting the count",
};

/// Authentication-Info, and the one sentence in the document that fixes the
/// width of `nc`.
pub const RFC_7616_3_5: SpecRef = SpecRef {
    spec: "RFC 7616",
    section: Some("3.5"),
    url: "https://www.rfc-editor.org/rfc/rfc7616.html#section-3.5",
    note: "The Authentication-Info Header Field — where the nc value's width is written down; § 3.4 introduces `nc` as \"the hexadecimal count\" and never fixes it, and this section requires the field's nc to be the client's, so it is one value with one width",
};

/// RFC 2617's conditional on the same two parameters, which is the half of the
/// requirement a qop-carrying credential meets by itself.
pub const RFC_2617_3_2_2: SpecRef = SpecRef {
    spec: "RFC 2617",
    section: Some("3.2.2"),
    url: "https://www.rfc-editor.org/rfc/rfc2617.html#section-3.2.2",
    note: "The Authorization Request Header — `cnonce` and `nc` MUST be specified if a qop directive is sent, which is the sentence that makes their absence observable from the credential alone",
};

defects! {
    /// A `Digest` credential that does not carry a parameter it owes:
    /// `username`, `realm`, `nonce`, `uri` or `response`, or — where the
    /// credential carries a `qop` — `cnonce` or `nc`, or an `opaque` the
    /// challenge supplied. A bare `Digest` with no parameters at all is the
    /// degenerate case and draws this id too.
    ///
    /// **Two antecedents, one entry.** §3.4 lists the parameters and names the
    /// consequence for the required ones being absent; for `cnonce` and `nc` it
    /// says instead that they "MUST be used by all implementations", and RFC
    /// 2617 §3.2.2 makes that observable from the message by requiring them
    /// whenever a `qop` directive is sent. Different sentences, one sender, one
    /// repair, and one loss — both documents compute the response value over
    /// what is absent, so the credential cannot be verified by the recipient it
    /// was written for. The message names which parameter and which sentence.
    ///
    /// **The `qop`-less case is deliberately not reported**, and that is a
    /// decision about a *document* rather than about a message: RFC 2617
    /// computes a qop-less response without either parameter, so demanding them
    /// of every `Digest` credential would reject that document's otherwise
    /// checkable shape.
    ///
    /// `warn`. Nothing on the wire is unreadable, and what a server does with
    /// an unverifiable credential — §3.4's 4xx — is the server's to decide.
    DIGEST_CREDENTIALS_PARAMETER_MISSING = {
        id: "digest_credentials_parameter_missing",
        title: "Digest credentials omit a parameter the response computation needs",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_7616_3_4, RFC_2617_3_2_2],
    }

    /// A required parameter written and left blank: `realm=""`, `nonce=`.
    ///
    /// **Separate from [`DIGEST_CREDENTIALS_PARAMETER_MISSING`] for the reason
    /// `docs/development.md` gives, and the split is load-bearing here.** A
    /// credential with no `realm` at all is a client that never had one; a
    /// credential with `realm=""` is a client that had one and lost it
    /// somewhere between the challenge and the request. Different senders,
    /// different places to look.
    ///
    /// `realm=""` is a perfectly good `quoted-string` — the production derives
    /// an empty interior, and [`parameter`](crate::violations::parameter) even
    /// records that `charset=""` conforms — so nothing about the grammar
    /// refuses this. What refuses it is that the response value is computed
    /// over these parameters and an empty one computes a digest of nothing in
    /// particular.
    ///
    // cite(RFC 7616 § 3.4): "If a parameter or its value is improper, or required parameters are missing, the proper response is a 4xx error code."
    DIGEST_CREDENTIALS_PARAMETER_EMPTY = {
        id: "digest_credentials_parameter_empty",
        title: "A required Digest parameter is written with nothing in it",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_7616_3_4],
    }

    /// A parameter written in the one syntax §3.4 does not admit for it: an
    /// unquoted `username`, `realm`, `nonce`, `uri`, `response`, `cnonce` or
    /// `opaque`, or a quoted `algorithm`, `qop` or `nc`.
    ///
    /// **`_invalid` and not `_malformed`, because both spellings derive.**
    /// `auth-param` gives every parameter the choice of `token` or
    /// `quoted-string`, so the grammar produces `uri=/` and `qop="auth"`
    /// equally well. §3.4 then removes the choice per parameter, for
    /// historical reasons it states outright — and that is the point of the
    /// entry: recipients of these parameters were deployed against one spelling
    /// each, so the wrong one is a credential some verifiers will not read.
    ///
    /// **One entry for two lists pointing opposite ways.** A `MUST only
    /// generate the quoted string syntax` and a `MUST NOT generate the quoted
    /// string syntax` are the same instruction addressed to different
    /// parameters, and a sender fixes either by changing the spelling of one
    /// value. Both sentences are in §3.4, so the finding keeps its reference
    /// and the message names which list the parameter is on.
    ///
    // cite(RFC 7616 § 3.4): "For historical reasons, a sender MUST only generate the quoted string syntax for the following parameters: username, realm, nonce, uri, response, cnonce, and opaque."
    DIGEST_CREDENTIALS_QUOTING_INVALID = {
        id: "digest_credentials_quoting_invalid",
        title: "A Digest parameter is written in the syntax its definition refuses",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_7616_3_4],
        strength: Strength::Must,
    }

    /// A credential naming a `nonce` no challenge in this exchange offered:
    /// no `Digest` challenge observed at all, or one whose `nonce` was a
    /// different string.
    ///
    /// **The same shape as
    /// [`conditional_validator_missing`](crate::violations::conditional::CONDITIONAL_VALIDATOR_MISSING),
    /// and uncited for the same reason.** A `nonce` is the server's to issue
    /// and opaque to the client, so a credential naming one nobody offered is
    /// worth a look — but nothing in RFC 7616 requires a client to answer the
    /// *most recent* challenge, a server may keep several nonces live at once,
    /// and a proxy that came up mid-conversation never saw the challenge that
    /// issued this one. The heuristic is this crate's and a reference on it
    /// would dress it as a requirement.
    ///
    /// One entry for both situations, because the claim is the same: this
    /// exchange cannot account for the nonce. The message says whether a
    /// challenge was seen.
    ///
    /// `info`, with the legitimate explanation available in every case.
    DIGEST_CREDENTIALS_CHALLENGE_MISSING = {
        id: "digest_credentials_challenge_missing",
        title: "Digest credentials name a nonce no observed challenge offered",
        message: "",
        default_severity: Severity::Info,
        spec: &[],
    }

    /// An `opaque` that is not the string the challenge supplied: returned
    /// changed, or not returned at all.
    ///
    /// **Both, under one sentence, and the gate is what found that.** The
    /// omitted case was first written as
    /// [`DIGEST_CREDENTIALS_PARAMETER_MISSING`], which was wrong for a reason
    /// worth keeping: that entry names RFC 2617 § 3.2.2 as well, a conditional
    /// about `cnonce` and `nc` that has nothing to say about an `opaque` —
    /// and `every_violation_spec_is_declared_by_its_rule` refused it, because
    /// the rule reading challenges does not state that section and should not.
    /// § 3.4 says the value *must be* the one supplied, which a credential
    /// omitting it fails exactly as squarely as one changing it, and the repair
    /// is the same sentence's: return what the challenge sent.
    ///
    /// **Cited where the nonce's counterpart is not, and the difference is the
    /// evidence rather than the fix.** § 3.4 says outright that the values of
    /// the `opaque` and `algorithm` fields must be those supplied in the
    /// `WWW-Authenticate`; nothing in the document says the same about the
    /// `nonce`, which is why a nonce that does not match is
    /// [`DIGEST_CREDENTIALS_CHALLENGE_MISSING`]'s heuristic and this is a
    /// stated requirement. *Where the evidence differs in kind, the entry
    /// differs too, even when the repair is the same.*
    ///

    // cite(RFC 7616 § 3.4): "The values of the opaque and algorithm fields must be those supplied in the WWW-Authenticate response header field for the entity being requested."
    DIGEST_CREDENTIALS_OPAQUE_CONFLICTING = {
        id: "digest_credentials_opaque_conflicting",
        title: "Digest credentials do not return the opaque the challenge supplied",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_7616_3_4],
    }

    /// An `nc` that is not eight hexadecimal digits: `nc=1`, `nc=0000000g`,
    /// `nc=000000001`.
    ///
    /// **The width is written in § 3.5 and nowhere else**, which is worth
    /// knowing before reading the reference: § 3.4 introduces `nc` as "the
    /// hexadecimal count" and never fixes its length, and the sentence that
    /// does sits in the section about `Authentication-Info` — a field whose own
    /// `nc` that section requires to be the one from the client's request. One
    /// value, one width, and the document writes it down once on the far side
    /// of the exchange.
    ///
    /// `warn`: a server that cannot read the count cannot use it to detect the
    /// replays the parameter exists for, and the credential's response value is
    /// computed over the count as written.
    ///
    // cite(RFC 7616 § 3.5): "For historical reasons, the nc value MUST be exactly 8 hexadecimal digits."
    DIGEST_CREDENTIALS_NC_MALFORMED = {
        id: "digest_credentials_nc_malformed",
        title: "A Digest nonce-count is not eight hexadecimal digits",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_7616_3_5],
        strength: Strength::Must,
    }

    /// Eight good hex digits naming the wrong number: a count that did not
    /// increase for a nonce already seen, or one that did not restart at
    /// `00000001` after a challenge said `stale=true`.
    ///
    /// **`_invalid`, because the value derives and the exchange refuses it.**
    /// Both halves are the same claim — the count is not the number this
    /// exchange calls for — and a sender fixes either by sending the number the
    /// protocol says. § 3.4 supplies the first (a repeated count *is* the
    /// replay signature the parameter exists to produce) and § 3.3 the second
    /// (a `stale` challenge is answered by keeping the new nonce and starting
    /// its count again), so the entry names both and neither governs; the
    /// message says which.
    ///
    /// `warn` rather than `error`, and the reason is what this rule can see: a
    /// proxy that missed requests holds a lower count than the server does, so
    /// a repeat is evidence and not proof. What the finding says is that a
    /// server is entitled to reject the request as a replay.
    DIGEST_CREDENTIALS_NC_INVALID = {
        id: "digest_credentials_nc_invalid",
        title: "A Digest nonce-count is not the number the exchange calls for",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_7616_3_4, RFC_7616_3_3],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pair that is easiest to get backwards, on a subject where the
    /// difference says where to look: a parameter nobody sent against one sent
    /// empty.
    #[test]
    fn the_absent_parameter_and_the_blank_one_are_two_ids() {
        assert_eq!(
            DIGEST_CREDENTIALS_PARAMETER_MISSING.id,
            "digest_credentials_parameter_missing"
        );
        assert_eq!(
            DIGEST_CREDENTIALS_PARAMETER_EMPTY.id,
            "digest_credentials_parameter_empty"
        );
    }

    /// One entry names two documents and the other two name one, which is the
    /// difference between a requirement two specifications state about one
    /// defect and a requirement written once.
    #[test]
    fn only_the_absence_needs_two_documents() {
        assert_eq!(DIGEST_CREDENTIALS_PARAMETER_MISSING.spec.len(), 2);
        assert_eq!(DIGEST_CREDENTIALS_PARAMETER_EMPTY.spec, [RFC_7616_3_4]);
        assert_eq!(DIGEST_CREDENTIALS_QUOTING_INVALID.spec, [RFC_7616_3_4]);
    }
}
