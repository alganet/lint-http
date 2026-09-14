// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Host` defects — the HTTP/1.1 half of a requirement written twice.
//!
//! What a `Host` value is made of belongs to [`uri`](crate::violations::uri):
//! `Host = uri-host [ ":" port ]` imports both halves from RFC 3986, so a
//! bracket, a host character and a port digit report the ids an `:authority`
//! reports for the same octets. A second field line is
//! [`field`](crate::violations::field)'s, since `Host` is not a list and § 5.3
//! forbids repeating any field that is not one.
//!
//! **What is here is the pair of requirements HTTP/1.1 states about the field
//! itself, and the reason they are not
//! [`authority`](crate::violations::authority)'s is worth writing down.** A
//! request that names no authority anywhere and one that carries a userinfo
//! subcomponent are the same two mistakes over `Host` and over `:authority`,
//! with the same repairs — and each version states them in its own document:
//! RFC 9110 § 7.2 and RFC 9112 § 3.2 here, RFC 9113 § 8.3.1 and RFC 9114
//! § 4.3.1 there. No sentence is common to all of them.
//!
//! A shared entry could therefore cite nothing, because
//! `every_violation_spec_is_declared_by_its_rule` compares a def's references
//! against *each* declaring rule's and no rule here states another version's
//! section. **So this catalogue pays one id per document to keep every finding
//! its reference** — which is the limit of the `spec` slice rather than a
//! revival of the retired "a def carries one quote" argument: the slice answers
//! a def whose sections one rule states, and these are stated one per rule.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// Host and :authority: the MUST, and the `unless` that lets a pseudo-header
/// satisfy it.
pub const RFC_9110_7_2: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("7.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-7.2",
    note: "Host and :authority — `Host = uri-host [ \":\" port ]`, the MUST to generate the field, and the `:authority` pseudo-header the MUST excepts",
};

/// Request Target: what an HTTP/1.1 `Host` must carry and what it must leave
/// out.
pub const RFC_9112_3_2: SpecRef = SpecRef {
    spec: "RFC 9112",
    section: Some("3.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2",
    note: "Request Target — a `Host` in every HTTP/1.1 request, a value identical to the target URI's authority *excluding* the userinfo and its `@`, an empty value where the target has no authority, and the 400 a server owes a request with none or with two",
};

defects! {
    /// A request that carries neither a `Host` field nor an `:authority`
    /// pseudo-header.
    ///
    /// **The `unless` is half the sentence and the finding respects it.** § 7.2
    /// requires the field *unless* the request sends that information as an
    /// `:authority`, so a request that used the pseudo-header has done what the
    /// requirement asks — reporting it would measure every HTTP/2 and HTTP/3
    /// request against the half of the sentence that excludes it.
    ///
    /// Separate from
    /// [`AUTHORITY_MISSING`](crate::violations::authority::AUTHORITY_MISSING),
    /// which is the same absence stated by RFC 9114 § 4.3.1 for the version
    /// that has pseudo-headers. The module doc above is the argument.
    ///
    /// `error`: no later part of the exchange supplies the origin, and a
    /// recipient that guesses one is choosing a server the sender never named.
    ///
    // cite(RFC 9110 § 7.2): "A user agent MUST generate a Host header field in a request unless it sends that information as an ":authority" pseudo-header field."
    HOST_MISSING = {
        id: "host_missing",
        title: "A request names its authority in neither Host nor :authority",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_7_2],
    }

    /// A `Host` field value carrying a userinfo subcomponent and its `@`.
    ///
    /// § 3.2 says the value is the target URI's authority component *excluding*
    /// the userinfo and its delimiter, which makes the `@` the tell: a value
    /// carrying one was copied from a URI without the exclusion being applied.
    ///
    /// **The sentence that names it is this one and not RFC 9110 § 4.2.4's**,
    /// whose MUST NOT is about an `http` or `https` URI reference generated as
    /// a target URI or a field value — and a `Host` value is neither, being a
    /// `uri-host` and a port.
    ///
    /// `error`, with
    /// [`AUTHORITY_USERINFO_FORBIDDEN`](crate::violations::authority::AUTHORITY_USERINFO_FORBIDDEN)
    /// which reports the same octet on the other version's field: the
    /// credential is out and no later message takes it back.
    ///
    // cite(RFC 9112 § 3.2): "If the target URI includes an authority component, then a client MUST send a field value for Host that is identical to that authority component, excluding any userinfo subcomponent and its "@" delimiter (Section 4.2 of [HTTP])."
    HOST_USERINFO_FORBIDDEN = {
        id: "host_userinfo_forbidden",
        title: "A Host field value carries the userinfo subcomponent",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9112_3_2],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::violations::authority::{AUTHORITY_MISSING, AUTHORITY_USERINFO_FORBIDDEN};

    /// The two pairs, and the assertion that keeps the split honest: each
    /// version's entry names its own document, which is the whole reason there
    /// are two of each. If a sentence is ever found that states either
    /// requirement for both versions at once, this is the test to revisit.
    #[test]
    fn each_version_names_its_own_document() {
        for (mine, theirs) in [
            (&HOST_MISSING, &AUTHORITY_MISSING),
            (&HOST_USERINFO_FORBIDDEN, &AUTHORITY_USERINFO_FORBIDDEN),
        ] {
            for ours in mine.spec {
                assert!(
                    !theirs.spec.contains(ours),
                    "{} and {} share {}",
                    mine.id,
                    theirs.id,
                    ours.spec
                );
            }
            assert_eq!(mine.default_severity, theirs.default_severity);
        }
    }
}
