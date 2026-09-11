// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `:authority` defects — what the pseudo-header field may carry, rather than
//! what an authority is made of.
//!
//! The field is HTTP/2's and HTTP/3's replacement for the `Host` field: it
//! conveys the authority component of the target URI, and on a CONNECT it is the
//! host and port of the tunnel destination. **Neither version writes a grammar
//! for it** — each points at RFC 3986, or at the authority-form of an HTTP/1.1
//! request-target — so a bracket, a host character or a port digit is
//! [`uri`](crate::violations::uri)'s defect here as it is in a `Host` field, and
//! both version rules already report those ids.
//!
//! What is left, and what this subject holds, is what the two documents say
//! about the field *beyond* the syntax: components the field may not carry, and
//! the halves a CONNECT owes. Those are prose requirements about a field, which
//! is what makes the field the subject.
//!
//! **The entry below is the shape the `spec` slice was made for.** RFC 9113
//! § 8.3.1 and RFC 9114 § 4.3.1 forbid the same subcomponent in the same field
//! for the same two schemes, one document per version and both in force, so the
//! entry names both and no finding carries either — each rule's message names
//! the section that governs the version it read.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// HTTP/2's account of the four request pseudo-headers, the userinfo MUST NOT
/// among them. Shared with `http2_pseudo_headers_valid`, which reads the rest of
/// the section at sites this catalogue has not named yet.
pub const RFC_9113_8_3_1: SpecRef = SpecRef {
    spec: "RFC 9113",
    section: Some("8.3.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9113.html#section-8.3.1",
    note: "Request Pseudo-Header Fields — what each of `:method`, `:scheme`, `:authority` and `:path` conveys, the `'*'` value for asterisk-form OPTIONS, the `:path`-must-not-be-empty MUST, and the userinfo MUST NOT written for `http` and `https` targets",
};

/// HTTP/3's, which states the same prohibition as a property of the authority
/// rather than of the field, and enumerates a different set of neighbours around
/// it.
pub const RFC_9114_4_3_1: SpecRef = SpecRef {
    spec: "RFC 9114",
    section: Some("4.3.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9114.html#section-4.3.1",
    note: "Request Pseudo-Header Fields — the exactly-one MUST for `:method`, \
           `:scheme` and `:path`, the `:authority`-or-Host requirement for schemes \
           with a mandatory authority component, and the MUST NOT on the deprecated \
           userinfo subcomponent for http and https URIs",
};

defects! {
    /// An `:authority` carrying the deprecated userinfo subcomponent and its
    /// `@`, on a request whose scheme is `http` or `https`. Two things are wrong
    /// with it at once, and the entry is worth having for either: credentials
    /// have been written into control data that intermediaries log and caches
    /// key on, and a reader splitting the value on its colon finds the
    /// password's leading digits where a port should be.
    ///
    /// **The scheme is the condition and not the subject.** Both documents say
    /// `:scheme` is not restricted to `http` and `https`, and both write this
    /// MUST NOT for those two only — so an authority under another scheme may
    /// carry a userinfo and is not reported. The finding names the scheme it
    /// found for that reason.
    ///
    /// **Both sentences, neither governing.** RFC 9113 § 8.3.1 states it of the
    /// field and RFC 9114 § 4.3.1 of the authority, one document per version,
    /// both in force at the same time; naming either would cite the wrong one on
    /// half the findings. Each rule's message names its own version's section,
    /// which is what a finding of a multi-sentence entry owes its reader.
    ///
    /// `error`, which both rules had already chosen: the credential is out and
    /// no later message takes it back.
    ///
    /// What a finding *shows* withholds everything after the first colon of the
    /// subcomponent — the elision is the shared helper's, carrying RFC 3986
    /// § 3.2.1's sentence — because a report printing the password would be one
    /// more place it is written down in clear.
    ///
    // cite(RFC 9113 § 8.3.1): "":authority" MUST NOT include the deprecated userinfo subcomponent for "http" or "https" schemed URIs."
    // cite(RFC 9114 § 4.3.1): "The authority MUST NOT include the deprecated userinfo subcomponent for URIs of scheme "http" or "https"."
    AUTHORITY_USERINFO_FORBIDDEN = {
        id: "authority_userinfo_forbidden",
        title: "An :authority carries the deprecated userinfo subcomponent",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9113_8_3_1, RFC_9114_4_3_1],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One id for two versions, and the id names neither. Pinned in both
    /// directions: dropping a reference would make the survivor look like *the*
    /// sentence and start a citation appearing on findings the other document
    /// governs.
    #[test]
    fn one_entry_names_both_version_documents_and_no_version() {
        assert_eq!(
            AUTHORITY_USERINFO_FORBIDDEN.spec,
            [RFC_9113_8_3_1, RFC_9114_4_3_1]
        );
        assert!(!AUTHORITY_USERINFO_FORBIDDEN.id.contains("http"));
        assert_eq!(
            AUTHORITY_USERINFO_FORBIDDEN.default_severity,
            Severity::Error
        );
    }

    /// The wording is the site's, because it names the value found and the
    /// section that governs it — and an entry naming two sentences can hold
    /// neither of those.
    #[test]
    fn the_wording_belongs_to_the_site() {
        assert!(AUTHORITY_USERINFO_FORBIDDEN.message.is_empty());
        assert!(AUTHORITY_USERINFO_FORBIDDEN.spec.len() > 1);
    }
}
