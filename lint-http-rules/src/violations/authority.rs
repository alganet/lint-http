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
//! **The first entry is the shape the `spec` slice was made for.** RFC 9113
//! § 8.3.1 and RFC 9114 § 4.3.1 forbid the same subcomponent in the same field
//! for the same two schemes, one document per version and both in force, so the
//! entry names both and no finding carries either — each rule's message names
//! the section that governs the version it read.
//!
//! **The second is the same octet and not the same defect**, which is the line
//! worth keeping straight here: on a CONNECT the field is the *tunnel
//! destination*, two components with no third, and the userinfo is out under
//! every scheme rather than under two. That reading is stated once for all
//! versions — RFC 9110 § 9.3.6, which both version documents point at instead
//! of writing their own — so this entry names one sentence and its findings
//! carry it. **Two entries for one octet, because the conditions differ and the
//! rule knows which it is in**: an entry naming several sentences gives up its
//! citation, and giving one up where a site could have named it is a loss.
//!
//! **The third is the field's absence, and writing it settled a disagreement
//! between the two rules that report it.** Each had grown its own account of a
//! CONNECT that names no destination — three sites on one version's rule, two on
//! the other's, and they answered differently for the same message. The entry is
//! one defect and the reading behind it is one question: **does anything in this
//! request name a host and port?** A capture holds the target the transport
//! reassembled and the field lines beside it, so there are two places to look and
//! neither is `:authority` under that name; a `Host` field is the other, which is
//! where an authority arrives when a library surfaces the pseudo-header as one.
//! What a capture cannot show is *which* of the two the sender wrote, so a
//! message naming a destination anywhere is not this defect — that is the reading
//! both rules already made for an origin-form target, applied to every form.

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

/// What a CONNECT's target is, stated once for every version: the two
/// components, the port that has no default, and the server's MUST to reject an
/// empty or invalid one. Both version documents describe `:authority` on a
/// CONNECT by pointing here rather than by restating it.
pub const RFC_9110_9_3_6: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("9.3.6"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6",
    note: "CONNECT — the host and port number of the tunnel destination, the absence of a default port, and the server's MUST to reject an empty or invalid one. This is where the port requirements come from; the grammar states none.",
};

/// What a CONNECT's header section is made of over HTTP/2 — the method, the two
/// omitted pseudo-headers, and the one carrying the host and port — with the
/// sentence that makes a request missing any of it malformed. Shared with
/// `http2_pseudo_headers_valid`, which reads the same section for the port
/// requirements § 9.3.6 states.
pub const RFC_9113_8_5: SpecRef = SpecRef {
    spec: "RFC 9113",
    section: Some("8.5"),
    url: "https://www.rfc-editor.org/rfc/rfc9113.html#section-8.5",
    note: "The CONNECT Method — `:method` is set to CONNECT, `:scheme` and `:path` are omitted, `:authority` carries the host and port, and the proxy opens a TCP connection to them",
};

/// HTTP/3's account of the same construction, which states the list as a MUST of
/// its own rather than as differences from the request pseudo-header section.
pub const RFC_9114_4_4: SpecRef = SpecRef {
    spec: "RFC 9114",
    section: Some("4.4"),
    url: "https://www.rfc-editor.org/rfc/rfc9114.html#section-4.4",
    note: "The CONNECT Method — the MUST that a CONNECT request be constructed with `:scheme` and `:path` omitted and `:authority` carrying the host and port to connect to, and the sentence making a request that does not malformed",
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

    /// A CONNECT's `:authority` carrying a userinfo subcomponent and its `@`.
    /// The field is the host and port of the tunnel destination and has no third
    /// component to put anything else in, so the credential is out here whatever
    /// scheme the request would have named — and a CONNECT names none.
    ///
    /// **Separate from
    /// [`AUTHORITY_USERINFO_FORBIDDEN`] because the condition is different, not
    /// because the octet is.** That entry is written for `http` and `https`
    /// targets and says nothing about an authority under another scheme; this
    /// one is about a field with two components, and it applies to every CONNECT
    /// there is. The reading is also stated in one place for all versions, which
    /// is what lets this entry name a single sentence and put it on its
    /// findings — an entry naming several gives its citation up, and giving one
    /// up where the site could have named it is a loss rather than a
    /// simplification.
    ///
    /// **Worse than the same octet elsewhere**, which is why it ranks with its
    /// sibling: a reader splitting `user:s3cret@example.com:443` on the first
    /// colon opens a tunnel to the host `user`, and one splitting on the last
    /// finds a port. The finding withholds everything after the first colon of
    /// the subcomponent, at the shared helper carrying RFC 3986 § 3.2.1.
    ///
    // cite(RFC 9110 § 9.3.6): "CONNECT uses a special form of request target, unique to this method, consisting of only the host and port number of the tunnel destination, separated by a colon."
    AUTHORITY_TUNNEL_USERINFO_FORBIDDEN = {
        id: "authority_tunnel_userinfo_forbidden",
        title: "A CONNECT's :authority carries a userinfo subcomponent",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_9_3_6],
    }

    /// A CONNECT request with no host and port anywhere in it. The method asks a
    /// recipient to open a tunnel and the field is where the far end of that
    /// tunnel is named, so a request carrying neither an authority in its target
    /// nor a `Host` field beside it asks for a connection to nothing.
    ///
    /// **One defect however the target is shaped.** A capture holds the URI the
    /// transport reassembled, and three of the four shapes it can take carry no
    /// authority at all: nothing, a path, an asterisk. Which of them arrived says
    /// something about what the sender was attempting and nothing about what is
    /// missing, which is why this is one entry and not three — a recipient's
    /// position is identical in all of them.
    ///
    /// **A `Host` field answers the question.** Both documents write `:authority`
    /// as the field that carries the destination and neither offers `Host` as an
    /// alternative *for this method*; what makes one enough here is the capture
    /// rather than the sentence, since a library that surfaces the pseudo-header
    /// as a `Host` field leaves a message indistinguishable from one whose sender
    /// wrote it that way. Reporting the pair apart would be reporting a guess, so
    /// **the finding is made only where nothing in the message names a
    /// destination**.
    ///
    /// **Two documents, one per version, and neither governing the other**, so no
    /// finding carries a citation and each rule's message names the section that
    /// governs the version it read. The HTTP/1.x rule declares neither: over that
    /// version the destination is the request-line's target, and a CONNECT
    /// carrying the wrong form of one is
    /// [`request_target`](crate::violations::request_target)'s question rather
    /// than this field's.
    ///
    /// `error`, with the rest of this subject: there is no tunnel to open and no
    /// later message in the exchange supplies one.
    ///
    // cite(RFC 9113 § 8.5): "The ":authority" pseudo-header field contains the host and port to connect to (equivalent to the authority-form of the request-target of CONNECT requests; see Section 3.2.3 of [HTTP/1.1])."
    // cite(RFC 9113 § 8.5): "A CONNECT request that does not conform to these restrictions is malformed (Section 8.1.1)."
    // cite(RFC 9114 § 4.4): "A CONNECT request MUST be constructed as follows:"
    // cite(RFC 9114 § 4.4): "The :authority pseudo-header field contains the host and port to connect to (equivalent to the authority-form of the request-target of CONNECT requests; see Section 7.1 of [HTTP])."
    AUTHORITY_TUNNEL_MISSING = {
        id: "authority_tunnel_missing",
        title: "A CONNECT names no host and port to open a tunnel to",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9113_8_5, RFC_9114_4_4],
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
        assert!(AUTHORITY_TUNNEL_USERINFO_FORBIDDEN.message.is_empty());
    }

    /// The tunnel entry names one sentence and therefore cites it on every
    /// finding. That is the whole reason it is not folded into its sibling: the
    /// condition a CONNECT puts on the field is stated once for all versions,
    /// and a site that can name its sentence should.
    #[test]
    fn the_tunnel_entry_names_one_sentence_for_every_version() {
        assert_eq!(AUTHORITY_TUNNEL_USERINFO_FORBIDDEN.spec, [RFC_9110_9_3_6]);
        assert_eq!(
            AUTHORITY_TUNNEL_USERINFO_FORBIDDEN.default_severity,
            AUTHORITY_USERINFO_FORBIDDEN.default_severity,
        );
    }

    /// The absence is one entry over two version documents and over every shape
    /// a target with no authority can take, so the id names neither a version
    /// nor a form. What a finding shows — which shape arrived, and which section
    /// governs it — is the site's, as it is for every entry here that names more
    /// than one sentence.
    #[test]
    fn the_absent_destination_is_one_entry_for_both_versions() {
        assert_eq!(AUTHORITY_TUNNEL_MISSING.spec, [RFC_9113_8_5, RFC_9114_4_4]);
        for spelling in ["http2", "http3", "path", "target"] {
            assert!(
                !AUTHORITY_TUNNEL_MISSING.id.contains(spelling),
                "the id names a version or a form of the target",
            );
        }
        assert!(AUTHORITY_TUNNEL_MISSING.message.is_empty());
        assert_eq!(
            AUTHORITY_TUNNEL_MISSING.default_severity,
            AUTHORITY_TUNNEL_USERINFO_FORBIDDEN.default_severity,
        );
    }
}
