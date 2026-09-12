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
//! the halves a CONNECT owes — three of the entries below are exactly those
//! halves, and all three are `uri-host ":" port` deriving something the prose
//! then refuses, since both halves of that production are `*`-quantified. Those
//! are prose requirements about a field, which is what makes the field the
//! subject.
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
//!
//! **The fourth is the same absence outside a CONNECT, and it is one version's
//! alone.** RFC 9114 § 4.3.1 requires a request whose scheme has a mandatory
//! authority component to carry either the field or a `Host`; RFC 9113 § 8.3.1
//! writes the opposite for HTTP/2, telling a client to omit `:authority` where
//! there is no authority to convey. So this entry names one sentence, cites it,
//! and is declared by one rule — **where two version documents differ, the
//! catalogue holds the difference rather than smoothing it**, and the pair of
//! `_missing` entries here is that line drawn twice: once by the method a request
//! used and once by the document that asked.

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

    /// A CONNECT whose destination names a port and no host — `:443`, or the
    /// colon alone. `uri-host` derives the empty string, so the grammar admits
    /// it and the prose is what does not: the target is *the host name and port
    /// number* of the tunnel destination, and a recipient with only the number
    /// has nothing to open a connection to.
    ///
    /// `_empty` rather than `_missing`, and the delimiter is what decides it: the
    /// colon says the sender knew the component was there and wrote nothing in
    /// it. [`AUTHORITY_TUNNEL_PORT_MISSING`] is the same line drawn on the other
    /// component, where a value with no colon at all names no port to be empty.
    ///
    // cite(RFC 9110 § 9.3.6): "CONNECT uses a special form of request target, unique to this method, consisting of only the host and port number of the tunnel destination, separated by a colon."
    AUTHORITY_TUNNEL_HOST_EMPTY = {
        id: "authority_tunnel_host_empty",
        title: "A CONNECT's destination names a port and no host",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_9_3_6],
    }

    /// A CONNECT whose destination carries the port's delimiter and no digits
    /// after it — `example.com:`. `port` is `*DIGIT`, so this derives too, and
    /// again the prose is the requirement: there is no default port for this
    /// method, and a server is told to reject a request targeting an empty one.
    ///
    /// **The sentence naming the empty port is the server's**, and it is why
    /// this is worth reporting at all rather than treating the colon as a typo:
    /// a recipient is required to answer 400 to it, so a client that sends it
    /// gets no tunnel and no useful diagnosis.
    ///
    // cite(RFC 9110 § 9.3.6): "A server MUST reject a CONNECT request that targets an empty or invalid port number, typically by responding with a 400 (Bad Request) status code."
    AUTHORITY_TUNNEL_PORT_EMPTY = {
        id: "authority_tunnel_port_empty",
        title: "A CONNECT's destination ends at the colon with no port",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_9_3_6],
    }

    /// A CONNECT whose destination names a port number no transport has. `port`
    /// is `*DIGIT` and bounds nothing at either end, so `70000` and
    /// `99999999999999999999` both derive — and the sentence beside the empty
    /// port refuses them in the same breath: a server is told to reject a
    /// request targeting an *empty or invalid* port number.
    ///
    /// **What makes a number invalid is not in either sentence, and that is the
    /// reading.** § 9.3.6 says a server rejects one and says nothing about which
    /// numbers those are; what supplies the bound is that this method opens a
    /// *TCP* connection to the host and port, and TCP's port namespace is
    /// sixteen bits wide (RFC 6335 § 6). So the entry names the sentence that
    /// makes it a defect and the rule declaring it names the two that supply the
    /// width — **a bound reached through a transport is still the requirement's
    /// defect, not the transport's.**
    ///
    /// **`0` is not reported.** It is inside the namespace: a reserved value at
    /// the edge of a range, held back for extending the ranges later, and no
    /// sentence here makes a reserved port an invalid one. The check this entry
    /// replaced in one rule rejected it under the same message as `70000`.
    ///
    /// **Not the same as a port outside a `Host` field's range, which is
    /// nobody's finding.** There the only sentence is `port = *DIGIT`, which
    /// bounds nothing, and `host_header` says so in its description; here the
    /// method's own section names the transport, which is what licenses the
    /// bound.
    ///
    // cite(RFC 9110 § 9.3.6): "A server MUST reject a CONNECT request that targets an empty or invalid port number, typically by responding with a 400 (Bad Request) status code."
    AUTHORITY_TUNNEL_PORT_INVALID = {
        id: "authority_tunnel_port_invalid",
        title: "A CONNECT's destination names a port no transport has",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_9_3_6],
    }

    /// A CONNECT whose destination names a host and no port at all — no colon
    /// anywhere in it. Every other request-target elides a port and lets the
    /// scheme supply one; this method has no scheme and no default, so the
    /// number is the client's to send even when the URI reference it started
    /// from left it out.
    ///
    /// Separate from [`AUTHORITY_TUNNEL_PORT_EMPTY`] because the senders are
    /// different and the document addresses them separately: one copied an
    /// authority whose port was elided and stopped, and the other built
    /// `host ":" port` from a port it did not have. **Over HTTP/1.1 only one of
    /// the two arrives here** — a request-target with no colon derives from no
    /// form at all and is [`request_target`](crate::violations::request_target)'s
    /// `_malformed` — which is a difference in the *spelling* and not in the
    /// defect, and is why the entry is the field's rather than the target's.
    ///
    // cite(RFC 9110 § 9.3.6): "There is no default port; a client MUST send the port number even if the CONNECT request is based on a URI reference that contains an authority component with an elided port (Section 4.1)."
    AUTHORITY_TUNNEL_PORT_MISSING = {
        id: "authority_tunnel_port_missing",
        title: "A CONNECT's destination names no port",
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

    /// A request whose scheme requires an authority and which carries none —
    /// neither an `:authority` the transport reassembled into its target nor a
    /// `Host` field beside it. Every `http` and `https` URI names a host, so a
    /// request that names none has no origin to be applied to and no way for an
    /// intermediary to choose one.
    ///
    /// **One version writes this and the other does not**, which is why the
    /// entry names one sentence and one rule declares it. RFC 9114 § 4.3.1 puts
    /// the requirement as an either-or, and the sibling paragraph in RFC 9113
    /// § 8.3.1 does the opposite: a client is told to use `:authority` *unless
    /// there is no authority information to convey*, in which case it may not
    /// generate one at all. So an HTTP/2 request with no authority anywhere is
    /// outside any sentence this catalogue could put behind a finding, and the
    /// HTTP/2 rule reports nothing here — **a version-split pair of rules is not
    /// obliged to report the same set, and where they differ the difference is
    /// the documents'.**
    ///
    /// **The scheme is the sentence's condition and is not in the capture.** The
    /// clause gates on a scheme with a mandatory authority component, and a
    /// capture of a request whose target is in origin form retains no scheme —
    /// which is exactly the shape this defect arrives in. What stands in for it
    /// is the transport: HTTP/3 runs over QUIC with TLS, so the request is
    /// `http` or `https` and both are named in the clause. That reading is the
    /// rule's, recorded in its `description()`, and it is why the id names no
    /// scheme.
    ///
    /// Separate from [`AUTHORITY_TUNNEL_MISSING`], which is the same absence on
    /// a CONNECT: there the field is the tunnel destination and both version
    /// documents require it, so neither the condition nor the sentence is
    /// shared.
    ///
    /// `error`: nothing later in the exchange supplies the host, and a recipient
    /// that guesses one is choosing an origin the sender never named.
    ///
    // cite(RFC 9114 § 4.3.1): "If the :scheme pseudo-header field identifies a scheme that has a mandatory authority component (including "http" and "https"), the request MUST contain either an :authority pseudo-header field or a Host header field."
    AUTHORITY_MISSING = {
        id: "authority_missing",
        title: "A request that owes an authority names none",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9114_4_3_1],
    }

    /// A request that answered the requirement above with a field written and
    /// left blank. The same clause states both: the request carries one of the
    /// two fields, and if it carries either, it is not empty — so a `Host:` with
    /// nothing on it satisfies the letter of the first half and is named by the
    /// second.
    ///
    /// **Separate from [`AUTHORITY_MISSING`] because the senders differ and so
    /// do their fixes.** One never wrote the field; this one wrote it and put no
    /// authority in it, which is a different mistake to make and a different one
    /// to correct. The closed vocabulary already separates the two, and here the
    /// evidence supports the separation: an absent field line and a blank one
    /// are both in the capture, unlike the pseudo-headers whose absence and
    /// blankness reassemble into one target.
    ///
    /// **What it is not is an HTTP/1.1 empty `Host`.** RFC 9112 § 3.2 *requires*
    /// an empty field value where the target URI's authority is missing or
    /// undefined, which is why `host_header` reports nothing for one and says so
    /// in its description. This entry is the other version's sentence, and it is
    /// read only on a request that version governs.
    ///
    /// **Nor is it a `Host` that disagrees with an `:authority`.** The clause's
    /// third half — both fields present, both naming the same authority — is
    /// `host_and_authority_consistent`'s, and an empty `Host` beside a target
    /// that does name an authority is that rule's finding rather than this one.
    /// This entry is for the request that names an authority *nowhere*.
    ///
    /// `error`, with its sibling: the consequence is the recipient's either way,
    /// and it is that the request names no origin.
    ///
    // cite(RFC 9114 § 4.3.1): "If these fields are present, they MUST NOT be empty."
    AUTHORITY_EMPTY = {
        id: "authority_empty",
        title: "A request's authority field is present and empty",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9114_4_3_1],
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

    /// The two absences are two entries and the split is the documents': a
    /// CONNECT owes its destination under both versions and a scheme's
    /// mandatory authority is required by one of them, so one entry names two
    /// sentences and carries none onto a finding while the other names one and
    /// cites it.
    #[test]
    fn the_two_absences_split_on_what_requires_the_field() {
        assert_eq!(AUTHORITY_TUNNEL_MISSING.spec.len(), 2);
        assert_eq!(AUTHORITY_MISSING.spec, [RFC_9114_4_3_1]);
        assert!(AUTHORITY_MISSING.message.is_empty());
        assert_eq!(
            AUTHORITY_MISSING.default_severity,
            AUTHORITY_TUNNEL_MISSING.default_severity,
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
