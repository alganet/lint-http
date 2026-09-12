// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Request-target defects — what is wrong with the thing a request is *about*,
//! rather than with any field on it.
//!
//! **The subject is a protocol element and not a field**, which is the shape
//! [`status`](crate::violations::status) has on the response side: a request
//! names its target in control data, and RFC 9110 § 7.1 is where what that
//! naming may be is written. Two of the four forms are *method-specific* — the
//! host and port a CONNECT tunnels to, and the asterisk a server-wide OPTIONS
//! asks about — and the section closes them both with one MUST NOT. **That one
//! sentence is two entries here**, because the two senders wrote different
//! mistakes and an operator silencing one has no reason to silence the other.
//!
//! **What makes this a subject rather than a drawer is that the element is
//! version-independent while its spelling is not.** Over HTTP/1.x the target is
//! the request-line's second token; over HTTP/2 and HTTP/3 the same information
//! arrives as `:method`, `:scheme`, `:authority` and `:path`, and a capture
//! records the URI the transport reassembled from them. So three rules read
//! three spellings of one element, and the first entry below is one defect in
//! all three — the first entry in this catalogue declared by three rules at
//! once. The second is two of the three, because HTTP/1.1 answers the same
//! question through the form a target derives from rather than through a
//! requirement of its own.
//!
//! **Which is also why an entry here may cite a version document.** The element
//! is one thing; the sentence requiring something of it is sometimes written
//! once for every version (§ 7.1) and sometimes once per version, and where it
//! is the latter the entry names them all and no finding carries one.
//!
//! **Three of the entries below are an HTTP/1.x request-line's alone**, and the
//! reason is the spelling rather than the element: whitespace inside the target,
//! a target of no characters and a target deriving from none of the four forms
//! are all visible where the sender wrote the element out between two spaces.
//! Over the multiplexed versions a capture holds the URI the transport
//! reassembled, so none of the three has evidence to be read from.
//!
//! What the *components* of a target are made of is not here: a scheme that is
//! not a scheme name, an authority that is not a host and port, a percent
//! triplet that does not derive are [`uri`](crate::violations::uri)'s, on every
//! version, and what a pseudo-header field may *carry* is
//! [`authority`](crate::violations::authority)'s.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::authority::{RFC_9113_8_3_1, RFC_9114_4_3_1};
use crate::violations::defects;

/// Where HTTP/1.1 writes the element out: the four forms as one production, the
/// sentence excluding whitespace from all of them, and what a recipient of an
/// invalid request-line is asked to answer. The three entries below that are
/// read out of an HTTP/1.x request-line name it; the two above are about the
/// element whichever way it arrived.
pub const RFC_9112_3_2: SpecRef = SpecRef {
    spec: "RFC 9112",
    section: Some("3.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2",
    note: "Request Target — `request-target = origin-form / absolute-form / authority-form / asterisk-form`, no whitespace allowed in any of them, the recipient's SHOULD to answer 400 rather than autocorrect, and why: a request-line like that might be crafted to bypass a filter along the chain",
};

/// The sentence that makes a value outside its ABNF a violation rather than an
/// observation. Two entries here need it because the request-target's own
/// production says what the four forms are and says nothing about a value that
/// is none of them.
pub const RFC_9110_2_2: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("2.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-2.2",
    note: "Conformance — a sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules",
};

/// The authority-form's own section: what a CONNECT's request-target consists
/// of, the MUST that a client send only that, and where the port comes from when
/// the target URI elided one. HTTP/1.1's, because it is HTTP/1.1 that writes a
/// request-target out — the entry citing it is one no pseudo-header rule can
/// report.
pub const RFC_9112_3_2_3: SpecRef = SpecRef {
    spec: "RFC 9112",
    section: Some("3.2.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2.3",
    note: "authority-form — `authority-form = uri-host \":\" port`, the MUST that a CONNECT send only the host and port of the tunnel destination as its request-target, and the form being used for CONNECT requests only",
};

/// Where the four forms are named, what each is for, and the one MUST NOT that
/// keeps the two method-specific ones to their methods. Shared by the three
/// rules that read a request target, which had grown three notes for it.
pub const RFC_9110_7_1: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("7.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-7.1",
    note: "Determining the Target Resource — the two method-specific forms, the MUST NOT that keeps each to its method, and the reconstruction being specific to each major protocol version",
};

defects! {
    /// A request whose target is the asterisk and whose method is not `OPTIONS`.
    /// The asterisk names no resource: it is the server as a whole, which is a
    /// thing only the method asking about capabilities has anything to say
    /// about. `GET *` therefore has nothing to be applied to, and a recipient
    /// has no target resource to resolve.
    ///
    /// **One defect over three spellings of the element.** Over HTTP/1.x the
    /// asterisk is the request-line's request-target; over HTTP/2 and HTTP/3 it
    /// is the value of `:path`, which each version's document says in its own
    /// words. None of those three is the sentence being broken — § 7.1's MUST
    /// NOT is, and it is written in the version-independent document precisely
    /// because the element is. So the entry carries that one sentence and is
    /// declared by all three rules, where before it was three findings citing
    /// one section through three differently worded consts.
    ///
    /// `error`, which is what all three rules had already chosen for
    /// themselves: the request cannot be routed, and a recipient's only honest
    /// answer is to refuse it.
    ///
    // cite(RFC 9110 § 7.1): "For OPTIONS (Section 9.3.7), the request target can be a single asterisk ("*")."
    // cite(RFC 9110 § 7.1): "These forms MUST NOT be used with other methods."
    REQUEST_TARGET_ASTERISK_FORBIDDEN = {
        id: "request_target_asterisk_forbidden",
        title: "The asterisk target is sent with a method other than OPTIONS",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_7_1],
    }

    /// A request whose target is a host and port — the authority-form — on a
    /// method other than `CONNECT`. That form names a tunnel destination and not
    /// a resource, so a `GET example.com:443` asks for nothing a server could
    /// apply the method to, and a recipient reading it as an origin-form path
    /// would route the request somewhere the client never named.
    ///
    /// **§ 7.1's MUST NOT closes both method-specific forms in one sentence**,
    /// and this is its other half:
    /// [`REQUEST_TARGET_ASTERISK_FORBIDDEN`] is the asterisk sent with a method
    /// that is not `OPTIONS`, and this is the host-and-port sent with a method
    /// that is not `CONNECT`. Two entries rather than one, because the fix
    /// differs — one sender wrote the wrong method, the other wrote a target for
    /// a tunnel it did not ask for — and because an operator silencing one has
    /// no reason to silence the other.
    ///
    /// **One declarer, unlike its sibling.** The asterisk survives reassembly as
    /// a `:path` of `*` and is reported on every version; a host and port does
    /// not, because a capture of an HTTP/2 or HTTP/3 request holds a URI built
    /// from `:scheme`, `:authority` and `:path`, and nothing in it says the
    /// client wrote the authority where a path goes.
    ///
    /// `error`, with the rest of this subject: the request names no resource and
    /// two recipients on one chain may disagree about what it named.
    ///
    // cite(RFC 9110 § 7.1): "For CONNECT (Section 9.3.6), the request target is the host name and port number of the tunnel destination, separated by a colon."
    // cite(RFC 9110 § 7.1): "These forms MUST NOT be used with other methods."
    REQUEST_TARGET_AUTHORITY_FORM_FORBIDDEN = {
        id: "request_target_authority_form_forbidden",
        title: "The host-and-port target is sent with a method other than CONNECT",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_7_1],
    }

    /// A request-target that derives from the authority-form *and* from the
    /// absolute-form, sent with a method that is not CONNECT — `example.com:443`,
    /// `tel:8005551212`, `urn:123`. Read one way it is a host and a port, which
    /// is CONNECT's target and no other method's; read the other it is a full
    /// URI asking a proxy for a resource under a scheme named `example.com`.
    /// Nothing else in the request-line chooses between them.
    ///
    /// **The first entry in this catalogue that reports no verdict about the
    /// message**, and the ending exists for it. Both readings derive, so it is
    /// not `_malformed`; one of them is conforming, so it is not `_invalid` and
    /// not `_forbidden`; and nothing in the message disagrees with anything else
    /// in it, so it is not `_conflicting`. What is being reported is that two
    /// recipients on one chain may route the request two ways — which is the
    /// shape a request-smuggling attempt has, and is also what an ordinary
    /// `tel:` URI in the wrong field looks like.
    ///
    /// **Separate from [`REQUEST_TARGET_AUTHORITY_FORM_FORBIDDEN`] because the
    /// evidence is weaker, not because the defect is different.** That entry is
    /// for a value only the authority-form generates — `192.0.2.1:443`,
    /// `[2001:db8::1]:443`, `:80`, none of which any `scheme` can open — where
    /// § 7.1's MUST NOT is established. Here it may not have been broken at all,
    /// so the entry carries no sentence and ranks below its neighbour.
    ///
    /// `warn`, which the ending requires: an entry that cannot say the message
    /// is wrong may not rank with the ones that can.
    ///
    REQUEST_TARGET_FORM_AMBIGUOUS = {
        id: "request_target_form_ambiguous",
        title: "A request-target derives from two of the four forms at once",
        message: "",
        default_severity: Severity::Warn,
        spec: &[],
    }

    /// A CONNECT whose request-target is in one of the other three forms — a
    /// path, a full URI with a scheme, the asterisk. The target of a CONNECT
    /// *is* the tunnel destination, so a value that is some other form names no
    /// destination at all and a recipient has nowhere to open the tunnel to.
    ///
    /// **`_invalid` and not `_malformed`**: the value derives from a form, just
    /// not from the one this method requires, which is the line the closed
    /// vocabulary draws between grammar and everything past it.
    /// [`REQUEST_TARGET_MALFORMED`] is for a value that derives from no form at
    /// all, and a CONNECT gets that one too — the method changes the wording of
    /// the finding and not which defect it is.
    ///
    /// **The mirror of [`REQUEST_TARGET_AUTHORITY_FORM_FORBIDDEN`], and not the
    /// same entry.** That one is another method reaching for CONNECT's form,
    /// which § 7.1 prohibits in so many words; this one is CONNECT failing to
    /// use it, which § 3.2.3 states as a positive requirement. Two directions,
    /// two sentences, two things a sender has to change.
    ///
    /// **One declarer, and it can only ever have one.** Over HTTP/2 and HTTP/3 a
    /// CONNECT with a `:scheme` and a `:path` is a conforming *extended* CONNECT
    /// (RFC 8441) and a malformed basic one, with nothing in a capture to choose
    /// between them — both pseudo-header rules decline it for that reason. The
    /// request-line has no such ambiguity: RFC 8441's mechanism is not part of
    /// HTTP/1.1.
    ///
    // cite(RFC 9112 § 3.2.3): "When making a CONNECT request to establish a tunnel through one or more proxies, a client MUST send only the host and port of the tunnel destination as the request-target."
    REQUEST_TARGET_CONNECT_FORM_INVALID = {
        id: "request_target_connect_form_invalid",
        title: "A CONNECT's request-target is not a host and port",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9112_3_2_3],
    }

    /// A request whose target carries no path component, on a method that owes
    /// one. Every non-CONNECT request names exactly one path, and where the URI
    /// has no path of its own the sender writes `/` — so a target with none
    /// names no resource for the request to be applied to, which is the same
    /// thing being wrong as in the asterisk above and for a different reason.
    ///
    /// **`_missing` although a capture cannot tell it from `_empty`.** Over
    /// HTTP/2 and HTTP/3 the path arrives as `:path` and a capture holds the URI
    /// the transport reassembled from the pseudo-headers, so a field that was
    /// never sent and one sent blank come back identical. The vocabulary
    /// separates those two by what the *sender* wrote, and here nothing does; the
    /// word is chosen from the recipient's side, which has no path either way.
    /// **Where the evidence cannot distinguish two senders, name the defect the
    /// recipient can see.**
    ///
    /// **Two documents, one per version, and neither governing the other.** Both
    /// state it twice over — the exactly-one MUST for the three pseudo-headers,
    /// and the MUST NOT on an empty value for `http` and `https` URIs — so each
    /// rule's message names the section that governs the version it read.
    ///
    /// `error`, with the asterisk: a recipient cannot resolve a target resource
    /// from this request, and no later message in the exchange repairs it.
    ///
    // cite(RFC 9113 § 8.3.1): "All HTTP/2 requests MUST include exactly one valid value for the ":method", ":scheme", and ":path" pseudo-header fields, unless they are CONNECT requests (Section 8.5)."
    // cite(RFC 9114 § 4.3.1): "This pseudo-header field MUST NOT be empty for "http" or "https" URIs; "http" or "https" URIs that do not contain a path component MUST include a value of / (ASCII 0x2f)."
    REQUEST_TARGET_PATH_MISSING = {
        id: "request_target_path_missing",
        title: "A request that owes a path names none",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9113_8_3_1, RFC_9114_4_3_1],
    }

    /// Whitespace inside a request-target: a SP or HTAB, or a CR, LF or FF. The
    /// sentence excluding it is written of the target as a whole rather than of
    /// any component, and it is written because senders do it — the paragraph
    /// carrying it says so, and follows with the reason a recipient is asked not
    /// to tidy it up: a request-line like that one may have been crafted to get
    /// two recipients on a chain to read two different requests out of it.
    ///
    /// **Only an HTTP/1.x request has this defect to have.** The element arrives
    /// as a request-line there, with SP delimiting the three parts of it, so a
    /// space inside the target is a boundary in the wrong place; over HTTP/2 and
    /// HTTP/3 the transport carries the components separately and a capture holds
    /// what it reassembled. The octet inside a target is a different question
    /// again, asked on every version by
    /// `request_uri_percent_encoding_valid` against the alphabet a URI is
    /// written from.
    ///
    /// `error`, which is what the rule reporting it had already chosen: a
    /// recipient asked not to guess has nothing left to do but refuse the
    /// request.
    ///
    // cite(RFC 9112 § 3.2): "No whitespace is allowed in the request-target."
    REQUEST_TARGET_WHITESPACE_FORBIDDEN = {
        id: "request_target_whitespace_forbidden",
        title: "A request-target carries whitespace",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9112_3_2],
    }

    /// A request-line whose target is the empty string. Every one of the four
    /// forms derives at least one character — an absolute path opens with `/`, an
    /// absolute-URI has a scheme and its colon, a host and port has the colon
    /// between them, and the asterisk is itself — so nothing was written where
    /// the element goes.
    ///
    /// Separate from [`REQUEST_TARGET_MALFORMED`] the way the vocabulary
    /// separates them everywhere: this sender wrote nothing and that one wrote
    /// something no form generates, and the two are different mistakes to make
    /// even though a recipient refuses both. **The pseudo-header versions have no
    /// such split** — there an absent `:path` and a blank one reassemble into one
    /// target, which is why [`REQUEST_TARGET_PATH_MISSING`] is one entry — and
    /// the difference is the request-line, where what the sender wrote is on the
    /// wire.
    ///
    // cite(RFC 9110 § 2.2): "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules."
    REQUEST_TARGET_EMPTY = {
        id: "request_target_empty",
        title: "A request-line carries no request-target",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_2_2],
    }

    /// A request-target that derives from none of the four forms. The four are
    /// alternatives of one production and alternation is not exclusive, so a
    /// value derives from at least one of them or from none — and "none" is not
    /// an odd target to be lenient about, it is a request-line whose recipient is
    /// asked to answer 400 rather than guess which form was meant.
    ///
    /// **The entry is the target's and not the method's**, though the rule
    /// reporting it words the finding differently for a CONNECT: a method that
    /// requires one particular form has more to say about a value in none of
    /// them, and none of that changes what is wrong with the value.
    ///
    // cite(RFC 9110 § 2.2): "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules."
    REQUEST_TARGET_MALFORMED = {
        id: "request_target_malformed",
        title: "A request-target derives from none of the four forms",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_2_2],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The id names the element and the form, and neither the version nor the
    /// field the form arrived in. An operator silencing this is silencing one
    /// defect, whichever of the three transports carried it.
    #[test]
    fn one_entry_serves_three_spellings_of_the_element() {
        assert_eq!(
            REQUEST_TARGET_ASTERISK_FORBIDDEN.id,
            "request_target_asterisk_forbidden"
        );
        for spelling in ["http", "path", "request_line"] {
            assert!(
                !REQUEST_TARGET_ASTERISK_FORBIDDEN.id.contains(spelling),
                "the id names a spelling of the element",
            );
        }
        assert_eq!(REQUEST_TARGET_ASTERISK_FORBIDDEN.spec, [RFC_9110_7_1]);
        assert_eq!(
            REQUEST_TARGET_ASTERISK_FORBIDDEN.default_severity,
            Severity::Error
        );
    }

    /// The message stays at the site: each rule names the method it found and
    /// the spelling the asterisk arrived in, which is what a reader needs to
    /// find it in the traffic and is not something the catalogue can hold.
    #[test]
    fn the_wording_belongs_to_the_site() {
        assert!(REQUEST_TARGET_ASTERISK_FORBIDDEN.message.is_empty());
        assert!(REQUEST_TARGET_PATH_MISSING.message.is_empty());
    }

    /// The asterisk's sentence is version-independent and the path's is not,
    /// which is the whole difference between the two entries' references: one
    /// carries a citation onto its findings and the other cannot.
    #[test]
    fn one_entry_cites_one_document_and_the_other_two() {
        assert_eq!(REQUEST_TARGET_ASTERISK_FORBIDDEN.spec.len(), 1);
        assert_eq!(
            REQUEST_TARGET_PATH_MISSING.spec,
            [RFC_9113_8_3_1, RFC_9114_4_3_1]
        );
    }
}
