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
//! asks about — and the section closes them both with one MUST NOT.
//!
//! **What makes this a subject rather than a drawer is that the element is
//! version-independent while its spelling is not.** Over HTTP/1.x the target is
//! the request-line's second token; over HTTP/2 and HTTP/3 the same information
//! arrives as `:method`, `:scheme`, `:authority` and `:path`, and a capture
//! records the URI the transport reassembled from them. So three rules read
//! three spellings of one element, and the defect below is one defect in all
//! three — the first entry in this catalogue declared by three rules at once.
//!
//! What the *components* of a target are made of is not here: a scheme that is
//! not a scheme name, an authority that is not a host and port, a percent
//! triplet that does not derive are [`uri`](crate::violations::uri)'s, on every
//! version, and the pseudo-header fields' own requirements are each version
//! document's.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

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
    }
}
