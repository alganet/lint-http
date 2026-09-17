// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Well-known URI defects — a path that looks like one of RFC 8615's reserved
//! locations and is not.
//!
//! **Every entry here is advice, and that is the subject rather than a
//! weakness in it.** RFC 8615 reserves a path prefix and *defines* what a
//! well-known URI is; it states no requirement on a request target at all, and
//! §1 is explicit that defining well-known locations usurps an origin's control
//! over its own URI space. So a path these entries report is a path the origin
//! is entitled to serve — what is being said is that an application looking for
//! site-wide metadata will not find it there, which is a thing worth saying to
//! whoever wrote the path and not a thing anybody breached.
//!
//! **The one MUST in the document is addressed to somebody else.** A registered
//! name MUST conform to `segment-nz`, and that sentence binds the application
//! registering the name — so the two entries resting on it report that no
//! conforming registration could answer the path, never that this client did
//! something it may not.
//!
//! **`info` throughout, and it is the ceiling rather than a starting point.**
//! An entry here can never rise: there is no requirement to have missed.
//
// cite(RFC 8615 § 1): "Furthermore, defining well-known locations usurps the origin's control over its own URI space [RFC7320]."

use crate::lint::Severity;
use crate::lint::Strength;
use crate::rules::SpecRef;
use crate::violations::defects;

/// The reserved prefix, trailing slash included, and the sentence that keeps
/// this memo out of an origin's URI space.
pub const RFC_8615_1: SpecRef = SpecRef {
    spec: "RFC 8615",
    section: Some("1"),
    url: "https://www.rfc-editor.org/rfc/rfc8615.html#section-1",
    note: "Introduction — the prefix this memo reserves, trailing slash included; that other schemes carry well-known URIs only where their definitions allow it; and the origin's control over its own URI space",
};

/// What a well-known URI *is*: the definition, the `segment-nz` MUST on a
/// registered name, and the sentence saying a `.well-known` further down the
/// path is not one.
pub const RFC_8615_3: SpecRef = SpecRef {
    spec: "RFC 8615",
    section: Some("3"),
    url: "https://www.rfc-editor.org/rfc/rfc8615.html#section-3",
    note: "Well-Known URIs — the definition and its scheme proviso, the `segment-nz` MUST on a registered name, the MAY for additional path components, and the sentence saying a `.well-known` elsewhere in the path is not one",
};

/// The path production a registered name is measured against, and the
/// character class inside it.
pub const RFC_3986_3_3: SpecRef = SpecRef {
    spec: "RFC 3986",
    section: Some("3.3"),
    url: "https://www.rfc-editor.org/rfc/rfc3986.html#section-3.3",
    note: "Path — `segment-nz = 1*pchar`, what a `pchar` is, and where the path component ends",
};

defects! {
    /// A `.well-known` segment somewhere other than the top of the path:
    /// `/foo/.well-known/example`.
    ///
    /// **The document states this case and its counter-example itself**, and it
    /// states them as a definition: such a path is *not* a well-known URI. So
    /// the finding says what the path is not, and the path names an ordinary
    /// resource the origin is entitled to serve under whatever name it likes.
    ///
    /// `_invalid` rather than `_malformed`: the path derives from
    /// `path-absolute` exactly as written, and what refuses it is the
    /// definition written past the grammar — which is the line this ending
    /// draws everywhere else in the catalogue.
    ///
    /// **The comparison is made after normalization**, because a dot segment
    /// moves the prefix: `/a/../.well-known/x` names the same resource as
    /// `/.well-known/x`, and reporting it would be a finding about a spelling.
    ///
    // cite(RFC 8615 § 3): "Well-known URIs are rooted in the top of the path's hierarchy; they are not well-known by definition in other parts of the path."
    WELL_KNOWN_PATH_INVALID = {
        id: "well_known_path_invalid",
        title: "A .well-known segment sits below the top of the path",
        message: "",
        default_severity: Severity::Info,
        spec: &[RFC_8615_3],
    }

    /// A path that is `/.well-known` and stops there.
    ///
    /// **The trailing slash is one of the prefix's characters**, so a path
    /// ending on the segment does not begin with the prefix and is not a
    /// well-known URI — one character short of the thing it looks like.
    ///
    /// **Separate from [`WELL_KNOWN_PATH_INVALID`] because the repair is**: a
    /// buried prefix is at the wrong depth and this one is at the right depth
    /// and incomplete. `_malformed` for the same reason — § 1 reserves a
    /// literal string and this value does not match it, where the buried case
    /// matches the string and fails the definition around it.
    ///
    // cite(RFC 8615 § 1): "To address these uses, this memo reserves a path prefix in HTTP, HTTPS, WebSocket (WS), and Secure WebSocket (WSS) URIs for these "well-known locations", "/.well-known/"."
    WELL_KNOWN_PREFIX_MALFORMED = {
        id: "well_known_prefix_malformed",
        title: "A path stops one character short of the reserved prefix",
        message: "",
        default_severity: Severity::Info,
        spec: &[RFC_8615_1],
    }

    /// The reserved prefix with nothing after it: `/.well-known/`, or
    /// `/.well-known//x`.
    ///
    /// **A cardinality, which is why it is `_empty` and not
    /// [`WELL_KNOWN_NAME_MALFORMED`]**: `segment-nz` is `1*pchar`, so no
    /// conforming registration generates an empty name, and what the sender
    /// wrote is the slot with nothing in it rather than something wrong in the
    /// slot. § 3 adds that it defines no format or media type for the resource
    /// at the prefix itself, so there is nothing there to have been meant.
    ///
    /// **`/.well-known//x` is reported too**: the MAY that licenses further
    /// path components licenses them *appended to a well-known URI*, and
    /// without a name there is no well-known URI to append them to.
    ///
    // cite(RFC 8615 § 3): "Registered names MUST conform to the "segment-nz" production in [RFC3986]."
    WELL_KNOWN_NAME_EMPTY = {
        id: "well_known_name_empty",
        title: "The reserved prefix carries no name after it",
        message: "",
        default_severity: Severity::Info,
        spec: &[RFC_8615_3],
        strength: Strength::Unstated,
    }

    /// A registered name holding an octet `pchar` does not admit.
    ///
    /// **Only the first segment after the prefix is the name.** § 3's own
    /// "they cannot contain the "/" character" is about the registered name,
    /// and the MAY beside it licenses further path components appended to the
    /// well-known URI — so `/.well-known/est/simpleenroll` names `est` and is
    /// nothing to report.
    ///
    /// `_malformed` against its sibling's `_empty`: there the slot was left
    /// blank, here it holds an octet the production has no room for.
    ///
    // cite(RFC 3986 § 3.3, label: pchar): "pchar         = unreserved / pct-encoded / sub-delims / ":" / "@""
    WELL_KNOWN_NAME_MALFORMED = {
        id: "well_known_name_malformed",
        title: "A well-known name holds a character outside pchar",
        message: "",
        default_severity: Severity::Info,
        spec: &[RFC_3986_3_3],
        strength: Strength::Unstated,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The subject's ceiling, asserted rather than described: RFC 8615 states
    /// no requirement on a request target, so nothing here can outrank advice.
    #[test]
    fn nothing_in_this_subject_claims_a_requirement() {
        for def in [
            &WELL_KNOWN_PATH_INVALID,
            &WELL_KNOWN_PREFIX_MALFORMED,
            &WELL_KNOWN_NAME_EMPTY,
            &WELL_KNOWN_NAME_MALFORMED,
        ] {
            assert_eq!(def.default_severity, Severity::Info);
        }
    }
}
