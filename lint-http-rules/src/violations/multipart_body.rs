// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Multipart body defects — the delimiter lines a declared boundary promises
//! and the body does not carry.
//!
//! [`boundary`](crate::violations::boundary) is about the parameter: whether
//! the value a sender chose can serve as a delimiter at all. This subject is
//! about the other half of the same promise — the body — and the two are
//! separable in both directions: a perfectly good boundary may delimit nothing,
//! and a body full of delimiter lines may be introduced by a boundary no
//! gateway will carry.
//!
//! **Every entry is measured only between the first delimiter line and the
//! last.** § 5.1.1 tells implementations to ignore whatever precedes the first
//! and follows the final one, so the preamble and the epilogue can neither
//! satisfy a check here nor fail one — a body whose only occurrence of the
//! boundary text is in its preamble reaches the first entry below, because
//! nothing that delimits anything was found.
//!
//! **Nothing here is a framing check.** RFC 9110 § 8.3.3 says HTTP does not use
//! the boundary to determine message length, so a body that is missing its
//! terminator is not a truncated message: it is a message whose recipient
//! cannot tell whether the parts it has are all of them.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// The delimiter lines: what opens a part, what ends the last one, and what a
/// recipient is told to ignore on either side of them.
pub const RFC_2046_5_1_1: SpecRef = SpecRef {
    spec: "RFC 2046",
    section: Some("5.1.1"),
    url: "https://www.rfc-editor.org/rfc/rfc2046.html#section-5.1.1",
    note: "Multipart common syntax: `dash-boundary`, `delimiter` and `close-delimiter`, the requirement that a delimiter begin a line, the instruction to compare against the beginning of a candidate line rather than the whole of it, and the ignoring of preamble and epilogue",
};

defects! {
    /// A body that carries no delimiter line for the boundary its own
    /// `Content-Type` declared. The parts, if any, are not separated by
    /// anything a recipient is allowed to recognise.
    ///
    /// The text occurring *somewhere* in the body does not count and is worth
    /// saying twice: a delimiter is a line, so `--boundary` in the middle of one
    /// delimits nothing. The message says which of the two was found, because
    /// the fixes differ — a sender who wrote the text without a line break has
    /// a different bug from one who wrote the wrong boundary.
    ///
    // cite(RFC 2046 § 5.1.1, label: preamble and epilogue): "implementations must ignore anything that appears before the first boundary delimiter line or after the last one."
    MULTIPART_BODY_DELIMITER_MISSING = {
        id: "multipart_body_delimiter_missing",
        title: "The body carries no delimiter line for its boundary",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_2046_5_1_1),
    }

    /// A body whose only delimiter line is the terminating one. The closing
    /// delimiter is defined as the line *following the last body part*, so a
    /// body where it comes first follows nothing — the type says the content is
    /// several representations and the content is none.
    ///
    /// One part is not the defect: § 5.1.1 permits a single body part in as
    /// many words, so the floor this entry enforces is one and not two.
    ///
    // cite(RFC 2046 § 5.1.1): "The use of the "multipart" media type with only a single body part may be useful in certain contexts, and is explicitly permitted."
    MULTIPART_BODY_PART_MISSING = {
        id: "multipart_body_part_missing",
        title: "The only delimiter line is the terminating one",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_2046_5_1_1),
    }

    /// A body with parts and no closing delimiter. Nothing tells a recipient
    /// that the parts have ended, which is the entire function § 5.1.1 gives
    /// that line — so a reader either waits for a part that is not coming or
    /// guesses that the last one it saw was the last.
    ///
    // cite(RFC 2046 § 5.1.1, label: close-delimiter): "Such a delimiter line is identical to the previous delimiter lines, with the addition of two more hyphens after the boundary parameter value."
    MULTIPART_BODY_TERMINATOR_MISSING = {
        id: "multipart_body_terminator_missing",
        title: "The body never closes its last part",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_2046_5_1_1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Three entries in the order a body fails them, and the order is the
    /// reading: no delimiter at all, then a delimiter that opens nothing, then
    /// parts that never close. Each is a strictly later question than the one
    /// before it, which is why a body reaches exactly one.
    #[test]
    fn the_three_entries_are_answered_in_one_order() {
        for def in [
            &MULTIPART_BODY_DELIMITER_MISSING,
            &MULTIPART_BODY_PART_MISSING,
            &MULTIPART_BODY_TERMINATOR_MISSING,
        ] {
            assert!(def.id.starts_with("multipart_body_"), "{}", def.id);
            assert_eq!(def.spec, Some(RFC_2046_5_1_1), "{}", def.id);
            assert!(def.message.is_empty(), "{}", def.id);
        }
    }
}
