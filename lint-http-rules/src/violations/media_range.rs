// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `media-range` defects — the two things only the *wider* production can say.
//!
//! `media-range = ( "*/*" / ( type "/" "*" ) / ( type "/" subtype ) )
//! parameters` is `media-type` with the asterisk let in, and it appears in one
//! field: RFC 9110 § 12.5.1's `Accept = #( media-range [ weight ] )`. Almost
//! everything a member can be wrong about therefore belongs somewhere else —
//! the two halves are `token`s, the tail is § 5.6.6's `parameters`, a value in
//! it is a `token` or a `quoted-string`, the number after `q=` is `qvalue`'s,
//! and *failing to be a `type "/" subtype` pair at all* is
//! [`media_type`](crate::violations::media_type)'s, which is the entry
//! `Content-Type` reaches through the same reader.
//!
//! **What is left is two findings the alternation itself produces**, and both
//! are about position rather than about characters: an asterisk written where
//! the production gives it no meaning, and a parameter written past the point
//! where the member ends.
//!
//! **A bare `*` is deliberately not among them.** It looks like this subject's
//! defect and it is not: `*` has no `/` in it, so it derives from none of the
//! three alternatives for the same arithmetic reason `text` does, and
//! [`MEDIA_TYPE_MALFORMED`](crate::violations::media_type::MEDIA_TYPE_MALFORMED)
//! already names that. Giving it an id of its own would split one defect on
//! what the sender probably meant, which is a thing no report can know — the
//! message says the value was `*` and that is where the guess belongs.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// `Accept` and the production that admits the asterisk, plus the sentences
/// that say what the asterisk ranges over and what a member may hold after its
/// weight.
pub const RFC_9110_12_5_1: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("12.5.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.1",
    note: "Accept: the `#( media-range [ weight ] )` list, the three shapes a `media-range` takes and what the asterisk ranges over, and the removal of the extension parameters that once followed the weight",
};

defects! {
    /// A wildcard type beside a concrete subtype: `*/json`, `*/plain`.
    ///
    /// **`_invalid` and not `_malformed`, because the value derives.** `type`
    /// is a `token` and `*` is a `tchar`, so `*/json` is a perfectly good
    /// `type "/" subtype` and no reading of the ABNF refuses it. What refuses
    /// it is the sentence that gives the asterisk its meaning: it groups media
    /// types into ranges, and it has exactly two jobs — all media types, or all
    /// subtypes of one type. A wildcard type beside a named subtype is neither,
    /// so the member names no set a recipient could match a representation
    /// against, and a preference that matches nothing is a preference that was
    /// not expressed.
    ///
    /// **Not
    /// [`MEDIA_TYPE_WILDCARD_FORBIDDEN`](crate::violations::media_type::MEDIA_TYPE_WILDCARD_FORBIDDEN),
    /// which is the same octet under the opposite claim.** That entry is for an
    /// asterisk in a `Content-Type`, where the field states *the* media type of
    /// a representation and any wildcard at all says nothing. Here the wildcard
    /// is what the production exists for; only this one arrangement of it names
    /// nothing. One asterisk, two fields, two sentences — and an entry shared
    /// between them would have to claim that a `Accept: text/*` is as wrong as
    /// a `Content-Type: text/*`, which is exactly backwards.
    ///
    // cite(RFC 9110 § 12.5.1): "The asterisk "*" character is used to group media types into ranges, with "*/*" indicating all media types and "type/*" indicating all subtypes of that type."
    MEDIA_RANGE_WILDCARD_INVALID = {
        id: "media_range_wildcard_invalid",
        title: "A wildcard type is written beside a concrete subtype",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_12_5_1],
    }

    /// A parameter written after the weight: `text/html;q=0.5;charset=utf-8`.
    ///
    /// The member is `media-range [ weight ]` and the media-range is what
    /// carries `parameters`, so the weight closes it and nothing derives past
    /// that point. RFC 9110 says so twice over: it removed the `accept-params`
    /// / `accept-ext` grammar that used to put extension parameters there, and
    /// it states the consequence as a `SHOULD` on senders in the same
    /// paragraph.
    ///
    /// `_forbidden` rather than `_malformed`, and the ending's own row is the
    /// argument: the parameter is well formed and so is the weight, and what is
    /// wrong is that it was written *here*. Reading it is unambiguous — the
    /// finding is about what a sender generated, not about what a recipient
    /// will do — which is also why it is `warn` and not `error`.
    ///
    // cite(RFC 9110 § 12.5.1): "Previous specifications allowed additional extension parameters to appear after the weight parameter."
    MEDIA_RANGE_PARAMETER_FORBIDDEN = {
        id: "media_range_parameter_forbidden",
        title: "Accept member writes a parameter after the weight",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_12_5_1],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::violations::media_type::MEDIA_TYPE_WILDCARD_FORBIDDEN;

    /// The two asterisk entries are two ids, and the assertion is the claim
    /// that keeps them apart: they answer opposite questions about the same
    /// character, so nothing about one may ever be inferred from the other.
    #[test]
    fn the_two_asterisk_entries_are_never_the_same_finding() {
        assert_ne!(
            MEDIA_RANGE_WILDCARD_INVALID.id,
            MEDIA_TYPE_WILDCARD_FORBIDDEN.id
        );
    }

    /// Both entries here are about a value a recipient can read perfectly well,
    /// so neither outranks the grammar defects the same rule reports.
    #[test]
    fn a_member_that_reads_and_says_nothing_is_a_warning() {
        assert_eq!(
            MEDIA_RANGE_WILDCARD_INVALID.default_severity,
            Severity::Warn
        );
        assert_eq!(
            MEDIA_RANGE_PARAMETER_FORBIDDEN.default_severity,
            Severity::Warn
        );
    }
}
