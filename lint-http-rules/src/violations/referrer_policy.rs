// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Referrer-Policy` defects — the one entry a field of eight literals has.
//!
//! **The subject is the field and never a member, and that is the document's
//! doing rather than a preference.** § 4.1 writes `1#policy-token`, so the
//! obvious reading is per member: a token outside the eight derives from no
//! `policy-token` and is a finding. § 8.1 refuses that reading. It walks the
//! tokens, sets the policy to the last one it *recognises* and ignores every
//! other, so a field carrying one good token configures a policy however many
//! unknown ones sit beside it — and § 11.1 makes exactly that the way an author
//! deploys a new policy value with a fallback for older user agents. A
//! per-member entry would report the pattern the specification tells authors to
//! write.
//!
//! So the entry fires on the one case where the two readings agree: **no member
//! is a `policy-token`**. The field then derives from no `1#policy-token` at
//! all, and § 8.1 returns the empty string, which § 8.2 leaves the request's
//! policy untouched by. Whatever the eight literals grow into, a field this
//! entry fires on is one that configures nothing in any user agent shipping
//! today — which is what the finding says, and all it says.
//!
//! **The `1#` construct's own two defects are
//! [`list`](crate::violations::list)'s**, as they are for every field that
//! borrows the production: a `Referrer-Policy` with a stray comma and one with
//! no member at all are the same two defects `Vary` and `Accept-Ranges` have,
//! and reading them here under a name of this field's own would split one
//! requirement across a second id.
//!
//! **Nothing here has a case-sensitivity entry, and that is the difference from
//! the `Sec-Fetch-*` family.** Those values are RFC 9651 `sf-token`s, which
//! fold no case, so `Script` is a finding. § 4.1 writes `policy-token` as bare
//! ABNF string literals, and RFC 5234 § 2.3 makes those case-insensitive — so
//! `NO-REFERRER` derives from the production and there is nothing to report.

use crate::lint::Severity;
use crate::lint::Strength;
use crate::rules::SpecRef;
use crate::violations::defects;

/// The header's own section: its ABNF, and the eight literals a `policy-token`
/// is one of.
pub const REFERRER_POLICY_4_1: SpecRef = SpecRef {
    spec: "Referrer Policy",
    section: Some("4.1"),
    url: "https://www.w3.org/TR/referrer-policy/#referrer-policy-header",
    note: "Delivery via Referrer-Policy header — `\"Referrer-Policy:\" 1#policy-token`, and the eight literals `policy-token` is one of",
};

/// What a user agent does with the field: the walk that keeps the last
/// recognised token, and what it returns when there is none.
pub const REFERRER_POLICY_8_1: SpecRef = SpecRef {
    spec: "Referrer Policy",
    section: Some("8.1"),
    url: "https://www.w3.org/TR/referrer-policy/#parse-referrer-policy-from-header",
    note: "Parse a referrer policy from a Referrer-Policy header — unknown tokens are ignored, the last recognised one wins, and a field with none of them yields the empty string",
};

/// Why an unknown token beside a known one is the documented deployment
/// pattern rather than a defect.
pub const REFERRER_POLICY_11_1: SpecRef = SpecRef {
    spec: "Referrer Policy",
    section: Some("11.1"),
    url: "https://www.w3.org/TR/referrer-policy/#unknown-policy-values",
    note: "Unknown Policy Values — the fallback idiom the § 8.1 walk exists to allow, and the reason this catalogue judges the field rather than its members",
};

defects! {
    /// A `Referrer-Policy` whose every member is a token § 4.1 does not print,
    /// so the response names no referrer policy at all.
    ///
    /// **What it costs is the whole field.** § 8.1 returns the empty string,
    /// § 8.2 then declines to touch the request's referrer policy, and the user
    /// agent falls back to whatever it would have used had the header never
    /// been sent. A site that meant `no-referrer` and wrote `no-referer` is
    /// leaking the full URL of every page it serves to every cross-origin
    /// destination it links to, and nothing on the wire says so — the header is
    /// present, well-formed as a list, and inert.
    ///
    /// **A member outside the eight is not this entry**, and the silence is
    /// § 11.1's: an author deploying a policy value older user agents do not
    /// know writes it beside one they do, and that field configures a policy
    /// everywhere. This entry is reached only where nothing is recognised,
    /// which is the state no fallback rescues.
    ///
    /// `Grammar`: § 4.1's `policy-token` is a closed alternation of string
    /// literals, and a field none of whose members derive from it derives from
    /// no `1#policy-token` either. That is the same footing
    /// [`CROSS_ORIGIN_RESOURCE_POLICY_INVALID`](crate::violations::cross_origin::CROSS_ORIGIN_RESOURCE_POLICY_INVALID)
    /// stands on, and it lands at `error` for the reason that variant gives.
    ///
    /// `_invalid`: the tokens derive and the closed set written past them is
    /// what refuses the value — the ending its three cross-origin-policy
    /// siblings carry for the same reason.
    ///
    // cite(Referrer Policy § 4.1): "policy-token = "no-referrer" / "no-referrer-when-downgrade" / "strict-origin" / "strict-origin-when-cross-origin" / "same-origin" / "origin" / "origin-when-cross-origin" / "unsafe-url""
    // cite(Referrer Policy § 8.1): "For each token in policy-tokens, if token is a referrer"
    REFERRER_POLICY_INVALID = {
        id: "referrer_policy_invalid",
        title: "Referrer-Policy names no referrer policy",
        message: "",
        default_severity: Severity::Error,
        spec: &[REFERRER_POLICY_4_1, REFERRER_POLICY_8_1],
        strength: Strength::Grammar,
    }
}
