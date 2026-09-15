// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Cross-origin policy defects — the three response headers a document uses to
//! say who may hold it, embed it, and load it.
//!
//! **Three fields, one shape.** Each carries a single token drawn from a closed
//! set its own document names, and none of them has a list form — so a value
//! with a comma in it is not a list defect but a value none of the sets
//! contains, which is the reading
//! [`access_control_allow_origin`](crate::violations::access_control_allow_origin)
//! settled for a field of the same shape.
//!
//! **The sets are not compared the same way, and that is the documents'
//! doing**: Fetch writes `Cross-Origin-Resource-Policy`'s ABNF with `%s`
//! literals and the words *case-sensitive*, while HTML's two are structured
//! field tokens read case-insensitively here. A `SAME-ORIGIN` is a finding and
//! a `REQUIRE-CORP` is not.
//!
//! **One entry in this subject is not the document's judgment but this
//! crate's**, and it says so: `unsafe-none` is a perfectly valid embedder
//! policy and the one that turns the protection off. A linter may be stricter
//! than a grammar as long as it does not dress the preference as a
//! requirement, which is why that entry names no sentence and ranks below the
//! rest.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// The opener policy header, parsed as a single structured field item.
pub const HTML_7_1_3_1: SpecRef = SpecRef {
    spec: "HTML",
    section: Some("7.1.3.1"),
    url: "https://html.spec.whatwg.org/multipage/browsers.html#the-coop-headers",
    note: "The `Cross-Origin-Opener-Policy` header is parsed as a single structured-field item (token); `same-origin-plus-COEP` is derived from `same-origin` + a compatible COEP, never set directly",
};

/// The embedder policy header, and the three strings its value is one of.
pub const HTML_7_1_4: SpecRef = SpecRef {
    spec: "HTML",
    section: Some("7.1.4"),
    url: "https://html.spec.whatwg.org/multipage/browsers.html#cross-origin-embedder-policy",
    note: "The `Cross-Origin-Embedder-Policy` header — its value is one of the three embedder policy strings `unsafe-none`, `require-corp`, `credentialless`",
};

/// The resource policy header: a case-sensitive grammar of three literals, and
/// what a user agent does with anything else.
pub const FETCH_3_7: SpecRef = SpecRef {
    spec: "Fetch",
    section: Some("3.7"),
    url: "https://fetch.spec.whatwg.org/#cross-origin-resource-policy-header",
    note: "`Cross-Origin-Resource-Policy` — the case-sensitive `same-origin`/`same-site`/`cross-origin` grammar, and unrecognized values set to null",
};

defects! {
    /// A `Cross-Origin-Opener-Policy` that is none of `same-origin`,
    /// `same-origin-allow-popups`, `noopener-allow-popups` and `unsafe-none` —
    /// including a value written as a comma-separated list.
    ///
    /// **The comma is not a list defect**, because the field has no list form:
    /// § 7.1.3.1 gets a structured field value as an *item*, so a comma
    /// produces something the item parse does not yield and the browsing
    /// context group gets no policy at all. Same sentence, same repair, one id.
    ///
    /// **`same-origin-plus-COEP` is not one of the accepted values and never
    /// was one to send**: it is derived from `same-origin` beside a compatible
    /// embedder policy, so a server writing it directly has written a value the
    /// parse does not know.
    ///
    /// `_invalid`: the token derives and the closed set written past it is what
    /// refuses the value.
    ///
    // cite(HTML § 7.1.3.1): "Let parsedItem be the result of getting a structured field value given `Cross-Origin-Opener-Policy` and "item" from response's header list."
    CROSS_ORIGIN_OPENER_POLICY_INVALID = {
        id: "cross_origin_opener_policy_invalid",
        title: "Cross-Origin-Opener-Policy names no opener policy",
        message: "",
        default_severity: Severity::Warn,
        spec: &[HTML_7_1_3_1],
    }

    /// A `Cross-Origin-Embedder-Policy` that is none of the three embedder
    /// policy strings.
    ///
    /// The comma case lands here for the reason it lands on the opener entry:
    /// the field carries one value and a list produces none of the three.
    ///
    /// **Separate from [`CROSS_ORIGIN_EMBEDDER_POLICY_ISOLATION_MISSING`]
    /// beside it, and the separation is the point of both.** That entry is
    /// about a value the document defines and this crate would rather not see;
    /// this one is about a value the document does not define at all. A
    /// deployment silencing the preference has not agreed to silence the typo.
    ///
    // cite(HTML § 7.1.4): "An embedder policy value is one of three strings that controls the fetching of cross-origin resources without explicit permission from resource owners."
    CROSS_ORIGIN_EMBEDDER_POLICY_INVALID = {
        id: "cross_origin_embedder_policy_invalid",
        title: "Cross-Origin-Embedder-Policy names no embedder policy",
        message: "",
        default_severity: Severity::Warn,
        spec: &[HTML_7_1_4],
    }

    /// A `Cross-Origin-Embedder-Policy: unsafe-none` — the one embedder policy
    /// that does not isolate.
    ///
    /// **This entry is a preference and names no sentence, which is the only
    /// honest way to hold one.** `unsafe-none` is valid, it is the default a
    /// document has without the header at all, and nothing in HTML says a
    /// server should avoid it. What this reports is that a deployment wrote the
    /// header and chose the value that turns the protection off — worth saying,
    /// and not worth dressing as a requirement.
    ///
    /// `_missing` names what is absent, which is the isolation rather than the
    /// value: the field is present and well formed, and the thing that is not
    /// there is the protection the other two values would have bought.
    ///
    /// `info`, and the ceiling is the same as the reason: an entry standing on
    /// this crate's preference cannot outrank one standing on a document.
    CROSS_ORIGIN_EMBEDDER_POLICY_ISOLATION_MISSING = {
        id: "cross_origin_embedder_policy_isolation_missing",
        title: "A Cross-Origin-Embedder-Policy is set to the value that does not isolate",
        message: "Cross-Origin-Embedder-Policy is 'unsafe-none', which is valid and does not enable cross-origin isolation (use 'require-corp' or 'credentialless')",
        default_severity: Severity::Info,
        spec: &[],
    }

    /// A `Cross-Origin-Resource-Policy` that is none of `same-origin`,
    /// `same-site` and `cross-origin`, compared byte for byte.
    ///
    /// **The case comparison is the grammar's and not a choice**: Fetch writes
    /// the three alternatives with `%s` literals and the words *case-sensitive*
    /// beside them, so `SAME-ORIGIN` is one of these findings. A user agent
    /// reading it sets the policy to null, which is the same place a typo
    /// leaves it — the resource is loadable from anywhere the header was meant
    /// to exclude.
    ///
    // cite(Fetch § 3.7): "Cross-Origin-Resource-Policy = %s"same-origin" / %s"same-site" / %s"cross-origin" ; case-sensitive"
    CROSS_ORIGIN_RESOURCE_POLICY_INVALID = {
        id: "cross_origin_resource_policy_invalid",
        title: "Cross-Origin-Resource-Policy names no resource policy",
        message: "",
        default_severity: Severity::Warn,
        spec: &[FETCH_3_7],
    }
}
