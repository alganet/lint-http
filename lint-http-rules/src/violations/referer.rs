// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Referer` defects — what a user agent may say about where it came from.
//!
//! **None of these is about the URI reference being well formed.** `Referer =
//! absolute-URI / partial-URI` borrows both alternatives whole, so a scheme
//! that is not one, a host that is not one and a percent-encoding that is not
//! one all report through [`uri`](crate::violations::uri) — the same ids a
//! `Location`, an `Alt-Svc` and an absolute-form request target report with.
//! What is left is the four things § 10.1.3 says about the field *beyond* its
//! grammar, and every one of them is about disclosure.
//!
//! **The field's whole hazard is that it is a URI written into somebody else's
//! logs**, which § 17.9 states in as many words: it tells a target site about
//! the context that produced the request, and that context may carry the user's
//! browsing history and whatever personal information the referring URI held.
//! So the two components § 10.1.3 excludes are excluded for what they *reveal*
//! rather than for what they break, and the entries rank on the same reading —
//! a credential above a component above a value that is merely unhelpful.
//
// cite(RFC 9110 § 17.9): "Since the Referer header field tells a target site about the context that resulted in a request, it has the potential to reveal information about the user's immediate browsing history and any personal information that might be found in the referring resource's URI."

use crate::lint::Severity;
use crate::lint::Strength;
use crate::rules::SpecRef;
use crate::violations::defects;

/// The field: its grammar, the two components excluded from it, the sentence
/// about an unsecured request, and what a user agent with nothing to state
/// does instead.
pub const RFC_9110_10_1_3: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("10.1.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1.3",
    note: "Referer — the field's grammar, the fragment and userinfo MUST NOT, the unsecured-request MUST NOT, and the two declined conditionals",
};

defects! {
    /// A `Referer` carrying a userinfo subcomponent and its `@` delimiter.
    ///
    /// **`error`, with the two entries reporting the same octet on other
    /// fields** —
    /// [`host_userinfo_forbidden`](crate::violations::host::HOST_USERINFO_FORBIDDEN)
    /// and
    /// [`authority_userinfo_forbidden`](crate::violations::authority::AUTHORITY_USERINFO_FORBIDDEN)
    /// — and for their reason: the credential is out, and no later message
    /// takes it back. Here it is out in the one field whose entire purpose is
    /// to be written down by the party receiving it.
    ///
    /// **`Some("")` is a userinfo too.** The production generates the empty
    /// one, and the `@` is what says the component was included at all — a
    /// sender that copied a reference without applying the exclusion, which is
    /// the mistake the entry is for.
    ///
    /// **Reported ahead of the host's own grammar**, because a userinfo makes
    /// the host look like a port to any reader splitting on the colon: asked
    /// second, the finding would name the wrong component.
    ///
    // cite(RFC 9110 § 10.1.3): "A user agent MUST NOT include the fragment and userinfo components of the URI reference [URI], if any, when generating the Referer field value."
    // cite(RFC 3986 § 3.2.1): "Use of the format "user:password" in the userinfo field is deprecated."
    REFERER_USERINFO_FORBIDDEN = {
        id: "referer_userinfo_forbidden",
        title: "A Referer carries the deprecated userinfo subcomponent",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_10_1_3],
        strength: Strength::Must,
    }

    /// A `Referer` carrying a fragment component.
    ///
    /// **The grammar refuses it and the section refuses it, which is why this
    /// entry has more behind it than its `Content-Location` counterpart.**
    /// `absolute-URI` and `partial-URI` are the two URI rules with the
    /// `[ "#" fragment ]` group dropped, so a value holding one derives from
    /// neither alternative — and § 10.1.3 then names the component in a MUST
    /// NOT of its own. *Two independent refusals of one character.*
    ///
    /// A number sign is the only character that opens the component and it
    /// appears in no other one, so finding one is finding a fragment. A
    /// percent-encoded `%23` is data and is not this.
    ///
    /// `warn`, below the userinfo above it: what a fragment discloses is which
    /// part of the referring page the user was on, which is information the
    /// target site was not meant to have and is not a credential.
    ///
    // cite(RFC 9110 § 10.1.3): "A user agent MUST NOT include the fragment and userinfo components of the URI reference [URI], if any, when generating the Referer field value."
    REFERER_FRAGMENT_FORBIDDEN = {
        id: "referer_fragment_forbidden",
        title: "A Referer carries a fragment component",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_10_1_3],
        strength: Strength::Must,
    }

    /// A `Referer` naming an `https` resource, on a request whose own target
    /// URI is an `http` one.
    ///
    /// **The finding is about the request rather than about the value.** The
    /// reference is well formed and correctly describes where the user came
    /// from; what is wrong is that this request should not be carrying it —
    /// § 10.1.3 states it as a flat MUST NOT, and § 4.2.2 is why: the two
    /// schemes are distinct origins, and a URL protected by TLS on the way in
    /// is put on the wire in the clear on the way out.
    ///
    /// **It ranks with the fragment and not with the userinfo**, on the split
    /// this subject draws everywhere: a component that should not be there,
    /// against a secret that should not be anywhere.
    ///
    /// **A request whose scheme is unknown draws nothing**, which is a limit
    /// worth stating on the page rather than in the rule alone: an origin-form
    /// target carries a path and no scheme, and no captured field records the
    /// one that would have completed it — so silence here is a capture's limit
    /// and never a verdict.
    ///
    // cite(RFC 9110 § 10.1.3): "A user agent MUST NOT send a Referer header field in an unsecured HTTP request if the referring resource was accessed with a secure protocol."
    // cite(RFC 9110 § 4.2.2): "Resources made available via the "https" scheme have no shared identity with the "http" scheme.  They are distinct origins with separate namespaces."
    REFERER_FORBIDDEN = {
        id: "referer_forbidden",
        title: "A Referer names a secure resource on an unsecured request",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_10_1_3],
        strength: Strength::Must,
    }

    /// A `Referer` written and left blank.
    ///
    /// **The grammar has no complaint and that is the entry.** `partial-URI`
    /// admits `path-empty`, so an empty value is a same-document reference: it
    /// resolves to the target URI the request already carried, and states the
    /// one thing the recipient certainly knew.
    ///
    /// **What makes it worth a word is that this section says what to write
    /// instead**, which its two sibling fields carrying the same production do
    /// not: a user agent with no referring URI to state either omits the field
    /// or sends `about:blank`, and an empty value is neither. So the entry
    /// names a sentence in order to point at the two spellings, never to claim
    /// the sentence was broken — nothing in a message says where the target URI
    /// came from, so the MUST's antecedent is not reachable from a capture.
    ///
    /// `info`, for a finding the document permits outright — the footing
    /// [`content_location_empty`](crate::violations::content_location::CONTENT_LOCATION_EMPTY)
    /// already sits on, one field over, for the same empty reference.
    ///
    // cite(RFC 9110 § 10.1.3): "If the target URI was obtained from a source that does not have its own URI (e.g., input from the user keyboard, or an entry within the user's bookmarks/favorites), the user agent MUST either exclude the Referer header field or send it with a value of "about:blank"."
    REFERER_EMPTY = {
        id: "referer_empty",
        title: "A Referer is written with nothing in it",
        message: "",
        default_severity: Severity::Info,
        spec: &[RFC_9110_10_1_3],
        strength: Strength::Unstated,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The subject used to rank on what a finding discloses: a credential,
    /// then a component, then a value that discloses nothing.
    ///
    /// § 10.1.3 writes one sentence over the first two — "A user agent MUST NOT
    /// include the fragment and userinfo components" — so no reading of it puts
    /// them at two levels, and the third `MUST NOT` in the same section joins
    /// them. What still sits below is `referer_empty`, and for the reason its
    /// own entry gives: nothing in a message says where the target URI came
    /// from, so that sentence's antecedent is not reachable from a capture and
    /// the entry claims no obligation at all.
    #[test]
    fn the_three_disclosures_rank_together_and_the_empty_value_below_them() {
        for def in [
            &REFERER_USERINFO_FORBIDDEN,
            &REFERER_FRAGMENT_FORBIDDEN,
            &REFERER_FORBIDDEN,
        ] {
            assert_eq!(def.default_severity, Severity::Error, "{}", def.id);
        }
        assert!(REFERER_EMPTY.default_severity < REFERER_FRAGMENT_FORBIDDEN.default_severity);
    }

    /// The credential entry sits with the two that report the same octet on
    /// other fields, and the three are only consistent if they say so here.
    #[test]
    fn one_octet_on_three_fields_ranks_the_same_way_each_time() {
        assert_eq!(
            REFERER_USERINFO_FORBIDDEN.default_severity,
            crate::violations::host::HOST_USERINFO_FORBIDDEN.default_severity
        );
        assert_eq!(
            REFERER_USERINFO_FORBIDDEN.default_severity,
            crate::violations::authority::AUTHORITY_USERINFO_FORBIDDEN.default_severity
        );
    }
}
