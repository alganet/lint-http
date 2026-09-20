// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `P3P` defects — the compact privacy policy a response still advertises.
//!
//! **The specification records its own obsolescence, which is what makes this
//! the rare `_obsolete` entry cited to the document it is about.** P3P 1.0
//! became a W3C Recommendation in April 2002 and was obsoleted on 30 August
//! 2018; the document at that URL is the obsoletion notice, and its Status
//! section says in as many words that it *"is obsolete and should no longer be
//! used as a basis for implementation"*. Contrast
//! [`report_to`](crate::violations::report_to), where the withdrawing body left
//! no sentence behind at all and MDN's page had to carry the fact, and
//! [`x_xss_protection`](crate::violations::x_xss_protection), where no
//! standards body ever wrote the field down. Here the field's own
//! specification is the evidence.
//!
//! **What the field did, and why nothing reads it now.** § 2.2.2 defines the
//! `P3P` response header as the place a site points at its policy reference
//! file and, through the `compact-policy-field`, states a performance-optimised
//! summary of its privacy practices. One user agent ever acted on it: Internet
//! Explorer used the presence of a compact policy as a gate on third-party
//! cookies. Internet Explorer is gone, so the field is read by nothing and the
//! header is the only thing left of the deployment that configured it.
//!
//! **The Status section also describes what the values in the wild look like,
//! which is why this entry does not grade them.** W3C's own account of why P3P
//! failed is that *"web site administrators chose to copy general policies
//! rather than encode specific policies that reflected their sites' own privacy
//! practices"* — so a compact policy on the wire is evidence about a copied
//! template rather than about a site's practices, and measuring one against
//! § 4's vocabulary would report the template's author. One entry, about the
//! field, and no second one about its value.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// The obsoletion notice: the document's own Status section, and W3C's account
/// of why the field is not worth implementing.
pub const P3P_STATUS: SpecRef = SpecRef {
    spec: "P3P",
    section: None,
    url: "https://www.w3.org/TR/P3P/",
    note: "The Platform for Privacy Preferences 1.0 — a W3C Recommendation of April 2002, obsoleted 30 August 2018. Its Status section states that the specification is obsolete and should no longer be used as a basis for implementation, that P3P never saw sufficient ecosystem uptake, and that what deployments actually sent were general policies copied rather than encoded — which is why this catalogue reads the field's presence and not its value",
};

/// § 2.2.2, the field itself: what a `P3P` header carries and what the compact
/// policy in it is for.
pub const P3P_2_2_2: SpecRef = SpecRef {
    spec: "P3P",
    section: Some("2.2.2"),
    url: "https://www.w3.org/TR/P3P/#syntax_ext",
    note: "The P3P response header: the `policyref` pointing at a policy reference file and the `compact-policy-field` carrying a compact policy, which is the half a user agent was expected to act on without a second request",
};

defects! {
    /// A response carrying a `P3P` header field.
    ///
    /// **`_obsolete` for the reason the ending exists**: a later act of the
    /// body that specified the field withdrew it. This is
    /// [`pragma_obsolete`](crate::violations::pragma)'s shape with a stronger
    /// document behind it — `Pragma` is deprecated by a paragraph inside the
    /// specification that still defines it, and P3P's whole specification is
    /// marked obsolete on its title line.
    ///
    /// **Not `_forbidden`, and the repair really is a deletion.** Nothing
    /// prohibits sending the field; what has changed is that no user agent
    /// reads it. Unlike `Report-To`, whose group names other fields point at,
    /// a compact policy is named by nothing else in the message, so there is
    /// no move to make and nothing downstream to keep working.
    ///
    /// `info`. The message is not wrong, no recipient behaves differently, and
    /// the cost is a field on every response that no longer buys the cookie
    /// acceptance it was deployed for. [`Strength::Unstated`](crate::lint::Strength::Unstated) because the
    /// sentence that settles it is a status note about a document rather than a
    /// requirement addressed to a sender: obsolescence is not a prohibition.
    ///
    // cite(P3P): "This specification is obsolete and should no longer be used as a basis for implementation."
    // cite(P3P): "web site administrators chose to copy general policies rather than encode specific policies that reflected their sites' own privacy practices"
    // cite(P3P § 2.2.2): "The compact-policy-field is used to specify"
    P3P_OBSOLETE = {
        id: "p3p_obsolete",
        title: "A response advertises a privacy policy in a field whose specification is obsolete",
        message: "",
        default_severity: Severity::Info,
        spec: &[P3P_STATUS, P3P_2_2_2],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The entry claims a withdrawal and not a violation, so it may not be
    /// spelled as a prohibition and may not outrank advice.
    #[test]
    fn the_entry_claims_no_prohibition() {
        assert!(P3P_OBSOLETE.id.ends_with("_obsolete"));
        assert_eq!(P3P_OBSOLETE.default_severity, Severity::Info);
    }

    /// The evidence is the field's own specification rather than a third party
    /// describing it, which is the whole difference from `report_to_obsolete`.
    /// Both references must be the P3P document itself.
    #[test]
    fn the_evidence_is_the_fields_own_specification() {
        assert!(!P3P_OBSOLETE.spec.is_empty());
        assert!(P3P_OBSOLETE.spec.iter().all(|s| s.spec == "P3P"));
        assert!(P3P_OBSOLETE
            .spec
            .iter()
            .all(|s| s.url.starts_with("https://www.w3.org/TR/P3P/")));
    }

    /// The entry is about the field and not about a value, so it carries no
    /// static message: what a finding says is the header the response wrote,
    /// which only the reading knows.
    #[test]
    fn the_entry_names_no_value_statically() {
        assert!(P3P_OBSOLETE.message.is_empty());
    }
}
