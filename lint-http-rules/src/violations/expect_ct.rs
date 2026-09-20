// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Expect-CT` defects — the Certificate Transparency policy a response still
//! asks for.
//!
//! **The specification is in force and the field is dead anyway, which is a
//! third footing and not either of the two this catalogue already had.** RFC
//! 9163 defines `Expect-CT` and nothing has superseded it, so unlike
//! [`report_to`](crate::violations::report_to) there is a current document to
//! read the field against, and unlike
//! [`x_xss_protection`](crate::violations::x_xss_protection) it was written
//! down by a standards body. What withdrew the field was the only
//! implementation of it: Chromium removed the header in version 107 because it
//! now enforces Certificate Transparency for every certificate, so the opt-in
//! the field expresses is both unread and unnecessary. That is a fact about
//! deployment, which an RFC does not revise itself to carry — so the sentence
//! recording it is MDN's, and IANA's registry agrees by listing the name
//! `deprecated`.
//!
//! **Why the field is not merely quiet but pointless.** The header asked a
//! browser to check that certificates for the site appear in public CT logs.
//! Since May 2018 every new publicly-trusted certificate carries signed
//! certificate timestamps by default, and the last certificates that predate
//! that requirement expired in June 2021 — so there is no certificate left for
//! the check to fail on. An origin sending the field is asking for an
//! enforcement it would get anyway from a browser that no longer looks.
//!
//! **One entry, about the field.** RFC 9163 § 2.1 gives the value a grammar and
//! the directives it takes, but a value's defects are claims about how a dead
//! field is spelled: whether `max-age` is well-formed changes nothing for any
//! recipient, because no recipient reads the field. What an operator can act on
//! is that the line does nothing, and that is one finding.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// The one document that records what became of the field, and why.
pub const MDN_EXPECT_CT: SpecRef = SpecRef {
    spec: "MDN Expect-CT",
    section: None,
    url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Expect-CT",
    note: "Expect-CT — marked Deprecated, and the page that says why: Chromium was the only engine that implemented the header and removed it in version 107 because it now enforces Certificate Transparency by default, while the certificates that predated universal SCT support expired in June 2021, leaving nothing for the check to catch",
};

/// The specification that defines the field, and is still in force.
pub const RFC_9163_1: SpecRef = SpecRef {
    spec: "RFC 9163",
    section: Some("1"),
    url: "https://www.rfc-editor.org/rfc/rfc9163.html#section-1",
    note: "Expect-CT: the response header by which a host declares that it expects Signed Certificate Timestamps in subsequent TLS connections — the definition this catalogue reads the field's presence against, and the reason a finding names a live document rather than only a third party's account of it",
};

defects! {
    /// A response carrying an `Expect-CT` header field.
    ///
    /// **`_obsolete` rather than `_ignored`.** `_ignored` is for a directive a
    /// recipient is entitled to disregard while the field still means
    /// something; here there is no recipient left that reads the field at all,
    /// which is the same end `pragma_obsolete` and
    /// [`report_to_obsolete`](crate::violations::report_to) name.
    ///
    /// **Not `_forbidden`, and the repair is a deletion.** RFC 9163 is in force
    /// and permits the field; nothing prohibits sending it. What has changed is
    /// that the sole implementation removed it, so the line buys nothing. No
    /// other field in a message names an `Expect-CT` policy, so unlike
    /// `Report-To` there is nothing to move first.
    ///
    /// `info`. A browser that ignores the field is correct and one that never
    /// implemented it is correct; nothing is broken, and what the sender learns
    /// is that a security control it believes it has configured is not in
    /// effect anywhere. [`Strength::Unstated`](crate::lint::Strength::Unstated) because the fact is about
    /// implementations rather than about what a sender may write: RFC 9163
    /// states no requirement this reports on, and MDN states none at all.
    ///
    // cite(MDN Expect-CT): "and Chromium has deprecated the header from version 107, because Chromium now enforces CT by default"
    // cite(MDN Expect-CT): "Since May 2018, all new TLS certificates are expected to support SCTs by default."
    // cite(RFC 9163 § 1): "enables UAs to identify web hosts that expect the presence of Signed Certificate Timestamps (SCTs)"
    EXPECT_CT_OBSOLETE = {
        id: "expect_ct_obsolete",
        title: "A response asks for Certificate Transparency in a field no browser reads",
        message: "",
        default_severity: Severity::Info,
        spec: &[MDN_EXPECT_CT, RFC_9163_1],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The entry claims a withdrawal by implementations and not a violation of
    /// a live specification, so it may not be spelled as a prohibition and may
    /// not outrank advice.
    #[test]
    fn the_entry_claims_no_prohibition() {
        assert!(EXPECT_CT_OBSOLETE.id.ends_with("_obsolete"));
        assert_eq!(EXPECT_CT_OBSOLETE.default_severity, Severity::Info);
    }

    /// **The third footing, asserted rather than described.** This entry is the
    /// only `_obsolete` one whose field has both a live specification and a
    /// third party's account of its withdrawal, and it must name both: the RFC
    /// alone would say the field is fine, and MDN alone would leave a reader
    /// thinking nothing ever defined it.
    #[test]
    fn the_entry_names_the_live_specification_and_the_withdrawal() {
        assert!(EXPECT_CT_OBSOLETE.spec.iter().any(|s| s.spec == "RFC 9163"));
        assert!(EXPECT_CT_OBSOLETE
            .spec
            .iter()
            .any(|s| s.spec == "MDN Expect-CT"));
    }

    /// The entry is about the field and not about a value, so it carries no
    /// static message.
    #[test]
    fn the_entry_names_no_value_statically() {
        assert!(EXPECT_CT_OBSOLETE.message.is_empty());
    }
}
