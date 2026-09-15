// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Permissions-Policy defects — what the Permissions Policy specification says
//! about a Dictionary that RFC 9651 has already parsed.
//!
//! A field subject on top of a production one, the shape
//! [`priority`](crate::violations::priority) has: everything about *writing* a
//! Dictionary belongs to RFC 9651 and answers to
//! [`structured_fields`](crate::violations::structured_fields), and what is left
//! for § 5.2 to state is what a member's value may be and what its one defined
//! parameter must carry.
//!
//! **Nothing here is invalid and nothing here is forbidden.** Both documents
//! define *ignore* semantics, at two scopes: a Structured Fields parse failure
//! discards the whole field, and a member that parses and is then refused for
//! its form costs one directive. The first scope is the production subject's
//! entirely — one stray capital in a feature name is the same defect wherever
//! it is written — so what is left here is the second.
//!
//! **The member names are not here either.** § 5.1 has an HTML-attribute
//! serialization with a `feature-identifier` grammar of its own, and § 5.2 —
//! the header — makes a member name an ordinary Structured Fields key. A name
//! this crate does not recognise is not a defect at all: § 5.2 ignores a member
//! naming no supported feature, and RFC 9651 § 3.2 has recipients ignore
//! unknown keys, so an entry for one would report the extension mechanism.
//
// cite(Permissions Policy § 5.2): "The Member Names must be Tokens."

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// The header's serialization: the Dictionary, the four shapes a Member Value
/// may take, the one parameter that is defined, and what becomes of anything
/// else.
///
/// No section number on purpose: this is an editor's draft, and an editor's
/// draft renumbers.
pub const PERMISSIONS_POLICY_5_2: SpecRef = SpecRef {
    spec: "Permissions Policy",
    section: None,
    url: "https://w3c.github.io/webappsec-permissions-policy/#structured-header-serialization",
    note: "§5.2 Structured header serialization — the production this subject answers for. Not §5.1, which is the HTML attribute and has a feature-identifier grammar of its own",
};

defects! {
    /// A Member Value that parses as a Structured Field and is none of the four
    /// shapes an allowlist may take: `geolocation=SELF`, `camera=?1`,
    /// `payment=3`, `fullscreen=:YWJj:`, or a bare `geolocation` with no value.
    ///
    /// **One entry, because § 5.2 refuses them in one sentence and with one
    /// outcome.** Its list of permitted Member Values is closed — a String, the
    /// Token `*`, the Token `self`, or an Inner List of those — and everything
    /// outside it is "any other form", which costs the member and nothing else.
    /// The message names what was written.
    ///
    /// **A bare member belongs here rather than in an `_empty` of its own**,
    /// which is the reading [`priority_urgency_malformed`](crate::violations::priority)
    /// reached from the other side: RFC 9651 § 4.2.2 makes a member with no `=`
    /// the Boolean true, so nothing is missing and nothing is blank — a Boolean
    /// is simply one of the other forms.
    ///
    /// **`SELF` is one of these and it is the case worth knowing**, because it
    /// is the one a working-looking deployment produces. § 5.2 names two
    /// *Tokens*, and RFC 9651 § 4.2.6 consumes a Token's characters unchanged —
    /// nothing anywhere folds one — so `SELF` is a different Token from `self`
    /// and a browser drops the directive. Compare § 3.2, which says outright
    /// that member *keys* have no uppercase in them: the specification
    /// distinguishes the two cases, and a reader that folds them calls this
    /// conforming.
    ///
    /// `_invalid` rather than `_malformed`: the value derives from a perfectly
    /// good Structured Fields production, and what refuses it is the closed
    /// list § 5.2 writes past the grammar.
    ///
    /// `warn`. What it costs is one directive out of a policy that is otherwise
    /// enforced, which is less than the whole field a parse failure takes — and
    /// what that directive was doing was refusing a browser permission, so it
    /// is not `info` either.
    ///
    // cite(Permissions Policy § 5.2): "Member Values of any other form will cause the entire Dictionary Member to be ignored by the processing steps."
    PERMISSIONS_POLICY_ALLOWLIST_INVALID = {
        id: "permissions_policy_allowlist_invalid",
        title: "A directive's allowlist is none of the permitted forms",
        message: "",
        default_severity: Severity::Warn,
        spec: &[PERMISSIONS_POLICY_5_2],
    }

    /// A `report-to` parameter whose value is not a String:
    /// `geolocation=(self);report-to=endpoint`.
    ///
    /// **What this costs is the reporting and not the directive**, which is the
    /// one place in this field where the two scopes § 5.2 defines are both too
    /// wide. The field still parses, so nothing is discarded; and the policy
    /// construction algorithm reads the parameter only *if* it "exists, and is
    /// a string", so a Token there is skipped and the allowlist beside it is
    /// applied exactly as written. What the sender loses is the endpoint the
    /// violations were meant to be reported to — silently, since nothing else
    /// in the field marks it.
    ///
    /// **The only parameter with an entry**, because it is the only one § 5.2
    /// defines: everything else after the `;` is a parameter the field says
    /// nothing about, and what is left to ask of one is the Structured Fields
    /// question its key and its value already answer to.
    ///
    /// `_malformed`: § 5.2 names a type, and a Token derives from a different
    /// production than a String does — the same reading
    /// [`priority_incremental_malformed`](crate::violations::priority) makes of
    /// a parameter defined as a Boolean.
    ///
    /// `info`. The permission is enforced as the sender wrote it; what is lost
    /// is telemetry about the times it bites.
    ///
    // cite(Permissions Policy § 5.2): "Member Values may have a Parameter named "report-to", whose value must be a String."
    PERMISSIONS_POLICY_REPORT_TO_MALFORMED = {
        id: "permissions_policy_report_to_malformed",
        title: "A directive's report-to parameter is not a String",
        message: "",
        default_severity: Severity::Info,
        spec: &[PERMISSIONS_POLICY_5_2],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two entries differ in what a browser does about them, and the ranks
    /// say so: one loses a permission decision, the other loses a report.
    #[test]
    fn the_ranks_follow_what_is_lost() {
        assert_eq!(
            PERMISSIONS_POLICY_ALLOWLIST_INVALID.default_severity,
            Severity::Warn
        );
        assert_eq!(
            PERMISSIONS_POLICY_REPORT_TO_MALFORMED.default_severity,
            Severity::Info
        );
    }
}
