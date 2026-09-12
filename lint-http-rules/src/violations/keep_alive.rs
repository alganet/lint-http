// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Keep-Alive` defects — a field the current specification defines by pointing
//! somewhere else.
//!
//! RFC 9110 § 7.6.1 lists this field among the connection-specific ones and
//! annotates it *Section 19.7.1 of \[RFC2068\]*, which is where the grammar and
//! the field's one requirement on a sender are written. So the sentences this
//! subject cites are a 1997 document's, and that is the document in force for
//! this field: **obsolete is not the same as superseded**, and nothing since has
//! restated what a `Keep-Alive` is.
//!
//! **The first entry is the third of a family**, and each member of it sits in
//! its own subject: a connection-specific field travels with its name written
//! as a `connection-option`, and the sentence saying so is written once per
//! field — § 7.8 for [`upgrade`](crate::violations::upgrade), § 10.1.4 for
//! [`te`](crate::violations::te), and § 19.7.1.1 here. The shape is identical
//! and the requirement is not shared, which is why one shared id would have to
//! name § 7.6.1's general wording as the sentence behind findings whose
//! evidence is a field-specific MUST.
//!
//! **What comes next in this subject is everything the field's own grammar
//! says**, and it is all still the rule's: a member written with no `=` at all,
//! a member naming no parameter, a `timeout` whose value is no `delta-seconds`,
//! and a `timeout` above the bound an operator configured — the last of which
//! will be uncited, since nothing published states a maximum and the bound is a
//! deployment's policy.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// The field's definition: the grammar, the sentence saying HTTP/1.1 defines no
/// parameters for it, and the one requirement on a sender that this subject's
/// first entry carries.
pub const RFC_2068_19_7_1_1: SpecRef = SpecRef {
    spec: "RFC 2068",
    section: Some("19.7.1.1"),
    url: "https://www.rfc-editor.org/rfc/rfc2068.html#section-19.7.1.1",
    note: "The `Keep-Alive` grammar, the sentence saying HTTP/1.1 defines no \
           parameters for it, and the field's one requirement on a sender — the \
           matching connection token. Obsoleted, and still the document RFC 9110 \
           §7.6.1 names for this field, so this is where the productions are read \
           from. The reference here used to be RFC 7230 §6.7, which is `Upgrade`",
};

defects! {
    /// A message carrying `Keep-Alive` with no `keep-alive` connection-option
    /// in `Connection`. The field describes the connection it is sent on and
    /// nothing further; the option is what stops an intermediary from relaying
    /// a timeout that belongs to a hop the recipient is not on.
    ///
    /// **One entry for both shapes of the absence**, the line
    /// [`upgrade_connection_option_missing`](crate::violations::upgrade) drew:
    /// a `Connection` naming other options and a message with no `Connection`
    /// at all are one missing name, and the site's message is where the two
    /// part company.
    ///
    /// **Asked only of HTTP/1.x**, which is the reading of the rule reporting
    /// it: HTTP/2 and HTTP/3 forbid both fields outright, so asking for the
    /// option there would be asking a sender to make its own message malformed.
    ///
    /// `warn`, with the two siblings: nothing about the message is unreadable,
    /// and a guard that was not set risks a *later* hop being misled — which no
    /// recipient of this message can detect.
    ///
    // cite(RFC 2068 § 19.7.1.1): "If the Keep-Alive header is sent, the corresponding connection token MUST be transmitted."
    KEEP_ALIVE_CONNECTION_OPTION_MISSING = {
        id: "keep_alive_connection_option_missing",
        title: "Keep-Alive is sent with no keep-alive connection-option in Connection",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_2068_19_7_1_1],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::violations::te::TE_CONNECTION_OPTION_MISSING;
    use crate::violations::upgrade::UPGRADE_CONNECTION_OPTION_MISSING;

    /// Three fields, one shape, three ids — and one rank, because what an
    /// operator is being told is the same thing about a different name. The ids
    /// differ because the sentences do; the rank does not, because the
    /// consequence does not.
    #[test]
    fn the_family_ranks_together_and_cites_apart() {
        for def in [
            &KEEP_ALIVE_CONNECTION_OPTION_MISSING,
            &TE_CONNECTION_OPTION_MISSING,
            &UPGRADE_CONNECTION_OPTION_MISSING,
        ] {
            assert_eq!(def.default_severity, Severity::Warn, "{}", def.id);
            assert_eq!(def.spec.len(), 1, "{}", def.id);
        }
        let sections: Vec<_> = [
            &KEEP_ALIVE_CONNECTION_OPTION_MISSING,
            &TE_CONNECTION_OPTION_MISSING,
            &UPGRADE_CONNECTION_OPTION_MISSING,
        ]
        .iter()
        .map(|def| def.spec[0].section)
        .collect();
        assert_eq!(
            sections.len(),
            sections
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            "no two of the family enforce one sentence"
        );
    }
}
