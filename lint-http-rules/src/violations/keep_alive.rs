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
//! **The rest of the subject is the field's own grammar, and none of it could
//! be borrowed.** `keepalive-param = param-name "=" value` is RFC 2068's
//! production and not RFC 9110 § 5.6.6's `parameters`, so the two absences a
//! [`parameter`](crate::violations::parameter) already names — the missing `=`
//! and the value that is not there — are written again here rather than taken.
//! Same words, different document, different production: borrowing either would
//! put § 5.6.6's sentence behind a member that does not derive from it, which is
//! the line [`sec_websocket_extensions`](crate::violations::sec_websocket_extensions)
//! drew for the same shape.
//!
//! **What could be borrowed was**: the `timeout` parameter's value is a
//! `delta-seconds` and its octets answer to
//! [`delta_seconds`](crate::violations::delta_seconds), which named this field
//! as one of its four readers before it had a declarer here.
//!
//! **One entry carries no sentence, and it is the deployment's rather than any
//! document's**: nothing published states a maximum for `timeout`, so the bound
//! is configured and the finding says which number it exceeded rather than
//! advising a smaller one.

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

/// Where this document writes the `value` half of a parameter — the same pair
/// RFC 9110 § 5.6.2 and § 5.6.4 write, in the document that defines the field.
pub const RFC_2068_3_7: SpecRef = SpecRef {
    spec: "RFC 2068",
    section: Some("3.7"),
    url: "https://www.rfc-editor.org/rfc/rfc2068.html#section-3.7",
    note: "`value = token | quoted-string`, the right-hand half of `keepalive-param`. \
           The rule name is defined once for the document and `keepalive-param` uses \
           it, which is why a parameter value may be quoted at all",
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

    /// A member with no `"="` in it at all. The production writes the delimiter
    /// and the value into itself, so a bare name derives from nothing — and the
    /// field's own section says HTTP/1.1 defines no parameters, which leaves a
    /// recipient no way to guess what a nameless one meant.
    ///
    /// **The expired draft would have allowed it**, writing
    /// `keep-alive-extension = token [ "=" ( token / quoted-string ) ]` with the
    /// value bracketed. The document in force is not that one, and a finding
    /// naming which reading it comes from is what keeps the difference visible
    /// rather than silently picked.
    ///
    // cite(RFC 2068 § 19.7.1.1, label: keepalive-param): "keepalive-param = param-name "=" value"
    KEEP_ALIVE_PARAMETER_EQUALS_MISSING = {
        id: "keep_alive_parameter_equals_missing",
        title: "Keep-Alive writes a parameter with no '=' and no value",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_2068_19_7_1_1],
    }

    /// A member that begins with its `"="`, so it names no parameter: the
    /// production puts a `param-name` before the delimiter, and there is nothing
    /// there.
    ///
    /// **`param-name` is used and never defined**, which is why this entry is
    /// about its absence and there is none about its spelling. The document
    /// writes the name into the production and gives it no grammar of its own,
    /// so a name that *is* written cannot be measured against anything — and a
    /// linter that measured it against `token` anyway would be enforcing a
    /// production the field does not use.
    ///
    // cite(RFC 2068 § 19.7.1.1, label: keepalive-param): "keepalive-param = param-name "=" value"
    KEEP_ALIVE_PARAMETER_NAME_MISSING = {
        id: "keep_alive_parameter_name_missing",
        title: "Keep-Alive writes a parameter that names nothing before its '='",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_2068_19_7_1_1],
    }

    /// A member ending on its `"="`. Neither alternative of `value = token |
    /// quoted-string` derives the empty string — a `token` is `1*<any CHAR
    /// except CTLs or tspecials>` and the shortest `quoted-string` is its two
    /// DQUOTEs — so the delimiter was written and nothing the grammar can
    /// generate followed it.
    ///
    /// **The catalogue declines this verdict in general and answers it per
    /// production**, which is why the entry is here rather than shared: six
    /// fields settled an empty `word` four ways and two tolerate it outright, so
    /// the reader returns the verdict unnamed and each production says what it
    /// means. This one has no sentence tolerating it.
    ///
    // cite(RFC 2068 § 3.7, label: keepalive value): "value          = token | quoted-string"
    KEEP_ALIVE_PARAMETER_VALUE_EMPTY = {
        id: "keep_alive_parameter_value_empty",
        title: "Keep-Alive writes a parameter '=' with no value after it",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_2068_3_7],
    }

    /// A `timeout` larger than the maximum this deployment configured.
    ///
    /// **Uncited, and the reason is a third one this catalogue had not written
    /// down.** The two entries that carry no reference today are uncited because
    /// no sentence states them and because a limit is this crate's own; this one
    /// is uncited because the limit is *an operator's*. No document states a
    /// maximum for `timeout` — the draft that named the parameter gives it an
    /// integer in seconds and no ceiling — so the bound comes from
    /// configuration, and a reference here would dress a deployment's policy as
    /// a requirement.
    ///
    /// `_invalid` rather than `_forbidden`: the value derives from its grammar
    /// and what it fails is a judgement past it. The finding names the
    /// configured number instead of advising a smaller one, because which number
    /// is right is exactly what no document answers.
    ///
    /// `warn`, with the rest of the subject. A recipient reads the field, keeps
    /// the connection open for as long as it is willing to, and the timeout is
    /// advisory in both directions — what an operator is being told is that a
    /// peer is asking for far more than this deployment expects.
    KEEP_ALIVE_TIMEOUT_INVALID = {
        id: "keep_alive_timeout_invalid",
        title: "Keep-Alive asks for a timeout above the configured maximum",
        message: "",
        default_severity: Severity::Warn,
        spec: &[],
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
