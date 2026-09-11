// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Origin-Agent-Cluster` defects — a response header whose whole value is one
//! structured-field boolean, and the three ways a sender writes something else.
//!
//! **The first subject here that exists for a single rule.** Every other one is
//! shared: a production several fields write their values in, a field two
//! mirrored rules read from opposite ends of the exchange, a sentence nineteen
//! rules word nineteen ways. This one is read by
//! `origin_isolated_header_valid` and by nothing else, and it is written down
//! anyway — because a violation id is what an operator configures, and an
//! operator configures a *defect in the traffic*, not the internal arrangement
//! of the crate that noticed it.
//!
//! **The subject is the field, and this field is the argument for that.** The
//! rule is named `origin_isolated_header_valid`, after the `Origin-Isolation`
//! proposal that never shipped; the header browsers honour is
//! `Origin-Agent-Cluster`. An id built from the rule would make an operator
//! silence a defect under the name of a header that does not exist, and would
//! move the day the rule is renamed or absorbed — neither of which is a fact
//! about the traffic. So the ids here name the field, exactly as
//! `docs/development.md` says and for the reason it gives, and the long tail of
//! rules whose findings are their own document's statements needs no new kind
//! of subject: it needs the field spelled out.
//!
//! **What HTML asks of the value, in one sentence and one consequence.** The
//! value must be a boolean, which is an Item and not a List; and any value that
//! is not the true value `?1` is ignored. The first is a grammar, so writing a
//! list or writing nothing breaks it. The second is not — `?0` is a perfectly
//! well-formed boolean — which is why the entry for it is `_invalid` rather
//! than `_malformed`, and why this crate reports something the specification
//! is content to drop on the floor: a server that wrote `?0` or `unsafe-none`
//! meant to ask for something, and is not getting it.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// Where the header is defined, what it requests, and the two sentences the
/// entries below enforce.
pub const HTML_7_1_2: SpecRef = SpecRef {
    spec: "HTML",
    section: Some("7.1.2"),
    url: "https://html.spec.whatwg.org/multipage/browsers.html#origin-keyed-agent-clusters",
    note: "`Origin-Agent-Cluster` — a structured-header boolean; only the `?1` true value requests an origin-keyed agent cluster",
};

defects! {
    /// The header is written and no boolean is written on it: an empty value,
    /// or one made of nothing but the commas of a list.
    ///
    /// Separated from the value that is merely not `?1` because the senders
    /// differ and so does the fix. A `?0` is a server stating a preference this
    /// crate disagrees with; an empty value is a server that meant to state one
    /// and emitted nothing — a template that expanded to nothing, or a proxy
    /// that dropped the value and kept the line.
    ///
    // cite(HTML § 7.1.2, label: Origin-Agent-Cluster is a boolean): "This header is a structured header whose value must be a boolean."
    ORIGIN_AGENT_CLUSTER_EMPTY = {
        id: "origin_agent_cluster_empty",
        title: "Origin-Agent-Cluster is written with no boolean on it",
        message: "Origin-Agent-Cluster is written with no value",
        default_severity: Severity::Warn,
        spec: &[HTML_7_1_2],
    }

    /// More than one member on the line, where the field's value is a single
    /// Item. `?1, ?1` is a List, and a List is not a boolean however true each
    /// of its members is — so this is the grammar being broken rather than a
    /// preference being refused, and a recipient has no sentence telling it
    /// which member to read.
    ///
    // cite(HTML § 7.1.2, label: Origin-Agent-Cluster is a boolean): "This header is a structured header whose value must be a boolean."
    ORIGIN_AGENT_CLUSTER_MALFORMED = {
        id: "origin_agent_cluster_malformed",
        title: "Origin-Agent-Cluster carries a list where a boolean is due",
        message: "Origin-Agent-Cluster must be a single value",
        default_severity: Severity::Warn,
        spec: &[HTML_7_1_2],
    }

    /// One value, and it is not the true value. `?1` is what requests an
    /// origin-keyed agent cluster; `?0`, `1`, `true` and `unsafe-none` are each
    /// a value the processing model ignores.
    ///
    /// **The document ignores it and this catalogue reports it**, which is a
    /// deliberate step past what is quoted below: nothing is broken for the
    /// recipient, since ignoring is exactly what it is told to do. What is
    /// broken is the sender's intent — the header has one use, and a value that
    /// is not `?1` puts it to none.
    ///
    // cite(HTML § 7.1.2): "values that are not the structured header boolean true value (i.e., `?1`) will be ignored."
    ORIGIN_AGENT_CLUSTER_INVALID = {
        id: "origin_agent_cluster_invalid",
        title: "Origin-Agent-Cluster states a value that is not `?1`",
        message: "",
        default_severity: Severity::Warn,
        spec: &[HTML_7_1_2],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The subject is the field and not the rule, and the ids say so — a rule
    /// named for a proposal that never shipped reports defects named for the
    /// header that did.
    #[test]
    fn every_id_names_the_field_rather_than_the_rule_that_reads_it() {
        for def in [
            &ORIGIN_AGENT_CLUSTER_EMPTY,
            &ORIGIN_AGENT_CLUSTER_MALFORMED,
            &ORIGIN_AGENT_CLUSTER_INVALID,
        ] {
            assert!(
                def.id.starts_with("origin_agent_cluster_"),
                "{} is not spelled for the field",
                def.id,
            );
            assert!(
                !def.id.contains("isolated"),
                "{} is spelled for the rule",
                def.id,
            );
        }
    }

    /// The grammar half carries its whole message and the preference half does
    /// not: `?0` is reported with the value in hand, because the operator's
    /// next question is which value arrived.
    #[test]
    fn only_the_entry_naming_a_value_leaves_its_message_to_the_site() {
        assert!(!ORIGIN_AGENT_CLUSTER_EMPTY.message.is_empty());
        assert!(!ORIGIN_AGENT_CLUSTER_MALFORMED.message.is_empty());
        assert!(ORIGIN_AGENT_CLUSTER_INVALID.message.is_empty());
    }
}
