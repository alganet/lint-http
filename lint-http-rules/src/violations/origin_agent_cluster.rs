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
//! list, writing nothing, or writing something a boolean's production does not
//! admit breaks it. The second is not — `?0` is a perfectly well-formed
//! boolean — which is why the entry for it is `_invalid` rather than
//! `_malformed`, and why this crate reports something the specification is
//! content to drop on the floor: a server that wrote `?0` meant to ask for
//! something, and is not getting it.
//!
//! **`unsafe-none` is not that, and used to be filed as though it were.** The
//! two entries divided the value by whether it was written once, so `?0` and
//! `unsafe-none` arrived under one id and one sentence calling each of them
//! invalid — while RFC 9651 § 4.2.8 admits exactly two strings and `?0` is one
//! of them. The line falls between a boolean the sender wrote false and a value
//! whose parse never reaches a boolean at all: the first is a preference the
//! document declines to honour, the second is a field a recipient cannot read.

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

    /// What is written on the line is not a boolean, in either of the two ways
    /// that can happen. `?1, ?1` is a List, and a List is not a boolean however
    /// true each of its members is; `unsafe-none` is one Item and the boolean's
    /// production never admits it. Both are the grammar being broken rather
    /// than a preference being refused, and in both a recipient is left with a
    /// field it has no sentence for — which member to read, or what value it
    /// read at all.
    ///
    /// The message is the site's, because the operator's next question is which
    /// value arrived and the two shapes answer it differently.
    ///
    // cite(HTML § 7.1.2, label: Origin-Agent-Cluster is a boolean): "This header is a structured header whose value must be a boolean."
    ORIGIN_AGENT_CLUSTER_MALFORMED = {
        id: "origin_agent_cluster_malformed",
        title: "Origin-Agent-Cluster carries something that is not a boolean",
        message: "",
        default_severity: Severity::Warn,
        spec: &[HTML_7_1_2],
    }

    /// One boolean, and it is the false one. `?1` is what requests an
    /// origin-keyed agent cluster, so `?0` is a sender stating the other of the
    /// field's two values — well-formed, and asking for what an absent header
    /// already gives.
    ///
    /// **The document ignores it and this catalogue reports it**, which is a
    /// deliberate step past what is quoted below, and the finding says so
    /// rather than calling the value invalid. It is not invalid: § 4.2.8 of RFC
    /// 9651 admits `?0` beside `?1`, and three hosts in a corpus of real
    /// traffic send it — one of them on every response. What can be said is
    /// narrower and is all this entry claims: a header was written and, having
    /// been written, requests nothing that leaving it out would not.
    ///
    /// `info`, and not the `warn` this shipped as, for the same reason. A
    /// severity is what a reader is asked to do about a finding, and there is
    /// nothing to do here that is not a matter of taste — the message is
    /// legible, the recipient's behaviour is exactly the specified one, and no
    /// requirement in any document is unmet. The two entries above stay at
    /// `warn`: a field a recipient cannot read is a different thing.
    ///
    /// The message is the catalogue's rather than the site's, which reverses
    /// what this entry did before. The site formatted the value in because the
    /// entry covered four of them; one boolean is left that can reach it, so
    /// the sentence is known where the entry is written.
    ///
    // cite(HTML § 7.1.2): "values that are not the structured header boolean true value (i.e., `?1`) will be ignored."
    ORIGIN_AGENT_CLUSTER_INVALID = {
        id: "origin_agent_cluster_invalid",
        title: "Origin-Agent-Cluster states the boolean's false value",
        message: "Origin-Agent-Cluster is `?0`, the false value of the boolean it carries: well-formed, and requesting what an absent header already gives, since only `?1` asks for an origin-keyed agent cluster",
        default_severity: Severity::Info,
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

    /// An entry leaves its message to the site exactly when the value that
    /// reaches it is not known here. `_malformed` is that one — a list or a
    /// token, and the operator's next question is which — while `_empty` has
    /// nothing to quote back and `_invalid` has one boolean that can reach it.
    #[test]
    fn an_entry_leaves_its_message_to_the_site_when_the_value_is_not_known_here() {
        assert!(!ORIGIN_AGENT_CLUSTER_EMPTY.message.is_empty());
        assert!(ORIGIN_AGENT_CLUSTER_MALFORMED.message.is_empty());
        assert!(!ORIGIN_AGENT_CLUSTER_INVALID.message.is_empty());
    }

    /// The two entries about a field a recipient cannot read outrank the one
    /// about a field it reads and is told to ignore.
    #[test]
    fn a_legible_value_is_advice_and_an_illegible_one_is_a_defect() {
        assert_eq!(
            ORIGIN_AGENT_CLUSTER_INVALID.default_severity,
            Severity::Info
        );
        assert_eq!(ORIGIN_AGENT_CLUSTER_EMPTY.default_severity, Severity::Warn);
        assert_eq!(
            ORIGIN_AGENT_CLUSTER_MALFORMED.default_severity,
            Severity::Warn
        );
    }
}
