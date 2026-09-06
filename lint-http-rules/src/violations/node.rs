// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Node identifier defects — RFC 7239 §6's `node`, in both of its spellings.
//!
//! A `Forwarded` `for=` or `by=` value *is* a node identifier by §5.1 and §5.2,
//! and an `X-Forwarded-For` or `X-Forwarded-By` element *becomes* one by §7.4's
//! conversion. Two fields, two rules, one production — so the defects are named
//! after the production and neither field's name appears in an id.
//!
//! Six of the seven entries are the production failing: the four `nodename`
//! alternatives, the value that is none of them, and the `node-port` after the
//! colon. The seventh is not a grammar failure at all — the address parses, and
//! only its spelling is discouraged — which is why it defaults a level below
//! every other entry here.

use crate::helpers::forwarded_node::NodeDefect;
use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::{defects, ViolationDef};

/// The identifier itself: the four alternatives a nodename takes, and the
/// optional port after them. Both fields that carry one reach this section —
/// `Forwarded` through §5.1 and §5.2, the legacy family through §7.4 — so the
/// note names the production rather than either caller.
pub const RFC_7239_6: SpecRef = SpecRef {
    spec: "RFC 7239",
    section: Some("6"),
    url: "https://www.rfc-editor.org/rfc/rfc7239.html#section-6",
    note: "`node` — an IPv4 address, a bracketed IPv6 address, `unknown` or an obfuscated identifier, each optionally followed by a `node-port`",
};

/// The two things said about the IPv6 address inside a node identifier, both of
/// them about how it is *written* rather than which address it is: the brackets
/// it always wears, and the representation RFC 5952 recommends for it.
pub const RFC_7239_6_1: SpecRef = SpecRef {
    spec: "RFC 7239",
    section: Some("6.1"),
    url: "https://www.rfc-editor.org/rfc/rfc7239.html#section-6.1",
    note: "How an `IPv6address` is spelled in a node identifier: always in square brackets, and following RFC 5952's textual representation recommendations",
};

defects! {
    /// An IPv6 address written with no brackets around it at all, where the
    /// spelling being read requires them. Asked of the whole value before it is
    /// split, because every colon in such an address looks like the one that
    /// opens a `node-port`.
    ///
    /// Reported for a `Forwarded` node and never for the legacy family, where
    /// §7.4 records the unbracketed form as the conforming one.
    ///
    // cite(RFC 7239 § 6.1): "Also, note that an IPv6 address is always enclosed in square brackets."
    NODE_IPV6_BRACKETS_MISSING = {
        id: "node_ipv6_brackets_missing",
        title: "Node identifier holds an IPv6 address without its square brackets",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_7239_6_1),
    }

    /// A `[`-led nodename that never closes. Told apart from a literal whose
    /// contents are not an address because the fix differs: this value was cut
    /// or joined, that one names something that is not an IPv6 address.
    ///
    // cite(RFC 7239 § 6, label: nodename grammar): "nodename = IPv4address / "[" IPv6address "]" / "unknown" / obfnode"
    NODE_IPV6_CLOSING_BRACKET_MISSING = {
        id: "node_ipv6_closing_bracket_missing",
        title: "Node identifier opens an IPv6 literal and never closes it",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_7239_6),
    }

    /// Brackets around something that is not an `IPv6address`. The brackets are
    /// what choose this alternative of the production, so what they hold is
    /// measured against that address grammar and nothing else.
    ///
    // cite(RFC 7239 § 6, label: nodename grammar): "nodename = IPv4address / "[" IPv6address "]" / "unknown" / obfnode"
    NODE_IPV6_ADDRESS_MALFORMED = {
        id: "node_ipv6_address_malformed",
        title: "Node identifier brackets something that is not an IPv6 address",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_7239_6),
    }

    /// Digits and dots that are not an `IPv4address` — `010.1.2.3`, `1.2.3`,
    /// `256.0.0.1`. Kept apart from the catch-all below because the value said
    /// which alternative it was trying to be.
    ///
    // cite(RFC 7239 § 6, label: nodename grammar): "nodename = IPv4address / "[" IPv6address "]" / "unknown" / obfnode"
    NODE_IPV4_ADDRESS_MALFORMED = {
        id: "node_ipv4_address_malformed",
        title: "Node identifier is digits and dots that are not an IPv4 address",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_7239_6),
    }

    /// A nodename no alternative of the production generates. The everyday
    /// shape behind it is an identifier that was obfuscated without the leading
    /// underscore that says so, which is what §6.3 requires to distinguish one.
    ///
    // cite(RFC 7239 § 6, label: nodename grammar): "nodename = IPv4address / "[" IPv6address "]" / "unknown" / obfnode"
    NODE_MALFORMED = {
        id: "node_malformed",
        title: "Node identifier derives from no alternative of the production",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_7239_6),
    }

    /// A well-formed `IPv6address` written against §6.1's recommendation —
    /// uppercase hexadecimal, or zeroes left uncompressed. `info`, and the only
    /// entry in this subject below `warn`: the address is the address the sender
    /// meant, the octets are not in dispute, and a SHOULD about how they are
    /// spelled does not outrank a value that has no parse at all.
    ///
    // cite(RFC 7239 § 6.1): "The "IPv6address" SHOULD comply with textual representation recommendations [RFC5952] (for example, lowercase, compression of zeros)."
    NODE_IPV6_REPRESENTATION_INVALID = {
        id: "node_ipv6_representation_invalid",
        title: "Node identifier writes an IPv6 address outside the recommended representation",
        message: "",
        default_severity: Severity::Info,
        spec: Some(RFC_7239_6_1),
    }

    /// Something after the `:` that is neither `1*5DIGIT` nor an `obfport`.
    /// The numeric form is five digits and no range: the port namespace a
    /// transport registers in is a different sentence than this one.
    ///
    // cite(RFC 7239 § 6, label: node-port grammar): "node-port     = port / obfport port          = 1*5DIGIT obfport       = "_" 1*(ALPHA / DIGIT / "." / "_" / "-")"
    NODE_PORT_MALFORMED = {
        id: "node_port_malformed",
        title: "Node identifier holds something that is not a node-port",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_7239_6),
    }
}

/// The defect a parsed [`NodeDefect`] reports as.
///
/// Exhaustive, so a variant added to the helper does not compile until it is
/// named here — and one-to-one, because the seven ways a node identifier fails
/// are seven different fixes.
pub fn node_defect(defect: NodeDefect<'_>) -> &'static ViolationDef {
    match defect {
        NodeDefect::UnbracketedIpv6(_) => &NODE_IPV6_BRACKETS_MISSING,
        NodeDefect::UnclosedBrackets(_) => &NODE_IPV6_CLOSING_BRACKET_MISSING,
        NodeDefect::NotIpv6(_) => &NODE_IPV6_ADDRESS_MALFORMED,
        NodeDefect::NotIpv4(_) => &NODE_IPV4_ADDRESS_MALFORMED,
        NodeDefect::NotANode { .. } => &NODE_MALFORMED,
        NodeDefect::TextualRepresentation { .. } => &NODE_IPV6_REPRESENTATION_INVALID,
        NodeDefect::NodePort(_) => &NODE_PORT_MALFORMED,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::forwarded_node::NodeForm;

    /// Seven variants, seven ids: nothing here answers with a def another
    /// subject owns, and nothing collapses two variants into one entry.
    #[test]
    fn each_node_defect_maps_to_its_own_id() {
        for (defect, id) in [
            (
                NodeDefect::UnbracketedIpv6("2001:db8::1"),
                "node_ipv6_brackets_missing",
            ),
            (
                NodeDefect::UnclosedBrackets("[::1"),
                "node_ipv6_closing_bracket_missing",
            ),
            (NodeDefect::NotIpv6("nope"), "node_ipv6_address_malformed"),
            (
                NodeDefect::NotIpv4("010.1.2.3"),
                "node_ipv4_address_malformed",
            ),
            (
                NodeDefect::NotANode {
                    nodename: "x-foo",
                    form: NodeForm::XForwarded,
                },
                "node_malformed",
            ),
            (
                NodeDefect::TextualRepresentation {
                    written: "2001:DB8::1",
                    recommended: "2001:db8::1".parse().expect("an IPv6 address"),
                },
                "node_ipv6_representation_invalid",
            ),
            (NodeDefect::NodePort("999999"), "node_port_malformed"),
        ] {
            assert_eq!(node_defect(defect).id, id);
        }
    }

    /// The spelling recommendation is the one entry here that is not a grammar
    /// failure, and the severities say so. This is the whole reason the subject
    /// is worth splitting out of the rule: one `ctx.severity` reported an
    /// address a recipient can act on at the same level as one nothing
    /// generates.
    #[test]
    fn the_recommended_representation_sits_below_the_grammar() {
        assert_eq!(
            NODE_IPV6_REPRESENTATION_INVALID.default_severity,
            Severity::Info
        );
        for def in [
            &NODE_IPV6_BRACKETS_MISSING,
            &NODE_IPV6_CLOSING_BRACKET_MISSING,
            &NODE_IPV6_ADDRESS_MALFORMED,
            &NODE_IPV4_ADDRESS_MALFORMED,
            &NODE_MALFORMED,
            &NODE_PORT_MALFORMED,
        ] {
            assert!(
                def.default_severity > NODE_IPV6_REPRESENTATION_INVALID.default_severity,
                "{} defaults at or below the spelling recommendation",
                def.id,
            );
        }
    }
}
