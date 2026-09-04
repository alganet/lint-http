// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! RFC 7239 §6's node identifier, and the two field families that carry one.
//!
//! `Forwarded`'s `for=` and `by=` values are node identifiers by §5.1 and §5.2.
//! The `X-Forwarded-*` family carries the same vocabulary by a different route:
//! §7.4 converts an `X-Forwarded-For` element into a `for=` value *by prepending
//! `for=`*, and names the one difference between the two spellings — the
//! brackets and quotes an IPv6 address wears inside `Forwarded` and does not wear
//! in the legacy field. Everything else about the identifier is one production,
//! which is why it is written here once rather than in each rule.

use std::net::{Ipv4Addr, Ipv6Addr};

/// Which of the two spellings of a node identifier is being read.
///
/// The variant decides two things and both come from the same pair of sentences:
/// whether an IPv6 address must wear square brackets, and — since RFC 7239 §6.1's
/// textual-representation SHOULD is written about the `IPv6address` of a
/// `Forwarded` node — whether that recommendation is asked at all.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NodeForm {
    /// A `Forwarded` `for=` / `by=` value, after quoted-string unescaping.
    Forwarded,
    /// An `X-Forwarded-For` / `X-Forwarded-By` element.
    // cite(RFC 7239 § 7.4): "Note that IPv6 addresses may not be quoted in X-Forwarded-For and may not be enclosed by square brackets, but they are quoted and enclosed in square brackets in "Forwarded"."
    XForwarded,
}

/// `obfnode` and `obfport` are one production under two names, and both of the
/// sentences below say the same two things about it: the leading underscore is
/// what distinguishes it, and the characters after it are not `tchar`'s.
///
/// Reading it as a `token` — which is what the `Forwarded` rule once did —
/// accepts `x-foo` as an obfuscated identifier. It is not one: nothing in §6
/// generates a nodename that is neither an address, nor `unknown`, nor
/// underscore-led, so `for=x-foo` has no parse at all.
///
// cite(RFC 7239 § 6, label: obfnode grammar): "obfnode = "_" 1*( ALPHA / DIGIT / "." / "_" / "-")"
// cite(RFC 7239 § 6.3): "To distinguish the obfuscated identifier from other identifiers, it MUST have a leading underscore "_". Furthermore, it MUST also consist of only "ALPHA", "DIGIT", and the characters ".", "_", and "-"."
// cite(RFC 7239 § 6): "To distinguish an "obfport" from a port, the "obfport" MUST have a leading underscore. Further, it MUST also consist of only "ALPHA", "DIGIT", and the characters ".", "_", and "-"."
pub fn is_obfuscated(s: &str) -> bool {
    let Some(rest) = s.strip_prefix('_') else {
        return false;
    };
    !rest.is_empty()
        && rest
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// Where the nodename ends and `":" node-port` begins.
///
/// The first colon settles it, not the last: no `nodename` alternative holds a
/// colon except the bracketed IPv6 literal, whose colons are all inside the
/// brackets, and no `node-port` alternative holds one at all. Splitting at the
/// last colon instead reads `2001:db8::1` as the nodename `2001:db8:` with a
/// port, hiding an address that had to be bracketed behind a port complaint.
///
// cite(RFC 7239 § 6, label: node grammar): "node     = nodename [ ":" node-port ]"
pub fn split_node(value: &str) -> (&str, Option<&str>) {
    let from = match value.starts_with('[') {
        true => value.find(']').map(|i| i + 1).unwrap_or(value.len()),
        false => 0,
    };
    match value[from..].find(':') {
        Some(offset) => (&value[..from + offset], Some(&value[from + offset + 1..])),
        None => (value, None),
    }
}

/// What a node identifier fails to be.
///
/// Every message is the *predicate* of a finding — "is not an IPv4 address"
/// rather than "invalid IPv4 address" — because both callers put a subject in
/// front of it: `Forwarded 'for'`, or the legacy field's name. That shape is
/// the module's convention and the reason it survives the conversion unchanged.
///
/// The variants sort into three groups the `String` could not mark. The first
/// four are the `nodename` failing to be one of its four alternatives. The
/// fifth is the value having no parse at all.
/// [`TextualRepresentation`](Self::TextualRepresentation) is the odd one and is
/// worth telling apart from every other variant: the address *is* an
/// `IPv6address`, and what is wrong is only how it was spelled — a SHOULD from
/// § 6.1, not a grammar failure. And [`NodePort`](Self::NodePort) is about the
/// half of the production after the colon, which every alternative above shares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeDefect<'a> {
    /// An IPv6 address written without its brackets, in the spelling that
    /// requires them. Asked of the whole value before it is split, because
    /// every colon in such an address looks like the one before a `node-port`.
    UnbracketedIpv6(&'a str),
    /// A `[`-led nodename with no closing `]`.
    UnclosedBrackets(&'a str),
    /// Brackets around something that is not an `IPv6address`, carrying what
    /// was inside them.
    NotIpv6(&'a str),
    /// Digits and dots that are not an `IPv4address` — `010.1.2.3`, `1.2.3`,
    /// `256.0.0.1`. Named apart from the catch-all because the value said what
    /// it was trying to be.
    NotIpv4(&'a str),
    /// A nodename no alternative of the production generates. Carries the form,
    /// because which IPv6 spelling the message offers depends on which field
    /// was being read.
    NotANode {
        /// The nodename as written.
        nodename: &'a str,
        /// The field family it was read under.
        form: NodeForm,
    },
    /// A well-formed `IPv6address` written against § 6.1's recommendation.
    /// Carries the address as written and the parser's own rendering of it,
    /// which is the recommended form — the two deviations § 6.1 names in
    /// passing, case and uncompressed zeroes, are exactly the two that survive
    /// the round trip.
    TextualRepresentation {
        /// The address as the sender wrote it.
        written: &'a str,
        /// The same address, in the recommended representation.
        recommended: Ipv6Addr,
    },
    /// Something after the `:` that is neither `1*5DIGIT` nor an `obfport`.
    NodePort(&'a str),
}

impl NodeDefect<'_> {
    /// The finding's predicate, for a caller that has already written its
    /// subject.
    pub fn message(self) -> String {
        match self {
            Self::UnbracketedIpv6(value) => {
                format!("holds an unbracketed IPv6 address: '{}'", value)
            }
            Self::UnclosedBrackets(nodename) => {
                format!("is not a bracketed IPv6 address: '{}'", nodename)
            }
            Self::NotIpv6(inner) => format!("is not an IPv6 address: '{}'", inner),
            Self::NotIpv4(nodename) => format!("is not an IPv4 address: '{}'", nodename),
            Self::NotANode { nodename, form } => {
                let ipv6 = match form {
                    NodeForm::Forwarded => "a bracketed IPv6 address",
                    NodeForm::XForwarded => "an IPv6 address",
                };
                format!(
                    "is not a node identifier: '{}' is neither an IPv4 address, {}, `unknown`, nor an obfuscated identifier (which must begin with `_` and hold only letters, digits, `.`, `_` and `-`)",
                    nodename, ipv6
                )
            }
            Self::TextualRepresentation {
                written,
                recommended,
            } => format!(
                "writes the IPv6 address as '{}' where the recommended textual representation is '{}'",
                written, recommended
            ),
            Self::NodePort(port) => format!(
                "has '{}' where a node-port is expected: one to five digits, or an obfuscated port beginning with `_`",
                port
            ),
        }
    }
}

/// A node identifier: RFC 7239 §6's `node`.
///
/// The defect is the tail of a finding — what is wrong with the value, with no
/// field or parameter named — so each caller writes the subject its own message
/// needs in front of it.
// cite(RFC 7239 § 6, label: node grammar): "node     = nodename [ ":" node-port ]"
pub fn validate_node(value: &str, form: NodeForm) -> Result<(), NodeDefect<'_>> {
    // Asked of the whole value, before it is split: an address written without
    // its brackets has colons in it, and every one of them looks like the
    // separator before a `node-port`. Reported here, the finding names what is
    // wrong with the value; reported by the checks below, it is a complaint
    // about `2001` not being an IPv4 address.
    //
    // In the legacy fields the same shape is the *conforming* one, which is the
    // whole of what §7.4 records about how they are written, so the address is
    // accepted rather than reported — and having consumed the colons, it leaves
    // no room for a port, which is a property of the spelling and not a rule.
    //
    // cite(RFC 7239 § 6.1): "Also, note that an IPv6 address is always enclosed in square brackets."
    if value.parse::<Ipv6Addr>().is_ok() {
        return match form {
            NodeForm::XForwarded => Ok(()),
            NodeForm::Forwarded => Err(NodeDefect::UnbracketedIpv6(value)),
        };
    }

    let (nodename, port) = split_node(value);

    // The four alternatives, in the production's order. Which one a value is
    // trying to be is decided by its first character in every case: a bracket
    // opens the IPv6 literal, an underscore the obfuscated identifier, and the
    // two remaining forms are exact.
    //
    // cite(RFC 7239 § 6, label: nodename grammar): "nodename = IPv4address / "[" IPv6address "]" / "unknown" / obfnode"
    if let Some(rest) = nodename.strip_prefix('[') {
        let Some(inner) = rest.strip_suffix(']') else {
            return Err(NodeDefect::UnclosedBrackets(nodename));
        };
        let Ok(address) = inner.parse::<Ipv6Addr>() else {
            return Err(NodeDefect::NotIpv6(inner));
        };
        // A SHOULD about how the address is written, not about which address it
        // is, so it is asked only once the octets are known to parse. The two
        // deviations §6.1 names in passing — case and uncompressed zeroes — are
        // exactly the two that survive a round trip through the parser, which is
        // why the recommended form can be shown rather than described.
        //
        // The sentence is written about a `Forwarded` node, so it is not asked of
        // the legacy spelling: §7.4 records what those fields do differently and
        // says nothing that would carry a recommendation over to them.
        //
        // cite(RFC 7239 § 6.1): "The "IPv6address" SHOULD comply with textual representation recommendations [RFC5952] (for example, lowercase, compression of zeros)."
        if form == NodeForm::Forwarded && inner != address.to_string() {
            return Err(NodeDefect::TextualRepresentation {
                written: inner,
                recommended: address,
            });
        }
        return validate_node_port(port);
    }

    // An ABNF string literal matches either case, so the fold here is the
    // production's and not a tolerance this code chose. `unknown` is the one
    // place in this field where that is true: everything else compared below is
    // a character class or an address.
    //
    // cite(RFC 5234 § 2.3): "ABNF strings are case insensitive and the character set for these strings is US-ASCII."
    // cite(RFC 7239 § 6.2): "The "unknown" identifier is used when the identity of the preceding entity is not known, but the proxy server still wants to signal that a forwarding of the request was made."
    if nodename.eq_ignore_ascii_case("unknown") {
        return validate_node_port(port);
    }

    if is_obfuscated(nodename) {
        return validate_node_port(port);
    }

    // Both address productions are RFC 3986's, named as such by §6's ABNF, and
    // both are the standard library's parsers here — including the part of
    // `dec-octet` that is easy to write by hand and wrong: `010` is generated by
    // no alternative of it, and `Ipv4Addr` refuses it too.
    //
    // cite(RFC 3986 § 3.2.2, label: IPv4address grammar): "IPv4address = dec-octet "." dec-octet "." dec-octet "." dec-octet"
    // cite(RFC 3986 § 3.2.2, label: dec-octet grammar): "dec-octet   = DIGIT                 ; 0-9 / %x31-39 DIGIT         ; 10-99"
    if nodename.parse::<Ipv4Addr>().is_ok() {
        return validate_node_port(port);
    }

    // Nothing generates this nodename. The message names the alternative the
    // value was closest to, because the everyday defect is an identifier that
    // was obfuscated without the underscore that says so.
    if nodename.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return Err(NodeDefect::NotIpv4(nodename));
    }
    Err(NodeDefect::NotANode { nodename, form })
}

/// The optional `":" node-port` of a node identifier.
///
/// `1*5DIGIT` is the whole of what a numeric port may be here: five digits, no
/// range. The `Forwarded` rule used to measure it with the shared TCP-port
/// reader, which reported `for="192.0.2.1:99999"` — a value the production
/// generates — while the obfuscated form it has no idea about was rejected
/// outright. It also rejected `for=192.0.2.1:0` at the time, which
/// `helpers::uri::port_number` no longer does; the ceiling is still not this
/// production's, so the two answers stay apart for the reason above rather than
/// by how far they happen to differ.
///
// cite(RFC 7239 § 6, label: node-port grammar): "node-port     = port / obfport port          = 1*5DIGIT obfport       = "_" 1*(ALPHA / DIGIT / "." / "_" / "-")"
fn validate_node_port(port: Option<&str>) -> Result<(), NodeDefect<'_>> {
    let Some(port) = port else {
        return Ok(());
    };
    if is_obfuscated(port) {
        return Ok(());
    }
    if !port.is_empty() && port.len() <= 5 && port.chars().all(|c| c.is_ascii_digit()) {
        return Ok(());
    }
    Err(NodeDefect::NodePort(port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_two_spellings_disagree_about_brackets_and_about_nothing_else() {
        // The one difference §7.4 names, in both directions.
        assert!(validate_node("2001:db8:cafe::17", NodeForm::XForwarded).is_ok());
        assert_eq!(
            validate_node("2001:db8:cafe::17", NodeForm::Forwarded),
            Err(NodeDefect::UnbracketedIpv6("2001:db8:cafe::17"))
        );

        // Everything else is one production, so the two forms agree.
        for form in [NodeForm::Forwarded, NodeForm::XForwarded] {
            assert!(validate_node("192.0.2.43", form).is_ok());
            assert!(validate_node("192.0.2.43:47011", form).is_ok());
            assert!(validate_node("unknown", form).is_ok());
            assert!(validate_node("_gazonk", form).is_ok());
            assert!(validate_node("_gazonk:_hidden", form).is_ok());
            assert!(validate_node("[2001:db8::1]", form).is_ok());
            assert_eq!(
                validate_node("x-foo", form),
                Err(NodeDefect::NotANode {
                    nodename: "x-foo",
                    form
                })
            );
            assert_eq!(
                validate_node("192.0.2.43:999999", form),
                Err(NodeDefect::NodePort("999999"))
            );
        }
    }

    #[test]
    fn the_textual_representation_should_is_asked_of_one_spelling() {
        // Both parse; only the `Forwarded` node is measured against §6.1.
        assert_eq!(
            validate_node("[2001:DB8::1]", NodeForm::Forwarded),
            Err(NodeDefect::TextualRepresentation {
                written: "2001:DB8::1",
                recommended: "2001:db8::1".parse().unwrap(),
            })
        );
        assert!(validate_node("[2001:DB8::1]", NodeForm::XForwarded).is_ok());
    }

    /// One variant, two messages: the catch-all carries the form because the
    /// IPv6 spelling it offers is the one the caller's field accepts.
    #[test]
    fn the_catch_all_names_the_ipv6_form_the_caller_accepts() {
        assert!(validate_node("x-foo", NodeForm::Forwarded)
            .unwrap_err()
            .message()
            .contains("a bracketed IPv6 address"));
        assert!(validate_node("x-foo", NodeForm::XForwarded)
            .unwrap_err()
            .message()
            .contains("neither an IPv4 address, an IPv6 address,"));
    }

    /// The four `nodename` alternatives failing separately, plus the two
    /// defects that are not one of them. `[::1` and `[nope]` were the pair
    /// `is_err()` could not tell apart from each other or from `x-foo`: the
    /// first has no closing bracket, the second has brackets around something
    /// that is not an address, and the third is not trying to be one.
    #[test]
    fn each_alternative_fails_as_itself() {
        for form in [NodeForm::Forwarded, NodeForm::XForwarded] {
            assert_eq!(
                validate_node("[::1", form),
                Err(NodeDefect::UnclosedBrackets("[::1"))
            );
            assert_eq!(
                validate_node("[nope]", form),
                Err(NodeDefect::NotIpv6("nope"))
            );
            assert_eq!(
                validate_node("010.1.2.3", form),
                Err(NodeDefect::NotIpv4("010.1.2.3"))
            );
            assert_eq!(
                validate_node("192.0.2.43:_", form),
                Err(NodeDefect::NodePort("_"))
            );
        }
    }

    #[test]
    fn a_nodename_ends_at_its_first_colon_outside_brackets() {
        assert_eq!(split_node("192.0.2.43:8080"), ("192.0.2.43", Some("8080")));
        assert_eq!(split_node("[::1]:8080"), ("[::1]", Some("8080")));
        assert_eq!(split_node("[::1]"), ("[::1]", None));
        assert_eq!(split_node("2001:db8::1"), ("2001", Some("db8::1")));
    }

    #[test]
    fn an_obfuscated_identifier_must_begin_with_an_underscore() {
        assert!(is_obfuscated("_gazonk"));
        assert!(!is_obfuscated("gazonk"));
        assert!(!is_obfuscated("_"));
        assert!(!is_obfuscated("_a b"));
    }
}
