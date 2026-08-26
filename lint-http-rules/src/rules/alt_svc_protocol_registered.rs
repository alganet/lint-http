// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::helpers::headers::{
    combined_field_value_as_written, describe_octet, list_members_as_written, quoting_is_balanced,
    shown_in_finding, split_semicolons_respecting_quotes, trim_ows,
};
use crate::lint::Violation;
use crate::rules::Rule;

/// The one alternative of the field's top production that names no alternative
/// service, and so carries no protocol identifier for this rule to look up.
// cite(RFC 7838 § 3, label: Alt-Svc grammar): "Alt-Svc       = clear / 1#alt-value"
// cite(RFC 7838 § 3): "The field value consists either of a list of values, each of which indicates one alternative service, or the keyword "clear"."
const CLEAR: &str = "clear";

/// A `ProtocolName` is a TLS vector with a one-octet length prefix, so
/// `2^8 - 1` is how many octets one can hold. A name longer than that is not
/// one a ClientHello or a ServerHello can express, whatever else it is.
// cite(RFC 7301 § 3.1): "opaque ProtocolName<1..2^8-1>;"
// cite(RFC 7301 § 3.1): ""ProtocolNameList" contains the list of protocols advertised by the client, in descending order of preference."
const MAX_ALPN_PROTOCOL_NAME_OCTETS: usize = 255;

/// What the rule reads out of its configuration.
///
/// The entries are ALPN protocol *names* — the octets IANA registers — and not
/// `protocol-id`s, which are those octets after RFC 7838 § 3's escaping. The two
/// coincide for `h2` and `h3` and do not for every registered name holding a
/// character no `token` admits: `http/1.1` is written `http%2F1.1` on the wire,
/// `/` being absent from `tchar`.
#[derive(Debug, Clone)]
pub struct AltSvcProtocolConfig {
    pub severity: crate::lint::Severity,
    pub allowed: Vec<String>,
}

/// The list is required and has no default, because the rule cannot derive one.
///
/// The registry the rule is named for is open: RFC 7301 § 6 hands it to a
/// designated expert rather than to a document, so it gains entries between
/// releases of this linter and a snapshot compiled in here would answer for the
/// day it was written. What an operator can state is the narrower and more
/// useful thing — which alternatives this deployment actually serves.
// cite(RFC 7301 § 6): "This document establishes a registry for protocol identifiers entitled "Application-Layer Protocol Negotiation (ALPN) Protocol IDs" under the existing "Transport Layer Security (TLS) Extensions" heading."
// cite(RFC 7301 § 6): "This registry operates under the "Expert Review" policy as defined in [RFC5226]."
// cite(RFC 8447 § 3): "For consistency amongst TLS registries, IANA has prepended "TLS" to the following registries:"
fn parse_allowed_config(
    config: &crate::config::Config,
    rule_id: &str,
) -> anyhow::Result<AltSvcProtocolConfig> {
    let severity = crate::rules::get_rule_severity_required(config, rule_id)?;

    // The two calls above already assert the rule's own table exists, so asking
    // again would build an error branch nothing can reach.
    let rule_cfg = config
        .get_rule_config(rule_id)
        .expect("internal error: rule config missing after validation");
    let table = rule_cfg
        .as_table()
        .ok_or_else(|| anyhow::anyhow!("Configuration for rule '{}' must be a table", rule_id))?;

    let allowed_val = table.get("allowed").ok_or_else(|| {
        anyhow::anyhow!(
            "Rule '{}' requires an 'allowed' array listing the ALPN protocol names this deployment offers as alternative services (e.g., ['h2','h3'])",
            rule_id
        )
    })?;

    let arr = allowed_val.as_array().ok_or_else(|| {
        anyhow::anyhow!("'allowed' must be an array of strings (e.g., ['h2','h3'])")
    })?;

    if arr.is_empty() {
        return Err(anyhow::anyhow!("'allowed' array cannot be empty"));
    }

    let mut out = Vec::new();
    for (i, item) in arr.iter().enumerate() {
        let s = item.as_str().ok_or_else(|| {
            anyhow::anyhow!("'allowed' array item at index {} must be a string", i)
        })?;
        // Stored as written. An ALPN protocol name is a byte string identified
        // by its exact octets, so folding either side of the comparison would
        // make `H2` the name `h2` — which is a claim no sentence in either
        // document supports, and which would silence the finding rather than
        // widen it.
        // cite(RFC 7301 § 3.1): "Protocols are named by IANA-registered, opaque, non-empty byte strings, as described further in Section 6 ("IANA Considerations") of this document."
        // cite(RFC 7301 § 6): "Identification Sequence: The precise set of octet values that identifies the protocol."
        if s.is_empty() {
            return Err(anyhow::anyhow!(
                "'allowed' array item at index {} is the empty string, which names no protocol: an ALPN protocol name is a non-empty byte string",
                i
            ));
        }
        if s.len() > MAX_ALPN_PROTOCOL_NAME_OCTETS {
            return Err(anyhow::anyhow!(
                "'allowed' array item at index {} is {} octets long; a ProtocolName holds at most {}",
                i,
                s.len(),
                MAX_ALPN_PROTOCOL_NAME_OCTETS
            ));
        }
        out.push(s.to_string());
    }

    Ok(AltSvcProtocolConfig {
        severity,
        allowed: out,
    })
}

/// The `protocol-id` written back out as the octets it stands for.
///
/// **Deliberately not `helpers::uri::decode_unreserved`, and the two must not be
/// folded.** That function decodes an `unreserved` triplet and leaves every
/// other one alone, because § 2.4 warns that decoding a delimiter moves the
/// component boundaries. This one decodes them all, because § 3.1 makes an ALPN
/// protocol name an opaque octet sequence — there are no components inside it
/// for a decoded delimiter to bound. One question, two callers, two answers,
/// each resting on its own sentence.
///
/// RFC 7838 § 3 makes the production a percent-*encoding* of the name rather
/// than the name itself, and its own escaping table is the round trip:
/// `w%3Dx%3Ay#z` is the ALPN protocol name `w=x:y#z`. So every triplet is
/// decoded here, delimiters included — the opposite of what
/// `helpers::uri`'s callers do, and right for the same reason theirs is. There
/// a decoded delimiter moves a component boundary; here the section says
/// outright that the name has no format for a boundary to sit in.
///
/// The caller has checked the value is a `token`, so it is US-ASCII throughout
/// and `as_bytes` is the octets rather than a re-encoding of them; and it has
/// checked the triplets, so every `%` below is followed by two `HEXDIG`.
// cite(RFC 7838 § 3): "protocol-id   = token ; percent-encoded ALPN protocol name"
// cite(RFC 7838 § 3): "ALPN protocol names are octet sequences with no additional constraints on format."
// cite(RFC 7838 § 3): "Octets not allowed in tokens ([RFC7230], Section 3.2.6) MUST be percent-encoded as per Section 2.1 of [RFC3986]."
// cite(RFC 3986 § 2.1): "pct-encoded = "%" HEXDIG HEXDIG"
fn alpn_protocol_name(protocol_id: &str) -> Vec<u8> {
    let bytes = protocol_id.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            // Indexed through `get` rather than directly: the invariant is the
            // caller's, and a caller that forgot it should meet the sentence
            // saying so rather than a slice panic.
            let digit = |offset: usize| {
                (*bytes
                    .get(i + offset)
                    .expect("the caller ran check_percent_encoding") as char)
                    .to_digit(16)
                    .expect("the caller ran check_percent_encoding")
            };
            out.push((digit(1) * 16 + digit(2)) as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    out
}

/// A decoded name, rendered for a finding.
///
/// The name is octets, and the octets a `protocol-id` exists to carry are
/// exactly the ones a message will not hold as themselves — so a name that is
/// visible US-ASCII throughout reads as itself and any other is named octet by
/// octet.
///
/// The `from_utf8_lossy` here is the one in this tree that is exact, and the
/// guard above it is why: inside that branch every octet is visible US-ASCII, so
/// the decode has nothing to substitute and nothing to fold. Everywhere else the
/// same call was a defect, because it reads octets as UTF-8 and hands back the
/// text they spell — [`field_line_as_written`] is the reader those callers
/// wanted. Left as it is on purpose, with the reason at the site.
///
/// [`field_line_as_written`]: crate::helpers::headers::field_line_as_written
fn shown_alpn_name(name: &[u8]) -> String {
    if name.iter().all(|b| (0x20..0x7f).contains(b)) {
        format!("'{}'", shown_in_finding(&String::from_utf8_lossy(name)))
    } else {
        name.iter()
            .map(|b| describe_octet(*b))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// `Alt-Svc` nominates alternative services by ALPN protocol name, and this
/// rule asks whether the name is one this deployment offers.
pub struct AltSvcProtocolRegistered;

impl Rule for AltSvcProtocolRegistered {
    fn id(&self) -> &'static str {
        "alt_svc_protocol_registered"
    }

    /// The field rides on responses an origin server writes, and RFC 9110 § 3.7
    /// is why a capture of a gateway's answer is measured by the same sentence.
    // cite(RFC 7838 § 3): "An HTTP(S) origin server can advertise the availability of alternative services to clients by adding an Alt-Svc header field to responses."
    // cite(RFC 9110 § 3.7): "All HTTP requirements applicable to an origin server also apply to the outbound communication of a gateway."
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn validate(&self, config: &crate::config::Config) -> anyhow::Result<()> {
        parse_allowed_config(config, self.id())?;
        // The two standard keys, **after** this rule's own options, so a config
        // naming a bad option still fails on that option. `enabled` is checked
        // here because the parser above stopped reading it: that read ran once
        // per message at lint time and the flag was discarded, since
        // `PreparedEngine` had already decided whether the rule runs.
        crate::rules::validate_rule_table(config, self.id())?;
        Ok(())
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        // No status gate: the section says in one sentence that there is no
        // status this field may not ride on. § 6's *"An Alt-Svc header field in
        // a 421 (Misdirected Request) response MUST be ignored."* would look
        // like the exception and is not one — it is addressed to the recipient,
        // and a server that advertises an alternative nobody can negotiate has
        // written the same defect whatever the status line says.
        // cite(RFC 7838 § 3): "Alt-Svc MAY occur in any HTTP response message, regardless of the status code."
        let resp = tx.response.as_ref()?;
        let config = parse_allowed_config(cfg, self.id()).ok()?;

        // One `char` per octet. `to_str` folds a field carrying `obs-text` into
        // "no such field here", which for this rule would drop every alternative
        // beside the offending one — and `obs-text` is admissible in this field,
        // inside the `quoted-string` an `alt-authority` or a parameter value is.
        // The join writes a bare comma where the sentence names a comma and
        // optional whitespace, which is why the members below are `OWS`-trimmed.
        // cite(RFC 9110 § 5.3): "A recipient MAY combine multiple field lines within a field section that have the same field name into one field line, without changing the semantics of the message, by appending each subsequent field line value to the initial field line value in order, separated by a comma (",") and optional whitespace (OWS, defined in Section 5.6.3)."
        let value = combined_field_value_as_written(&resp.headers, "alt-svc")?;
        let value = trim_ows(&value);

        // The keyword is the field's other alternative and nominates nothing,
        // so there is no protocol identifier to ask about. It is matched exactly
        // because `%s"clear"` is RFC 7405's case-sensitive string; a case
        // variant is an `alt-value`, and one with no '=' in it, which the walk
        // below hands to the rule that owns the grammar.
        // cite(RFC 7838 § 3): "clear         = %s"clear"; "clear", case-sensitive"
        if value == CLEAR {
            return None;
        }

        // A DQUOTE that never closes makes every separator after it a guess, so
        // the members are not members. Declined rather than reported:
        // `alt_svc_header_syntax` reads this field's grammar and reports
        // it, under the same scope and with no gate this one does not have.
        if !quoting_is_balanced(value) {
            return None;
        }

        for member in list_members_as_written(value) {
            // An empty member is `1#alt-value`'s floor or a sender's empty list
            // element; both are the grammar's question and are reported there.
            if member.is_empty() {
                continue;
            }
            // `alt-value` is an `alternative` with the parameter group behind
            // it, and the splitter always yields a first segment.
            // cite(RFC 7838 § 3): "alt-value     = alternative *( OWS ";" OWS parameter )"
            let parts = split_semicolons_respecting_quotes(member);
            let alternative = parts
                .first()
                .expect("the splitter yields at least one segment");

            // Everything below this line is a decline, and each one is the
            // grammar's question rather than the registry's: a value that
            // derives from no `protocol-id` names no ALPN protocol name, so
            // there is nothing for a list to be asked about. Saying so a second
            // time here would be the same finding in worse words.
            // cite(RFC 7838 § 3): "alternative   = protocol-id "=" alt-authority"
            let Some((protocol_id, _)) = alternative.split_once('=') else {
                continue;
            };
            // `token = 1*tchar` admits no empty string and no whitespace, so
            // this also declines the `OWS`-beside-the-`=` case the neighbouring
            // rule reports.
            // cite(RFC 9110 § 5.6.2): "token = 1*tchar tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA"
            if protocol_id.is_empty()
                || crate::helpers::token::find_invalid_token_char(protocol_id).is_some()
            {
                continue;
            }
            // A malformed triplet is not a name spelled wrong, it is a name
            // that cannot be read at all; the three spelling MUSTs a
            // well-formed triplet can still break are the neighbour's too.
            if crate::helpers::uri::check_percent_encoding(protocol_id).is_some() {
                continue;
            }

            let name = alpn_protocol_name(protocol_id);

            // The one finding here that needs no configuration. A name longer
            // than the vector that carries it is not one any handshake can put
            // on the wire, so no list has to be consulted to know it names
            // nothing.
            if name.len() > MAX_ALPN_PROTOCOL_NAME_OCTETS {
                return Some(self.violation(
                    config.severity,
                    format!(
                        "Alt-Svc protocol-id '{}' decodes to an ALPN protocol name of {} octets. A `ProtocolName` carries at most {}, so this alternative is named by something no ClientHello or ServerHello can express",
                        shown_in_finding(protocol_id),
                        name.len(),
                        MAX_ALPN_PROTOCOL_NAME_OCTETS
                    ),
                ));
            }

            // The comparison is against the configured list and not against the
            // registry the rule's name invokes — nothing here fetches
            // <https://www.iana.org/assignments/tls-extensiontype-values>. That
            // is a real divergence and `description()` says so. It is also what
            // makes the finding worth having: a name absent from an open,
            // expert-reviewed registry is not thereby wrong, while one this
            // deployment does not serve is an alternative every client will
            // fail over to and away from.
            // cite(RFC 7838 § 2): "An Application Layer Protocol Negotiation (ALPN) protocol name, as per [RFC7301]"
            // cite(RFC 7838 § 2): "The ALPN protocol name is used to identify the application protocol or suite of protocols used by the alternative service."
            // cite(RFC 7301 § 3.2): "In the event that the server supports no protocols that the client advertises, then the server SHALL respond with a fatal "no_application_protocol" alert."
            // cite(RFC 7838 § 2.4): "If the connection to the alternative service does not negotiate the expected protocol (for example, ALPN fails to negotiate h2, or an Upgrade request to h2c is not accepted), the connection to the alternative service MUST be considered to have failed."
            if !config
                .allowed
                .iter()
                .any(|allowed| allowed.as_bytes() == name.as_slice())
            {
                return Some(self.violation(
                    config.severity,
                    format!(
                        "Alt-Svc protocol-id '{}' names the ALPN protocol {}, which is not one this deployment lists as an alternative service it offers. A client taking this alternative negotiates that name in TLS and is required to treat the connection as failed when it is not the one selected",
                        shown_in_finding(protocol_id),
                        shown_alpn_name(&name)
                    ),
                ));
            }
        }

        None
    }

    fn title(&self) -> Option<&'static str> {
        Some("Server Alt-Svc Protocol IANA-Registered")
    }

    fn description(&self) -> &'static str {
        "Read the `protocol-id` of each `Alt-Svc` alternative as the ALPN protocol name it stands for, and ask whether that name is one this deployment offers.\n\n**A `protocol-id` is not the name; it is an escaping of it.** RFC 7838 §3 writes `protocol-id = token ; percent-encoded ALPN protocol name` and says *\"ALPN protocol names are octet sequences with no additional constraints on format\"*, so every triplet is decoded before the comparison — delimiters included, because there are no components inside a name for a decoded delimiter to move. This matters for more registered names than it looks: `/` is not a `tchar`, so `http/1.1`, `acme-tls/1`, `ntske/1`, `sip/2` and `radius/1.1` all appear on the wire percent-encoded (`http%2F1.1`), and a list written from the registry would match none of them otherwise.\n\n**The comparison is byte-exact.** RFC 7301 §3.1 says protocols are *\"named by IANA-registered, opaque, non-empty byte strings\"* and §6's registration template asks for *\"the precise set of octet values that identifies the protocol\"*, so `H2` is not `h2`. Neither side of the comparison is case-folded, and the registry itself carries a mixed-case entry.\n\n**The `allowed` list is required and stands in for the registry.** Nothing here fetches <https://www.iana.org/assignments/tls-extensiontype-values>; RFC 7301 §6 hands the *\"TLS Application-Layer Protocol Negotiation (ALPN) Protocol IDs\"* registry (renamed by RFC 8447 §3) to a designated expert under Expert Review, so it gains entries between releases and a list compiled in here would answer for the day it was written. The list is written as ALPN protocol **names**, the octets IANA registers, and not as the escaped `protocol-id`s. What the finding rests on is what happens next: RFC 7301 §3.2 has a server with no protocol in common send a fatal `no_application_protocol` alert, and RFC 7838 §2.4 requires a client whose alternative does not negotiate the expected protocol to treat that connection as failed.\n\n**One finding needs no configuration.** A `ProtocolName` is `opaque ProtocolName<1..2^8-1>`, so a name longer than 255 octets is one no ClientHello or ServerHello can carry, whatever any list says.\n\n**What this rule declines, and to whom.** Everything that is the field's grammar rather than its registry goes to `alt_svc_header_syntax`, which reads the same field under the same scope with no gate this rule lacks: an unterminated `quoted-string`, an empty list element, an alternative with no `=`, an empty `protocol-id`, a character no `tchar` admits, a malformed percent triplet, and whitespace beside the `=`. So are the three spelling MUSTs on a well-formed triplet — a lowercase hex digit, an encoded `tchar`, an unencoded `%` — which that rule reports with the reason `x%3dy` and `x%3Dy` are two protocols to a recipient. Here a well-formed triplet is simply decoded, so `%68%32` is read as `h2` and reported once rather than twice. The `clear` keyword nominates no service and is skipped, matched case-sensitively because `%s\"clear\"` is. RFC 7838 §2.1's *\"Clients MUST have reasonable assurances that the alternative service is under control of and valid for the whole origin\"* — with the §2.1 example that `h2c` cannot provide them — is addressed to clients and is not reported against the server that advertised it. Draft HTTP/3 tokens are `alt_svc_h3_advertisement_valid`'s."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 7838",
                section: Some("2"),
                url: "https://www.rfc-editor.org/rfc/rfc7838.html#section-2",
                note: "Alternative Services Concepts: an alternative service is identified by an ALPN protocol name as per RFC 7301, a host and a port; §2.4 requires a client to treat a connection that does not negotiate the expected protocol as failed",
            },
            crate::rules::SpecRef {
                spec: "RFC 7838",
                section: Some("3"),
                url: "https://www.rfc-editor.org/rfc/rfc7838.html#section-3",
                note: "The Alt-Svc HTTP Header Field: `protocol-id = token ; percent-encoded ALPN protocol name`, the escaping table that is its round trip, and the `clear` keyword",
            },
            crate::rules::SpecRef {
                spec: "RFC 7301",
                section: Some("3.1"),
                url: "https://www.rfc-editor.org/rfc/rfc7301.html#section-3.1",
                note: "The Application-Layer Protocol Negotiation Extension: protocol names are IANA-registered opaque byte strings, carried in a `ProtocolName` vector of at most 255 octets; §3.2 is the fatal alert a server sends when nothing is in common",
            },
            crate::rules::SpecRef {
                spec: "RFC 7301",
                section: Some("6"),
                url: "https://www.rfc-editor.org/rfc/rfc7301.html#section-6",
                note: "IANA Considerations: the ALPN Protocol IDs registry, its Identification Sequence column, and its Expert Review policy — the reason the allowed list is configuration rather than a table compiled in here",
            },
            crate::rules::SpecRef {
                spec: "RFC 8447",
                section: Some("3"),
                url: "https://www.rfc-editor.org/rfc/rfc8447.html#section-3",
                note: "Adding \"TLS\" to Registry Names: the registry RFC 7301 §6 created is now \"TLS Application-Layer Protocol Negotiation (ALPN) Protocol IDs\"",
            },
            crate::rules::SpecRef {
                spec: "IANA TLS ALPN Protocol IDs",
                section: None,
                url: "https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids",
                note: "TLS Application-Layer Protocol Negotiation (ALPN) Protocol IDs: the registry an operator writes the allowed list from — nothing in this rule reads it",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("5.6.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.2",
                note: "Tokens: `token = 1*tchar`, the production a `protocol-id` is, and §5.3's rule for combining a field spread over several lines",
            },
            crate::rules::SpecRef {
                spec: "RFC 3986",
                section: Some("2.1"),
                url: "https://www.rfc-editor.org/rfc/rfc3986.html#section-2.1",
                note: "Percent-Encoding: `pct-encoded = \"%\" HEXDIG HEXDIG`, the triplet decoded back into an octet of the name",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "Alt-Svc: h2=\":443\"; ma=2592000\nAlt-Svc: h3=\"example.com:8443\"\nAlt-Svc: http%2F1.1=\"old.example.com:443\"  # the ALPN name is http/1.1\nAlt-Svc: clear",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "Alt-Svc: xproto=\":443\"                    # names no ALPN protocol this deployment offers\nAlt-Svc: H2=\"example.com:443\"             # an ALPN protocol name is its exact octets\nAlt-Svc: spdy%2F3=\"old.example.com:443\"   # spdy/3 is registered, and not offered here",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &AltSvcProtocolRegistered;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn make_cfg() -> crate::config::Config {
        allowing(&["h2", "h3", "h2c", "http/1.1"])
    }

    fn allowing(allowed: &[&str]) -> crate::config::Config {
        let mut cfg = crate::config::Config::default();
        cfg.rules.insert(
            "alt_svc_protocol_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(
                        allowed
                            .iter()
                            .map(|p| toml::Value::String(p.to_string()))
                            .collect(),
                    ),
                );
                t
            }),
        );
        cfg
    }

    fn check(tx: &crate::http_transaction::HttpTransaction) -> Option<Violation> {
        AltSvcProtocolRegistered.check_transaction(
            tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &make_cfg(),
        )
    }

    fn run(headers: &[(&str, &str)]) -> Option<Violation> {
        check(&crate::test_helpers::make_test_transaction_with_response(
            200, headers,
        ))
    }

    fn message(header: &str) -> String {
        run(&[("alt-svc", header)])
            .unwrap_or_else(|| panic!("expected a violation for {header:?}"))
            .message
    }

    #[rstest]
    #[case("h2=\":443\"; ma=2592000")]
    #[case("h3=\"example.com:8443\"")]
    #[case("h2=\"alt.example.com:8000\", h3=\":443\"")]
    #[case("clear")]
    // A parameter's quoted value may hold a comma, and what follows it is not a
    // member: the naive comma split this replaced read `h9=x` as an alternative
    // and reported a protocol nobody advertised.
    #[case("h2=\":443\"; zzz=\"a,h9=x\"")]
    // The escaping is decoded before the comparison, so a name a `token` cannot
    // hold is still the name it stands for.
    #[case("http%2F1.1=\":443\"")]
    // A non-canonical spelling of a listed name decodes to that name here: an
    // encoded `tchar` in the first, a lowercase hex digit in the second. Both
    // break a MUST, and both are the syntax rule's to report — saying it again
    // here would be the same finding in worse words.
    #[case("%68%32=\":443\"")]
    #[case("http%2f1.1=\":443\"")]
    fn conforming_values_draw_nothing(#[case] header: &str) {
        assert!(run(&[("alt-svc", header)]).is_none(), "for {header:?}");
    }

    #[test]
    fn absent_field_and_absent_response_draw_nothing() {
        assert!(run(&[]).is_none());
        assert!(check(&crate::test_helpers::make_test_transaction()).is_none());
    }

    /// Each finding is pinned by its wording rather than by its existence: the
    /// message is built in two halves — a verb phrase and the name it is about —
    /// and an `is_some` assertion cannot see the two disagree.
    #[rstest]
    #[case("xproto=\":443\"", "names the ALPN protocol 'xproto'")]
    #[case("h2=\":443\", xproto=\":443\"", "'xproto'")]
    #[case("spdy%2F3=\":443\"", "names the ALPN protocol 'spdy/3'")]
    #[case("w%3Dx%3Ay#z=\":443\"", "names the ALPN protocol 'w=x:y#z'")]
    fn each_finding_names_what_it_is_about(#[case] header: &str, #[case] expected: &str) {
        let m = message(header);
        assert!(
            m.contains(expected),
            "for {header:?} expected {expected:?} in {m:?}"
        );
    }

    /// `H2` is not `h2`. The fold this replaced silenced the finding rather than
    /// widening it, which is the opposite of the deliberate permissive fold
    /// `alt_svc_h3_advertisement_valid` records for its draft-token scan.
    #[test]
    fn an_alpn_protocol_name_is_its_exact_octets() {
        assert!(run(&[("alt-svc", "H2=\"example.com:443\"")]).is_some());
        assert!(run(&[("alt-svc", "h2=\"example.com:443\"")]).is_none());
        let cfg = allowing(&["H2"]);
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("alt-svc", "h2=\":443\"")],
        );
        assert!(AltSvcProtocolRegistered
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg
            )
            .is_some());
    }

    /// A name is octets, so a decoded one that is not visible US-ASCII is named
    /// octet by octet rather than written through into the message.
    #[test]
    fn a_name_that_is_not_text_is_shown_as_octets() {
        let m = message("%00%FF=\":443\"");
        assert!(m.contains("0x00 0xFF"), "{m}");
    }

    /// `opaque ProtocolName<1..2^8-1>` is the whole of this finding, and it is
    /// the one branch here that consults no configuration.
    #[test]
    fn a_name_longer_than_the_vector_that_carries_it_is_reported() {
        let at_the_bound = "a".repeat(MAX_ALPN_PROTOCOL_NAME_OCTETS);
        let over = "a".repeat(MAX_ALPN_PROTOCOL_NAME_OCTETS + 1);
        let cfg = allowing(&[at_the_bound.as_str()]);
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("alt-svc", &format!("{at_the_bound}=\":443\""))],
        );
        assert!(AltSvcProtocolRegistered
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg
            )
            .is_none());
        let m = message(&format!("{over}=\":443\""));
        assert!(m.contains("256 octets"), "{m}");
        assert!(m.contains("ClientHello"), "{m}");
    }

    /// Every input this rule declines is one the neighbour reports, and the
    /// neighbour's gate is read here rather than assumed: it takes any response
    /// under the same scope, so a hand-off to it is not a hand-off into silence.
    #[rstest]
    #[case("h2example.com:443")]
    #[case("=\":443\"")]
    #[case("h@=\":443\"")]
    // The registered name written as itself rather than as its escaping: `/` is
    // in no `token`, so this derives from no `protocol-id` at all.
    #[case("http/1.1=\":443\"")]
    #[case("x%zzy=\":443\"")]
    #[case("x%4=\":443\"")]
    #[case("h2 =\":443\"")]
    #[case("h2=\":443")]
    #[case(",")]
    #[case("h2=\":443\",")]
    #[case("CLEAR")]
    #[case("clear, h2=\":443\"")]
    fn what_this_rule_declines_the_grammar_rule_reports(#[case] header: &str) {
        assert!(
            run(&[("alt-svc", header)]).is_none(),
            "this rule should decline {header:?}"
        );
        let tx =
            crate::test_helpers::make_test_transaction_with_response(200, &[("alt-svc", header)]);
        let syntax = crate::rules::alt_svc_header_syntax::AltSvcHeaderSyntax;
        assert!(
            syntax
                .check_transaction(
                    &tx,
                    &crate::transaction_history::TransactionHistory::empty(),
                    &crate::test_helpers::make_test_config_with_severity(
                        "alt_svc_header_syntax",
                        "warn"
                    ),
                )
                .is_some(),
            "the grammar rule should report {header:?}"
        );
    }

    /// `obs-text` is admissible inside this field's `quoted-string`s, and
    /// `to_str` folded such a field into "no such field here" — which for a
    /// per-member rule drops every alternative beside the offending one.
    #[test]
    fn obs_text_elsewhere_in_the_field_does_not_hide_a_member() {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;

        let mut headers = HeaderMap::new();
        headers.insert(
            "alt-svc",
            HeaderValue::from_bytes(b"h2=\":443\"; zzz=\"\xE9\", xproto=\":443\"")
                .expect("obs-text is a field-content octet"),
        );
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers,
            body_length: None,
            trailers: None,
        });
        let v = check(&tx).expect("the second alternative names no listed protocol");
        assert!(v.message.contains("'xproto'"), "{}", v.message);
    }

    /// The field is one list however many lines carry it.
    #[test]
    fn members_spread_over_two_field_lines_are_all_read() {
        let v = run(&[("alt-svc", "h2=\":443\""), ("alt-svc", "xproto=\":443\"")])
            .expect("the second line names no listed protocol");
        assert!(v.message.contains("'xproto'"), "{}", v.message);
    }

    /// An entry naming no ALPN protocol name is refused where the operator can
    /// still do something about it, rather than silently never matching.
    #[test]
    fn the_allowed_list_is_validated() {
        let too_long = "a".repeat(MAX_ALPN_PROTOCOL_NAME_OCTETS + 1);
        for (entry, expected) in [
            ("", "names no protocol"),
            (too_long.as_str(), "octets long"),
        ] {
            let err = AltSvcProtocolRegistered
                .validate(&allowing(&[entry]))
                .expect_err("the entry names no ALPN protocol");
            assert!(err.to_string().contains(expected), "{err}");
        }
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        crate::rules::validate_rules(&allowing(&["h2", "h3"]))?;
        Ok(())
    }

    #[test]
    fn scope_is_server() {
        assert_eq!(
            AltSvcProtocolRegistered.scope(),
            crate::rules::RuleScope::Server
        );
    }
}
