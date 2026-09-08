// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::helpers::comment::scan_comment;
use crate::helpers::headers::combined_field_value_octets;
use crate::helpers::shown::describe_octet;
use crate::helpers::token::is_tchar_byte;
use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::comment::{
    comment_defect, COMMENT_CHARACTER_FORBIDDEN, COMMENT_DELIMITER_MISSING, RFC_9110_5_6_5,
};
use crate::violations::list::{LIST_MEMBER_EMPTY, RFC_9110_5_6_1_1};
use crate::violations::quoted_pair::QUOTED_PAIR_MALFORMED;
use crate::violations::quoted_string::RFC_9110_5_6_4;
use crate::violations::token::{
    token_character, RFC_9110_5_6_2, TOKEN_CHARACTER_FORBIDDEN, TOKEN_EMPTY,
    TOKEN_WHITESPACE_OR_CONTROL_FORBIDDEN,
};
use crate::violations::uri::{RFC_3986_3_2_3, URI_PORT_CHARACTER_FORBIDDEN};
use crate::violations::ViolationDef;

pub struct ViaHeaderSyntax;

/// Every production this field is assembled from, and none of its assembly.
///
/// `Via = #( received-protocol RWS received-by [ RWS comment ] )` names four
/// things and defines none of them: the `#` list, the two `token`s a
/// `received-protocol` is, the `token` a `pseudonym` is, the `port` RFC 3986
/// writes, and § 5.6.5's comment with the escape inside it. So a `Via` member
/// holding a bad octet answers with the same id an `Upgrade`, a `Server` or a
/// `Content-Type` parameter would.
///
/// What stays this rule's own is what the *member* says about its parts: a
/// `received-by` that is missing, a second comment where the production
/// permits one, content after a member that has ended, and the bracketed IPv6
/// literal § B.2 took out of this production when it removed `uri-host` from
/// it. Every one of those is a statement about assembly, and no borrowed
/// production has a defect for it.
static DECLARED: &[&ViolationDef] = &[
    &LIST_MEMBER_EMPTY,
    &TOKEN_EMPTY,
    &TOKEN_CHARACTER_FORBIDDEN,
    &TOKEN_WHITESPACE_OR_CONTROL_FORBIDDEN,
    &URI_PORT_CHARACTER_FORBIDDEN,
    &COMMENT_DELIMITER_MISSING,
    &COMMENT_CHARACTER_FORBIDDEN,
    &QUOTED_PAIR_MALFORMED,
];

/// One finding from the reading, and the defect it reports as where the
/// catalogue names that defect.
///
/// The shape `expect_header_valid` settled. Here the unnamed half is the
/// member's assembly, and it is the larger half by count — which is what a
/// field that borrows every production it is made of looks like from the
/// inside.
struct Defect {
    def: Option<&'static ViolationDef>,
    message: String,
}

impl Defect {
    /// A defect the catalogue names.
    fn named(def: &'static ViolationDef, message: String) -> Self {
        Self {
            def: Some(def),
            message,
        }
    }

    /// A defect no subject has claimed: this production's own statement about
    /// how its parts go together.
    fn unnamed(message: String) -> Self {
        Self { def: None, message }
    }

    /// The same defect with its message read from further out — the direction
    /// the field travelled in.
    fn in_context(self, context: impl FnOnce(String) -> String) -> Self {
        Self {
            def: self.def,
            message: context(self.message),
        }
    }
}

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9110_7_6_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("7.6.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6.3",
    note: "The `Via` grammar this rule parses, the sentence that puts the field in both \
           directions, and the requirements about forwarding and combining that a single \
           captured message cannot answer",
};
const RFC_9110_7_8: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("7.8"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-7.8",
    note: "`received-protocol` points here for its two halves: `protocol-name = token` \
           and `protocol-version = token`",
};
const RFC_9110_B_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("B.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#appendix-B.2",
    note: "Why a `received-by` is a token: RFC 9110 removed `uri-host` from the \
           production, which is what makes a bracketed IPv6 literal a finding here and \
           not under RFC 7230",
};
const RFC_9110_5_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("5.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.2",
    note: "Several `Via` lines in one section are one field value, which is why the \
           members are counted after they are joined",
};

impl RuleMeta for ViaHeaderSyntax {
    fn id(&self) -> &'static str {
        "via_header_syntax"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
severity = "warn"
"#
    }

    fn description(&self) -> &'static str {
        "Parses the `Via` field of a request and of a response — every field line of one section \
         joined into the single list they are — against RFC 9110 §7.6.3's grammar: \
         `Via = #( received-protocol RWS received-by [ RWS comment ] )`, where `received-protocol` is \
         a `protocol-version` optionally preceded by a `protocol-name` and a slash (§7.8 makes both \
         tokens), `received-by = pseudonym [ \":\" port ]`, and `pseudonym = token`. \
         \n\n\
         Three consequences of that grammar are worth stating before the rule is enabled. \
         **`received-by` is a token, not a host.** RFC 9110 removed `uri-host` from the production \
         (Appendix B.2) on the grounds that a pseudonym encompasses it, so a bracketed IPv6 literal — \
         `Via: 1.1 [2001:db8::1]:8080`, which RFC 7230's grammar admitted — has no spelling here and \
         is reported. **A port is `*DIGIT`** (RFC 3986 §3.2.3): it carries no range, so `:0` and \
         `:99999` are syntax-conforming, and so is a colon with no digits after it. **An empty field \
         value is a list of no members** and is not reported, while an empty member — including one \
         written at a line boundary, since the lines of one section are one list — is RFC 9110 \
         §5.6.1.1's sender MUST NOT. \
         \n\n\
         A member's optional comment is parsed as §5.6.5's `comment`: nested parentheses and \
         backslash escapes are honoured, `obs-text` inside it is permitted, and it must be the last \
         thing in the member and separated from the `received-by` by whitespace. \
         \n\n\
         What the rule does not judge: whether a proxy sent a `Via` at all. §7.6.3's MUST is about \
         each message a proxy *forwards*, and a capture does not record whether the message arrived \
         through an intermediary, so an absent field is not evidence of anything. Neither are the \
         section's requirements about combining members (a sender MUST NOT combine members with \
         different received-protocols, and SHOULD NOT combine members outside one organization) or \
         the firewall SHOULD NOT: a combined member and a member that was always one are the same \
         octets, and no field records the topology the other sentences are about."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_9110_7_6_3,
            RFC_9110_7_8,
            RFC_9110_B_2,
            RFC_9110_5_6_5,
            RFC_9110_5_6_1_1,
            RFC_9110_5_2,
            RFC_3986_3_2_3,
            RFC_9110_5_6_2,
            RFC_9110_5_6_4,
        ]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("The chain §7.6.3 prints, and the collapsed form it prints beside it"),
                snippet: "GET /index.html HTTP/1.1\nVia: 1.0 fred, 1.1 p.example.net\nVia: 1.0 ricky, 1.1 mertz, 1.0 lucy",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("A named protocol, a port, and a comment naming the software"),
                snippet: "GET /index.html HTTP/1.1\nVia: HTTP/1.1 proxy.example.com:8080 (squid/5.7)",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("A member with a received-protocol and no received-by"),
                snippet: "GET /index.html HTTP/1.1\nVia: 1.1",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("`@` is not a tchar, and both halves of a received-protocol are tokens"),
                snippet: "GET /index.html HTTP/1.1\nVia: HT@P/1.1 proxy.example.com",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("A port is digits, however few"),
                snippet: "GET /index.html HTTP/1.1\nVia: 1.1 example.com:port",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("An empty list member, which a sender must not generate"),
                snippet: "GET /index.html HTTP/1.1\nVia: 1.1 example.com, , 1.0 proxy",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some(
                    "`received-by` is a pseudonym, and RFC 9110 removed the host that admitted brackets",
                ),
                snippet: "GET /index.html HTTP/1.1\nVia: 1.1 [2001:db8::1]:8080",
            },
        ]
    }
}

impl Rule for ViaHeaderSyntax {
    /// A `Via` travels in both directions, and the field's first sentence is
    /// what says so: the chain it records runs toward the server on a request
    /// and back toward the client on a response.
    // cite(RFC 9110 § 7.6.3): "The "Via" header field indicates the presence of intermediate protocols and recipients between the user agent and the server (on requests) or between the origin server and the client (on responses)"
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // Single-finding body behind an Option: `?` ends it early, and the
        // one finding (or none) becomes the vector.
        let finding = || -> Option<Violation> {
            // cite(RFC 9110 § 7.6.3): "A proxy MUST send an appropriate Via header field, as described below, in each message that it forwards."
            let report = |defect: Defect| match defect.def {
                Some(def) => ctx.report_with(def, defect.message),
                None => self.cited(&RFC_9110_7_6_3, ctx.severity, defect.message),
            };

            if let Some(defect) = judge(&tx.request.headers, "Request") {
                return Some(report(defect));
            }

            // cite(RFC 9110 § 7.6.3): "An HTTP-to-HTTP gateway MUST send an appropriate Via header field in each inbound request message and MAY send a Via header field in forwarded response messages."
            if let Some(resp) = &tx.response {
                if let Some(defect) = judge(&resp.headers, "Response") {
                    return Some(report(defect));
                }
            }

            None
        };
        Vec::from_iter(finding())
    }
}

/// Judge one field section's `Via` lines, naming the direction the finding is in.
///
/// The lines are joined before anything is counted, because the members of a
/// list-based field do not belong to the line that happens to carry them — a
/// member written empty at a line boundary is an empty member.
fn judge(headers: &hyper::HeaderMap, side: &str) -> Option<Defect> {
    let value = combined_field_value_octets(headers, "via")?;
    validate_via(&value)
        .err()
        .map(|defect| defect.in_context(|message| format!("{side} Via header: {message}")))
}

/// Skip `OWS` -- the optional whitespace a list permits around its commas.
// cite(RFC 9110 § 5.6.3): "OWS = *( SP / HTAB )"
fn skip_ws(v: &[u8], mut i: usize) -> usize {
    while i < v.len() && (v[i] == b' ' || v[i] == b'\t') {
        i += 1;
    }
    i
}

/// Consume the run of `tchar`s starting at `start`, which may be empty; the
/// caller decides whether an empty one is an error, because `token = 1*tchar`
/// appears in this grammar three times and the error differs each time.
fn scan_token(v: &[u8], start: usize) -> usize {
    // cite(RFC 9110 § 5.6.2): "token = 1*tchar tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA"
    let mut i = start;
    while i < v.len() && is_tchar_byte(v[i]) {
        i += 1;
    }
    i
}

/// Whether `b` can end a member: the list's separator, or whitespace that may
/// precede it.
fn ends_a_member(b: u8) -> bool {
    b == b',' || b == b' ' || b == b'\t'
}

/// Validate a whole `Via` field value.
///
/// Takes octets rather than a `&str` for the same reason the `product` grammar
/// does: `ctext` admits `obs-text`, so a member may legally carry a comment that
/// is not visible US-ASCII, while the same octet in a `pseudonym` is not a
/// `tchar` and has to be reported *there* -- at the production that excludes it,
/// rather than as a claim about the whole field's encoding.
fn validate_via(value: &[u8]) -> Result<(), Defect> {
    // cite(RFC 9110 § 5.5): "A field value does not include leading or trailing whitespace."
    let mut v = value;
    while let [b' ' | b'\t', rest @ ..] = v {
        v = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = v {
        v = rest;
    }

    // `Via` is a `#` list with no lower bound, and the expansion of that
    // construct is what says a value carrying no member at all conforms. The
    // sentence below governs the *members*, and a list with none of them
    // violates nothing.
    // cite(RFC 9110 § 7.6.3): "Via = #( received-protocol RWS received-by [ RWS comment ] )"
    // cite(RFC 9110 § 5.6.1.1): "#element => [ 1#element ]"
    if v.is_empty() {
        return Ok(());
    }

    let mut i = 0usize;
    let mut n = 0usize;
    loop {
        n += 1;
        i = skip_ws(v, i);

        // cite(RFC 9110 § 5.6.1.1): "In any production that uses the list construct, a sender MUST NOT generate empty list elements."
        if i == v.len() || v[i] == b',' {
            return Err(Defect::named(
                &LIST_MEMBER_EMPTY,
                format!("member {n} is empty, and a sender must not generate empty list elements"),
            ));
        }

        let commented;
        (i, commented) = validate_member(v, i, n)?;
        i = skip_ws(v, i);

        if i == v.len() {
            return Ok(());
        }
        if v[i] != b',' {
            // `validate_member` stops at the first octet that cannot continue a
            // member, so whatever is here followed a complete one. A `(` can only
            // be a second comment: an unspaced one is not a comment at all and
            // has already been reported against the `received-by` it ran into.
            return Err(Defect::unnamed(if v[i] == b'(' {
                format!("member {n} carries more than one comment, and the production permits one")
            } else if commented {
                format!(
                    "member {n} has content after its comment, starting {}",
                    describe_octet(v[i])
                )
            } else {
                format!(
                    "member {n} has content after its received-by, starting {}",
                    describe_octet(v[i])
                )
            }));
        }
        i += 1;
    }
}

/// Validate one list member, returning the offset just past it and whether the
/// optional comment was there.
///
/// The three parts are consumed in the order the production writes them, so the
/// octet that stops each one is reported against the part it interrupted rather
/// than against the member as a whole -- including the caller's report of what
/// follows the member, which is why it is told whether a comment was taken.
// cite(RFC 9110 § 7.6.3): "Via = #( received-protocol RWS received-by [ RWS comment ] )"
fn validate_member(v: &[u8], start: usize, n: usize) -> Result<(usize, bool), Defect> {
    // A `received-protocol` is a `protocol-version` that a `protocol-name` and a
    // slash may precede, so the first token is the version until a slash proves
    // it was the name. Both halves are tokens; §7.8 is where the field's own
    // section sends the reader for them.
    // cite(RFC 9110 § 7.6.3): "received-protocol = [ protocol-name "/" ] protocol-version"
    // cite(RFC 9110 § 7.8): "protocol-name = token"
    // cite(RFC 9110 § 7.8): "protocol-version = token"
    // cite(RFC 9110 § 7.6.3): "For brevity, the protocol-name is omitted when the received protocol is HTTP."
    let mut i = scan_token(v, start);
    if i == start {
        return Err(Defect::named(
            &TOKEN_EMPTY,
            format!(
                "member {n} does not begin with a received-protocol, but with {}",
                describe_octet(v[start])
            ),
        ));
    }
    let mut half = "received-protocol";
    if i < v.len() && v[i] == b'/' {
        let version = scan_token(v, i + 1);
        if version == i + 1 {
            return Err(Defect::named(
                &TOKEN_EMPTY,
                match v.get(version) {
                    None => format!("member {n} ends with the slash of its received-protocol"),
                    Some(&b) => format!(
                        "member {n} has an empty protocol version, with {} after the slash",
                        describe_octet(b)
                    ),
                },
            ));
        }
        i = version;
        half = "protocol version";
    }

    // The whitespace between the two halves is required, so the octet sitting
    // here is either a missing `received-by` or the character that stopped the
    // protocol version.
    // cite(RFC 9110 § 5.6.3): "The RWS rule is used when at least one linear whitespace octet is required to separate field tokens."
    // cite(RFC 9110 § 5.6.3): "RWS = 1*( SP / HTAB )"
    match v.get(i) {
        None => {
            return Err(Defect::unnamed(format!(
                "member {n} has a received-protocol and no received-by"
            )))
        }
        Some(&b',') => {
            return Err(Defect::unnamed(format!(
                "member {n} has a received-protocol and no received-by"
            )))
        }
        Some(&b) if b != b' ' && b != b'\t' => {
            return Err(Defect::named(
                token_character(b as char),
                format!("member {n} has a {half} containing {}", describe_octet(b)),
            ))
        }
        _ => {}
    }
    i = skip_ws(v, i);

    // `received-by = pseudonym [ ":" port ]`, and the pseudonym is a bare token:
    // RFC 9110 took `uri-host` back out of this production, so the host forms it
    // used to admit are here only inasmuch as a token spells them. A dotted name
    // and an IPv4 literal do; a bracketed IPv6 literal does not, and the
    // brackets are the octets that say so.
    // cite(RFC 9110 § 7.6.3): "received-by = pseudonym [ ":" port ] pseudonym = token"
    // cite(RFC 9110 § B.2): "For simplicity, we have removed uri-host from the received-by production because it can be encompassed by the existing grammar for pseudonym."
    // cite(RFC 9110 § 7.6.3): "The received-by portion is normally the host and optional port number of a recipient server or client that subsequently forwarded the message."
    // cite(RFC 9110 § 7.6.3): "However, if the real host is considered to be sensitive information, a sender MAY replace it with a pseudonym."
    let pseudonym = scan_token(v, i);
    if pseudonym == i {
        return Err(match v.get(i) {
            None => Defect::unnamed(format!(
                "member {n} has a received-protocol and no received-by"
            )),
            // The brackets are § B.2's statement rather than the token's: the
            // production used to admit a `uri-host` and does not, so what is
            // wrong is which production the sender wrote, not which octet.
            Some(&b'[') => Defect::unnamed(format!(
                "member {n} spells its received-by as a bracketed IPv6 literal, which is not a \
                 pseudonym; RFC 9110 removed uri-host from this production, so \"[\" cannot appear \
                 in a received-by"
            )),
            Some(&b',') => Defect::unnamed(format!(
                "member {n} has a received-protocol and no received-by"
            )),
            Some(&b) => Defect::named(
                &TOKEN_EMPTY,
                format!(
                    "member {n} has a received-by beginning with {}",
                    describe_octet(b)
                ),
            ),
        });
    }
    i = pseudonym;

    // The port is whatever digits follow the colon, including none of them: the
    // production it resolves to has no lower bound and no range, so a rule that
    // reads it as a TCP port number invents both.
    // cite(RFC 9110 § 4.1): "port = <port, see [URI], Section 3.2.3>"
    // cite(RFC 3986 § 3.2.3): "The port subcomponent of authority is designated by an optional port number in decimal following the host and delimited from it by a single colon (":") character."
    if i < v.len() && v[i] == b':' {
        i += 1;
        while i < v.len() && v[i].is_ascii_digit() {
            i += 1;
        }
        if let Some(&b) = v.get(i) {
            if !ends_a_member(b) {
                return Err(Defect::named(
                    &URI_PORT_CHARACTER_FORBIDDEN,
                    format!("member {n} has a port containing {}", describe_octet(b)),
                ));
            }
        }
    } else if let Some(&b) = v.get(i) {
        if !ends_a_member(b) {
            return Err(Defect::named(
                token_character(b as char),
                format!(
                    "member {n} has a received-by containing {}",
                    describe_octet(b)
                ),
            ));
        }
    }

    // The comment is optional and, when present, is separated from the
    // `received-by` by whitespace -- so `fred(squid)` is not a member with a
    // comment, it is a pseudonym holding two octets no token admits, which the
    // check above has already reported.
    // cite(RFC 9110 § 7.6.3): "A sender MAY generate comments to identify the software of each recipient, analogous to the User-Agent and Server header fields."
    // cite(RFC 9110 § 7.6.3): "However, comments in Via are optional, and a recipient MAY remove them prior to forwarding the message."
    let after_ws = skip_ws(v, i);
    if after_ws > i && v.get(after_ws) == Some(&b'(') {
        return Ok((
            scan_comment(v, after_ws).map_err(|e| {
                Defect::named(comment_defect(e), format!("member {n}: {}", e.message()))
            })?,
            true,
        ));
    }

    Ok((i, false))
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ViaHeaderSyntax;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn headers(pairs: &[(&str, &str)]) -> hyper::HeaderMap {
        crate::test_helpers::make_headers_from_pairs(pairs)
    }

    #[rstest]
    // The three field values RFC 9110 §7.6.3 prints.
    #[case("1.0 fred, 1.1 p.example.net")]
    #[case("1.0 ricky, 1.1 ethel, 1.1 fred, 1.0 lucy")]
    #[case("1.0 ricky, 1.1 mertz, 1.0 lucy")]
    #[case("1.1 example.com")]
    #[case("HTTP/1.1 example.com")]
    #[case("HTTP/1.1 example.com, 1.0 proxy.example.com:8080")]
    #[case("1.1 example.com (cached)")]
    #[case("1.1 example.com\t(cached)")]
    // A comment is `comment`, so it nests and it escapes.
    #[case("1.1 fred (outer (inner) still-outer)")]
    #[case("1.1 fred (escaped \\) paren)")]
    // `port = *DIGIT`: no range, and no digits is a port.
    #[case("1.1 example.com:0")]
    #[case("1.1 example.com:99999")]
    #[case("1.1 example.com:")]
    // `#element => [ 1#element ]` -- a value with no member is a list of none.
    #[case("")]
    #[case("   ")]
    // OWS is permitted on both sides of the separator.
    #[case("1.1 a ,\t1.0 b")]
    fn accepts_conforming_values(#[case] v: &str) {
        assert!(validate_via(v.as_bytes()).is_ok(), "{v}");
    }

    #[rstest]
    #[case("1.1", "member 1 has a received-protocol and no received-by")]
    #[case("1.1 ", "member 1 has a received-protocol and no received-by")]
    #[case("1.1, 1.0 fred", "member 1 has a received-protocol and no received-by")]
    #[case(
        "1.1 , 1.0 fred",
        "member 1 has a received-protocol and no received-by"
    )]
    #[case(",", "member 1 is empty")]
    #[case("1.1 a, , 1.0 b", "member 2 is empty")]
    #[case("1.1 a,", "member 2 is empty")]
    #[case(", 1.1 a", "member 1 is empty")]
    #[case(
        "HT@P/1.1 example.com",
        "member 1 has a received-protocol containing '@'"
    )]
    #[case(
        "HTTP/1@1 example.com",
        "member 1 has a protocol version containing '@'"
    )]
    #[case(
        "HTTP/ example.com",
        "member 1 has an empty protocol version, with ' ' after the slash"
    )]
    #[case("HTTP/", "member 1 ends with the slash of its received-protocol")]
    #[case("1.1 example.com:port", "member 1 has a port containing 'p'")]
    #[case("1.1 example.com:80:90", "member 1 has a port containing ':'")]
    #[case("1.1 ex@mple", "member 1 has a received-by containing '@'")]
    #[case(
        "1.1 exa mple",
        "member 1 has content after its received-by, starting 'm'"
    )]
    #[case(
        "1.1 fred (a) (b)",
        "member 1 carries more than one comment, and the production permits one"
    )]
    #[case(
        "1.1 fred (a) x",
        "member 1 has content after its comment, starting 'x'"
    )]
    #[case(
        "1.1 fred (unterminated",
        "member 1: unterminated parenthesized comment"
    )]
    #[case(
        "(cached) 1.1 fred",
        "member 1 does not begin with a received-protocol, but with '('"
    )]
    fn reports_non_conforming_values(#[case] v: &str, #[case] expected: &str) {
        let err = validate_via(v.as_bytes()).expect_err(v).message;
        assert!(err.contains(expected), "{v}: got {err}");
    }

    /// RFC 9110 took `uri-host` out of `received-by`, so the one host spelling a
    /// token cannot hold is the one that lost its place in the grammar. The
    /// finding says which production is missing, not merely which octet.
    #[test]
    fn a_bracketed_ipv6_literal_is_not_a_pseudonym() {
        for v in ["1.1 [::1]", "1.1 [2001:db8::1]:8080"] {
            let err = validate_via(v.as_bytes()).expect_err(v).message;
            assert!(
                err.contains("removed uri-host from this production"),
                "{v}: got {err}"
            );
        }
    }

    /// `ctext` admits `obs-text`, so a comment may legally hold an octet outside
    /// US-ASCII -- and the same octet in a `pseudonym` is not a `tchar` and is
    /// reported there, rather than the whole field being called unreadable.
    #[test]
    fn obs_text_is_a_comment_only_licence() {
        let mut inside = b"1.1 fred (U".to_vec();
        inside.push(0xdc);
        inside.extend_from_slice(b"nix)");
        assert!(validate_via(&inside).is_ok());

        let mut outside = b"1.1 fr".to_vec();
        outside.push(0xdc);
        outside.extend_from_slice(b"ed");
        assert!(validate_via(&outside)
            .expect_err("obs-text is not a tchar")
            .message
            .contains("received-by containing 0xDC"));
    }

    /// A comma inside a comment is text. A splitter that counts parentheses
    /// without reading `quoted-pair` disagrees, and cuts this value in two.
    #[test]
    fn a_comma_inside_a_comment_is_not_a_separator() {
        assert!(validate_via(b"1.1 fred (a\\), b), 1.0 lucy").is_ok());
    }

    /// Every production this field is made of, answering with the id it
    /// answers with everywhere else: the list's empty member, both `token`s of
    /// the `received-protocol`, the `pseudonym`, RFC 3986's port, and the
    /// comment with its escape. The rows ending in `None` are the member's own
    /// assembly, which no borrowed production has a defect for.
    #[rstest]
    #[case("1.1 fred, , 1.0 lucy", Some("list_member_empty"))]
    #[case("1.1 fr@ed", Some("token_character_forbidden"))]
    #[case("1.1@ fred", Some("token_character_forbidden"))]
    #[case("(cached) 1.1 fred", Some("token_empty"))]
    #[case("1.1/ fred", Some("token_empty"))]
    #[case("1.1 fred:80x", Some("uri_port_character_forbidden"))]
    #[case("1.1 fred (unterminated", Some("comment_delimiter_missing"))]
    #[case("1.1 fred (a\\", Some("quoted_pair_malformed"))]
    #[case("1.1 [::1]", None)]
    #[case("1.1", None)]
    fn a_via_member_borrows_every_production_it_is_made_of(
        #[case] value: &str,
        #[case] id: Option<&str>,
    ) {
        let defect = judge(&headers(&[("via", value)]), "Request").expect("a finding");
        assert_eq!(defect.def.map(|def| def.id), id, "{value}");
    }

    /// The lines of one field section are one list, so a member written empty
    /// at a line boundary is an empty member -- invisible to a rule that reads
    /// each line as a value of its own.
    #[test]
    fn an_empty_member_at_a_line_boundary_is_found() {
        let hm = headers(&[("via", "1.1 fred"), ("via", "")]);
        let defect = judge(&hm, "Request").expect("an empty member");
        assert_eq!(defect.def.expect("the list's id").id, "list_member_empty");
        let err = defect.message;
        assert!(err.contains("member 2 is empty"), "got {err}");
    }

    /// The same emptiness one line down is a list of no members, which is what
    /// `#element` permits.
    #[test]
    fn a_single_empty_line_is_a_list_of_no_members() {
        assert!(judge(&headers(&[("via", "")]), "Request").is_none());
    }

    /// A second field line carries the second hop at least as often as the first
    /// line is extended, so the rule that reads `headers.get()` sees one hop of
    /// a chain and calls the message judged.
    #[test]
    fn every_field_line_is_read() {
        let hm = headers(&[("via", "1.1 fred"), ("via", "1.0 [::1]")]);
        let err = judge(&hm, "Request")
            .expect("the second line is measured too")
            .message;
        assert!(err.contains("member 2"), "got {err}");
    }

    #[test]
    fn a_value_outside_us_ascii_does_not_hide_the_field() {
        use hyper::header::HeaderValue;
        let mut hm = hyper::HeaderMap::new();
        hm.insert(
            "via",
            HeaderValue::from_bytes(b"1.1 fr\xffed").expect("a field value hyper accepts"),
        );
        let err = judge(&hm, "Request")
            .expect("the octet is reported where it sits")
            .message;
        assert!(err.contains("received-by containing 0xFF"), "got {err}");
    }

    #[test]
    fn the_finding_names_the_direction_it_is_in() -> anyhow::Result<()> {
        let rule = ViaHeaderSyntax;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let history = crate::transaction_history::TransactionHistory::empty();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = headers(&[("via", "1.1 example.com")]);
        assert!(crate::test_helpers::run_rule(&rule, &tx, &history, &cfg).is_none());

        tx.request.headers = headers(&[("via", "1.1")]);
        let v = crate::test_helpers::run_rule(&rule, &tx, &history, &cfg)
            .expect("the request field is judged");
        assert!(v.message.starts_with("Request Via header:"), "{v:?}");

        let tx = crate::test_helpers::make_test_transaction_with_response(200, &[("via", "1.1")]);
        let v = crate::test_helpers::run_rule(&rule, &tx, &history, &cfg)
            .expect("the response field is judged");
        assert!(v.message.starts_with("Response Via header:"), "{v:?}");
        Ok(())
    }

    #[test]
    fn scope_is_both() {
        let rule = ViaHeaderSyntax;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }

    #[test]
    fn published_examples_are_judged_the_way_they_are_labelled() {
        use crate::rules::Compliance;

        let mut saw_a_finding = false;
        for ex in ViaHeaderSyntax.examples() {
            // The first line is the request line and is checked to be one rather
            // than skipped: a `skip(1)` that never looks at what it dropped is
            // how a field line goes unjudged when an example is edited later.
            let mut lines = ex.snippet.lines();
            let request_line = lines.next().expect("a snippet with a request line");
            assert!(
                request_line.ends_with(" HTTP/1.1"),
                "not a request line: {request_line:?}"
            );
            let pairs: Vec<(&str, &str)> = lines
                .map(|l| {
                    l.split_once(": ")
                        .unwrap_or_else(|| panic!("not a field line: {l:?}"))
                })
                .collect();
            let found = judge(&headers(&pairs), "Request").map(|defect| defect.message);
            match ex.compliance {
                Compliance::Compliant => assert!(
                    found.is_none(),
                    "rule reports its Compliant example {:?}: {found:?}",
                    ex.snippet
                ),
                Compliance::NonCompliant => {
                    assert!(
                        found.is_some(),
                        "rule accepts its NonCompliant example {:?}",
                        ex.snippet
                    );
                    saw_a_finding = true;
                }
            }
        }
        assert!(saw_a_finding, "the guard ran without exercising a finding");
    }
}
