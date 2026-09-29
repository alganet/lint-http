// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::delta_seconds::{
    DELTA_SECONDS_CHARACTER_FORBIDDEN, DELTA_SECONDS_EMPTY, RFC_9111_1_2_2,
};
use crate::violations::field::{FIELD_LINE_DUPLICATED, RFC_9110_5_3};
use crate::violations::quoted_pair::QUOTED_PAIR_MALFORMED;
use crate::violations::quoted_string::{
    quoted_string_defect, QUOTED_STRING_CONTROL_CHARACTER_FORBIDDEN,
    QUOTED_STRING_DELIMITER_MISSING, QUOTED_STRING_QUOTE_ESCAPE_MISSING, RFC_9110_5_6_4,
};
use crate::violations::strict_transport_security::{
    RFC_6797_6_1, RFC_6797_6_1_1, RFC_6797_6_1_2, RFC_6797_7_2,
    STRICT_TRANSPORT_SECURITY_DIRECTIVE_DUPLICATED, STRICT_TRANSPORT_SECURITY_DIRECTIVE_EMPTY,
    STRICT_TRANSPORT_SECURITY_DIRECTIVE_VALUE_FORBIDDEN,
    STRICT_TRANSPORT_SECURITY_DIRECTIVE_VALUE_MISSING, STRICT_TRANSPORT_SECURITY_EMPTY,
    STRICT_TRANSPORT_SECURITY_FORBIDDEN, STRICT_TRANSPORT_SECURITY_MAX_AGE_MISSING,
};
use crate::violations::token::{
    token_character, RFC_9110_5_6_2, TOKEN_CHARACTER_FORBIDDEN, TOKEN_EMPTY,
    TOKEN_WHITESPACE_OR_CONTROL_FORBIDDEN,
};
use crate::violations::ViolationDef;

pub struct StrictTransportSecurityValid;

/// Six defects over two subjects, borrowed from a document RFC 6797 does not
/// name — and the reading that says it may be.
///
/// § 6.1 imports both productions from RFC 2616 § 2.2 by reference:
/// `directive-name = token`, `directive-value = token | quoted-string`. RFC
/// 2616's `token` is RFC 9110's `tchar` set, which is the judgment
/// `Sec-WebSocket-Extensions` reached from its own grammar — 2616 subtracts its
/// separators and CTLs from `CHAR`, and what is left is `tchar`. So the two
/// `token` entries transfer with nothing to decide.
///
/// **The `quoted-string` half genuinely differs, and half of the difference can
/// now arrive.** RFC 2616 writes `quoted-pair = "\" CHAR`, which admits an
/// escaped control octet § 5.6.4 refuses and refuses the `obs-text` § 5.6.4
/// admits. The escaped CTL still cannot reach this rule — a control octet does
/// not enter a `hyper::HeaderValue` — but the `obs-text` one does, because the
/// value is no longer read through `to_str`: it is read as the octets the sender
/// wrote, so `foo="a\<%xFF>"` reaches [`check_quoted_string`](crate::helpers::quoted_string::check_quoted_string) and is accepted
/// under § 5.6.4 where RFC 2616's production would refuse it. **That is an
/// under-report of one octet class in a superseded document's grammar, and it is
/// the deliberate answer**: § 5.6.4 is the escape a recipient applies today, and
/// no finding here claims otherwise. A backslash before the closing DQUOTE
/// escapes it, so `foo="ab\"` is an unterminated string —
/// `quoted_string_delimiter_missing` — and not a dangling escape; `\"` is a
/// `quoted-pair` in either document. The reader is what decides this, which is
/// why it is written down beside the ids rather than at the site.
///
/// `quoted_pair_malformed` and `quoted_string_control_character_forbidden` are
/// declared and unreachable for the one reason that survives an octet-wise read:
/// a control octet cannot enter a `hyper::HeaderValue`, whatever the rule does
/// with it afterwards.
static DECLARED: &[&ViolationDef] = &[
    &FIELD_LINE_DUPLICATED,
    &STRICT_TRANSPORT_SECURITY_EMPTY,
    &STRICT_TRANSPORT_SECURITY_DIRECTIVE_EMPTY,
    &STRICT_TRANSPORT_SECURITY_MAX_AGE_MISSING,
    &STRICT_TRANSPORT_SECURITY_DIRECTIVE_DUPLICATED,
    &STRICT_TRANSPORT_SECURITY_DIRECTIVE_VALUE_MISSING,
    &STRICT_TRANSPORT_SECURITY_DIRECTIVE_VALUE_FORBIDDEN,
    &STRICT_TRANSPORT_SECURITY_FORBIDDEN,
    &DELTA_SECONDS_EMPTY,
    &DELTA_SECONDS_CHARACTER_FORBIDDEN,
    &TOKEN_EMPTY,
    &TOKEN_CHARACTER_FORBIDDEN,
    &TOKEN_WHITESPACE_OR_CONTROL_FORBIDDEN,
    &QUOTED_STRING_DELIMITER_MISSING,
    &QUOTED_PAIR_MALFORMED,
    &QUOTED_STRING_QUOTE_ESCAPE_MISSING,
    &QUOTED_STRING_CONTROL_CHARACTER_FORBIDDEN,
];

/// The sender's once-only rule for the field, stated by the field's own
/// document rather than inferred from § 5.3's exception clause. § 6.1's grammar
/// already puts the field outside that exception — the directives are
/// semicolon-separated and no alternative of the production is a comma list —
/// but § 7.1 says the same thing about the field lines directly, which is why
/// this rule cites both and not only the general sentence.
const RFC_6797_7_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 6797",
    section: Some("7.1"),
    url: "https://www.rfc-editor.org/rfc/rfc6797.html#section-7.1",
    note: "HTTP-over-Secure-Transport Request Type — the sentence obliging an \
           HSTS Host that includes the field to include only one of it",
};

/// What the recipient does with the second line, and the reason this finding
/// does not talk about recombination. § 5.2 joins repeated field lines with a
/// comma within a section, and for most singleton fields that joined value is
/// the hazard; here no recipient ever builds it. A UA takes the first line and
/// drops the rest, so the sender's second policy is not misread — it is not
/// read.
const RFC_6797_8_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 6797",
    section: Some("8.1"),
    url: "https://www.rfc-editor.org/rfc/rfc6797.html#section-8.1",
    note: "Strict-Transport-Security Response Header Field Processing — the UA \
           processes only the first of several STS header fields",
};

impl RuleMeta for StrictTransportSecurityValid {
    fn id(&self) -> &'static str {
        "strict_transport_security_valid"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn description(&self) -> &'static str {
        "The `Strict-Transport-Security` response header signals HSTS policies. This rule ensures responses include the required `max-age` directive (a non-negative integer) and that optional directives `includeSubDomains` and `preload` are present without values. Unknown directives are accepted but any value must be a `token` or `quoted-string`. The value is read as the octets the sender wrote, so an octet outside the `token` alphabet is reported where it lands rather than as an encoding verdict about the whole field.\\n\\n**The field may be written only once.** RFC 6797 §7.1: *\"If an STS header field is included, the HSTS Host MUST include only one such header field\"* — and §6.1's directives are semicolon-separated, so no alternative of the production is a comma-separated list and RFC 9110 §5.3's exception does not reach the field. What a recipient does about it is not §5.2's recombination: §8.1 has a UA *\"process only the first such header field\"*, so a second line is discarded rather than joined, and the policy in force is whichever one the server emitted first. The finding names every line, because which one is first is the whole answer."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_6797_6_1,
            RFC_6797_6_1_1,
            RFC_6797_6_1_2,
            RFC_6797_7_1,
            RFC_6797_7_2,
            RFC_6797_8_1,
            RFC_9110_5_3,
            RFC_9111_1_2_2,
            RFC_9110_5_6_2,
            RFC_9110_5_6_4,
        ]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::Presumed(crate::lint::Party::Server)
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "Strict-Transport-Security: max-age=0",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("— the quoted-string form § 6.1.1 unescapes before reading"),
                snippet: "Strict-Transport-Security: max-age=\"63072000\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— missing `max-age`"),
                snippet: "Strict-Transport-Security: includeSubDomains",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— `max-age` not numeric"),
                snippet: "Strict-Transport-Security: max-age=abc",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— `max-age` requires a value, though the grammar makes one optional"),
                snippet: "Strict-Transport-Security: max-age; includeSubDomains",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— one directive, written twice in one policy"),
                snippet: "Strict-Transport-Security: max-age=100; max-age=200",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some(
                    "— every directive appears once, a flag as much as `max-age`, and names fold",
                ),
                snippet: "Strict-Transport-Security: max-age=31536000; includeSubDomains; includesubdomains",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— a policy with nothing in it"),
                snippet: "Strict-Transport-Security:",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— `includeSubDomains` must not have a value"),
                snippet: "Strict-Transport-Security: max-age=63072000; includeSubDomains=1",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— a trailing `;` opens a directive the sender never wrote"),
                snippet: "Strict-Transport-Security: max-age=15552000;",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("— the transport the policy is about, stated by the request-target"),
                snippet: "GET https://example.com/ HTTP/1.1\nHost: example.com\n\nHTTP/1.1 200 OK\nStrict-Transport-Security: max-age=63072000",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some(
                    "— a policy on a response the request never secured; a UA ignores it, so the host is not protected at all",
                ),
                snippet: "GET http://example.com/ HTTP/1.1\nHost: example.com\n\nHTTP/1.1 200 OK\nStrict-Transport-Security: max-age=63072000; includeSubDomains",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some(
                    "— two policies, of which a UA reads the ten-minute one and discards the other",
                ),
                snippet: "HTTP/1.1 200 OK\nStrict-Transport-Security: max-age=600\nStrict-Transport-Security: max-age=15724800; includeSubDomains",
            },
        ]
    }
}

impl Rule for StrictTransportSecurityValid {
    fn needs_response(&self) -> bool {
        true
    }

    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // Single-finding body behind an Option: `?` ends it early, and the
        // one finding (or none) becomes the vector.
        let finding = || -> Vec<Violation> {
            // Only applicable to responses
            let Some(resp) = tx.response.as_ref() else {
                return Vec::new();
            };

            // A malformed STS header is not a weaker policy — the UA drops it whole and the
            // host is not treated as Known HSTS, so every syntax check below enforces this MUST.
            // cite(RFC 6797 § 6.1): "UAs MUST ignore any STS header field containing directives, or other header field value data, that does not conform to the syntax defined in this specification."
            // Read as the octets the sender wrote. A `directive-name` is a
            // `token`, so an octet no `tchar` admits is the production's defect
            // and reports under the id below; inside a `directive-value`'s
            // `quoted-string` it is `qdtext`, which admits `obs-text`, so the
            // string reader was refusing a value this field generates.
            let lines = crate::helpers::headers::field_lines_as_written(
                &resp.headers,
                "strict-transport-security",
            );

            // **The second line is not read by anyone**, and that is what makes
            // this worth a finding of its own rather than the general untidiness
            // of a repeated field. § 6.1's directives are semicolon-separated,
            // so no alternative of the production is a comma list and § 5.3's
            // exception does not apply; § 7.1 then says the same thing about
            // this field directly. What a recipient does about it is § 8.1's
            // sentence, and it is not § 5.2's recombination — a UA takes the
            // first line and discards the rest, so the policy in force is
            // whichever one the server happened to emit first and the other one
            // is not a weaker policy but no policy. The finding names every line
            // for that reason: which one is first is the whole answer, and an
            // operator reading it needs to see that the line they meant is the
            // one being dropped.
            // cite(RFC 6797 § 7.1): "If an STS header field is included, the HSTS Host MUST include only one such header field."
            // cite(RFC 6797 § 8.1): "If a UA receives more than one STS header field in an HTTP response message over secure transport, then the UA MUST process only the first such header field."
            // cite(RFC 9110 § 5.3): "a sender MUST NOT generate multiple field lines with the same name in a message (whether in the headers or trailers) or append a field line when a field line of the same name already exists in the message, unless that field's definition allows multiple field line values to be recombined as a comma-separated list"
            if lines.len() > 1 {
                let shown: Vec<String> = lines
                    .iter()
                    .map(|l| {
                        format!(
                            "'{}'",
                            crate::helpers::shown::shown_in_finding(
                                crate::helpers::headers::trim_ows(l)
                            )
                        )
                    })
                    .collect();
                return vec![ctx.report_with(
                    &FIELD_LINE_DUPLICATED,
                    format!(
                        "Strict-Transport-Security is written on {} header lines ({}); \
                         the field is a singleton — `[ directive ] *( \";\" [ directive ] )` \
                         has no comma-separated-list alternative — so an HSTS Host that \
                         includes it must include only one (RFC 6797 §7.1). A UA processes \
                         only the first, so every later line is discarded rather than \
                         combined (RFC 6797 §8.1)",
                        lines.len(),
                        shown.join(", ")
                    ),
                )];
            }

            // Exactly one line past the check above, which returns on two or
            // more: `Strict-Transport-Security` is a singleton and a second
            // line is `field_line_duplicated`'s subject rather than a second
            // policy to judge.
            let Some(line) = lines.into_iter().next() else {
                return Vec::new();
            };
            {
                let v = crate::helpers::headers::trim_ows(&line);

                // Unnamed, and the grammar is the reason. § 6.1 writes
                // `[ directive ] *( ";" [ directive ] )`, so the empty value
                // derives — this finding is the rule saying a policy that
                // declares nothing is not a policy, which is a statement about
                // this field and not about a production it broke.
                if v.is_empty() {
                    return vec![ctx.report(&STRICT_TRANSPORT_SECURITY_EMPTY)];
                }

                let mut saw_max_age = false;
                // Every directive name the walk read, as written, so a name
                // given twice is seen whatever case each is spelled in.
                let mut names: Vec<&str> = Vec::new();
                let mut empty_directives = 0usize;
                // One finding per directive. `[ directive ] *( ";" [ directive ] )`
                // writes them beside each other rather than inside each other,
                // so a policy naming two of them badly is two things to
                // correct, and the walk over them stopped at the first. Each
                // directive's own reading is still a chain: a name that is not
                // a token and a value that is no `directive-value` are two
                // readings of one directive, and the second reads text the
                // first has already condemned.
                let mut out = Vec::new();

                for member in crate::helpers::list::split_semicolons_respecting_quotes(v) {
                    let member = crate::helpers::headers::trim_ows(member);
                    // **Not `list_member_empty`.** That def carries § 5.6.1.1's
                    // MUST NOT against an empty element of a `#` list, and this
                    // is not one: the members are semicolon-separated by this
                    // field's own production, whose optional brackets *generate*
                    // the empty one. The rule refuses it anyway and that is its
                    // own claim, which is the same shape of refusal
                    // `Sec-WebSocket-Extensions` made about RFC 2616's list.
                    //
                    // Recorded and stepped over rather than returned on. A
                    // separator states nothing about the directives around it,
                    // and the one directive this field is required to carry is
                    // looked for only after the whole value has been read.
                    if member.is_empty() {
                        empty_directives += 1;
                        continue;
                    }
                    if let Some((def, message)) =
                        directive_defect(member, &mut saw_max_age, &mut names)
                    {
                        out.push(ctx.report_with(def, message));
                    }
                }

                // Every directive, and not only the one whose two values
                // disagree: the sentence counts appearances. One finding per
                // name, whichever spellings it came in.
                // cite(RFC 6797 § 6.1): "All directives MUST appear only once in an STS header field."
                // cite(RFC 6797 § 6.1): "Directive names are case-insensitive."
                for (i, name) in names.iter().enumerate() {
                    let first = names[..i].iter().all(|n| !n.eq_ignore_ascii_case(name));
                    let times = names
                        .iter()
                        .filter(|n| n.eq_ignore_ascii_case(name))
                        .count();
                    if first && times > 1 {
                        out.push(ctx.report_with(
                            &STRICT_TRANSPORT_SECURITY_DIRECTIVE_DUPLICATED,
                            format!(
                                "Strict-Transport-Security writes the '{name}' directive {times} times, and every directive MUST appear only once"
                            ),
                        ));
                    }
                }

                // Ahead of the separator finding below, and the ranks are
                // the reason. This is a MUST § 6.1.1 states, and § 6.1 gives it
                // teeth by having the user agent ignore the entire field: a
                // policy with no `max-age` is not a weaker policy but no policy,
                // and the deployment reading the report believes it has one. The
                // empty directive is this rule's own claim against a member the
                // § 6.1 grammar derives, which is not a thing to repair inside a
                // field already discarded.
                if !saw_max_age {
                    // Still ahead of the separator finding, and still instead
                    // of it rather than beside it: the ranks are the argument
                    // above and unmasking the walk does not touch them. What
                    // the walk collected stands, because a directive whose
                    // value derives from nothing is a defect in what the sender
                    // wrote and is worth correcting alongside the missing
                    // `max-age` rather than behind it.
                    //
                    // The value, because the deployed shape of this is a
                    // `max-age` misspelled into a directive of another name,
                    // and a sentence that only says the directive is absent
                    // hides the one character the repair is.
                    out.push(ctx.report_with(
                        &STRICT_TRANSPORT_SECURITY_MAX_AGE_MISSING,
                        format!(
                            "Strict-Transport-Security '{}' has no 'max-age' directive, the one \
                             RFC 6797 \u{a7}6.1.1 requires, so it states no duration for a user \
                             agent to note the host for",
                            crate::helpers::shown::shown_in_finding(v)
                        ),
                    ));
                } else if empty_directives > 0 {
                    // The value and the count, because the one-line sentence
                    // this was named neither: an operator reading it could not
                    // tell a trailing `;` from a doubled one in the middle, and
                    // every one on the web is the first.
                    let what = if empty_directives == 1 {
                        "an empty directive, a ';' with nothing on one side of it".to_string()
                    } else {
                        format!(
                            "{empty_directives} empty directives, each a ';' with nothing on one \
                             side of it"
                        )
                    };
                    out.push(ctx.report_with(
                        &STRICT_TRANSPORT_SECURITY_DIRECTIVE_EMPTY,
                        format!(
                            "Strict-Transport-Security '{v}' has {what}; RFC 6797 \u{a7}6.1's \
                             grammar admits it, and the policy reads the same with the stray ';' \
                             removed"
                        ),
                    ));
                }

                out
            }
        };
        // Beside what the value reading collected, and ahead of it. The two
        // are independent repairs: a policy in the wrong place is still
        // spelled however it is spelled, and the same spelling is on the
        // `https` responses this transaction cannot see. Masking either with
        // the other would send an operator to make one of two edits.
        let mut out = policy_on_unsecured_transport(tx, ctx);
        out.extend(finding());
        out
    }
}

/// The one thing this rule reads about the *response's place* rather than
/// about its value: whether a policy was sent at all on a transaction the
/// request-target says was not secured.
///
/// **Ahead of every other reading here, and not instead of any of them.**
/// § 7.2's sentence is about the field being present, so it is answered before
/// the value is looked at and it does not depend on the value being well
/// formed — a malformed policy on an `http` response is in the wrong place
/// *and* misspelled, and the sender has two edits to make. A repeated field
/// draws this too, for the same reason: `field_line_duplicated` returns early
/// out of the value reading, and a policy written twice on a response that may
/// not carry one at all is still a policy that may not be carried.
///
/// **The third answer of [`target_uri_security`] is why this is a function and
/// not a comparison.** Only an absolute-form request-target states a scheme.
/// An origin-form target carries a path, an authority-form one a host, and
/// over HTTP/1.1 to an origin server that is the ordinary shape — so a
/// reading spelled "not `https`" condemns most of the web on the strength of
/// evidence it does not have. [`ConnectionSecurity::is_known_insecure`] is the
/// question that has an answer here, and `Unstated` is a silence this rule
/// owes rather than a verdict it withholds.
///
// cite(RFC 6797 § 7.2): "An HSTS Host MUST NOT include the STS header field in HTTP responses conveyed over non-secure transport."
// cite(RFC 6797 § 8.1): "If an HTTP response is received over insecure transport, the UA MUST ignore any present STS header field(s)."
fn policy_on_unsecured_transport(
    tx: &crate::http_transaction::HttpTransaction,
    ctx: &crate::rules::RuleContext<'_>,
) -> Vec<Violation> {
    let Some(resp) = tx.response.as_ref() else {
        return Vec::new();
    };
    if !crate::helpers::request_target::target_uri_security(&tx.request.uri).is_known_insecure() {
        return Vec::new();
    }
    let lines =
        crate::helpers::headers::field_lines_as_written(&resp.headers, "strict-transport-security");
    if lines.is_empty() {
        return Vec::new();
    }
    // The value is named because the operator has to find the line, and it is
    // named whole rather than summarised: what is wrong with it is not
    // anything inside it, so there is no component to point at. Several lines
    // are shown as several, because a sender that writes two of them on an
    // `http` response has written two things that must not be there.
    let shown: Vec<String> = lines
        .iter()
        .map(|l| {
            format!(
                "'{}'",
                crate::helpers::shown::shown_in_finding(crate::helpers::headers::trim_ows(l))
            )
        })
        .collect();
    vec![ctx.report_with(
        &STRICT_TRANSPORT_SECURITY_FORBIDDEN,
        format!(
            "Strict-Transport-Security ({}) is sent on a response to an http:// \
             request; an HSTS Host must not include the field over non-secure \
             transport (RFC 6797 §7.2) and a user agent ignores any it receives \
             there (§8.1), so this policy is not in force. Send it on the https \
             responses instead, and redirect this request to https",
            shown.join(", ")
        ),
    )]
}

/// What is wrong with one `directive`, if anything, and what it tells the
/// policy about its `max-age`.
///
/// Split out of the walk above rather than written inside it: the walk stopped
/// at its first defective directive, and one that keeps going spells every
/// finding as a `continue` where it used to spell them `return` — the same
/// reading in a control-flow shape nobody can follow, and past the closure's
/// complexity ceiling on that alone.
fn directive_defect<'a>(
    member: &'a str,
    saw_max_age: &mut bool,
    names: &mut Vec<&'a str>,
) -> Option<(&'static crate::violations::ViolationDef, String)> {
    // **Not `list_member_empty`.** That def carries § 5.6.1.1's
    // MUST NOT against an empty element of a `#` list, and this
    // is not one: the members are semicolon-separated by this
    // field's own production, whose optional brackets *generate*
    // the empty one. The rule refuses it anyway and that is its
    // own claim, which is the same shape of refusal
    // `Sec-WebSocket-Extensions` made about RFC 2616's list.
    //
    // Recorded and stepped over rather than returned on. A
    // separator states nothing about the directives around it,
    // and the one directive this field is required to carry is
    // looked for only after the whole value has been read — so
    // ending the scan here answers a policy that never states a
    // `max-age` with the stray `;` it also happens to contain.

    // directive = token [ "=" token ]
    let mut kv = member.splitn(2, '=');
    let name = crate::helpers::headers::trim_ows(kv.next().unwrap());
    if name.is_empty() {
        return Some((
            &TOKEN_EMPTY,
            format!(
                "Empty directive name in Strict-Transport-Security directive '{}'",
                crate::helpers::shown::shown_in_finding(member)
            ),
        ));
    }

    // The statement below is RFC 6797's and stays: *this
    // field's* directive name is a token, which is what licenses
    // borrowing the subject at all. What moves onto the two defs
    // is the sentence saying what a token is — § 5.6.2's
    // `token = 1*tchar`, the character set RFC 2616's derives too.
    // cite(RFC 6797 § 6.1): "directive-name            = token"
    if let Some(c) = crate::helpers::token::find_invalid_token_char(name) {
        return Some((token_character(c), format!("Strict-Transport-Security directive '{}' has a name containing an invalid character: {}", crate::helpers::shown::shown_in_finding(member), crate::helpers::shown::describe_char(c))));
    }

    names.push(name);
    let lname = name.to_ascii_lowercase();
    match lname.as_str() {
        // max-age is REQUIRED (enforced by the `saw_max_age` check after the loop)
        // and its value is a count of seconds, i.e. all-digits (checked below).
        "max-age" => {
            *saw_max_age = true;
            // must have a value
            let Some(vpart) = kv.next() else {
                return Some((
                    &STRICT_TRANSPORT_SECURITY_DIRECTIVE_VALUE_MISSING,
                    "Strict-Transport-Security 'max-age' must have a value".into(),
                ));
            };
            let vpart = crate::helpers::headers::trim_ows(vpart);
            // Either alternative of `directive-value`, and the
            // digits are asked of what the alternative carries.
            // § 6.1.1 defines the value "after quoted-string
            // unescaping, if necessary", so `max-age="31536000"`
            // is the policy `max-age=31536000` is: the quote is
            // the form's delimiter and not a character in the
            // count, and a reader that measured it against
            // `tchar` reported a conforming policy for how it
            // was spelled.
            // cite(RFC 6797 § 6.1): "directive-value           = token | quoted-string"
            // cite(RFC 6797 § 6.1.1): "The syntax of the max-age directive's REQUIRED value (after quoted-string unescaping, if necessary) is defined as:"
            let unquoted: String;
            let digits: &str = if vpart.starts_with('"') {
                match crate::helpers::quoted_string::unescape_quoted_string(vpart) {
                    Ok(inner) => {
                        unquoted = inner;
                        unquoted.as_str()
                    }
                    Err(defect) => {
                        return Some((quoted_string_defect(defect), format!("Invalid quoted-string in Strict-Transport-Security 'max-age' value: {}", defect.message(vpart))));
                    }
                }
            } else {
                // Asked before the digits, and answered by the
                // catalogue: a `directive-value` is a `token` or
                // a `quoted-string` whatever the directive means
                // by it, so an octet no `tchar` admits is the
                // production's defect and not `max-age`'s.
                if let Some(c) = crate::helpers::token::find_invalid_token_char(vpart) {
                    return Some((
                        token_character(c),
                        format!(
                            "Strict-Transport-Security 'max-age' contains invalid character: {}",
                            crate::helpers::shown::describe_char(c)
                        ),
                    ));
                }
                vpart
            };
            if digits.is_empty() {
                return Some((
                    &DELTA_SECONDS_EMPTY,
                    "Strict-Transport-Security 'max-age' must have a numeric value".into(),
                ));
            }
            // The sign of `-1` and the point of `1.5` are the
            // production's defect and answer under its id,
            // whichever field imported it.
            if digits.chars().any(|ch| !ch.is_ascii_digit()) {
                return Some((
                    &DELTA_SECONDS_CHARACTER_FORBIDDEN,
                    "Strict-Transport-Security 'max-age' must be a non-negative integer".into(),
                ));
            }
            // A run of digits too long for a `u64` used to be
            // reported here as "not a valid integer", and it is
            // not a defect at all: `delta-seconds` sets no
            // ceiling and a recipient meeting a value it cannot
            // hold is told to clamp it, so such a policy is
            // conforming and what could not hold it was this
            // reader. The `delta_seconds` subject records the
            // same reading, and refuses the entry for the same
            // reason.
        }
        "includesubdomains" => {
            // canonical name is includeSubDomains, but accept case-insensitively
            // must NOT have a value (it is "valueless" per §6.1.2)
            if kv.next().is_some() {
                return Some((
                    &STRICT_TRANSPORT_SECURITY_DIRECTIVE_VALUE_FORBIDDEN,
                    "Strict-Transport-Security 'includeSubDomains' directive must not have a value"
                        .into(),
                ));
            }
        }
        // `preload` is not an RFC 6797 directive — it is a de-facto extension (the
        // browser HSTS preload list), the kind §6.1 anticipates being "defined in
        // other specifications". Its valueless form is convention, so no 6797 quote
        // governs this branch; it is validated like a known valueless directive.
        "preload" => {
            if kv.next().is_some() {
                return Some((
                    &STRICT_TRANSPORT_SECURITY_DIRECTIVE_VALUE_FORBIDDEN,
                    "Strict-Transport-Security 'preload' directive must not have a value".into(),
                ));
            }
        }
        _ => {
            // Unknown directives: allow but ensure if a value is present it is token or quoted-string
            // cite(RFC 6797 § 6.1): "directive-value           = token | quoted-string"
            if let Some(vpart) = kv.next() {
                let vpart = crate::helpers::headers::trim_ows(vpart);
                if vpart.starts_with('"') {
                    if let Err(defect) = crate::helpers::quoted_string::check_quoted_string(vpart) {
                        return Some((quoted_string_defect(defect), format!("Invalid quoted-string in Strict-Transport-Security directive value: {}", defect.message(vpart))));
                    }
                } else if let Some(c) = crate::helpers::token::find_invalid_token_char(vpart) {
                    return Some((token_character(c), format!("Strict-Transport-Security directive '{}' value contains invalid character: {}", name, crate::helpers::shown::describe_char(c))));
                }
            }
        }
    }

    None
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &StrictTransportSecurityValid;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// **On an `https` target, and the default is why that has to be said.**
    /// `make_test_transaction` builds a request to `http://example/`, which is
    /// absolute-form with an insecure scheme — the one record on which a
    /// perfectly spelled policy is still a defect. Every row below is about
    /// the *value*, so the fixture states a transport on which the value is
    /// the only thing left to be wrong about. `on_target` is where the other
    /// reading is tested.
    fn make_resp(val: &str) -> crate::http_transaction::HttpTransaction {
        let mut tx = on_target("https://example/", val);
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[(
                "strict-transport-security",
                val,
            )]),

            body_length: None,
            body_interrupted: false,
            trailers: None,
        });
        tx
    }

    /// One transaction, with the request-target and the policy both stated.
    fn on_target(target: &str, val: &str) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.uri = target.to_string();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[(
                "strict-transport-security",
                val,
            )]),
            body_length: None,
            body_interrupted: false,
            trailers: None,
        });
        tx
    }

    /// Every id this rule draws on one transaction, not the first of them.
    fn ids(tx: &crate::http_transaction::HttpTransaction) -> Vec<String> {
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "strict_transport_security_valid",
        ]);
        let mut out: Vec<String> = crate::test_helpers::run_rule_all(
            &StrictTransportSecurityValid,
            tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .into_iter()
        .map(|v| v.violation)
        .collect();
        out.sort();
        out
    }

    /// § 7.2's requirement is answered from the request-target and from
    /// nothing else, so the rows here are the three answers a target has —
    /// and the third one is the reason there are three. An origin-form target
    /// is what an ordinary HTTP/1.1 request to an origin server carries, and
    /// a reading spelled "not https" reports every one of them on evidence it
    /// does not have. The policy is conforming in every row, so the id below
    /// is the only one that can appear.
    #[rstest]
    #[case::absolute_http("http://example.com/", true)]
    #[case::absolute_http_uppercase("HTTP://example.com/", true)]
    #[case::absolute_https("https://example.com/", false)]
    #[case::absolute_https_uppercase("HTTPS://example.com/", false)]
    #[case::origin_form("/index.html", false)]
    #[case::authority_form("example.com:443", false)]
    #[case::asterisk_form("*", false)]
    #[case::a_scheme_this_document_does_not_define("ftp://example.com/", false)]
    #[case::a_scheme_named_in_the_query_only("/login?next=http://evil.example/", false)]
    fn a_policy_is_forbidden_where_the_target_states_an_insecure_scheme(
        #[case] target: &str,
        #[case] forbidden: bool,
    ) {
        let got = ids(&on_target(target, "max-age=63072000; includeSubDomains"));
        assert_eq!(
            got.contains(&"strict_transport_security_forbidden".to_string()),
            forbidden,
            "target: {target}, drew: {got:?}"
        );
    }

    /// Beside the value findings and not instead of them. This is the value
    /// one origin serves on plain `http`: a hyphen where the `=` goes, so no
    /// directive named `max-age` is written at all. The two are separate
    /// edits — the field is in the wrong place, and the spelling is still
    /// wrong on the `https` responses this transaction cannot see — so an
    /// operator who is told only one of them makes one of two changes.
    #[test]
    fn a_misplaced_policy_and_a_misspelled_one_are_two_findings() {
        let tx = on_target(
            "http://example.com/",
            "max-age-16000000; includeSubDomains; preload;",
        );
        assert_eq!(
            ids(&tx),
            vec![
                "strict_transport_security_forbidden".to_string(),
                "strict_transport_security_max_age_missing".to_string(),
            ]
        );
    }

    /// A repeated field over insecure transport draws both too, and this is
    /// the row that holds the ordering: the value reading returns early on a
    /// second line, so a transport check written inside it would never be
    /// reached here.
    #[test]
    fn a_policy_written_twice_where_it_may_not_be_written_at_all_draws_both() {
        let mut tx = on_target("http://example.com/", "max-age=1");
        if let Some(resp) = tx.response.as_mut() {
            resp.headers = crate::test_helpers::make_headers_from_pairs(&[
                ("strict-transport-security", "max-age=1"),
                ("strict-transport-security", "max-age=2"),
            ]);
        }
        assert_eq!(
            ids(&tx),
            vec![
                "field_line_duplicated".to_string(),
                "strict_transport_security_forbidden".to_string(),
            ]
        );
    }

    #[rstest]
    #[case("max-age=63072000", false)]
    #[case("max-age=0", false)]
    #[case("max-age=63072000; includeSubDomains; preload", false)]
    #[case("max-age=\"63072000\"", false)]
    #[case("max-age=\"63072000\"; includeSubDomains; preload", false)]
    #[case("includeSubDomains", true)]
    #[case("max-age=abc", true)]
    #[case("max-age=\"abc\"", true)]
    #[case("max-age=\"\"", true)]
    #[case("max-age=\"63072000", true)]
    #[case("max-age=63072000; includeSubDomains=1", true)]
    #[case("max-age=63072000; preload=1", true)]
    #[case("max-age=63072000; max-age=1", true)]
    fn cases(#[case] val: &str, #[case] expect_violation: bool) -> anyhow::Result<()> {
        let rule = StrictTransportSecurityValid;
        let tx = make_resp(val);
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "strict_transport_security_valid",
        ]);
        let got = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .is_some();
        assert_eq!(got, expect_violation, "value: {}", val);
        Ok(())
    }

    /// Every finding, with the sentence it says it in and the defect it reports
    /// as. The named rows are the two productions § 6.1 imports and does not
    /// define; the empty ones are RFC 6797's own policy — that a policy
    /// declaring nothing is not one, that `max-age` counts seconds and is
    /// required, that two directives are valueless, and that a directive
    /// appears once.
    #[rstest]
    #[case::empty_value("", "must not be empty", "strict_transport_security_empty")]
    #[case::empty_directive(
        "max-age=1;;preload",
        "'max-age=1;;preload' has an empty directive",
        "strict_transport_security_directive_empty"
    )]
    #[case::empty_directives_counted(
        "; max-age=1;",
        "'; max-age=1;' has 2 empty directives",
        "strict_transport_security_directive_empty"
    )]
    #[case::empty_name("max-age=1; =2", "Empty directive name", "token_empty")]
    #[case::name_character(
        "max-age=1; pre@load",
        "has a name containing an invalid character",
        "token_character_forbidden"
    )]
    #[case::max_age_character(
        "max-age=1@2",
        "'max-age' contains invalid",
        "token_character_forbidden"
    )]
    #[case::max_age_not_a_number(
        "max-age=1.5",
        "non-negative integer",
        "delta_seconds_character_forbidden"
    )]
    #[case::max_age_empty("max-age=", "must have a numeric value", "delta_seconds_empty")]
    #[case::max_age_quoted_empty(
        "max-age=\"\"",
        "must have a numeric value",
        "delta_seconds_empty"
    )]
    #[case::max_age_quoted_not_a_number(
        "max-age=\"1.5\"",
        "non-negative integer",
        "delta_seconds_character_forbidden"
    )]
    #[case::max_age_quoted_unterminated(
        "max-age=\"63072000",
        "'max-age' value",
        "quoted_string_delimiter_missing"
    )]
    #[case::max_age_valueless(
        "max-age",
        "must have a value",
        "strict_transport_security_directive_value_missing"
    )]
    #[case::include_subdomains_valued(
        "max-age=1; includeSubDomains=1",
        "must not have a value",
        "strict_transport_security_directive_value_forbidden"
    )]
    #[case::preload_valued(
        "max-age=1; preload=1",
        "must not have a value",
        "strict_transport_security_directive_value_forbidden"
    )]
    #[case::value_character(
        "max-age=1; foo=b@r",
        "value contains invalid",
        "token_character_forbidden"
    )]
    #[case::unterminated_quote(
        "max-age=1; foo=\"bar",
        "Invalid quoted-string",
        "quoted_string_delimiter_missing"
    )]
    #[case::unescaped_quote(
        "max-age=1; foo=\"a\"b\"",
        "Invalid quoted-string",
        "quoted_string_quote_escape_missing"
    )]
    #[case::escaped_final_quote(
        "max-age=1; foo=\"ab\\\"",
        "Invalid quoted-string",
        "quoted_string_delimiter_missing"
    )]
    #[case::repeated_max_age(
        "max-age=1; max-age=2",
        "'max-age' directive 2 times",
        "strict_transport_security_directive_duplicated"
    )]
    #[case::repeated_flag(
        "max-age=1; includeSubDomains; includeSubDomains",
        "'includeSubDomains' directive 2 times",
        "strict_transport_security_directive_duplicated"
    )]
    #[case::repeated_in_two_cases(
        "max-age=1; preload; PRELOAD",
        "'preload' directive 2 times",
        "strict_transport_security_directive_duplicated"
    )]
    #[case::missing_max_age(
        "includeSubDomains",
        "'includeSubDomains' has no 'max-age'",
        "strict_transport_security_max_age_missing"
    )]
    fn each_finding_reports_the_production_it_belongs_to(
        #[case] value: &str,
        #[case] expected: &str,
        #[case] violation: &str,
    ) {
        let finding = crate::test_helpers::run_rule(
            &StrictTransportSecurityValid,
            &make_resp(value),
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "strict_transport_security_valid",
            ]),
        )
        .unwrap_or_else(|| panic!("expected a finding for {value:?}"));
        assert!(
            finding.message.contains(expected),
            "for {value:?}: {:?}",
            finding.message
        );
        assert_eq!(finding.violation, violation, "for {value:?}");
    }

    /// Every finding one `Strict-Transport-Security` value draws.
    fn all_sts(value: &str) -> Vec<Violation> {
        crate::test_helpers::run_rule_all(
            &StrictTransportSecurityValid,
            &make_resp(value),
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "strict_transport_security_valid",
            ]),
        )
    }

    /// **Every defective directive of one policy is answered.**
    /// `[ directive ] *( ";" [ directive ] )` writes them beside each other,
    /// so a policy naming two badly is two things to correct and a walk that
    /// stopped at the first named one.
    #[test]
    fn every_defective_directive_is_reported() {
        let found = all_sts("max-age=10; includeSubDomains=1; preload=2");
        assert_eq!(found.len(), 2, "{found:?}");
        assert!(found
            .iter()
            .all(|v| v.violation == "strict_transport_security_directive_value_forbidden"));
        assert_ne!(found[0].message, found[1].message);
    }

    /// Two directives whose names carry the same forbidden octet are two
    /// sentences that can be told apart, because each names the directive.
    #[test]
    fn two_bad_directive_names_name_their_own() {
        let found = all_sts("max-age=1; pre@load; inc@ude");
        assert_eq!(found.len(), 2, "{found:?}");
        assert_ne!(found[0].message, found[1].message);
    }

    /// A policy that states no `max-age` still reports the directives that
    /// derive from nothing, and still answers the separator with the missing
    /// duration rather than beside it — the rank the comment at that site
    /// argues for, which unmasking the walk does not touch.
    #[test]
    fn a_policy_with_no_max_age_keeps_its_rank_and_its_directive_findings() {
        let found = all_sts("includeSubDomains=1; preload;");
        assert_eq!(
            found
                .iter()
                .map(|v| v.violation.as_str())
                .collect::<Vec<_>>(),
            vec![
                "strict_transport_security_directive_value_forbidden",
                "strict_transport_security_max_age_missing",
            ],
            "{found:?}"
        );
    }

    /// The other direction: the policy nearly every origin in the wild sends
    /// draws nothing at all.
    /// The finding quotes the policy it read. A `max-age` misspelled into
    /// another directive's name is the shape this takes on the web, and the
    /// sentence is the only place an operator can see the character that
    /// has to change.
    #[rstest]
    #[case("max-age-16000000; includeSubDomains; preload;")]
    #[case("includeSubDomains")]
    #[case("maxage=600")]
    fn the_missing_duration_is_named_with_the_policy_it_is_missing_from(#[case] value: &str) {
        let found = all_sts(value);
        let missing = found
            .iter()
            .find(|v| v.violation == "strict_transport_security_max_age_missing")
            .expect("a max-age finding");
        assert!(
            missing.message.starts_with(&format!(
                "Strict-Transport-Security '{value}' has no 'max-age'"
            )),
            "{}",
            missing.message
        );
    }

    #[test]
    fn a_conforming_policy_is_silent() {
        assert!(all_sts("max-age=31536000; includeSubDomains; preload").is_empty());
    }

    /// A separator is not an answer to a policy that states no duration.
    ///
    /// `max-age` is looked for only once the whole value has been read, so a
    /// scan that ends at the first empty member never reaches the question. The
    /// shape that makes this matter is deployed: a `max-age` misspelled with a
    /// hyphen is a well-formed unknown directive § 6.1 says to ignore, which
    /// leaves the field carrying no duration at all, and such a field is one the
    /// user agent discards whole — while the trailing `;` beside it is a member
    /// the § 6.1 grammar derives and this rule refuses on its own authority, at
    /// `info`, citing nothing. The deployment reading that answer is told about
    /// the semicolon and not that it has no HSTS.
    #[rstest]
    #[case::hyphen_for_equals_and_a_trailing_separator(
        "max-age-16000000; includeSubDomains; preload;",
        "strict_transport_security_max_age_missing"
    )]
    #[case::no_duration_behind_a_trailing_separator(
        "includeSubDomains;",
        "strict_transport_security_max_age_missing"
    )]
    #[case::a_separator_leads_the_value(
        "; includeSubDomains",
        "strict_transport_security_max_age_missing"
    )]
    // The separator still answers for itself when the policy is otherwise whole,
    // which is every one of these the field carries in practice.
    #[case::a_whole_policy_keeps_its_separator_finding(
        "max-age=31536000;",
        "strict_transport_security_directive_empty"
    )]
    #[case::a_whole_policy_keeps_it_mid_value(
        "max-age=31536000;; includeSubDomains",
        "strict_transport_security_directive_empty"
    )]
    // And a defect written after the separator is now read rather than hidden
    // behind it.
    #[case::a_directive_past_the_separator_is_still_read(
        "max-age=1;; includeSubDomains=2",
        "strict_transport_security_directive_value_forbidden"
    )]
    fn an_empty_member_does_not_end_the_search_for_the_required_directive(
        #[case] value: &str,
        #[case] violation: &str,
    ) {
        let finding = crate::test_helpers::run_rule(
            &StrictTransportSecurityValid,
            &make_resp(value),
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "strict_transport_security_valid",
            ]),
        )
        .unwrap_or_else(|| panic!("expected a finding for {value:?}"));
        assert_eq!(finding.violation, violation, "for {value:?}");
    }

    /// A directive name is a `token` here and in every other field, and RFC
    /// 6797 taking the production from RFC 2616 changes nothing about the
    /// octet: 2616 subtracts its separators and CTLs from `CHAR`, and what is
    /// left is `tchar`. Asserted against a rule reading a field defined by
    /// RFC 9110 itself, which shares no code with this one.
    #[test]
    fn a_directive_name_is_a_token_under_either_document() {
        let here = crate::test_helpers::run_rule(
            &StrictTransportSecurityValid,
            &make_resp("max-age=1; pre@load"),
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "strict_transport_security_valid",
            ]),
        )
        .expect("a finding");
        let elsewhere = crate::test_helpers::run_rule(
            &crate::rules::vary_header_valid::VaryHeaderValid,
            &crate::test_helpers::make_test_transaction_with_response(200, &[("vary", "b@d")]),
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&["vary_header_valid"]),
        )
        .expect("a finding");

        assert_eq!(here.violation, elsewhere.violation);
        assert_ne!(here.message, elsewhere.message);
    }

    /// The one place RFC 2616's `quoted-pair` and RFC 9110's disagree — an
    /// escaped control octet, which 2616 admits and § 5.6.4 refuses — cannot
    /// arrive, because the reader this rule uses does not admit the octet at
    /// all. That is what makes borrowing the def safe here rather than a claim
    /// about a sentence the field's document does not use.
    #[test]
    fn the_two_documents_disagreement_cannot_reach_this_rule() {
        use hyper::header::HeaderValue;
        assert!(HeaderValue::from_bytes(b"max-age=1; foo=\"a\x01b\"").is_err());
        // `to_str` is what the rule reads through, and it refuses `obs-text`
        // too -- the other half of the disagreement, in the other direction.
        let obs = HeaderValue::from_bytes(b"max-age=1; foo=\"a\\\xe9b\"").expect("a value");
        assert!(obs.to_str().is_err());
    }

    #[test]
    fn non_utf8_header_is_violation() {
        use hyper::header::HeaderValue;
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut headers = crate::test_helpers::make_headers_from_pairs(&[]);
        headers.append(
            "strict-transport-security",
            HeaderValue::from_bytes(b"max-age=1\xFF" as &[u8]).unwrap(),
        );
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers,

            body_length: None,
            body_interrupted: false,
            trailers: None,
        });
        let rule = StrictTransportSecurityValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "strict_transport_security_valid",
        ]);
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .is_some());
    }

    #[test]
    fn empty_value_is_violation() {
        let rule = StrictTransportSecurityValid;
        let tx = make_resp("");
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "strict_transport_security_valid",
        ]);
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .is_some());
    }

    #[test]
    fn trailing_semicolon_reports_empty_directive() {
        let rule = StrictTransportSecurityValid;
        let tx = make_resp("max-age=1;");
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "strict_transport_security_valid",
        ]);
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .is_some());
    }

    #[test]
    fn unknown_directive_with_bad_quoted_string_reports_violation() {
        let rule = StrictTransportSecurityValid;
        let tx = make_resp("max-age=1; foo=\"unterminated");
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "strict_transport_security_valid",
        ]);
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .is_some());
    }

    #[test]
    fn unknown_directive_with_invalid_token_value_reports_violation() {
        let rule = StrictTransportSecurityValid;
        let tx = make_resp("max-age=1; bar=bad@val");
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "strict_transport_security_valid",
        ]);
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .is_some());
    }

    #[test]
    fn unknown_directive_with_quoted_string_is_ok() {
        let rule = StrictTransportSecurityValid;
        let tx = make_resp("max-age=1; foo=\"valid\"");
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "strict_transport_security_valid",
        ]);
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .is_none());
    }

    #[test]
    fn max_age_empty_value_is_violation() {
        let rule = StrictTransportSecurityValid;
        let tx = make_resp("max-age=");
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "strict_transport_security_valid",
        ]);
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .is_some());
    }

    #[test]
    fn max_age_without_equals_is_violation() {
        let rule = StrictTransportSecurityValid;
        let tx = make_resp("max-age");
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "strict_transport_security_valid",
        ]);
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .is_some());
    }

    /// `directive-value = token | quoted-string`, and § 6.1.1 reads `max-age`'s
    /// value after unescaping the quoted form. The quote is the alternative's
    /// delimiter, so a policy spelled this way is the same policy, and a test
    /// here used to hold the opposite.
    #[test]
    fn max_age_quoted_is_the_same_policy() {
        let rule = StrictTransportSecurityValid;
        let tx = make_resp("max-age=\"3600\"");
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "strict_transport_security_valid",
        ]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none(), "{v:?}");
    }

    #[test]
    fn directive_name_with_invalid_char_is_violation() {
        let rule = StrictTransportSecurityValid;
        let tx = make_resp("ma x=1");
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "strict_transport_security_valid",
        ]);
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .is_some());
    }

    #[test]
    fn unknown_directive_with_token_value_is_ok() {
        let rule = StrictTransportSecurityValid;
        let tx = make_resp("max-age=1; foo=bar");
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "strict_transport_security_valid",
        ]);
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .is_none());
    }

    #[test]
    fn include_subdomains_case_insensitive_is_ok() {
        let rule = StrictTransportSecurityValid;
        let tx = make_resp("max-age=1; IncludeSubDomains");
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "strict_transport_security_valid",
        ]);
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .is_none());
    }

    /// A second line lacking `max-age` is not a policy without a lifetime, and
    /// this is the row that says so. § 8.1 has the UA process only the first
    /// field, so the deployed policy here is the complete `max-age=1` and the
    /// line that declares no lifetime is one nothing reads — reporting
    /// `strict_transport_security_max_age_missing` about it would name a defect
    /// of no policy in force. The repetition is what is wrong with the message,
    /// and it is what the rule says.
    #[test]
    fn a_line_nobody_reads_is_not_a_policy_missing_its_lifetime() {
        // On an `https` target: what is read here is the value, and the
        // fixture's default target is absolute-form `http`, on which a policy
        // is forbidden outright and would be the first finding.
        let mut tx = on_target("https://example/", "max-age=1");
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[
                ("strict-transport-security", "max-age=1"),
                ("strict-transport-security", "includeSubDomains"),
            ]),

            body_length: None,
            body_interrupted: false,
            trailers: None,
        });
        let rule = StrictTransportSecurityValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "strict_transport_security_valid",
        ]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .expect("a finding");
        assert_eq!(v.violation, "field_line_duplicated");
    }

    #[test]
    fn an_obs_text_octet_lands_where_the_grammar_puts_it() {
        use hyper::header::HeaderValue;

        let rule = StrictTransportSecurityValid;

        // In a directive name it is a `token` defect, with the octet named.
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        // As above: a value reading needs a transport on which the value is
        // the only thing left to be wrong about.
        tx.request.uri = "https://example/".to_string();
        let mut hm = hyper::HeaderMap::new();
        hm.insert(
            "strict-transport-security",
            HeaderValue::from_bytes(b"max-age=1; inc\xffude").expect("a field line"),
        );
        tx.response.as_mut().expect("a response").headers = hm;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .expect("a finding");
        assert_eq!(v.violation, "token_character_forbidden");
        assert_eq!(
            v.message,
            "Strict-Transport-Security directive 'inc\u{ff}ude' has a name containing an invalid character: 0xFF"
        );

        // Inside a quoted-string it is `qdtext`, which admits it: the string
        // reader used to report the whole header for an octet the production
        // generates.
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.request.uri = "https://example/".to_string();
        let mut hm = hyper::HeaderMap::new();
        hm.insert(
            "strict-transport-security",
            HeaderValue::from_bytes(b"max-age=1; ext=\"caf\xe9\"").expect("a field line"),
        );
        tx.response.as_mut().expect("a response").headers = hm;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none(), "{v:?}");
    }

    /// Two policies on one response, and the finding names both — because
    /// which one is first decides which one is deployed, and the operator
    /// reading the report is looking for the line that is being dropped.
    ///
    /// The single-line row is the other direction and is the reason this test
    /// is not one assertion: a check that reported every policy would satisfy
    /// the first half and make the entry useless.
    #[test]
    fn two_policy_lines_are_reported_and_one_is_not() {
        let rule = StrictTransportSecurityValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let history = crate::transaction_history::TransactionHistory::empty();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        // As above: `https`, so the repetition is the only thing being read.
        tx.request.uri = "https://example/".to_string();
        tx.response.as_mut().expect("a response").headers =
            crate::test_helpers::make_headers_from_pairs(&[
                ("strict-transport-security", "max-age=600"),
                (
                    "strict-transport-security",
                    "max-age=15724800; includeSubDomains",
                ),
            ]);
        let v = crate::test_helpers::run_rule(&rule, &tx, &history, &cfg).expect("a finding");
        assert_eq!(v.violation, "field_line_duplicated");
        assert!(
            v.message.contains("'max-age=600'")
                && v.message.contains("'max-age=15724800; includeSubDomains'"),
            "both lines are named: {}",
            v.message
        );

        // The discarded line is the second one, and both policies here are
        // well formed on their own — so nothing but the repetition is wrong,
        // and one line of the same shape says nothing.
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.request.uri = "https://example/".to_string();
        tx.response.as_mut().expect("a response").headers =
            crate::test_helpers::make_headers_from_pairs(&[(
                "strict-transport-security",
                "max-age=15724800; includeSubDomains",
            )]);
        let v = crate::test_helpers::run_rule(&rule, &tx, &history, &cfg);
        assert!(v.is_none(), "{v:?}");
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "strict_transport_security_valid");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
