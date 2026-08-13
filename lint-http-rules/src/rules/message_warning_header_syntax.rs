// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::helpers::headers::{
    combined_field_value_as_written, describe_char, quoted_string_end, shown_in_finding,
    split_commas_respecting_quotes, trim_ows, unescape_quoted_string, validate_quoted_string,
};
use crate::helpers::token::find_invalid_token_char;
use crate::helpers::uri::validate_host_and_optional_port;
use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageWarningHeaderSyntax;

impl Rule for MessageWarningHeaderSyntax {
    fn id(&self) -> &'static str {
        "message_warning_header_syntax"
    }

    /// The field is not a response field, and the sentence that says so says it
    /// while naming the exception: the *codes*, not the field, are what some
    /// caches-only requirements are about.
    // cite(RFC 7234 § 5.5): "Warning header fields can in general be applied to any message, however some warn-codes are specific to caches and can only be applied to response messages."
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        // The config is read last. `parse_rule_config` is several map probes and
        // a hash of the rule id; the field probe under it is one lookup, and a
        // message carrying no `Warning` is nearly every message.
        let message = judge(&tx.request.headers, "Request").or_else(|| {
            tx.response
                .as_ref()
                .and_then(|resp| judge(&resp.headers, "Response"))
        })?;

        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
        Some(Violation {
            rule: self.id().into(),
            severity: config.severity,
            message,
        })
    }

    fn description(&self) -> &'static str {
        "Parses the `Warning` field of a request and of a response — every field line of one \
         section joined into the single list they are — against the grammar that defines it: \
         `Warning = 1#warning-value`, where \
         `warning-value = warn-code SP warn-agent SP warn-text [ SP warn-date ]`, \
         `warn-code = 3DIGIT`, `warn-agent = ( uri-host [ \":\" port ] ) / pseudonym`, \
         `warn-text = quoted-string` and `warn-date = DQUOTE HTTP-date DQUOTE`. \
         RFC 9110 §2.2 is what makes a value outside that grammar a finding.\
         \n\n\
         **The field is obsolete, and its presence is not reported.** RFC 9111 §5.5 obsoletes \
         `Warning`, and §8.1 registers it with the status `obsoleted` — but §5.5 holds no BCP 14 \
         keyword at all, so nothing there forbids a sender to write the field and nothing here \
         reports one for existing. What §5.5 also does not carry is a grammar: the last document \
         to state one is RFC 7234 §5.5, which RFC 9111 obsoleted, so this rule names both \
         documents rather than pretending the current one still defines a syntax. The \
         leaf productions RFC 7234 imported from RFC 7230 and RFC 7231 are read from RFC 9110 \
         instead, where each of them survived under its own name: `token` and `quoted-string` \
         (§5.6.2, §5.6.4), `OWS` (§5.6.3), `pseudonym` (§7.6.3), `uri-host` and `port` (§4.1, \
         reaching RFC 3986 §3.2.2 and §3.2.3), and `HTTP-date` (§5.6.7).\
         \n\n\
         Four consequences of that grammar are worth stating.\
         \n\n\
         - **The separators are single spaces.** The production writes `SP` between the parts and \
         `OWS` nowhere inside a member, so `214 example.net  \"text\"` is not two spaces' worth of \
         slack — it is a member whose `warn-agent` is empty and whose `warn-text` begins with a \
         letter. `reg-name` is `*( unreserved / pct-encoded / sub-delims )`, so a `uri-host` of no \
         characters is one and an empty `warn-agent` between the two spaces is accepted rather \
         than reported.\
         \n\
         - **A `warn-agent` is a host and optional port, or a token.** `user@example.com`, `a^b`, \
         `{a}` and `[not-an-address]` derive from neither alternative and are reported; `a|b^c` \
         and `%zz` are `token`s and are not, because the second alternative does not have to agree \
         with the first about what a character means. A \
         bracketed IPv6 literal *is* generated here, unlike in `Via`, whose identical \
         `( uri-host [ \":\" port ] ) / pseudonym` RFC 9110 §B.2 narrowed to a bare pseudonym; \
         RFC 7234's copy was never narrowed. A port is `*DIGIT` — no range and no minimum — so \
         `:0`, `:99999` and a colon with no digits after it are all syntax-conforming.\
         \n\
         - **A `warn-date` is an `HTTP-date`, and a sender may only write one of its three \
         formats.** RFC 9110 §5.6.7 requires IMF-fixdate, so the two obsolete formats are reported \
         as themselves rather than accepted or called \"not a date\". The DQUOTEs sit directly \
         against the date, so whitespace inside them is reported too: SP is `qdtext`, which makes \
         `\" Wed, 21 Oct 2015 07:28:00 GMT \"` a well-formed quoted-string holding something that \
         is not an `HTTP-date`.\
         \n\
         - **`1#` has a floor and `#` does not.** A `Warning` field value carrying no member at \
         all — an empty value, or one that is nothing but commas — is reported, because at least \
         one non-empty element is required (RFC 9110 §5.6.1.2 prints `\"\"`, `\",\"` and `\",   ,\"` \
         as the invalid values of exactly this construct). An empty member *between* two real ones \
         is a separate finding, RFC 9110 §5.6.1.1's sender MUST NOT, and a member written empty at \
         a line boundary is one of those: the lines of one section are one list.\
         \n\n\
         **What this rule does not decide.**\
         \n\n\
         - **Which `warn-code` was used.** `warn-code = 3DIGIT` is the whole of the syntax. The \
         codes are an IANA registry with its own registration procedure, and RFC 7234 §5.5's own \
         list is seven of them, so an unregistered three-digit code is not a syntax finding.\
         \n\
         - **Whether a `1xx` code was allowed to be there.** §5.5 lets a cache generate one only \
         when validating a stored response, and requires a cache to delete it after validation — \
         both are statements about what the sender is and what it just did, and no captured \
         message says either.\
         \n\
         - **Whether a `1xx` code needed a `warn-date`.** §5.5's MUST applies when the message is \
         going \"to a recipient known to implement only HTTP/1.0\". A capture records the version \
         each message *arrived under*, which is its sender's conformance (RFC 9110 §2.5) — it \
         never records the recipient's, so the antecedent has no representation here.\
         \n\
         - **Whether a `warn-date` agrees with `Date`.** §5.5's requirement there is on a \
         recipient that uses, evaluates or displays the field, and it is to exclude the \
         warning-value; nothing in it makes the disagreement the sender's defect.\
         \n\
         - **Repeated codes, and where a field line sits.** §5.5 permits multiple warnings with \
         the same `warn-code` differing only in `warn-text`, so duplicates are not counted; and \
         its MUST to append new field lines after existing ones distinguishes fields this message \
         arrived with from fields its sender added, which a capture does not record.\
         \n\
         - **A `warn-agent` holding a comma.** `,` is a `sub-delim` and so a `reg-name` character, \
         and it is also the list's separator: nothing in the field value tells the two apart. The \
         separator wins here, which is what a list parser does, and the halves are then judged as \
         members."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 7234",
                section: Some("5.5"),
                url: "https://www.rfc-editor.org/rfc/rfc7234.html#section-5.5",
                note: "The last statement of the `Warning` grammar, and the requirements about \
                       warn-codes and warn-dates that go with it. Obsoleted by RFC 9111, which \
                       removed the field rather than restating it — so this is where the \
                       productions are read from, and RFC 9111 §5.5 is where the field's status \
                       is read from",
            },
            crate::rules::SpecRef {
                spec: "RFC 9111",
                section: Some("5.5"),
                url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-5.5",
                note: "Where `Warning` is obsoleted. The section carries no BCP 14 keyword, so it \
                       states no requirement on a sender and the field's presence is not reported",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("2.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-2.2",
                note: "The sender MUST NOT behind every finding here: a value that derives from \
                       none of §5.5's productions is a protocol element matching no ABNF rule",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("5.6.1.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.1",
                note: "The list construct's sender requirement — an empty member is the finding, \
                       and §5.6.1.2's worked example is what makes an empty *value* one too, \
                       because `Warning` is `1#`",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("5.6.4"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.4",
                note: "`quoted-string`, the `qdtext` that admits `obs-text` inside a warn-text, \
                       and the recipient's handling of a `quoted-pair` — which is why a warn-date \
                       is unescaped before it is read as a date",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("5.6.7"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.7",
                note: "`HTTP-date`, and the MUST that a sender generate it in the IMF-fixdate \
                       format — the two obsolete formats parse and are still findings. This \
                       reference said §7.1.1.1, which is RFC 7231's number for it and does not \
                       exist in RFC 9110",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("7.6.3"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6.3",
                note: "`pseudonym = token`, the second alternative of `warn-agent`. RFC 7234 \
                       imported the name from RFC 7230 §5.7.1; this is where it lives now",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("B.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#appendix-B.2",
                note: "Why `Via` and `Warning` no longer agree: RFC 9110 removed `uri-host` from \
                       `received-by`, and RFC 7234's `warn-agent` — the same production — was \
                       never touched, so a bracketed IPv6 literal is a finding there and not here",
            },
            crate::rules::SpecRef {
                spec: "RFC 3986",
                section: Some("3.2.2"),
                url: "https://www.rfc-editor.org/rfc/rfc3986.html#section-3.2.2",
                note: "`host`, which `warn-agent`'s first alternative reaches through RFC 9110 \
                       §4.1 — including the `reg-name` that derives the empty string",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("§5.5.1's code, with the \"-\" §5.5 recommends when the agent is unknown"),
                snippet: "HTTP/1.1 200 OK\nWarning: 110 - \"Response is stale\"",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("A warn-agent that is a uri-host and a port"),
                snippet: "HTTP/1.1 200 OK\nWarning: 214 example.com:80 \"Transformation applied\"",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("The exchange §5.5 itself prints for the 1xx warn-date requirement"),
                snippet: "HTTP/1.1 200 OK\nDate: Sat, 25 Aug 2012 23:34:45 GMT\nWarning: 112 - \"network down\" \"Sat, 25 Aug 2012 23:34:45 GMT\"",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("A warn-agent of no characters, which `reg-name = *( ... )` generates"),
                snippet: "HTTP/1.1 200 OK\nWarning: 214  \"Transformation applied\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("A 1# list needs one non-empty member, and §5.6.1.2 prints this value as invalid"),
                snippet: "HTTP/1.1 200 OK\nWarning: ,",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("A warn-code is three digits"),
                snippet: "HTTP/1.1 200 OK\nWarning: 21a host \"text\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("A warn-text is a quoted-string"),
                snippet: "HTTP/1.1 200 OK\nWarning: 214 host text",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("\"@\" is the userinfo delimiter: no uri-host holds one, and it is not a tchar"),
                snippet: "HTTP/1.1 200 OK\nWarning: 214 user@example.com \"text\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("A warn-date that is not an HTTP-date at all"),
                snippet: "HTTP/1.1 200 OK\nWarning: 214 host \"x\" \"not-a-date\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("An RFC 850 date parses, and §5.6.7 lets a sender generate only IMF-fixdate"),
                snippet: "HTTP/1.1 200 OK\nWarning: 214 host \"x\" \"Saturday, 25-Aug-12 23:34:45 GMT\"",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &MessageWarningHeaderSyntax;

/// Judge one field section's `Warning` lines, naming the direction the finding
/// is in.
///
/// The lines are joined before anything is counted, because the members of a
/// list-based field do not belong to the line that happens to carry them — a
/// member written empty at a line boundary is an empty member. The join is over
/// the octets: `qdtext` admits `obs-text`, so a conforming `warn-text` need not
/// be visible US-ASCII, and `to_str` used to fold every such message into
/// "`Warning` header contains non-UTF8 value" — a claim about an encoding, made
/// of a value that was legal where it stood.
fn judge(headers: &hyper::HeaderMap, side: &str) -> Option<String> {
    let value = combined_field_value_as_written(headers, "warning")?;
    validate_warning(&value)
        .err()
        .map(|e| format!("{side} Warning header: {e}"))
}

/// The octet a parse stopped in front of, for the finding that says so.
///
/// Every caller has already established that the slice is not empty: the member
/// arrived `OWS`-trimmed, so no part of it can end on the SP that separates it
/// from the next one. An empty slice would mean that reasoning is wrong, and the
/// word below says so rather than hiding it behind a plausible-looking octet.
fn first_octet(s: &str) -> String {
    s.chars()
        .next()
        .map(describe_char)
        .unwrap_or_else(|| "nothing".into())
}

/// Validate a whole `Warning` field value.
// cite(RFC 9110 § 2.2): "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules."
fn validate_warning(value: &str) -> Result<(), String> {
    // cite(RFC 9110 § 5.5): "A field value does not include leading or trailing whitespace."
    let v = trim_ows(value);

    // The members are cut at the top-level commas only: a `warn-text` and a
    // `warn-date` are `quoted-string`s and may hold one as data.
    let members: Vec<&str> = split_commas_respecting_quotes(v)
        .into_iter()
        .map(trim_ows)
        .collect();

    // The cardinality character is the requirement. `Warning` is `1#`, so a
    // value with no member in it derives from nothing — which is the same
    // finding for an empty field value and for a value of nothing but commas,
    // and §5.6.1.2 prints both as invalid values of exactly this construct.
    // cite(RFC 7234 § 5.5): "Warning = 1#warning-value"
    // cite(RFC 9110 § 5.6.1.2): "In contrast, the following values would be invalid, since at least one non-empty element is required by the example-list production:"
    if members.iter().all(|m| m.is_empty()) {
        return Err(
            "the field value carries no warning-value, and `Warning = 1#warning-value` requires \
             at least one"
                .into(),
        );
    }

    for (index, member) in members.iter().enumerate() {
        let n = index + 1;

        // cite(RFC 9110 § 5.6.1.1): "In any production that uses the list construct, a sender MUST NOT generate empty list elements."
        if member.is_empty() {
            return Err(format!(
                "member {n} is empty, and a sender must not generate empty list elements"
            ));
        }

        validate_warning_value(member).map_err(|e| format!("member {n} {e}"))?;
    }

    Ok(())
}

/// Validate one `warning-value`, whose three or four parts are consumed in the
/// order the production writes them.
///
/// The separator is `SP` at each seam and the member holds no `OWS` of its own,
/// so a run of spaces is not slack: the second space of a run starts the next
/// part. That is how `214  "text"` is read — a `warn-agent` of no characters
/// between two spaces, which the first alternative generates.
// cite(RFC 7234 § 5.5): "warning-value = warn-code SP warn-agent SP warn-text [ SP warn-date ]"
fn validate_warning_value(member: &str) -> Result<(), String> {
    // `warn-code = 3DIGIT` is eighteen characters standing alone, under the
    // extractor's twenty-character floor, so the quote below is the two
    // productions as the section prints them — one under the other — and the
    // `warn-agent` half is read at [`validate_warn_agent`].
    // cite(RFC 7234 § 5.5): "warn-code = 3DIGIT warn-agent = ( uri-host [ ":" port ] ) / pseudonym"
    // cite(RFC 7234 § 5.5): "Warnings are assigned three digit warn-codes."
    let mut chars = member.char_indices();
    for _ in 0..3 {
        match chars.next() {
            Some((_, c)) if c.is_ascii_digit() => {}
            Some((_, c)) => {
                return Err(format!(
                    "has {} in its warn-code, and a warn-code is three digits",
                    describe_char(c)
                ))
            }
            None => return Err("is shorter than the three digits of a warn-code".into()),
        }
    }

    let Some((sp, c)) = chars.next() else {
        return Err("is a warn-code and nothing else".into());
    };
    if c != ' ' {
        return Err(format!(
            "has {} where the SP after its warn-code goes, so either the warn-code runs longer \
             than three digits or the parts are unseparated",
            describe_char(c)
        ));
    }

    // The SP is one octet, so the offset just past it is a character boundary.
    let rest = &member[sp + 1..];

    // Neither alternative of `warn-agent` admits a space, so the next one ends
    // it — and a member with none of them left has no `warn-text` behind it.
    let Some(agent_end) = rest.find(' ') else {
        return Err("has a warn-code and a warn-agent and no warn-text".into());
    };
    validate_warn_agent(&rest[..agent_end])?;
    let after = &rest[agent_end + 1..];

    // cite(RFC 7234 § 5.5): "warn-text = quoted-string"
    if !after.starts_with('"') {
        return Err(format!(
            "has a warn-text beginning {}, and a warn-text is a quoted-string",
            first_octet(after)
        ));
    }
    let Some(text_end) = quoted_string_end(after) else {
        return Err("has a warn-text whose quoted-string is never closed".into());
    };
    // The octets `qdtext` and `quoted-pair` between them refuse -- the controls
    // other than HTAB, and DEL -- are exactly the octets `HeaderValue` refuses to
    // hold, so no value reaching this rule can fail the call below. The check
    // stays because it is the production and the boundary belongs to a
    // dependency rather than to the grammar; a `#[test]` in this module pins
    // that dependency's answer.
    validate_quoted_string(&after[..=text_end])
        .map_err(|e| format!("has an invalid warn-text: {e}"))?;

    let tail = &after[text_end + 1..];
    if tail.is_empty() {
        return Ok(());
    }

    // cite(RFC 7234 § 5.5): "warn-date = DQUOTE HTTP-date DQUOTE"
    let Some(date) = tail.strip_prefix(' ') else {
        return Err(format!(
            "has {} after its warn-text, where the production writes either nothing or one SP and \
             a warn-date",
            first_octet(tail)
        ));
    };
    if !date.starts_with('"') {
        return Err(format!(
            "has a warn-date beginning {}, and a warn-date is an HTTP-date between two DQUOTEs",
            first_octet(date)
        ));
    }
    let Some(date_end) = quoted_string_end(date) else {
        return Err("has a warn-date whose quoted-string is never closed".into());
    };
    let remainder = &date[date_end + 1..];
    if let Some(c) = remainder.chars().next() {
        return Err(format!(
            "has {} after its warn-date, which is the last part a member has",
            describe_char(c)
        ));
    }

    validate_warn_date(&date[..=date_end])
}

/// Validate a `warn-agent`: a host with an optional port, or a pseudonym.
///
/// The alternation is decided rather than unioned. A pseudonym is a bare token
/// and a `uri-host` is not — `(`, `)`, `,`, `;` and `=` are `sub-delims` and no
/// `tchar`, the brackets belong to an IP literal alone — so a value failing both
/// is reported against the host reading, which is the one that carries a port
/// and therefore the one a `warn-agent` with a colon in it must be.
///
/// The same production is `Via`'s `received-by` before RFC 9110 §B.2 removed
/// `uri-host` from it "because it can be encompassed by the existing grammar for
/// pseudonym". It is not encompassed — a bracketed IPv6 literal has no spelling
/// as a token — which is why `message_via_header_syntax_valid` reports one and
/// this rule accepts it. RFC 7234's copy was never narrowed.
// cite(RFC 7234 § 5.5): "warn-agent = ( uri-host [ ":" port ] ) / pseudonym"
fn validate_warn_agent(agent: &str) -> Result<(), String> {
    // Reported here rather than left to the host reading below, because the
    // finding is about one octet and neither alternative admits any of them:
    // `obs-text` is outside `tchar` and outside every `uri-host` character set.
    if let Some(c) = agent.chars().find(|c| !c.is_ascii()) {
        return Err(format!(
            "has a warn-agent holding {}, which no uri-host admits and is not a tchar",
            describe_char(c)
        ));
    }

    // `reg-name` is `*( ... )`, so a host of no characters is a host and the
    // member's two spaces with nothing between them derive from the production.
    //
    // Deleting this branch would change no verdict, because
    // `find_invalid_token_char` finds no character to object to in the empty
    // string either -- and that is the reason to keep it. `token = 1*tchar` does
    // not generate the empty string; a character-class helper is never a
    // cardinality, and the acceptance below would be resting on its blind spot
    // rather than on the sentence above.
    // cite(RFC 3986 § 3.2.2): "reg-name    = *( unreserved / pct-encoded / sub-delims )"
    if agent.is_empty() {
        return Ok(());
    }

    // cite(RFC 9110 § 7.6.3): "received-by = pseudonym [ ":" port ] pseudonym = token"
    if find_invalid_token_char(agent).is_none() {
        return Ok(());
    }

    validate_host_and_optional_port(agent).map_err(|e| {
        format!(
            "has a warn-agent '{}' that is neither a pseudonym nor a host and port: {}",
            shown_in_finding(agent),
            e
        )
    })
}

/// Validate the `quoted-string` a `warn-date` is written as.
///
/// The caller enforces the two DQUOTEs; this enforces what has to sit between
/// them. What an `HTTP-date` *is* is transcribed once, in
/// `lint_http_core::http_date`, which carries the production and the sentence
/// that a recipient must accept all three of its formats — so there is no second
/// copy of either here, and the quotes below are the two things this site
/// decides on its own.
// cite(RFC 7234 § 5.5): "warn-date = DQUOTE HTTP-date DQUOTE"
fn validate_warn_date(quoted: &str) -> Result<(), String> {
    let inner =
        unescape_quoted_string(quoted).map_err(|e| format!("has an invalid warn-date: {e}"))?;

    // The DQUOTEs of `warn-date` sit directly against the `HTTP-date`, and SP is
    // `qdtext` — so a padded date is a well-formed quoted-string holding
    // something no date production generates. It is asked here because the date
    // reader trims before it parses, being written for a field *value*, where
    // §5.5's sentence puts the whitespace outside the value.
    if inner != trim_ows(&inner) {
        return Err(format!(
            "has a warn-date padded with whitespace inside its DQUOTEs: '{}'",
            shown_in_finding(&inner)
        ));
    }

    if !crate::http_date::is_valid_http_date(&inner) {
        return Err(format!(
            "has a warn-date that is not an HTTP-date: '{}'",
            shown_in_finding(&inner)
        ));
    }

    // Both obsolete formats parse, and generating either of them is the
    // sender's defect rather than the value's illegibility — which is why this
    // is a separate finding from the one above and worded as one. The first
    // sentence below is what the finding's word "obsolete" rests on: there are
    // three formats and two of them are the historical ones.
    // cite(RFC 9110 § 5.6.7): "Prior to 1995, there were three different formats commonly used by servers to communicate timestamps."
    // cite(RFC 9110 § 5.6.7): "When a sender generates a field that contains one or more timestamps defined as HTTP-date, the sender MUST generate those timestamps in the IMF-fixdate format."
    if !crate::http_date::is_valid_imf_fixdate(&inner) {
        return Err(format!(
            "has a warn-date in one of the two obsolete formats, where a sender must generate \
             IMF-fixdate: '{}'",
            shown_in_finding(&inner)
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn judged_response(value: &str) -> Option<String> {
        let tx =
            crate::test_helpers::make_test_transaction_with_response(200, &[("Warning", value)]);
        MessageWarningHeaderSyntax
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &crate::test_helpers::make_test_config_with_enabled_rules(&[
                    "message_warning_header_syntax",
                ]),
            )
            .map(|v| v.message)
    }

    #[rstest]
    #[case("110 - \"Response is stale\"")]
    #[case("214 example.com:80 \"Transformation applied\"")]
    #[case("214 example.com:80 \"X\" \"Wed, 21 Oct 2015 07:28:00 GMT\"")]
    #[case("214 example.com \"T\", 110 - \"Stale\"")]
    #[case("214 example.com \"T\" , 110 - \"Stale\"")]
    // A `warn-text` may hold the list's separator, because it is a quoted-string.
    #[case("214 example.com \"one, two\"")]
    // Both halves of the first alternative, at their edges: `port = *DIGIT` has
    // no range and no minimum, and a bracketed IP literal is a `uri-host`.
    #[case("214 example.com: \"T\"")]
    #[case("214 example.com:99999 \"T\"")]
    #[case("214 [2001:db8::1]:8080 \"T\"")]
    // A pseudonym is a token, and every one of these characters is a `tchar`.
    #[case("214 a|b^c \"T\"")]
    // `%` is a `tchar`, so a percent sign that opens no `pct-encoded` triplet is
    // still a pseudonym — the second alternative does not have to agree with the
    // first about what a `%` means.
    #[case("214 %zz \"T\"")]
    // A `uri-host` of no characters, between the production's two spaces.
    #[case("214  \"T\"")]
    fn conforming_values_are_not_reported(#[case] value: &str) {
        assert_eq!(judged_response(value), None, "reported {value:?}");
    }

    #[rstest]
    // The three values §5.6.1.2 prints as invalid for a `1#` production.
    #[case("", "carries no warning-value")]
    #[case(",", "carries no warning-value")]
    #[case(",   ,", "carries no warning-value")]
    #[case(
        "214 host \"ok\", ,214 host \"bad\"",
        "member 2 is empty, and a sender must not generate empty list elements"
    )]
    #[case("21a host \"text\"", "has 'a' in its warn-code")]
    #[case("21 host \"text\"", "has ' ' in its warn-code")]
    #[case("1", "is shorter than the three digits of a warn-code")]
    #[case("214", "is a warn-code and nothing else")]
    #[case("110-\"bad\"", "where the SP after its warn-code goes")]
    #[case("2140 host \"x\"", "where the SP after its warn-code goes")]
    #[case("214 host", "has a warn-code and a warn-agent and no warn-text")]
    #[case("214 host text", "has a warn-text beginning 't'")]
    #[case("214 host \"unclosed", "warn-text whose quoted-string is never closed")]
    #[case("214 host \"x\" extra", "has a warn-date beginning 'e'")]
    #[case(
        "214 host \"x\"extra",
        "after its warn-text, where the production writes"
    )]
    #[case(
        "214 host \"x\" \"Wed, 21 Oct 2015",
        "warn-date whose quoted-string is never closed"
    )]
    #[case(
        "214 host \"x\" \"Wed, 21 Oct 2015 07:28:00 GMT\"garbage",
        "after its warn-date, which is the last part a member has"
    )]
    #[case("214 host \"x\" \"not-a-date\"", "is not an HTTP-date")]
    fn malformed_values_are_reported(#[case] value: &str, #[case] expected: &str) {
        let message = judged_response(value).unwrap_or_else(|| panic!("accepted {value:?}"));
        assert!(
            message.contains(expected),
            "value {value:?} reported {message:?}, which does not contain {expected:?}"
        );
    }

    /// The old check asked only that a `warn-agent` hold no control character,
    /// DQUOTE or whitespace, which is not a production. None of these derives
    /// from `( uri-host [ ":" port ] ) / pseudonym`, and every one of them was
    /// clean.
    #[rstest]
    #[case("214 user@example.com \"T\"")]
    #[case("214 a\\b \"T\"")]
    #[case("214 {a} \"T\"")]
    #[case("214 <a> \"T\"")]
    #[case("214 [not-an-address] \"T\"")]
    #[case("214 example.com:80x \"T\"")]
    fn a_warn_agent_that_derives_from_neither_alternative_is_reported(#[case] value: &str) {
        let message = judged_response(value).unwrap_or_else(|| panic!("accepted {value:?}"));
        assert!(
            message.contains("neither a pseudonym nor a host and port"),
            "unexpected message for {value:?}: {message:?}"
        );
    }

    /// `qdtext` admits `obs-text`, so this member is conforming where it stands.
    /// `to_str` refuses every octet above %x7F, so the whole message used to be
    /// reported as carrying a "non-UTF8 value" — a claim about an encoding, on a
    /// value whose own production allows the octet.
    #[test]
    fn obs_text_inside_a_warn_text_is_not_a_finding() {
        use hyper::header::HeaderValue;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers.append(
            "Warning",
            HeaderValue::from_bytes(b"214 example.com \"caf\xe9\"")
                .expect("obs-text is legal here"),
        );
        assert_eq!(
            judge(&tx.response.as_ref().unwrap().headers, "Response"),
            None
        );
    }

    /// The same octet in a `warn-agent` is a finding, and the finding names the
    /// octet the sender wrote rather than the encoding it is not part of.
    #[test]
    fn obs_text_inside_a_warn_agent_is_reported_as_the_octet_it_is() {
        use hyper::header::HeaderValue;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers.append(
            "Warning",
            HeaderValue::from_bytes(b"214 exa\xe9mple.com \"T\"").expect("obs-text is legal here"),
        );
        let message = judge(&tx.response.as_ref().unwrap().headers, "Response")
            .expect("an obs-text octet in a warn-agent is a finding");
        assert!(
            message.contains("0xE9") && message.contains("is not a tchar"),
            "unexpected message: {message:?}"
        );
        assert!(
            !message.contains("UTF"),
            "the finding is not about an encoding"
        );
    }

    /// The lines of one section are one list, so a member written empty at a
    /// line boundary is an empty member and not an empty field value.
    #[test]
    fn two_field_lines_are_one_list() {
        use hyper::header::HeaderValue;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("Warning", "214 example.com \"T\"")],
        );
        tx.response
            .as_mut()
            .unwrap()
            .headers
            .append("Warning", HeaderValue::from_static(""));
        let message = judge(&tx.response.as_ref().unwrap().headers, "Response")
            .expect("the second line contributes an empty member");
        assert!(message.contains("member 2 is empty"), "got {message:?}");
    }

    /// Both obsolete formats parse as an `HTTP-date`, and §5.6.7's MUST is what
    /// makes generating one a finding — reported as itself, not as "not a date".
    #[rstest]
    #[case("Saturday, 25-Aug-12 23:34:45 GMT")]
    #[case("Sat Aug 25 23:34:45 2012")]
    fn an_obsolete_date_format_in_a_warn_date_is_reported(#[case] date: &str) {
        let value = format!("214 example.com \"T\" \"{date}\"");
        let message = judged_response(&value).unwrap_or_else(|| panic!("accepted {value:?}"));
        assert!(
            message.contains("one of the two obsolete formats"),
            "got {message:?}"
        );
    }

    /// `warn-date` writes its DQUOTEs against the `HTTP-date`; the date reader
    /// trims, being written for a field value, so the padding is asked about
    /// here.
    #[test]
    fn a_warn_date_padded_inside_its_quotes_is_reported() {
        let message = judged_response("214 example.com \"T\" \" Wed, 21 Oct 2015 07:28:00 GMT\"")
            .expect("padding inside the DQUOTEs is a finding");
        assert!(
            message.contains("padded with whitespace"),
            "got {message:?}"
        );
    }

    /// A `quoted-pair` is handled as the octet after the backslash, so an
    /// escaped date is the date.
    #[test]
    fn a_warn_date_written_with_quoted_pairs_is_the_date_it_unescapes_to() {
        assert_eq!(
            judged_response("214 example.com \"T\" \"\\W\\e\\d, 21 Oct 2015 07:28:00 GMT\""),
            None
        );
    }

    /// RFC 7234 §5.5's own worked example, the one it prints for the 1xx
    /// warn-date requirement.
    #[test]
    fn the_sections_own_worked_example_is_clean() {
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[
                ("Date", "Sat, 25 Aug 2012 23:34:45 GMT"),
                (
                    "Warning",
                    "112 - \"network down\" \"Sat, 25 Aug 2012 23:34:45 GMT\"",
                ),
            ],
        );
        assert!(MessageWarningHeaderSyntax
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &crate::test_helpers::make_test_config_with_enabled_rules(&[
                    "message_warning_header_syntax",
                ]),
            )
            .is_none());
    }

    #[test]
    fn a_request_warning_is_read_and_named_as_one() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers.insert(
            "Warning",
            "214 example.com \"OK\""
                .parse::<hyper::header::HeaderValue>()
                .unwrap(),
        );
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_warning_header_syntax",
        ]);
        let history = crate::transaction_history::TransactionHistory::empty();
        assert!(MessageWarningHeaderSyntax
            .check_transaction(&tx, &history, &cfg)
            .is_none());

        tx.request.headers.insert(
            "Warning",
            "110-\"bad\"".parse::<hyper::header::HeaderValue>().unwrap(),
        );
        let message = MessageWarningHeaderSyntax
            .check_transaction(&tx, &history, &cfg)
            .expect("a malformed request Warning is a finding")
            .message;
        assert!(
            message.starts_with("Request Warning header:"),
            "got {message:?}"
        );
    }

    #[test]
    fn a_message_with_no_warning_is_not_read() {
        let tx = crate::test_helpers::make_test_transaction();
        assert!(MessageWarningHeaderSyntax
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &crate::test_helpers::make_test_config_with_enabled_rules(&[
                    "message_warning_header_syntax",
                ]),
            )
            .is_none());
    }

    /// The quoted-string checks in this rule answer a question no input can
    /// pose: `qdtext` and `quoted-pair` refuse the controls other than HTAB and
    /// refuse DEL, and `HeaderValue` refuses to hold those octets at all. The
    /// boundary is the dependency's, so it is pinned here rather than assumed —
    /// a `HeaderValue` that started accepting them would make the checks live
    /// again, and one that stopped accepting `obs-text` would take a conforming
    /// `warn-text` away from the rule.
    #[test]
    fn a_warn_text_defect_below_obs_text_cannot_reach_this_rule() {
        use hyper::header::HeaderValue;
        for octet in [0x00u8, 0x07, 0x1f, 0x7f] {
            assert!(
                HeaderValue::from_bytes(&[b'"', octet, b'"']).is_err(),
                "HeaderValue accepted {octet:#04X}, which quoted-string refuses"
            );
        }
        assert!(
            HeaderValue::from_bytes(&[b'"', b'\t', 0xe9, b'"']).is_ok(),
            "HTAB and obs-text are qdtext, and a capture has to be able to carry them"
        );
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_warning_header_syntax",
        ]);
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn scope_is_both() {
        assert_eq!(
            MessageWarningHeaderSyntax.scope(),
            crate::rules::RuleScope::Both
        );
    }

    /// Nothing runs a rule's own `examples()` through the engine, so a
    /// `Compliant` value the rule rejects is published as guidance.
    #[test]
    fn published_examples_are_judged_the_way_they_are_labelled() {
        use crate::rules::Compliance;
        let mut saw_a_finding = false;
        for ex in MessageWarningHeaderSyntax.examples() {
            let mut lines = ex.snippet.lines();
            let start = lines.next().expect("an example has a start line");
            assert!(
                start.starts_with("HTTP/"),
                "this guard files an example's fields onto the response: {start:?}"
            );
            let fields: Vec<(&str, &str)> = lines
                .filter(|l| !l.trim().is_empty())
                .map(|l| {
                    l.split_once(": ")
                        .unwrap_or_else(|| panic!("not a header line: {l:?}"))
                })
                .collect();
            let tx = crate::test_helpers::make_test_transaction_with_response(200, &fields);
            let found = judge(&tx.response.as_ref().unwrap().headers, "Response");
            match ex.compliance {
                Compliance::Compliant => assert!(
                    found.is_none(),
                    "rule reports its Compliant example {:?}: {found:?}",
                    ex.snippet
                ),
                Compliance::NonCompliant => {
                    found.unwrap_or_else(|| {
                        panic!("rule accepts its NonCompliant example {:?}", ex.snippet)
                    });
                    saw_a_finding = true;
                }
            }
        }
        assert!(saw_a_finding, "no published example produced a finding");
    }
}
