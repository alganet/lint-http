// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageAcceptHeaderMediaTypeSyntax;

impl Rule for MessageAcceptHeaderMediaTypeSyntax {
    fn id(&self) -> &'static str {
        "message_accept_header_media_type_syntax"
    }

    // `Both`, because the rule reads a response's Accept as well as a
    // request's, and §12.5.1 gives that one a meaning of its own rather than
    // treating it as a stray request field. The label said `Client` while the
    // code checked both directions; dispatch is unaffected (only `Server` is
    // filtered), so this corrects what the rule *says* it looks at.
    // cite(RFC 9110 § 12.5.1): "The "Accept" header field can be used by user agents to specify their preferences regarding response media types."
    // cite(RFC 9110 § 12.5.1): "When sent by a server in a response, Accept provides information about which content types are preferred in the content of a subsequent request to the same resource."
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
        // The list grammar, and the one production every branch below is a
        // piece of. A member is a media-range and at most one weight; the
        // media-range carries the parameters.
        // cite(RFC 9110 § 12.5.1): "Accept = #( media-range [ weight ] )"
        // cite(RFC 9110 § 12.5.1): "Each media-range might be followed by optional applicable media type parameters (e.g., charset), followed by an optional "q" parameter for indicating a relative weight (Section 12.4.2)."
        let check_val = |hdr: &str, val: &str| -> Option<Violation> {
            // Quote-aware, because a comma inside a quoted parameter value is
            // not a list separator. A raw `split(',')` cut such a value in half
            // and handed the halves on as members, so `text/html;foo="a,b"` —
            // a conforming header — was reported for the malformed
            // quoted-string the splitting had just created. An unbalanced quote
            // is still reported, and reported here: this is the rule that owns
            // a malformed Accept, so it names the defect rather than declining.
            for member in crate::helpers::headers::split_commas_respecting_quotes(val) {
                let member = member.trim();
                // An empty list element is legal for a recipient to ignore, and
                // ignoring it is all this rule does with it. The production
                // brackets each element, so `a, , b` conforms.
                // cite(RFC 9110 § 5.6.1.2): "#element => [ element ] *( OWS "," OWS [ element ] )"
                // cite(RFC 9110 § 5.6.1.2): "Empty elements do not contribute to the count of elements present."
                if member.is_empty() {
                    continue;
                }
                // Quote-aware for the same reason: a `;` inside a quoted value
                // does not start a parameter.
                let mut parts =
                    crate::helpers::headers::split_semicolons_respecting_quotes(member).into_iter();
                let media = parts.next().unwrap_or("").trim();
                // A member that is all parameters has no media-range to carry
                // them: `[ weight ]` is optional, the media-range is not.
                if media.is_empty() {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!("Empty media-range in {} header", hdr),
                    });
                }

                // No whitespace inside a media-range. The member has already
                // been trimmed at both ends, so anything left is interior, and
                // `media-range` admits none: the OWS in these grammars sits
                // around list elements and around the `;` before a parameter,
                // never between a type and its subtype. `text /html` used to
                // pass, because the helper trims each half before returning it
                // and the space vanished before any check could see it.
                // cite(RFC 9110 § 5.6.2): "Tokens are short textual identifiers that do not include whitespace or delimiters."
                if media.contains(char::is_whitespace) {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!(
                            "Invalid media-range '{}' in {} header: whitespace inside a media-range",
                            media, hdr
                        ),
                    });
                }

                // Three shapes, and a bare asterisk is none of them. The
                // asterisk stands for a whole type or a whole subtype; on its
                // own it names neither side of a pair the grammar requires.
                // cite(RFC 9110 § 12.5.1): "media-range    = ( "*/*" / ( type "/" "*" ) / ( type "/" subtype ) ) parameters"
                // cite(RFC 9110 § 12.5.1): "The asterisk "*" character is used to group media types into ranges, with "*/*" indicating all media types and "type/*" indicating all subtypes of that type."
                if media == "*" {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!("Invalid media-range '*' in {} header", hdr),
                    });
                }

                if media == "*/*" {
                    // wildcard is valid, but still validate params
                } else {
                    // must contain '/'
                    if !media.contains('/') {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!(
                                "Invalid media-range '{}' in {} header: missing '/'",
                                media, hdr
                            ),
                        });
                    }

                    // Both halves are `token`, which is what these checks
                    // enforce; the subtype is exempted when it is the literal
                    // asterisk, since that is the wildcard rather than a name.
                    // (Quoted as the whole production block: either half on its
                    // own is under apycite's 20-character floor for evidence.)
                    // cite(RFC 9110 § 8.3.1): "media-type = type "/" subtype parameters type       = token subtype    = token"
                    if let Ok(parsed) = crate::helpers::headers::parse_media_type(media) {
                        if let Some(c) =
                            crate::helpers::token::find_invalid_token_char(parsed.type_)
                        {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: format!(
                                    "Invalid token '{}' in media type '{}' of {}",
                                    c, parsed.type_, hdr
                                ),
                            });
                        }
                        // A wildcard type with a concrete subtype is not one of
                        // the shapes the asterisk has a meaning in. This is a
                        // judgement about the prose, not a reading of the ABNF:
                        // `type` is a `token` and `*` is a `tchar`, so `*/json`
                        // does derive from `type "/" subtype`. But §12.5.1 gives
                        // the asterisk exactly two jobs — all media types, or
                        // all subtypes of one type — and this is neither, so
                        // there is nothing a recipient could match it against.
                        // `message_content_type_well_formed` takes the same
                        // position on the same shape in Content-Type.
                        if parsed.type_ == "*" {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: format!(
                                    "Invalid media-range '{}' in {} header: a wildcard type is only meaningful with a wildcard subtype ('*/*'), since the asterisk names all media types or all subtypes of one type and nothing else",
                                    media, hdr
                                ),
                            });
                        }
                        if parsed.subtype != "*" {
                            if let Some(c) =
                                crate::helpers::token::find_invalid_token_char(parsed.subtype)
                            {
                                return Some(Violation {
                                    rule: self.id().into(),
                                    severity: config.severity,
                                    message: format!(
                                        "Invalid token '{}' in media subtype '{}' of {}",
                                        c, parsed.subtype, hdr
                                    ),
                                });
                            }
                        }
                    } else {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!("Invalid media-range '{}' in {} header", media, hdr),
                        });
                    }
                }

                // Validate parameters (name=value). 'q' must be a valid qvalue
                let mut weight_seen = false;
                for p in parts {
                    let p = p.trim();
                    if p.is_empty() {
                        continue;
                    }
                    // The weight closes the member. `Accept = #( media-range
                    // [ weight ] )` puts it after the media-range, and the
                    // media-range is what carries the parameters, so a
                    // parameter after `q=` derives from nothing in this
                    // grammar. RFC 9110 removed the production that used to
                    // allow it and states the consequence as a SHOULD.
                    // cite(RFC 9110 § 12.5.1): "The accept extension grammar (accept-params, accept-ext) has been removed because it had a complicated definition, was not being used in practice, and is more easily deployed through new header fields."
                    // cite(RFC 9110 § 12.5.1): "Senders using weights SHOULD send "q" last (after all media-range parameters)."
                    if weight_seen {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!(
                                "Parameter '{}' follows the weight in {} header: the weight closes a media-range, and the extension parameters that once came after it were removed from the grammar",
                                p, hdr
                            ),
                        });
                    }
                    // A parameter is a name, an "=", and a value; none of the
                    // three is optional, so a bare word among the parameters is
                    // not a parameter with a missing value but not a parameter
                    // at all. The split and the two `OWS` trims are the shared
                    // walk's; the whitespace beside the `=` it hands back is
                    // this rule's published leniency, read and dropped here so
                    // that the paragraph saying so is a statement about the code.
                    let Some(parsed) = crate::helpers::headers::parameter_of(p) else {
                        continue;
                    };
                    let parsed = match parsed {
                        Ok(parsed) => parsed,
                        Err(crate::helpers::headers::ParameterDefect::NoEquals(_)) => {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: format!(
                                    "Invalid parameter '{}' in {} header: missing '='",
                                    p, hdr
                                ),
                            })
                        }
                    };
                    let _ = parsed.whitespace_beside_equals;
                    let k = parsed.name;
                    let v = parsed.value;
                    // `token = 1*tchar`, so a name with no characters is not a
                    // name. Scanning for an invalid character cannot see this:
                    // an empty string has no invalid character in it, and
                    // `; =value` passed on exactly that reasoning.
                    // (`token = 1*tchar` is under apycite's 20-character floor
                    // on its own; §5.6.2's sentence carries the same point and
                    // covers the whitespace check above as well.)
                    // cite(RFC 9110 § 5.6.6): "parameter-name  = token"
                    // cite(RFC 9110 § 5.6.2): "Tokens are short textual identifiers that do not include whitespace or delimiters."
                    if k.is_empty() {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!(
                                "Empty parameter name in '{}' of {} header: a token is one or more characters",
                                p, hdr
                            ),
                        });
                    }
                    if let Some(c) = crate::helpers::token::find_invalid_token_char(k) {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!(
                                "Invalid character '{}' in parameter name '{}' in {} header",
                                c, k, hdr
                            ),
                        });
                    }

                    // The weight's name is matched without regard to case
                    // because §12.4.2 defines it that way, and it is looked for
                    // among all the parameters because §12.5.1 tells recipients
                    // to find it wherever it sits.
                    // cite(RFC 9110 § 12.4.2): "The content negotiation fields defined by this specification use a common parameter, named "q" (case-insensitive), to assign a relative "weight" to the preference for that associated kind of content."
                    // cite(RFC 9110 § 12.5.1): "Recipients SHOULD process any parameter named "q" as weight, regardless of parameter ordering."
                    if k.eq_ignore_ascii_case("q") {
                        weight_seen = true;
                        // The three-digit cap and the asymmetry between the
                        // two branches are both in the production, and the
                        // helper owns it — this rule does not keep a second
                        // copy. The MUST NOT is the sender-side statement of
                        // the same bound, and it is senders this rule reports.
                        // cite(RFC 9110 § 12.4.2): "A sender of qvalue MUST NOT generate more than three digits after the decimal point."
                        if !crate::helpers::headers::valid_qvalue(v) {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: format!("Invalid qvalue '{}' in {} header", v, hdr),
                            });
                        }
                    } else {
                        // `parameter-value` is `( token / quoted-string )`, and
                        // the alternation is read by the helper that owns it.
                        // cite(RFC 9110 § 5.6.6): "parameter-value = ( token / quoted-string )"
                        match crate::helpers::headers::token_or_quoted_string(v) {
                            Ok(_) => {}
                            // The same shape the parameter *name* above was
                            // corrected for, left standing on the value half:
                            // `a/b;x=` reached a `tchar` scan, which finds no
                            // invalid character in the empty string and called it
                            // clean. Neither alternative derives the empty string
                            // -- `token = 1*tchar`, and the shortest
                            // `quoted-string` is its two DQUOTEs -- so the value
                            // as written derives from no `parameter-value`.
                            // (`x=""` is a different value and still conforms.)
                            Err(crate::helpers::headers::WordDefect::Empty) => {
                                return Some(Violation {
                                    rule: self.id().into(),
                                    severity: config.severity,
                                    message: format!(
                                        "Empty parameter value in '{}' of {} header: a parameter-value is a token or a quoted-string, and neither derives the empty string",
                                        p, hdr
                                    ),
                                });
                            }
                            Err(crate::helpers::headers::WordDefect::NotQuotedString(e)) => {
                                return Some(Violation {
                                    rule: self.id().into(),
                                    severity: config.severity,
                                    message: format!(
                                        "Invalid quoted-string parameter '{}' in {} header: {}",
                                        p, hdr, e
                                    ),
                                });
                            }
                            Err(crate::helpers::headers::WordDefect::NotToken(c)) => {
                                return Some(Violation {
                                    rule: self.id().into(),
                                    severity: config.severity,
                                    message: format!(
                                        "Invalid token '{}' in parameter value '{}' of {} header",
                                        c, v, hdr
                                    ),
                                });
                            }
                        }
                    }
                }
            }
            None
        };

        // Every Accept field line, not just the first. `Accept` is a list
        // field, so a sender may spread its members over several lines and a
        // malformed member on the second is as malformed as one on the first —
        // it was simply never read.
        //
        // Each line is validated on its own rather than after recombining them,
        // which is not the same thing: an unbalanced quote in one line would
        // otherwise swallow the members of every line after it, and this rule
        // would report the first line's defect against the last line's text.
        let check_all = |hdr: &str, headers: &hyper::HeaderMap| -> Option<Violation> {
            for hv in headers.get_all("accept").iter() {
                // Decoded from the raw octets rather than through `to_str`,
                // which refuses `obs-text` — legal inside a `quoted-string`, so
                // a value carrying one is a value this rule still has to judge.
                // Skipping it meant a bare `*` sitting on the same line as an
                // obs-text parameter was reported by nothing at all.
                let val = String::from_utf8_lossy(hv.as_bytes());
                if let Some(v) = check_val(hdr, &val) {
                    return Some(v);
                }
            }
            None
        };

        if let Some(v) = check_all("Accept", &tx.request.headers) {
            return Some(v);
        }

        if let Some(resp) = &tx.response {
            if let Some(v) = check_all("Accept", &resp.headers) {
                return Some(v);
            }
        }

        None
    }

    fn title(&self) -> Option<&'static str> {
        Some("Message Accept Header Media Type Syntax")
    }

    fn description(&self) -> &'static str {
        "Check that an `Accept` header reads as `#( media-range [ weight ] )`: each member a `media-range` — `*/*`, `type/*`, or `type/subtype`, both halves `token` — optionally followed by media type parameters and then a weight. A `q` value must be a `qvalue`: `0` to `1` with at most three digits after the decimal point.\n\n**A bare `*` is reported**, and so is a wildcard type with a concrete subtype (`*/json`). The second of those is a judgement about the prose rather than a reading of the ABNF: `type` is a `token` and `*` is a `tchar`, so `*/json` does derive from `type \"/\" subtype`. But §12.5.1 gives the asterisk exactly two jobs — all media types, or all subtypes of one type — and this is neither, so it names no set a recipient could match against. `message_content_type_well_formed` takes the same position on the same shape in `Content-Type`.\n\n**A parameter after the weight is reported.** `Accept = #( media-range [ weight ] )` puts the weight last and the media-range is what carries the parameters, so `text/html;q=0.5;charset=utf-8` derives from nothing in this grammar. RFC 9110 removed the `accept-ext` production that used to allow it and states the consequence as a SHOULD on senders. Finding the `q` itself is unaffected: it is looked for among all the parameters and its name matched case-insensitively, because §12.5.1 tells recipients to process it regardless of ordering. This rule reports what a sender did; it does not pretend not to understand it.\n\n**Both directions are read.** A request's `Accept` states a preference; a response's, per §12.5.1, says what a subsequent request to the same resource should prefer. Each field line is validated on its own rather than recombined, so an unbalanced quote in one line cannot swallow the members of the next.\n\n**Quoting that never closes is reported here** rather than declined. The rules that consume `Accept` — `message_accept_and_content_type_negotiation` among them — decline to judge a member list they cannot read; this rule is the one that owns a malformed `Accept`, so declining would leave the defect with no reporter.\n\n**Whitespace inside a media-range is reported.** The OWS these grammars allow sits around list elements and around the `;` before a parameter, never between a type and its subtype, so `text /html` is malformed — and used to pass, because the media-type helper trims each half before returning it and the space vanished before any check saw it.\n\n**Known leniency:** RFC 9110 §5.6.6 forbids whitespace around a parameter's `=`, and this rule trims it, so `q =0.5` is accepted. Empty list elements (`text/html, , text/plain`) are skipped, which §5.6.1.2 permits a recipient to do."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("12.5.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.1",
                note: "Accept: the `#( media-range [ weight ] )` list, the three shapes a `media-range` takes and what the asterisk ranges over, the removal of the extension parameters that once followed the weight, and the meaning of an Accept sent in a response",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("12.4.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-12.4.2",
                note: "Quality Values: the `qvalue` production and its three-digit bound, and that the parameter name is matched case-insensitively",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("8.3.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3.1",
                note: "Media Type: `type` and `subtype` are both `token`, which is what the character checks enforce",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("5.6.6"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.6",
                note: "Parameters: the `name=value` grammar and the two alternatives a value may take. Its prohibition on whitespace around `=` is NOT enforced here",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("5.6.1.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.2",
                note: "Sender Requirements for lists: the bracketing that makes an empty list element something a recipient may ignore",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "Accept: text/html",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(a media type parameter, then the weight)"),
                snippet: "Accept: text/*;q=0.8, application/json;charset=utf-8;q=0.9",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(a comma inside a quoted value is not a separator)"),
                snippet: "Accept: text/html;foo=\"a,b\", */*;q=0.1",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(the asterisk names a type or a subtype, not a pair)"),
                snippet: "Accept: *",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(a wildcard type ranges over nothing without a wildcard subtype)"),
                snippet: "Accept: */json",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(no subtype)"),
                snippet: "Accept: text; q=0.8",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(a qvalue has at most three digits after the point)"),
                snippet: "Accept: text/html; q=1.0000",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(the weight closes a media-range)"),
                snippet: "Accept: text/html; q=0.5; charset=utf-8",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(a parameter is a name, an \"=\", and a value)"),
                snippet: "Accept: text/html; charset",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(the quoting never closes)"),
                snippet: "Accept: text/html; foo=\"unterminated",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &MessageAcceptHeaderMediaTypeSyntax;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(Some("text/html"), false)]
    #[case(Some("text/*;q=0.8, application/json;q=0.9"), false)]
    #[case(Some("*/*;q=0.1"), false)]
    #[case(Some("application/json; charset=utf-8"), false)]
    #[case(Some("type/*;q=0.5"), false)]
    #[case(Some("text/html; param=token-with-hyphen"), false)]
    #[case(Some("text/html; param=\"ok\""), false)]
    #[case(Some("text/html; param=\"a\\\"b\""), false)]
    #[case(Some("text/*; param=\"ok\""), false)]
    #[case(Some("*"), true)]
    #[case(Some("text; q=0.8"), true)]
    #[case(Some("text/html; q=1.0000"), true)]
    #[case(Some("*/*; q=1.0000"), true)]
    #[case(Some("text/; q=0.8"), true)]
    #[case(Some("te@xt/html"), true)]
    #[case(Some("text/ht@ml"), true)]
    #[case(Some("text/html; charset"), true)]
    #[case(Some("text/html; param=\"unterminated"), true)]
    #[case(Some("text/html; bad name=value"), true)]
    #[case(Some("application/json; charset=bad@"), true)]
    // A comma or semicolon inside a quoted parameter value is not a separator.
    // Splitting on it produced the very malformed quoted-string it then
    // reported, out of a header that is conforming.
    #[case(Some("text/html;foo=\"a,b\""), false)]
    #[case(Some("text/html;foo=\"a;b\""), false)]
    #[case(Some("text/html;foo=\"a,b\", application/json"), false)]
    // Quoting that never closes is still a finding, and it is this rule's:
    // nothing downstream can read the members once the quoting breaks.
    #[case(Some("text/html;foo=\"a, application/json"), true)]
    // An empty list element is legal for a recipient to ignore.
    #[case(Some("text/html, , application/json"), false)]
    // A wildcard type with a concrete subtype names no set a recipient could
    // match against. The two shapes the asterisk does have still pass.
    #[case(Some("*/json"), true)]
    #[case(Some("text/html, */json"), true)]
    #[case(Some("*/*"), false)]
    #[case(Some("text/*"), false)]
    // The weight closes a media-range; the extension parameters that used to
    // follow it were removed from the grammar.
    #[case(Some("text/html;q=0.5;charset=utf-8"), true)]
    #[case(Some("text/html;q=0.5;q=0.8"), true)]
    #[case(Some("text/html;charset=utf-8;q=0.5"), false)]
    #[case(Some("text/html;charset=utf-8;q=0.5, text/plain;q=1"), false)]
    // The weight closes its own member, not the ones after it.
    #[case(Some("text/html;q=0.5, text/plain;charset=utf-8"), false)]
    // `token = 1*tchar`: a name with no characters is not a name, and scanning
    // for an invalid character cannot notice that there are none.
    #[case(Some("text/html; =value"), true)]
    // The same shape on the value half, which the audit that fixed the name half
    // left standing: `parameter-value = ( token / quoted-string )` derives no
    // empty string either, and `charset=` used to be clean for exactly the
    // reason `=value` used to be. `""` is a different value and conforms.
    #[case(Some("text/html; charset="), true)]
    #[case(Some("text/html; charset=\"\""), false)]
    // No whitespace inside a media-range. The OWS in these grammars sits around
    // list elements and around the `;`, never between a type and its subtype.
    #[case(Some("text /html"), true)]
    #[case(Some("text/ html"), true)]
    #[case(Some("*/ *"), true)]
    // OWS around the member and around the parameter separator is legal.
    #[case(Some(" text/html , application/json ; q=0.5"), false)]
    #[case(None, false)]
    fn check_accept_request(
        #[case] accept: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageAcceptHeaderMediaTypeSyntax;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_accept_header_media_type_syntax",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(v) = accept {
            // Some test cases include control characters; construct header value from bytes in that case
            if v.chars()
                .any(|c| c == '\x01' || c == '\x7f' || c.is_control())
            {
                let mut hm = hyper::HeaderMap::new();
                let hv = hyper::header::HeaderValue::from_bytes(v.as_bytes())
                    .expect("should construct non-utf8 header");
                hm.insert("accept", hv);
                tx.request.headers = hm;
            } else {
                tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[("accept", v)]);
            }
        }

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(v.is_some());
        } else {
            assert!(v.is_none());
        }
        Ok(())
    }

    /// Every published snippet is run through the rule, and each NonCompliant
    /// one is pinned to the finding it illustrates. The old NonCompliant
    /// example bundled four different defects into one snippet, of which a
    /// rule can only ever report the first — so three of them were published
    /// as illustrations of nothing.
    #[test]
    fn published_examples_are_judged_the_way_they_are_labelled() {
        use crate::rules::{Compliance, Rule as _};
        let rule = MessageAcceptHeaderMediaTypeSyntax;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let reasons: [(&str, &str); 7] = [
            ("Accept: *", "Invalid media-range '*'"),
            ("Accept: */json", "wildcard type is only meaningful"),
            ("Accept: text; q=0.8", "missing '/'"),
            ("Accept: text/html; q=1.0000", "Invalid qvalue"),
            (
                "Accept: text/html; q=0.5; charset=utf-8",
                "follows the weight",
            ),
            ("Accept: text/html; charset", "missing '='"),
            (
                "Accept: text/html; foo=\"unterminated",
                "Invalid quoted-string parameter",
            ),
        ];

        for ex in rule.examples() {
            let (k, v) = ex
                .snippet
                .split_once(": ")
                .unwrap_or_else(|| panic!("example is not `Name: value`: {:?}", ex.snippet));
            let mut tx = crate::test_helpers::make_test_transaction();
            tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(k, v)]);
            let found = rule.check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            );
            match ex.compliance {
                Compliance::Compliant => assert!(
                    found.is_none(),
                    "rule rejects its Compliant example {:?}: {found:?}",
                    ex.snippet
                ),
                Compliance::NonCompliant => {
                    let found = found.unwrap_or_else(|| {
                        panic!("rule accepts its NonCompliant example {:?}", ex.snippet)
                    });
                    let expected = *reasons
                        .iter()
                        .find(|(s, _)| *s == ex.snippet)
                        .map(|(_, reason)| reason)
                        .unwrap_or_else(|| {
                            panic!(
                                "NonCompliant example {:?} has no expected finding here",
                                ex.snippet
                            )
                        });
                    assert!(
                        found.message.contains(expected),
                        "NonCompliant example {:?} should fail with {expected:?}: {found:?}",
                        ex.snippet
                    );
                }
            }
        }
    }

    #[test]
    fn message_and_id() {
        let rule = MessageAcceptHeaderMediaTypeSyntax;
        assert_eq!(rule.id(), "message_accept_header_media_type_syntax");
        // `Both`: the rule reads a response's Accept as well as a request's,
        // and §12.5.1 gives that one a meaning of its own.
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }

    /// The empty-value branch, pinned rather than merely asserted to exist. A
    /// case that only checks `is_some()` cannot see a message whose subject and
    /// verb phrase disagree, and this one has to name the value half so it is
    /// not read as the parameter-name finding twelve lines above it.
    #[test]
    fn the_empty_parameter_value_finding_names_the_value_half() {
        let rule = MessageAcceptHeaderMediaTypeSyntax;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_accept_header_media_type_syntax",
        ]);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("accept", "text/html; charset=")]);
        let v = rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            )
            .expect("an empty parameter-value derives from neither alternative");
        assert_eq!(
            v.message,
            "Empty parameter value in 'charset=' of Accept header: a parameter-value is a token or a quoted-string, and neither derives the empty string"
        );
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_accept_header_media_type_syntax",
        ]);
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    /// A malformed member on the second Accept line is as malformed as one on
    /// the first; only the first was ever read.
    #[rstest]
    #[case(&["text/html", "*"], true)]
    #[case(&["*", "text/html"], true)]
    #[case(&["text/html", "application/json;q=0.5"], false)]
    // Each line is validated on its own, so an unbalanced quote is reported
    // against the line that carries it and does not swallow the next one.
    #[case(&["text/html;foo=\"x", "application/json"], true)]
    fn every_accept_field_line_is_read(#[case] values: &[&str], #[case] expect_violation: bool) {
        let rule = MessageAcceptHeaderMediaTypeSyntax;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let mut tx = crate::test_helpers::make_test_transaction();
        let pairs: Vec<(&str, &str)> = values.iter().map(|v| ("accept", *v)).collect();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&pairs);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert_eq!(v.is_some(), expect_violation, "{values:?} -> {v:?}");
    }

    /// obs-text is legal inside a quoted-string, so this is a value the rule
    /// still has to judge — and it carries a bare `*`, which is not a
    /// media-range. `to_str` refused the whole line and the `*` went unreported.
    #[test]
    fn obs_text_does_not_hide_the_rest_of_the_line() {
        use hyper::header::HeaderValue;
        let rule = MessageAcceptHeaderMediaTypeSyntax;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers.insert(
            "accept",
            HeaderValue::from_bytes(b"*, text/html;foo=\"\xe4\"").unwrap(),
        );
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        let v = v.expect("a bare '*' is not a media-range");
        assert!(v.message.contains("'*'"), "{v:?}");
    }

    #[test]
    fn check_accept_in_response() -> anyhow::Result<()> {
        let rule = MessageAcceptHeaderMediaTypeSyntax;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_accept_header_media_type_syntax",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("accept", "text/html; q=1.0000")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        Ok(())
    }
}
