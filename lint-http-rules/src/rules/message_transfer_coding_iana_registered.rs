// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

#[derive(Debug, Clone)]
pub struct TransferCodingConfig {
    pub enabled: bool,
    pub severity: crate::lint::Severity,
    pub allowed: Vec<String>,
}

fn parse_allowed_config(
    config: &crate::config::Config,
    rule_id: &str,
) -> anyhow::Result<TransferCodingConfig> {
    let severity = crate::rules::get_rule_severity_required(config, rule_id)?;
    let enabled = crate::rules::get_rule_enabled_required(config, rule_id)?;

    // get_rule_severity_required/required_enabled already asserts the rule config exists,
    // so unwrap is safe here and avoids creating an unreachable error branch.
    let rule_cfg = config
        .get_rule_config(rule_id)
        .expect("internal error: rule config missing after validation");
    let table = rule_cfg
        .as_table()
        .ok_or_else(|| anyhow::anyhow!("Configuration for rule '{}' must be a table", rule_id))?;

    let allowed_val = table.get("allowed").ok_or_else(|| {
        anyhow::anyhow!(
            "Rule '{}' requires an 'allowed' array listing allowed transfer-coding tokens (e.g., ['chunked','gzip','deflate'])",
            rule_id
        )
    })?;

    let arr = allowed_val.as_array().ok_or_else(|| {
        anyhow::anyhow!("'allowed' must be an array of strings (e.g., ['chunked','gzip'])")
    })?;

    if arr.is_empty() {
        return Err(anyhow::anyhow!("'allowed' array cannot be empty"));
    }

    let mut out = Vec::new();
    for (i, item) in arr.iter().enumerate() {
        let s = item.as_str().ok_or_else(|| {
            anyhow::anyhow!("'allowed' array item at index {} must be a string", i)
        })?;
        // Folded once here so the comparison site can fold the wire value and
        // be done. The fold is not a convenience: the names are defined to be
        // case-insensitive, so `GZIP` in a config file and `gzip` on the wire
        // are the same coding.
        // cite(RFC 9112 § 7): "All transfer-coding names are case-insensitive and ought to be registered within the HTTP Transfer Coding registry, as defined in Section 7.3."
        out.push(s.to_ascii_lowercase());
    }

    Ok(TransferCodingConfig {
        enabled,
        severity,
        allowed: out,
    })
}

/// The compression transfer codings, and the whole of them. RFC 9112 § 7.2
/// defines these five by reference to the content coding of the same name, and
/// the two `x-` forms are named there as alternates rather than as a general
/// licence for an `x-` prefix.
const COMPRESSION_CODINGS: [&str; 5] = ["compress", "x-compress", "deflate", "gzip", "x-gzip"];

pub struct MessageTransferCodingIanaRegistered;

impl Rule for MessageTransferCodingIanaRegistered {
    fn id(&self) -> &'static str {
        "message_transfer_coding_iana_registered"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn validate(&self, config: &crate::config::Config) -> anyhow::Result<()> {
        parse_allowed_config(config, self.id())?;
        Ok(())
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = parse_allowed_config(cfg, self.id()).ok()?;
        // check a list-style header value (Transfer-Encoding or TE) against allowed list
        let check_value = |hdr_name: &str, val: &str, allowed: &[String]| -> Option<Violation> {
            // An odd number of unescaped DQUOTEs means the quoting never
            // closes, and then no comma after it is a separator: the splitter
            // below swallows the rest of the field into one member, and
            //
            //     Transfer-Encoding: gzip;ext="x, x-bogus
            //
            // would pass on the strength of `gzip` alone. The value is
            // malformed either way -- a `quoted-string` that never closes is
            // not one -- so this is reported rather than declined. The sibling
            // rules that decline an unbalanced value do so because another rule
            // owns the field's syntax and will report it; for
            // `Transfer-Encoding` no such rule exists, and silence here would
            // be the whole of the answer.
            // cite(RFC 9110 § 5.6.4): "quoted-string  = DQUOTE *( qdtext / quoted-pair ) DQUOTE"
            if !crate::helpers::headers::quoting_is_balanced(val) {
                return Some(Violation {
                    rule: "message_transfer_coding_iana_registered".into(),
                    severity: config.severity,
                    message: format!(
                        "Unterminated quoted-string in {} header: '{}'",
                        hdr_name, val
                    ),
                });
            }
            // cite(RFC 9112 § 7.3): "The "HTTP Transfer Coding Registry" defines the namespace for transfer coding names."
            //
            // Quote-aware, because a comma inside a transfer-parameter's
            // quoted-string value is not a list separator. A raw `split(',')`
            // cut such a value apart and read the pieces as members of their
            // own, so `chunked;ext="a,b"` -- one coding, one parameter --
            // yielded a second "member" of `b"`, whose closing DQUOTE is not a
            // `tchar`, and the rule reported a conforming field.
            // cite(RFC 9110 § 10.1.4): "transfer-parameter = token BWS "=" BWS ( token / quoted-string )"
            for part in crate::helpers::headers::split_commas_respecting_quotes(val) {
                let part = part.trim();
                // `#element` admits empty members, and they are not elements.
                // `parse_list_header` used to drop these; the quote-aware
                // splitter does not, so the filter moves here with its licence.
                // cite(RFC 9110 § 5.6.1.2): "Empty elements do not contribute to the count of elements present."
                if part.is_empty() {
                    continue;
                }
                // Splitting the name off at the first `;` needs no quote
                // awareness: a `quoted-string` can only appear in a
                // transfer-parameter value, which is behind a `;` already, so
                // nothing quoted ever precedes the first one.
                let token = part.split(';').next().unwrap().trim();
                // `trailers` occupies the first alternative of `t-codings`, so
                // it is a member of TE that is not a coding name and has no
                // registry question to answer. It is skipped rather than looked
                // up. Its own constraints -- it takes neither parameters nor a
                // weight, since the alternative that admits those is the other
                // one -- are `message_te_header_constraints`' subject, and that
                // rule reports them.
                // cite(RFC 9112 § 7.4): "The keyword "trailers" indicates that the sender will not discard trailer fields, as described in Section 6.5 of [HTTP]."
                //
                // The literal is matched case-insensitively because ABNF string
                // literals are, and § 7's blanket sentence about coding names
                // would not settle this one on its own -- `trailers` is not a
                // coding name here.
                if hdr_name.eq_ignore_ascii_case("TE") && token.eq_ignore_ascii_case("trailers") {
                    continue;
                }
                // `token = 1*tchar` has no empty alternative, so a member that
                // is nothing but parameters names no coding. `find_invalid_token_char`
                // answers `None` for the empty string -- there is no offending
                // character to point at -- and without this the member reached
                // the registry check and was reported as an unrecognized coding
                // named `''`, which describes the wrong defect.
                // cite(RFC 9110 § 5.6.2): "token = 1*tchar tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA"
                if token.is_empty() {
                    return Some(Violation {
                        rule: "message_transfer_coding_iana_registered".into(),
                        severity: config.severity,
                        message: format!(
                            "Missing transfer-coding name in {} header member '{}'",
                            hdr_name, part
                        ),
                    });
                }
                if let Some(c) = crate::helpers::token::find_invalid_token_char(token) {
                    return Some(Violation {
                        rule: "message_transfer_coding_iana_registered".into(),
                        severity: config.severity,
                        message: format!("Invalid token '{}' in {} header", c, hdr_name),
                    });
                }
                // `chunked` is a registered coding and sits in the default
                // `allowed` list, so the registry check below waves it through
                // wherever it appears. In TE it is forbidden outright, and for
                // a reason the second half of the sentence gives: a client
                // cannot decline it, so naming it says nothing. This is the one
                // place where a name being *recognized* is not enough.
                // cite(RFC 9112 § 7.4): "A client MUST NOT send the chunked transfer coding name in TE; chunked is always acceptable for HTTP/1.1 recipients."
                //
                // Case-insensitively, like every other name comparison here.
                // cite(RFC 9112 § 7): "All transfer-coding names are case-insensitive and ought to be registered within the HTTP Transfer Coding registry, as defined in Section 7.3."
                if hdr_name.eq_ignore_ascii_case("TE") && token.eq_ignore_ascii_case("chunked") {
                    return Some(Violation {
                        rule: "message_transfer_coding_iana_registered".into(),
                        severity: config.severity,
                        message: "A client must not send the chunked transfer coding name in TE; \
                             chunked is always acceptable for HTTP/1.1 recipients"
                            .into(),
                    });
                }
                // § 7.2 defines exactly these five names by reference to the
                // content codings of the same name, and then says outright what
                // follows for their parameters. The rule stripped everything
                // from the first `;` onward and never looked, so
                // `Transfer-Encoding: gzip;level=9` passed as an ordinary gzip.
                // cite(RFC 9112 § 7.2): "The compression codings do not define any parameters."
                // cite(RFC 9112 § 7.2): "The presence of parameters with any of these compression codings SHOULD be treated as an error."
                //
                // The list stops there on purpose. `chunked` also defines no
                // parameters, but § 7.2's sentence is about the compression
                // codings and no sentence makes a parameter on `chunked` an
                // error, so `chunked;ext=1` stays unreported -- the divergence
                // is the specification's, not this rule's. Nor does this reach
                // a coding the operator added to `allowed`: what its parameters
                // mean is its own registration's business.
                if COMPRESSION_CODINGS
                    .iter()
                    .any(|c| token.eq_ignore_ascii_case(c))
                {
                    for param in crate::helpers::headers::split_semicolons_respecting_quotes(part)
                        .into_iter()
                        .skip(1)
                    {
                        let param = param.trim();
                        if param.is_empty() {
                            continue;
                        }
                        // In TE the `q` is the rank, which the grammar puts
                        // outside `transfer-coding` as a `weight` and § 7.3
                        // calls a pseudo-parameter -- so it is not one of the
                        // parameters § 7.2 forbids, and `TE: deflate;q=0.5` is
                        // exactly the form § 7.4's own example uses. In
                        // `Transfer-Encoding` there is no weight in the grammar
                        // at all, so a `q` there is an ordinary parameter and is
                        // reported like any other.
                        // cite(RFC 9110 § 10.1.4): "TE                 = #t-codings t-codings          = "trailers" / ( transfer-coding [ weight ] ) transfer-coding    = token *( OWS ";" OWS transfer-parameter ) transfer-parameter = token BWS "=" BWS ( token / quoted-string )"
                        // cite(RFC 9112 § 7.4): "When multiple transfer codings are acceptable, the client MAY rank the codings by preference using a case-insensitive "q" parameter (similar to the qvalues used in content negotiation fields; see Section 12.4.2 of [HTTP])."
                        let name = param.split('=').next().unwrap().trim();
                        if hdr_name.eq_ignore_ascii_case("TE") && name.eq_ignore_ascii_case("q") {
                            continue;
                        }
                        return Some(Violation {
                            rule: "message_transfer_coding_iana_registered".into(),
                            severity: config.severity,
                            message: format!(
                                "Compression transfer-coding '{}' defines no parameters, but '{}' \
                                 is present in the {} header",
                                token, param, hdr_name
                            ),
                        });
                    }
                }
                // The registry check, and the weakest sentence in the rule.
                // § 7 says coding names "ought to be" registered -- not MUST,
                // not even SHOULD -- so an unregistered name is not by itself a
                // violation of anything. What gives the finding its point is
                // what happens next to a coding the recipient does not know:
                // cite(RFC 9112 § 6.1): "A server that receives a request message with a transfer coding it does not understand SHOULD respond with 501 (Not Implemented)."
                //
                // The comparison is against `allowed`, a configured list, and
                // not against the registry the rule's name invokes -- nothing
                // here fetches <https://www.iana.org/assignments/http-parameters>.
                // That is a real divergence and the description says so. It is
                // also why an operator's own coding is configuration rather
                // than a finding: § 7.3's registration procedure is IETF
                // Review, which no linter can stand in for.
                //
                // Lowercased on both sides. § 7 settles this outright, and it
                // is the same sentence the config parser folds by.
                // cite(RFC 9112 § 7): "All transfer-coding names are case-insensitive and ought to be registered within the HTTP Transfer Coding registry, as defined in Section 7.3."
                if !allowed.contains(&token.to_ascii_lowercase()) {
                    return Some(Violation {
                        rule: "message_transfer_coding_iana_registered".into(),
                        severity: config.severity,
                        message: format!(
                            "Unrecognized transfer-coding '{}' in {} header",
                            token, hdr_name
                        ),
                    });
                }
            }
            None
        };
        // Both fields are lists, so a sender may spread their members over
        // several field lines and a recipient recombines them. `get_header_str`
        // returns the first line only, and of all the fields in HTTP,
        // `Transfer-Encoding` is the one where reading only the first is worst:
        // a second `Transfer-Encoding` line is the shape request smuggling
        // arrives in, and
        //
        //     Transfer-Encoding: chunked
        //     Transfer-Encoding: x-bogus
        //
        // reported nothing at all. Each line is walked on its own rather than
        // joined first, which for a per-member check is the same answer either
        // way and keeps a member from being described in terms of its
        // neighbour.
        // cite(RFC 9110 § 5.3): "A recipient MAY combine multiple field lines within a field section that have the same field name into one field line, without changing the semantics of the message, by appending each subsequent field line value to the initial field line value in order, separated by a comma (",") and optional whitespace (OWS, defined in Section 5.6.3).  For consistency, use comma SP."
        //
        // Decoded from the raw octets rather than through `to_str`, which
        // refuses everything outside visible US-ASCII and made the whole field
        // line vanish on one stray byte. Unlike the fields whose grammars are
        // ASCII throughout, `obs-text` *is* legal in this one — but only inside
        // a `quoted-string`, which the grammar admits only as a
        // transfer-parameter value, and this rule reads no parameter values.
        // The coding name in front of them is a `token`, every character of
        // which is ASCII, so the replacement character the decode leaves behind
        // can only ever reach the name check, where it is reported like any
        // other octet the production excludes.
        // cite(RFC 9110 § 5.6.4): "quoted-string  = DQUOTE *( qdtext / quoted-pair ) DQUOTE"
        // cite(RFC 9110 § 5.6.4): "qdtext         = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text"
        fn decode(hv: &hyper::header::HeaderValue) -> std::borrow::Cow<'_, str> {
            String::from_utf8_lossy(hv.as_bytes())
        }

        // Transfer-Encoding is defined for both directions: it names the codings
        // applied to *this message's* body, whichever way it is travelling.
        // cite(RFC 9112 § 6.1): "Transfer-Encoding = #transfer-coding"
        if let Some(resp) = &tx.response {
            for hv in resp.headers.get_all("transfer-encoding").iter() {
                if let Some(v) = check_value("Transfer-Encoding", &decode(hv), &config.allowed) {
                    return Some(v);
                }
            }
        }

        for hv in tx.request.headers.get_all("transfer-encoding").iter() {
            if let Some(v) = check_value("Transfer-Encoding", &decode(hv), &config.allowed) {
                return Some(v);
            }
        }

        // TE describes the client, so only the request side is read here. A TE
        // field on a response is `message_te_header_constraints`' finding, not a
        // coding-name question.
        //
        // An empty TE is conforming and reaches no check: the splitter yields
        // one empty member and the § 5.6.1.2 filter drops it. That is a
        // deliberate silence rather than an accident of the loop -- § 7.4 lists
        // `TE:` among its three examples of TE use and says what it means.
        // cite(RFC 9112 § 7.4): "If the TE field value is empty or if no TE field is present, the only acceptable transfer coding is chunked."
        // cite(RFC 9110 § 10.1.4): "The TE field value is a list of members, with each member (aside from "trailers") consisting of a transfer coding name token with an optional weight indicating the client's relative preference for that transfer coding (Section 12.4.2) and optional parameters for that transfer coding."
        for hv in tx.request.headers.get_all("te").iter() {
            if let Some(v) = check_value("TE", &decode(hv), &config.allowed) {
                return Some(v);
            }
        }

        None
    }

    fn description(&self) -> &'static str {
        "Validate `Transfer-Encoding` and `TE` header values: transfer-coding names must be syntactically valid `token`s and must appear in the configured `allowed` list. The `TE` header's `trailers` member is not a coding name and is skipped.\n\n**The rule is named after a registry it does not read.** Nothing here fetches IANA's HTTP Transfer Coding registry; names are compared against the configured `allowed` list, whose shipped default is `chunked`, `compress`, `gzip`, `deflate`. The registry also holds `x-compress` and `x-gzip` (both Deprecated) and `identity` (withdrawn), which the default omits on purpose — reporting them is the useful answer. `trailers` is registered as reserved and never reaches the comparison. Widen or narrow the list to suit; an unregistered name is a configuration question, because RFC 9112 §7.3 puts registration behind IETF Review and no linter can stand in for that.\n\n**The strongest thing RFC 9112 §7 says about registration is \"ought to\"** — not MUST, not SHOULD. An unrecognised coding is therefore reported for its consequence rather than for disobedience: §6.1, \"A server that receives a request message with a transfer coding it does not understand SHOULD respond with 501 (Not Implemented).\"\n\n**Every field line of both fields is read**, since each is a list whose members may be spread across lines — and for `Transfer-Encoding` a second field line is the shape request smuggling arrives in, so reading only the first is the one omission this rule cannot afford. Values are decoded from the raw octets: an octet outside visible US-ASCII is not a `tchar`, so where a coding name belongs it is reported rather than used as a reason to skip the line.\n\n**Members are split on commas that are not inside a quoted-string.** `transfer-parameter = token BWS \"=\" BWS ( token / quoted-string )`, so `chunked;ext=\"a,b\"` is one coding carrying one parameter, not two members. Quoting that never closes leaves the members undelimitable and is reported here rather than passed over, because no other rule reports a malformed `Transfer-Encoding`.\n\n**`chunked` is reported in `TE` and only there.** RFC 9112 §7.4: \"A client MUST NOT send the chunked transfer coding name in TE; chunked is always acceptable for HTTP/1.1 recipients.\" It is a registered coding, so the registry check waves it through; this is the one place where a recognised name is still the wrong name. In `Transfer-Encoding` it is the ordinary case.\n\n**A parameter on a compression coding is reported.** RFC 9112 §7.2 defines `compress`, `x-compress`, `deflate`, `gzip` and `x-gzip`, states that they \"do not define any parameters\", and says their presence \"SHOULD be treated as an error\". The `q` in `TE: deflate;q=0.5` is exempt — the grammar puts the `weight` outside `transfer-coding` and §7.3 calls it a pseudo-parameter — but `Transfer-Encoding` has no weight in its grammar, so a `q` there is an ordinary parameter. This reaches no other coding: `chunked;ext=1` is unreported because §7.2's sentence is about the compression codings and no sentence makes a parameter on `chunked` an error, and a coding you add to `allowed` answers to its own registration."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9112",
                section: Some("6.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-6.1",
                note: "Transfer-Encoding = #transfer-coding, and the 501 a recipient owes a coding it does not understand",
            },
            crate::rules::SpecRef {
                spec: "RFC 9112",
                section: Some("7"),
                url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-7",
                note: "Transfer codings: the names are case-insensitive and 'ought to be' registered — the whole of this rule's strength",
            },
            crate::rules::SpecRef {
                spec: "RFC 9112",
                section: Some("7.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-7.2",
                note: "The five compression codings, which define no parameters",
            },
            crate::rules::SpecRef {
                spec: "RFC 9112",
                section: Some("7.4"),
                url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-7.4",
                note: "Negotiating transfer codings: chunked is forbidden in TE, an empty TE is conforming, and the q is a rank",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("10.1.4"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1.4",
                note: "TE, and the grammar both fields share — including the quoted-string a transfer-parameter may carry",
            },
            crate::rules::SpecRef {
                spec: "IANA HTTP Parameters",
                section: None,
                url: "https://www.iana.org/assignments/http-parameters/http-parameters.xhtml#transfer-coding",
                note: "The registry this rule is named after and does not read: names are checked against the configured 'allowed' list instead",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nTransfer-Encoding: chunked\n\n0\n",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(TE request)"),
                snippet: "GET / HTTP/1.1\nHost: example.com\nTE: trailers\n",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(TE ranks a coding; the q is a weight, not a parameter)"),
                snippet: "GET / HTTP/1.1\nHost: example.com\nTE: trailers, deflate;q=0.5\n",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nTransfer-Encoding: x-custom\n",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(chunked is always acceptable, so TE cannot name it)"),
                snippet: "GET / HTTP/1.1\nHost: example.com\nTE: chunked;q=0.8\n",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(the compression codings define no parameters)"),
                snippet: "HTTP/1.1 200 OK\nTransfer-Encoding: gzip;level=9, chunked\n",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &MessageTransferCodingIanaRegistered;

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;
    use rstest::rstest;

    fn make_cfg() -> crate::config::Config {
        let mut cfg = crate::config::Config::default();
        cfg.rules.insert(
            "message_transfer_coding_iana_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![
                        toml::Value::String("chunked".into()),
                        toml::Value::String("gzip".into()),
                        toml::Value::String("deflate".into()),
                    ]),
                );
                t
            }),
        );
        cfg
    }

    #[rstest]
    #[case(Some("chunked"), false)]
    #[case(Some("gzip"), false)]
    #[case(Some("x-custom"), true)]
    #[case(Some("chunked, x-custom"), true)]
    #[case(Some("chunked; param=1"), false)]
    #[case(None, false)]
    fn check_transfer_encoding_response_cases(
        #[case] te: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageTransferCodingIanaRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        if let Some(v) = te {
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[("transfer-encoding", v)]);
        }

        let violation = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(violation.is_some());
        } else {
            assert!(violation.is_none());
        }
        Ok(())
    }

    #[rstest]
    #[case(Some("trailers"), false)]
    #[case(Some("gzip;q=1.0"), false)]
    #[case(Some("x-custom;q=0.1"), true)]
    #[case(Some("x!bad"), true)]
    #[case(None, false)]
    fn check_te_request_cases(
        #[case] te: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageTransferCodingIanaRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(v) = te {
            tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[("te", v)]);
        }

        let violation = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(violation.is_some());
        } else {
            assert!(violation.is_none());
        }
        Ok(())
    }

    #[test]
    fn invalid_token_in_transfer_encoding_is_reported() -> anyhow::Result<()> {
        let rule = MessageTransferCodingIanaRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("transfer-encoding", "x@bad")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let v = v.unwrap();
        assert_eq!(v.rule, "message_transfer_coding_iana_registered");
        assert!(
            v.message.contains("Invalid token")
                || v.message.contains("Unrecognized transfer-coding")
        );
        Ok(())
    }

    /// An octet outside visible US-ASCII is not a `tchar`, so where the grammar
    /// wants a coding name it is a finding rather than a reason to stop reading.
    /// This used to assert the opposite: `to_str` failed and the whole field
    /// line was dropped, unreported.
    #[test]
    fn non_ascii_octet_in_a_coding_name_is_reported() {
        let rule = MessageTransferCodingIanaRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = hyper::HeaderMap::new();
        hm.insert(
            "transfer-encoding",
            HeaderValue::from_bytes(b"\xff").unwrap(),
        );
        tx.response.as_mut().unwrap().headers = hm;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.unwrap().message.contains("Invalid token"));

        let mut tx2 = crate::test_helpers::make_test_transaction();
        let mut hm2 = hyper::HeaderMap::new();
        hm2.insert("te", HeaderValue::from_bytes(b"\xff").unwrap());
        tx2.request.headers = hm2;
        let v2 = rule.check_transaction(
            &tx2,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v2.unwrap().message.contains("Invalid token"));
    }

    /// The stray octet must not take its neighbours down with it: the member
    /// after it is still read and still reported.
    #[test]
    fn a_stray_octet_does_not_hide_the_rest_of_the_line() {
        let rule = MessageTransferCodingIanaRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = hyper::HeaderMap::new();
        hm.insert(
            "transfer-encoding",
            HeaderValue::from_bytes(b"gzip, \xe4, x-bogus").unwrap(),
        );
        tx.response.as_mut().unwrap().headers = hm;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    /// Two `Transfer-Encoding` field lines is the shape request smuggling
    /// arrives in. Reading only the first left the second unchecked.
    #[rstest]
    #[case("transfer-encoding", "chunked", "x-bogus")]
    #[case("te", "trailers", "x-bogus")]
    fn every_field_line_is_read(
        #[case] name: &'static str,
        #[case] first: &'static str,
        #[case] second: &'static str,
    ) {
        let rule = MessageTransferCodingIanaRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = hyper::HeaderMap::new();
        hm.append(name, HeaderValue::from_static(first));
        hm.append(name, HeaderValue::from_static(second));
        tx.request.headers = hm;

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(
            v.is_some_and(|v| v.message.contains("x-bogus")),
            "the second {} field line went unread",
            name
        );
    }

    /// Every published snippet is run through the rule, each NonCompliant one
    /// pinned to the finding it illustrates. Nothing else in the project does
    /// this, so a `Compliant` example the rule rejects reaches the docs intact
    /// -- and `gendocs` publishes it.
    ///
    /// `make_cfg` and not `make_test_config_with_enabled_rules`: this rule
    /// requires an `allowed` array, and without one `parse_allowed_config`
    /// fails, `check_transaction` returns `None` for everything, and the whole
    /// test passes by declining to run.
    #[test]
    fn published_examples_are_judged_the_way_they_are_labelled() {
        use crate::rules::{Compliance, Rule as _};
        let rule = MessageTransferCodingIanaRegistered;
        let cfg = make_cfg();
        let reasons: [(&str, &str); 3] = [
            (
                "Transfer-Encoding: x-custom",
                "Unrecognized transfer-coding",
            ),
            ("TE: chunked;q=0.8", "must not send the chunked"),
            (
                "Transfer-Encoding: gzip;level=9, chunked",
                "defines no parameters",
            ),
        ];

        for ex in rule.examples() {
            let mut lines = ex.snippet.lines();
            let start = lines.next().expect("empty snippet");
            let is_response = start.starts_with("HTTP/");
            // The header section ends at the first empty line; one example
            // carries a body after it.
            let pairs: Vec<(&str, &str)> = lines
                .take_while(|l| !l.trim().is_empty())
                .map(|l| {
                    l.split_once(": ")
                        .unwrap_or_else(|| panic!("not a header line: {l:?}"))
                })
                .collect();
            let subject = pairs
                .iter()
                .find(|(k, _)| {
                    k.eq_ignore_ascii_case("transfer-encoding") || k.eq_ignore_ascii_case("te")
                })
                .map(|(k, v)| format!("{k}: {v}"))
                .unwrap_or_else(|| panic!("example names neither field: {:?}", ex.snippet));

            let mut tx = if is_response {
                crate::test_helpers::make_test_transaction_with_response(200, &[])
            } else {
                crate::test_helpers::make_test_transaction()
            };
            let headers = crate::test_helpers::make_headers_from_pairs(&pairs);
            if is_response {
                tx.response.as_mut().unwrap().headers = headers;
            } else {
                tx.request.headers = headers;
            }

            let found = rule.check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            );
            match ex.compliance {
                Compliance::Compliant => assert!(
                    found.is_none(),
                    "rule rejects its Compliant example {subject:?}: {found:?}"
                ),
                Compliance::NonCompliant => {
                    let found = found.unwrap_or_else(|| {
                        panic!("rule accepts its NonCompliant example {subject:?}")
                    });
                    let expected = *reasons
                        .iter()
                        .find(|(v, _)| *v == subject)
                        .map(|(_, reason)| reason)
                        .unwrap_or_else(|| {
                            panic!("NonCompliant example {subject:?} has no expected finding here")
                        });
                    assert!(
                        found.message.contains(expected),
                        "NonCompliant example {subject:?} should fail with {expected:?}: {found:?}"
                    );
                }
            }
        }
    }

    /// § 7.2's compression codings define no parameters, and the presence of
    /// one is to be treated as an error. Everything from the first `;` used to
    /// be discarded unread.
    #[rstest]
    #[case("transfer-encoding", "gzip;level=9")]
    #[case("transfer-encoding", "deflate;foo=\"a,b\"")]
    #[case("transfer-encoding", "chunked, gzip;x=1")]
    #[case("transfer-encoding", "GZIP;X=1")]
    // No `weight` exists in `Transfer-Encoding`'s grammar, so a `q` here is an
    // ordinary parameter and gets no exemption.
    #[case("transfer-encoding", "gzip;q=0.5")]
    #[case("te", "deflate;foo=1")]
    fn a_parameter_on_a_compression_coding_is_reported(#[case] field: &str, #[case] value: &str) {
        let rule = MessageTransferCodingIanaRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(field, value)]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(
            v.is_some_and(|v| v.message.contains("defines no parameters")),
            "{field}: {value:?} carries a parameter § 7.2 forbids"
        );
    }

    /// The exemptions, each for its own reason: the TE rank is a weight and not
    /// a transfer-parameter; `chunked` is not one of § 7.2's codings and no
    /// sentence makes a parameter on it an error; a configured coding's
    /// parameters belong to whatever defines it.
    #[rstest]
    #[case("te", "deflate;q=0.5")]
    #[case("te", "trailers, deflate;q=0.5")]
    #[case("transfer-encoding", "chunked;ext=1")]
    fn parameters_that_are_not_a_finding(#[case] field: &str, #[case] value: &str) {
        let rule = MessageTransferCodingIanaRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(field, value)]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none(), "{field}: {value:?}: {v:?}");
    }

    /// `chunked` is registered, and in the default `allowed` list, so the
    /// registry check passes it everywhere. TE is the one field where being
    /// recognized is not enough.
    #[rstest]
    #[case("chunked")]
    #[case("chunked;q=0.8")]
    #[case("CHUNKED")]
    #[case("trailers, chunked")]
    fn chunked_is_forbidden_in_te(#[case] value: &str) {
        let rule = MessageTransferCodingIanaRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[("te", value)]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(
            v.is_some_and(|v| v.message.contains("must not send the chunked")),
            "TE: {value:?} is a MUST NOT"
        );
    }

    /// The prohibition belongs to TE alone. `Transfer-Encoding: chunked` is the
    /// ordinary case and must stay silent.
    #[test]
    fn chunked_is_ordinary_in_transfer_encoding() {
        let rule = MessageTransferCodingIanaRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("transfer-encoding", "gzip, chunked")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none(), "{v:?}");
    }

    /// A comma inside a transfer-parameter's quoted-string value is not a list
    /// separator. Cutting there invented a member out of the tail of the quoted
    /// value and reported a conforming field.
    #[rstest]
    #[case("chunked;ext=\"a,b\"")]
    // `chunked` rather than a compression coding: § 7.2 forbids a parameter on
    // those, and this case is about the splitter, not about the parameter.
    #[case("chunked;ext=\"a,b\", deflate")]
    #[case("chunked;ext=\"a\\\",b\"")]
    fn a_comma_inside_a_quoted_parameter_value_is_not_a_separator(#[case] value: &str) {
        let rule = MessageTransferCodingIanaRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("transfer-encoding", value)]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none(), "{value:?} is conforming: {v:?}");
    }

    /// Quoting that never closes leaves every later comma inside it, so the
    /// members cannot be delimited at all. Reported, because no other rule
    /// reports a malformed `Transfer-Encoding`.
    #[test]
    fn unterminated_quoting_is_reported() {
        let rule = MessageTransferCodingIanaRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "transfer-encoding",
            "gzip;ext=\"x, x-bogus",
        )]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.unwrap().message.contains("Unterminated quoted-string"));
    }

    /// A member that is nothing but parameters names no coding. It used to be
    /// reported as an unrecognized coding called `''`.
    #[test]
    fn a_member_with_no_coding_name_says_so() {
        let rule = MessageTransferCodingIanaRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("transfer-encoding", ";ext=1")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.unwrap().message.contains("Missing transfer-coding name"));
    }

    /// Empty list members are not elements, and the quote-aware splitter --
    /// unlike `parse_list_header` -- does not drop them for us.
    #[test]
    fn empty_list_members_are_skipped() {
        let rule = MessageTransferCodingIanaRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("transfer-encoding", ", chunked, ,")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none(), "{v:?}");
    }

    /// The same, for a response's `Transfer-Encoding`.
    #[test]
    fn every_response_transfer_encoding_line_is_read() {
        let rule = MessageTransferCodingIanaRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = hyper::HeaderMap::new();
        hm.append("transfer-encoding", HeaderValue::from_static("gzip"));
        hm.append("transfer-encoding", HeaderValue::from_static("x-bogus"));
        tx.response.as_mut().unwrap().headers = hm;

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some_and(|v| v.message.contains("x-bogus")));
    }

    #[test]
    fn scope_is_both() {
        let rule = MessageTransferCodingIanaRegistered;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }

    #[test]
    fn parse_config_allows_custom_list() -> anyhow::Result<()> {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_transfer_coding_iana_registered",
        ]);
        cfg.rules.insert(
            "message_transfer_coding_iana_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![toml::Value::String("x-custom".into())]),
                );
                t
            }),
        );

        let parsed = parse_allowed_config(&cfg, "message_transfer_coding_iana_registered")?;
        assert_eq!(parsed.allowed, vec!["x-custom".to_string()]);
        Ok(())
    }

    #[test]
    fn parse_config_rejects_empty_allowed_array() {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_transfer_coding_iana_registered",
        ]);
        cfg.rules.insert(
            "message_transfer_coding_iana_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert("allowed".into(), toml::Value::Array(vec![]));
                t
            }),
        );

        let res = parse_allowed_config(&cfg, "message_transfer_coding_iana_registered");
        assert!(res.is_err());
    }

    #[test]
    fn parse_config_rejects_non_string_allowed_item() {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_transfer_coding_iana_registered",
        ]);
        cfg.rules.insert(
            "message_transfer_coding_iana_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![toml::Value::Integer(1)]),
                );
                t
            }),
        );

        let res = parse_allowed_config(&cfg, "message_transfer_coding_iana_registered");
        assert!(res.is_err());
    }

    #[test]
    fn parse_config_requires_allowed_array() {
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_transfer_coding_iana_registered",
        ]);
        let res = parse_allowed_config(&cfg, "message_transfer_coding_iana_registered");
        assert!(res.is_err());
    }

    #[test]
    fn validate_parses_config() -> anyhow::Result<()> {
        let rule = MessageTransferCodingIanaRegistered;
        let mut full_cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_transfer_coding_iana_registered",
        ]);
        full_cfg.rules.insert(
            "message_transfer_coding_iana_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![toml::Value::String("chunked".into())]),
                );
                t
            }),
        );

        let arc = parse_allowed_config(&full_cfg, rule.id())?;
        assert!(arc.allowed.contains(&"chunked".to_string()));
        Ok(())
    }

    #[test]
    fn request_custom_allowed_is_accepted() -> anyhow::Result<()> {
        let rule = MessageTransferCodingIanaRegistered;
        let mut full_cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_transfer_coding_iana_registered",
        ]);
        full_cfg.rules.insert(
            "message_transfer_coding_iana_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![toml::Value::String("x-custom".into())]),
                );
                t
            }),
        );

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("te", "x-custom;q=0.5")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &full_cfg,
        );
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn response_custom_allowed_is_accepted() -> anyhow::Result<()> {
        let rule = MessageTransferCodingIanaRegistered;
        let mut full_cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_transfer_coding_iana_registered",
        ]);
        full_cfg.rules.insert(
            "message_transfer_coding_iana_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![toml::Value::String("x-custom".into())]),
                );
                t
            }),
        );

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("transfer-encoding", "x-custom")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &full_cfg,
        );
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn unrecognized_transfer_coding_message_and_severity() -> anyhow::Result<()> {
        let rule = MessageTransferCodingIanaRegistered;
        let mut cfg = crate::config::Config::default();
        cfg.rules.insert(
            "message_transfer_coding_iana_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("error".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![toml::Value::String("chunked".into())]),
                );
                t
            }),
        );

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("transfer-encoding", "x-foo")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let v = v.unwrap();
        assert_eq!(v.severity, crate::lint::Severity::Error);
        assert_eq!(
            v.message,
            "Unrecognized transfer-coding 'x-foo' in Transfer-Encoding header"
        );
        Ok(())
    }

    #[test]
    fn parse_config_rejects_non_table_rule_cfg() {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_transfer_coding_iana_registered",
        ]);
        cfg.rules.insert(
            "message_transfer_coding_iana_registered".into(),
            toml::Value::Integer(1),
        );
        let res = parse_allowed_config(&cfg, "message_transfer_coding_iana_registered");
        assert!(res.is_err());
    }

    #[test]
    fn parse_config_rejects_allowed_not_array() {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_transfer_coding_iana_registered",
        ]);
        cfg.rules.insert(
            "message_transfer_coding_iana_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert("allowed".into(), toml::Value::String("chunked".into()));
                t
            }),
        );

        let res = parse_allowed_config(&cfg, "message_transfer_coding_iana_registered");
        assert!(res.is_err());
    }

    #[rstest]
    #[case(Some("chunked"), false)]
    #[case(Some("x-custom"), true)]
    #[case(Some("chunked, x-custom"), true)]
    #[case(Some("chunked; param=1"), false)]
    #[case(None, false)]
    fn check_transfer_encoding_request_cases(
        #[case] te: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageTransferCodingIanaRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(v) = te {
            tx.request.headers =
                crate::test_helpers::make_headers_from_pairs(&[("transfer-encoding", v)]);
        }

        let violation = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(violation.is_some());
        } else {
            assert!(violation.is_none());
        }
        Ok(())
    }

    #[test]
    fn parse_config_requires_named_rule_cfg() {
        // No rule entry present at all should produce an error stating configuration is required
        let cfg = crate::config::Config::default();
        let res = parse_allowed_config(&cfg, "message_transfer_coding_iana_registered");
        assert!(res.is_err());
        let e = res.unwrap_err();
        // Depending on which helper fails first the message may reference "missing configuration"
        // or the older phrasing "requires configuration". Accept either.
        assert!(
            format!("{}", e).contains("missing configuration")
                || format!("{}", e).contains("requires configuration")
        );
    }

    #[test]
    fn te_trailers_with_unknown_reports_violation() -> anyhow::Result<()> {
        let rule = MessageTransferCodingIanaRegistered;
        let cfg = make_cfg();
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("te", "trailers, x-custom")]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let v = v.unwrap();
        assert!(
            v.message.contains("Unrecognized transfer-coding")
                || v.message.contains("Invalid token")
        );
        Ok(())
    }

    #[test]
    fn invalid_token_in_transfer_encoding_request_is_reported() -> anyhow::Result<()> {
        let rule = MessageTransferCodingIanaRegistered;
        let cfg = make_cfg();
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("transfer-encoding", "x@bad")]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let v = v.unwrap();
        assert!(v.message.contains("Invalid token"));
        Ok(())
    }
}
