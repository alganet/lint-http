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

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
        // Validate a single Accept-like header value (media-range list)
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
                // ignoring it is all this rule does with it.
                if member.is_empty() {
                    continue;
                }
                // Quote-aware for the same reason: a `;` inside a quoted value
                // does not start a parameter.
                let mut parts =
                    crate::helpers::headers::split_semicolons_respecting_quotes(member).into_iter();
                let media = parts.next().unwrap_or("").trim();
                if media.is_empty() {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!("Empty media-range in {} header", hdr),
                    });
                }

                // Accept allows "*/*", "type/*" or "type/subtype" only. A bare "*" is invalid.
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

                    // cite(RFC 9110 § 12.5.1): "Accept = #( media-range [ weight ] )"
                    if let Ok(parsed) = crate::helpers::headers::parse_media_type(media) {
                        // validate type and subtype tokens (allow '*' as subtype)
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
                    // grammar. RFC 9110 removed the `accept-ext` production
                    // that used to allow it and states the consequence as a
                    // SHOULD on senders.
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
                    let mut kv = p.splitn(2, '=');
                    let k = kv.next().unwrap().trim();
                    let v = kv.next();
                    if v.is_none() {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!(
                                "Invalid parameter '{}' in {} header: missing '='",
                                p, hdr
                            ),
                        });
                    }
                    let v = v.unwrap().trim();
                    // Parameter name must be a token
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

                    if k.eq_ignore_ascii_case("q") {
                        weight_seen = true;
                        if !crate::helpers::headers::valid_qvalue(v) {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: format!("Invalid qvalue '{}' in {} header", v, hdr),
                            });
                        }
                    } else {
                        // value may be token or quoted-string
                        if v.starts_with('"') {
                            if let Err(e) = crate::helpers::headers::validate_quoted_string(v) {
                                return Some(Violation {
                                    rule: self.id().into(),
                                    severity: config.severity,
                                    message: format!(
                                        "Invalid quoted-string parameter '{}' in {} header: {}",
                                        p, hdr, e
                                    ),
                                });
                            }
                        } else if let Some(c) = crate::helpers::token::find_invalid_token_char(v) {
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

    fn description(&self) -> &'static str {
        "Validate `Accept` header media-range syntax. Each member must be a valid media-range (`type/subtype`, `type/*`, or `*/*`), and parameters must be well-formed (`name=value`). The `q` parameter must be a valid quality value (0.000–1.000 with up to three decimal places). This rule is conservative and focuses on syntactic correctness rather than semantic content negotiation."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[crate::rules::SpecRef {
            spec: "RFC 9110",
            section: Some("12.5.1"),
            url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.1",
            note: "Accept header field and media-range syntax",
        }]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "Accept: text/html\nAccept: application/json; charset=utf-8\nAccept: text/*;q=0.8, application/json;q=0.9\nAccept: */*;q=0.1",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "Accept: *\nAccept: text; q=0.8\nAccept: text/html; q=1.0000\nAccept: application/json; charset=bad\\x01",
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

    #[test]
    fn message_and_id() {
        let rule = MessageAcceptHeaderMediaTypeSyntax;
        assert_eq!(rule.id(), "message_accept_header_media_type_syntax");
        assert_eq!(rule.scope(), crate::rules::RuleScope::Client);
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
