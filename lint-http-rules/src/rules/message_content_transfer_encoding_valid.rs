// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageContentTransferEncodingValid;

impl Rule for MessageContentTransferEncodingValid {
    fn id(&self) -> &'static str {
        "message_content_transfer_encoding_valid"
    }

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
        // The five named mechanisms. The grammar admits two more alternatives —
        // `ietf-token` and `x-token` — so this list is not the whole of it; see the
        // x-token branch below.
        let allowed = ["7bit", "8bit", "binary", "quoted-printable", "base64"];

        // Describe what is wrong with the *value*, if anything. This is diagnostic
        // detail only: no value can make the field belong in an HTTP message, so the
        // verdict is decided by presence alone (below), not by this.
        let describe_value = |val: &str| -> Option<String> {
            let s = val.trim();
            if s.is_empty() {
                return Some("the value is empty".into());
            }

            // RFC 2045 defines a single token value here; if commas are present it's likely malformed
            let parts: Vec<&str> = crate::helpers::headers::parse_list_header(s).collect();
            // cite(RFC 2045 § 6.1): "mechanism := "7bit" / "8bit" / "binary" / "quoted-printable" / "base64" / ietf-token / x-token"
            if parts.len() > 1 {
                return Some(
                    "the value is a comma-separated list, but a mechanism is a single token".into(),
                );
            }

            let tok = parts[0];
            if let Some(c) = crate::helpers::token::find_invalid_token_char(tok) {
                return Some(format!("the value contains an invalid character: '{}'", c));
            }

            let lower = tok.to_ascii_lowercase();
            // `x-token` is a first-class alternative in the mechanism grammar, and
            // §6.3 spells out how to use it: a private encoding *must* carry the `X-`
            // prefix precisely so it is recognizable as non-standard. So an `x-`
            // value is the conforming way to name a private mechanism, not an
            // unrecognized one — rejecting it contradicted the grammar quoted above.
            // cite(RFC 2045 § 6.3): "Implementors may, if necessary, define private Content-Transfer-Encoding values, but must use an x-token, which is a name prefixed by "X-", to indicate its non-standard status"
            // cite(RFC 2045 § 6.1): "These values are not case sensitive"
            if !allowed.contains(&lower.as_str()) && !lower.starts_with("x-") {
                return Some(format!("'{}' is not a MIME transfer mechanism either", tok));
            }

            None
        };

        // The field's *presence* is the finding, whatever it carries. HTTP has no
        // Content-Transfer-Encoding: a gateway from a MIME-compliant protocol is
        // required to strip it before the message reaches an HTTP client, so one
        // arriving over HTTP means that strip did not happen. A recipient that
        // ignores the field (as an HTTP recipient will) reads the body without
        // decoding it, which silently yields the wrong bytes — the reason this is
        // worth reporting even when the value is a perfectly good MIME mechanism.
        // cite(RFC 9112 § B.5): "HTTP does not use the Content-Transfer-Encoding field of MIME."
        // cite(RFC 9112 § B.5): "Proxies and gateways from MIME-compliant protocols to HTTP need to remove any Content-Transfer-Encoding prior to delivering the response message to an HTTP client."
        let report = |which: &str, headers: &hyper::HeaderMap| -> Option<Violation> {
            let hv = headers.get_all("content-transfer-encoding").iter().next()?;
            let shown = hv.to_str().unwrap_or("<non-UTF-8>");
            let detail = describe_value(shown).map(|d| format!("; {}", d));
            Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!(
                    "Content-Transfer-Encoding: {} present in {}; HTTP does not use this field and a gateway is required to remove it{}",
                    shown.trim(),
                    which,
                    detail.unwrap_or_default()
                ),
            })
        };

        if let Some(resp) = &tx.response {
            if let Some(v) = report("response", &resp.headers) {
                return Some(v);
            }
        }
        report("request", &tx.request.headers)
    }

    fn description(&self) -> &'static str {
        "Flags any `Content-Transfer-Encoding` header in an HTTP message. HTTP does not use this field: it belongs to MIME, and a gateway from a MIME-compliant protocol is required to remove it before the message reaches an HTTP client, so one arriving over HTTP means that removal did not happen.\n\nThe consequence is silent corruption rather than a mere style problem — an HTTP recipient ignores the field, so a body that was (say) base64-encoded for MIME transport is read without being decoded.\n\nThe value is reported as detail: a single `token` naming one of `7bit`, `8bit`, `binary`, `quoted-printable`, `base64` (case-insensitive), or a private `x-` mechanism, is well-formed MIME — but being well-formed MIME does not make the field belong in HTTP."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9112",
                section: Some("B.5"),
                url: "https://www.rfc-editor.org/rfc/rfc9112.html#appendix-B.5",
                note: "Why the field is reported at all: HTTP does not use Content-Transfer-Encoding, and gateways from MIME-compliant protocols must remove it",
            },
            crate::rules::SpecRef {
                spec: "RFC 2045",
                section: Some("6.1"),
                url: "https://www.rfc-editor.org/rfc/rfc2045.html#section-6.1",
                note: "The MIME `mechanism` grammar the value is described against — five named encodings plus `ietf-token` / `x-token`, all case-insensitive",
            },
            crate::rules::SpecRef {
                spec: "RFC 2045",
                section: Some("6.3"),
                url: "https://www.rfc-editor.org/rfc/rfc2045.html#section-6.3",
                note: "Private mechanisms must be spelled with an `X-` prefix, which is why an `x-` value is well-formed MIME rather than an unrecognized one",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("HTTP carries no transfer encoding of its own here"),
                snippet: "HTTP/1.1 200 OK\nContent-Type: application/octet-stream\n\n<response body>",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("well-formed MIME, but HTTP does not use the field"),
                snippet: "HTTP/1.1 200 OK\nContent-Transfer-Encoding: base64\n\n<response body>",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("not a MIME mechanism either"),
                snippet: "HTTP/1.1 200 OK\nContent-Transfer-Encoding: no-such-mechanism\n\n<response body>",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &MessageContentTransferEncodingValid;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// Only absence is compliant: HTTP does not use the field, so every value —
    /// including a perfectly well-formed MIME mechanism — is reported.
    #[rstest]
    #[case(None, false)]
    #[case(Some("7bit"), true)]
    #[case(Some("BASE64"), true)]
    #[case(Some("quoted-printable"), true)]
    // `x-token` is how RFC 2045 §6.3 says to spell a private mechanism: it is
    // valid MIME, and still does not belong in an HTTP message.
    #[case(Some("x-custom"), true)]
    #[case(Some("X-My-New-Encoding"), true)]
    #[case(Some("base64, gzip"), true)]
    #[case(Some("bad@token"), true)]
    fn content_transfer_encoding_cases(
        #[case] hdr: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageContentTransferEncodingValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_content_transfer_encoding_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        if let Some(v) = hdr {
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[("content-transfer-encoding", v)]);
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
    fn non_utf8_header_values_are_ignored() -> anyhow::Result<()> {
        let rule = MessageContentTransferEncodingValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_content_transfer_encoding_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = hyper::HeaderMap::new();
        hm.insert(
            "content-transfer-encoding",
            hyper::header::HeaderValue::from_bytes(b"\xff").unwrap(),
        );
        tx.response.as_mut().unwrap().headers = hm;

        // The value cannot be decoded, but presence is what is reported, so a
        // non-UTF-8 value is still a finding rather than a silent skip.
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        let v = v.expect("presence is reported regardless of the value");
        assert!(v.message.contains("<non-UTF-8>"));
        Ok(())
    }

    #[test]
    fn request_header_valid_and_request_scoped_is_checked() -> anyhow::Result<()> {
        let rule = MessageContentTransferEncodingValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_content_transfer_encoding_valid",
        ]);

        // A well-formed MIME mechanism on a request is still reported: the field
        // does not belong in an HTTP message at all.
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-transfer-encoding", "8bit")]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        let v = v.expect("presence in a request is reported");
        assert!(v.message.contains("present in request"));
        assert!(!v.message.contains("is not a MIME transfer mechanism"));

        // invalid request header should produce a violation
        let mut tx2 = crate::test_helpers::make_test_transaction();
        tx2.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-transfer-encoding",
            "xcodec",
        )]);
        let v2 = rule.check_transaction(
            &tx2,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v2.is_some());
        Ok(())
    }

    #[test]
    fn empty_header_value_is_violation_and_multiple_headers_with_one_invalid_is_reported(
    ) -> anyhow::Result<()> {
        let rule = MessageContentTransferEncodingValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_content_transfer_encoding_valid",
        ]);

        // empty header value
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-transfer-encoding", " ")]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());

        // multiple header fields where one is invalid -> should report violation
        let tx2 = crate::test_helpers::make_test_transaction_with_headers(&[
            ("content-transfer-encoding", "base64"),
            // Not `x-bad`: an `x-` name is a conforming private mechanism.
            ("content-transfer-encoding", "no-such-mechanism"),
        ]);
        let v2 = rule.check_transaction(
            &tx2,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v2.is_some());
        Ok(())
    }

    #[test]
    fn scope_is_both() {
        let rule = MessageContentTransferEncodingValid;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }
}
