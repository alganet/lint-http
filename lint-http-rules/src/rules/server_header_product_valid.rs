// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ServerHeaderProductValid;

impl Rule for ServerHeaderProductValid {
    fn id(&self) -> &'static str {
        "server_header_product_valid"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        // `Server` is defined for responses only, so a request carrying one is
        // not this rule's subject -- there is no sentence giving the field a
        // meaning in that direction to measure the value against.
        // cite(RFC 9110 § 10.2.4): "An origin server MAY generate a Server header field in its responses."
        crate::rules::RuleScope::Server
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
        let resp = tx.response.as_ref()?;

        // The response trailer section is deliberately not walked. §10.2.4
        // permits `Server` in a response and says nothing about trailers, which
        // makes a `Server` trailer a violation of the sentence below rather than
        // a value for this rule to grammar-check; the trailer rules own it.
        // cite(RFC 9110 § 6.5.1): "A sender MUST NOT generate a trailer field unless the sender knows the corresponding header field name's definition permits the field to be sent in trailers."
        //
        // Each field line is parsed on its own, and deliberately not joined
        // first. No alternative of `Server` is a comma-separated list, so the
        // recombination the note in §5.5 assumes does not apply here and the
        // comma a recipient would insert is not a `tchar` -- joining would turn
        // a second field line into a grammar finding, which blames the wrong
        // sentence. The second line is a violation of §5.3 as a whole message,
        // which `singleton_fields_not_repeated` owns and reports.
        // cite(RFC 9110 § 5.3): "a sender MUST NOT generate multiple field lines with the same name in a message (whether in the headers or trailers)"
        for hv in resp.headers.get_all("server").iter() {
            // The raw octets, not `to_str()`: `ctext` admits `obs-text`, so a
            // conforming `Server` value is not always visible US-ASCII and the
            // decode would reject the field before the grammar could accept it.
            // cite(RFC 9110 § 5.5): "A recipient SHOULD treat other allowed octets in field content (i.e., obs-text) as opaque data."
            if let Err(e) = crate::helpers::product::validate_product_list(hv.as_bytes()) {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!("Invalid Server header: {}", e),
                });
            }
        }

        None
    }

    fn description(&self) -> &'static str {
        "Validate a `Server` response header against `Server = product *( RWS ( product / comment ) )`. Each product is a `token` with an optional `/`-separated version token; parenthesized comments may nest and may hold a `quoted-pair`, but a comment can only follow a product, so a value that opens with one — or holds nothing else — does not match the grammar. Required whitespace between elements is enforced, and `obs-text` is accepted inside a comment, where `ctext` allows it, and nowhere else."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("10.2.4"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.4",
                note: "`Server = product *( RWS ( product / comment ) )`; the section defines the field and defers the product syntax itself to Section 10.1.5",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("10.1.5"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1.5",
                note: "`product = token [\"/\" product-version]` and `product-version = token`, defined once under `User-Agent` and shared by `Server`",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("5.6.5"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.5",
                note: "`comment = \"(\" *( ctext / quoted-pair / comment ) \")\"` — comments nest, and `ctext` admits `obs-text` but not the parentheses or the backslash",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nServer: nginx/1.18.0",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("the example RFC 9110 prints for the field"),
                snippet: "HTTP/1.1 200 OK\nServer: CERN/3.0 libwww/2.17",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("a comment following a product"),
                snippet: "HTTP/1.1 200 OK\nServer: Apache/2.4.41 (Ubuntu)",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("no leading product identifier"),
                snippet: "HTTP/1.1 200 OK\nServer: /1.0",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("a comment before the first product"),
                snippet: "HTTP/1.1 200 OK\nServer: (Ubuntu) Apache/2.4.41",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("illegal character in the product token"),
                snippet: "HTTP/1.1 200 OK\nServer: Bad@Srv/1.0",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("illegal character in the product version"),
                snippet: "HTTP/1.1 200 OK\nServer: Srv/1@0",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("unterminated comment"),
                snippet: "HTTP/1.1 200 OK\nServer: Bad (unbalanced comment",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ServerHeaderProductValid;

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;
    use rstest::rstest;

    #[rstest]
    #[case(Some("nginx/1.18.0"), false)]
    #[case(Some("nginx"), false)]
    #[case(Some("Apache/2.4.41 (Ubuntu)"), false)]
    #[case(Some("MySrv/1.0 Another/2.0"), false)]
    #[case(Some("CERN/3.0 libwww/2.17"), false)]
    #[case(Some("/1.0"), true)]
    #[case(Some("Bad@Srv/1.0"), true)]
    #[case(Some("Srv/1@0"), true)]
    #[case(Some("Srv//1.0"), true)]
    #[case(Some("nginx/1.18.0(Ubuntu)"), true)]
    #[case(None, false)]
    fn check_server_header_response(
        #[case] server: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = ServerHeaderProductValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "server_header_product_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut resp = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        if let Some(v) = server {
            resp.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[("server", v)]);
        }
        tx.response = resp.response;

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
    fn multiple_server_fields_checked() -> anyhow::Result<()> {
        let rule = ServerHeaderProductValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "server_header_product_valid",
        ]);

        let mut hm = crate::test_helpers::make_headers_from_pairs(&[("server", "nginx/1.18.0")]);
        hm.append("server", HeaderValue::from_static("Bad@Srv/1.0"));
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = hm;

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        Ok(())
    }

    /// `obs-text` is `ctext`, so the same octet is a conforming comment
    /// character and a non-`tchar` outside one. The rule reads the raw octets
    /// precisely so the two cases can be told apart.
    #[rstest]
    #[case(b"\xff".as_slice(), true)]
    #[case(b"Apache (U\xdcnix)".as_slice(), false)]
    #[case(b"Apac\xdche".as_slice(), true)]
    fn obs_text_is_judged_by_where_it_sits(
        #[case] value: &[u8],
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = ServerHeaderProductValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "server_header_product_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        hm.insert("server", HeaderValue::from_bytes(value).unwrap());
        tx.response.as_mut().unwrap().headers = hm;

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert_eq!(v.is_some(), expect_violation, "{value:?} -> {v:?}");
        Ok(())
    }

    #[test]
    fn unterminated_comment_reports_violation() -> anyhow::Result<()> {
        let rule = ServerHeaderProductValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "server_header_product_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("server", "Bad (unbalanced")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn server_only_comments_is_reported() -> anyhow::Result<()> {
        let rule = ServerHeaderProductValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "server_header_product_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("server", "(Apache)")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        Ok(())
    }

    /// A comment is only reachable through the repetition that follows the
    /// first product, so a leading one is a grammar violation however
    /// product-like the rest of the value looks. The rule used to strip
    /// comments before parsing and so could not see the difference.
    #[test]
    fn comment_before_the_first_product_is_reported() -> anyhow::Result<()> {
        let rule = ServerHeaderProductValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "server_header_product_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("server", "(test) nginx/1.18.0")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v
            .unwrap()
            .message
            .contains("does not begin with a product identifier"));
        Ok(())
    }

    /// A comment may follow a product, and may nest.
    #[test]
    fn nested_comment_after_a_product_is_accepted() -> anyhow::Result<()> {
        let rule = ServerHeaderProductValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "server_header_product_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "server",
            "Apache/2.4.41 (Ubuntu (LTS)) mod_x/1.0",
        )]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none(), "{v:?}");
        Ok(())
    }

    #[test]
    fn published_examples_are_judged_the_way_they_are_labelled() {
        use crate::rules::{Compliance, Rule as _};
        let rule = ServerHeaderProductValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "server_header_product_valid",
        ]);

        let mut saw_a_finding = false;
        for ex in rule.examples() {
            let pairs: Vec<(&str, &str)> = ex
                .snippet
                .lines()
                .skip(1)
                .filter(|l| !l.trim().is_empty())
                .map(|l| {
                    l.split_once(": ")
                        .unwrap_or_else(|| panic!("not a header line: {l:?}"))
                })
                .collect();

            let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&pairs);
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
                    found.unwrap_or_else(|| {
                        panic!("rule accepts its NonCompliant example {:?}", ex.snippet)
                    });
                    saw_a_finding = true;
                }
            }
        }
        assert!(saw_a_finding, "the guard never produced a finding");
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "server_header_product_valid");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
