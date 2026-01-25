// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ServerProblemDetailsContentType;

impl Rule for ServerProblemDetailsContentType {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "server_problem_details_content_type"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _previous: Option<&crate::http_transaction::HttpTransaction>,
        config: &Self::Config,
    ) -> Option<Violation> {
        let resp = match &tx.response {
            Some(r) => r,
            None => return None,
        };

        // Only consider responses that indicate an error or problem (4xx/5xx)
        if resp.status < 400 {
            return None;
        }

        if let Some(ct_str) = crate::helpers::headers::get_header_str(&resp.headers, "content-type")
        {
            if let Ok(parsed) = crate::helpers::headers::parse_media_type(ct_str) {
                let t = parsed.type_.to_ascii_lowercase();
                let sub = parsed.subtype.to_ascii_lowercase();

                // Accept application/problem+json and application/problem+xml
                if t == "application" && (sub == "problem+json" || sub == "problem+xml") {
                    return None;
                }

                // If the response is JSON-ish but not using Problem Details media type,
                // flag as a SHOULD: servers SHOULD use application/problem+json or application/problem+xml
                if sub == "json" || sub.ends_with("+json") || sub == "xml" || sub.ends_with("+xml")
                {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!(
                            "Problem Details responses SHOULD use 'application/problem+json' or 'application/problem+xml' (found '{}')",
                            ct_str
                        ),
                    });
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(400, Some("application/problem+json"), false)]
    #[case(400, Some("application/PROBLEM+JSON"), false)]
    #[case(400, Some("application/problem+JSON"), false)]
    #[case(500, Some("application/problem+xml"), false)]
    #[case(500, Some("application/json"), true)]
    #[case(404, Some("application/json; charset=utf-8"), true)]
    #[case(500, Some("application/hal+json"), true)]
    #[case(500, Some("application/xml"), true)]
    #[case(500, Some("text/xml"), true)]
    #[case(500, Some("text/problem+json"), true)]
    #[case(500, Some("application/problem+xml; charset=utf-8"), false)]
    #[case(500, Some("text/html"), false)]
    #[case(500, Some("not-a-media"), false)]
    #[case(200, Some("application/json"), false)]
    #[case(404, None, false)]
    fn check_cases(
        #[case] status: u16,
        #[case] content_type: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = ServerProblemDetailsContentType;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(
                &content_type
                    .map(|v| ("content-type", v))
                    .into_iter()
                    .collect::<Vec<_>>(),
            ),

            body_length: None,
        });

        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        if expect_violation {
            assert!(v.is_some());
            let msg = v.unwrap().message;
            assert!(msg.contains("Problem Details responses SHOULD use"));
        } else {
            assert!(v.is_none());
        }
        Ok(())
    }

    #[test]
    fn scope_is_server() {
        let rule = ServerProblemDetailsContentType;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }
}
