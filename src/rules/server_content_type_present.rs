// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;
use crate::state::StateStore;

pub struct ServerContentTypePresent;

impl Rule for ServerContentTypePresent {
    fn id(&self) -> &'static str {
        "server_content_type_present"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _state: &StateStore,
        _config: &crate::config::Config,
    ) -> Option<Violation> {
        let Some(resp) = &tx.response else {
            return None;
        };

        // Per RFCs, no body is allowed for 1xx, 204, 304 responses
        let status = resp.status;
        if (100..200).contains(&status) || status == 204 || status == 304 {
            return None;
        }

        if resp.headers.contains_key("content-type") {
            return None;
        }

        // If response likely contains a body, require Content-Type.
        let has_nonzero_content_length = resp
            .headers
            .get("content-length")
            .and_then(|v| v.to_str().ok().and_then(|s| s.parse::<usize>().ok()))
            .map(|n| n > 0)
            .unwrap_or(false);

        let has_transfer_encoding = resp.headers.contains_key("transfer-encoding");

        // There is likely a body if any of the following holds:
        // - non-zero Content-Length
        // - Transfer-Encoding is present
        // - 2xx status and neither Content-Length nor Transfer-Encoding is present
        let likely_has_body = has_nonzero_content_length
            || has_transfer_encoding
            || ((200..300).contains(&status) && !resp.headers.contains_key("content-length"));

        if likely_has_body {
            return Some(Violation {
                rule: self.id().into(),
                severity: crate::rules::get_rule_severity(_config, self.id()),
                message: "Response likely has body but is missing Content-Type header".into(),
            });
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::make_test_context;
    use rstest::rstest;

    #[rstest]
    #[case(200, vec![("content-type", "text/html")], false, None)]
    #[case(200, vec![], true, Some("Response likely has body but is missing Content-Type header"))]
    #[case(204, vec![], false, None)]
    #[case(100, vec![], false, None)]
    #[case(101, vec![], false, None)]
    #[case(304, vec![], false, None)]
    #[case(200, vec![("content-length", "0")], false, None)]
    #[case(200, vec![("content-length", "10")], true, Some("Response likely has body but is missing Content-Type header"))]
    #[case(404, vec![("content-type", "text/html")], false, None)]
    #[case(404, vec![("content-length", "10")], true, Some("Response likely has body but is missing Content-Type header"))]
    #[case(500, vec![("transfer-encoding", "chunked")], true, Some("Response likely has body but is missing Content-Type header"))]
    #[case(200, vec![("transfer-encoding", "chunked")], true, Some("Response likely has body but is missing Content-Type header"))]
    fn check_response_cases(
        #[case] status: u16,
        #[case] header_pairs: Vec<(&str, &str)>,
        #[case] expect_violation: bool,
        #[case] expected_message: Option<&str>,
    ) -> anyhow::Result<()> {
        let rule = ServerContentTypePresent;
        let (_client, _state) = make_test_context();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status,
            headers: crate::test_helpers::make_headers_from_pairs(header_pairs.as_slice()),
        });

        let violation = rule.check_transaction(&tx, &_state, &crate::config::Config::default());

        if expect_violation {
            assert!(violation.is_some());
            assert_eq!(
                violation.map(|v| v.message),
                expected_message.map(|s| s.to_string())
            );
        } else {
            assert!(violation.is_none());
        }
        Ok(())
    }
}
