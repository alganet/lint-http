// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// Trailer fields that MUST NOT appear per RFC 9110 §6.5.1.
///
/// Includes fields necessary for message framing, routing, request modifiers
/// (controls and conditionals), authentication, response control data, and
/// fields that determine how to process the payload.
const PROHIBITED_TRAILER_FIELDS: &[&str] = &[
    // Message framing (RFC 9110 §6.5.1)
    "content-length",
    "transfer-encoding",
    // Routing
    "host",
    // Request modifiers — controls
    "cache-control",
    "expect",
    "max-forwards",
    "pragma",
    "range",
    "te",
    // Request modifiers — conditionals
    "if-match",
    "if-modified-since",
    "if-none-match",
    "if-range",
    "if-unmodified-since",
    // Authentication (RFC 9110 §11)
    "authentication-info",
    "authorization",
    "proxy-authenticate",
    "proxy-authentication-info",
    "proxy-authorization",
    "www-authenticate",
    // Response control data (RFC 9110 §6.2)
    "age",
    "date",
    "expires",
    "location",
    "retry-after",
    "vary",
    "warning",
    // Payload processing
    "content-encoding",
    "content-range",
    "content-type",
    "trailer",
    // Hop-by-hop (RFC 9110 §7.6.1)
    "connection",
    "keep-alive",
    "upgrade",
];

pub struct MessageTrailerFieldsValidity;

impl Rule for MessageTrailerFieldsValidity {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_trailer_fields_validity"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        config: &Self::Config,
    ) -> Option<Violation> {
        // Check request trailers.
        if let Some(ref trailers) = tx.request.trailers {
            let declared = collect_declared_trailers(&tx.request.headers);
            let conn_val =
                crate::helpers::headers::get_header_str(&tx.request.headers, "connection");
            if let Some(v) = check_trailers(self.id(), config, trailers, &declared, conn_val) {
                return Some(v);
            }
        }

        // Check response trailers.
        if let Some(ref resp) = tx.response {
            if let Some(ref trailers) = resp.trailers {
                let declared = collect_declared_trailers(&resp.headers);
                let conn_val = crate::helpers::headers::get_header_str(&resp.headers, "connection");
                if let Some(v) = check_trailers(self.id(), config, trailers, &declared, conn_val) {
                    return Some(v);
                }
            }
        }

        None
    }
}

/// Collect field-names declared in the `Trailer` header, lowercased.
fn collect_declared_trailers(headers: &hyper::HeaderMap) -> Vec<String> {
    let mut declared = Vec::new();
    let mut saw_trailer_header = false;
    let mut saw_invalid_or_empty_value = false;
    for val in headers.get_all("trailer") {
        saw_trailer_header = true;
        match val.to_str() {
            Ok(s) => {
                let mut had_member = false;
                for member in crate::helpers::headers::parse_list_header(s) {
                    had_member = true;
                    declared.push(member.to_ascii_lowercase());
                }
                // If the value was present but contained only whitespace (and thus
                // produced no list members), treat it as effectively invalid so
                // we don't silently downgrade checks.
                if !had_member && s.trim().is_empty() {
                    saw_invalid_or_empty_value = true;
                }
            }
            // Non-UTF-8 values are invalid for header field-content; remember that
            // we saw an unusable Trailer declaration instead of ignoring it.
            Err(_) => {
                saw_invalid_or_empty_value = true;
            }
        }
    }
    // If a Trailer header was present but yielded no valid field-names (because
    // all values were invalid/empty), insert a sentinel so that downstream code
    // can distinguish this from "no Trailer header at all" and still run
    // undeclared-trailer checks.
    if saw_trailer_header && declared.is_empty() && saw_invalid_or_empty_value {
        declared.push("__lint_http_invalid_trailer_declaration__".to_string());
    }
    declared
}

/// Validate actual trailer fields against the prohibited list and declared set.
fn check_trailers(
    rule_id: &str,
    config: &crate::rules::RuleConfig,
    trailers: &hyper::HeaderMap,
    declared: &[String],
    connection_val: Option<&str>,
) -> Option<Violation> {
    for key in trailers.keys() {
        let name = key.as_str(); // hyper normalises header names to lowercase

        // Prohibited trailer field (MUST NOT per RFC 9110 §6.5.1).
        if PROHIBITED_TRAILER_FIELDS.contains(&name) {
            return Some(Violation {
                rule: rule_id.to_string(),
                severity: config.severity,
                message: format!(
                    "Trailer section contains prohibited field '{}'; \
                     trailers must not include fields used for message framing, \
                     routing, request modifiers, authentication, response control \
                     data, or payload processing (RFC 9110 §6.5.1)",
                    name
                ),
            });
        }

        // Dynamic hop-by-hop: headers nominated by the Connection header
        // are hop-by-hop and must not appear as trailer fields.
        // The static hop-by-hop set is already covered by PROHIBITED_TRAILER_FIELDS,
        // so we only need to check Connection-nominated headers here.
        if crate::helpers::headers::is_hop_by_hop_header(name, connection_val)
            && !PROHIBITED_TRAILER_FIELDS.contains(&name)
        {
            return Some(Violation {
                rule: rule_id.to_string(),
                severity: config.severity,
                message: format!(
                    "Trailer field '{}' is a hop-by-hop header nominated by the \
                     Connection header; trailers must not contain hop-by-hop \
                     fields (RFC 9110 §6.5.1, §7.6.1)",
                    name
                ),
            });
        }

        // Undeclared trailer field — only checked when a Trailer header exists.
        if !declared.is_empty() && !declared.iter().any(|d| d == name) {
            return Some(Violation {
                rule: rule_id.to_string(),
                severity: config.severity,
                message: format!(
                    "Trailer field '{}' was not declared in the Trailer header; \
                     senders should list expected trailer fields before the \
                     message body (RFC 9110 §6.5)",
                    name
                ),
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{
        make_headers_from_pairs, make_test_rule_config, make_test_transaction,
        make_test_transaction_with_response,
    };
    use crate::transaction_history::TransactionHistory;
    use rstest::rstest;

    fn cfg() -> crate::rules::RuleConfig {
        make_test_rule_config()
    }

    fn empty_history() -> TransactionHistory {
        TransactionHistory::empty()
    }

    // ---- Prohibited trailer fields (response) ----

    #[rstest]
    #[case("content-length")]
    #[case("transfer-encoding")]
    #[case("host")]
    #[case("cache-control")]
    #[case("expect")]
    #[case("max-forwards")]
    #[case("pragma")]
    #[case("range")]
    #[case("te")]
    #[case("if-match")]
    #[case("if-modified-since")]
    #[case("if-none-match")]
    #[case("if-range")]
    #[case("if-unmodified-since")]
    #[case("authentication-info")]
    #[case("authorization")]
    #[case("proxy-authenticate")]
    #[case("proxy-authentication-info")]
    #[case("proxy-authorization")]
    #[case("www-authenticate")]
    #[case("age")]
    #[case("date")]
    #[case("expires")]
    #[case("location")]
    #[case("retry-after")]
    #[case("vary")]
    #[case("warning")]
    #[case("content-encoding")]
    #[case("content-range")]
    #[case("content-type")]
    #[case("trailer")]
    #[case("connection")]
    #[case("keep-alive")]
    #[case("upgrade")]
    fn response_prohibited_trailer_field_is_violation(#[case] field: &str) {
        let rule = MessageTrailerFieldsValidity;
        let mut tx = make_test_transaction_with_response(200, &[]);
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert(
            field.parse::<hyper::header::HeaderName>().unwrap(),
            "some-value".parse().unwrap(),
        );
        tx.response.as_mut().unwrap().trailers = Some(trailers);

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(
            v.is_some(),
            "expected violation for prohibited trailer '{field}'"
        );
        assert!(v.unwrap().message.contains(field));
    }

    // ---- Prohibited trailer fields (request) ----

    #[rstest]
    #[case("content-length")]
    #[case("transfer-encoding")]
    #[case("host")]
    #[case("authorization")]
    #[case("content-type")]
    #[case("trailer")]
    fn request_prohibited_trailer_field_is_violation(#[case] field: &str) {
        let rule = MessageTrailerFieldsValidity;
        let mut tx = make_test_transaction();
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert(
            field.parse::<hyper::header::HeaderName>().unwrap(),
            "some-value".parse().unwrap(),
        );
        tx.request.trailers = Some(trailers);

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(
            v.is_some(),
            "expected violation for prohibited request trailer '{field}'"
        );
        assert!(v.unwrap().message.contains(field));
    }

    // ---- Valid trailer fields ----

    #[test]
    fn response_valid_trailer_field_no_violation() {
        let rule = MessageTrailerFieldsValidity;
        let mut tx = make_test_transaction_with_response(200, &[]);
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("x-checksum", "abc123".parse().unwrap());
        tx.response.as_mut().unwrap().trailers = Some(trailers);

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_none());
    }

    #[test]
    fn request_valid_trailer_field_no_violation() {
        let rule = MessageTrailerFieldsValidity;
        let mut tx = make_test_transaction();
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("x-checksum", "abc123".parse().unwrap());
        tx.request.trailers = Some(trailers);

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_none());
    }

    // ---- No trailers at all — no violation ----

    #[test]
    fn no_trailers_no_violation() {
        let rule = MessageTrailerFieldsValidity;
        let tx = make_test_transaction_with_response(200, &[]);
        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_none());
    }

    #[test]
    fn request_only_no_trailers_no_violation() {
        let rule = MessageTrailerFieldsValidity;
        let tx = make_test_transaction();
        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_none());
    }

    // ---- Undeclared trailer fields ----

    #[test]
    fn response_trailer_not_declared_in_trailer_header_is_violation() {
        let rule = MessageTrailerFieldsValidity;
        let mut tx = make_test_transaction_with_response(200, &[("trailer", "x-checksum")]);
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("x-signature", "sig-value".parse().unwrap());
        tx.response.as_mut().unwrap().trailers = Some(trailers);

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("not declared"));
    }

    #[test]
    fn request_trailer_not_declared_in_trailer_header_is_violation() {
        let rule = MessageTrailerFieldsValidity;
        let mut tx = make_test_transaction();
        tx.request.headers = make_headers_from_pairs(&[("trailer", "x-checksum")]);
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("x-signature", "sig-value".parse().unwrap());
        tx.request.trailers = Some(trailers);

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("not declared"));
    }

    #[test]
    fn response_trailer_declared_and_matching_no_violation() {
        let rule = MessageTrailerFieldsValidity;
        let mut tx = make_test_transaction_with_response(200, &[("trailer", "X-Checksum")]);
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("x-checksum", "abc123".parse().unwrap());
        tx.response.as_mut().unwrap().trailers = Some(trailers);

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_none());
    }

    #[test]
    fn response_trailer_declared_case_insensitive_match() {
        let rule = MessageTrailerFieldsValidity;
        let mut tx = make_test_transaction_with_response(200, &[("trailer", "X-CHECKSUM")]);
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("x-checksum", "abc123".parse().unwrap());
        tx.response.as_mut().unwrap().trailers = Some(trailers);

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_none());
    }

    #[test]
    fn response_trailer_multiple_declared_fields() {
        let rule = MessageTrailerFieldsValidity;
        let mut tx =
            make_test_transaction_with_response(200, &[("trailer", "X-Checksum, X-Signature")]);
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("x-checksum", "abc123".parse().unwrap());
        trailers.insert("x-signature", "sig-value".parse().unwrap());
        tx.response.as_mut().unwrap().trailers = Some(trailers);

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_none());
    }

    // ---- No Trailer header but trailers present — no undeclared violation ----

    #[test]
    fn response_trailers_present_without_trailer_header_no_undeclared_violation() {
        let rule = MessageTrailerFieldsValidity;
        let mut tx = make_test_transaction_with_response(200, &[]);
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("x-checksum", "abc123".parse().unwrap());
        tx.response.as_mut().unwrap().trailers = Some(trailers);

        // No Trailer header → declared is empty → undeclared check skipped
        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_none());
    }

    // ---- Prohibited takes priority over undeclared ----

    #[test]
    fn prohibited_field_takes_priority_over_undeclared() {
        let rule = MessageTrailerFieldsValidity;
        let mut tx = make_test_transaction_with_response(200, &[("trailer", "x-checksum")]);
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("content-length", "42".parse().unwrap());
        tx.response.as_mut().unwrap().trailers = Some(trailers);

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("prohibited"));
    }

    // ---- Connection-nominated hop-by-hop trailer fields ----

    #[test]
    fn response_connection_nominated_trailer_is_violation() {
        let rule = MessageTrailerFieldsValidity;
        let mut tx = make_test_transaction_with_response(200, &[("connection", "X-Custom-Hop")]);
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("x-custom-hop", "value".parse().unwrap());
        tx.response.as_mut().unwrap().trailers = Some(trailers);

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("hop-by-hop"));
    }

    #[test]
    fn request_connection_nominated_trailer_is_violation() {
        let rule = MessageTrailerFieldsValidity;
        let mut tx = make_test_transaction();
        tx.request.headers = make_headers_from_pairs(&[("connection", "X-Req-Hop")]);
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("x-req-hop", "value".parse().unwrap());
        tx.request.trailers = Some(trailers);

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("hop-by-hop"));
    }

    #[test]
    fn connection_nominated_case_insensitive_match() {
        let rule = MessageTrailerFieldsValidity;
        let mut tx = make_test_transaction_with_response(200, &[("connection", "X-CUSTOM-HOP")]);
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("x-custom-hop", "value".parse().unwrap());
        tx.response.as_mut().unwrap().trailers = Some(trailers);

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("hop-by-hop"));
    }

    #[test]
    fn trailer_not_in_connection_is_ok() {
        let rule = MessageTrailerFieldsValidity;
        let mut tx = make_test_transaction_with_response(200, &[("connection", "X-Custom-Hop")]);
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("x-other", "value".parse().unwrap());
        tx.response.as_mut().unwrap().trailers = Some(trailers);

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_none());
    }

    #[test]
    fn prohibited_takes_priority_over_connection_nominated() {
        // A statically prohibited field is caught before the dynamic check.
        let rule = MessageTrailerFieldsValidity;
        let mut tx =
            make_test_transaction_with_response(200, &[("connection", "transfer-encoding")]);
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("transfer-encoding", "chunked".parse().unwrap());
        tx.response.as_mut().unwrap().trailers = Some(trailers);

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_some());
        // Should say "prohibited", not "hop-by-hop", since static check runs first.
        assert!(v.unwrap().message.contains("prohibited"));
    }

    // ---- Request trailers checked before response trailers ----

    #[test]
    fn request_trailers_checked_first() {
        let rule = MessageTrailerFieldsValidity;
        let mut tx = make_test_transaction_with_response(200, &[]);

        // Add prohibited field to request trailers
        let mut req_trailers = hyper::HeaderMap::new();
        req_trailers.insert("host", "example.com".parse().unwrap());
        tx.request.trailers = Some(req_trailers);

        // Add valid field to response trailers
        let mut resp_trailers = hyper::HeaderMap::new();
        resp_trailers.insert("x-checksum", "abc".parse().unwrap());
        tx.response.as_mut().unwrap().trailers = Some(resp_trailers);

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("host"));
    }

    // ---- Multiple Trailer header fields ----

    #[test]
    fn multiple_trailer_header_fields_collected() {
        let rule = MessageTrailerFieldsValidity;
        let mut tx = make_test_transaction_with_response(200, &[]);
        let mut hm = hyper::HeaderMap::new();
        hm.append(
            "trailer",
            "X-Checksum".parse::<hyper::header::HeaderValue>().unwrap(),
        );
        hm.append(
            "trailer",
            "X-Signature".parse::<hyper::header::HeaderValue>().unwrap(),
        );
        tx.response.as_mut().unwrap().headers = hm;

        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("x-checksum", "abc".parse().unwrap());
        trailers.insert("x-signature", "sig".parse().unwrap());
        tx.response.as_mut().unwrap().trailers = Some(trailers);

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_none());
    }

    // ---- Empty trailers HeaderMap — no violation ----

    #[test]
    fn empty_trailers_headermap_no_violation() {
        let rule = MessageTrailerFieldsValidity;
        let mut tx = make_test_transaction_with_response(200, &[("trailer", "x-checksum")]);
        tx.response.as_mut().unwrap().trailers = Some(hyper::HeaderMap::new());

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_none());
    }

    // ---- Whitespace-only Trailer header triggers undeclared via sentinel ----

    #[test]
    fn whitespace_only_trailer_header_with_actual_trailers_flags_undeclared() {
        // A whitespace-only Trailer header value is effectively invalid.
        // The sentinel ensures actual trailer fields are still flagged as undeclared.
        let rule = MessageTrailerFieldsValidity;
        let mut tx = make_test_transaction_with_response(200, &[("trailer", "  ")]);
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("x-checksum", "abc".parse().unwrap());
        tx.response.as_mut().unwrap().trailers = Some(trailers);

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("not declared"));
    }

    // ---- RFC edge cases ----

    #[test]
    fn common_valid_trailer_etag_passes() {
        // RFC 9110 §8.8.3 explicitly allows ETag as a trailer field.
        let rule = MessageTrailerFieldsValidity;
        let mut tx = make_test_transaction_with_response(200, &[("trailer", "ETag")]);
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("etag", "\"abc\"".parse().unwrap());
        tx.response.as_mut().unwrap().trailers = Some(trailers);

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_none());
    }

    #[test]
    fn common_valid_trailer_server_timing_passes() {
        let rule = MessageTrailerFieldsValidity;
        let mut tx = make_test_transaction_with_response(200, &[("trailer", "Server-Timing")]);
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("server-timing", "db;dur=53".parse().unwrap());
        tx.response.as_mut().unwrap().trailers = Some(trailers);

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_none());
    }

    #[test]
    fn mix_of_valid_and_prohibited_in_trailers_reports_prohibited() {
        let rule = MessageTrailerFieldsValidity;
        let mut tx = make_test_transaction_with_response(200, &[]);
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("x-checksum", "abc123".parse().unwrap());
        trailers.insert("transfer-encoding", "chunked".parse().unwrap());
        tx.response.as_mut().unwrap().trailers = Some(trailers);

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("prohibited"));
    }

    #[test]
    fn partial_declaration_match_flags_undeclared() {
        // Declare X-Checksum but send X-Checksum + X-Extra — X-Extra is undeclared.
        let rule = MessageTrailerFieldsValidity;
        let mut tx = make_test_transaction_with_response(200, &[("trailer", "X-Checksum")]);
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("x-checksum", "abc".parse().unwrap());
        trailers.insert("x-extra", "extra".parse().unwrap());
        tx.response.as_mut().unwrap().trailers = Some(trailers);

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("not declared"));
    }

    #[test]
    fn non_utf8_trailer_header_value_still_catches_prohibited() {
        // If the Trailer header has non-UTF-8, collect_declared_trailers skips it.
        // Prohibited fields in actual trailers should still be caught.
        let rule = MessageTrailerFieldsValidity;
        let mut tx = make_test_transaction_with_response(200, &[]);
        let mut hm = hyper::HeaderMap::new();
        hm.append(
            "trailer",
            hyper::header::HeaderValue::from_bytes(&[0xff]).unwrap(),
        );
        tx.response.as_mut().unwrap().headers = hm;

        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("content-type", "text/plain".parse().unwrap());
        tx.response.as_mut().unwrap().trailers = Some(trailers);

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("prohibited"));
    }

    #[test]
    fn both_request_and_response_prohibited_reports_request_first() {
        let rule = MessageTrailerFieldsValidity;
        let mut tx = make_test_transaction_with_response(200, &[]);

        let mut req_trailers = hyper::HeaderMap::new();
        req_trailers.insert("authorization", "Bearer x".parse().unwrap());
        tx.request.trailers = Some(req_trailers);

        let mut resp_trailers = hyper::HeaderMap::new();
        resp_trailers.insert("content-length", "99".parse().unwrap());
        tx.response.as_mut().unwrap().trailers = Some(resp_trailers);

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("authorization"));
    }

    #[test]
    fn response_only_prohibited_when_request_trailers_clean() {
        let rule = MessageTrailerFieldsValidity;
        let mut tx = make_test_transaction_with_response(200, &[]);

        let mut req_trailers = hyper::HeaderMap::new();
        req_trailers.insert("x-request-id", "123".parse().unwrap());
        tx.request.trailers = Some(req_trailers);

        let mut resp_trailers = hyper::HeaderMap::new();
        resp_trailers.insert("date", "Sat, 01 Jan 2026 00:00:00 GMT".parse().unwrap());
        tx.response.as_mut().unwrap().trailers = Some(resp_trailers);

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("date"));
    }

    #[test]
    fn multiple_valid_trailers_all_declared_passes() {
        let rule = MessageTrailerFieldsValidity;
        let mut tx = make_test_transaction_with_response(
            200,
            &[("trailer", "X-Checksum, ETag, Server-Timing")],
        );
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("x-checksum", "sha256=abc".parse().unwrap());
        trailers.insert("etag", "\"v1\"".parse().unwrap());
        trailers.insert("server-timing", "total;dur=100".parse().unwrap());
        tx.response.as_mut().unwrap().trailers = Some(trailers);

        let v = rule.check_transaction(&tx, &empty_history(), &cfg());
        assert!(v.is_none());
    }

    // ---- Scope and config ----

    #[test]
    fn id_and_scope_are_expected() {
        let rule = MessageTrailerFieldsValidity;
        assert_eq!(rule.id(), "message_trailer_fields_validity");
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_trailer_fields_validity");
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
