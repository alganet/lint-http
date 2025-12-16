// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Canonical HTTP transaction struct used across the pipeline.

use crate::lint::Violation;
use crate::state::ClientIdentifier;
use chrono::{DateTime, Utc};
use hyper::HeaderMap;
use serde::{Deserialize, Serialize};

use uuid::Uuid;

/// Subset of timing information for the transaction.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TimingInfo {
    pub duration_ms: u64,
}

/// Request portion of an HTTP transaction.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RequestInfo {
    pub method: String,
    pub uri: String,
    #[serde(
        serialize_with = "crate::serde_helpers::serialize_headers",
        deserialize_with = "crate::serde_helpers::deserialize_headers"
    )]
    pub headers: HeaderMap,
}

/// Response portion of an HTTP transaction (may be absent for failed upstreams).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ResponseInfo {
    pub status: u16,
    #[serde(
        serialize_with = "crate::serde_helpers::serialize_headers",
        deserialize_with = "crate::serde_helpers::deserialize_headers"
    )]
    pub headers: HeaderMap,
}

/// Canonical transaction that flows through parsing -> linting -> capture.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HttpTransaction {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,

    pub client: ClientIdentifier,

    pub request: RequestInfo,
    pub response: Option<ResponseInfo>,

    pub timing: TimingInfo,

    pub violations: Vec<Violation>,
}

impl HttpTransaction {
    /// Create a minimal transaction skeleton for tests or construction sites.
    pub fn new(client: ClientIdentifier, method: String, uri: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            client,
            request: RequestInfo {
                method,
                uri,
                headers: HeaderMap::new(),
            },
            response: None,
            timing: TimingInfo { duration_ms: 0 },
            violations: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::make_test_transaction;
    use hyper::header::HeaderValue;

    #[test]
    fn serde_roundtrip_preserves_utf8_headers() -> anyhow::Result<()> {
        let mut tx = make_test_transaction();

        let mut req_headers = HeaderMap::new();
        req_headers.insert("x-test", "1".parse()?);
        req_headers.insert("content-type", "text/plain; charset=utf-8".parse()?);
        req_headers.insert("x-quote", "\"a\"".parse()?);
        tx.request.headers = req_headers;

        let mut resp_headers = HeaderMap::new();
        resp_headers.insert("etag", "\"abc\"".parse()?);
        tx.response = Some(ResponseInfo {
            status: 200,
            headers: resp_headers,
        });

        let s = serde_json::to_string(&tx)?;
        let tx2: HttpTransaction = serde_json::from_str(&s)?;

        assert_eq!(tx.id, tx2.id);
        assert_eq!(tx.request.method, tx2.request.method);
        assert_eq!(tx.request.uri, tx2.request.uri);
        assert_eq!(
            tx2.request
                .headers
                .get("x-test")
                .and_then(|v| v.to_str().ok()),
            Some("1")
        );
        assert_eq!(
            tx2.request
                .headers
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("text/plain; charset=utf-8")
        );

        let resp = tx2.response.expect("response present after roundtrip");
        assert_eq!(resp.status, 200);
        assert_eq!(
            resp.headers.get("etag").and_then(|v| v.to_str().ok()),
            Some("\"abc\"")
        );

        Ok(())
    }

    #[test]
    fn serde_roundtrip_drops_non_utf8_header_values() -> anyhow::Result<()> {
        let mut tx = make_test_transaction();

        let mut req_headers = HeaderMap::new();
        req_headers.insert("x-good", "ok".parse()?);
        // Create a non-UTF8 header value
        let bad = HeaderValue::from_bytes(&[0xff]).expect("should construct non-utf8 header");
        req_headers.insert("x-bad", bad);
        tx.request.headers = req_headers;

        let s = serde_json::to_string(&tx)?;
        let tx2: HttpTransaction = serde_json::from_str(&s)?;

        // Good header should be present
        assert_eq!(
            tx2.request
                .headers
                .get("x-good")
                .and_then(|v| v.to_str().ok()),
            Some("ok")
        );
        // Non-UTF8 header is dropped during serialization
        assert!(tx2.request.headers.get("x-bad").is_none());

        Ok(())
    }
}
