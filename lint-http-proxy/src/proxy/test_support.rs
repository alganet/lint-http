// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

#![cfg(test)]

//! Test support helpers shared across proxy submodule test blocks.

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client as LegacyClient;
use hyper_util::rt::TokioExecutor;
use std::sync::Arc as StdArc;
use uuid::Uuid;

use crate::ca::CertificateAuthority;
use crate::capture::CaptureWriter;

use super::Shared;

/// Construct a `Shared` wired to a fresh temp capture file. Returns the Shared,
/// the temp path (so tests can read/cleanup), and a clone of the writer.
pub(super) async fn make_shared_with_cfg(
    cfg: StdArc<crate::config::Config>,
    ca: Option<std::sync::Arc<CertificateAuthority>>,
) -> anyhow::Result<(StdArc<Shared>, String, CaptureWriter)> {
    let tmp =
        std::env::temp_dir().join(format!("lint_proxy_connect_test_{}.jsonl", Uuid::new_v4()));
    let p = tmp
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("temp path not utf8"))?
        .to_string();
    let cw = CaptureWriter::new(p.clone(), false).await?;

    let https = HttpsConnectorBuilder::new()
        .with_native_roots()?
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build();
    let client: LegacyClient<_, super::ClientBody> =
        LegacyClient::builder(TokioExecutor::new()).build(https);
    let state = StdArc::new(crate::state::StateStore::new(300, 10));
    let protocol_event_store = StdArc::new(crate::protocol_event_store::ProtocolEventStore::new(
        300, 100,
    ));
    let engine = StdArc::new(crate::engine::PreparedEngine::new(&cfg));
    let shared = StdArc::new(Shared {
        client,
        captures: cw.clone(),
        cfg,
        state,
        protocol_event_store,
        ca,
        quic_transport_params: None,
        engine,
        semaphore: StdArc::new(tokio::sync::Semaphore::new(1024)),
        shutdown: tokio_util::sync::CancellationToken::new(),
    });
    Ok((shared, p, cw))
}

pub(super) fn boxed_empty(
) -> http_body_util::combinators::BoxBody<bytes::Bytes, std::convert::Infallible> {
    Full::new(Bytes::new()).boxed()
}

pub(super) fn make_request_with_headers(
    method: &str,
    uri: impl AsRef<str>,
    headers: Option<&[(&str, &str)]>,
) -> anyhow::Result<
    hyper::Request<http_body_util::combinators::BoxBody<bytes::Bytes, std::convert::Infallible>>,
> {
    let mut builder = Request::builder().method(method).uri(uri.as_ref());
    if let Some(hs) = headers {
        for (k, v) in hs {
            builder = builder.header(*k, *v);
        }
    }
    Ok(builder.body(boxed_empty())?)
}

pub(super) async fn read_capture(path: &str) -> anyhow::Result<Vec<serde_json::Value>> {
    let s = tokio::fs::read_to_string(path).await?;
    let mut entries = Vec::new();
    for line in s.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        entries.push(serde_json::from_str(line)?);
    }
    Ok(entries)
}

/// Drive a streaming response body to completion (firing the capture-prefix tee
/// and its detached commit task), then poll the capture file until the
/// transaction lands. With streaming, the transaction is committed only after
/// the response body has been fully read, so a test must consume the body and
/// wait for the asynchronous commit before reading the capture.
pub(super) async fn drain_and_read_captures(
    resp: hyper::Response<super::ResponseBody>,
    cw: &CaptureWriter,
    path: &str,
) -> anyhow::Result<Vec<serde_json::Value>> {
    use http_body_util::BodyExt;
    let _ = resp.into_body().collect().await;
    read_captures_after_stream(cw, path).await
}

/// Poll the capture file until the streamed transaction's commit task has
/// landed (the commit is detached, firing after the body finishes streaming).
pub(super) async fn read_captures_after_stream(
    cw: &CaptureWriter,
    path: &str,
) -> anyhow::Result<Vec<serde_json::Value>> {
    for _ in 0..200 {
        cw.flush().await?;
        let entries = read_capture(path).await?;
        if !entries.is_empty() {
            return Ok(entries);
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    anyhow::bail!("capture not written within timeout")
}
