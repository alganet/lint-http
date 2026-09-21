// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! The `/_lint_http/stream` live capture endpoint: a Server-Sent Events feed
//! that pushes each capture record as it commits, so a dev loop can watch proxy
//! traffic in real time instead of tailing the JSONL file.

use bytes::Bytes;
use http_body_util::{BodyExt, StreamBody};
use hyper::body::Frame;
use hyper::Response;
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::warn;

use super::{boxed_full, BoxError, ResponseBody, Shared};
use crate::capture::serialize_record;

/// Build the response for `GET /_lint_http/stream`. Returns 404 when the live
/// stream is disabled (mirroring the cert endpoint's gated 404); otherwise a
/// `text/event-stream` body that emits one SSE event per captured record.
pub(super) fn stream_response(shared: &Arc<Shared>) -> Response<ResponseBody> {
    if !shared.cfg.general.live_stream_enabled {
        return super::http::error_resp(
            404,
            "live capture stream is disabled (set general.live_stream_enabled = true)",
        );
    }

    let body = sse_body(
        shared.captures.subscribe(),
        shared.cfg.general.captures_include_body,
    );

    Response::builder()
        .status(200)
        .header("Content-Type", "text/event-stream")
        .header("Cache-Control", "no-cache")
        .header("Connection", "keep-alive")
        .body(body)
        .unwrap_or_else(|_| Response::new(boxed_full(Bytes::new())))
}

/// Turn a broadcast receiver into an SSE [`ResponseBody`]. Each record becomes a
/// `data: <json>\n\n` event; a lagging subscriber gets a `: lagged N\n\n`
/// comment (keeps the stream alive and signals the gap) and the stream ends when
/// the writer closes or the client disconnects (dropping the receiver).
fn sse_body(
    rx: broadcast::Receiver<Arc<crate::capture::CaptureEnvelope>>,
    include_body: bool,
) -> ResponseBody {
    let stream = futures_util::stream::unfold(rx, move |mut rx| async move {
        loop {
            match rx.recv().await {
                Ok(env) => match serialize_record(&env, include_body) {
                    Ok(json) => {
                        let frame = Frame::data(Bytes::from(format!("data: {json}\n\n")));
                        return Some((Ok::<_, BoxError>(frame), rx));
                    }
                    // A single unserializable record must not kill the feed.
                    Err(e) => {
                        warn!(error = %e, "failed to serialize capture record for SSE stream");
                        continue;
                    }
                },
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    let frame = Frame::data(Bytes::from(format!(": lagged {n}\n\n")));
                    return Some((Ok(frame), rx));
                }
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    });

    StreamBody::new(stream).boxed_unsync()
}
