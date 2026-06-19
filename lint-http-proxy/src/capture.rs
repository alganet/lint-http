// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Request/response capture writing to JSONL format.

use base64::Engine;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs::OpenOptions;
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::sync::{broadcast, mpsc, oneshot, Mutex};
use tokio::task::JoinHandle;
use tracing::warn;

/// Version of the on-disk JSONL capture schema. Bump on any incompatible
/// change to a record's shape so readers can migrate or reject older files.
pub const CAPTURE_SCHEMA_VERSION: u32 = 1;

/// A single top-level capture record, tagged by `type` in the JSONL output.
///
/// The `HttpTransaction` payload is boxed (it is much larger than a session
/// record); `Box<T>` is transparent to serde, so the JSON shape is unchanged.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CaptureRecord {
    HttpTransaction(Box<crate::http_transaction::HttpTransaction>),
    WebsocketSession(Box<crate::websocket_session::WebSocketSession>),
}

/// Versioned envelope wrapping each capture record. Serializes flat: the
/// `schema_version` and the record's `type` discriminator sit alongside the
/// record's own fields, keeping every entry a single line-readable JSON object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureEnvelope {
    #[serde(default)]
    pub schema_version: u32,
    #[serde(flatten)]
    pub record: CaptureRecord,
}

impl CaptureEnvelope {
    /// Wrap a record with the current schema version.
    pub fn new(record: CaptureRecord) -> Self {
        Self {
            schema_version: CAPTURE_SCHEMA_VERSION,
            record,
        }
    }
}

/// Depth of the bounded channel feeding the background writer task. When the
/// channel is full, `send().await` applies backpressure to the caller rather
/// than dropping a record — captures stay a complete record of proxy traffic.
const CAPTURE_CHANNEL_CAPACITY: usize = 1024;

/// `BufWriter` capacity. Within a drained batch, records accumulate in this
/// buffer and spill to the OS as it fills, so memory stays bounded even under a
/// burst larger than the buffer.
const WRITE_BUFFER_BYTES: usize = 64 * 1024;

/// Depth of the per-subscriber broadcast channel feeding the live capture
/// stream. Unlike the durable file channel, this one is lossy on purpose: a
/// subscriber that falls more than this many records behind drops the oldest
/// (surfaced as `RecvError::Lagged`), so a slow SSE client can never slow the
/// durable file write.
const LIVE_STREAM_CHANNEL_CAPACITY: usize = 256;

/// A message to the background writer task.
enum CaptureMsg {
    /// Serialize and append a record. Carried as an `Arc` so the live-stream
    /// tee in the writer task is a cheap refcount bump rather than a deep clone
    /// of the transaction.
    Record(Arc<CaptureEnvelope>),
    /// Flush + fsync everything written so far, then acknowledge.
    Flush(oneshot::Sender<()>),
    /// Drain the queue, flush + fsync, acknowledge, then stop the task.
    Shutdown(oneshot::Sender<()>),
}

/// Appends capture records to a JSONL file from a single background task.
///
/// Cloning is cheap: every clone shares the one channel and writer task, so the
/// global append order is preserved by the single consumer — without a
/// per-write mutex or an fsync on the request hot path. [`Self::flush`] forces
/// a durable flush (used by tests and, later, the live-stream seam);
/// [`Self::shutdown`] drains and joins the task (used by graceful shutdown).
#[derive(Clone)]
pub struct CaptureWriter {
    tx: mpsc::Sender<CaptureMsg>,
    /// Live fan-out of each record as it is written. Subscribers (the
    /// `/_lint_http/stream` SSE endpoint) get an `Arc` so one clone serves all
    /// of them; the durable file write is never gated on this channel.
    events: broadcast::Sender<Arc<CaptureEnvelope>>,
    /// Shared so any clone can join the task on shutdown: the first caller
    /// takes the handle, later callers find `None` and no-op.
    join: Arc<Mutex<Option<JoinHandle<()>>>>,
}

impl CaptureWriter {
    pub async fn new<P: Into<PathBuf>>(path: P, include_body: bool) -> anyhow::Result<Self> {
        // Open before spawning so path errors (e.g. a directory) surface here
        // to the caller rather than only inside the background task.
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path.into())
            .await?;
        let (tx, rx) = mpsc::channel(CAPTURE_CHANNEL_CAPACITY);
        let (events, _) = broadcast::channel(LIVE_STREAM_CHANNEL_CAPACITY);
        let join = tokio::spawn(writer_task(file, rx, events.clone(), include_body));
        Ok(Self {
            tx,
            events,
            join: Arc::new(Mutex::new(Some(join))),
        })
    }

    /// Subscribe to the live stream of capture records. Each record is delivered
    /// as it is written to the file. The returned receiver is lossy under lag:
    /// a slow consumer drops the oldest records rather than slowing the writer.
    pub fn subscribe(&self) -> broadcast::Receiver<Arc<CaptureEnvelope>> {
        self.events.subscribe()
    }

    /// Queue a record for the writer task. Returns `Err` only if the task is
    /// gone (e.g. after [`Self::shutdown`]); serialization and IO errors are
    /// logged in the task, not returned here.
    async fn queue(&self, record: CaptureRecord) -> anyhow::Result<()> {
        let envelope = Arc::new(CaptureEnvelope::new(record));
        self.tx
            .send(CaptureMsg::Record(envelope))
            .await
            .map_err(|_| anyhow::anyhow!("capture writer task is gone"))
    }

    /// Queue a transaction for the writer task.
    pub async fn write_transaction(
        &self,
        tx: crate::http_transaction::HttpTransaction,
    ) -> anyhow::Result<()> {
        self.queue(CaptureRecord::HttpTransaction(Box::new(tx)))
            .await
    }

    /// Queue a WebSocket session record for the writer task.
    pub async fn write_websocket_session(
        &self,
        session: crate::websocket_session::WebSocketSession,
    ) -> anyhow::Result<()> {
        self.queue(CaptureRecord::WebsocketSession(Box::new(session)))
            .await
    }

    /// Block until every record queued so far is flushed and fsynced to disk.
    /// The deterministic sync point for reading the capture file back.
    pub async fn flush(&self) -> anyhow::Result<()> {
        let (ack, done) = oneshot::channel();
        self.tx
            .send(CaptureMsg::Flush(ack))
            .await
            .map_err(|_| anyhow::anyhow!("capture writer task is gone"))?;
        done.await
            .map_err(|_| anyhow::anyhow!("capture writer task dropped flush ack"))
    }

    /// Drain queued records, flush + fsync, and join the background task.
    /// Idempotent across clones: only the first caller joins the task.
    pub async fn shutdown(&self) -> anyhow::Result<()> {
        let (ack, done) = oneshot::channel();
        if self.tx.send(CaptureMsg::Shutdown(ack)).await.is_ok() {
            let _ = done.await;
        }
        if let Some(handle) = self.join.lock().await.take() {
            let _ = handle.await;
        }
        Ok(())
    }
}

/// The single consumer. Wakes on a message, then greedily drains every record
/// already queued before a single flush + fsync — so a burst coalesces into one
/// durability barrier while a lone record is made durable promptly. The request
/// path has already returned by the time this runs (it awaited only the channel
/// send), so the fsync never blocks a handler. Owns the file for its lifetime.
async fn writer_task(
    file: tokio::fs::File,
    mut rx: mpsc::Receiver<CaptureMsg>,
    events: broadcast::Sender<Arc<CaptureEnvelope>>,
    include_body: bool,
) {
    let mut writer = BufWriter::with_capacity(WRITE_BUFFER_BYTES, file);

    while let Some(first) = rx.recv().await {
        let mut acks: Vec<oneshot::Sender<()>> = Vec::new();
        let mut shutting_down = false;

        // Process the waking message, then drain whatever else is already
        // queued so the whole batch shares one flush below.
        let mut next = Some(first);
        while let Some(msg) = next {
            match msg {
                CaptureMsg::Record(envelope) => {
                    // Tee to live subscribers before the durable write. The clone
                    // is a cheap `Arc` refcount bump; skip it (and the ring-buffer
                    // push) when nobody is listening. `send` never blocks and a
                    // lagging subscriber drops records rather than slowing us.
                    if events.receiver_count() > 0 {
                        let _ = events.send(envelope.clone());
                    }
                    write_record(&mut writer, &envelope, include_body).await;
                }
                CaptureMsg::Flush(ack) => acks.push(ack),
                CaptureMsg::Shutdown(ack) => {
                    acks.push(ack);
                    shutting_down = true;
                }
            }
            // `Empty` ends this batch; `Disconnected` (all senders dropped)
            // also stops here and the outer loop then exits.
            next = rx.try_recv().ok();
        }

        flush_and_sync(&mut writer).await;
        for ack in acks {
            let _ = ack.send(());
        }
        if shutting_down {
            return;
        }
    }

    // All senders dropped — final flush in case the last batch raced the close.
    flush_and_sync(&mut writer).await;
}

/// Serialize `envelope` and append it as one line to `writer`'s buffer.
/// Serialization and IO errors are logged, not fatal — one bad record must not
/// take down the writer task.
async fn write_record(
    writer: &mut BufWriter<tokio::fs::File>,
    envelope: &CaptureEnvelope,
    include_body: bool,
) {
    let line = match serialize_record(envelope, include_body) {
        Ok(line) => line,
        Err(e) => {
            warn!(error = %e, "failed to serialize capture record");
            return;
        }
    };
    if let Err(e) = writer.write_all(line.as_bytes()).await {
        warn!(error = %e, "failed to write capture record");
        return;
    }
    if let Err(e) = writer.write_all(b"\n").await {
        warn!(error = %e, "failed to write capture newline");
    }
}

/// Flush the `BufWriter` to the OS and fsync the file. Errors are logged; a
/// failed flush skips the fsync.
async fn flush_and_sync(writer: &mut BufWriter<tokio::fs::File>) {
    if let Err(e) = writer.flush().await {
        warn!(error = %e, "failed to flush capture buffer");
        return;
    }
    if let Err(e) = writer.get_ref().sync_data().await {
        warn!(error = %e, "failed to fsync capture file");
    }
}

/// Serialize an envelope to a single JSON object string. For transaction
/// records, request/response bodies are base64-injected when `include_body` is
/// set and stripped otherwise (defensive — body fields are skipped by serde by
/// default). WebSocket sessions carry no separately-skipped bodies and
/// serialize directly. Shared by the file writer (one JSONL line) and the live
/// SSE stream, so the on-disk and on-wire JSON shapes are identical.
pub(crate) fn serialize_record(
    envelope: &CaptureEnvelope,
    include_body: bool,
) -> serde_json::Result<String> {
    let tx = match &envelope.record {
        CaptureRecord::HttpTransaction(tx) => tx.as_ref(),
        CaptureRecord::WebsocketSession(_) => return serde_json::to_string(envelope),
    };

    // Internal tagging + flatten keep `request`/`response` at the top level, so
    // the body-injection below targets them directly.
    let mut v = serde_json::to_value(envelope)?;

    if include_body {
        if let Some(obj) = v.as_object_mut() {
            // request body: if present as skipped field it won't be in `v` by default
            if let Some(req_obj) = obj.get_mut("request").and_then(|r| r.as_object_mut()) {
                // If original transaction had a body (it is skipped by default),
                // fetch it directly from `tx` and insert as base64.
                if let Some(b) = &tx.request_body {
                    req_obj.insert(
                        "body".to_string(),
                        serde_json::Value::String(
                            base64::engine::general_purpose::STANDARD.encode(b),
                        ),
                    );
                }
            }
            if let Some(resp_val) = obj.get_mut("response") {
                if resp_val.is_object() {
                    if let Some(resp_obj) = resp_val.as_object_mut() {
                        if let Some(_r) = &tx.response {
                            if let Some(b) = &tx.response_body {
                                resp_obj.insert(
                                    "body".to_string(),
                                    serde_json::Value::String(
                                        base64::engine::general_purpose::STANDARD.encode(b),
                                    ),
                                );
                            }
                        }
                    }
                }
            }
        }
    } else {
        // Ensure body fields are not present in serialized output (defensive)
        if let Some(obj) = v.as_object_mut() {
            if let Some(req_obj) = obj.get_mut("request").and_then(|r| r.as_object_mut()) {
                req_obj.remove("body");
            }
            if let Some(resp_val) = obj.get_mut("response") {
                if resp_val.is_object() {
                    if let Some(resp_obj) = resp_val.as_object_mut() {
                        resp_obj.remove("body");
                    }
                }
            }
        }
    }

    serde_json::to_string(&v)
}

/// Load capture records from a JSONL file. Skips malformed lines with warnings.
pub async fn load_captures<P: AsRef<std::path::Path>>(
    path: P,
) -> anyhow::Result<Vec<crate::http_transaction::HttpTransaction>> {
    use tokio::io::AsyncBufReadExt;

    let path_ref = path.as_ref();

    if !tokio::fs::try_exists(path_ref).await.unwrap_or(false) {
        return Ok(Vec::new());
    }

    let file = tokio::fs::File::open(path_ref).await?;
    let reader = tokio::io::BufReader::new(file);
    let mut lines = reader.lines();
    let mut records = Vec::new();
    let mut line_num = 0;

    while let Some(line) = lines.next_line().await? {
        line_num += 1;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            tracing::debug!(line = line_num, "skipping empty/whitespace capture line");
            continue;
        }

        // Parse the tagged, versioned envelope. Non-transaction records
        // (e.g. websocket_session) and unknown types are skipped.
        match serde_json::from_str::<CaptureEnvelope>(trimmed) {
            Ok(envelope) => match envelope.record {
                CaptureRecord::HttpTransaction(tx) => records.push(*tx),
                CaptureRecord::WebsocketSession(_) => {
                    tracing::debug!(line = line_num, "skipping non-transaction capture record");
                }
            },
            Err(e) => {
                tracing::warn!(line = line_num, error = %e, "failed to parse capture record, skipping");
            }
        }
    }

    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::HeaderMap;
    use serde_json::Value;
    use tokio::fs;
    use uuid::Uuid;

    /// Headers serialize as an array of `[name, value]` pairs; check membership.
    fn header_present(headers: &Value, name: &str) -> bool {
        headers
            .as_array()
            .map(|pairs| pairs.iter().any(|p| p[0] == name))
            .unwrap_or(false)
    }

    /// Serialize a transaction as an enveloped JSONL line (as the writer does).
    fn tx_line(tx: &crate::http_transaction::HttpTransaction) -> String {
        serde_json::to_string(&CaptureEnvelope::new(CaptureRecord::HttpTransaction(
            Box::new(tx.clone()),
        )))
        .unwrap()
    }

    /// Serialize a WebSocket session as an enveloped JSONL line.
    fn session_line(session: &crate::websocket_session::WebSocketSession) -> String {
        serde_json::to_string(&CaptureEnvelope::new(CaptureRecord::WebsocketSession(
            Box::new(session.clone()),
        )))
        .unwrap()
    }

    #[tokio::test]
    async fn write_transaction_writes_jsonl() -> anyhow::Result<()> {
        let tmp = std::env::temp_dir().join(format!("lint_capture_test_{}.jsonl", Uuid::new_v4()));
        let p = tmp
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("temp path not utf8"))?
            .to_string();

        let cw = CaptureWriter::new(p.clone(), false).await?;

        let mut req_headers = HeaderMap::new();
        req_headers.insert("x-test", "1".parse()?);

        let violations = vec![crate::lint::Violation {
            rule: "r1".into(),
            severity: crate::lint::Severity::Warn,
            message: "m".into(),
        }];

        // Build a minimal transaction using helper
        use crate::http_transaction::TimingInfo;
        use crate::test_helpers::make_test_transaction;
        let mut tx = make_test_transaction();
        tx.request.headers = req_headers;
        tx.timing = TimingInfo { duration_ms: 10 };
        tx.violations = violations;

        cw.write_transaction(tx).await?;
        cw.flush().await?;

        let s = fs::read_to_string(&tmp).await?;
        let v: Value = serde_json::from_str(s.trim())?;
        assert_eq!(v["request"]["method"].as_str(), Some("GET"));
        assert_eq!(v["request"]["uri"].as_str(), Some("http://example/"));
        assert!(header_present(&v["request"]["headers"], "x-test"));
        // Ensure severity serialized as lowercase string
        assert_eq!(v["violations"][0]["severity"].as_str(), Some("warn"));

        fs::remove_file(&tmp).await?;
        Ok(())
    }

    #[tokio::test]
    async fn write_transaction_includes_bodies_when_enabled() -> anyhow::Result<()> {
        let tmp =
            std::env::temp_dir().join(format!("lint_capture_bodies_test_{}.jsonl", Uuid::new_v4()));
        let p = tmp
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("temp path not utf8"))?
            .to_string();

        // Create writer that includes bodies
        let cw = CaptureWriter::new(p.clone(), true).await?;

        use crate::test_helpers::make_test_transaction_with_response;
        let mut tx = make_test_transaction_with_response(
            400,
            &[("content-type", "application/problem+json")],
        );
        tx.request_body = Some(bytes::Bytes::from_static(b"req-body"));
        tx.request.body_length = Some(8);
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 400,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[(
                "content-type",
                "application/problem+json",
            )]),
            body_length: Some(13),
            trailers: None,
        });
        tx.response_body = Some(bytes::Bytes::from_static(b"{\"type\":\"x\"}"));

        cw.write_transaction(tx).await?;
        cw.flush().await?;

        let s = fs::read_to_string(&tmp).await?;
        let v: Value = serde_json::from_str(s.trim())?;
        // request body should be base64 string
        assert!(v["request"]["body"].is_string());
        let req_b64 = v["request"]["body"].as_str().unwrap();
        assert_eq!(
            base64::engine::general_purpose::STANDARD.decode(req_b64)?,
            b"req-body"
        );
        // response body should be base64 string
        assert!(v["response"]["body"].is_string());
        let resp_b64 = v["response"]["body"].as_str().unwrap();
        assert_eq!(
            base64::engine::general_purpose::STANDARD.decode(resp_b64)?,
            b"{\"type\":\"x\"}"
        );

        fs::remove_file(&tmp).await?;
        Ok(())
    }

    #[tokio::test]
    async fn load_captures_reads_jsonl() -> anyhow::Result<()> {
        let tmp = std::env::temp_dir().join(format!("lint_load_test_{}.jsonl", Uuid::new_v4()));
        let p = tmp
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("temp path not utf8"))?
            .to_string();

        // Write some sample transaction records
        let cw = CaptureWriter::new(p.clone(), false).await?;

        let mut req_headers = HeaderMap::new();
        req_headers.insert("user-agent", "test-client".parse()?);

        let mut resp_headers = HeaderMap::new();
        resp_headers.insert("etag", "\"abc123\"".parse()?);

        use crate::test_helpers::make_test_transaction_with_response;
        let mut tx = make_test_transaction_with_response(200, &[("etag", "\"abc123\"")]);
        tx.request.headers = req_headers;
        // Ensure URI matches test expectation
        tx.request.uri = "http://example/test".to_string();
        tx.timing.duration_ms = 100;

        cw.write_transaction(tx).await?;
        cw.flush().await?;

        // Load the captures
        let records = load_captures(&tmp).await?;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].request.method, "GET");
        assert_eq!(records[0].request.uri, "http://example/test");
        assert_eq!(records[0].timing.duration_ms, 100);
        assert!(records[0].response.is_some());

        fs::remove_file(&tmp).await?;
        Ok(())
    }

    #[tokio::test]
    async fn load_captures_skips_malformed_lines() -> anyhow::Result<()> {
        let tmp =
            std::env::temp_dir().join(format!("lint_malformed_test_{}.jsonl", Uuid::new_v4()));

        // Write a mix of valid and invalid transaction JSON
        use crate::test_helpers::{make_test_transaction, make_test_transaction_with_response};
        let mut tx1 = make_test_transaction();
        let mut tx2 = make_test_transaction_with_response(201, [("user", "u2")].as_ref());
        tx1.request.uri = "http://example/".to_string();
        tx2.request.method = "POST".to_string();
        tx2.request.uri = "http://example/post".to_string();

        let content = format!("{}\ninvalid json line\n{}\n", tx_line(&tx1), tx_line(&tx2));
        fs::write(&tmp, content).await?;

        // Should load only the valid records
        let records = load_captures(&tmp).await?;
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].request.method, "GET");
        assert_eq!(records[1].request.method, "POST");

        fs::remove_file(&tmp).await?;
        Ok(())
    }

    #[tokio::test]
    async fn load_captures_skips_empty_lines() -> anyhow::Result<()> {
        let tmp =
            std::env::temp_dir().join(format!("lint_empty_lines_test_{}.jsonl", Uuid::new_v4()));

        // Write a valid record, then an empty line, then another valid record
        use crate::test_helpers::{make_test_transaction, make_test_transaction_with_response};
        let tx1 = make_test_transaction();
        let tx2 = make_test_transaction_with_response(202, &[("x", "y")]);
        let content = format!("{}\n\n{}\n", tx_line(&tx1), tx_line(&tx2));
        fs::write(&tmp, content).await?;

        let records = load_captures(&tmp).await?;
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].request.method, "GET");
        assert_eq!(records[1].response.as_ref().unwrap().status, 202);

        fs::remove_file(&tmp).await?;
        Ok(())
    }

    #[tokio::test]
    async fn load_captures_skips_whitespace_lines() -> anyhow::Result<()> {
        let tmp = std::env::temp_dir().join(format!("lint_ws_test_{}.jsonl", Uuid::new_v4()));

        use crate::test_helpers::{make_test_transaction, make_test_transaction_with_response};
        let tx1 = make_test_transaction();
        let tx2 = make_test_transaction_with_response(202, &[("x", "y")]);
        let content = format!("{}\n   \n{}\n", tx_line(&tx1), tx_line(&tx2));
        fs::write(&tmp, content).await?;

        let records = load_captures(&tmp).await?;
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].request.method, "GET");
        assert_eq!(records[1].response.as_ref().unwrap().status, 202);

        fs::remove_file(&tmp).await?;
        Ok(())
    }

    #[tokio::test]
    async fn load_captures_blank_line_returns_empty() -> anyhow::Result<()> {
        let tmp =
            std::env::temp_dir().join(format!("lint_blank_line_test_{}.jsonl", Uuid::new_v4()));
        // Single blank line should be ignored
        fs::write(&tmp, "\n").await?;

        let records = load_captures(&tmp).await?;
        assert_eq!(records.len(), 0);

        fs::remove_file(&tmp).await?;
        Ok(())
    }

    #[tokio::test]
    async fn load_captures_empty_file_returns_empty() -> anyhow::Result<()> {
        let tmp = std::env::temp_dir().join(format!("lint_empty_test_{}.jsonl", Uuid::new_v4()));
        fs::write(&tmp, "").await?;

        let records = load_captures(&tmp).await?;
        assert_eq!(records.len(), 0);

        fs::remove_file(&tmp).await?;
        Ok(())
    }

    #[tokio::test]
    async fn load_captures_nonexistent_file_returns_empty() -> anyhow::Result<()> {
        let tmp = std::env::temp_dir().join(format!("lint_nonexistent_{}.jsonl", Uuid::new_v4()));

        // Should not error, just return empty vector
        let records = load_captures(&tmp).await?;
        assert_eq!(records.len(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn write_websocket_session_writes_jsonl() -> anyhow::Result<()> {
        let tmp =
            std::env::temp_dir().join(format!("lint_ws_session_test_{}.jsonl", Uuid::new_v4()));
        let p = tmp
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("temp path not utf8"))?
            .to_string();

        let cw = CaptureWriter::new(p.clone(), false).await?;

        use crate::websocket_session::{MessageDirection, WebSocketMessageInfo, WebSocketSession};
        let tx_id = Uuid::new_v4();
        let mut session = WebSocketSession::new(tx_id);
        session.messages.push(WebSocketMessageInfo {
            direction: MessageDirection::Client,
            opcode: 1,
            payload_length: 5,
            fin: true,
            rsv: 0,
        });
        session.duration_ms = 100;
        session.close_code = Some(1000);

        cw.write_websocket_session(session).await?;
        cw.flush().await?;

        let s = fs::read_to_string(&tmp).await?;
        let v: Value = serde_json::from_str(s.trim())?;
        assert_eq!(v["type"].as_str(), Some("websocket_session"));
        assert_eq!(
            v["transaction_id"].as_str(),
            Some(tx_id.to_string().as_str())
        );
        assert_eq!(v["messages"][0]["opcode"].as_u64(), Some(1));
        assert_eq!(v["close_code"].as_u64(), Some(1000));

        fs::remove_file(&tmp).await?;
        Ok(())
    }

    #[tokio::test]
    async fn load_captures_skips_websocket_session_records() -> anyhow::Result<()> {
        let tmp =
            std::env::temp_dir().join(format!("lint_mixed_records_test_{}.jsonl", Uuid::new_v4()));

        use crate::test_helpers::make_test_transaction_with_response;
        use crate::websocket_session::{MessageDirection, WebSocketMessageInfo, WebSocketSession};

        let tx = make_test_transaction_with_response(200, &[]);
        let mut session = WebSocketSession::new(Uuid::new_v4());
        session.messages.push(WebSocketMessageInfo {
            direction: MessageDirection::Client,
            opcode: 1,
            payload_length: 5,
            fin: true,
            rsv: 0,
        });

        // Write a transaction, then a websocket_session, then another transaction
        let content = format!(
            "{}\n{}\n{}\n",
            tx_line(&tx),
            session_line(&session),
            tx_line(&tx),
        );
        fs::write(&tmp, content).await?;

        let records = load_captures(&tmp).await?;
        // Should load only the 2 http_transaction records, skipping the websocket_session
        assert_eq!(records.len(), 2);

        fs::remove_file(&tmp).await?;
        Ok(())
    }

    #[test]
    fn capture_envelope_roundtrips_both_variants() {
        use crate::test_helpers::make_test_transaction;
        use crate::websocket_session::WebSocketSession;

        // Transaction variant: tagged and versioned, fields flattened.
        let tx = make_test_transaction();
        let line = tx_line(&tx);
        let v: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["type"].as_str(), Some("http_transaction"));
        assert_eq!(
            v["schema_version"].as_u64(),
            Some(CAPTURE_SCHEMA_VERSION as u64)
        );
        assert!(v.get("request").is_some(), "fields flatten to top level");
        match serde_json::from_str::<CaptureEnvelope>(&line)
            .unwrap()
            .record
        {
            CaptureRecord::HttpTransaction(parsed) => assert_eq!(parsed.id, tx.id),
            other => panic!("expected http_transaction, got {other:?}"),
        }

        // WebSocket session variant.
        let session = WebSocketSession::new(Uuid::new_v4());
        let line = session_line(&session);
        let v: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["type"].as_str(), Some("websocket_session"));
        assert_eq!(
            v["schema_version"].as_u64(),
            Some(CAPTURE_SCHEMA_VERSION as u64)
        );
        match serde_json::from_str::<CaptureEnvelope>(&line)
            .unwrap()
            .record
        {
            CaptureRecord::WebsocketSession(parsed) => {
                assert_eq!(parsed.id, session.id);
            }
            other => panic!("expected websocket_session, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn subscribe_receives_written_record() -> anyhow::Result<()> {
        let tmp = std::env::temp_dir().join(format!("lint_stream_sub_{}.jsonl", Uuid::new_v4()));
        let cw = CaptureWriter::new(tmp.clone(), false).await?;

        let mut rx = cw.subscribe();

        use crate::test_helpers::make_test_transaction;
        let tx = make_test_transaction();
        let id = tx.id;
        cw.write_transaction(tx).await?;
        cw.flush().await?;

        let env = rx.recv().await?;
        match &env.record {
            CaptureRecord::HttpTransaction(t) => assert_eq!(t.id, id),
            other => panic!("expected http_transaction, got {other:?}"),
        }

        fs::remove_file(&tmp).await?;
        Ok(())
    }

    #[tokio::test]
    async fn write_without_subscriber_still_writes_file() -> anyhow::Result<()> {
        let tmp = std::env::temp_dir().join(format!("lint_stream_nosub_{}.jsonl", Uuid::new_v4()));
        let cw = CaptureWriter::new(tmp.clone(), false).await?;

        // No `subscribe()` call: the broadcast tee must be skipped and the
        // durable write must proceed unaffected.
        use crate::test_helpers::make_test_transaction;
        cw.write_transaction(make_test_transaction()).await?;
        cw.flush().await?;

        let s = fs::read_to_string(&tmp).await?;
        let v: Value = serde_json::from_str(s.trim())?;
        assert_eq!(v["request"]["method"].as_str(), Some("GET"));

        fs::remove_file(&tmp).await?;
        Ok(())
    }

    #[tokio::test]
    async fn capture_new_with_directory_errors() -> anyhow::Result<()> {
        let dir = std::env::temp_dir().join(format!("lint_capture_dir_{}", Uuid::new_v4()));
        tokio::fs::create_dir(&dir).await?;
        let res = CaptureWriter::new(dir.clone(), false).await;
        assert!(res.is_err());
        tokio::fs::remove_dir(&dir).await?;
        Ok(())
    }
}
