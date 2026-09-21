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
    /// One protocol event and what the rules said about it.
    ///
    /// Written whether or not anything was wrong, which is what separates this
    /// from the two above: they exist because traffic happened, and this exists
    /// so that a protocol rule running quietly leaves a trace at all. See
    /// [`ProtocolEventRecord`](crate::protocol_event::ProtocolEventRecord).
    ProtocolEvent(Box<crate::protocol_event::ProtocolEventRecord>),
}

/// Versioned envelope wrapping each capture record. Serializes flat: the
/// `schema_version` and the record's `type` discriminator sit alongside the
/// record's own fields, keeping every entry a single line-readable JSON object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureEnvelope {
    #[serde(default)]
    pub schema_version: u32,
    /// Which writing session produced this record.
    ///
    /// A capture file is opened for append, so one path can hold the output of
    /// many sessions — and a session that shares its path with a *concurrent*
    /// one cannot tell its own records apart by position: both start before
    /// either writes, so an offset or a count taken at the start says the same
    /// thing to both, and each ends up reporting the other's traffic. A gate
    /// then fails on findings from a run that already passed its own.
    ///
    /// Absent for a record written by a `proxy-start` session, which has no
    /// report to scope, and for every record written before this field existed
    /// — serde-defaulted both ways, so an older capture reads back unchanged
    /// and a record with no session serializes exactly as it always has.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<uuid::Uuid>,
    #[serde(flatten)]
    pub record: CaptureRecord,
}

impl CaptureEnvelope {
    /// Wrap a record with the current schema version, unattributed.
    pub fn new(record: CaptureRecord) -> Self {
        Self {
            schema_version: CAPTURE_SCHEMA_VERSION,
            session: None,
            record,
        }
    }

    /// Wrap a record and say which session wrote it.
    pub fn for_session(record: CaptureRecord, session: Option<uuid::Uuid>) -> Self {
        Self {
            schema_version: CAPTURE_SCHEMA_VERSION,
            session,
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
    /// Stamped onto every record this writer queues; see
    /// [`CaptureEnvelope::session`].
    session: Option<uuid::Uuid>,
    /// Shared so any clone can join the task on shutdown: the first caller
    /// takes the handle, later callers find `None` and no-op.
    join: Arc<Mutex<Option<JoinHandle<()>>>>,
}

impl CaptureWriter {
    pub async fn new<P: Into<PathBuf>>(path: P, include_body: bool) -> anyhow::Result<Self> {
        Self::for_session(path, include_body, None).await
    }

    /// A writer whose records carry a session id, so a reader sharing the file
    /// with another writer can pick out the ones this session produced.
    pub async fn for_session<P: Into<PathBuf>>(
        path: P,
        include_body: bool,
        session: Option<uuid::Uuid>,
    ) -> anyhow::Result<Self> {
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
            session,
            join: Arc::new(Mutex::new(Some(join))),
        })
    }

    /// Subscribe to the live stream of capture records. Each record is delivered
    /// as it is written to the file. The returned receiver is lossy under lag:
    /// a slow consumer drops the oldest records rather than slowing the writer.
    pub fn subscribe(&self) -> broadcast::Receiver<Arc<CaptureEnvelope>> {
        self.events.subscribe()
    }

    /// A handle that can make subscribers later without being one.
    ///
    /// Holding a [`broadcast::Receiver`] is not free: it keeps
    /// `receiver_count()` above zero, which switches on the tee in
    /// the writer task for a session that may never read a record, and it
    /// pins the channel's whole backlog — bodies included — alive behind it.
    /// A `Sender` clone costs neither, so a caller that only *might* subscribe
    /// takes this and calls `subscribe()` on it if it does.
    pub fn events(&self) -> broadcast::Sender<Arc<CaptureEnvelope>> {
        self.events.clone()
    }

    /// Queue a record for the writer task. Returns `Err` only if the task is
    /// gone (e.g. after [`Self::shutdown`]); serialization and IO errors are
    /// logged in the task, not returned here.
    async fn queue(&self, record: CaptureRecord) -> anyhow::Result<()> {
        let envelope = Arc::new(CaptureEnvelope::for_session(record, self.session));
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

    /// Write one protocol event and the findings it drew.
    ///
    /// Queued like every other record, so an event still applies backpressure
    /// rather than being dropped: a capture that silently loses the quiet
    /// events would lose exactly the evidence this record was added to carry.
    pub async fn write_protocol_event(
        &self,
        record: crate::protocol_event::ProtocolEventRecord,
    ) -> anyhow::Result<()> {
        self.queue(CaptureRecord::ProtocolEvent(Box::new(record)))
            .await
    }

    /// Queue a protocol event from synchronous code.
    ///
    /// The frame observer that produces these is a plain `Fn` inside the h3
    /// connection driver and cannot await. Rather than spawn every write —
    /// which would leave a record that had not yet been polled unqueued at
    /// shutdown, and is the one moment a GOAWAY is most likely to arrive — this
    /// takes the free slot the channel almost always has and returns with the
    /// record **already queued**, so [`Self::shutdown`]'s drain covers it.
    ///
    /// The fallback is the interesting case and it keeps the promise the
    /// bounded channel makes: a full queue means the writer is behind, so the
    /// send is moved to a task that can wait for a slot instead of dropping the
    /// record. Backpressure is deferred rather than skipped, which is the most
    /// a caller with no `await` can offer.
    pub fn queue_protocol_event(&self, record: crate::protocol_event::ProtocolEventRecord) {
        let envelope = Arc::new(CaptureEnvelope::for_session(
            CaptureRecord::ProtocolEvent(Box::new(record)),
            self.session,
        ));
        match self.tx.try_send(CaptureMsg::Record(envelope)) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(msg)) => {
                let tx = self.tx.clone();
                tokio::spawn(async move {
                    if tx.send(msg).await.is_err() {
                        warn!("capture writer task is gone; protocol event not recorded");
                    }
                });
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                warn!("capture writer task is gone; protocol event not recorded");
            }
        }
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
        // Neither carries a separately-skipped body, so both serialize whole.
        CaptureRecord::WebsocketSession(_) | CaptureRecord::ProtocolEvent(_) => {
            return serde_json::to_string(envelope)
        }
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

/// The inverse of [`serialize_record`]'s body injection: take the base64
/// `body` a capture line carries on its `request`/`response` object and hand
/// the octets back as the transaction's own.
///
/// **The writer had no reader, and nothing said so.** `request_body` and
/// `response_body` are `#[serde(skip)]`, which skips both directions, so the
/// bodies `captures_include_body` writes were dropped on every read — and the
/// rules that parse body octets reported nothing on any capture file, silently.
/// The metadata beside the octets was the tell: `body_length`,
/// `*_body_over_limit` and `body_interrupted` all serialize, so a reader kept
/// everything needed to judge a body it could never see.
///
/// A `body` that is present and does not decode makes the record unreadable
/// rather than body-less. Linting the headers and staying quiet about content
/// nobody could reconstruct is the failure being fixed here, not a fallback for
/// it; `records_unread` is where a report says what it could not take in.
fn take_injected_body(
    v: &mut serde_json::Value,
    which: &str,
) -> Result<Option<bytes::Bytes>, String> {
    let Some(obj) = v.get_mut(which).and_then(|m| m.as_object_mut()) else {
        return Ok(None);
    };
    let Some(raw) = obj.remove("body") else {
        return Ok(None);
    };
    let Some(encoded) = raw.as_str() else {
        return Err(format!("`{which}.body` is not a string"));
    };
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map(|b| Some(bytes::Bytes::from(b)))
        .map_err(|e| format!("`{which}.body` is not base64: {e}"))
}

/// Parse one capture line, restoring any bodies the writer injected.
///
/// The parse goes through `serde_json::Value` because that is the shape the
/// writer injects into, so the two halves stay each other's inverse rather
/// than two independent readings of the same key.
pub(crate) fn parse_record_line(line: &str) -> Result<CaptureEnvelope, String> {
    let mut v: serde_json::Value = serde_json::from_str(line).map_err(|e| e.to_string())?;
    let request_body = take_injected_body(&mut v, "request")?;
    let response_body = take_injected_body(&mut v, "response")?;
    let mut envelope: CaptureEnvelope = serde_json::from_value(v).map_err(|e| e.to_string())?;

    // Only a transaction has anywhere to put them. A body key on any other
    // record type was removed above and is not carried anywhere, which is what
    // the writer's own shape says: nothing else has a separately-skipped body.
    if let CaptureRecord::HttpTransaction(tx) = &mut envelope.record {
        tx.request_body = request_body;
        tx.response_body = response_body;
    }
    Ok(envelope)
}

/// What one read of a capture file yielded: the records, and how many lines it
/// could not turn into one.
///
/// **The count is returned rather than only logged.** The skip has always
/// written a `tracing::warn!`, which reaches a reader only where diagnostics
/// were initialised — and on the `lint-captures` path they are not, so the
/// warning went nowhere and a file whose every line was unreadable produced an
/// empty report and a zero exit. But a subscriber would not have been the fix
/// either: what is missing from the report is content, and a report says what
/// it is missing in the report. That is the argument `hidden_severity` and
/// `hidden_party` already carry — a filtered report and a clean one are
/// indistinguishable unless one of them says so — reaching the one cause the
/// reader cannot correct with a flag.
#[derive(Debug, Default)]
pub struct CaptureLoad {
    /// The records the file yielded, in file order.
    pub records: Vec<CaptureRecord>,
    /// Lines that were not empty and did not parse as a record.
    ///
    /// Blank lines are not counted: a JSONL file ends with a newline, and a
    /// trailing empty line is how it is written rather than something lost.
    pub unread: usize,
}

/// Load every capture record from a JSONL file, in file order. Skips malformed
/// lines with warnings. Missing file → empty (callers that require the file to
/// exist check first).
pub async fn load_capture_records<P: AsRef<std::path::Path>>(
    path: P,
) -> anyhow::Result<Vec<CaptureRecord>> {
    Ok(load_capture_records_from(path, 0).await?.records)
}

/// Load the records appended at or after `offset` bytes.
///
/// The capture file is opened for append, so a session that shares its path
/// with another writer cannot identify its own records by counting: both would
/// count before either wrote. A byte offset taken when a session starts is that
/// session's own mark whatever else is appending, and seeking past the history
/// also skips parsing it — which for a long-lived capture file is the whole
/// cost of reading it twice.
///
/// The offset is expected to land on a record boundary, because it is the
/// file's length at a moment when only whole lines had been written. A partial
/// line after it is skipped with a warning like any other unparseable record.
pub async fn load_capture_records_from<P: AsRef<std::path::Path>>(
    path: P,
    offset: u64,
) -> anyhow::Result<CaptureLoad> {
    load_session_records(path, offset, None).await
}

/// Load records appended at or after `offset`, optionally keeping only those a
/// given session wrote.
///
/// The offset is the cheap half — it skips parsing a history that may be far
/// larger than the session. The session id is the exact half: two sessions
/// appending to one path both start at the same offset, so position alone
/// cannot separate them and only the stamp can.
pub async fn load_session_records<P: AsRef<std::path::Path>>(
    path: P,
    offset: u64,
    session: Option<uuid::Uuid>,
) -> anyhow::Result<CaptureLoad> {
    use tokio::io::{AsyncBufReadExt, AsyncSeekExt};

    let path_ref = path.as_ref();

    if !tokio::fs::try_exists(path_ref).await.unwrap_or(false) {
        return Ok(CaptureLoad::default());
    }

    let mut file = tokio::fs::File::open(path_ref).await?;
    if offset > 0 {
        // A file that shrank under us (truncated, or replaced) leaves the
        // offset past the end; seeking there simply yields nothing, which is
        // the right answer — this session's records are gone either way.
        file.seek(std::io::SeekFrom::Start(offset)).await?;
    }
    let reader = tokio::io::BufReader::new(file);
    let mut lines = reader.lines();
    let mut records = Vec::new();
    let mut unread = 0;
    let mut line_num = 0;

    while let Some(line) = lines.next_line().await? {
        line_num += 1;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            tracing::debug!(line = line_num, "skipping empty/whitespace capture line");
            continue;
        }

        // Parse the tagged, versioned envelope. Unknown types are skipped.
        match parse_record_line(trimmed) {
            // A session filter keeps only what this session stamped. Records
            // with no stamp are another writer's (or predate the field), so
            // they are not this session's either way.
            Ok(envelope) if session.is_some() && envelope.session != session => {}
            Ok(envelope) => records.push(envelope.record),
            Err(e) => {
                unread += 1;
                tracing::warn!(line = line_num, error = %e, "failed to parse capture record, skipping");
            }
        }
    }

    Ok(CaptureLoad { records, unread })
}

/// Load only the HTTP transactions from a JSONL capture file (other record
/// types are dropped). Backs the proxy's cold-start state seeding; `lint`
/// replays every record via [`load_capture_records`].
pub async fn load_captures<P: AsRef<std::path::Path>>(
    path: P,
) -> anyhow::Result<Vec<crate::http_transaction::HttpTransaction>> {
    Ok(load_capture_records(path)
        .await?
        .into_iter()
        .filter_map(|record| match record {
            CaptureRecord::HttpTransaction(tx) => Some(*tx),
            CaptureRecord::WebsocketSession(_) | CaptureRecord::ProtocolEvent(_) => None,
        })
        .collect())
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
        let mut temp = crate::temp_files::TempFiles::new();
        let tmp = temp.path("lint_capture_test", "jsonl");
        let p = tmp
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("temp path not utf8"))?
            .to_string();

        let cw = CaptureWriter::new(p.clone(), false).await?;

        let mut req_headers = HeaderMap::new();
        req_headers.insert("x-test", "1".parse()?);

        let violations = vec![crate::lint::Violation::new(
            "r1",
            crate::lint::Severity::Warn,
            "m",
        )];

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
        let mut temp = crate::temp_files::TempFiles::new();
        let tmp = temp.path("lint_capture_bodies_test", "jsonl");
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
            body_interrupted: false,
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

    /// The other half of the test above, and for a long time nobody wrote it.
    ///
    /// `write_transaction_includes_bodies_when_enabled` asserts the octets
    /// reach the JSON. That they come back was assumed, and they did not:
    /// `request_body`/`response_body` are `#[serde(skip)]`, which skips reading
    /// as well as writing, so every body a capture carried was dropped on load
    /// and every rule that parses body octets reported nothing on a capture
    /// file — silently, since a rule with no body to read has nothing to say.
    #[tokio::test]
    async fn read_restores_the_bodies_that_were_written() -> anyhow::Result<()> {
        let mut temp = crate::temp_files::TempFiles::new();
        let tmp = temp.path("lint_capture_body_roundtrip", "jsonl");
        let p = tmp
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("temp path not utf8"))?
            .to_string();

        let cw = CaptureWriter::new(p.clone(), true).await?;
        use crate::test_helpers::make_test_transaction_with_response;
        let mut tx = make_test_transaction_with_response(200, &[("content-type", "text/plain")]);
        tx.request_body = Some(bytes::Bytes::from_static(b"req-body"));
        tx.response_body = Some(bytes::Bytes::from_static(b"resp-body"));
        cw.write_transaction(tx).await?;
        cw.flush().await?;

        let loaded = load_captures(&tmp).await?;
        assert_eq!(loaded.len(), 1);
        assert_eq!(
            loaded[0].request_body.as_deref(),
            Some(&b"req-body"[..]),
            "the request body did not survive the round trip"
        );
        assert_eq!(
            loaded[0].response_body.as_deref(),
            Some(&b"resp-body"[..]),
            "the response body did not survive the round trip"
        );

        fs::remove_file(&tmp).await?;
        Ok(())
    }

    /// A file written without bodies reads back body-less, and is not thereby
    /// unreadable. The absent key is the writer saying there was nothing to
    /// carry, which is a different answer from a key nobody could decode.
    #[tokio::test]
    async fn read_without_bodies_is_not_an_unread_record() -> anyhow::Result<()> {
        let mut temp = crate::temp_files::TempFiles::new();
        let tmp = temp.path("lint_capture_no_body", "jsonl");
        let p = tmp
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("temp path not utf8"))?
            .to_string();

        let cw = CaptureWriter::new(p.clone(), false).await?;
        use crate::test_helpers::make_test_transaction_with_response;
        let mut tx = make_test_transaction_with_response(200, &[("content-type", "text/plain")]);
        tx.request_body = Some(bytes::Bytes::from_static(b"req-body"));
        cw.write_transaction(tx).await?;
        cw.flush().await?;

        let load = load_capture_records_from(&tmp, 0).await?;
        assert_eq!(load.unread, 0);
        assert_eq!(load.records.len(), 1);
        match &load.records[0] {
            CaptureRecord::HttpTransaction(tx) => {
                assert!(tx.request_body.is_none());
                assert!(tx.response_body.is_none());
            }
            other => panic!("expected a transaction, got {other:?}"),
        }

        fs::remove_file(&tmp).await?;
        Ok(())
    }

    /// A `body` that is present and does not decode leaves the record unread
    /// rather than body-less. Linting the headers and saying nothing about
    /// content nobody could reconstruct is the failure this reader exists to
    /// end, so it must not be the fallback when the reconstruction fails.
    #[tokio::test]
    async fn a_body_that_is_not_base64_makes_the_record_unread() -> anyhow::Result<()> {
        let mut temp = crate::temp_files::TempFiles::new();
        let tmp = temp.path("lint_capture_bad_body", "jsonl");

        use crate::test_helpers::make_test_transaction_with_response;
        let tx = make_test_transaction_with_response(200, &[("content-type", "text/plain")]);
        let mut v: Value = serde_json::from_str(&tx_line(&tx))?;
        v["response"]["body"] = Value::String("not base64 !!!".into());
        fs::write(&tmp, format!("{v}\n")).await?;

        let load = load_capture_records_from(&tmp, 0).await?;
        assert_eq!(load.unread, 1, "an undecodable body must count as unread");
        assert!(load.records.is_empty());

        fs::remove_file(&tmp).await?;
        Ok(())
    }

    #[tokio::test]
    async fn load_captures_reads_jsonl() -> anyhow::Result<()> {
        let mut temp = crate::temp_files::TempFiles::new();
        let tmp = temp.path("lint_load_test", "jsonl");
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
    async fn load_capture_records_keeps_all_kinds_in_file_order() -> anyhow::Result<()> {
        let mut temp = crate::temp_files::TempFiles::new();
        let tmp = temp.path("lint_load_all", "jsonl");
        let p = tmp
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("temp path not utf8"))?
            .to_string();

        let cw = CaptureWriter::new(p.clone(), false).await?;
        use crate::test_helpers::make_test_transaction_with_response;
        cw.write_transaction(make_test_transaction_with_response(200, &[]))
            .await?;
        let session = crate::websocket_session::WebSocketSession::new(Uuid::new_v4());
        cw.write_websocket_session(session).await?;
        cw.flush().await?;

        let records = load_capture_records(&tmp).await?;
        assert_eq!(records.len(), 2);
        assert!(matches!(records[0], CaptureRecord::HttpTransaction(_)));
        assert!(matches!(records[1], CaptureRecord::WebsocketSession(_)));

        // The transaction-only view still filters the session out.
        let txs = load_captures(&tmp).await?;
        assert_eq!(txs.len(), 1);

        fs::remove_file(&tmp).await?;
        Ok(())
    }

    #[tokio::test]
    async fn load_captures_skips_malformed_lines() -> anyhow::Result<()> {
        let mut temp = crate::temp_files::TempFiles::new();
        let tmp = temp.path("lint_malformed_test", "jsonl");

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

    /// The count is the whole point of returning a load rather than a vector:
    /// the records alone cannot say that anything is missing from them, and the
    /// `tracing::warn!` beside this skip reaches a reader only where a
    /// subscriber was installed.
    #[tokio::test]
    async fn a_load_counts_the_lines_it_could_not_read() -> anyhow::Result<()> {
        let mut temp = crate::temp_files::TempFiles::new();
        let tmp = temp.path("lint_unread_count_test", "jsonl");

        use crate::test_helpers::make_test_transaction;
        let tx = make_test_transaction();
        // Two unreadable lines, of three different kinds of unreadable: not
        // JSON at all, and JSON that is not a record. Blank lines are between
        // them and are *not* unread — a file ends in a newline.
        let content = format!(
            "{}\ninvalid json line\n\n{{\"not\":\"a capture\"}}\n",
            tx_line(&tx)
        );
        fs::write(&tmp, content).await?;

        let load = load_capture_records_from(&tmp, 0).await?;
        assert_eq!(load.records.len(), 1);
        assert_eq!(load.unread, 2, "the blank line is not an unread record");

        fs::remove_file(&tmp).await?;
        Ok(())
    }

    /// A file of nothing but unreadable lines yields no records *and* says so.
    /// Read through the records alone it is indistinguishable from a capture of
    /// a session that saw no traffic, which is what let it pass as one.
    #[tokio::test]
    async fn a_wholly_unreadable_file_is_not_an_empty_one() -> anyhow::Result<()> {
        let mut temp = crate::temp_files::TempFiles::new();
        let unreadable = temp.path("lint_all_unread_test", "jsonl");
        let empty = temp.path("lint_no_lines_test", "jsonl");

        fs::write(&unreadable, "{\"not\":\"a capture\"}\nnor this\n").await?;
        fs::write(&empty, "").await?;

        let bad = load_capture_records_from(&unreadable, 0).await?;
        let nothing = load_capture_records_from(&empty, 0).await?;

        assert!(bad.records.is_empty() && nothing.records.is_empty());
        assert_eq!(bad.unread, 2);
        assert_eq!(nothing.unread, 0);

        fs::remove_file(&unreadable).await?;
        fs::remove_file(&empty).await?;
        Ok(())
    }

    #[tokio::test]
    async fn load_captures_skips_empty_lines() -> anyhow::Result<()> {
        let mut temp = crate::temp_files::TempFiles::new();
        let tmp = temp.path("lint_empty_lines_test", "jsonl");

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
        let mut temp = crate::temp_files::TempFiles::new();
        let tmp = temp.path("lint_ws_test", "jsonl");

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
        let mut temp = crate::temp_files::TempFiles::new();
        let tmp = temp.path("lint_blank_line_test", "jsonl");
        // Single blank line should be ignored
        fs::write(&tmp, "\n").await?;

        let records = load_captures(&tmp).await?;
        assert_eq!(records.len(), 0);

        fs::remove_file(&tmp).await?;
        Ok(())
    }

    #[tokio::test]
    async fn load_captures_empty_file_returns_empty() -> anyhow::Result<()> {
        let mut temp = crate::temp_files::TempFiles::new();
        let tmp = temp.path("lint_empty_test", "jsonl");
        fs::write(&tmp, "").await?;

        let records = load_captures(&tmp).await?;
        assert_eq!(records.len(), 0);

        fs::remove_file(&tmp).await?;
        Ok(())
    }

    #[tokio::test]
    async fn load_captures_nonexistent_file_returns_empty() -> anyhow::Result<()> {
        let mut temp = crate::temp_files::TempFiles::new();
        let tmp = temp.path("lint_nonexistent", "jsonl");

        // Should not error, just return empty vector
        let records = load_captures(&tmp).await?;
        assert_eq!(records.len(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn write_websocket_session_writes_jsonl() -> anyhow::Result<()> {
        let mut temp = crate::temp_files::TempFiles::new();
        let tmp = temp.path("lint_ws_session_test", "jsonl");
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
            masked: None,
            timestamp: None,
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
        let mut temp = crate::temp_files::TempFiles::new();
        let tmp = temp.path("lint_mixed_records_test", "jsonl");

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
            masked: None,
            timestamp: None,
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
        let mut temp = crate::temp_files::TempFiles::new();
        let tmp = temp.path("lint_stream_sub", "jsonl");
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
        let mut temp = crate::temp_files::TempFiles::new();
        let tmp = temp.path("lint_stream_nosub", "jsonl");
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
        let mut temp = crate::temp_files::TempFiles::new();
        let dir = temp.dir("lint_capture_dir");
        tokio::fs::create_dir(&dir).await?;
        let res = CaptureWriter::new(dir.clone(), false).await;
        assert!(res.is_err());
        tokio::fs::remove_dir(&dir).await?;
        Ok(())
    }
}
