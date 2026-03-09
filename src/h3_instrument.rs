// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Instrumented wrapper around `h3_quinn::Connection` for HTTP/3 frame
//! observation.
//!
//! The `h3` crate processes HTTP/3 framing internally, which means
//! control-stream frames (SETTINGS, MAX_PUSH_ID, etc.) are never directly
//! visible to application code.  This module provides transparent wrappers
//! that sit between `h3_quinn` and `h3`, intercepting raw QUIC stream bytes
//! on incoming unidirectional streams to parse HTTP/3 frame headers and emit
//! [`ProtocolEvent`](crate::protocol_event::ProtocolEvent)s.
//!
//! Bidirectional streams and outgoing streams are passed through unchanged.

use std::sync::Arc;
use std::task::{self, Poll};

use bytes::{Buf, Bytes};
use h3::quic;

use crate::protocol_event::ProtocolEventKind;

/// Callback type for emitting protocol events from within stream wrappers.
pub type EventSink = Arc<dyn Fn(ProtocolEventKind) + Send + Sync>;

// ── QUIC variable-length integer helpers ─────────────────────────────

/// Incremental parser for QUIC variable-length integers (RFC 9000 §16).
///
/// Feed one byte at a time; the parser returns `Some(value)` once the
/// complete integer has been received.
#[derive(Debug, Clone)]
struct VarIntReader {
    buf: [u8; 8],
    len: usize,
    expected: usize,
}

impl VarIntReader {
    fn new() -> Self {
        Self {
            buf: [0; 8],
            len: 0,
            expected: 0,
        }
    }

    fn reset(&mut self) {
        self.len = 0;
        self.expected = 0;
    }

    /// Feed a single byte.  Returns `Some(value)` when the integer is
    /// complete.
    fn feed(&mut self, byte: u8) -> Option<u64> {
        self.buf[self.len] = byte;
        self.len += 1;

        if self.len == 1 {
            self.expected = 1 << (byte >> 6);
        }

        if self.len < self.expected {
            return None;
        }

        let value = match self.expected {
            1 => u64::from(self.buf[0] & 0x3F),
            2 => {
                let v = u16::from_be_bytes([self.buf[0], self.buf[1]]);
                u64::from(v & 0x3FFF)
            }
            4 => {
                let v = u32::from_be_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]);
                u64::from(v & 0x3FFF_FFFF)
            }
            8 => {
                let v = u64::from_be_bytes(self.buf);
                v & 0x3FFF_FFFF_FFFF_FFFF
            }
            _ => unreachable!(),
        };

        Some(value)
    }
}

/// Parse a complete QUIC variable-length integer starting at `pos`.
/// Returns `(value, bytes_consumed)` or `None` if the buffer is too short.
fn parse_varint_at(buf: &[u8], pos: usize) -> Option<(u64, usize)> {
    if pos >= buf.len() {
        return None;
    }
    let first = buf[pos];
    let len = 1usize << (first >> 6);
    if pos + len > buf.len() {
        return None;
    }
    let value = match len {
        1 => u64::from(first & 0x3F),
        2 => {
            let v = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
            u64::from(v & 0x3FFF)
        }
        4 => {
            let v = u32::from_be_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]);
            u64::from(v & 0x3FFF_FFFF)
        }
        8 => {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&buf[pos..pos + 8]);
            let v = u64::from_be_bytes(arr);
            v & 0x3FFF_FFFF_FFFF_FFFF
        }
        _ => unreachable!(),
    };
    Some((value, len))
}

// ── Frame observer state machine ─────────────────────────────────────

/// HTTP/3 frame type: SETTINGS (RFC 9114 §7.2.4).
const H3_FRAME_SETTINGS: u64 = 0x04;
/// HTTP/3 frame type: MAX_PUSH_ID (RFC 9114 §7.2.7).
const H3_FRAME_MAX_PUSH_ID: u64 = 0x0D;
/// HTTP/3 unidirectional stream type for the control stream (RFC 9114 §6.2.1).
const H3_STREAM_TYPE_CONTROL: u64 = 0x00;

/// Maximum payload we buffer for a single frame.  Frames larger than this
/// are skipped instead of buffered, preventing a peer from causing unbounded
/// memory growth by advertising a huge frame length.
///
/// MAX_PUSH_ID needs at most 8 bytes (one varint).  SETTINGS is a sequence
/// of `(identifier, value)` varint pairs — even 256 pairs of 8-byte varints
/// fit in 4 KiB.  8 KiB is generous for any realistic control frame.
const MAX_BUFFERED_PAYLOAD: u64 = 8192;

/// Internal state for the frame-level observer on a unidirectional stream.
#[derive(Debug)]
enum ObserverState {
    /// Reading the stream-type varint (first bytes on any uni stream).
    ReadingStreamType,
    /// Stream is not a control stream — stop parsing.
    PassThrough,
    /// Reading the frame-type varint.
    ReadingFrameType,
    /// Reading the frame-length varint.
    ReadingFrameLength,
    /// Buffering payload for a frame we want to parse.
    ReadingPayload,
    /// Skipping payload for a frame we don't need.
    SkippingPayload,
}

/// Observes raw bytes on an HTTP/3 unidirectional stream, detecting
/// control-stream frames (SETTINGS, MAX_PUSH_ID) and emitting protocol
/// events without modifying the data.
struct FrameObserver {
    state: ObserverState,
    varint: VarIntReader,
    frame_type: u64,
    frame_remaining: u64,
    payload_buf: Vec<u8>,
    sink: EventSink,
}

impl std::fmt::Debug for FrameObserver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FrameObserver")
            .field("state", &self.state)
            .field("frame_type", &self.frame_type)
            .field("frame_remaining", &self.frame_remaining)
            .finish_non_exhaustive()
    }
}

impl FrameObserver {
    fn new(sink: EventSink) -> Self {
        Self {
            state: ObserverState::ReadingStreamType,
            varint: VarIntReader::new(),
            frame_type: 0,
            frame_remaining: 0,
            payload_buf: Vec::new(),
            sink,
        }
    }

    /// Observe a chunk of bytes flowing through the stream.
    ///
    /// This is a pure "tap" — bytes are never modified or withheld.
    fn observe(&mut self, data: &[u8]) {
        let mut pos = 0;
        while pos < data.len() {
            match self.state {
                ObserverState::PassThrough => return,

                ObserverState::ReadingStreamType => {
                    if let Some(stream_type) = self.varint.feed(data[pos]) {
                        self.varint.reset();
                        self.state = if stream_type == H3_STREAM_TYPE_CONTROL {
                            ObserverState::ReadingFrameType
                        } else {
                            ObserverState::PassThrough
                        };
                    }
                    pos += 1;
                }

                ObserverState::ReadingFrameType => {
                    if let Some(frame_type) = self.varint.feed(data[pos]) {
                        self.varint.reset();
                        self.frame_type = frame_type;
                        self.state = ObserverState::ReadingFrameLength;
                    }
                    pos += 1;
                }

                ObserverState::ReadingFrameLength => {
                    if let Some(length) = self.varint.feed(data[pos]) {
                        self.varint.reset();
                        self.frame_remaining = length;

                        let dominated = self.frame_type == H3_FRAME_SETTINGS
                            || self.frame_type == H3_FRAME_MAX_PUSH_ID;

                        if length == 0 && dominated {
                            self.payload_buf.clear();
                            self.emit_frame();
                            self.state = ObserverState::ReadingFrameType;
                        } else if dominated && length <= MAX_BUFFERED_PAYLOAD {
                            self.payload_buf.clear();
                            self.state = ObserverState::ReadingPayload;
                        } else if length == 0 {
                            self.state = ObserverState::ReadingFrameType;
                        } else {
                            self.state = ObserverState::SkippingPayload;
                        }
                    }
                    pos += 1;
                }

                ObserverState::ReadingPayload => {
                    let take = (data.len() - pos).min(self.frame_remaining as usize);
                    self.payload_buf.extend_from_slice(&data[pos..pos + take]);
                    pos += take;
                    self.frame_remaining -= take as u64;

                    if self.frame_remaining == 0 {
                        self.emit_frame();
                        self.state = ObserverState::ReadingFrameType;
                    }
                }

                ObserverState::SkippingPayload => {
                    let skip = (data.len() - pos).min(self.frame_remaining as usize);
                    pos += skip;
                    self.frame_remaining -= skip as u64;

                    if self.frame_remaining == 0 {
                        self.state = ObserverState::ReadingFrameType;
                    }
                }
            }
        }
    }

    /// Parse the buffered payload and emit the corresponding protocol event.
    fn emit_frame(&mut self) {
        match self.frame_type {
            H3_FRAME_SETTINGS => {
                let settings = self.parse_settings();
                (self.sink)(ProtocolEventKind::H3SettingsReceived { settings });
            }
            H3_FRAME_MAX_PUSH_ID => {
                if let Some(push_id) = parse_varint_at(&self.payload_buf, 0).map(|(v, _)| v) {
                    (self.sink)(ProtocolEventKind::H3MaxPushId { push_id });
                }
            }
            _ => {}
        }
    }

    /// Parse SETTINGS payload: repeated `(identifier, value)` varint pairs.
    fn parse_settings(&self) -> Vec<(u64, u64)> {
        let mut out = Vec::new();
        let mut pos = 0;
        while pos < self.payload_buf.len() {
            let (id, consumed) = match parse_varint_at(&self.payload_buf, pos) {
                Some(v) => v,
                None => break,
            };
            pos += consumed;

            let (value, consumed) = match parse_varint_at(&self.payload_buf, pos) {
                Some(v) => v,
                None => break,
            };
            pos += consumed;

            out.push((id, value));
        }
        out
    }
}

// ── Instrumented RecvStream ──────────────────────────────────────────

/// A transparent wrapper around [`h3_quinn::RecvStream`] that feeds incoming
/// bytes through a [`FrameObserver`] before returning them to `h3`.
pub struct InstrumentedRecvStream {
    inner: h3_quinn::RecvStream,
    observer: FrameObserver,
}

impl quic::RecvStream for InstrumentedRecvStream {
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Option<Self::Buf>, h3::quic::StreamErrorIncoming>> {
        let result = self.inner.poll_data(cx);
        if let Poll::Ready(Ok(Some(ref data))) = result {
            self.observer.observe(data.chunk());
        }
        result
    }

    fn stop_sending(&mut self, error_code: u64) {
        self.inner.stop_sending(error_code);
    }

    fn recv_id(&self) -> h3::quic::StreamId {
        self.inner.recv_id()
    }
}

// ── Instrumented Connection ──────────────────────────────────────────

/// A transparent wrapper around [`h3_quinn::Connection`] that instruments
/// incoming unidirectional streams with HTTP/3 frame-level observation.
///
/// Bidirectional streams and outgoing streams are delegated directly to the
/// inner [`h3_quinn::Connection`] without modification.
pub struct InstrumentedConnection {
    inner: h3_quinn::Connection,
    sink: EventSink,
}

impl InstrumentedConnection {
    /// Wrap an existing [`h3_quinn::Connection`].
    ///
    /// Every unidirectional stream accepted via [`poll_accept_recv`] will be
    /// wrapped in an [`InstrumentedRecvStream`] whose frame observer emits
    /// events through `sink`.
    pub fn new(conn: h3_quinn::Connection, sink: EventSink) -> Self {
        Self { inner: conn, sink }
    }
}

impl<B: Buf> quic::OpenStreams<B> for InstrumentedConnection {
    type BidiStream = h3_quinn::BidiStream<B>;
    type SendStream = h3_quinn::SendStream<B>;

    fn poll_open_bidi(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Self::BidiStream, h3::quic::StreamErrorIncoming>> {
        <h3_quinn::Connection as quic::OpenStreams<B>>::poll_open_bidi(&mut self.inner, cx)
    }

    fn poll_open_send(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Self::SendStream, h3::quic::StreamErrorIncoming>> {
        <h3_quinn::Connection as quic::OpenStreams<B>>::poll_open_send(&mut self.inner, cx)
    }

    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        <h3_quinn::Connection as quic::OpenStreams<B>>::close(&mut self.inner, code, reason);
    }
}

impl<B: Buf> quic::Connection<B> for InstrumentedConnection {
    type RecvStream = InstrumentedRecvStream;
    type OpenStreams = h3_quinn::OpenStreams;

    fn poll_accept_recv(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Self::RecvStream, h3::quic::ConnectionErrorIncoming>> {
        match <h3_quinn::Connection as quic::Connection<B>>::poll_accept_recv(&mut self.inner, cx) {
            Poll::Ready(Ok(stream)) => Poll::Ready(Ok(InstrumentedRecvStream {
                inner: stream,
                observer: FrameObserver::new(self.sink.clone()),
            })),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_accept_bidi(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Self::BidiStream, h3::quic::ConnectionErrorIncoming>> {
        <h3_quinn::Connection as quic::Connection<B>>::poll_accept_bidi(&mut self.inner, cx)
    }

    fn opener(&self) -> Self::OpenStreams {
        <h3_quinn::Connection as quic::Connection<B>>::opener(&self.inner)
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Collect emitted events for assertions.
    fn test_sink() -> (EventSink, Arc<Mutex<Vec<ProtocolEventKind>>>) {
        let events: Arc<Mutex<Vec<ProtocolEventKind>>> = Arc::new(Mutex::new(Vec::new()));
        let events_clone = events.clone();
        let sink: EventSink = Arc::new(move |kind| {
            events_clone.lock().unwrap().push(kind);
        });
        (sink, events)
    }

    // ── VarIntReader ─────────────────────────────────────────────────

    #[test]
    fn varint_1byte() {
        let mut r = VarIntReader::new();
        assert_eq!(r.feed(0x25), Some(0x25)); // 00_100101 → 37
    }

    #[test]
    fn varint_2byte() {
        let mut r = VarIntReader::new();
        assert_eq!(r.feed(0x7B), None); // 01_111011 → need 2 bytes
        assert_eq!(r.feed(0xBD), Some(0x3BBD)); // 0111_1011_1011_1101 & 0x3FFF = 0x3BBD
    }

    #[test]
    fn varint_4byte() {
        let mut r = VarIntReader::new();
        assert_eq!(r.feed(0x9D), None); // 10_... → need 4 bytes
        assert_eq!(r.feed(0x7F), None);
        assert_eq!(r.feed(0x3E), None);
        assert_eq!(r.feed(0x7D), Some(0x1D7F_3E7D));
    }

    #[test]
    fn varint_8byte() {
        let mut r = VarIntReader::new();
        let bytes = [0xC2, 0x19, 0x7C, 0x5E, 0xFF, 0x14, 0xE8, 0x8C];
        for &b in &bytes[..7] {
            assert_eq!(r.feed(b), None);
        }
        assert_eq!(r.feed(bytes[7]), Some(151_288_809_941_952_652));
    }

    #[test]
    fn varint_8byte_example() {
        let mut r = VarIntReader::new();
        // From RFC 9000 §A.1: 0xC2197C5EFF14E88C → 151288809941952652
        let bytes = [0xC2, 0x19, 0x7C, 0x5E, 0xFF, 0x14, 0xE8, 0x8C];
        for &b in &bytes[..7] {
            assert_eq!(r.feed(b), None);
        }
        assert_eq!(r.feed(bytes[7]), Some(151_288_809_941_952_652));
    }

    #[test]
    fn varint_reset_and_reuse() {
        let mut r = VarIntReader::new();
        assert_eq!(r.feed(0x05), Some(5));
        r.reset();
        assert_eq!(r.feed(0x0A), Some(10));
    }

    // ── parse_varint_at ──────────────────────────────────────────────

    #[test]
    fn parse_varint_at_1byte() {
        assert_eq!(parse_varint_at(&[0x00], 0), Some((0, 1)));
        assert_eq!(parse_varint_at(&[0x3F], 0), Some((63, 1)));
    }

    #[test]
    fn parse_varint_at_2byte() {
        // 0x4001 → 01_000000_00000001 & 0x3FFF = 1
        assert_eq!(parse_varint_at(&[0x40, 0x01], 0), Some((1, 2)));
    }

    #[test]
    fn parse_varint_at_offset() {
        assert_eq!(parse_varint_at(&[0xFF, 0x05], 1), Some((5, 1)));
    }

    #[test]
    fn parse_varint_at_truncated() {
        assert_eq!(parse_varint_at(&[0x40], 0), None); // needs 2 bytes
    }

    #[test]
    fn parse_varint_at_empty() {
        assert_eq!(parse_varint_at(&[], 0), None);
    }

    // ── FrameObserver: non-control streams ───────────────────────────

    #[test]
    fn non_control_stream_passthrough() {
        let (sink, events) = test_sink();
        let mut obs = FrameObserver::new(sink);
        // Stream type 0x02 (QPACK encoder) — not a control stream.
        obs.observe(&[0x02, 0xFF, 0xFF, 0xFF]);
        assert!(events.lock().unwrap().is_empty());
        assert!(matches!(obs.state, ObserverState::PassThrough));
    }

    // ── FrameObserver: SETTINGS ──────────────────────────────────────

    #[test]
    fn settings_single_chunk() {
        let (sink, events) = test_sink();
        let mut obs = FrameObserver::new(sink);

        // Control stream type (0x00), then SETTINGS frame:
        // Frame type 0x04, length 4 (two setting pairs: id=0x06 val=0x10, id=0x01 val=0x00)
        let data = [
            0x00, // stream type: control
            0x04, // frame type: SETTINGS
            0x04, // payload length: 4 bytes
            0x06, 0x10, // SETTINGS_MAX_FIELD_SECTION_SIZE = 16
            0x01, 0x00, // SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0
        ];
        obs.observe(&data);

        let evts = events.lock().unwrap();
        assert_eq!(evts.len(), 1);
        if let ProtocolEventKind::H3SettingsReceived { ref settings } = evts[0] {
            assert_eq!(settings, &[(0x06, 16), (0x01, 0)]);
        } else {
            panic!("expected H3SettingsReceived, got {:?}", evts[0]);
        }
    }

    #[test]
    fn settings_split_across_chunks() {
        let (sink, events) = test_sink();
        let mut obs = FrameObserver::new(sink);

        // Split the same SETTINGS frame across multiple observe() calls.
        obs.observe(&[0x00]); // stream type
        obs.observe(&[0x04]); // frame type
        obs.observe(&[0x02]); // payload length: 2
        obs.observe(&[0x06]); // first setting id byte
        obs.observe(&[0x10]); // first setting value byte

        let evts = events.lock().unwrap();
        assert_eq!(evts.len(), 1);
        if let ProtocolEventKind::H3SettingsReceived { ref settings } = evts[0] {
            assert_eq!(settings, &[(0x06, 16)]);
        } else {
            panic!("expected H3SettingsReceived");
        }
    }

    #[test]
    fn settings_empty_payload() {
        let (sink, events) = test_sink();
        let mut obs = FrameObserver::new(sink);

        // SETTINGS with zero-length payload (no settings).
        obs.observe(&[0x00, 0x04, 0x00]);

        let evts = events.lock().unwrap();
        assert_eq!(evts.len(), 1);
        if let ProtocolEventKind::H3SettingsReceived { ref settings } = evts[0] {
            assert!(settings.is_empty());
        } else {
            panic!("expected H3SettingsReceived");
        }
    }

    // ── FrameObserver: MAX_PUSH_ID ───────────────────────────────────

    #[test]
    fn max_push_id_frame() {
        let (sink, events) = test_sink();
        let mut obs = FrameObserver::new(sink);

        // Control stream, then a dummy SETTINGS (required first), then MAX_PUSH_ID.
        obs.observe(&[
            0x00, // stream type: control
            0x04, 0x00, // SETTINGS (empty)
            0x0D, // frame type: MAX_PUSH_ID
            0x01, // payload length: 1
            0x07, // push_id = 7
        ]);

        let evts = events.lock().unwrap();
        assert_eq!(evts.len(), 2); // SETTINGS + MAX_PUSH_ID
        if let ProtocolEventKind::H3MaxPushId { push_id } = evts[1] {
            assert_eq!(push_id, 7);
        } else {
            panic!("expected H3MaxPushId, got {:?}", evts[1]);
        }
    }

    // ── FrameObserver: unknown frames skipped ────────────────────────

    #[test]
    fn unknown_frame_skipped() {
        let (sink, events) = test_sink();
        let mut obs = FrameObserver::new(sink);

        obs.observe(&[
            0x00, // control stream
            0x04, 0x00, // SETTINGS (empty)
            0x21, // unknown frame type (0x21 = reserved/extension)
            0x03, // payload length: 3
            0xAA, 0xBB, 0xCC, // payload (skipped)
            0x0D, // MAX_PUSH_ID
            0x01, // length: 1
            0x02, // push_id = 2
        ]);

        let evts = events.lock().unwrap();
        assert_eq!(evts.len(), 2); // SETTINGS + MAX_PUSH_ID
        if let ProtocolEventKind::H3MaxPushId { push_id } = evts[1] {
            assert_eq!(push_id, 2);
        } else {
            panic!("expected H3MaxPushId");
        }
    }

    #[test]
    fn unknown_frame_split_across_chunks() {
        let (sink, events) = test_sink();
        let mut obs = FrameObserver::new(sink);

        // Control stream + SETTINGS
        obs.observe(&[0x00, 0x04, 0x00]);
        // Unknown frame type with 5-byte payload, split into two chunks
        obs.observe(&[0x21, 0x05, 0x01, 0x02]);
        obs.observe(&[0x03, 0x04, 0x05]);
        // Then MAX_PUSH_ID
        obs.observe(&[0x0D, 0x01, 0x09]);

        let evts = events.lock().unwrap();
        assert_eq!(evts.len(), 2);
        if let ProtocolEventKind::H3MaxPushId { push_id } = evts[1] {
            assert_eq!(push_id, 9);
        } else {
            panic!("expected H3MaxPushId");
        }
    }

    // ── FrameObserver: multi-byte varints in frames ──────────────────

    #[test]
    fn settings_with_2byte_varint_values() {
        let (sink, events) = test_sink();
        let mut obs = FrameObserver::new(sink);

        // SETTINGS_MAX_FIELD_SECTION_SIZE (0x06) = 1000 (2-byte varint 0x43E8)
        // Payload: 0x06 (1) + 0x43,0xE8 (2) + 0x01 (1) + 0x00 (1) = 5 bytes
        obs.observe(&[
            0x00, // control stream
            0x04, // SETTINGS
            0x05, // payload length: 5 bytes
            0x06, // id: 0x06
            0x43, 0xE8, // value: 2-byte varint = 0x03E8 = 1000
            0x01, // id: 0x01 (QPACK_MAX_TABLE_CAPACITY)
        ]);
        // Remaining byte of the last setting pair
        obs.observe(&[0x00]); // value: 0

        let evts = events.lock().unwrap();
        assert_eq!(evts.len(), 1);
        if let ProtocolEventKind::H3SettingsReceived { ref settings } = evts[0] {
            assert_eq!(settings, &[(0x06, 1000), (0x01, 0)]);
        } else {
            panic!("expected H3SettingsReceived");
        }
    }

    // ── FrameObserver: 2-byte varint stream type ─────────────────────

    #[test]
    fn two_byte_stream_type_non_control() {
        let (sink, events) = test_sink();
        let mut obs = FrameObserver::new(sink);

        // Stream type 0x41 (2-byte varint for value 1 = push stream).
        obs.observe(&[0x40, 0x01, 0xFF, 0xFF]);
        assert!(events.lock().unwrap().is_empty());
        assert!(matches!(obs.state, ObserverState::PassThrough));
    }

    // ── Zero-length frame does not reuse stale payload_buf ───────────

    #[test]
    fn zero_length_settings_after_nonempty_settings_emits_empty() {
        let (sink, events) = test_sink();
        let mut obs = FrameObserver::new(sink);

        // First SETTINGS with one pair, then a zero-length SETTINGS.
        obs.observe(&[
            0x00, // control stream
            0x04, 0x02, // SETTINGS, length=2
            0x06, 0x10, // (0x06, 16)
            0x04, 0x00, // SETTINGS, length=0
        ]);

        let evts = events.lock().unwrap();
        assert_eq!(evts.len(), 2);
        // Second SETTINGS must have an empty settings vec, not stale data.
        if let ProtocolEventKind::H3SettingsReceived { ref settings } = evts[1] {
            assert!(settings.is_empty());
        } else {
            panic!("expected H3SettingsReceived, got {:?}", evts[1]);
        }
    }

    #[test]
    fn zero_length_max_push_id_does_not_emit() {
        let (sink, events) = test_sink();
        let mut obs = FrameObserver::new(sink);

        // Control stream, SETTINGS (empty), then MAX_PUSH_ID with length=0.
        // A zero-length MAX_PUSH_ID has no varint to parse, so no event.
        obs.observe(&[
            0x00, // control stream
            0x04, 0x00, // SETTINGS (empty)
            0x0D, 0x00, // MAX_PUSH_ID, length=0
        ]);

        let evts = events.lock().unwrap();
        // Only the SETTINGS event; MAX_PUSH_ID has no payload to parse.
        assert_eq!(evts.len(), 1);
        assert!(matches!(
            evts[0],
            ProtocolEventKind::H3SettingsReceived { .. }
        ));
    }

    // ── Oversized frame payload is skipped ───────────────────────────

    #[test]
    fn oversized_settings_frame_is_skipped() {
        let (sink, events) = test_sink();
        let mut obs = FrameObserver::new(sink);

        // Control stream, then a SETTINGS frame claiming a payload larger
        // than MAX_BUFFERED_PAYLOAD.  The observer must skip it rather
        // than buffer unbounded data.
        //
        // Encode length 10000 as a 2-byte varint: 0x4000 | 10000 = 0x6710.
        obs.observe(&[
            0x00, // control stream
            0x04, // SETTINGS
            0x67, 0x10, // length = 10000 (2-byte varint)
        ]);
        // Feed 10000 bytes of junk payload (the observer skips them).
        let junk = vec![0xAA; 10000];
        obs.observe(&junk);

        // No SETTINGS event emitted — the frame was too large.
        assert!(events.lock().unwrap().is_empty());
        // Observer is back to ReadingFrameType, ready for the next frame.
        assert!(matches!(obs.state, ObserverState::ReadingFrameType));
    }

    #[test]
    fn frame_after_oversized_frame_still_observed() {
        let (sink, events) = test_sink();
        let mut obs = FrameObserver::new(sink);

        // Control stream, oversized SETTINGS (skipped), then normal MAX_PUSH_ID.
        obs.observe(&[0x00, 0x04, 0x67, 0x10]); // SETTINGS, length=10000
        obs.observe(&vec![0xAA; 10000]); // skipped payload
        obs.observe(&[0x0D, 0x01, 0x05]); // MAX_PUSH_ID, length=1, push_id=5

        let evts = events.lock().unwrap();
        assert_eq!(evts.len(), 1);
        if let ProtocolEventKind::H3MaxPushId { push_id } = evts[0] {
            assert_eq!(push_id, 5);
        } else {
            panic!("expected H3MaxPushId");
        }
    }
}
