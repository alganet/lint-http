// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! The passive per-direction observer between the wire and the record.
//!
//! Each relay direction owns one: the pump hands it every chunk it forwards,
//! the observer scans frame boundaries, stamps each completed header with its
//! arrival time, commits one protocol event per frame (real FIN, RSV, opcode,
//! MASK bit, and length — as the wire spelled them), and accumulates the
//! session's rows. No sharing, no locks: a direction's state belongs to its
//! own task until the relay joins both and merges the outcomes.

use chrono::Utc;
use uuid::Uuid;

use crate::lint::Violation;
use crate::protocol_event::NegotiatedExtensions;
use crate::proxy::pipeline::ProtocolEventPipeline;
use crate::websocket_session::{MessageDirection, WebSocketMessageInfo};

use super::frame::{FrameScanner, ScanItem};

/// Observes one direction of a relayed session.
pub(super) struct DirectionObserver {
    direction: MessageDirection,
    connection_id: Uuid,
    session_id: Uuid,
    extensions: NegotiatedExtensions,
    pipeline: ProtocolEventPipeline,
    scanner: FrameScanner,
    frames: Vec<WebSocketMessageInfo>,
    violations: Vec<Violation>,
    close_code: Option<u16>,
}

/// What one direction saw, ready to merge into the session record.
pub(super) struct DirectionOutcome {
    pub frames: Vec<WebSocketMessageInfo>,
    pub violations: Vec<Violation>,
    /// The status code of this direction's first Close frame, if one arrived
    /// with a readable code.
    pub close_code: Option<u16>,
}

impl DirectionObserver {
    pub(super) fn new(
        direction: MessageDirection,
        connection_id: Uuid,
        session_id: Uuid,
        extensions: NegotiatedExtensions,
        pipeline: ProtocolEventPipeline,
    ) -> Self {
        Self {
            direction,
            connection_id,
            session_id,
            extensions,
            pipeline,
            scanner: FrameScanner::new(),
            frames: Vec::new(),
            violations: Vec::new(),
            close_code: None,
        }
    }

    /// Observe a chunk the pump is about to forward: scan it, and for every
    /// frame header it completes, record the row and commit the event through
    /// lint. Synchronous on purpose — nothing here awaits, so observation
    /// cannot reorder against the forward write.
    pub(super) fn observe(&mut self, chunk: &[u8]) {
        for item in self.scanner.feed(chunk) {
            match item {
                ScanItem::Frame(header) => {
                    let stamp = Utc::now();
                    let info = WebSocketMessageInfo {
                        direction: self.direction,
                        opcode: header.opcode,
                        payload_length: header.payload_length,
                        fin: header.fin,
                        rsv: header.rsv,
                        masked: Some(header.masked),
                        timestamp: Some(stamp),
                    };
                    let event = info.frame_event(
                        stamp,
                        self.connection_id,
                        self.session_id,
                        &self.extensions,
                    );
                    self.violations.extend(self.pipeline.commit(&event));
                    self.frames.push(info);
                }
                // The status code is the first two octets of a Close payload;
                // the scanner already unmasked it. First Close wins within a
                // direction — anything after it is recorded but changes no
                // conclusion here.
                // cite(RFC 6455 § 5.5.1): "If there is a body, the first two bytes of the body MUST be a 2-byte unsigned integer (in network byte order) representing a status code with value /code/ defined in Section 7.4."
                ScanItem::ControlPayload { opcode: 8, payload } => {
                    if self.close_code.is_none() && payload.len() >= 2 {
                        self.close_code = Some(u16::from_be_bytes([payload[0], payload[1]]));
                    }
                }
                ScanItem::ControlPayload { .. } => {}
            }
        }
    }

    /// True when this direction's wire ended in the middle of a frame.
    pub(super) fn mid_frame(&self) -> bool {
        self.scanner.mid_frame()
    }

    pub(super) fn into_outcome(self) -> DirectionOutcome {
        DirectionOutcome {
            frames: self.frames,
            violations: self.violations,
            close_code: self.close_code,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::CaptureWriter;
    use std::sync::Arc;

    async fn test_observer(
        direction: MessageDirection,
        temp: &mut crate::temp_files::TempFiles,
    ) -> (DirectionObserver, String) {
        let tmp = temp.path("lint_ws_observer", "jsonl");
        let path = tmp.to_str().unwrap().to_string();
        let captures = CaptureWriter::new(path.clone(), false).await.unwrap();
        let cfg = crate::config::Config::default();
        let engine = Arc::new(crate::engine::PreparedEngine::new(&cfg).unwrap());
        let pipeline = ProtocolEventPipeline::new(
            engine,
            Arc::new(crate::protocol_event_store::ProtocolEventStore::new(
                300, 100,
            )),
            captures,
        );
        (
            DirectionObserver::new(
                direction,
                Uuid::new_v4(),
                Uuid::new_v4(),
                NegotiatedExtensions::NoneAccepted,
                pipeline,
            ),
            path,
        )
    }

    /// The observer records the header bits as the wire spelled them — the
    /// masked flag is `Some(bit)` now, never the old `None`, and each frame
    /// carries its own arrival time.
    #[tokio::test]
    async fn frames_are_recorded_with_real_header_bits_and_timestamps() {
        let mut temp = crate::temp_files::TempFiles::new();
        let (mut observer, _path) = test_observer(MessageDirection::Client, &mut temp).await;

        // Masked text "hi", then an unmasked fragmented binary start.
        let key = [1u8, 2, 3, 4];
        let mut wire = vec![0x81, 0x82, 1, 2, 3, 4];
        wire.extend(b"hi".iter().enumerate().map(|(i, b)| b ^ key[i % 4]));
        wire.extend([0x02, 0x03, 9, 9, 9]); // binary, fin=false, unmasked, 3 bytes

        observer.observe(&wire);
        let outcome = observer.into_outcome();

        assert_eq!(outcome.frames.len(), 2);
        assert_eq!(outcome.frames[0].masked, Some(true));
        assert_eq!(outcome.frames[0].opcode, 1);
        assert!(outcome.frames[0].fin);
        assert!(outcome.frames[0].timestamp.is_some());
        assert_eq!(outcome.frames[1].masked, Some(false));
        assert!(
            !outcome.frames[1].fin,
            "the real FIN bit, not a hardcoded true"
        );
        assert_eq!(outcome.close_code, None);
    }

    /// Each direction reads its own close code, from an unmasked payload.
    #[tokio::test]
    async fn the_close_code_is_read_from_this_directions_close_frame() {
        let mut temp = crate::temp_files::TempFiles::new();
        let (mut observer, _path) = test_observer(MessageDirection::Client, &mut temp).await;

        let key = [7u8, 7, 7, 7];
        let payload = [0x03u8, 0xE9]; // 1001
        let mut wire = vec![0x88, 0x82, 7, 7, 7, 7];
        wire.extend(payload.iter().enumerate().map(|(i, b)| b ^ key[i % 4]));

        observer.observe(&wire);
        assert!(!observer.mid_frame());
        let outcome = observer.into_outcome();
        assert_eq!(outcome.close_code, Some(1001));
        assert_eq!(outcome.frames.len(), 1);
        assert_eq!(outcome.frames[0].opcode, 8);
    }

    /// A truncated direction is visible to the relay for its wind-down log.
    #[tokio::test]
    async fn a_wire_cut_mid_frame_reports_as_such() {
        let mut temp = crate::temp_files::TempFiles::new();
        let (mut observer, _path) = test_observer(MessageDirection::Server, &mut temp).await;
        observer.observe(&[0x81, 0x05, b'h']);
        assert!(observer.mid_frame());
    }
}
