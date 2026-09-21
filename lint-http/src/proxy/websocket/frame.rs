// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! An incremental RFC 6455 frame-boundary scanner that records what it reads
//! and refuses nothing.
//!
//! This exists because a linting relay needs the opposite of a validating
//! parser: a reserved opcode, a nonzero RSV bit, or an unmasked client frame
//! are the *findings*, so the reader that meets them first must record them,
//! not fail the connection. Base framing is total — every octet sequence
//! spells some header, extension data is carried inside the counted payload,
//! and so the scanner never desyncs, whatever the frames contain.
//!
//! Data-frame payloads are never buffered here: the relay forwards the same
//! bytes it scanned, and the header-level facts are all the frame rules read.
//! Control-frame payloads are buffered (the document bounds them at 125
//! bytes) and unmasked, because the close code lives in the first two octets
//! of a Close frame's payload.

/// A frame header exactly as the wire spelled it. Nothing here is validated:
/// reserved opcodes, nonzero RSV bits, and a clear MASK bit from a client are
/// all recorded, because recording them is this proxy's job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct WireFrameHeader {
    /// The FIN bit as written; `false` is a fragment with more to follow.
    pub fin: bool,
    /// The three reserved bits, packed as RSV1 << 2 | RSV2 << 1 | RSV3 — the
    /// same packing the protocol event carries.
    // cite(RFC 6455 § 5.2): "RSV1, RSV2, RSV3:  1 bit each"
    pub rsv: u8,
    /// The opcode as written, 0..=15 — including the reserved ranges, which
    /// parse like any other value here so a rule can report them.
    // cite(RFC 6455 § 5.2): "%x3-7 are reserved for further non-control frames"
    // cite(RFC 6455 § 5.2): "%xB-F are reserved for further control frames"
    pub opcode: u8,
    /// The MASK bit as written. The bit, not the key: § 5.2 defines it as
    /// whether the payload is masked, and a key is present exactly when set.
    pub masked: bool,
    /// The masking key, present exactly when `masked`.
    pub mask_key: Option<[u8; 4]>,
    /// The payload length as read from len7/len16/len64, exactly as written.
    pub payload_length: u64,
}

/// What a fed chunk completed.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum ScanItem {
    /// A header completed; emitted before its payload is consumed, so the
    /// event carries the arrival time of the frame's first bytes.
    Frame(WireFrameHeader),
    /// A control frame's payload completed. Unmasked here (§ 5.3's XOR with
    /// the key octet at index i mod 4) when the header carried a key, so a
    /// Close frame's code can be read from its first two octets.
    ControlPayload { opcode: u8, payload: Vec<u8> },
}

/// Payload buffering for the frame currently being consumed.
enum PayloadMode {
    /// Data frame: bytes stream through, only counted.
    Streamed,
    /// Control frame within the § 5.5 bound: payload collected for the
    /// observer, with the mask key to undo before emitting.
    // cite(RFC 6455 § 5.5): "All control frames MUST have a payload length of 125 bytes or less and MUST NOT be fragmented."
    Buffered {
        opcode: u8,
        mask_key: Option<[u8; 4]>,
        collected: Vec<u8>,
    },
}

/// Incremental scanner: feed it the chunks read off the wire, in order, and
/// it returns the frame boundaries those chunks crossed. Infallible by
/// construction — there is no invalid header, only headers worth reporting.
pub(super) struct FrameScanner {
    /// Partial header bytes (a complete header is at most 14 bytes).
    hbuf: Vec<u8>,
    /// Payload bytes left in the frame currently being consumed.
    remaining: u64,
    mode: PayloadMode,
}

impl FrameScanner {
    pub(super) fn new() -> Self {
        Self {
            hbuf: Vec::with_capacity(14),
            remaining: 0,
            mode: PayloadMode::Streamed,
        }
    }

    /// Feed the chunk just read off the wire. Returns the items whose
    /// boundaries this chunk crossed, in wire order.
    pub(super) fn feed(&mut self, chunk: &[u8]) -> Vec<ScanItem> {
        let mut items = Vec::new();
        let mut rest = chunk;
        while !rest.is_empty() {
            rest = if self.remaining > 0 {
                self.consume_payload(rest, &mut items)
            } else {
                self.consume_header(rest, &mut items)
            };
        }
        items
    }

    /// True when the wire ended mid-frame — a truncated direction worth a log
    /// line when the relay winds down.
    pub(super) fn mid_frame(&self) -> bool {
        !self.hbuf.is_empty() || self.remaining > 0
    }

    /// Take payload bytes for the current frame; returns what is left of the
    /// chunk after the frame's payload is satisfied.
    fn consume_payload<'a>(&mut self, chunk: &'a [u8], items: &mut Vec<ScanItem>) -> &'a [u8] {
        let take = (self.remaining).min(chunk.len() as u64) as usize;
        if let PayloadMode::Buffered { collected, .. } = &mut self.mode {
            collected.extend_from_slice(&chunk[..take]);
        }
        self.remaining -= take as u64;
        if self.remaining == 0 {
            self.finish_payload(items);
        }
        &chunk[take..]
    }

    /// The current frame's payload is complete: emit the buffered control
    /// payload, unmasked, if this frame carried one.
    fn finish_payload(&mut self, items: &mut Vec<ScanItem>) {
        if let PayloadMode::Buffered {
            opcode,
            mask_key,
            collected,
        } = std::mem::replace(&mut self.mode, PayloadMode::Streamed)
        {
            items.push(ScanItem::ControlPayload {
                opcode,
                payload: unmask(collected, mask_key),
            });
        }
    }

    /// Accumulate header bytes; when a header completes, emit it and set up
    /// its payload. Returns what is left of the chunk.
    fn consume_header<'a>(&mut self, chunk: &'a [u8], items: &mut Vec<ScanItem>) -> &'a [u8] {
        let needed = self.header_len_needed();
        let take = (needed - self.hbuf.len()).min(chunk.len());
        self.hbuf.extend_from_slice(&chunk[..take]);
        if self.hbuf.len() == self.header_len_needed() && self.hbuf.len() >= 2 {
            let header = parse_header(&self.hbuf);
            self.hbuf.clear();
            // Wire order: the header first, then — for an empty control frame,
            // whose payload is complete the moment its header is — the payload.
            let empty_control = self.begin_payload(&header);
            items.push(ScanItem::Frame(header));
            items.extend(empty_control);
        }
        &chunk[take..]
    }

    /// How many bytes the header being accumulated needs in total, given what
    /// has arrived so far; a header is complete only when this many are held
    /// *and* at least the first two bytes have been seen.
    fn header_len_needed(&self) -> usize {
        if self.hbuf.len() < 2 {
            return 2;
        }
        let b1 = self.hbuf[1];
        let mask_len = if b1 & 0x80 != 0 { 4 } else { 0 };
        let len_ext = match b1 & 0x7F {
            126 => 2,
            127 => 8,
            _ => 0,
        };
        2 + len_ext + mask_len
    }

    /// Set up payload consumption for a freshly parsed header. Returns the
    /// already-complete payload item of an *empty* control frame, which has no
    /// payload bytes to wait for.
    fn begin_payload(&mut self, header: &WireFrameHeader) -> Option<ScanItem> {
        self.remaining = header.payload_length;
        self.mode = PayloadMode::Streamed;
        // Control frames are identified by the opcode's high bit; buffer only
        // those the document bounds, so an over-length "control" frame streams
        // through uncollected (its header is already on record).
        // cite(RFC 6455 § 5.5): "Control frames are identified by opcodes where the most significant bit of the opcode is 1."
        if header.opcode & 0x08 == 0 || header.payload_length > 125 {
            return None;
        }
        if header.payload_length == 0 {
            return Some(ScanItem::ControlPayload {
                opcode: header.opcode,
                payload: Vec::new(),
            });
        }
        self.mode = PayloadMode::Buffered {
            opcode: header.opcode,
            mask_key: header.mask_key,
            collected: Vec::with_capacity(header.payload_length as usize),
        };
        None
    }
}

/// Parse a complete header. `h` holds exactly the header's bytes, as
/// determined by [`FrameScanner::header_len_needed`].
fn parse_header(h: &[u8]) -> WireFrameHeader {
    let b0 = h[0];
    let b1 = h[1];
    let masked = b1 & 0x80 != 0;
    let (payload_length, idx) = match b1 & 0x7F {
        126 => (u64::from(u16::from_be_bytes([h[2], h[3]])), 4),
        127 => (
            u64::from_be_bytes([h[2], h[3], h[4], h[5], h[6], h[7], h[8], h[9]]),
            10,
        ),
        n => (u64::from(n), 2),
    };
    let mask_key = masked.then(|| [h[idx], h[idx + 1], h[idx + 2], h[idx + 3]]);
    WireFrameHeader {
        fin: b0 & 0x80 != 0,
        rsv: (b0 >> 4) & 0x07,
        opcode: b0 & 0x0F,
        masked,
        mask_key,
        payload_length,
    }
}

/// Undo § 5.3 masking: octet i XOR key octet at index i mod 4. Applied only
/// to buffered control payloads; data payloads pass through still masked,
/// exactly as the wire carried them.
// cite(RFC 6455 § 5.3): "Octet i of the transformed data ("transformed-octet-i") is the XOR of octet i of the original data ("original-octet-i") with octet at index i modulo 4 of the masking key"
fn unmask(mut payload: Vec<u8>, mask_key: Option<[u8; 4]>) -> Vec<u8> {
    if let Some(key) = mask_key {
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte ^= key[i % 4];
        }
    }
    payload
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// Collect every item a scanner produces for one contiguous wire image.
    fn scan_all(bytes: &[u8]) -> Vec<ScanItem> {
        FrameScanner::new().feed(bytes)
    }

    fn headers(items: &[ScanItem]) -> Vec<&WireFrameHeader> {
        items
            .iter()
            .filter_map(|i| match i {
                ScanItem::Frame(h) => Some(h),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn a_masked_text_frame_reads_back_field_by_field() {
        // FIN + text, masked, len 5, key 01 02 03 04, payload "hello" XOR key.
        let mut wire = vec![0x81, 0x85, 1, 2, 3, 4];
        wire.extend(
            b"hello"
                .iter()
                .enumerate()
                .map(|(i, b)| b ^ [1, 2, 3, 4][i % 4]),
        );
        let items = scan_all(&wire);
        assert_eq!(
            items,
            vec![ScanItem::Frame(WireFrameHeader {
                fin: true,
                rsv: 0,
                opcode: 1,
                masked: true,
                mask_key: Some([1, 2, 3, 4]),
                payload_length: 5,
            })],
            "a data payload streams through: header only"
        );
    }

    /// Headers parse identically however the reads split them — including
    /// one byte at a time, and splits inside the extended length and the key.
    #[test]
    fn a_header_split_across_reads_parses_like_a_contiguous_one() {
        let mut wire = vec![0x82, 0xFE, 0x01, 0x00, 9, 8, 7, 6]; // binary, masked, len16 = 256
        wire.extend(std::iter::repeat_n(0u8, 256));
        let contiguous = scan_all(&wire);

        for split_at in 1..wire.len().min(12) {
            let mut scanner = FrameScanner::new();
            let mut items = scanner.feed(&wire[..split_at]);
            items.extend(scanner.feed(&wire[split_at..]));
            assert_eq!(items, contiguous, "split at {split_at}");
        }

        let mut scanner = FrameScanner::new();
        let mut items = Vec::new();
        for byte in &wire {
            items.extend(scanner.feed(std::slice::from_ref(byte)));
        }
        assert_eq!(items, contiguous, "one byte at a time");
        assert!(!scanner.mid_frame());
    }

    #[rstest]
    // len7 boundary values
    #[case(125, vec![0x81, 125])]
    // len16: 126 and the top of the range
    #[case(126, vec![0x81, 126, 0x00, 126])]
    #[case(65535, vec![0x81, 126, 0xFF, 0xFF])]
    // len64
    #[case(65536, vec![0x81, 127, 0, 0, 0, 0, 0, 1, 0, 0])]
    fn payload_lengths_read_as_written(#[case] expected: u64, #[case] header: Vec<u8>) {
        let mut scanner = FrameScanner::new();
        let items = scanner.feed(&header);
        assert_eq!(headers(&items)[0].payload_length, expected);
        assert!(scanner.mid_frame(), "payload not yet consumed");
    }

    /// A len64 with the most significant bit set is not a length this side
    /// can refuse to read: it is recorded exactly as written.
    #[test]
    fn a_len64_with_the_msb_set_is_recorded_as_read() {
        let items = FrameScanner::new().feed(&[0x81, 127, 0x80, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(headers(&items)[0].payload_length, 0x8000_0000_0000_0001);
    }

    /// Reserved opcodes and nonzero RSV bits parse like anything else — the
    /// whole reason this scanner exists instead of a validating parser.
    #[rstest]
    #[case(0x3)]
    #[case(0x7)]
    #[case(0xB)]
    #[case(0xF)]
    fn a_reserved_opcode_is_recorded_not_refused(#[case] opcode: u8) {
        let items = scan_all(&[0x80 | opcode, 0x00]);
        assert_eq!(headers(&items)[0].opcode, opcode);
    }

    #[test]
    fn rsv_bits_are_recorded_in_event_packing() {
        // RSV1 set: bit 6 of the first byte; packed as 0b100.
        let items = scan_all(&[0xC1, 0x00]);
        assert_eq!(headers(&items)[0].rsv, 0b100);
        // RSV3 set: packed as 0b001.
        let items = scan_all(&[0x91, 0x00]);
        assert_eq!(headers(&items)[0].rsv, 0b001);
    }

    #[test]
    fn an_unmasked_frame_records_the_clear_bit() {
        let items = scan_all(&[0x81, 0x02, b'h', b'i']);
        let h = headers(&items)[0];
        assert!(!h.masked);
        assert_eq!(h.mask_key, None);
    }

    #[test]
    fn a_fragmented_message_reads_as_its_actual_frames() {
        // text fin=false, then continuation fin=true — what the opcode
        // sequence rule was written to see.
        let mut wire = vec![0x01, 0x02, b'h', b'i'];
        wire.extend([0x80, 0x03, b'!', b'!', b'!']);
        let items = scan_all(&wire);
        let hs = headers(&items);
        assert_eq!((hs[0].opcode, hs[0].fin), (1, false));
        assert_eq!((hs[1].opcode, hs[1].fin), (0, true));
    }

    /// A masked Close payload comes back unmasked, code readable.
    #[test]
    fn a_masked_close_payload_is_buffered_and_unmasked() {
        let key = [9, 9, 9, 9];
        let payload = [0x03u8, 0xE8]; // 1000
        let mut wire = vec![0x88, 0x82, 9, 9, 9, 9];
        wire.extend(payload.iter().enumerate().map(|(i, b)| b ^ key[i % 4]));
        let items = scan_all(&wire);
        assert_eq!(items.len(), 2);
        assert_eq!(
            items[1],
            ScanItem::ControlPayload {
                opcode: 8,
                payload: vec![0x03, 0xE8],
            }
        );
    }

    /// An empty control frame's payload is complete with its header, and the
    /// header item still comes first.
    #[test]
    fn an_empty_ping_yields_header_then_empty_payload() {
        let items = scan_all(&[0x89, 0x00]);
        assert_eq!(items.len(), 2);
        assert!(matches!(items[0], ScanItem::Frame(_)));
        assert_eq!(
            items[1],
            ScanItem::ControlPayload {
                opcode: 9,
                payload: Vec::new(),
            }
        );
    }

    /// An over-length "control" frame streams through uncollected: its header
    /// is already on record, and the § 5.5 bound is a rule's finding to make,
    /// not a reason for the scanner to buffer unboundedly.
    #[test]
    fn an_over_length_control_frame_is_not_buffered() {
        let mut wire = vec![0x88, 126, 0x00, 200];
        wire.extend(std::iter::repeat_n(0u8, 200));
        let items = scan_all(&wire);
        assert_eq!(items.len(), 1, "header only, no ControlPayload");
        assert_eq!(headers(&items)[0].payload_length, 200);
    }

    /// A data frame following an empty control frame keeps wire order intact
    /// within one fed chunk.
    #[test]
    fn wire_order_survives_mixed_frames_in_one_chunk() {
        let mut wire = vec![0x89, 0x00]; // empty ping
        wire.extend([0x81, 0x02, b'h', b'i']); // text "hi"
        wire.extend([0x8A, 0x01, 0x42]); // pong, 1 byte
        let items = scan_all(&wire);
        assert!(matches!(
            items[0],
            ScanItem::Frame(WireFrameHeader { opcode: 9, .. })
        ));
        assert!(matches!(
            items[1],
            ScanItem::ControlPayload { opcode: 9, .. }
        ));
        assert!(matches!(
            items[2],
            ScanItem::Frame(WireFrameHeader { opcode: 1, .. })
        ));
        assert!(matches!(
            items[3],
            ScanItem::Frame(WireFrameHeader { opcode: 10, .. })
        ));
        assert!(
            matches!(items[4], ScanItem::ControlPayload { opcode: 10, payload: ref p } if p == &vec![0x42])
        );
    }

    #[test]
    fn mid_frame_reports_a_truncated_wire() {
        let mut scanner = FrameScanner::new();
        scanner.feed(&[0x81]);
        assert!(scanner.mid_frame(), "half a header");
        let mut scanner = FrameScanner::new();
        scanner.feed(&[0x81, 0x05, b'h']);
        assert!(scanner.mid_frame(), "payload cut short");
    }
}
