// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! A body wrapper that forwards every frame unchanged while teeing a bounded
//! prefix (for capture + lint) and counting the total length. Used to stream a
//! response/request body through the proxy without buffering it whole.

use bytes::{Bytes, BytesMut};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};
use hyper::HeaderMap;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::sync::oneshot;

use super::BoxError;

type InnerBody = http_body_util::combinators::UnsyncBoxBody<Bytes, BoxError>;

/// Wrap `inner` in a [`TeeBody`] and return the streaming body to forward plus a
/// receiver that resolves with the [`CapturedBody`] once the body finishes
/// streaming (or is dropped). Used for both request and response bodies.
pub(super) fn tee(
    inner: InnerBody,
    prefix_cap: usize,
) -> (InnerBody, oneshot::Receiver<CapturedBody>) {
    let (done, rx) = oneshot::channel();
    let body = TeeBody::new(inner, prefix_cap, done).boxed_unsync();
    (body, rx)
}

/// What the tee captured once the body finished streaming (or was dropped, e.g.
/// the client disconnected mid-stream).
pub(super) struct CapturedBody {
    /// Up to `prefix_cap` bytes of the body.
    pub prefix: Bytes,
    /// Total data bytes observed (may exceed `prefix.len()`).
    pub total: u64,
    /// Whether `prefix` is a truncated view of a larger body.
    pub truncated: bool,
    /// False when the stream stopped before end-of-stream, which is to say that
    /// `total` counts the octets that arrived rather than the octets the body
    /// had. Only the end-of-stream path can set this, so every other way out --
    /// an error, a drop -- leaves it false and says so.
    pub complete: bool,
    /// Trailers, if the body carried any.
    pub trailers: Option<HeaderMap>,
}

/// Forwards `inner`'s frames unchanged while copying a bounded prefix and
/// summing total length. When the stream ends, errors, or the body is dropped,
/// the captured prefix/total/trailers are sent over the oneshot so a commit
/// task can record the transaction.
pub(super) struct TeeBody {
    inner: InnerBody,
    prefix: BytesMut,
    prefix_cap: usize,
    total: u64,
    trailers: Option<HeaderMap>,
    done: Option<oneshot::Sender<CapturedBody>>,
}

impl TeeBody {
    pub(super) fn new(
        inner: InnerBody,
        prefix_cap: usize,
        done: oneshot::Sender<CapturedBody>,
    ) -> Self {
        Self {
            inner,
            prefix: BytesMut::new(),
            prefix_cap,
            total: 0,
            trailers: None,
            done: Some(done),
        }
    }

    /// Send the captured body to the waiting commit task. Idempotent: only the
    /// first call (end-of-stream, error, or drop) fires -- which is also what
    /// makes `complete` trustworthy: a body that reaches end-of-stream finalizes
    /// there, and the `Drop` that follows every body finds the sender already
    /// taken and says nothing.
    ///
    /// `complete` is the whole reason this takes an argument. All three exits
    /// used to build the same `CapturedBody`, so a count of the octets that
    /// arrived before a client hung up was indistinguishable from a count of the
    /// octets the body had -- and a reader comparing that count against a
    /// declared `Content-Length` was told the sender's framing was wrong when
    /// the only thing that had gone wrong was the reading.
    fn finalize(&mut self, complete: bool) {
        if let Some(done) = self.done.take() {
            let prefix = std::mem::take(&mut self.prefix).freeze();
            let truncated = self.total > prefix.len() as u64;
            let _ = done.send(CapturedBody {
                prefix,
                total: self.total,
                truncated,
                complete,
                trailers: self.trailers.take(),
            });
        }
    }
}

impl Body for TeeBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        // `InnerBody` (a `BoxBody`) is `Unpin`, so `TeeBody` is `Unpin` and the
        // inner body can be polled without structural pinning.
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    let len = data.len();
                    this.total += len as u64;
                    let room = this.prefix_cap.saturating_sub(this.prefix.len());
                    if room > 0 {
                        this.prefix.extend_from_slice(&data[..room.min(len)]);
                    }
                } else if let Some(trailers) = frame.trailers_ref() {
                    this.trailers = Some(trailers.clone());
                }
                Poll::Ready(Some(Ok(frame)))
            }
            // The stream failed part-way. Whatever `total` holds is the octets
            // that arrived before it did, and the body's real length is unknown.
            Poll::Ready(Some(Err(e))) => {
                this.finalize(false);
                Poll::Ready(Some(Err(e)))
            }
            // End of stream: every octet the body had has been counted, and this
            // is the only exit that can say so.
            Poll::Ready(None) => {
                this.finalize(true);
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for TeeBody {
    fn drop(&mut self) {
        // Covers early client disconnect: the body is dropped before reaching
        // end-of-stream, but we still record whatever prefix was forwarded.
        //
        // Reaching here with the sender still in hand does *not* mean the body
        // was cut short, and reading it that way was wrong on the most ordinary
        // response there is. A body of declared length is finished when its last
        // octet arrives, and hyper knows it: it stops polling rather than asking
        // once more to be told `None`. So the common case -- a complete
        // `Content-Length` body -- arrives here having delivered everything it
        // had, and calling that an interruption suppressed findings on traffic
        // where nothing went wrong at all.
        //
        // The inner body is the one that knows, and it is asked. `is_end_stream`
        // is true exactly when there are no more frames to come, which is the
        // question, and false for the reading that genuinely stopped early.
        let complete = self.inner.is_end_stream();
        self.finalize(complete);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::Full;

    fn boxed(bytes: &'static [u8]) -> InnerBody {
        Full::new(Bytes::from_static(bytes))
            .map_err(|e| match e {})
            .boxed_unsync()
    }

    #[tokio::test]
    async fn forwards_full_body_and_tees_truncated_prefix() {
        let (tx, rx) = oneshot::channel();
        let tee = TeeBody::new(boxed(b"hello world"), 5, tx);

        // The whole body is forwarded downstream...
        let forwarded = tee.collect().await.unwrap().to_bytes();
        assert_eq!(forwarded, Bytes::from_static(b"hello world"));

        // ...while only a bounded prefix is captured.
        let captured = rx.await.unwrap();
        assert_eq!(captured.prefix, Bytes::from_static(b"hello"));
        assert_eq!(captured.total, 11);
        assert!(captured.truncated);
        // The stream reached its end, so the count is the body's length and not
        // merely the octets that had arrived.
        assert!(captured.complete);
    }

    #[tokio::test]
    async fn small_body_captured_in_full_without_truncation() {
        let (tx, rx) = oneshot::channel();
        let tee = TeeBody::new(boxed(b"hi"), 1024, tx);

        let forwarded = tee.collect().await.unwrap().to_bytes();
        assert_eq!(forwarded, Bytes::from_static(b"hi"));

        let captured = rx.await.unwrap();
        assert_eq!(captured.prefix, Bytes::from_static(b"hi"));
        assert_eq!(captured.total, 2);
        assert!(!captured.truncated);
        assert!(captured.complete);
    }

    #[tokio::test]
    async fn dropping_mid_stream_still_reports_capture() {
        let (tx, rx) = oneshot::channel();
        let tee = TeeBody::new(boxed(b"abcdef"), 1024, tx);
        // Drop without polling to completion (client disconnect).
        drop(tee);
        let captured = rx.await.unwrap();
        assert_eq!(captured.total, 0);
        assert!(captured.prefix.is_empty());
        assert!(!captured.truncated);
        assert!(!captured.complete);
    }

    /// The ordinary case, and the one that says why `Drop` cannot assume the
    /// worst. A body of declared length is finished when its last octet arrives;
    /// nothing polls it again just to be told so, and it is dropped having
    /// delivered everything it had. Calling that an interruption would suppress
    /// findings on the most common response there is.
    #[tokio::test]
    async fn dropping_a_body_that_had_nothing_left_is_not_an_interruption() {
        let (tx, rx) = oneshot::channel();
        let mut tee = TeeBody::new(boxed(b"abcdef"), 1024, tx);

        // The whole body arrives in one frame; end-of-stream is never polled for.
        let frame = tee.frame().await.unwrap().unwrap();
        assert_eq!(frame.into_data().unwrap(), Bytes::from_static(b"abcdef"));
        drop(tee);

        let captured = rx.await.unwrap();
        assert_eq!(captured.total, 6);
        assert!(captured.complete, "the body had no more frames to give");
    }

    /// The case a declared length is read against, and the one that makes the
    /// flag worth carrying: octets *were* counted, more were still coming, and
    /// the count is not the body. A capture that says only `total: 3` cannot be
    /// told from a body that was three octets long.
    #[tokio::test]
    async fn dropping_with_frames_still_to_come_says_the_count_is_partial() {
        use futures_util::stream;
        let (tx, rx) = oneshot::channel();
        let inner = http_body_util::StreamBody::new(stream::iter([
            Ok::<_, BoxError>(Frame::data(Bytes::from_static(b"abc"))),
            Ok(Frame::data(Bytes::from_static(b"def"))),
        ]))
        .boxed_unsync();
        let mut tee = TeeBody::new(inner, 1024, tx);

        let frame = tee.frame().await.unwrap().unwrap();
        assert_eq!(frame.into_data().unwrap(), Bytes::from_static(b"abc"));
        drop(tee);

        let captured = rx.await.unwrap();
        assert_eq!(captured.total, 3);
        assert!(!captured.complete);
    }

    /// A body that fails part-way leaves the same partial count as a disconnect,
    /// and says so for the same reason: the octets after the error were never
    /// counted because they never arrived.
    #[tokio::test]
    async fn erroring_mid_stream_reports_an_incomplete_count() {
        use futures_util::stream;
        let (tx, rx) = oneshot::channel();
        let inner = http_body_util::StreamBody::new(stream::iter([
            Ok(Frame::data(Bytes::from_static(b"abc"))),
            Err(BoxError::from("upstream went away")),
        ]))
        .boxed_unsync();
        let tee = TeeBody::new(inner, 1024, tx);

        // Collecting surfaces the error; the tee has already finalized by then.
        assert!(tee.collect().await.is_err());

        let captured = rx.await.unwrap();
        assert_eq!(captured.total, 3);
        assert!(!captured.complete);
    }
}
