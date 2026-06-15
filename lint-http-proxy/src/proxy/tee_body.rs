// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! A body wrapper that forwards every frame unchanged while teeing a bounded
//! prefix (for capture + lint) and counting the total length. Used to stream a
//! response/request body through the proxy without buffering it whole.

use bytes::{Bytes, BytesMut};
use http_body_util::{BodyExt, Full};
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

/// Present an already-buffered body (e.g. the H3 request body) through the same
/// streaming interface: a `Full` body plus an immediately-resolved capture
/// bounded to the same prefix rule as [`TeeBody`].
pub(super) fn buffered(
    bytes: Bytes,
    trailers: Option<HeaderMap>,
    prefix_cap: usize,
) -> (InnerBody, oneshot::Receiver<CapturedBody>) {
    let total = bytes.len() as u64;
    let truncated = bytes.len() > prefix_cap;
    let prefix = bytes.slice(0..prefix_cap.min(bytes.len()));
    let (done, rx) = oneshot::channel();
    // The receiver is live (just created), so this never drops.
    let _ = done.send(CapturedBody {
        prefix,
        total,
        truncated,
        trailers,
    });
    let body = Full::new(bytes).map_err(|e| match e {}).boxed_unsync();
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
    /// first call (end-of-stream, error, or drop) fires.
    fn finalize(&mut self) {
        if let Some(done) = self.done.take() {
            let prefix = std::mem::take(&mut self.prefix).freeze();
            let truncated = self.total > prefix.len() as u64;
            let _ = done.send(CapturedBody {
                prefix,
                total: self.total,
                truncated,
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
            Poll::Ready(Some(Err(e))) => {
                this.finalize();
                Poll::Ready(Some(Err(e)))
            }
            Poll::Ready(None) => {
                this.finalize();
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
        self.finalize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    }

    #[tokio::test]
    async fn buffered_presents_full_body_with_bounded_capture() {
        let (body, rx) = buffered(Bytes::from_static(b"hello world"), None, 5);
        let forwarded = body.collect().await.unwrap().to_bytes();
        assert_eq!(forwarded, Bytes::from_static(b"hello world"));

        let captured = rx.await.unwrap();
        assert_eq!(captured.prefix, Bytes::from_static(b"hello"));
        assert_eq!(captured.total, 11);
        assert!(captured.truncated);
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
    }
}
