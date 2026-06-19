// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! A [`hyper::body::Body`] adapter over the receive half of an HTTP/3
//! `RequestStream`, so the request body streams into the shared `exchange` core
//! (teed for capture) instead of being buffered whole. The send half stays with
//! the handler to deliver the response — h3 lets a bidirectional request stream
//! be `split()` so the two directions can be driven independently.

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, Bytes};
use h3::quic::RecvStream;
use h3::server::RequestStream;
use http_body_util::BodyExt;
use hyper::body::{Body, Frame};

use super::BoxError;

type InnerBody = http_body_util::combinators::UnsyncBoxBody<Bytes, BoxError>;

/// Whether the next poll reads body data, then trailers, then ends.
enum State {
    Data,
    Trailers,
    Done,
}

/// Streams the request body out of an h3 receive stream, yielding a trailers
/// frame after the data if the client sent any.
struct H3RequestBody<S> {
    recv: RequestStream<S, Bytes>,
    state: State,
}

impl<S> Body for H3RequestBody<S>
where
    S: RecvStream,
{
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        // `RequestStream` is `Unpin`, so poll the recv half without structural
        // pinning (the same pattern `TeeBody` uses for its inner body).
        let this = self.get_mut();
        loop {
            match this.state {
                State::Data => match this.recv.poll_recv_data(cx) {
                    Poll::Ready(Ok(Some(mut buf))) => {
                        let bytes = buf.copy_to_bytes(buf.remaining());
                        return Poll::Ready(Some(Ok(Frame::data(bytes))));
                    }
                    Poll::Ready(Ok(None)) => this.state = State::Trailers,
                    Poll::Ready(Err(e)) => {
                        this.state = State::Done;
                        return Poll::Ready(Some(Err(Box::new(e) as BoxError)));
                    }
                    Poll::Pending => return Poll::Pending,
                },
                State::Trailers => match this.recv.poll_recv_trailers(cx) {
                    Poll::Ready(Ok(Some(trailers))) => {
                        this.state = State::Done;
                        return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
                    }
                    Poll::Ready(Ok(None)) => {
                        this.state = State::Done;
                        return Poll::Ready(None);
                    }
                    Poll::Ready(Err(e)) => {
                        this.state = State::Done;
                        return Poll::Ready(Some(Err(Box::new(e) as BoxError)));
                    }
                    Poll::Pending => return Poll::Pending,
                },
                State::Done => return Poll::Ready(None),
            }
        }
    }
}

/// Box the receive half of an h3 `RequestStream` as a streaming request body,
/// ready to be teed and forwarded to the upstream by `exchange`.
pub(super) fn boxed<S>(recv: RequestStream<S, Bytes>) -> InnerBody
where
    S: RecvStream + Send + 'static,
{
    H3RequestBody {
        recv,
        state: State::Data,
    }
    .boxed_unsync()
}
