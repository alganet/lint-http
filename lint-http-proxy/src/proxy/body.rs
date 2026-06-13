// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Bounded body collection shared by the proxy request handlers.
//!
//! Interim guard until the body pipeline streams (#1b): bodies are still
//! buffered fully in memory, but never beyond `general.max_body_bytes`.

use bytes::Bytes;
use http_body_util::{BodyExt, LengthLimitError, Limited};

/// Why a bounded body collection failed.
pub(super) enum CollectLimitedError {
    /// The body exceeded the configured limit. Nothing was collected.
    OverLimit,
    /// The underlying body errored before the limit was reached.
    Other(Box<dyn std::error::Error + Send + Sync>),
}

/// Collect a body into memory, enforcing `limit` on the total data bytes.
///
/// Trailer frames are not counted against the limit. A body of exactly
/// `limit` bytes succeeds; the first data frame that pushes the total past
/// `limit` yields [`CollectLimitedError::OverLimit`].
pub(super) async fn collect_limited<B>(
    body: B,
    limit: usize,
) -> Result<(Bytes, Option<hyper::HeaderMap>), CollectLimitedError>
where
    B: hyper::body::Body,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    match Limited::new(body, limit).collect().await {
        Ok(collected) => {
            let trailers = collected.trailers().cloned();
            Ok((collected.to_bytes(), trailers))
        }
        Err(e) if e.downcast_ref::<LengthLimitError>().is_some() => {
            Err(CollectLimitedError::OverLimit)
        }
        Err(e) => Err(CollectLimitedError::Other(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::Full;

    #[tokio::test]
    async fn under_limit_returns_bytes() {
        let body = Full::new(Bytes::from_static(b"hello"));
        let (bytes, trailers) = match collect_limited(body, 16).await {
            Ok(v) => v,
            Err(_) => panic!("expected success under limit"),
        };
        assert_eq!(&bytes[..], b"hello");
        assert!(trailers.is_none());
    }

    #[tokio::test]
    async fn exactly_at_limit_passes() {
        let body = Full::new(Bytes::from_static(b"12345678"));
        let (bytes, _) = match collect_limited(body, 8).await {
            Ok(v) => v,
            Err(_) => panic!("expected success exactly at limit"),
        };
        assert_eq!(bytes.len(), 8);
    }

    #[tokio::test]
    async fn over_limit_is_distinguished() {
        let body = Full::new(Bytes::from_static(b"123456789"));
        match collect_limited(body, 8).await {
            Err(CollectLimitedError::OverLimit) => {}
            Err(CollectLimitedError::Other(e)) => panic!("expected OverLimit, got Other: {e}"),
            Ok(_) => panic!("expected OverLimit, got success"),
        }
    }

    /// A body that errors before producing any data.
    struct FailingBody;

    impl hyper::body::Body for FailingBody {
        type Data = Bytes;
        type Error = std::io::Error;

        fn poll_frame(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
            std::task::Poll::Ready(Some(Err(std::io::Error::other("simulated body error"))))
        }
    }

    #[tokio::test]
    async fn body_error_maps_to_other() {
        match collect_limited(FailingBody, 8).await {
            Err(CollectLimitedError::Other(e)) => {
                assert!(e.to_string().contains("simulated body error"));
            }
            Err(CollectLimitedError::OverLimit) => panic!("expected Other, got OverLimit"),
            Ok(_) => panic!("expected Other, got success"),
        }
    }
}
