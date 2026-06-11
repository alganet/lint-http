// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! CONNECT tunneling and TLS MITM upgrade.

use hyper::body::Incoming;
use hyper::upgrade::Upgraded;
use hyper::{service::service_fn, Request, Uri};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::sync::Arc;
use tracing::{error, info, trace};

use super::http::handle_inner_request;
use super::{ServiceFuture, Shared};

#[derive(Debug)]
pub(super) struct AlwaysResolves(Arc<CertifiedKey>);

impl AlwaysResolves {
    pub(super) fn new(key: Arc<CertifiedKey>) -> Self {
        Self(key)
    }
}

impl ResolvesServerCert for AlwaysResolves {
    fn resolve(&self, _client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

pub(super) async fn handle_connect(
    client_conn: Upgraded,
    uri: Uri,
    shared: Arc<Shared>,
    conn_metadata: Arc<crate::connection::ConnectionMetadata>,
) -> anyhow::Result<()> {
    let host = uri.host().unwrap_or("unknown");

    // Check for passthrough domains
    if shared
        .cfg
        .tls
        .passthrough_domains
        .iter()
        .any(|d| host.ends_with(d))
    {
        info!(%host, "tunneling connection (passthrough)");
        if let Err(e) = tunnel(client_conn, host, uri.port_u16().unwrap_or(443)).await {
            error!("tunnel error: {}", e);
        }
        return Ok(());
    }

    let ca = match shared.ca.as_ref() {
        Some(c) => c,
        None => {
            error!("handle_connect called when TLS CA is not configured");
            return Ok(());
        }
    };
    let cert = ca.gen_cert_for_domain(host)?;

    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(AlwaysResolves::new(cert)));

    // Configure ALPN to support HTTP/2 and HTTP/1.1
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
    // Wrap the hyper `Upgraded` (which implements hyper's `Read`/`Write`) with
    // `TokioIo` so it implements tokio's `AsyncRead`/`AsyncWrite` required by
    // `tokio_rustls::TlsAcceptor::accept`.
    let stream = acceptor.accept(TokioIo::new(client_conn)).await?;

    let service = service_fn(move |req: Request<Incoming>| {
        let shared = shared.clone();
        let conn_metadata = conn_metadata.clone();
        let fut: ServiceFuture = Box::pin(async move {
            handle_inner_request(req, shared, conn_metadata, hyper::http::uri::Scheme::HTTPS).await
        });
        fut
    });

    // Build an auto-detect HTTP connection for the TLS stream.
    let executor = TokioExecutor::new();
    let builder = hyper_util::server::conn::auto::Builder::new(executor);
    if let Err(e) = builder
        .serve_connection_with_upgrades(TokioIo::new(stream), service)
        .await
    {
        error!("TLS connection error: {}", e);
    }

    Ok(())
}

async fn tunnel(upgraded: Upgraded, host: &str, port: u16) -> std::io::Result<()> {
    trace!("tunnel: connecting to {}:{}", host, port);
    let mut server = tokio::net::TcpStream::connect((host, port)).await?;
    trace!("tunnel: connected to {}:{}", host, port);
    // Wrap both sides in TokioIo so they implement tokio::AsyncRead/Write
    let mut upgraded_io = TokioIo::new(upgraded);
    let (n1, n2) = tokio::io::copy_bidirectional(&mut upgraded_io, &mut server).await?;
    trace!("tunnel: copy finished: {} bytes -> {} bytes", n1, n2);
    Ok(())
}

#[cfg(test)]
async fn tunnel_with_io<S>(mut upgraded_io: S, host: &str, port: u16) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    trace!("tunnel (test helper): connecting to {}:{}", host, port);
    let mut server = tokio::net::TcpStream::connect((host, port)).await?;
    // Perform bidirectional copy between the upgraded side and the remote server
    let (n1, n2) = tokio::io::copy_bidirectional(&mut upgraded_io, &mut server).await?;
    trace!("tunnel: copy finished: {} bytes -> {} bytes", n1, n2);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::CertificateAuthority;
    use crate::proxy::http::{handle_inner_request, handle_request};
    use crate::proxy::test_support::make_shared_with_cfg;
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use hyper::Request;
    use rstest::rstest;
    use std::sync::Arc as StdArc;
    use tokio::fs;
    use uuid::Uuid;

    #[rstest]
    #[case(false, false, 405u16)]
    #[case(false, true, 200u16)]
    #[case(true, false, 405u16)]
    #[case(true, true, 405u16)]
    #[tokio::test]
    async fn connect_cases(
        #[case] use_inner: bool,
        #[case] ca_present: bool,
        #[case] expected_status: u16,
    ) -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        if ca_present {
            cfg.tls.enabled = true;
        }
        let cfg = StdArc::new(cfg);

        let ca_arc = if ca_present {
            let cert_path = std::env::temp_dir().join(format!("test_ca_{}.crt", Uuid::new_v4()));
            let key_path = std::env::temp_dir().join(format!("test_ca_{}.key", Uuid::new_v4()));
            let ca = CertificateAuthority::load_or_generate(&cert_path, &key_path).await?;
            Some(ca)
        } else {
            None
        };

        let (shared, tmp_path, _cw) = make_shared_with_cfg(cfg, ca_arc.clone()).await?;

        let req = Request::builder()
            .method("CONNECT")
            .uri("example.com:443")
            .body(Full::new(Bytes::new()).boxed())?;

        let conn_metadata = StdArc::new(crate::connection::ConnectionMetadata::new(
            "127.0.0.1:12345".parse()?,
        ));

        let resp = if use_inner {
            handle_inner_request(
                req,
                shared.clone(),
                conn_metadata,
                hyper::http::uri::Scheme::HTTP,
            )
            .await?
        } else {
            handle_request(
                req,
                shared.clone(),
                conn_metadata,
                hyper::http::uri::Scheme::HTTP,
            )
            .await?
        };

        assert_eq!(resp.status().as_u16(), expected_status);

        let _ = fs::remove_file(&tmp_path).await;
        Ok(())
    }

    #[tokio::test]
    async fn tunnel_copies_data_between_sides() -> anyhow::Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Start a simple TCP server that reads 'ping' and replies 'pong'
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let server_task = tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 4];
                if sock.read_exact(&mut buf).await.is_ok() {
                    assert_eq!(&buf, b"ping");
                    let _ = sock.write_all(b"pong").await;
                }
            }
        });

        // Create a duplex pair to simulate the upgraded client side
        let (mut client_side, server_side) = tokio::io::duplex(64);

        // Run the tunnel helper which will connect to the mock server and copy data
        let t = tokio::spawn(async move { tunnel_with_io(server_side, "127.0.0.1", port).await });

        // Write 'ping' from the client side and read 'pong' in response
        tokio::io::AsyncWriteExt::write_all(&mut client_side, b"ping").await?;
        let mut resp = [0u8; 4];
        tokio::io::AsyncReadExt::read_exact(&mut client_side, &mut resp).await?;
        assert_eq!(&resp, b"pong");

        // Close the client side to let tunnel finish
        drop(client_side);
        let res = t.await?;
        assert!(res.is_ok());

        let _ = server_task.await;
        Ok(())
    }

    #[tokio::test]
    async fn tunnel_fails_when_remote_not_listening() -> anyhow::Result<()> {
        use tokio::io::AsyncWriteExt;

        // pick a currently-unused port by binding and dropping
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        drop(listener);

        // Create a duplex pair to simulate the upgraded client side
        let (mut client_side, server_side) = tokio::io::duplex(64);

        // Run the tunnel helper which should fail to connect
        let t = tokio::spawn(async move { tunnel_with_io(server_side, "127.0.0.1", port).await });

        // Write some data; the tunnel should error when trying to connect
        let _ = client_side.write_all(b"ping").await;

        let res = t.await?;
        assert!(res.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn tunnel_completes_when_remote_closes_early() -> anyhow::Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::timeout;

        // Start a simple TCP server that reads a couple bytes then closes
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let server_task = tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                // read two bytes then close
                let mut buf = [0u8; 2];
                let _ = sock.read_exact(&mut buf).await;
                // drop socket to close prematurely
                drop(sock);
            }
        });

        let (mut client_side, server_side) = tokio::io::duplex(64);
        let t = tokio::spawn(async move { tunnel_with_io(server_side, "127.0.0.1", port).await });

        // send 4 bytes even though server only reads 2 and then closes
        client_side.write_all(b"ping").await?;

        // closing client side to let tunnel finish
        drop(client_side);
        // Ensure the tunnel finishes quickly instead of hanging indefinitely.
        let res = timeout(std::time::Duration::from_secs(2), t)
            .await
            .map_err(|_| anyhow::anyhow!("tunnel did not complete within timeout"))??;
        // The tunnel may succeed or return an IO error depending on timing; that's acceptable
        // as long as it didn't hang or panic (timeout/JoinError would have been returned above).
        let _ = res;
        let _ = server_task.await;
        Ok(())
    }
}
