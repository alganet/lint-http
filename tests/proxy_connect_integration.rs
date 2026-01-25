// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::time::{sleep, timeout};
use tokio_rustls::TlsConnector;
use wiremock::{Mock, MockServer, ResponseTemplate};

use lint_http::capture::CaptureWriter;
use lint_http::config::Config;
use lint_http::proxy::run_proxy;
use lint_http::rules::RuleConfigEngine;

// Helper: start run_proxy in background and wait until it is accepting and CA files exist
async fn start_run_proxy_and_wait(
    cfg: Config,
    engine: Arc<RuleConfigEngine>,
) -> anyhow::Result<(tokio::task::JoinHandle<()>, SocketAddr, String)> {
    // prepare capture file
    let tmp = std::env::temp_dir().join(format!("lint_integ_{}.jsonl", uuid::Uuid::new_v4()));
    let p = tmp
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("tmp path not utf8"))?
        .to_string();
    let cw = CaptureWriter::new(p.clone()).await?;

    // Choose a free port by binding then dropping
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    drop(listener);

    let cfg_arc = Arc::new(cfg.clone());
    let cfg_for_spawn = cfg_arc.clone();
    let engine2 = engine.clone();
    let handle = tokio::spawn(async move {
        let _ = run_proxy(addr, cw, cfg_for_spawn, engine2).await;
    });

    // Wait for server to accept connections (try connecting) and CA files exist if enabled
    let deadline = Instant::now() + Duration::from_secs(5);
    use tokio::io::AsyncWriteExt;

    loop {
        if Instant::now() > deadline {
            return Err(anyhow::anyhow!("timeout waiting for proxy to start"));
        }
        // try connect
        if let Ok(mut s) = tokio::net::TcpStream::connect(addr).await {
            // connected -> close and proceed
            let _ = s.shutdown().await;
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }

    // If TLS enabled, wait for CA files
    if cfg.tls.enabled {
        let cert_path = cfg
            .tls
            .ca_cert_path
            .clone()
            .unwrap_or_else(|| "ca.crt".into());
        let key_path = cfg
            .tls
            .ca_key_path
            .clone()
            .unwrap_or_else(|| "ca.key".into());
        let cert_path = std::path::PathBuf::from(cert_path);
        let key_path = std::path::PathBuf::from(key_path);
        let deadline2 = Instant::now() + Duration::from_secs(5);
        loop {
            if cert_path.exists() && key_path.exists() {
                break;
            }
            if Instant::now() > deadline2 {
                return Err(anyhow::anyhow!("timeout waiting for CA files"));
            }
            sleep(Duration::from_millis(50)).await;
        }
    }

    Ok((handle, addr, p))
}

// Helper: perform CONNECT and a TLS handshake and send an inner request, returning response bytes
async fn perform_connect_and_tls(
    proxy_addr: SocketAddr,
    connect_host: &str,
    connect_port: u16,
    ca_cert_path: &std::path::Path,
    inner_request: &str,
) -> anyhow::Result<Vec<u8>> {
    use rustls::client::ClientConfig;
    use rustls::pki_types::ServerName;
    use rustls::RootCertStore;
    use rustls_pemfile;
    use std::fs::File;
    use std::io::BufReader;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Connect TCP
    let mut stream = tokio::net::TcpStream::connect(proxy_addr).await?;

    // Send CONNECT
    let connect = format!(
        "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n",
        host = connect_host,
        port = connect_port
    );
    stream.write_all(connect.as_bytes()).await?;

    // Read response headers until \r\n\r\n
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if Instant::now() > deadline {
            return Err(anyhow::anyhow!("timeout reading CONNECT response"));
        }
        let n = match timeout(Duration::from_millis(500), stream.read(&mut tmp)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                continue;
            }
        };
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let hdrs = String::from_utf8_lossy(&buf);
    if !hdrs.starts_with("HTTP/1.1 200") && !hdrs.starts_with("HTTP/1.1 2") {
        return Err(anyhow::anyhow!("CONNECT not successful: {}", hdrs));
    }

    // Setup TLS client config trusting ca_cert_path
    let mut root_store = RootCertStore::empty();
    let mut f = BufReader::new(File::open(ca_cert_path)?);
    let certs: Vec<_> = rustls_pemfile::certs(&mut f).collect::<Result<Vec<_>, _>>()?;
    // Pass the parsed certificate DER buffers directly to RootCertStore
    root_store.add_parsable_certificates(certs);
    let client_cfg = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = TlsConnector::from(std::sync::Arc::new(client_cfg));
    let server_name = ServerName::try_from(connect_host.to_string())
        .map_err(|_| anyhow::anyhow!("invalid server name"))?;

    let mut tls = connector.connect(server_name, stream).await?;

    // Send inner request and read response
    tls.write_all(inner_request.as_bytes()).await?;

    // Read until we have some body or timeout
    let mut resp = Vec::new();
    let deadline2 = Instant::now() + Duration::from_secs(3);
    loop {
        if Instant::now() > deadline2 {
            break;
        }
        let mut tmp2 = [0u8; 1024];
        match timeout(Duration::from_millis(500), tls.read(&mut tmp2)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                resp.extend_from_slice(&tmp2[..n]);
                // quick heuristic: stop if we see mock body 'ok'
                if resp.windows(2).any(|w| w == b"ok") {
                    break;
                }
            }
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => continue,
        }
    }

    Ok(resp)
}

#[tokio::test]
async fn connect_tls_full_forwarding() -> anyhow::Result<()> {
    // 1) Start upstream mock
    let mock = MockServer::start().await;
    Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&mock)
        .await;

    // 2) Build config with TLS enabled and temp CA paths
    let mut cfg = Config::default();
    cfg.tls.enabled = true;
    let cert_path = std::env::temp_dir().join(format!("test_ca_{}.crt", uuid::Uuid::new_v4()));
    let key_path = std::env::temp_dir().join(format!("test_ca_{}.key", uuid::Uuid::new_v4()));
    cfg.tls.ca_cert_path = Some(cert_path.to_string_lossy().to_string());
    cfg.tls.ca_key_path = Some(key_path.to_string_lossy().to_string());

    // 3) Start proxy and wait
    let engine = Arc::new(RuleConfigEngine::new());
    let (handle, addr, cap_path) = start_run_proxy_and_wait(cfg.clone(), engine.clone()).await?;

    // 4) Perform CONNECT + TLS + inner request
    let host = "example.com";
    let inner = format!(
        "GET http://127.0.0.1:{}/ HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
        mock.address().port(),
        mock.address().port()
    );

    let resp_bytes =
        perform_connect_and_tls(addr, host, mock.address().port(), &cert_path, &inner).await?;
    let resp_str = String::from_utf8_lossy(&resp_bytes);
    assert!(resp_str.contains("200"));

    // 5) Verify upstream mock saw request
    let mut attempts = 0u32;
    let reqs = loop {
        attempts += 1;
        let r = mock.received_requests().await.expect("received requests");
        if !r.is_empty() || attempts > 10 {
            break r;
        }
        sleep(Duration::from_millis(50)).await;
    };
    assert!(!reqs.is_empty());
    assert_eq!(reqs[0].method.as_str(), "GET");
    assert_eq!(reqs[0].url.path(), "/");

    // 6) Cleanup
    handle.abort();
    let _ = handle.await;

    // remove temp files
    let _ = tokio::fs::remove_file(cert_path).await;
    let _ = tokio::fs::remove_file(key_path).await;
    let _ = tokio::fs::remove_file(&cap_path).await;

    Ok(())
}
