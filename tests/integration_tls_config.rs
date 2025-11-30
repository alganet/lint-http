use hyper::{Uri};
use std::sync::Arc;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;
use wiremock::{Mock, MockServer, ResponseTemplate};
use wiremock::matchers::{method, path};

#[tokio::test]
async fn test_suppress_headers() {
    let mock = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&mock)
        .await;

    let tmp_capture = std::env::temp_dir().join(format!("lint_test_suppress_{}.jsonl", Uuid::new_v4()));
    let cw = lint_http::capture::CaptureWriter::new(tmp_capture.to_str().unwrap().to_string())
        .await
        .expect("create writer");

    let mut cfg = lint_http::config::Config::default();
    cfg.tls.suppress_headers = vec!["x-secret".to_string()];
    let cfg = Arc::new(cfg);

    let addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener = std::net::TcpListener::bind(addr).unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    drop(listener); // Release port so proxy can bind to it

    let cw_clone = cw.clone();
    let cfg_clone = cfg.clone();
    tokio::spawn(async move {
        lint_http::proxy::run_proxy(proxy_addr, cw_clone, cfg_clone).await.unwrap();
    });

    // Wait for proxy to start
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Send request via proxy using raw TCP
    let mut stream = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
    let target_uri = mock.uri();
    // Parse target uri to get host header
    let uri_obj: Uri = target_uri.parse().unwrap();
    let host = uri_obj.host().unwrap();
    let port = uri_obj.port_u16().unwrap();

    let req_str = format!(
        "GET {} HTTP/1.1\r\nHost: {}:{}\r\nx-secret: super-secret-value\r\nx-public: public-value\r\n\r\n",
        target_uri, host, port
    );
    stream.write_all(req_str.as_bytes()).await.unwrap();

    let mut buf = [0; 4096];
    let n = stream.read(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf[0..n]);
    
    assert!(response.contains("200 OK"));

    // Now verify the capture to see if the header was suppressed in the upstream request?
    // We can't easily check upstream request from here without the mock telling us.
    // BUT, we can check the capture file. 
    // Wait, the capture records the INCOMING request headers.
    // So the capture WILL contain "x-secret".
    
    // To verify it was suppressed upstream, we need to check what the mock received.
    // Wiremock's `ScopedMock` or `MockServer::received_requests` would be useful.
    // `wiremock` 0.5+ has `received_requests()`.
    
    let requests = mock.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    let received_req = &requests[0];
    
    // Check headers
    assert!(received_req.headers.get("x-public").is_some());
    assert!(received_req.headers.get("x-secret").is_none());

    let _ = fs::remove_file(&tmp_capture).await;
}

#[tokio::test]
async fn test_passthrough_domains() {
    // Start a dummy TCP server to represent the target
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = listener.local_addr().unwrap();
    let target_port = target_addr.port();

    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = [0; 1024];
        let n = socket.read(&mut buf).await.unwrap();
        socket.write_all(&buf[0..n]).await.unwrap(); // Echo server
    });

    let tmp_capture = std::env::temp_dir().join(format!("lint_test_pass_{}.jsonl", Uuid::new_v4()));
    let cw = lint_http::capture::CaptureWriter::new(tmp_capture.to_str().unwrap().to_string())
        .await
        .expect("create writer");

    let mut cfg = lint_http::config::Config::default();
    cfg.tls.enabled = true;
    cfg.tls.passthrough_domains = vec!["localhost".to_string()]; // We will use localhost
    let cfg = Arc::new(cfg);

    let addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let proxy_listener = std::net::TcpListener::bind(addr).unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    drop(proxy_listener); // Release port so proxy can bind to it

    let cw_clone = cw.clone();
    let cfg_clone = cfg.clone();
    tokio::spawn(async move {
        lint_http::proxy::run_proxy(proxy_addr, cw_clone, cfg_clone).await.unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Connect via proxy
    let mut stream = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
    
    let connect_req = format!("CONNECT localhost:{} HTTP/1.1\r\nHost: localhost:{}\r\n\r\n", target_port, target_port);
    stream.write_all(connect_req.as_bytes()).await.unwrap();
    
    let mut buf = [0; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf[0..n]);
    assert!(response.contains("200 OK")); // Proxy established tunnel

    // Now send data. If it was MITM'd, the proxy would expect TLS ClientHello.
    // But since it's passthrough, it should just forward our raw bytes.
    // Our target is an echo server (no TLS).
    // So if we send "hello", we should get "hello".
    // If the proxy tried to do TLS handshake, it would fail or send TLS bytes.

    stream.write_all(b"hello").await.unwrap();
    let n = stream.read(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf[0..n]);
    assert_eq!(response, "hello");

    let _ = fs::remove_file(&tmp_capture).await;
}
