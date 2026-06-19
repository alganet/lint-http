// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Integration test for request-side hop-by-hop header filtering: a forward
//! proxy must not relay RFC 7230 §6.1 hop-by-hop request headers (nor headers
//! the client names in `Connection:`) to the origin.

use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::sleep;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use lint_http::config::Config;

mod common;
use common::start_run_proxy_and_wait;

#[tokio::test]
async fn request_side_hop_by_hop_headers_are_stripped() -> anyhow::Result<()> {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/x"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&mock)
        .await;

    let mut cfg = Config::default();
    cfg.tls.enabled = false;
    let (handle, addr, cap_path) = start_run_proxy_and_wait(cfg).await?;

    // Drive a plaintext forward-proxy request carrying a static hop-by-hop
    // header (`Proxy-Authorization`), a dynamically-marked one (`X-Custom`, named
    // in `Connection:`), and a normal header (`X-Keep`) that must pass through.
    let mut client = TcpStream::connect(addr).await?;
    let req = format!(
        "GET http://127.0.0.1:{port}/x HTTP/1.1\r\n\
         Host: 127.0.0.1:{port}\r\n\
         Proxy-Authorization: secret\r\n\
         Connection: x-custom\r\n\
         X-Custom: drop-me\r\n\
         X-Keep: keep-me\r\n\
         \r\n",
        port = mock.address().port()
    );
    client.write_all(req.as_bytes()).await?;

    // The upstream records the forwarded request as soon as the proxy relays it;
    // poll until it arrives rather than parsing the proxy's response.
    let mut attempts = 0u32;
    let reqs = loop {
        attempts += 1;
        let r = mock.received_requests().await.unwrap_or_default();
        if !r.is_empty() || attempts > 40 {
            break r;
        }
        sleep(Duration::from_millis(50)).await;
    };
    assert_eq!(reqs.len(), 1, "upstream should have received the request");
    let got = &reqs[0];

    // The normal header is forwarded.
    assert!(
        got.headers.contains_key("x-keep"),
        "a non-hop-by-hop header should reach the origin"
    );
    // A static hop-by-hop request header is stripped.
    assert!(
        !got.headers.contains_key("proxy-authorization"),
        "Proxy-Authorization must not be relayed to the origin"
    );
    // A header named in the client's `Connection:` is stripped (dynamic case).
    assert!(
        !got.headers.contains_key("x-custom"),
        "a header listed in Connection: must be stripped"
    );

    handle.abort();
    let _ = tokio::fs::remove_file(&cap_path).await;
    Ok(())
}
