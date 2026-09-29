// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Test utilities for the proxy crate.
//!
//! Re-exports the core fixtures (built on core types). The proxy's tests only
//! need transaction/config fixtures, not the rule-layer ones.

pub use lint_http_core::test_helpers::*;

/// Proxy-shaped counterpart of `make_test_config_with_enabled_rules`: the
/// same rule table under default transport sections, for fixtures that feed
/// `Shared`/`run_proxy` rather than the rule layer directly.
pub fn make_proxy_config_with_enabled_rules(rules: &[&str]) -> crate::config::Config {
    crate::config::Config {
        lint: lint_http_core::test_helpers::make_test_config_with_enabled_rules(rules),
        ..Default::default()
    }
}

/// A loopback port that refuses connections for as long as the returned socket
/// is held.
///
/// The idiom this replaces bound a listener to port 0, read the port and
/// dropped the listener, so the port was free the moment the test asked it to
/// be refused -- and free for any test running beside it to bind. When one
/// did, the connection the test expected to fail went through and the test
/// failed on a machine doing nothing wrong. A socket that is bound and never
/// listens holds the port against every other bind and answers a connection
/// with a reset, which is the refusal the test is about.
pub fn refusing_port() -> std::io::Result<(tokio::net::TcpSocket, u16)> {
    let socket = tokio::net::TcpSocket::new_v4()?;
    socket.bind(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))?;
    let port = socket.local_addr()?.port();
    Ok((socket, port))
}
