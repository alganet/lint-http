// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! The proxy's outbound shapes, built once and shared.
//!
//! Both the forwarding client (H1/H2, and H3-forwarded requests) and the
//! WebSocket-upgrade connection need the system trust store. Building it here
//! once — a single native-roots `ClientConfig` that the main client adds ALPN
//! to and the WS path uses bare — means the trust store loads exactly once at
//! startup instead of per WebSocket upgrade. Future outbound features (an H3
//! upstream, connection pooling, mTLS) get a single seam to extend.

use std::sync::Arc;

use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client as LegacyClient;
use hyper_util::rt::TokioExecutor;
use tracing::warn;

use super::ClientBody;

/// Outbound connection resources, constructed once from a single trust-store
/// load and shared across every outbound path.
///
/// `pub(crate)` to match the visibility of the `Shared::upstream` field that
/// holds it; the fields below stay `pub(super)` (used only within the proxy).
pub(crate) struct Upstream {
    /// Forwarding client for H1/H2 (and H3-forwarded) requests.
    pub(super) client: LegacyClient<hyper_rustls::HttpsConnector<HttpConnector>, ClientBody>,
    /// Base TLS config: native roots, no client auth, **no ALPN**. The forwarding
    /// client adds ALPN on top; the WebSocket upgrade path uses it bare. Shared
    /// so the trust store is loaded a single time.
    pub(super) tls_config: Arc<rustls::ClientConfig>,
}

impl Upstream {
    /// Load the platform trust store once and build both outbound shapes from it.
    pub(super) fn new() -> anyhow::Result<Self> {
        let loaded = rustls_native_certs::load_native_certs();
        if !loaded.errors.is_empty() {
            warn!(errors = ?loaded.errors, "errors loading platform certificates");
        }
        let mut roots = rustls::RootCertStore::empty();
        for cert in loaded.certs {
            roots.add(cert).ok();
        }
        if roots.is_empty() {
            anyhow::bail!("no native root certificates could be loaded");
        }

        // Base config carries no ALPN: `with_tls_config` asserts that, and the
        // WebSocket path needs it bare. The forwarding client adds h1/h2 below.
        let base = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let tls_config = Arc::new(base.clone());

        let https = HttpsConnectorBuilder::new()
            .with_tls_config(base)
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();
        let client = LegacyClient::builder(TokioExecutor::new()).build(https);

        Ok(Self { client, tls_config })
    }
}
