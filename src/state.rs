// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! State management for cross-transaction HTTP analysis.

use hyper::HeaderMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

/// Identifies a client by IP address and User-Agent string.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ClientIdentifier {
    pub ip: IpAddr,
    pub user_agent: String,
}

impl ClientIdentifier {
    pub fn new(ip: IpAddr, user_agent: String) -> Self {
        Self { ip, user_agent }
    }
}

/// Key for indexing state records by client and resource.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ResourceKey {
    client: ClientIdentifier,
    resource: String,
}

/// Record of a previous HTTP transaction.
#[derive(Debug, Clone)]
pub struct TransactionRecord {
    pub status: u16,
    pub timestamp: SystemTime,
    /// Subset of headers relevant for stateful analysis
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub cache_control: Option<String>,
}

impl TransactionRecord {
    fn from_headers(status: u16, headers: &HeaderMap) -> Self {
        let etag = headers
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        let last_modified = headers
            .get("last-modified")
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        let cache_control = headers
            .get("cache-control")
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        Self {
            status,
            timestamp: SystemTime::now(),
            etag,
            last_modified,
            cache_control,
        }
    }

    fn is_expired(&self, ttl: Duration) -> bool {
        self.timestamp
            .elapsed()
            .map(|elapsed| elapsed > ttl)
            .unwrap_or(true)
    }
}

#[derive(Debug, Clone)]
struct ClientStats {
    connection_count: u64,
    request_count: u64,
    last_seen: SystemTime,
}

impl Default for ClientStats {
    fn default() -> Self {
        Self {
            connection_count: 0,
            request_count: 0,
            last_seen: SystemTime::UNIX_EPOCH,
        }
    }
}

/// Thread-safe store for transaction state.
pub struct StateStore {
    store: Arc<RwLock<HashMap<ResourceKey, TransactionRecord>>>,
    stats: Arc<RwLock<HashMap<ClientIdentifier, ClientStats>>>,
    ttl: Duration,
}

impl StateStore {
    pub fn new(ttl_seconds: u64) -> Self {
        Self {
            store: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(HashMap::new())),
            ttl: Duration::from_secs(ttl_seconds),
        }
    }

    /// Record a transaction for future analysis.
    pub fn record_transaction(
        &self,
        client: &ClientIdentifier,
        resource: &str,
        status: u16,
        headers: &HeaderMap,
    ) {
        let key = ResourceKey {
            client: client.clone(),
            resource: resource.to_string(),
        };
        let record = TransactionRecord::from_headers(status, headers);

        if let Ok(mut store) = self.store.write() {
            store.insert(key, record);
        }

        if let Ok(mut stats) = self.stats.write() {
            let entry = stats.entry(client.clone()).or_default();
            entry.request_count += 1;
            entry.last_seen = SystemTime::now();
        }
    }

    /// Retrieve the previous transaction for this client+resource, if any.
    pub fn get_previous(
        &self,
        client: &ClientIdentifier,
        resource: &str,
    ) -> Option<TransactionRecord> {
        let key = ResourceKey {
            client: client.clone(),
            resource: resource.to_string(),
        };

        if let Ok(store) = self.store.read() {
            store.get(&key).cloned()
        } else {
            tracing::warn!("StateStore lock poisoned during read");
            None
        }
    }

    /// Remove expired entries from the store.
    pub fn cleanup_expired(&self) {
        if let Ok(mut store) = self.store.write() {
            store.retain(|_, record| !record.is_expired(self.ttl));
        }
    }

    /// Record a new connection establishment.
    pub fn record_connection(
        &self,
        client: &ClientIdentifier,
        _conn_metadata: &crate::connection::ConnectionMetadata,
    ) {
        if let Ok(mut stats) = self.stats.write() {
            let entry = stats.entry(client.clone()).or_default();
            entry.connection_count += 1;
            entry.last_seen = SystemTime::now();
        }
    }

    /// Get connection efficiency stats (requests per connection).
    pub fn get_connection_efficiency(&self, client: &ClientIdentifier) -> Option<f64> {
        if let Ok(stats) = self.stats.read() {
            stats.get(client).map(|s| {
                if s.connection_count == 0 {
                    0.0
                } else {
                    s.request_count as f64 / s.connection_count as f64
                }
            })
        } else {
            tracing::warn!("StateStore stats lock poisoned during read");
            None
        }
    }

    /// Get total connection count for a client.
    pub fn get_connection_count(&self, client: &ClientIdentifier) -> u64 {
        if let Ok(stats) = self.stats.read() {
            stats.get(client).map(|s| s.connection_count).unwrap_or(0)
        } else {
            0
        }
    }

    /// Seed the StateStore from a transaction record.
    ///
    /// This method populates the state with transaction data from previously captured
    /// HTTP exchanges. It enables:
    /// - Continuing analysis from previous proxy sessions
    /// - Setting up elaborate testing scenarios with mocked previous states
    ///
    /// The client is identified from the request headers (user-agent). Since we don't
    /// have the actual client IP from the capture, we use a localhost IP as a placeholder.
    /// Transactions without response headers are skipped.
    pub fn seed_from_transaction(&self, tx: &crate::http_transaction::HttpTransaction) {
        // Extract user agent from request headers, default to "unknown"
        let user_agent = tx
            .request
            .headers
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
            .unwrap_or_else(|| "unknown".to_string());

        // Use localhost IP as placeholder since we don't capture client IPs
        let client_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1));
        let client = ClientIdentifier::new(client_ip, user_agent);

        // Only seed if we have response headers (complete transaction)
        if let Some(ref resp) = tx.response {
            // Record the transaction using the response header map directly
            self.record_transaction(&client, &tx.request.uri, resp.status, &resp.headers);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::thread;
    use std::time::Duration;

    fn make_client() -> ClientIdentifier {
        ClientIdentifier::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            "test-agent/1.0".to_string(),
        )
    }

    #[test]
    fn record_and_retrieve_transaction() -> anyhow::Result<()> {
        let store = StateStore::new(300);
        let client = make_client();
        let resource = "http://example.com/resource";

        let mut headers = HeaderMap::new();
        headers.insert("etag", "\"abc123\"".parse()?);
        headers.insert("cache-control", "max-age=3600".parse()?);

        store.record_transaction(&client, resource, 200, &headers);

        let record = store.get_previous(&client, resource);
        assert!(record.is_some());
        let record = record.ok_or_else(|| anyhow::anyhow!("expected record to exist"))?;
        assert_eq!(record.status, 200);
        assert_eq!(record.etag, Some("\"abc123\"".to_string()));
        assert_eq!(record.cache_control, Some("max-age=3600".to_string()));
        assert_eq!(record.last_modified, None);
        Ok(())
    }

    #[test]
    fn different_clients_have_separate_state() -> anyhow::Result<()> {
        let store = StateStore::new(300);
        let client1 = ClientIdentifier::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            "client-1".to_string(),
        );
        let client2 = ClientIdentifier::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            "client-2".to_string(),
        );
        let resource = "http://example.com/resource";

        let mut headers1 = HeaderMap::new();
        headers1.insert("etag", "\"etag1\"".parse()?);
        store.record_transaction(&client1, resource, 200, &headers1);

        let mut headers2 = HeaderMap::new();
        headers2.insert("etag", "\"etag2\"".parse()?);
        store.record_transaction(&client2, resource, 200, &headers2);

        let record1 = store
            .get_previous(&client1, resource)
            .ok_or_else(|| anyhow::anyhow!("expected record1 to exist"))?;
        let record2 = store
            .get_previous(&client2, resource)
            .ok_or_else(|| anyhow::anyhow!("expected record2 to exist"))?;

        assert_eq!(record1.etag, Some("\"etag1\"".to_string()));
        assert_eq!(record2.etag, Some("\"etag2\"".to_string()));
        Ok(())
    }

    #[test]
    fn cleanup_removes_expired_entries() {
        let store = StateStore::new(1); // 1 second TTL
        let client = make_client();
        let resource = "http://example.com/resource";

        let headers = HeaderMap::new();
        store.record_transaction(&client, resource, 200, &headers);

        // Verify it exists
        assert!(store.get_previous(&client, resource).is_some());

        // Wait for expiration
        thread::sleep(Duration::from_secs(2));

        // Cleanup
        store.cleanup_expired();

        // Should be gone
        assert!(store.get_previous(&client, resource).is_none());
    }

    #[test]
    fn concurrent_access_is_safe() -> anyhow::Result<()> {
        let store = Arc::new(StateStore::new(300));
        let client = make_client();
        let resource = "http://example.com/resource";

        let store1 = store.clone();
        let client1 = client.clone();
        let resource1 = resource.to_string();
        let handle1 = thread::spawn(move || {
            for i in 0..100 {
                let headers = HeaderMap::new();
                store1.record_transaction(&client1, &resource1, 200 + i, &headers);
            }
        });

        let store2 = store.clone();
        let client2 = client.clone();
        let resource2 = resource.to_string();
        let handle2 = thread::spawn(move || {
            for _ in 0..100 {
                let _ = store2.get_previous(&client2, &resource2);
            }
        });

        if let Err(e) = handle1.join() {
            panic!("thread1 panicked: {:?}", e);
        }
        if let Err(e) = handle2.join() {
            panic!("thread2 panicked: {:?}", e);
        }

        // Should complete without panicking
        let record = store.get_previous(&client, resource);
        assert!(record.is_some());
        Ok(())
    }

    #[test]
    fn track_connection_efficiency() -> anyhow::Result<()> {
        let store = StateStore::new(300);
        let client = make_client();
        let conn = crate::connection::ConnectionMetadata::new("127.0.0.1:12345".parse()?);

        // Initial state
        assert_eq!(store.get_connection_count(&client), 0);
        assert!(store.get_connection_efficiency(&client).is_none());

        // Record connection
        store.record_connection(&client, &conn);
        assert_eq!(store.get_connection_count(&client), 1);

        // 0 requests, 1 connection -> efficiency 0.0
        assert_eq!(store.get_connection_efficiency(&client), Some(0.0));

        // Record request
        let headers = HeaderMap::new();
        store.record_transaction(&client, "http://example.com", 200, &headers);

        // 1 request, 1 connection -> efficiency 1.0
        assert_eq!(store.get_connection_efficiency(&client), Some(1.0));

        // Record another request
        store.record_transaction(&client, "http://example.com", 200, &headers);

        // 2 requests, 1 connection -> efficiency 2.0
        assert_eq!(store.get_connection_efficiency(&client), Some(2.0));

        // Record another connection
        store.record_connection(&client, &conn);

        // 2 requests, 2 connections -> efficiency 1.0
        assert_eq!(store.get_connection_efficiency(&client), Some(1.0));
        Ok(())
    }

    #[test]
    fn seed_from_transaction_populates_state() -> anyhow::Result<()> {
        let store = StateStore::new(300);

        // Create a transaction with response headers
        let mut resp_headers = std::collections::HashMap::new();
        resp_headers.insert("etag".to_string(), "\"12345\"".to_string());
        resp_headers.insert("cache-control".to_string(), "max-age=3600".to_string());

        use crate::test_helpers::make_test_transaction_with_response;
        let mut tx = make_test_transaction_with_response(
            200,
            &[("etag", "\"12345\""), ("cache-control", "max-age=3600")],
        );
        tx.request
            .headers
            .insert("user-agent", "test-client/1.0".parse()?);
        // Ensure the resource matches the expected URL
        tx.request.uri = "http://example.com/resource".to_string();
        tx.timing.duration_ms = 100;

        // Seed the state
        store.seed_from_transaction(&tx);

        // Verify the transaction was recorded
        let client = ClientIdentifier::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            "test-client/1.0".to_string(),
        );

        let prev = store
            .get_previous(&client, "http://example.com/resource")
            .ok_or_else(|| anyhow::anyhow!("State should contain seeded transaction"))?;
        assert_eq!(prev.status, 200);
        assert_eq!(prev.etag, Some("\"12345\"".to_string()));
        assert_eq!(prev.cache_control, Some("max-age=3600".to_string()));
        Ok(())
    }

    #[test]
    fn seed_from_transaction_without_response_headers_does_nothing() {
        let store = StateStore::new(300);

        use crate::test_helpers::make_test_transaction;
        let tx = make_test_transaction();

        // Seed the state (should do nothing since no response headers)
        store.seed_from_transaction(&tx);

        // Verify nothing was recorded
        let client = ClientIdentifier::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            "unknown".to_string(),
        );

        let prev = store.get_previous(&client, "http://example.com/resource");
        assert!(prev.is_none());
    }
}
