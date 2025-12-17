// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! State management for cross-transaction HTTP analysis.

use chrono::Utc;
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
    store: Arc<RwLock<HashMap<ResourceKey, crate::http_transaction::HttpTransaction>>>,
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
    pub fn record_transaction(&self, tx: &crate::http_transaction::HttpTransaction) {
        let key = ResourceKey {
            client: tx.client.clone(),
            resource: tx.request.uri.clone(),
        };

        if let Ok(mut store) = self.store.write() {
            store.insert(key, tx.clone());
        }

        if let Ok(mut stats) = self.stats.write() {
            let entry = stats.entry(tx.client.clone()).or_default();
            entry.request_count += 1;
            entry.last_seen = SystemTime::now();
        }
    }

    /// Retrieve the previous transaction for this client+resource, if any.
    pub fn get_previous(
        &self,
        client: &ClientIdentifier,
        resource: &str,
    ) -> Option<crate::http_transaction::HttpTransaction> {
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
            let ttl_chrono = chrono::Duration::from_std(self.ttl)
                .unwrap_or_else(|_| chrono::Duration::seconds(0));
            store.retain(|_, tx| {
                let age = Utc::now().signed_duration_since(tx.timestamp);
                // If timestamp is in the future (age < 0), treat as expired (remove)
                if age < chrono::Duration::zero() {
                    return false;
                }
                age <= ttl_chrono
            });
        }
    }

    /// Record a new connection establishment.
    pub fn record_connection(&self, client: &ClientIdentifier) {
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
        if tx.response.is_some() {
            let mut seeded = tx.clone();
            seeded.client = client;
            // Preserve captured timestamp and other fields
            self.record_transaction(&seeded);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::HeaderMap;
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

        use crate::test_helpers::make_test_transaction_with_response;
        let mut tx = make_test_transaction_with_response(
            200,
            &[("etag", "\"abc123\""), ("cache-control", "max-age=3600")],
        );
        tx.client = client.clone();
        tx.request.uri = resource.to_string();

        store.record_transaction(&tx);

        let prev = store.get_previous(&client, resource);
        assert!(prev.is_some());
        let prev = prev.ok_or_else(|| anyhow::anyhow!("expected record to exist"))?;
        let resp = prev
            .response
            .ok_or_else(|| anyhow::anyhow!("expected response"))?;
        assert_eq!(resp.status, 200);
        assert_eq!(
            resp.headers.get("etag").and_then(|v| v.to_str().ok()),
            Some("\"abc123\"")
        );
        assert_eq!(
            resp.headers
                .get("cache-control")
                .and_then(|v| v.to_str().ok()),
            Some("max-age=3600")
        );
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

        use crate::test_helpers::make_test_transaction_with_response;
        let mut tx1 = make_test_transaction_with_response(200, &[("etag", "\"etag1\"")]);
        tx1.client = client1.clone();
        tx1.request.uri = resource.to_string();
        store.record_transaction(&tx1);

        let mut tx2 = make_test_transaction_with_response(200, &[("etag", "\"etag2\"")]);
        tx2.client = client2.clone();
        tx2.request.uri = resource.to_string();
        store.record_transaction(&tx2);

        let record1 = store
            .get_previous(&client1, resource)
            .ok_or_else(|| anyhow::anyhow!("expected record1 to exist"))?;
        let record2 = store
            .get_previous(&client2, resource)
            .ok_or_else(|| anyhow::anyhow!("expected record2 to exist"))?;

        assert_eq!(
            record1
                .response
                .as_ref()
                .and_then(|r| r.headers.get("etag"))
                .and_then(|v| v.to_str().ok()),
            Some("\"etag1\"")
        );
        assert_eq!(
            record2
                .response
                .as_ref()
                .and_then(|r| r.headers.get("etag"))
                .and_then(|v| v.to_str().ok()),
            Some("\"etag2\"")
        );
        Ok(())
    }

    #[test]
    fn cleanup_removes_expired_entries() {
        let store = StateStore::new(1); // 1 second TTL
        let client = make_client();
        let resource = "http://example.com/resource";

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.client = client.clone();
        tx.request.uri = resource.to_string();
        store.record_transaction(&tx);

        // Verify it exists
        assert!(store.get_previous(&client, resource).is_some());

        // Wait for expiration
        thread::sleep(Duration::from_secs(2));

        // Cleanup
        store.cleanup_expired();

        // Should be gone
        assert!(store.get_previous(&client, resource).is_none());
    }

    use rstest::rstest;

    #[rstest]
    #[case(60, -30, true)]
    #[case(60, -120, false)]
    #[case(60, 60, false)]
    fn cleanup_expiry_cases(
        #[case] ttl_secs: u64,
        #[case] offset_secs: i64,
        #[case] expect_present: bool,
    ) {
        let store = StateStore::new(ttl_secs);
        let client = make_client();
        let resource = format!("http://example.com/cleanup/{}", offset_secs);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.client = client.clone();
        tx.request.uri = resource.clone();
        tx.timestamp = Utc::now() + chrono::Duration::seconds(offset_secs);
        store.record_transaction(&tx);

        store.cleanup_expired();

        if expect_present {
            assert!(store.get_previous(&client, &resource).is_some());
        } else {
            assert!(store.get_previous(&client, &resource).is_none());
        }
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
                let mut tx = crate::test_helpers::make_test_transaction();
                tx.client = client1.clone();
                tx.request.uri = resource1.clone();
                tx.response = Some(crate::http_transaction::ResponseInfo {
                    status: 200 + i,
                    headers: HeaderMap::new(),
                });
                store1.record_transaction(&tx);
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

        // Initial state
        assert_eq!(store.get_connection_count(&client), 0);
        assert!(store.get_connection_efficiency(&client).is_none());

        // Record connection
        store.record_connection(&client);
        assert_eq!(store.get_connection_count(&client), 1);

        // 0 requests, 1 connection -> efficiency 0.0
        assert_eq!(store.get_connection_efficiency(&client), Some(0.0));

        // Record request
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.client = client.clone();
        tx.request.uri = "http://example.com".to_string();
        store.record_transaction(&tx);

        // 1 request, 1 connection -> efficiency 1.0
        assert_eq!(store.get_connection_efficiency(&client), Some(1.0));

        // Record another request
        let mut tx2 = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx2.client = client.clone();
        tx2.request.uri = "http://example.com".to_string();
        store.record_transaction(&tx2);

        // 2 requests, 1 connection -> efficiency 2.0
        assert_eq!(store.get_connection_efficiency(&client), Some(2.0));

        // Record another connection
        store.record_connection(&client);

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

        let prev_tx = store
            .get_previous(&client, "http://example.com/resource")
            .ok_or_else(|| anyhow::anyhow!("State should contain seeded transaction"))?;
        let resp = prev_tx
            .response
            .ok_or_else(|| anyhow::anyhow!("expected response"))?;
        assert_eq!(resp.status, 200);
        assert_eq!(
            resp.headers.get("etag").and_then(|v| v.to_str().ok()),
            Some("\"12345\"")
        );
        assert_eq!(
            resp.headers
                .get("cache-control")
                .and_then(|v| v.to_str().ok()),
            Some("max-age=3600")
        );
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
