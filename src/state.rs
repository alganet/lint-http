// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! State management for cross-transaction HTTP analysis.

use hyper::HeaderMap;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

/// Identifies a client by IP address and User-Agent string.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
        _metadata: &crate::connection::ConnectionMetadata,
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
    fn record_and_retrieve_transaction() {
        let store = StateStore::new(300);
        let client = make_client();
        let resource = "http://example.com/resource";

        let mut headers = HeaderMap::new();
        headers.insert("etag", "\"abc123\"".parse().unwrap());
        headers.insert("cache-control", "max-age=3600".parse().unwrap());

        store.record_transaction(&client, resource, 200, &headers);

        let record = store.get_previous(&client, resource);
        assert!(record.is_some());
        let record = record.unwrap();
        assert_eq!(record.status, 200);
        assert_eq!(record.etag, Some("\"abc123\"".to_string()));
        assert_eq!(record.cache_control, Some("max-age=3600".to_string()));
        assert_eq!(record.last_modified, None);
    }

    #[test]
    fn different_clients_have_separate_state() {
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
        headers1.insert("etag", "\"etag1\"".parse().unwrap());
        store.record_transaction(&client1, resource, 200, &headers1);

        let mut headers2 = HeaderMap::new();
        headers2.insert("etag", "\"etag2\"".parse().unwrap());
        store.record_transaction(&client2, resource, 200, &headers2);

        let record1 = store.get_previous(&client1, resource).unwrap();
        let record2 = store.get_previous(&client2, resource).unwrap();

        assert_eq!(record1.etag, Some("\"etag1\"".to_string()));
        assert_eq!(record2.etag, Some("\"etag2\"".to_string()));
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
    fn concurrent_access_is_safe() {
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

        handle1.join().unwrap();
        handle2.join().unwrap();

        // Should complete without panicking
        let record = store.get_previous(&client, resource);
        assert!(record.is_some());
    }

    #[test]
    fn track_connection_efficiency() {
        let store = StateStore::new(300);
        let client = make_client();
        let conn = crate::connection::ConnectionMetadata::new("127.0.0.1:12345".parse().unwrap());

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
    }
}
