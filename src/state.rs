// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! State management for cross-transaction HTTP analysis.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use uuid::Uuid;

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

/// Thread-safe store for transaction state with bounded history.
///
/// Each `(client, resource)` key maps to a bounded ring-buffer of recent
/// transactions (newest first).  The `queries` module reads from this store;
/// lint rules never access it directly.
pub struct StateStore {
    store: Arc<RwLock<HashMap<ResourceKey, VecDeque<crate::http_transaction::HttpTransaction>>>>,
    /// Index mapping resource string to list of clients that have entries for
    /// that resource.  Used to efficiently support cross-client history
    /// queries without scanning every key in `store`.
    resource_index: Arc<RwLock<HashMap<String, Vec<ClientIdentifier>>>>,
    /// Index mapping connection UUID to the resource keys whose entries belong
    /// to that connection.  Used by `get_history_for_connection`.
    connection_index: Arc<RwLock<HashMap<Uuid, Vec<ResourceKey>>>>,
    ttl: Duration,
    max_history: usize,
}

impl StateStore {
    pub fn new(ttl_seconds: u64, max_history: usize) -> Self {
        Self {
            store: Arc::new(RwLock::new(HashMap::new())),
            resource_index: Arc::new(RwLock::new(HashMap::new())),
            connection_index: Arc::new(RwLock::new(HashMap::new())),
            ttl: Duration::from_secs(ttl_seconds),
            max_history,
        }
    }

    /// Record a transaction for future analysis.
    ///
    /// Pushes to the front of the deque (newest first) and evicts the oldest
    /// entry when the bounded capacity is reached.
    pub fn record_transaction(&self, tx: &crate::http_transaction::HttpTransaction) {
        let key = ResourceKey {
            client: tx.client.clone(),
            resource: tx.request.uri.clone(),
        };

        // Update the main store first, then release its lock before updating
        // secondary indexes.  This avoids nested lock acquisition which could
        // deadlock with readers that access indexes then the store.
        let is_new = match self.store.write() {
            Ok(mut store) => {
                let was_new = store.get(&key).is_none();
                let deque = store.entry(key.clone()).or_insert_with(VecDeque::new);
                deque.push_front(tx.clone());
                if deque.len() > self.max_history {
                    deque.pop_back();
                }
                was_new
            }
            Err(_) => {
                tracing::warn!("StateStore lock poisoned during write");
                return;
            }
        };

        if is_new {
            if let Ok(mut idx) = self.resource_index.write() {
                let clients = idx.entry(key.resource.clone()).or_insert_with(Vec::new);
                if !clients.iter().any(|c| c == &key.client) {
                    clients.push(key.client.clone());
                }
            }
        }

        if let Some(conn_id) = tx.connection_id {
            if let Ok(mut idx) = self.connection_index.write() {
                let keys = idx.entry(conn_id).or_insert_with(Vec::new);
                if !keys.contains(&key) {
                    keys.push(key);
                }
            }
        }
    }

    /// Retrieve the most recent transaction for this client+resource, if any.
    pub fn get_previous(
        &self,
        client: &ClientIdentifier,
        resource: &str,
    ) -> Option<crate::http_transaction::HttpTransaction> {
        let key = ResourceKey {
            client: client.clone(),
            resource: resource.to_string(),
        };

        match self.store.read() {
            Ok(store) => store.get(&key).and_then(|dq| dq.front().cloned()),
            Err(_) => {
                tracing::warn!("StateStore lock poisoned during read");
                None
            }
        }
    }

    /// Retrieve the full bounded history for this client+resource (newest first).
    pub fn get_history(
        &self,
        client: &ClientIdentifier,
        resource: &str,
    ) -> Vec<crate::http_transaction::HttpTransaction> {
        let key = ResourceKey {
            client: client.clone(),
            resource: resource.to_string(),
        };

        match self.store.read() {
            Ok(store) => store
                .get(&key)
                .map(|dq| dq.iter().cloned().collect())
                .unwrap_or_default(),
            Err(_) => {
                tracing::warn!("StateStore lock poisoned during read");
                Vec::new()
            }
        }
    }
    /// Retrieve the full bounded history across **all clients** for the given
    /// resource string.  The returned vector is sorted newest-first by
    /// timestamp.  This is useful for rules that need to observe behaviour that
    /// crosses client boundaries, such as ensuring `private` responses are not
    /// reused by other clients.
    pub fn get_history_for_resource(
        &self,
        resource: &str,
    ) -> Vec<crate::http_transaction::HttpTransaction> {
        // Clone the client list from the index first, then release the index
        // lock before acquiring the store lock to avoid lock-order inversion.
        let clients = match self.resource_index.read() {
            Ok(idx) => match idx.get(resource) {
                Some(c) => c.clone(),
                None => return Vec::new(),
            },
            Err(_) => return Vec::new(),
        };

        let mut entries = Vec::new();
        if let Ok(store) = self.store.read() {
            for client in &clients {
                let key = ResourceKey {
                    client: client.clone(),
                    resource: resource.to_string(),
                };
                if let Some(dq) = store.get(&key) {
                    for tx in dq.iter() {
                        entries.push(tx.clone());
                    }
                }
            }
        }
        // ensure newest-first ordering by timestamp (entries from different
        // clients may be interleaved)
        entries.sort_by_key(|tx| std::cmp::Reverse(tx.timestamp));
        entries
    }
    /// Collect all transactions for a given client across all resources (newest first per resource).
    ///
    /// Used by origin-based queries that need to scan across URIs.
    pub fn collect_for_client(
        &self,
        client: &ClientIdentifier,
    ) -> Vec<crate::http_transaction::HttpTransaction> {
        match self.store.read() {
            Ok(store) => store
                .iter()
                .filter(|(k, _)| &k.client == client)
                .flat_map(|(_, dq)| dq.iter().cloned())
                .collect(),
            Err(_) => {
                tracing::warn!("StateStore lock poisoned during read");
                Vec::new()
            }
        }
    }

    /// Retrieve all transactions that share the given `connection_id`.
    pub fn get_history_for_connection(
        &self,
        connection_id: Uuid,
    ) -> Vec<crate::http_transaction::HttpTransaction> {
        let keys = match self.connection_index.read() {
            Ok(idx) => match idx.get(&connection_id) {
                Some(k) => k.clone(),
                None => return Vec::new(),
            },
            Err(_) => {
                tracing::warn!("StateStore connection_index lock poisoned during read");
                return Vec::new();
            }
        };

        let mut entries = Vec::new();
        if let Ok(store) = self.store.read() {
            for key in &keys {
                if let Some(dq) = store.get(key) {
                    for tx in dq.iter() {
                        if tx.connection_id == Some(connection_id) {
                            entries.push(tx.clone());
                        }
                    }
                }
            }
        }
        entries
    }

    /// Remove expired entries from the store.
    pub fn cleanup_expired(&self) {
        let mut removed_keys: Vec<ResourceKey> = Vec::new();

        if let Ok(mut store) = self.store.write() {
            let ttl_chrono = chrono::Duration::from_std(self.ttl)
                .unwrap_or_else(|_| chrono::Duration::seconds(0));

            for (_key, deque) in store.iter_mut() {
                deque.retain(|tx| {
                    let age = Utc::now().signed_duration_since(tx.timestamp);
                    // If timestamp is in the future (age < 0), treat as expired (remove)
                    if age < chrono::Duration::zero() {
                        return false;
                    }
                    age <= ttl_chrono
                });
            }
            // identify empties so we can update indexes after removal
            store.retain(|key, dq| {
                if dq.is_empty() {
                    removed_keys.push(key.clone());
                    false
                } else {
                    true
                }
            });
        } else {
            tracing::warn!("StateStore lock poisoned during cleanup");
            return;
        }

        // Update indexes outside the store lock scope to avoid nested locking.
        if !removed_keys.is_empty() {
            if let Ok(mut idx) = self.resource_index.write() {
                for key in &removed_keys {
                    if let Some(clients) = idx.get_mut(&key.resource) {
                        clients.retain(|c| c != &key.client);
                        if clients.is_empty() {
                            idx.remove(&key.resource);
                        }
                    }
                }
            }

            if let Ok(mut idx) = self.connection_index.write() {
                idx.retain(|_conn_id, keys| {
                    keys.retain(|k| !removed_keys.contains(k));
                    !keys.is_empty()
                });
            }
        }
    }

    /// Seed the StateStore from a transaction record.
    /// Extracts user-agent from headers and uses localhost IP as placeholder.
    /// Skips transactions without responses.
    pub fn seed_from_transaction(&self, tx: &crate::http_transaction::HttpTransaction) {
        let user_agent = tx
            .request
            .headers
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
            .unwrap_or_else(|| "unknown".to_string());

        let client_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1));
        let client = ClientIdentifier::new(client_ip, user_agent);

        if tx.response.is_some() {
            let mut seeded = tx.clone();
            seeded.client = client;
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

    fn make_client() -> ClientIdentifier {
        ClientIdentifier::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            "test-agent/1.0".to_string(),
        )
    }

    #[test]
    fn record_and_retrieve_transaction() -> anyhow::Result<()> {
        let store = StateStore::new(300, 10);
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
        let store = StateStore::new(300, 10);
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
    fn get_history_for_resource_includes_all_clients() {
        let store = StateStore::new(300, 10);
        let client1 =
            ClientIdentifier::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), "a".to_string());
        let client2 =
            ClientIdentifier::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), "b".to_string());
        let resource = "http://example.com/res";

        use crate::test_helpers::make_test_transaction_with_response;
        let mut tx1 = make_test_transaction_with_response(200, &[("etag", "\"e1\"")]);
        tx1.client = client1.clone();
        tx1.request.uri = resource.to_string();
        tx1.timestamp = chrono::Utc::now();
        store.record_transaction(&tx1);

        let mut tx2 = make_test_transaction_with_response(200, &[("etag", "\"e2\"")]);
        tx2.client = client2.clone();
        tx2.request.uri = resource.to_string();
        tx2.timestamp = chrono::Utc::now() + chrono::Duration::seconds(1);
        store.record_transaction(&tx2);

        let history = store.get_history_for_resource(resource);
        assert_eq!(history.len(), 2);
        // newest-first should show tx2 first
        assert_eq!(
            history[0]
                .response
                .as_ref()
                .unwrap()
                .headers
                .get("etag")
                .unwrap()
                .to_str()
                .unwrap(),
            "\"e2\""
        );
    }

    #[test]
    fn cleanup_removes_expired_entries() {
        eprintln!("cleanup test start");
        let store = StateStore::new(1, 10); // 1 second TTL
        let client = make_client();
        let resource = "http://example.com/resource";

        eprintln!("about to create tx");
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.client = client.clone();
        tx.request.uri = resource.to_string();
        eprintln!("recording transaction");
        store.record_transaction(&tx);
        eprintln!("recorded");
        // index should contain mapping
        {
            let idx = store.resource_index.read().unwrap();
            assert!(idx
                .get(resource)
                .map(|v| v.contains(&client))
                .unwrap_or(false));
            eprintln!("index contains entry");
        } // read lock dropped here

        // sleep long enough to expire
        eprintln!("sleeping");
        std::thread::sleep(std::time::Duration::from_secs(2));
        eprintln!("woke up, about to cleanup");
        store.cleanup_expired();
        eprintln!("cleanup done");
        assert!(store.get_previous(&client, resource).is_none());
        // index should no longer have resource
        let idx2 = store.resource_index.read().unwrap();
        assert!(!idx2.contains_key(resource));
        eprintln!("cleanup test end");
    }

    #[test]
    fn get_history_for_resource_uses_index() {
        let store = StateStore::new(300, 10);
        let client1 = make_client();
        let mut client2 = client1.clone();
        client2.user_agent = "other".to_string();
        let resource = "http://example.com/res";

        let mut tx1 =
            crate::test_helpers::make_test_transaction_with_response(200, &[("etag", "\"a\"")]);
        tx1.client = client1.clone();
        tx1.request.uri = resource.to_string();
        store.record_transaction(&tx1);

        let mut tx2 =
            crate::test_helpers::make_test_transaction_with_response(200, &[("etag", "\"b\"")]);
        tx2.client = client2.clone();
        tx2.request.uri = resource.to_string();
        store.record_transaction(&tx2);

        let history = store.get_history_for_resource(resource);
        assert_eq!(history.len(), 2);
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
        let store = StateStore::new(ttl_secs, 10);
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
        let store = Arc::new(StateStore::new(300, 10));
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
                    version: "HTTP/1.1".into(),
                    headers: HeaderMap::new(),

                    body_length: None,
                    trailers: None,
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

    #[rstest]
    #[case(Some("test-client/1.0"), true, true)]
    #[case(None, true, true)]
    #[case(Some("other"), false, false)]
    fn test_seed_from_transaction(
        #[case] user_agent: Option<&str>,
        #[case] has_response: bool,
        #[case] expect_seeded: bool,
    ) -> anyhow::Result<()> {
        let store = StateStore::new(300, 10);
        let uri = "http://example.com/resource";

        let mut tx = if has_response {
            crate::test_helpers::make_test_transaction_with_response(200, &[("etag", "\"123\"")])
        } else {
            crate::test_helpers::make_test_transaction()
        };

        if let Some(ua) = user_agent {
            tx.request.headers.insert("user-agent", ua.parse()?);
        } else {
            tx.request.headers.remove("user-agent");
        }
        tx.request.uri = uri.to_string();

        store.seed_from_transaction(&tx);

        let expected_ua = user_agent.unwrap_or("unknown");
        let client = ClientIdentifier::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            expected_ua.to_string(),
        );

        let prev = store.get_previous(&client, uri);
        if expect_seeded {
            assert!(
                prev.is_some(),
                "Should have seeded for UA={}, has_resp={}",
                expected_ua,
                has_response
            );
        } else {
            assert!(
                prev.is_none(),
                "Should NOT have seeded for UA={}, has_resp={}",
                expected_ua,
                has_response
            );
        }
        Ok(())
    }

    #[test]
    fn get_previous_handles_poisoned_lock() {
        let store = StateStore::new(300, 10);
        let client = make_client();
        let resource = "http://example.com/resource";

        // Poison the lock by panicking while holding a write lock in another thread.
        let store_arc = store.store.clone();
        let handle = thread::spawn(move || {
            let _guard = store_arc.write().unwrap();
            panic!("intentional panic to poison lock");
        });
        let _ = handle.join(); // ignore the panic result

        // Now attempting to read should hit the poisoned branch and return None
        let res = store.get_previous(&client, resource);
        assert!(res.is_none());
    }

    #[test]
    fn bounded_history_evicts_oldest() {
        let store = StateStore::new(300, 3);
        let client = make_client();
        let resource = "http://example.com/resource";

        for i in 0..5u16 {
            let mut tx = crate::test_helpers::make_test_transaction_with_response(200 + i, &[]);
            tx.client = client.clone();
            tx.request.uri = resource.to_string();
            store.record_transaction(&tx);
        }

        let history = store.get_history(&client, resource);
        assert_eq!(history.len(), 3);
        // Newest first: 204, 203, 202
        assert_eq!(history[0].response.as_ref().unwrap().status, 204);
        assert_eq!(history[1].response.as_ref().unwrap().status, 203);
        assert_eq!(history[2].response.as_ref().unwrap().status, 202);
    }

    #[test]
    fn get_history_returns_newest_first() {
        let store = StateStore::new(300, 10);
        let client = make_client();
        let resource = "http://example.com/resource";

        for i in 0..3u16 {
            let mut tx = crate::test_helpers::make_test_transaction_with_response(200 + i, &[]);
            tx.client = client.clone();
            tx.request.uri = resource.to_string();
            store.record_transaction(&tx);
        }

        let history = store.get_history(&client, resource);
        assert_eq!(history.len(), 3);
        assert_eq!(history[0].response.as_ref().unwrap().status, 202);
        assert_eq!(history[1].response.as_ref().unwrap().status, 201);
        assert_eq!(history[2].response.as_ref().unwrap().status, 200);
    }

    #[test]
    fn collect_for_client_returns_all_resources() {
        let store = StateStore::new(300, 10);
        let client = make_client();

        let mut tx1 = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx1.client = client.clone();
        tx1.request.uri = "http://example.com/a".to_string();
        store.record_transaction(&tx1);

        let mut tx2 = crate::test_helpers::make_test_transaction_with_response(201, &[]);
        tx2.client = client.clone();
        tx2.request.uri = "http://example.com/b".to_string();
        store.record_transaction(&tx2);

        let all = store.collect_for_client(&client);
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn collect_for_client_excludes_other_clients() {
        let store = StateStore::new(300, 10);
        let client1 = make_client();
        let client2 =
            ClientIdentifier::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), "other".to_string());

        let mut tx1 = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx1.client = client1.clone();
        tx1.request.uri = "http://example.com/a".to_string();
        store.record_transaction(&tx1);

        let mut tx2 = crate::test_helpers::make_test_transaction_with_response(201, &[]);
        tx2.client = client2.clone();
        tx2.request.uri = "http://example.com/a".to_string();
        store.record_transaction(&tx2);

        let c1_txs = store.collect_for_client(&client1);
        assert_eq!(c1_txs.len(), 1);
        assert_eq!(c1_txs[0].response.as_ref().unwrap().status, 200);
    }

    #[test]
    fn get_history_for_connection_returns_matching_transactions() {
        let store = StateStore::new(300, 10);
        let client = make_client();
        let conn_id = uuid::Uuid::new_v4();

        let mut tx1 = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx1.client = client.clone();
        tx1.request.uri = "http://example.com/a".to_string();
        tx1.connection_id = Some(conn_id);
        store.record_transaction(&tx1);

        let mut tx2 = crate::test_helpers::make_test_transaction_with_response(201, &[]);
        tx2.client = client.clone();
        tx2.request.uri = "http://example.com/b".to_string();
        tx2.connection_id = Some(conn_id);
        store.record_transaction(&tx2);

        // Different connection
        let mut tx3 = crate::test_helpers::make_test_transaction_with_response(202, &[]);
        tx3.client = client.clone();
        tx3.request.uri = "http://example.com/c".to_string();
        tx3.connection_id = Some(uuid::Uuid::new_v4());
        store.record_transaction(&tx3);

        let history = store.get_history_for_connection(conn_id);
        assert_eq!(history.len(), 2);
        let statuses: Vec<u16> = history
            .iter()
            .map(|t| t.response.as_ref().unwrap().status)
            .collect();
        assert!(statuses.contains(&200));
        assert!(statuses.contains(&201));
    }

    #[test]
    fn get_history_for_connection_returns_empty_for_unknown() {
        let store = StateStore::new(300, 10);
        let history = store.get_history_for_connection(uuid::Uuid::new_v4());
        assert!(history.is_empty());
    }

    #[test]
    fn connection_index_updated_on_record() {
        let store = StateStore::new(300, 10);
        let client = make_client();
        let conn_id = uuid::Uuid::new_v4();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.client = client.clone();
        tx.request.uri = "http://example.com/x".to_string();
        tx.connection_id = Some(conn_id);
        store.record_transaction(&tx);

        let idx = store.connection_index.read().unwrap();
        assert!(idx.contains_key(&conn_id));
        assert!(!idx.get(&conn_id).unwrap().is_empty());
    }

    #[test]
    fn get_history_for_connection_handles_poisoned_connection_index() {
        let store = StateStore::new(300, 10);

        // Poison the connection_index lock
        let idx_arc = store.connection_index.clone();
        let handle = thread::spawn(move || {
            let _guard = idx_arc.write().unwrap();
            panic!("intentional panic to poison connection_index lock");
        });
        let _ = handle.join();

        // Should return empty vec instead of panicking
        let history = store.get_history_for_connection(uuid::Uuid::new_v4());
        assert!(history.is_empty());
    }

    #[test]
    fn record_transaction_handles_poisoned_store_lock() {
        let store = StateStore::new(300, 10);
        let client = make_client();

        // Poison the store lock
        let store_arc = store.store.clone();
        let handle = thread::spawn(move || {
            let _guard = store_arc.write().unwrap();
            panic!("intentional panic to poison store lock");
        });
        let _ = handle.join();

        // Should not panic, just log warning
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.client = client.clone();
        tx.request.uri = "http://example.com/x".to_string();
        store.record_transaction(&tx);
    }

    #[test]
    fn get_history_handles_poisoned_lock() {
        let store = StateStore::new(300, 10);
        let client = make_client();

        // Poison the store lock
        let store_arc = store.store.clone();
        let handle = thread::spawn(move || {
            let _guard = store_arc.write().unwrap();
            panic!("intentional panic to poison store lock");
        });
        let _ = handle.join();

        let history = store.get_history(&client, "http://example.com/x");
        assert!(history.is_empty());
    }

    #[test]
    fn collect_for_client_handles_poisoned_lock() {
        let store = StateStore::new(300, 10);
        let client = make_client();

        // Poison the store lock
        let store_arc = store.store.clone();
        let handle = thread::spawn(move || {
            let _guard = store_arc.write().unwrap();
            panic!("intentional panic to poison store lock");
        });
        let _ = handle.join();

        let results = store.collect_for_client(&client);
        assert!(results.is_empty());
    }

    #[test]
    fn cleanup_expired_handles_poisoned_lock() {
        let store = StateStore::new(300, 10);

        // Poison the store lock
        let store_arc = store.store.clone();
        let handle = thread::spawn(move || {
            let _guard = store_arc.write().unwrap();
            panic!("intentional panic to poison store lock");
        });
        let _ = handle.join();

        // Should not panic
        store.cleanup_expired();
    }

    #[test]
    fn cleanup_expired_prunes_connection_index() {
        let store = StateStore::new(1, 10); // 1-second TTL
        let client = make_client();
        let conn_id = uuid::Uuid::new_v4();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.client = client.clone();
        tx.request.uri = "http://example.com/conn-cleanup".to_string();
        tx.connection_id = Some(conn_id);
        store.record_transaction(&tx);

        // connection_index should have an entry
        {
            let idx = store.connection_index.read().unwrap();
            assert!(idx.contains_key(&conn_id));
        }

        // Wait for expiry
        std::thread::sleep(std::time::Duration::from_secs(2));
        store.cleanup_expired();

        // connection_index should be pruned
        let idx = store.connection_index.read().unwrap();
        assert!(
            !idx.contains_key(&conn_id),
            "connection_index should be pruned after cleanup"
        );
    }

    #[test]
    fn connection_index_no_duplicate_keys() {
        let store = StateStore::new(300, 10);
        let client = make_client();
        let conn_id = uuid::Uuid::new_v4();

        // Record two transactions on the same connection + resource
        for i in 0..2u16 {
            let mut tx = crate::test_helpers::make_test_transaction_with_response(200 + i, &[]);
            tx.client = client.clone();
            tx.request.uri = "http://example.com/x".to_string();
            tx.connection_id = Some(conn_id);
            store.record_transaction(&tx);
        }

        let idx = store.connection_index.read().unwrap();
        // Should only have one key entry (same resource key)
        assert_eq!(idx.get(&conn_id).unwrap().len(), 1);
    }
}
