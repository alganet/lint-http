// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Bounded, TTL-managed store for protocol-level events.
//!
//! Indexed primarily by `connection_id` (and optionally by `session_id` for
//! WebSocket events).  Follows the same `Arc<RwLock<HashMap<K, VecDeque<V>>>>`
//! pattern as [`StateStore`](crate::state::StateStore) but stores
//! [`ProtocolEvent`] instead of `HttpTransaction`.

use crate::protocol_event::ProtocolEvent;
use chrono::Utc;
use parking_lot::RwLock;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

/// Thread-safe store for protocol events with bounded history and TTL expiry.
pub struct ProtocolEventStore {
    by_connection: Arc<RwLock<HashMap<Uuid, VecDeque<ProtocolEvent>>>>,
    by_session: Arc<RwLock<HashMap<Uuid, VecDeque<ProtocolEvent>>>>,
    ttl: Duration,
    max_events_per_key: usize,
}

impl ProtocolEventStore {
    pub fn new(ttl_seconds: u64, max_events_per_key: usize) -> Self {
        Self {
            by_connection: Arc::new(RwLock::new(HashMap::new())),
            by_session: Arc::new(RwLock::new(HashMap::new())),
            ttl: Duration::from_secs(ttl_seconds),
            max_events_per_key,
        }
    }

    /// Record a protocol event.
    ///
    /// The event is indexed by `connection_id`.  WebSocket frame events are
    /// additionally indexed by `session_id`.
    pub fn record_event(&self, event: &ProtocolEvent) {
        // Index by connection_id. Scoped so the guard drops before we acquire
        // the by_session lock below — the two are never held at once.
        {
            let mut store = self.by_connection.write();
            let deque = store.entry(event.connection_id).or_default();
            deque.push_front(event.clone());
            if deque.len() > self.max_events_per_key {
                deque.pop_back();
            }
        }

        // Additionally index WebSocket frame events by session_id
        if let crate::protocol_event::ProtocolEventKind::WebSocketFrame { session_id, .. } =
            &event.kind
        {
            let mut store = self.by_session.write();
            let deque = store.entry(*session_id).or_default();
            deque.push_front(event.clone());
            if deque.len() > self.max_events_per_key {
                deque.pop_back();
            }
        }
    }

    /// Retrieve event history for a connection (newest first).
    pub fn get_history_for_connection(&self, connection_id: Uuid) -> Vec<ProtocolEvent> {
        self.by_connection
            .read()
            .get(&connection_id)
            .map(|dq| dq.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Retrieve event history for a WebSocket session (newest first).
    pub fn get_history_for_session(&self, session_id: Uuid) -> Vec<ProtocolEvent> {
        self.by_session
            .read()
            .get(&session_id)
            .map(|dq| dq.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Remove expired events from the store.
    pub fn cleanup_expired(&self) {
        let ttl_chrono =
            chrono::Duration::from_std(self.ttl).unwrap_or_else(|_| chrono::Duration::seconds(0));

        Self::cleanup_map(&self.by_connection, ttl_chrono);
        Self::cleanup_map(&self.by_session, ttl_chrono);
    }

    fn cleanup_map(
        map: &Arc<RwLock<HashMap<Uuid, VecDeque<ProtocolEvent>>>>,
        ttl: chrono::Duration,
    ) {
        let mut store = map.write();
        for deque in store.values_mut() {
            deque.retain(|evt| {
                let age = Utc::now().signed_duration_since(evt.timestamp);
                if age < chrono::Duration::zero() {
                    return false;
                }
                age <= ttl
            });
        }
        store.retain(|_, dq| !dq.is_empty());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol_event::{MessageDirection, ProtocolEvent, ProtocolEventKind};

    fn make_ws_event(conn: Uuid, session: Uuid) -> ProtocolEvent {
        ProtocolEvent {
            timestamp: Utc::now(),
            connection_id: conn,
            kind: ProtocolEventKind::WebSocketFrame {
                session_id: session,
                direction: MessageDirection::Client,
                fin: true,
                opcode: 1,
                rsv: 0,
                payload_length: 10,
            },
        }
    }

    fn make_h3_event(conn: Uuid) -> ProtocolEvent {
        ProtocolEvent {
            timestamp: Utc::now(),
            connection_id: conn,
            kind: ProtocolEventKind::H3StreamOpened { stream_id: 0 },
        }
    }

    #[test]
    fn record_and_retrieve_by_connection() {
        let store = ProtocolEventStore::new(300, 100);
        let conn = Uuid::new_v4();
        let evt = make_h3_event(conn);
        store.record_event(&evt);

        let history = store.get_history_for_connection(conn);
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].connection_id, conn);
    }

    #[test]
    fn websocket_events_indexed_by_session() {
        let store = ProtocolEventStore::new(300, 100);
        let conn = Uuid::new_v4();
        let session = Uuid::new_v4();
        let evt = make_ws_event(conn, session);
        store.record_event(&evt);

        let by_conn = store.get_history_for_connection(conn);
        assert_eq!(by_conn.len(), 1);

        let by_session = store.get_history_for_session(session);
        assert_eq!(by_session.len(), 1);
    }

    #[test]
    fn bounded_history_evicts_oldest() {
        let store = ProtocolEventStore::new(300, 3);
        let conn = Uuid::new_v4();
        for _ in 0..5 {
            store.record_event(&make_h3_event(conn));
        }
        let history = store.get_history_for_connection(conn);
        assert_eq!(history.len(), 3);
    }

    #[test]
    fn cleanup_removes_expired() {
        let store = ProtocolEventStore::new(1, 100);
        let conn = Uuid::new_v4();
        store.record_event(&make_h3_event(conn));

        std::thread::sleep(std::time::Duration::from_secs(2));
        store.cleanup_expired();

        assert!(store.get_history_for_connection(conn).is_empty());
    }

    #[test]
    fn empty_history_for_unknown_connection() {
        let store = ProtocolEventStore::new(300, 100);
        assert!(store.get_history_for_connection(Uuid::new_v4()).is_empty());
    }

    #[test]
    fn empty_history_for_unknown_session() {
        let store = ProtocolEventStore::new(300, 100);
        assert!(store.get_history_for_session(Uuid::new_v4()).is_empty());
    }

    #[test]
    fn concurrent_access_is_safe() {
        use std::sync::Arc;
        use std::thread;

        let store = Arc::new(ProtocolEventStore::new(300, 100));
        let conn = Uuid::new_v4();

        let store1 = store.clone();
        let h1 = thread::spawn(move || {
            for _ in 0..100 {
                store1.record_event(&make_h3_event(conn));
            }
        });

        let store2 = store.clone();
        let h2 = thread::spawn(move || {
            for _ in 0..100 {
                let _ = store2.get_history_for_connection(conn);
            }
        });

        h1.join().unwrap();
        h2.join().unwrap();

        assert!(!store.get_history_for_connection(conn).is_empty());
    }
}
