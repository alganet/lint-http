// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Connection metadata definitions.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use uuid::Uuid;

/// Transport protocol used for the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportProtocol {
    /// TCP (HTTP/1.1 or HTTP/2)
    Tcp,
    /// QUIC (HTTP/3)
    Quic,
}

/// Metadata associated with an underlying connection (TCP or QUIC).
#[derive(Debug)]
pub struct ConnectionMetadata {
    pub id: Uuid,
    pub remote_addr: SocketAddr,
    pub transport: TransportProtocol,
    request_counter: AtomicU32,
}

impl ConnectionMetadata {
    pub fn new(remote_addr: SocketAddr) -> Self {
        Self {
            id: Uuid::new_v4(),
            remote_addr,
            transport: TransportProtocol::Tcp,
            request_counter: AtomicU32::new(0),
        }
    }

    pub fn new_quic(remote_addr: SocketAddr) -> Self {
        Self {
            id: Uuid::new_v4(),
            remote_addr,
            transport: TransportProtocol::Quic,
            request_counter: AtomicU32::new(0),
        }
    }

    /// Returns the next zero-based sequence number for this connection.
    pub fn next_sequence_number(&self) -> u32 {
        self.request_counter.fetch_add(1, Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_creates_tcp_connection() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let meta = ConnectionMetadata::new(addr);
        assert_eq!(meta.transport, TransportProtocol::Tcp);
        assert_eq!(meta.remote_addr, addr);
    }

    #[test]
    fn new_quic_creates_quic_connection() {
        let addr: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let meta = ConnectionMetadata::new_quic(addr);
        assert_eq!(meta.transport, TransportProtocol::Quic);
        assert_eq!(meta.remote_addr, addr);
    }

    #[test]
    fn tcp_and_quic_transports_are_distinct() {
        assert_ne!(TransportProtocol::Tcp, TransportProtocol::Quic);
    }

    #[test]
    fn each_connection_gets_unique_id() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let m1 = ConnectionMetadata::new(addr);
        let m2 = ConnectionMetadata::new(addr);
        let m3 = ConnectionMetadata::new_quic(addr);
        assert_ne!(m1.id, m2.id);
        assert_ne!(m1.id, m3.id);
    }

    #[test]
    fn transport_protocol_debug_and_clone() {
        let t = TransportProtocol::Quic;
        let cloned = t;
        assert_eq!(format!("{:?}", cloned), "Quic");
        assert_eq!(format!("{:?}", TransportProtocol::Tcp), "Tcp");
    }

    #[test]
    fn arc_clone_shares_sequence_counter() {
        use std::sync::Arc;
        let addr: SocketAddr = "10.0.0.1:9090".parse().unwrap();
        let meta = Arc::new(ConnectionMetadata::new_quic(addr));
        let cloned = meta.clone();
        assert_eq!(cloned.id, meta.id);
        assert_eq!(cloned.remote_addr, meta.remote_addr);
        assert_eq!(cloned.transport, meta.transport);
        // Both Arcs share the same counter
        assert_eq!(meta.next_sequence_number(), 0);
        assert_eq!(cloned.next_sequence_number(), 1);
        assert_eq!(meta.next_sequence_number(), 2);
    }

    #[test]
    fn next_sequence_number_increments() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let meta = ConnectionMetadata::new(addr);
        assert_eq!(meta.next_sequence_number(), 0);
        assert_eq!(meta.next_sequence_number(), 1);
        assert_eq!(meta.next_sequence_number(), 2);
    }

    #[test]
    fn new_quic_starts_sequence_at_zero() {
        let addr: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let meta = ConnectionMetadata::new_quic(addr);
        assert_eq!(meta.next_sequence_number(), 0);
    }
}
