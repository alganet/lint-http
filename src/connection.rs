// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Connection metadata definitions.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use uuid::Uuid;

/// Metadata associated with an underlying TCP connection.
#[derive(Debug)]
pub struct ConnectionMetadata {
    pub id: Uuid,
    pub remote_addr: SocketAddr,
    request_counter: AtomicU32,
}

impl ConnectionMetadata {
    pub fn new(remote_addr: SocketAddr) -> Self {
        Self {
            id: Uuid::new_v4(),
            remote_addr,
            request_counter: AtomicU32::new(0),
        }
    }

    /// Returns the next zero-based sequence number for this connection.
    pub fn next_sequence_number(&self) -> u32 {
        self.request_counter.fetch_add(1, Ordering::Relaxed)
    }
}
