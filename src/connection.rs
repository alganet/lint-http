// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Connection metadata definitions.

use std::net::SocketAddr;
use uuid::Uuid;

/// Metadata associated with an underlying TCP connection.
#[derive(Debug, Clone)]
pub struct ConnectionMetadata {
    pub id: Uuid,
    pub remote_addr: SocketAddr,
}

impl ConnectionMetadata {
    pub fn new(remote_addr: SocketAddr) -> Self {
        Self {
            id: Uuid::new_v4(),
            remote_addr,
        }
    }
}
