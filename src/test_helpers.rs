// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Shared test utilities to reduce duplication across test modules.

use crate::state::{ClientIdentifier, StateStore};
use std::net::{IpAddr, Ipv4Addr};

/// Create a test client identifier with standard test values
pub fn make_test_client() -> ClientIdentifier {
    ClientIdentifier::new(
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        "test-agent".to_string(),
    )
}

/// Create a test client and state store for rule testing
pub fn make_test_context() -> (ClientIdentifier, StateStore) {
    (make_test_client(), StateStore::new(300))
}

/// Create a test connection metadata with standard test address
pub fn make_test_conn() -> crate::connection::ConnectionMetadata {
    crate::connection::ConnectionMetadata::new(
        "127.0.0.1:12345".parse().expect("valid test address")
    )
}
