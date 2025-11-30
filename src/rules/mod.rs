// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::state::{ClientIdentifier, StateStore};
use hyper::{HeaderMap, Method};

pub trait Rule: Send + Sync {
    fn id(&self) -> &'static str;

    fn check_request(
        &self,
        _client: &ClientIdentifier,
        _resource: &str,
        _method: &Method,
        _headers: &HeaderMap,
        _conn: &crate::connection::ConnectionMetadata,
        _state: &StateStore,
    ) -> Option<Violation> {
        None
    }

    fn check_response(
        &self,
        _client: &ClientIdentifier,
        _resource: &str,
        _status: u16,
        _headers: &HeaderMap,
        _conn: &crate::connection::ConnectionMetadata,
        _state: &StateStore,
    ) -> Option<Violation> {
        None
    }
}

pub mod client_accept_encoding_present;
pub mod client_cache_respect;
pub mod client_user_agent_present;
pub mod connection_efficiency;
pub mod server_cache_control_present;
pub mod server_etag_or_last_modified;
pub mod server_x_content_type_options;

pub const RULES: &[&dyn Rule] = &[
    &server_cache_control_present::ServerCacheControlPresent,
    &server_etag_or_last_modified::ServerEtagOrLastModified,
    &server_x_content_type_options::ServerXContentTypeOptions,
    &client_user_agent_present::ClientUserAgentPresent,
    &client_accept_encoding_present::ClientAcceptEncodingPresent,
    &client_cache_respect::ClientCacheRespect,
    &connection_efficiency::ConnectionEfficiency,
];
