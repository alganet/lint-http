// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Mapping between rules and the state queries they require.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryType {
    ByResource,
    ByOrigin,
    /// Like `ByResource` but returns history for **all clients** that have
    /// accessed the given resource.  Used by rules that need to observe
    /// cross-client behaviour (e.g. private cache visibility).
    ByResourceAll,
    /// Returns all transactions on the same TCP connection, ordered
    /// newest-first by timestamp.  Used by rules that validate
    /// connection-level protocol behaviour (pipelining, multiplexing,
    /// connection reuse).
    ByConnection,
}

/// Returns the required QueryType for a given rule ID.
///
/// This central mapping allows the engine to optimize which queries are run
/// without complicating the Rule trait. Rules missing from this map default
/// to ByResource.
pub fn get_query_type_for_rule(rule_id: &str) -> QueryType {
    match rule_id {
        "stateful_authentication_failure_loop" => QueryType::ByOrigin,
        "stateful_digest_auth_nonce_handling" => QueryType::ByOrigin,
        "stateful_cookie_lifecycle" => QueryType::ByOrigin,
        "stateful_cookie_same_site_enforcement" => QueryType::ByOrigin,
        "stateful_cookie_domain_matching" => QueryType::ByResource,
        "semantic_cache_coherence" => QueryType::ByResource,
        "stateful_vary_header_cache_validity" => QueryType::ByResource,
        "stateful_max_age_directive_validity" => QueryType::ByResource,
        "stateful_must_revalidate_enforcement" => QueryType::ByResource,
        "stateful_immutable_cache_never_stale" => QueryType::ByResource,
        "stateful_no_cache_revalidation" => QueryType::ByResource,
        "stateful_s_max_age_enforcement" => QueryType::ByResource,
        "stateful_no_store_enforcement" => QueryType::ByResource,
        "stateful_private_cache_visibility" => QueryType::ByResourceAll,
        "stateful_request_response_pairing" => QueryType::ByConnection,
        "semantic_connection_reuse_validity" => QueryType::ByConnection,
        _ => QueryType::ByResource,
    }
}
