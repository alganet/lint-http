// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Mapping between rules and the state queries they require.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryType {
    ByResource,
    ByOrigin,
}

/// Returns the required QueryType for a given rule ID.
///
/// This central mapping allows the engine to optimize which queries are run
/// without complicating the Rule trait. Rules missing from this map default
/// to ByResource.
pub fn get_query_type_for_rule(rule_id: &str) -> QueryType {
    match rule_id {
        "stateful_authentication_failure_loop" => QueryType::ByOrigin,
        _ => QueryType::ByResource,
    }
}
