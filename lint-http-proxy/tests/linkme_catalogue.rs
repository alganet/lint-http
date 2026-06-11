// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Cross-crate linkme guard.
//!
//! The rule catalogue self-registers into `linkme` distributed slices in the
//! `lint-http-rules` crate. After the workspace split, the binary links those
//! rules as a library dependency — a configuration where dead-code elimination
//! or a missing reference could leave the slices empty *only in the shipped
//! binary*, which a rules-crate-internal test would not catch. This test runs
//! in the proxy crate's link configuration (the one that ships) and fails loud
//! if the catalogue did not collect.

#[test]
fn registered_rules_collected_in_binary_link_config() {
    assert!(
        !lint_http::rules::REGISTERED_RULES.is_empty(),
        "no transaction rules were collected by linkme in the proxy link config",
    );
    assert!(
        !lint_http::rules::REGISTERED_PROTOCOL_RULES.is_empty(),
        "no protocol rules were collected by linkme in the proxy link config",
    );

    // Sorted views must agree with the raw registrations.
    assert_eq!(
        lint_http::rules::RULES.len(),
        lint_http::rules::REGISTERED_RULES.len(),
    );
    assert_eq!(
        lint_http::rules::PROTOCOL_RULES.len(),
        lint_http::rules::REGISTERED_PROTOCOL_RULES.len(),
    );

    // Spot-check a known transaction rule and a known protocol rule.
    assert!(lint_http::rules::RULES
        .iter()
        .any(|r| r.id() == "client_host_header"));
    assert!(lint_http::rules::PROTOCOL_RULES
        .iter()
        .any(|r| r.id() == "server_quic_transport_parameters"));
}
