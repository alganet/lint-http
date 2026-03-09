// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Protocol-event linting entry point.
//!
//! Mirrors [`lint_transaction`](crate::lint::lint_transaction) but evaluates
//! [`ProtocolRule`](crate::rules::ProtocolRule) implementations against
//! [`ProtocolEvent`](crate::protocol_event::ProtocolEvent) instances.

use crate::config::Config;
use crate::lint::Violation;
use crate::protocol_event::{ProtocolEvent, ProtocolEventHistory};
use crate::protocol_event_store::ProtocolEventStore;
use crate::rules::RuleConfigEngine;

/// Lint a single protocol event against all enabled protocol rules.
pub fn lint_protocol_event(
    event: &ProtocolEvent,
    cfg: &Config,
    event_store: &ProtocolEventStore,
    engine: &RuleConfigEngine,
) -> Vec<Violation> {
    let mut out = Vec::new();

    // Lazily computed history for this connection.
    let mut history_by_connection: Option<ProtocolEventHistory> = None;

    for rule in crate::rules::PROTOCOL_RULES {
        if cfg.is_enabled(rule.id()) {
            let history = history_by_connection.get_or_insert_with(|| {
                let entries = event_store.get_history_for_connection(event.connection_id);
                ProtocolEventHistory::new(entries)
            });

            out.extend(rule.check_event_erased(event, history, cfg, engine));
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    #[test]
    fn lint_protocol_event_returns_empty_for_no_enabled_rules() {
        let cfg = Config::default();
        let store = ProtocolEventStore::new(300, 100);
        let engine = RuleConfigEngine::new();
        let event = ProtocolEvent {
            timestamp: Utc::now(),
            connection_id: Uuid::new_v4(),
            kind: crate::protocol_event::ProtocolEventKind::H3GoawayReceived { stream_id: None },
        };

        let violations = lint_protocol_event(&event, &cfg, &store, &engine);
        assert!(violations.is_empty());
    }
}
