// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Protocol-event linting entry point.
//!
//! Mirrors [`lint_transaction`](crate::lint::lint_transaction) but evaluates
//! [`ProtocolRule`](crate::rules::ProtocolRule) implementations against
//! [`ProtocolEvent`](crate::protocol_event::ProtocolEvent) instances.

use crate::config::Config;
use crate::engine::PreparedEngine;
use crate::lint::Violation;
use crate::protocol_event::{ProtocolEvent, ProtocolEventHistory};
use crate::protocol_event_store::ProtocolEventStore;

impl PreparedEngine {
    /// Lint a single protocol event against the enabled protocol rules
    /// (disabled rules were filtered out when the engine was built).
    pub fn lint_protocol_event(
        &self,
        event: &ProtocolEvent,
        cfg: &Config,
        event_store: &ProtocolEventStore,
    ) -> Vec<Violation> {
        let mut out = Vec::new();

        // Lazily computed history for this connection.
        let mut history_by_connection: Option<ProtocolEventHistory> = None;

        for rule in &self.enabled_protocol {
            let history = history_by_connection.get_or_insert_with(|| {
                let entries = event_store.get_history_for_connection(event.connection_id);
                ProtocolEventHistory::new(entries)
            });

            out.extend(rule.check_event(event, history, cfg));
        }

        out
    }
}

/// Lint a single protocol event against all enabled protocol rules.
/// Convenience one-shot: builds a [`PreparedEngine`] for `cfg`; hot paths build
/// one once and call [`PreparedEngine::lint_protocol_event`] instead.
pub fn lint_protocol_event(
    event: &ProtocolEvent,
    cfg: &Config,
    event_store: &ProtocolEventStore,
) -> Vec<Violation> {
    PreparedEngine::new(cfg).lint_protocol_event(event, cfg, event_store)
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
        let event = ProtocolEvent {
            timestamp: Utc::now(),
            connection_id: Uuid::new_v4(),
            kind: crate::protocol_event::ProtocolEventKind::H3GoawayReceived { stream_id: None },
        };

        let violations = lint_protocol_event(&event, &cfg, &store);
        assert!(violations.is_empty());
    }
}
