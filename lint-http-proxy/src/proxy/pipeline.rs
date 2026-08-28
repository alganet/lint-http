// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Canonical lint → record → capture orchestration for the proxy.
//!
//! The ordering is load-bearing: state must be recorded *after* lint,
//! otherwise the current transaction shows up in its own history. Both
//! pipelines run lint themselves and `TransactionPipeline::commit` consumes
//! the transaction, so callers that go through `commit` cannot reorder the
//! steps, re-commit, or mutate the transaction after capture. Error exchanges
//! route through `commit` too (`record_error_transaction`), so they are linted
//! and recorded like any other traffic. The WebSocket *session* record goes
//! through [`ProtocolEventPipeline::commit_session`] — its violations were
//! already collected frame by frame through `commit`, so the session write is
//! capture routing, and routing it here means no proxy record reaches the
//! capture file except through a pipeline.

use std::sync::Arc;

use tracing::warn;

use crate::capture::CaptureWriter;
use crate::engine::PreparedEngine;
use crate::http_transaction::HttpTransaction;
use crate::lint::Violation;
use crate::protocol_event::ProtocolEvent;
use crate::protocol_event_store::ProtocolEventStore;
use crate::state::StateStore;

use super::Shared;

/// Orchestrates the per-transaction cycle: lint, record to state, write the
/// capture line. No config here: the rules' configuration was resolved into
/// the engine when it was built.
pub(super) struct TransactionPipeline {
    engine: Arc<PreparedEngine>,
    state: Arc<StateStore>,
    captures: CaptureWriter,
}

impl TransactionPipeline {
    /// Lint `tx` (populating `tx.violations`), record it to state, then write
    /// it to the capture file — in that order. Consumes the transaction so it
    /// cannot be re-committed or mutated after capture; returns the
    /// violations for callers that need them.
    pub(super) async fn commit(&self, mut tx: HttpTransaction) -> Vec<Violation> {
        tx.violations = self.engine.lint_transaction(&tx, &self.state);
        self.state.record_transaction(&tx);
        // Extract violations before moving the transaction into the writer.
        let violations = tx.violations.clone();
        if let Err(e) = self.captures.write_transaction(tx).await {
            warn!(error = %e, "failed to write transaction capture");
        }
        violations
    }
}

/// Orchestrates the per-protocol-event cycle: lint, then record to the event
/// store. Cloneable so concurrent relay tasks can each own one. No config
/// here: the protocol rules' configuration was resolved into the engine when
/// it was built.
#[derive(Clone)]
pub(super) struct ProtocolEventPipeline {
    engine: Arc<PreparedEngine>,
    store: Arc<ProtocolEventStore>,
    captures: CaptureWriter,
}

impl ProtocolEventPipeline {
    pub(super) fn new(
        engine: Arc<PreparedEngine>,
        store: Arc<ProtocolEventStore>,
        captures: CaptureWriter,
    ) -> Self {
        Self {
            engine,
            store,
            captures,
        }
    }

    /// Lint `event`, then record it — in that order. Returns the violations
    /// so callers can log or collect them.
    pub(super) fn commit(&self, event: &ProtocolEvent) -> Vec<Violation> {
        let violations = self.engine.lint_protocol_event(event, &self.store);
        self.store.record_event(event);
        violations
    }

    /// Write a finished WebSocket session record to the capture file. There is
    /// no session-level lint to run: every frame was linted through [`commit`]
    /// as it was relayed and the collected violations ride on the session —
    /// this is the one place the record reaches the capture, documented as
    /// routing rather than a bypass.
    ///
    /// [`commit`]: ProtocolEventPipeline::commit
    pub(super) async fn commit_session(&self, session: crate::websocket_session::WebSocketSession) {
        if let Err(e) = self.captures.write_websocket_session(session).await {
            warn!(error = %e, "failed to write websocket session capture");
        }
    }
}

impl Shared {
    pub(super) fn pipeline(&self) -> TransactionPipeline {
        TransactionPipeline {
            engine: self.engine.clone(),
            state: self.state.clone(),
            captures: self.captures.clone(),
        }
    }

    pub(super) fn protocol_event_pipeline(&self) -> ProtocolEventPipeline {
        ProtocolEventPipeline::new(
            self.engine.clone(),
            self.protocol_event_store.clone(),
            self.captures.clone(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::{make_shared_with_cfg, read_capture};
    use super::*;
    use crate::test_helpers::{
        make_proxy_config_with_enabled_rules, make_test_transaction_with_response,
    };
    use tokio::fs;

    #[tokio::test]
    async fn commit_populates_violations_and_writes_capture() -> anyhow::Result<()> {
        let cfg_inner = make_proxy_config_with_enabled_rules(&[
            "cache_control_present",
            "etag_or_last_modified_present",
        ]);
        let (shared, tmp, cw) = make_shared_with_cfg(Arc::new(cfg_inner), None).await?;

        let tx = make_test_transaction_with_response(200, &[]);
        let violations = shared.pipeline().commit(tx).await;

        assert!(!violations.is_empty());

        cw.flush().await?;
        let entries = read_capture(&tmp).await?;
        assert_eq!(entries.len(), 1);
        let captured = entries[0]["violations"]
            .as_array()
            .expect("violations array in capture");
        assert_eq!(captured.len(), violations.len());

        let _ = fs::remove_file(&tmp).await;
        Ok(())
    }

    #[tokio::test]
    async fn commit_records_to_state_after_lint() -> anyhow::Result<()> {
        let cfg_inner = make_proxy_config_with_enabled_rules(&[
            "cache_control_present",
            "etag_or_last_modified_present",
        ]);
        let (shared, tmp, _cw) = make_shared_with_cfg(Arc::new(cfg_inner), None).await?;

        let tx = make_test_transaction_with_response(200, &[]);
        let client = tx.client.clone();
        let uri = tx.request.uri.clone();
        let violations = shared.pipeline().commit(tx).await;

        // The recorded copy carries the lint result, proving record ran
        // after lint populated `tx.violations`.
        let history = shared.state.get_history(&client, &uri);
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].violations.len(), violations.len());

        let _ = fs::remove_file(&tmp).await;
        Ok(())
    }

    #[tokio::test]
    async fn protocol_event_pipeline_commit_records_and_returns() -> anyhow::Result<()> {
        let (shared, tmp, _cw) =
            make_shared_with_cfg(Arc::new(crate::config::Config::default()), None).await?;

        let connection_id = uuid::Uuid::new_v4();
        let pe = ProtocolEvent {
            timestamp: chrono::Utc::now(),
            connection_id,
            kind: crate::protocol_event::ProtocolEventKind::WebSocketFrame {
                session_id: uuid::Uuid::new_v4(),
                direction: crate::websocket_session::MessageDirection::Client,
                fin: true,
                opcode: 1,
                rsv: 0,
                extensions: Default::default(),
                masked: None,
                payload_length: 2,
            },
        };
        let violations = shared.protocol_event_pipeline().commit(&pe);

        let recorded = shared
            .protocol_event_store
            .get_history_for_connection(connection_id);
        assert_eq!(recorded.len(), 1);

        // No protocol rules are enabled in the default config.
        assert!(violations.is_empty());

        let _ = fs::remove_file(&tmp).await;
        Ok(())
    }
}
