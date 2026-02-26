<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

## Purpose
Actionable guidance for AI coding agents working in `lint-http` (TLS-terminating HTTP(S) forward proxy + lint engine + JSONL capture writer).

## Big picture architecture
- Startup wiring is in `src/main.rs`: parse `--config`, call `Config::load_from_path`, build `CaptureWriter`, run proxy.
- Runtime flow: client traffic enters `src/proxy.rs` → transaction is built (`src/http_transaction.rs`) → violations computed in `src/lint.rs` using `src/rules/` → capture appended by `src/capture.rs`.
- TLS MITM and CA management live in `src/ca.rs`; CA cert is exposed at `/_lint_http/cert`.
- Stateful checks use `src/state.rs`; rules do not query store directly, they consume precomputed history from `src/queries/`.
- Query strategy is centrally mapped in `src/queries/mapping.rs` (`ByResource` default, specific rules can opt into `ByOrigin`).

## Commands and CI expectations
- Run locally: `cargo run -- --config config_example.toml`
- Format: `cargo fmt`
- Lint: `cargo lint` (alias for strict clippy with `-D warnings`)
- Tests: `cargo test`
- Coverage: `cargo coverage` (tarpaulin alias, currently `--fail-under 96` in `.cargo/config.toml`)
- Treat `.cargo/config.toml` as source of truth for lint/coverage aliases and thresholds.

## Rule implementation workflow (required)
1. Add `src/rules/<client|server|message|semantic>_<name>.rs`.
2. Implement `Rule` in `src/rules/mod.rs` style; set `scope()` (`Client`, `Server`, or `Both`).
3. Register module and add rule to `RULES` in `src/rules/mod.rs`.
4. If custom config is needed, override `validate_and_box` and fail fast on invalid config.
5. Add docs in `docs/rules/<rule_id>.md` and link in `docs/rules.md`.
6. Add example config in `config_example.toml` (tests assert rule/doc example coverage).
7. Add tests with `src/test_helpers.rs` helpers (`enable_rule`, `enable_rule_with_paths`, `make_test_transaction_with_response`, `make_test_engine`).

## Project-specific conventions and gotchas
- SPDX header is required in all new source, test, and docs files.
- Rules are disabled by default; enabling requires `[rules.<id>] enabled = <bool>` and `severity = "info|warn|error"`.
- Config validation happens before runtime in `Config::load_from_path` via `validate_rules`; missing `enabled`/`severity` is a startup error.
- `RuleConfigEngine::get_cached` panics if an enabled rule wasn’t validated/cached; always rely on validated engine instances.
- `config_example.toml` is canonical; keep it synchronized with `RULES`.
- Prefer existing helpers/utilities (`src/test_helpers.rs`, `src/token.rs`) over custom parsing/fixture code.

## Integration points to understand before editing
- Outbound forwarding uses `hyper` + `hyper-rustls` client in `src/proxy.rs`; inbound serving uses `hyper-util` connection builder.
- State can be seeded from prior captures (`general.captures_seed`), and cleanup runs periodically (TTL/max history from config).
- Capture output is JSONL (`captures.jsonl`); optional body persistence is controlled by `general.captures_include_body` and is base64-encoded.
- Integration behavior for CONNECT/TLS passthrough and interception is covered under `tests/proxy_connect_*.rs` and `tests/integration_tls_config.rs`.
