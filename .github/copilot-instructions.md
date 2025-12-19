<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

## What this file is for ✅
Short, actionable tips for AI agents and contributors working on `lint-http`: where to look, how to run and test, and project-specific conventions that cannot be inferred from Rust conventions alone.

## Quick project summary (big picture) 🔧
- Purpose: TLS-terminating HTTP/HTTPS forward proxy that lints traffic and writes JSONL captures.
- High-level flow: Client → `src/proxy.rs` (terminates TLS via `src/ca.rs`) → `src/lint.rs` (runs rules in `src/rules/`) → `src/capture.rs` (writes `captures.jsonl`).
- Rules are stateful when needed and can consult previous transactions using `src/state.rs` (keyed by `ClientIdentifier`).

## Essential commands & CI expectations ⚙️
- Format: `cargo fmt` (required)
- Lint: `cargo lint` (alias in `.cargo/config.toml`) ≈ `cargo clippy --all-features --all-targets -- -D warnings`
- Tests: `cargo test`
- Coverage: `cargo coverage` (alias in `.cargo/config.toml`, uses tarpaulin); CI enforces a coverage threshold — check `.cargo/config.toml` for `fail-under` (project uses strict threshold).
- Run locally: `cargo run -- --config config_example.toml`
- Note: for minimum supported Rust version and other tooling settings, rely on repo files like `Cargo.toml` and `.cargo/config.toml` as the sources of truth.

## How rules are added and validated (do this exactly) 🧩
1. Add a file: `src/rules/<client|server>_<name>.rs` (name → rule id returned by `id()`).
2. Implement the `Rule` trait (see `src/rules/mod.rs` for the trait signature and `RuleScope`).
   - If your rule needs custom config, override `validate_and_box` to return a parsed config type.
3. Register the rule in `src/rules/mod.rs` (add module and append to `RULES`).
4. Add docs: `docs/rules/<rule_id>.md` and reference it from `docs/rules.md`.
5. Add configuration example to `config_example.toml` (tests assert it contains all rules).
6. Add tests covering:
   - Violation and non-violation cases
   - `validate_rules` behavior (valid + invalid config cases)
   - Use helpers from `src/test_helpers.rs`: `enable_rule`, `enable_rule_with_paths`, `make_test_transaction_with_response`, `make_test_engine`.

Important: rules are disabled by default. The `Config::load_from_path` function calls `validate_rules` at startup and returns a `RuleConfigEngine` — ensure enabled rules are validated and cached before runtime. `RuleConfigEngine::get_cached` will panic if a rule wasn't validated.

## Project conventions & gotchas ⚠️
- SPDX header: every source/test/doc file must include the SPDX license header at the top.
- Rule tables must explicitly include `enabled` (boolean) and `severity` (string: `info|warn|error`) — missing keys cause startup validation to fail.
- `config_example.toml` is canonical for examples; a test asserts it contains an example for every rule in `RULES`.
- Tests use small helpers from `src/test_helpers.rs` (don’t re-implement common setups).
- TLS is implemented using Rust-native TLS stacks (e.g., `rustls`, `tokio-rustls`, `hyper-rustls`) with no required system OpenSSL dependency — rely on the crates listed in `Cargo.toml` for implementation details.
- Be mindful that `.cargo/config.toml` contains the authoritative lint & coverage aliases and thresholds.

## Rule documentation style 📚
Each rule must have a corresponding doc in `docs/rules/<rule_id>.md` and follow this strict structure and formatting to make docs machine-parsable and consistent:

1. SPDX header (same header as other files).
2. H1 title: either a human-friendly title or the exact rule id (both are acceptable, but prefer the more-readable title for user-facing docs).
3. `## Description` — short, 1–3 paragraphs describing what the rule checks and why it matters.
4. `## Specifications` — bullet list of authoritative references (prefer `https://www.rfc-editor.org/rfc/` links for RFCs, include section anchors when relevant, e.g. `RFC 7234 §5.2`).
5. `## Configuration` — TOML snippet showing the minimal example required to enable the rule (include `enabled` and `severity` keys).
6. `## Examples` — include `✅ Good` and `❌ Bad` examples as fenced `http` blocks; show minimal requests/responses that illustrate pass/fail cases.

Formatting rules:
- Use fenced code blocks with language markers (`toml`, `http`).
- Keep docs concise and focused (avoid long protocol digressions).
- When referencing RFCs or specs, prefer canonical links (rfc-editor.org, w3.org, MDN) and include the specific section if applicable.
- Add `docs/rules/<rule_id>.md` for each new rule and add an example in `config_example.toml` (a test asserts coverage).

Rationale: Consistent docs make it easy for contributors and automated tools (including AI agents) to locate example traffic, canonical references, and config snippets quickly.


## Helpers & common utilities 🔁
- Reuse existing helpers whenever possible — the codebase centralizes common parsing and test helpers to reduce duplication.
  - `src/token.rs` — token/header parsing utilities used by multiple rules for HTTP token validation (e.g., header name/value/token checks). Prefer using or extending these helpers when implementing rules that parse or validate header tokens.
  - `src/test_helpers.rs` — test fixtures and helpers (`enable_rule`, `make_test_transaction_with_response`, etc.) for consistent unit tests.
  - When adding new helpers: add tests, document intent with a module-level comment, and keep APIs small and focused for reuse.

## Useful files to inspect (start here) 📚
- `src/proxy.rs` — main runtime, connection handling, and TLS entry points
- `src/ca.rs` — dynamic certificate generation and CA endpoints (`/_lint_http/cert`)
- `src/lint.rs` & `src/rules/mod.rs` — rule engine and registration
- `src/state.rs` — state store and TTL behavior
- `src/capture.rs` — JSONL capture format and writer
- `src/test_helpers.rs` — utilities for unit tests
- `config_example.toml` — canonical rule examples
- `.cargo/config.toml` — lint/coverage aliases and thresholds
- `docs/rules/` — per-rule documentation examples

## Testing checklist for PRs ✅
- `cargo fmt` passes
- `cargo lint` (or `cargo clippy -- -D warnings`) passes
- `cargo test` passes on CI
- New rule: add doc entry in `docs/rules/` and update `config_example.toml`
- Add tests for invalid configurations (validation should fail with helpful error messages)
- Ensure SPDX header present in new files
