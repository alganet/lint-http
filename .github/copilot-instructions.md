<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# lint-http AI Coding Instructions

## Project Overview

`lint-http` is a Rust HTTP/HTTPS forward proxy that intercepts traffic to check for best practices and capture detailed logs. It performs TLS termination with on-the-fly certificate generation for HTTPS inspection.

## Architecture

### Core Data Flow
```
Client → Proxy (proxy.rs) → TLS termination (ca.rs) → Forward to upstream
                ↓                                              ↓
        State tracking (state.rs)                    Response received
                ↓                                              ↓
        Lint rules (lint.rs + rules/) ← ← ← ← ← ← ← ← ← ← ← ←
                ↓
        Capture (capture.rs) → JSONL file
```

### Key Modules
- `src/proxy.rs` - Main proxy server, handles HTTP/1.1 and HTTP/2, CONNECT tunneling
- `src/ca.rs` - Certificate Authority for dynamic TLS cert generation per domain
- `src/lint.rs` - Orchestrates rule evaluation against requests/responses
- `src/rules/mod.rs` - Defines `Rule` trait and `RULES` static array
- `src/state.rs` - Cross-request state tracking (keyed by `ClientIdentifier`: IP + User-Agent)
- `src/capture.rs` - JSONL output via `CaptureWriter` and `HttpTransaction`
- `src/config.rs` - TOML config loading with `Config::is_enabled(rule_id)`

## Development Commands

```bash
cargo fmt                          # Format code (required)
cargo clippy -- -D warnings        # Lint with zero warnings (required)
cargo test                         # Run all tests
cargo coverage                     # Run tarpaulin coverage (alias in .cargo/config.toml)
cargo run -- --config config_example.toml  # Run locally with example config
```

**Minimum 80% test coverage required.**

## Adding a New Lint Rule

1. **Create rule file**: `src/rules/<category>_<name>.rs` (e.g., `server_cache_control_present.rs`)

2. **Implement the `Rule` trait**:
```rust
use crate::lint::Violation;
use crate::rules::Rule;
use crate::state::{ClientIdentifier, StateStore};

pub struct MyRuleName;

impl Rule for MyRuleName {
    fn id(&self) -> &'static str {
        "category_my_rule_name"  // Must match filename convention
    }

    fn check_transaction(&self, tx: &crate::http_transaction::HttpTransaction, previous: Option<&crate::http_transaction::HttpTransaction>, config: &crate::config::Config) -> Option<Violation> {
        // Return Some(Violation{...}) on failure, None on pass
    }

    // Declare rule scope explicitly. Prefer setting this to Client/Server when
    // the rule only inspects requests or responses respectively.
    fn scope(&self) -> crate::rules::RuleScope { crate::rules::RuleScope::Both }
}
```

3. **Register in `src/rules/mod.rs`**: Add module declaration and append to `RULES` array

4. **Add tests in same file**: Must cover both violation and non-violation cases. Use `test_helpers`:
```rust
use crate::test_helpers::{make_test_client};
```

5. **Document in `docs/rules/<rule_name>.md`** and link from `docs/rules.md`

## Conventions

### SPDX Headers
All files must start with license header:
```rust
// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC
```

### Rule Naming
- Client rules: `client_<name>` (e.g., `client_user_agent_present`)
- Server rules: `server_<name>` (e.g., `server_cache_control_present`)

### Error Handling
Use `anyhow::Result` for fallible operations. The proxy is development-only, so fail-fast is acceptable.

### State Management
`StateStore` tracks transactions per `(ClientIdentifier, resource)` with configurable TTL. Rules receive an `Option<&HttpTransaction>` representing the previous transaction for the same client+resource when available; use this for stateful analysis like cache validation.

### Test Helpers Location
Shared test utilities are in `src/test_helpers.rs` (only compiled in test cfg).

## Configuration

Rules default to disabled. Enable via TOML only by adding a rule table with `enabled = true`:
```toml
[rules.server_cache_control_present]
enabled = true
```

Check rule status: `cfg.is_enabled("rule_id")` returns `true` only when there is a `[rules.<rule_id>]` table containing `enabled = true`.

### Configurable Rules

- Configurable rules should not rely on hardcoded defaults. If a rule requires configuration, it must be provided via a `[rules.<rule_id>]` table in TOML and include the necessary keys (numeric values, arrays, etc.).
- During `validate_config`, a rule should parse and validate the provided TOML values. If required keys are missing or invalid types are present, `validate_config` must return an error to fail startup validation.
- Parse and validate configuration in `validate_config`. Prefer to avoid rule-level static caches; if caching is necessary for performance, centralize it (for example, store parsed values in the main `Config` struct or a dedicated cache component) rather than using per-rule globals. In `check_transaction`, read configuration via `Config::get_rule_config` or re-parse as needed; to preserve tests that call `check_transaction` directly you may defensively panic with a clear message if parsing fails at runtime.
- Include explicit tests to validate `validate_config` behavior and runtime behavior with valid configuration. Tests should also include invalid config and missing config failure cases for `validate_config`.
