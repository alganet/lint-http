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
- `src/capture.rs` - JSONL output via `CaptureWriter` and `CaptureRecordBuilder`
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

    fn check_response(/* or check_request */) -> Option<Violation> {
        // Return Some(Violation{...}) on failure, None on pass
    }
}
```

3. **Register in `src/rules/mod.rs`**: Add module declaration and append to `RULES` array

4. **Add tests in same file**: Must cover both violation and non-violation cases. Use `test_helpers`:
```rust
use crate::test_helpers::{make_test_client, make_test_conn, make_test_context};
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
`StateStore` tracks transactions per `(ClientIdentifier, resource)` with configurable TTL. Rules can query previous responses via `state.get_previous()` for stateful analysis like cache validation.

### Test Helpers Location
Shared test utilities are in `src/test_helpers.rs` (only compiled in test cfg).

## Configuration

Rules default to enabled. Disable via TOML:
```toml
[rules]
server_cache_control_present = false
```

Check rule status: `cfg.is_enabled("rule_id")` returns `true` if not explicitly disabled.
