<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Development Guidelines

This document outlines the standards and workflows for contributing to `lint-http`.

## Workflow

1. **Fork & Branch**: Create a feature branch from `main`.
2. **Implement**: Write code and tests.
3. **Verify**: Run the full QA suite.
4. **PR**: Submit a Pull Request with a clear description.

## Quality Assurance

We maintain high standards for code quality and testing.

### Requirements

- **Code Coverage**: Minimum **80%** test coverage is required.
- **Tests**: All tests must pass (`cargo test`).
- **Linting**: No clippy warnings allowed (`cargo clippy`).
- **Formatting**: Code must be formatted with `rustfmt` (`cargo fmt`).

### Running QA

Run the full suite before submitting a PR:

```bash
# Format code
cargo fmt

# Run linter
cargo clippy -- -D warnings

# Run tests
cargo test

# Check coverage (requires cargo-tarpaulin)
cargo tarpaulin --out Xml
```

## Rule Creation Guidelines

Adding a new lint rule involves several steps.

### 1. Naming Convention

Rules should be named using `snake_case` and prefixed with their category:
- Client rules: `client_<name>`
- Server rules: `server_<name>`

Example: `server_cache_control_present`

### 2. Implementation

Create a new file in `src/rules/<rule_name>.rs`. Implement the `Rule` trait:

```rust
use crate::lint::Violation;
use crate::rules::Rule;

pub struct MyRule;

impl Rule for MyRule {
    fn id(&self) -> &'static str {
        "category_my_rule_name"
    }

    fn check_transaction(&self, tx: &crate::http_transaction::HttpTransaction, conn: &crate::connection::ConnectionMetadata, state: &crate::state::StateStore, config: &crate::config::Config) -> Option<Violation> {
        // Implementation
    }
}
```

#### Scoping

Rules must declare their intended scope by overriding `scope()` when appropriate. This makes it explicit whether a rule is intended for **requests**, **responses**, or both.

- Use `crate::rules::RuleScope::Client` for request-only checks.
- Use `crate::rules::RuleScope::Server` for response-only checks.
- Use `crate::rules::RuleScope::Both` if the rule must evaluate both the request and the response.

Example:

```rust
impl Rule for ClientHostHeader {
    fn id(&self) -> &'static str { "client_host_header" }
    fn scope(&self) -> crate::rules::RuleScope { crate::rules::RuleScope::Client }

    fn check_transaction(&self, tx: &crate::http_transaction::HttpTransaction, conn: &crate::connection::ConnectionMetadata, state: &crate::state::StateStore, config: &crate::config::Config) -> Option<Violation> {
        // Check tx.request.headers
    }
}
```

Being explicit prevents accidental evaluation on the wrong side and improves readability during code review.


### 3. Registration

Register the new rule in `src/rules/mod.rs` by adding it to the `RULES` list.

### 4. Testing

You must include unit tests in your rule file covering:
- **Positive case**: The rule triggers a violation when expected.
- **Negative case**: The rule does NOT trigger when the traffic is compliant.

### 5. Documentation

Create a markdown file in `docs/rules/<rule_name>.md` explaining:
- What the rule checks.
- Why it is important (best practice justification).
- Examples of compliant and non-compliant headers/behavior.

Finally, add a link to your new rule in `docs/rules.md`.

### 6. Configurable Rules Guidelines

- Do not use hardcoded defaults in rule implementations. If a rule requires configuration, it should require an explicit TOML table under `[rules.<rule_id>]` and parse its numeric/string values from that table.
- On missing or invalid configuration, `validate_config` must return an `Err(...)` so startup validation fails fast. Do not silently fallback to a default unless this behavior is explicitly documented and desired.
- Use `crate::rules::config_cache::RuleConfigCache<T>` to cache parsed config in `validate_config` and retrieve it in `check_transaction` using `get_or_init`.
- Tests should validate both `validate_config` errors for invalid/missing config and the runtime behavior when valid configs are provided (including edge cases like negative numbers, invalid types, and boundary values).
