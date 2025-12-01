<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Development Guidelines

This document outlines the standards and workflows for contributing to `lint-http`.

## Workflow

1.  **Fork & Branch**: Create a feature branch from `main`.
2.  **Implement**: Write code and tests.
3.  **Verify**: Run the full QA suite.
4.  **PR**: Submit a Pull Request with a clear description.

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

    fn check_response(/* ... */) -> Option<Violation> {
        // Implementation
    }
}
```

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
