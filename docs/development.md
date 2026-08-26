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

- **Code Coverage**: Minimum **95%** test coverage is required (see `.cargo/config.toml` for the configured threshold/alias).
- **Tests**: All tests must pass (`cargo test`).
- **Linting**: Use `cargo lint` (alias in `.cargo/config.toml`) — clippy warnings are treated as errors.
- **Formatting**: Code must be formatted with `cargo fmt` (`rustfmt`).
- **Headers & Docs**: New source, test, and documentation files must include the SPDX header; new rules must include a docs file in `docs/rules/` and an example entry in `config_example.toml`.

### Running QA

Run the full suite before submitting a PR:

```bash
# Format code
cargo fmt

# Run linter (alias)
cargo lint

# Run tests
cargo test

# Coverage (alias)
cargo coverage
```

## Rule Creation Guidelines

Adding a new lint rule involves several steps.

### 1. Naming Convention

Rule ids are `snake_case` and carry no category prefix. The file stem, the id
returned by `id()`, and the `PascalCase` struct name are the same name in three
spellings — `cache_control_present.rs`, `"cache_control_present"`,
`CacheControlPresent` — and `build.rs` and the citation store both derive from
the stem, so they must agree.

The shape is `<subject>[_<qualifier>]_<predicate>`: name the thing being read,
then the property asserted about it.

| Meaning | Ending | Example |
| --- | --- | --- |
| Conforms to the field's ABNF grammar | `_syntax` | `etag_syntax` |
| Value acceptable beyond grammar (in range, well-formed, permitted) | `_valid` | `link_header_valid` |
| Value appears in an IANA registry | `_registered` | `charset_registered` |
| Field or value must be present | `_present` | `cache_control_present` |
| Two things must agree | `_consistent` | `conditional_headers_consistent` |
| A directive must be honoured | `_enforced` | `no_store_enforced` |

`_syntax` and `_valid` are not alternatives to pick between: `_syntax` is
conformance to the grammar, `_valid` is acceptability past it. A rule checking
only the grammar takes `_syntax`, never `_syntax_valid`.

Do not bolt a predicate onto an id that names a relation, an event, or a subject
area rather than a claim — `status_3xx_vs_request_method`, `cookie_lifecycle`,
`websocket_frame_rsv_bits`, `retry_after_date_or_delay` are correct as they
stand.

Include `_header` only where the subject is also a common noun and would read as
one without it (`host_header`, `prefer_header_valid`); leave it out where the
field name is already unmistakable (`etag_syntax`, `content_type_registered`).

An id must be a valid Rust identifier, because `build.rs` emits `pub mod
<stem>;`. A rule keyed on a status code therefore takes a `status_` subject
rather than leading with the number: `status_426_upgrade_valid`.

Renaming an existing rule is a breaking change for every configuration naming
it, and this catalogue does not alias: `validate_rules` fails at startup on an
id it does not recognise, pointing the operator at `docs/rules.md`.

### 2. Implementation

Create a new file in `src/rules/<rule_name>.rs`. Implement the `Rule` trait:

```rust
use crate::lint::Violation;
use crate::rules::Rule;

pub struct MyRule;

impl Rule for MyRule {
    fn id(&self) -> &'static str {
        "my_rule_name"
    }

    fn check_transaction(&self, tx: &crate::http_transaction::HttpTransaction, previous: Option<&crate::http_transaction::HttpTransaction>, config: &crate::config::Config) -> Option<Violation> {
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
impl Rule for HostHeader {
    fn id(&self) -> &'static str { "host_header" }
    fn scope(&self) -> crate::rules::RuleScope { crate::rules::RuleScope::Client }

    fn check_transaction(&self, tx: &crate::http_transaction::HttpTransaction, previous: Option<&crate::http_transaction::HttpTransaction>, config: &crate::config::Config) -> Option<Violation> {
        // Check tx
    }
}
```

Being explicit prevents accidental evaluation on the wrong side and improves readability during code review.


### 3. Registration

Nothing to edit. `build.rs` lists `src/rules/*.rs` and emits a `pub mod` for each
stem, and the rule registers itself into the catalogue with a `linkme`
distributed slice at the bottom of its own file:

```rust
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &MyRule;
```

Use `REGISTERED_PROTOCOL_RULES` and `&dyn ProtocolRule` for a rule that reads
protocol events rather than transactions. Creating the file is the whole of the
registration.

### 4. Testing

You must include unit tests in your rule file covering:
- **Positive case**: The rule triggers a violation when expected.
- **Negative case**: The rule does NOT trigger when the traffic is compliant.

### 5. Documentation

`docs/rules/<rule_name>.md` and the `docs/rules.md` index are **generated** — do
not write them by hand. Put the prose on the rule itself, in `description()`,
`specifications()` and `examples()`, covering:

- What the rule checks.
- Why it is important (best practice justification).
- Examples of compliant and non-compliant headers/behavior.

Then regenerate:

```bash
cargo xtask gendocs
```

The `docs_match_generated` test diffs the checked-in tree against freshly
rendered output, so a rule whose metadata changed without a regeneration fails
CI. The index places the rule by its `scope()`, so there is no link to add.

### 6. Configurable Rules Guidelines

- Do not use hardcoded defaults in rule implementations. If a rule requires configuration, it should require an explicit TOML table under `[rules.<rule_id>]` and parse its numeric/string values from that table.
- On missing or invalid configuration, `validate_config` must return an `Err(...)` so startup validation fails fast. Do not silently fallback to a default unless this behavior is explicitly documented and desired.
- Tests should validate both `validate_config` errors for invalid/missing config and the runtime behavior when valid configs are provided (including edge cases like negative numbers, invalid types, and boundary values).
