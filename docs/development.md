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
- **Headers & Docs**: New source, test, and documentation files must include the SPDX header; new rules must carry their prose as metadata (regenerate with `cargo xtask gendocs`) and an example entry in `config_example.toml`. Nothing under `docs/rules/` is hand-written — the generator deletes any page no rule claims.
- **Minimum Rust version**: `rust-version` in the workspace `Cargo.toml` — currently **1.94**, about three releases behind stable. It is a support window we choose, not the oldest toolchain that happens to compile. The `msrv` CI job builds on exactly that version; raising it is a deliberate edit to the manifest, not something a new API call does silently.
- **Dependencies**: A manifest declares only what its code reads, and a crate used only from tests belongs in `[dev-dependencies]`. `cargo machete` gates this.

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

Create a new file in `src/rules/<rule_name>.rs`. Every rule implements two
traits: `RuleMeta`, which is everything the rule says about itself and is shared
with `ProtocolRule`, and `Rule`, which is the transaction it reads.

```rust
use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};

pub struct MyRule;

impl RuleMeta for MyRule {
    fn id(&self) -> &'static str {
        "my_rule_name"
    }
}

impl Rule for MyRule {
    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // Implementation. `ctx.severity` is the configured severity, already
        // resolved — nothing here reads TOML.
    }
}
```

Configuration is resolved **once, when the engine is built**, by `RuleMeta`'s
`prepare` hook. The default resolves the two required keys (`enabled`,
`severity`); a rule with its own options overrides `prepare`, parses them into
a typed value, and returns it as the `state` of its `ResolvedRule` — the check
gets it back with `ctx.state::<MyConfig>()`. Validation *is* successful
preparation: a malformed section fails engine construction by rule name, so
there is no separate `validate` hook to keep in sync.

#### How many findings

`findings` returns a `Vec`, and the number is a judgment about the specification
rather than about the code. Ask what the sentence is addressed to:

- **Independent defects are separate findings.** Two configured fields, two
  Dictionary members, two field sections, the request and the response: each is
  something a sender did on its own and something an operator fixes on its own.
  Returning at the first hides the rest, and the one reported is the only one the
  next run will show — fixing it reveals the next.
- **One contradiction is one finding, however many values it names.** A message
  that says `Accept-Ranges` advertises `bytes` and `pages` beside `none` describes
  a single response saying two things at once. Splitting it would report the same
  contradiction twice.
- **A whole-field failure is one finding and the only one.** Where a parse failure
  discards the field, nothing else in it survived to be described, and the scan
  stops. Where a member is ignored on its own, the rest of the field is still in
  force and the scan carries on.

A rule with one finding keeps a `?`-shaped body behind a private `Option` adapter
and collects it — `Vec::from_iter(finding())`. Tests read one finding through
`run_rule` and several through `run_rule_all`.

#### Citing the sentence

Findings are built with `self.violation(ctx.severity, message)`, or with
`self.cited(&SPEC, ctx.severity, message)` where the sentence being enforced is
known. `cited` takes one of the rule's own `specifications()`, which live as
named consts above the impl:

```rust
const RFC_9112_6_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9112",
    section: Some("6.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-6.1",
    note: "Transfer-Encoding — chunked at most once, and chunked last",
};
```

`specifications()` is built from exactly those consts, so a citation and the
generated docs cannot come to name different text. A `debug_assert` in `cited`
rejects a reference the rule does not declare, and the suite runs in debug.

The `.html` in that URL is not a style preference, and
`spec_refs_use_the_source_registry` insists on it: it is the document apysource
fetches and checks every `// cite` quote against. The link a reader clicks and
the document the quote was verified in are the same string, which is the whole
reason the gate can be strict about it.

Attachment is per finding site and opt-in. The `// cite` comment beside the
statement is the oracle: attach the reference that comment names, and leave the
site un-cited when the answer needs a decision — where the block quotes several
sentences and it is not settled which one the finding reports, or where the quote
is a supporting definition rather than the requirement. `cite` defaults to `None`,
so an un-cited finding is complete; a *wrongly* cited one is worse than none.
`citation_coverage_does_not_regress` pins the count so the direction only moves
one way.

#### Scoping

Rules must declare their intended scope by overriding `scope()` when appropriate. This makes it explicit whether a rule is intended for **requests**, **responses**, or both.

- Use `crate::rules::RuleScope::Client` for request-only checks.
- Use `crate::rules::RuleScope::Server` for response-only checks.
- Use `crate::rules::RuleScope::Both` if the rule must evaluate both the request and the response.

Example:

```rust
impl RuleMeta for HostHeader {
    fn id(&self) -> &'static str { "host_header" }
}

impl Rule for HostHeader {
    fn scope(&self) -> crate::rules::RuleScope { crate::rules::RuleScope::Client }

    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
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

Dispatch through `crate::test_helpers::run_rule`, which prepares the rule under a
config the way the engine does and hands back the first finding. A rule that can
report several — see [How many findings](#how-many-findings) — needs
`run_rule_all` for the case where it does, so that the split is asserted rather
than assumed: a test reading only the first finding passes just as well when the
rest were swallowed.

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

That test lives in `xtask` alongside the generator, so `cargo test -p
lint-http-rules` will not run it: a targeted run can come back green on a rule
whose docs are stale. `just test` and a bare `cargo test` are workspace-wide and
do run it, as does CI.

### 6. Configurable Rules Guidelines

- Do not use hardcoded defaults in rule implementations. If a rule requires configuration, it should require an explicit TOML table under `[rules.<rule_id>]` and parse its values in `prepare`.
- On missing or invalid configuration, `prepare` must return an `Err(...)` so engine construction fails fast, by rule name. Do not silently fall back to a default unless this behavior is explicitly documented and desired.
- A required list of case-insensitive names (the `allowed`/`headers` shape) is parsed by `helpers::rule_config::parse_lowercased_list`; the citation licensing the case-fold stays in the rule's `prepare`, beside the call.
- Tests should cover both `prepare` errors for invalid/missing config and the runtime behavior when valid configs are provided (including edge cases like negative numbers, invalid types, and boundary values). Dispatch a rule in tests through `test_helpers::run_rule` / `run_protocol_rule`, which prepare and then check the way the engine does.
- Every registered rule must prepare successfully under `config_example.toml` — the `every_rule_prepares_under_the_example_config` test enforces it, so a new configurable rule needs its example section in the same commit.
