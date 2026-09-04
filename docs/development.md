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
- **Headers & Docs**: New source, test, and documentation files must include the SPDX header; new rules must carry their prose as metadata (regenerate with `cargo xtask gendocs`) and their example configuration as `config_example()` (regenerate with `cargo xtask genconfig`). Neither `docs/rules/` nor `config_example.toml` is hand-written — and the docs generator deletes any page no rule claims.
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

#### Rule ids

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

#### Violation ids

A rule id names a **claim** about the traffic; a violation id names the
**defect** that breaks it, so the predicate vocabulary inverts. The shape is
`<subject>[_<part>]_<defect>`, and it reads as a noun phrase closed by the
adjective that condemns it: `if_match_member_malformed` is "the `If-Match`
member is malformed".

- The **subject** is the field or protocol element, spelled the way the rules
  spell it — `if_match`, `content_type`, `www_authenticate`. It is never the id
  of the rule that reports the defect. Two rules may report one defect and one
  rule may absorb another, and neither event may rename what an operator has
  already configured.
- The **part** is optional, and narrows the subject to the piece of it that is
  wrong: the noun the grammar uses — `member`, `parameter`, `directive`,
  `scheme`, `name`, `value`. Leave it out when the whole field is the defect.
- The **defect** is the last word, and comes from this closed list.

| Meaning | Ending | Claim it breaks |
| --- | --- | --- |
| Does not match the field's ABNF grammar | `_malformed` | `_syntax` |
| Grammatical, but unacceptable past the grammar | `_invalid` | `_valid` |
| Absent from the IANA registry | `_unregistered` | `_registered` |
| Not written at all where it is required | `_missing` | `_present` |
| Two things that must agree do not | `_conflicting` | `_consistent` |
| A directive was not honoured | `_ignored` | `_enforced` |
| Written, and left with nothing in it | `_empty` | — |
| Appears more times than the grammar allows | `_duplicated` | — |
| Written where the specification prohibits it | `_forbidden` | — |
| Retired by a later specification | `_obsolete` | — |

`_missing` and `_empty` are not alternatives to pick between: `_missing` is a
sender that never wrote the thing, `_empty` is a sender that wrote it and put
nothing in it. Different senders, different fixes, different messages. Same
relation as `_syntax` to `_valid` above.

The list is closed on purpose, and it is what keeps the two catalogues from
colliding — no rule id ends in a defect, so
`violation_ids_are_unique_and_disjoint_from_rule_ids` holds by construction
rather than by luck, and `every_violation_id_names_a_defect` checks the ending
against the same words. Extending it is a reviewed act: the row here and the
word in that test move in one commit.

An id must be a valid Rust identifier, because the def is a `static` named by
the id in `SCREAMING_SNAKE_CASE` — `IF_MATCH_MEMBER_MALFORMED` — the same
one-name-several-spellings rule the rule files follow. The def lives in
`src/violations/<subject>.rs`, grouped by subject the way `helpers/` is; a
subject file holds every defect of the fields it covers, so the file stem is a
grouping and not required to prefix the id.

Renaming a violation breaks a configuration exactly as renaming a rule does,
and for the same reason: `[violations.<id>]` is refused at startup when the id
names nothing.

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
- **One exception, and only one: a violation's severity.** A `ViolationDef` carries a `default_severity`, and `[violations.<id>]` overrides it. A rule *option* is policy about the traffic and nobody but the operator can choose it; a severity is a preference, and a catalogue with one entry per defect cannot be made to run at all if every entry must be answered first. Nothing else on a def or a rule gets a default by this argument.
- On missing or invalid configuration, `prepare` must return an `Err(...)` so engine construction fails fast, by rule name. Do not silently fall back to a default unless this behavior is explicitly documented and desired.
- A required list of case-insensitive names (the `allowed`/`headers` shape) is parsed by `helpers::rule_config::parse_lowercased_list`; the citation licensing the case-fold stays in the rule's `prepare`, beside the call.
- Tests should cover both `prepare` errors for invalid/missing config and the runtime behavior when valid configs are provided (including edge cases like negative numbers, invalid types, and boundary values). Dispatch a rule in tests through `test_helpers::run_rule` / `run_protocol_rule`, which prepare and then check the way the engine does.
- Every registered rule must prepare successfully under `config_example.toml` — the `every_rule_prepares_under_the_example_config` test enforces it, so a new configurable rule needs its example section in the same commit.
- That example section is `config_example()`, a required `RuleMeta` member returning everything under the `[rules.<id>]` header: the two keys, the rule's own options, and the comment explaining them. It is required for the same reason the options above have no defaults — an example nobody chose is still an example someone will copy.
- `config_example.toml` is **generated** from those bodies, plus one `[violations.<id>]` section per catalogue entry rendered from its `default_severity`. Do not edit it; edit the rule or the def and run:

```bash
cargo xtask genconfig
```

The `config_example_matches_generated` test diffs the checked-in file against a fresh render, the same way `docs_match_generated` does for the docs, and it lives in `xtask` for the same reason — a targeted `cargo test -p lint-http-rules` will not run it.
