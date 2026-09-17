<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

## Purpose

Orientation for AI coding agents working in `lint-http` — a TLS-terminating HTTP(S) forward
proxy that lints the traffic it forwards against the specifications, and writes JSONL captures.

**This file is a map and a list of traps, not a procedure.** It carries no counts, no command
recipes, and no rule-authoring checklist, because the previous version of it carried all three
and every one of them rotted: it still named `src/queries/mapping.rs`, `RuleConfigEngine` and
`get_cached` — none of which exist anywhere in the workspace — and described a single-crate
layout two splits out of date. Anything procedural belongs in the source that is gated:
`docs/development.md` for rules, the `justfile` for commands, `.cargo/config.toml` for aliases.
Send the reader there rather than copying it here.

## Layout — four crates, no `src/` at the root

| Crate | Owns | Depends on |
|---|---|---|
| `lint-http-core` | The data types, and nothing that knows about rules or transport: `HttpTransaction`, `TransactionHistory`, `ProtocolEvent` + its store, the bounded `StateStore`, `Config`, `Violation`/`Severity` | nothing in-workspace |
| `lint-http-rules` | The rule catalogue (`src/rules/`), the defect catalogue (`src/violations/`), the helper library (`src/helpers/`), the state-query layer (`src/queries/`), and dispatch (`engine`, `lint_protocol`) | core |
| `lint-http-proxy` | Transport, TLS/CA, capture, WebSocket — and the `lint-http` binary | core + rules |
| `xtask` | The docs and config generators, unpublished so the shipped binary carries neither | rules |

Both downstream crates re-export core's modules under their original names, so a path like
`crate::http_transaction::…` inside a rule file still resolves. Do not read that as evidence the
type lives in that crate.

## Runtime flow

Startup is `lint-http-proxy/src/main.rs`: clap subcommands (`run` carries `--config`; a bare
`--config` is a deprecated alias), then `Config::load_from_path`, then rule validation, then the
capture writer, then the proxy. Traffic enters `proxy/` — `http.rs`, `http3.rs`, `connect.rs`,
`websocket/` by protocol — a transaction is assembled, `engine::lint_transaction` runs the
enabled rules over it, and `capture.rs` appends JSONL. TLS interception and CA management are in
`ca.rs`; the CA certificate is served at `/_lint_http/cert`.

Rules never touch the store. They read a `TransactionHistory` precomputed by `queries/`, whose
`QueryType` — `ByResource` (the default), `ByOrigin`, `ByResourceAll` — a rule opts into and the
engine resolves lazily per transaction.

## Commands

`just` lists every recipe with a one-line summary. Two tiers: **`just check`** is the fast gate
to run constantly, **`just check-all`** adds MSRV, supply chain, release build and coverage and
is what to run before pushing. Each recipe's comment names the CI job it mirrors and where it
stops short; the file's header names the two answers no local recipe can give.

## Adding a rule

`docs/development.md` § "Rule Creation Guidelines" is canonical and current — follow it rather
than anything reconstructed from the tree. Four things that are easy to get wrong:

1. **The file stem, the `id()` literal, and the `PascalCase` struct name are one name in three
   spellings.** Ids carry no category prefix and use the predicate vocabulary in that document.
2. **There is nothing to register.** `build.rs` discovers `src/rules/*.rs`; a `linkme`
   distributed-slice static at the bottom of the file joins the catalogue. Creating the file is
   the registration, and `every_rule_file_is_registered` fails if it is missing.
3. **Configuration is resolved once, in `prepare`, not read at the check site.** A rule's own
   options come back through `ctx.state::<T>()`. Findings are built with `ctx.report(&DEF)` /
   `ctx.report_with(&DEF, msg)` — never constructed by hand, because the id, the sentence and
   the configured severity all come off the def.
4. **`docs/rules/`, `docs/rules.md` and `config_example.toml` are generated.** Put the prose on
   the rule and run `just gendocs` / `just genconfig`. Editing them by hand fails
   `docs_match_generated` and `config_example_matches_generated`.

## Conventions an agent will otherwise violate

- **A quote is copied out of the document, never recalled.** Every `// cite` comment beside a
  rule or helper is verified against the published text by `just quotes`. A remembered quote
  compiles, formats, passes clippy and passes `just citations` — this is the only gate that
  catches it, and it has caught it.
- **Never delete or detach a cite.** When a statement moves, its citation moves with it.
- **Activating a rule is the moment to finish its cites** — no decorative cites, and no uncited
  live construct. `every_violation_declares_a_spec` ratchets the count in one direction only.
- **A `SpecRef` URL ends in `.html`** and points at the rfc-editor rendition apysource fetches;
  `spec_refs_use_the_source_registry` enforces it. The link a reader clicks and the document the
  quote was checked against must be the same string.
- **Every commit must build green *as committed*,** not merely in the worktree. A selective
  `git add` has produced broken commits here twice.
- **`helpers/` modules are shelved by the question a value answers, never by the document that
  defines it.** `helpers/mod.rs` states the rule and the two splits that established it; read it
  before adding a module or dropping a function into an existing one.
- **`violations/` is shelved by subject instead**, which is a different scheme on purpose.
- SPDX headers are required on every new source, test and docs file; `reuse lint` gates it.
- **Rules are off by default.** `[rules.<id>]` always requires `enabled`, and requires whatever
  else that rule's own `prepare` parses — which must fail fast rather than default. Severity is
  per *defect*, not per rule: a `ViolationDef` carries a `default_severity`, and
  `[violations.<id>]` overrides `severity` or `enabled`. Rule ids are breaking to change and are
  never aliased — an unknown `[rules.<id>]` is a startup error.
- **Do not edit source while a coverage run is in flight** (~15 minutes; tarpaulin reads the
  tree as it goes).
- **Prefer an existing helper to new parsing.** The helper library is large and the grammar you
  need is probably already transcribed and cited.

## Integration points to understand before editing

- Outbound forwarding is `hyper` + `hyper-rustls`, with an HTTP/3 leg in `proxy/upstream_h3.rs`
  whose selection policy — allow/deny, discovery, negative cache, pool — is stated in
  `proxy/h3_policy.rs` and testable without driving a request.
- State can be seeded from prior captures (`general.captures_seed`); TTL and history bounds come
  from config and cleanup runs periodically.
- Captures are JSONL; body persistence is opt-in via `general.captures_include_body` and
  base64-encoded.
- **Protocol events are not file-observable.** They live only in the in-memory store, so an
  end-to-end assertion about one must be an in-crate test reaching the store directly.
- CONNECT, TLS passthrough and interception behaviour is covered by the integration tests in
  `lint-http-proxy/tests/`.
