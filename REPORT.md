<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# lint-http — Architectural Review

## Overview

`lint-http` is a Rust-based forward proxy that intercepts HTTP/1.1, HTTP/2,
HTTP/3 and WebSocket traffic, runs a catalogue of lint rules over each
transaction, and appends JSONL captures to disk. The rule catalogue currently
holds **184 leaf rule modules**: 179 transaction rules registered in the `RULES`
slice plus 5 protocol-event rules in `PROTOCOL_RULES`. By prefix the rules
break down as 16 `client_`, 99 `message_`, 8 `semantic_`, 36 `server_`, and
25 `stateful_`. The source tree is ~80k lines: ~14k of engine / transport /
helper code and ~66k in the rule modules and their inline tests.

The codebase is organized as:

- A **proxy module tree** (`src/proxy/`) split into `mod.rs`, `http.rs`,
  `http3.rs`, `connect.rs`, `websocket.rs`, `hop_by_hop.rs`, and
  `test_support.rs`. Between them they own TCP listening, CONNECT
  tunneling/MITM, hop-by-hop filtering, body collection, request forwarding,
  WebSocket relay, and the HTTP/3 (QUIC) accept loop. `proxy/websocket.rs`
  (~1,250 lines) and `proxy/http.rs` (~1,210 lines) are now the largest proxy
  units; `src/helpers/headers.rs` (~1,850 lines) is the single largest file.
- A rule engine (`src/lint.rs`, `src/lint_protocol.rs`, `src/rules/mod.rs`)
  built around a `Rule` trait with an associated `Config` type, a hand-curated
  `RULES` slice (179 entries), and a parallel `PROTOCOL_RULES` slice (5
  entries).
- A 184-file `src/rules/` directory of leaf rule modules, mirrored by
  `docs/rules/` (184 per-rule files plus `TEMPLATE.md`) and a hand-maintained
  `docs/rules.md` index.
- A bounded, TTL-aware `StateStore` (`src/state.rs`) and `ProtocolEventStore`
  exposing cross-transaction history, queried indirectly through pre-built
  `TransactionHistory` / `ProtocolEventHistory` views.
- A helpers tree (`src/helpers/*`), serde header-map adapters
  (`src/serde_helpers.rs`), an rcgen-based MITM CA (`src/ca.rs`), and a
  `CaptureWriter` (`src/capture.rs`) that serializes transactions to a shared
  JSONL file.

The design has clear strengths: rules are isolated, configurable, and
well-tested; state is decoupled from rules through pre-queried history views;
TLS is rust-native; HTTP/3 has dedicated frame-level instrumentation. The
trade-offs documented below are about scaling the architecture as the rule
catalogue grows, sharpening boundaries between transport / lint / capture
concerns, and removing redundancy that has accreted between adjacent
abstractions.

The improvement entries below are organized by impact tier and tagged with
**Size** (S / M / L / XL — rough lines-of-change), **Complexity** (Low / Medium
/ High — coordination cost, blast radius, risk), and **Architectural Gains**
(what the change buys us beyond the immediate diff).

---

## Guiding principle: rules as a portable library

`src/transaction_history.rs` already declares the architectural intent:

> Rules depend only on `TransactionHistory` (and `HttpTransaction`), never on
> `StateStore` or the query layer, so the rule crate can be extracted
> independently in the future.

That extraction (#2) is the long-term goal. Every change in this report should
preserve or strengthen rule independence — a rule consumed by a CI capture
linter, a HAR/PCAP analyzer, or a replay harness should not have to know about
the proxy's transport, its query system, its capture format, or its config
cache.

When a proposal is tempted to push an engine concern (history queries, state
storage, capture IO, config caching) into the `Rule` trait, the rule library
gets dragged along with it. Several Tier 2 proposals below were originally
drafted that way; the revised forms keep engine concerns *outside* the trait.

The dispatch cleanups (#6–#11) are sequenced to land *before* the workspace
split (#2) so that the rule crate's public API has no engine-shaped types in
it by the time the boundary becomes a `Cargo.toml` boundary.

---

## Commit-sizing convention: one atomic commit per step

Every step in the suggested ordering at the bottom of this report corresponds
to **one atomic commit** that compiles and passes tests on its own. When an
item from the analysis below is genuinely too large for a single coherent
commit, it is split into ordered sub-steps (e.g. `#8a`, `#8b`, `#8c`); each
sub-step is itself an atomic commit. The sub-step decomposition lives next to
the item description so context stays local.

A few items resist clean splitting because the change cascades through the
trait surface. Those are kept as single commits in the ordering with their
size noted honestly — splitting them artificially would produce intermediate
commits that don't individually compile, which is worse for review than one
larger but coherent change.

---

## Tier 1 — Structural

### 1. Split `src/proxy.rs` into a `proxy/` module tree — ✅ DONE (commit `1501c66`)

Completed. `src/proxy/` now contains `mod.rs`, `http.rs`, `http3.rs`,
`connect.rs`, `websocket.rs`, `hop_by_hop.rs`, and `test_support.rs`. Tests
live alongside their subsystem.

This unblocks the rest of Tier 1 — #3 (streaming bodies) and #4 (writer task)
can now move per-subsystem instead of touching one 3,800-line file, and the
proxy crate boundary in #2 has natural module seams to keep.

### 2. Cargo workspace: split into `lint-http-core`, `lint-http-rules`, `lint-http-proxy`

Today this is a single crate; `lib.rs` exposes 19 modules and rules and proxy
live together. `Cargo.toml` has no `[workspace]`.
`transaction_history.rs` is already the explicit boundary (its own doc-comment
notes it exists "so the rule crate can be extracted independently in the
future").

**Proposed crates:**

- `lint-http-core` — `http_transaction`, `lint`, `transaction_history`,
  `protocol_event`, `serde_helpers`, `state` (extracted as a trait).
- `lint-http-rules` — `rules/`, `helpers/`, `queries/`, `lint_protocol` —
  depends only on `lint-http-core`.
- `lint-http-proxy` (binary + thin lib) — `proxy/`, `ca`, `capture`,
  `connection`, `h3_instrument`, `websocket_session`.

- **Size:** L
- **Complexity:** Medium — needs careful re-export hygiene, visibility audits,
  and dev-dependency review.
- **Gains:** Reuses the 184-rule library outside the proxy (e.g. HAR/PCAP
  analyzers, CI HTTP-fixture linting, postman-style replay), independent
  versioning, faster incremental builds (rule changes don't rebuild the proxy
  and vice versa), and a much easier "publish rules to crates.io" story.

### 3. Streaming proxy body pipeline

`handle_http_logic` (`src/proxy/http.rs`) calls `body.collect().await` to fully
buffer the request body before forwarding, and `resp.into_body().collect().await`
to fully buffer the response before returning to the client. Both bodies are
then cloned again — once into the `Full` body that is forwarded, and once held
as `Bytes` in the transaction.

This breaks several real workflows: large downloads, server-sent events,
long-poll, chunked CDN responses. Even when bodies are small, holding multiple
full copies (request and response) per in-flight transaction is wasteful.

**Proposed shape:**

- Stream bodies by default; tee a bounded prefix into a capture buffer
  (configurable byte cap, e.g. `captures_max_body_bytes`).
- Compute `body_length` from the streamed total, not from a buffered `Bytes`.
- Lint rules that need the body (today: very few; mostly content-length /
  multipart) get a `body_prefix: Option<Bytes>` slice on the transaction
  alongside the streamed length.

- **Size:** XL
- **Complexity:** High — touches every error path in `handle_http_logic` plus
  the H3 stream handler; needs careful trailers handling.
- **Gains:** Restores correct proxy semantics (SSE, chunked stream), unblocks
  large-body workloads, removes a memory-amplification bug, decouples capture
  from forwarding.

### 4. Capture writer: dedicated writer task with bounded mpsc

`CaptureWriter` (`src/capture.rs`) holds an `Arc<Mutex<tokio::fs::File>>` (a
`tokio::sync::Mutex`). Its `write_line` acquires the mutex, writes the line, and
**flushes** while still holding the lock. Every concurrent request serializes on
this mutex and the per-write `flush()`. The async mutex avoids blocking the
runtime thread, but the per-write fsync barrier and the single shared file
handle still serialize the capture path — a hidden bottleneck for a proxy.

**Proposed shape:**

```rust
pub struct CaptureWriter {
    tx: mpsc::Sender<CaptureRecord>,
}
// background task: pull from rx, write batched, flush on idle/timer
```

- Use `tokio::sync::mpsc` with a bounded queue (drop or backpressure on
  overflow per a configured policy).
- Use `BufWriter` + interval-based or size-based flush, not per-line.
- Provide a `shutdown()` that drains and fsyncs.

- **Size:** M
- **Complexity:** Medium — backpressure policy is the one design choice that
  matters; everything else is mechanical.
- **Gains:** Removes a synchronous fs barrier from the request hot path,
  isolates IO failures behind a channel boundary, makes the proxy feel "fast"
  under burst load, and gives a natural place to add capture rotation /
  compression / streaming endpoints (#13).

### 5. Lossless capture schema (multi-value headers, tagged records, schema version)

`serde_helpers::serialize_headers` collapses `HeaderMap` into a
`HashMap<String, String>`. Headers that legitimately appear multiple times —
`Set-Cookie`, `Vary`, `Link`, `Cache-Control`, `Via`, `Forwarded`,
`WWW-Authenticate` — lose all but one value, and non-UTF-8 values are silently
dropped by the `v.to_str()` guard. For a tool whose entire purpose is verifying
HTTP correctness, this is a quiet correctness hazard: a replayed capture can
pass rules that the live traffic would have failed.

The JSONL also has weak versioning. `WebSocketSession` carries a
`type: "websocket_session"` discriminator (added via a manual `record_type`
field), but `HttpTransaction` has none — `load_captures` treats any record
whose `type` is missing (or equals `http_transaction`) as a transaction and
skips the rest. There is no `schema_version`.

**Proposed:**

- Serialize headers as `Vec<(String, String)>` (ordered, lossless) or
  `HashMap<String, Vec<String>>`. Provide a one-shot migrator for the existing
  format.
- Wrap top-level capture records in a tagged enum:
  ```rust
  #[serde(tag = "type", rename_all = "snake_case")]
  enum CaptureRecord { HttpTransaction(...), WebsocketSession(...), ... }
  ```
- Add `schema_version: u32` (or a `meta` envelope) so future readers can
  reject / migrate older files cleanly.
- Decide the policy for non-UTF-8 header bytes: emit base64 with a marker, or
  fail loud — but stop dropping silently.

- **Size:** M
- **Complexity:** Medium — touches serde, capture loader, replay/seed paths,
  and any external tools that consume the JSONL.
- **Gains:** Correctness of stateful rules over replayed captures, room for
  schema evolution without ad-hoc heuristics, and an enum that makes capture
  consumers (dashboards, analyzers) trivial to write.

---

## Tier 2 — Rule Engine

### 6. Wire `RuleScope` into dispatch — ✅ DONE

Implemented as a single-slice filter rather than the originally-proposed
three-way partition: a `LazyLock`-built `REQUEST_ONLY_RULES` excludes
`Server`-scoped rules while preserving the source order of `RULES`, and the
`rules_for_scope(has_response)` helper returns either `RULES` or
`&REQUEST_ONLY_RULES`. Dispatch in `src/lint.rs` selects with
`rules_for_scope(tx.response.is_some())`. The simpler shape avoids reordering
violations on the has-response path and matches the only two dispatch cases
that actually exist today (`PROTOCOL_RULES` carries no scope yet, so it is
unchanged).

The `Rule::scope` doc-comment now spells out the engine contract: `Server`
rules may assume the response is present. The defensive `if let Some(resp)`
guards inside the server rules become redundant under that contract; removing
them is left as opportunistic cleanup, not part of this change.

Note: in production `lint_transaction` is only called after response
collection, so the runtime saving is theoretical for the proxy path. The
real value lands in #18 (`lint-http lint <captures.jsonl>`) and any other
non-proxy caller.

### 7. Make stateful rules' query needs explicit — but keep `QueryType` off the `Rule` trait

`src/queries/mapping.rs` is a hardcoded `match rule_id { "stateful_x" =>
ByOrigin, ... }` with a silent `_ => QueryType::ByResource` default. Adding a
new stateful rule that needs `ByOrigin` will compile and run, but get the wrong
history — detectable only via test, if a test exists.

**Rejected fix.** The obvious move — adding `fn query_type(&self) -> QueryType`
to the `Rule` trait — is rejected on modularity grounds. The vast majority of
the 184 rules don't need history at all; forcing all of them to import
`QueryType` and declare an answer pulls the engine's query layer into the rule
library's public API. A rule reused in a CI capture linter that has no state
store would still have to satisfy that method.

**Proposed.** Keep the query layer external to the `Rule` trait, but make the
declaration *exhaustive* and *colocated with rule registration*. Two shapes
work — the choice depends on how #9 lands:

- **Pair-the-slice.** A separate `STATEFUL_RULES: &[(&dyn Rule, QueryType)]`
  registry alongside `RULES`, with a test that fails if any rule whose ID
  begins with `stateful_` (or, better, any rule that opts in via marker)
  appears in `RULES` but not in `STATEFUL_RULES`. Stateless rules don't change.
- **Companion trait.** `pub trait StatefulRule: Rule { fn query_type(&self) ->
  QueryType; }`. The engine iterates two slices. Stateless rules implement only
  `Rule` and never see `QueryType`.

Either form deletes `queries/mapping.rs` and the silent default. Either keeps
the stateless majority of rules unaware of the query system.

- **Size:** S
- **Complexity:** Low.
- **Gains:** Removes the silent-default failure mode without saddling the
  `Rule` trait — and any future external rule pack — with engine-level
  metadata.

### 8. Drop the associated `Config` type and the type-erasure ceremony

Today `Rule` (`src/rules/mod.rs`) has an associated `Config` type. Because that
prevents `&dyn Rule` from being stored in `RULES`, the codebase carries:

- A second trait, `RuleConfigValidator`, that erases the associated type into
  `Arc<dyn Any + Send + Sync>`.
- A `RuleConfigEngine` that holds `HashMap<&'static str, Arc<dyn Any>>` and
  panics on lookup miss (`"Rule '{}' config not found in cache. This is a
  bug..."`).
- A `validate_and_box` method on the public `Rule` trait whose return type is
  *engine-shaped* (`Arc<dyn Any + Send + Sync>`) — the trait itself leaks
  the engine's caching strategy.
- A parallel `ProtocolRuleConfigValidator` for the protocol-event side.

**Rejected alternative.** Returning a single `enum RuleConfig { CacheControl(...),
CookieLifecycle(...), ... }` would be *worse* than today: every rule's config
shape becomes part of one closed enum, every external rule pack would have to
fork that enum, and the rule library can no longer be extended without modifying
central code. Drop the suggestion.

**Proposed.** Drop the associated type entirely. Rules consume
`&crate::config::Config` directly and parse their own section internally —
several non-trivial rules (e.g. `ServerClearSiteData`) already parse a custom
section in `validate_and_box`:

```rust
pub trait Rule: Send + Sync {
    fn id(&self) -> &'static str;
    fn scope(&self) -> RuleScope { RuleScope::Both }
    fn validate(&self, _cfg: &Config) -> anyhow::Result<()> { Ok(()) }
    fn check_transaction(
        &self,
        tx: &HttpTransaction,
        history: &TransactionHistory,
        config: &Config,
    ) -> Option<Violation>;
}
```

- Each rule's parsed config struct stays private to its module.
- Rules that want to amortize parsing use a `OnceLock<ParsedConfig>` on
  themselves; the engine no longer owns a config cache.
- `validate` returns `()` on success — no boxing, no `Any`, no downcast.
- `RuleConfigValidator`, `RuleConfigEngine`, the runtime panic path, and the
  parallel `ProtocolRuleConfigValidator` all delete entirely.

- **Size:** L overall — ~2.5–3 k lines across ~200 files, dominated by
  mechanical signature changes in the 184 rule files and their tests.
- **Complexity:** Medium — most of the work is repetitive; the design
  decisions are small in number.
- **Gains:** Removes ~200 lines of trait scaffolding and the panic path,
  shrinks the public `Rule` API to one method plus metadata, and — crucially
  for #2 — removes the engine-shaped return type (`Arc<dyn Any>`) from the
  trait so the rule library's public surface no longer leaks the proxy's
  config-cache implementation.

**Atomic-commit decomposition.**

- **#8a — Add a `check(&self, tx, history, cfg, engine)` method** to `Rule`
  (and `ProtocolRule`) with a default impl that delegates to the legacy
  `check_transaction(&Self::Config)` via the engine cache. Engine dispatch
  switches to call `check` (through the `*_erased` wrappers).
  `check_transaction` gains an `unreachable!()` default so future rules can
  skip it. No rule changes; tests unchanged. — ✅ **DONE (commit `9514afc`).**
- **#8b — Migrate every rule to override `check` directly.** Each rule sets
  `type Config = ();`, removes its `check_transaction` impl, and provides a
  `check` impl that takes `cfg: &Config` and parses inline (the custom-config
  rules call their existing `parse_*_config` helpers from inside `check`). Rule
  tests migrate from constructing parsed `RuleConfig` / custom-config structs
  to building a `Config`. Single commit if reviewable as one structural move;
  can be batched by category (`client_*`, `server_*`, `message_*`,
  `stateful_*`, `semantic_*`, `protocol`) since each rule's migration is
  independent thanks to the dual-method trait from #8a. ~2–3 k lines.
- **#8c — Delete the legacy machinery.** — ✅ **DONE.** Removed `type Config`,
  `validate_and_box`, the legacy `check_transaction` / `check_event` and their
  `unreachable!()` defaults, `RuleConfigValidator`, `RuleConfigEngine`,
  `ProtocolRuleConfigValidator`, and the `engine` parameter that cascaded
  through `lint_transaction` / `lint_protocol_event` / `Config::load_from_path`
  / `main.rs` / `Shared` / the proxy submodules. The `check` methods were
  renamed to `check_transaction` / `check_event` (the legacy names freed). A new
  object-safe `Rule::validate(&Config) -> Result<()>` replaces `validate_and_box`
  for startup validation (custom-config rules override it to parse their
  section); `RULES` / `PROTOCOL_RULES` now store `&dyn Rule` / `&dyn ProtocolRule`
  directly and `validate_rules` returns `()`.

#8a landed the bridge; #8b did the mechanical per-rule migration; #8c was the
pure deletion once the bridge had done its job.

### 9. Auto-register rules with `linkme` or `inventory`

`src/rules/mod.rs` has 184 `pub mod ...;` lines, a 179-entry `RULES` slice, and
a 5-entry `PROTOCOL_RULES` slice, all hand-maintained. There's a test that
asserts `config_example.toml` contains every registered rule, but nothing
prevents adding a `pub mod foo;` without registering its struct in `RULES` (or
vice versa). No `linkme` / `inventory` dependency is present today.

**Proposed:**

- Use `linkme::distributed_slice` (no global ctor on macOS/Windows issue today)
  or `inventory` to let each rule register itself: `#[lint_http::rule] static
  RULE: ServerCacheControlPresent = ...;`.
- Generate the `pub mod` declarations via `build.rs` from directory contents,
  or move rules into one-file-per-category modules.

- **Size:** M
- **Complexity:** Medium — needs to be robust on all build targets the project
  supports (Linux/macOS/Windows already in CI).
- **Gains:** Adding a rule = create one file. Drop ~370 lines of
  bookkeeping. Makes external rule packs (#2) realistic.

**Atomic-commit decomposition.**

- **#9a — Wire `linkme` infrastructure.** Add the `linkme` dependency,
  declare the `#[distributed_slice] static REGISTERED_RULES: [&dyn Rule]`
  (and the protocol equivalent), and the `#[lint_http::rule]` attribute (or
  rely on raw `linkme::distributed_slice` registration). The engine still
  iterates the hand-maintained `RULES` const; the new slice is initially
  empty and unused. ~80–120 lines.
- **#9b — Migrate rules to self-register; delete the const.** Every rule
  file gains a `#[distributed_slice(REGISTERED_RULES)]` registration; the
  hand-maintained `RULES` slice and the `pub mod ...;` declarations in
  `mod.rs` go away (modules can be discovered via `build.rs` generating the
  declarations from the directory listing). Engine swaps to the linkme slice.
  ~400–600 lines, mostly mechanical 1-line registrations per rule.

### 10. Collapse the lint + record + capture sequence — in the proxy crate, not the rule crate

Across the proxy submodules the sequence
```rust
let violations = lint::lint_transaction(&tx, &shared.cfg, &shared.state, &shared.engine);
tx.violations = violations.clone();
shared.state.record_transaction(&tx);
let _ = captures.write_transaction(&tx).await;
```
appears in **three** places (`proxy/http.rs`, `proxy/websocket.rs`,
`proxy/http3.rs`). The ordering is load-bearing: state must be recorded
*after* lint, otherwise the current tx shows up in its own history. That
invariant is maintained by convention, not by the type system. (The early
error paths add a secondary duplication via `build_and_write_transaction`.)

**Rejected fix.** The straightforward `lint::Engine { cfg, state,
rules_engine, captures }` that owns the cycle would *bind the rule library to
the proxy's IO surface* (state store + capture writer). That breaks #18: a
`lint-http lint <captures.jsonl>` subcommand that re-runs rules over an
existing capture file has no proxy, no live state store, and no on-the-fly
capture writer. If `Engine` insists on owning all four, the rule crate stops
being usable from a CLI that has only capture files and a config.

**Proposed.**

- Keep `lint_transaction(tx, cfg, history) -> Vec<Violation>` — pure, IO-free,
  in the rule crate. Untouched.
- Move the orchestration into the *proxy* crate: a
  `proxy::TransactionPipeline { state, captures }` that takes a
  `(HttpTransaction, Vec<Violation>)` and runs record-then-capture in the
  required order, behind one method call.
- The three call-sites become `pipeline.commit(tx, lint_transaction(&tx,
  ...)).await?`. The load-bearing ordering invariant lives in
  `TransactionPipeline`, not on the rule crate's public surface.
- Same shape for the protocol-event side.

- **Size:** S–M
- **Complexity:** Low.
- **Gains:** One canonical proxy pipeline (no duplicated sequence), a single
  seam for backpressure (#4) and instrumentation, but the rule library stays
  usable from a non-proxy caller — exactly what #18 needs.

### 11. Generate per-rule docs from rule metadata

`docs/rules/` has 184 hand-written markdown files (plus `TEMPLATE.md`) mirrored
against `src/rules/`, with a hand-maintained `docs/rules.md` index. This is a
documentation-drift trap: rule logic can change without the doc being updated,
and `config_example.toml` is already kept in sync only via a test assertion.
There is no test that the markdown matches the rule.

**Proposed:**

- Rule trait gains optional metadata: `fn description(&self) -> &'static str`,
  `fn rfc_reference(&self) -> Option<&'static str>`,
  `fn examples(&self) -> &'static [(Compliant | NonCompliant, &'static str)]`.
- A `cargo run --bin gendocs` (or `xtask`) renders `docs/rules/<id>.md` and
  `docs/rules.md` from the trait. CI fails if the on-disk docs diverge from
  what would be regenerated.

**Modularity constraint.** Any types referenced by the metadata — a
`Compliance::{Compliant, NonCompliant}` enum used by `examples()`, an
`RfcReference` struct, a `Severity` recommendation type — must live in the
rule crate alongside the trait, not in a downstream `gendocs` or proxy
crate. Otherwise external rule packs inherit a docs-tooling dependency just
to declare metadata. The metadata itself is intrinsic to the rule (unlike
`QueryType` in #7, which is intrinsic to the engine), so it belongs on the
trait — but only if its types live there too.

- **Size:** L (one-time tool + per-rule attribute fill-in)
- **Complexity:** Medium.
- **Gains:** Single source of truth for what each rule does; dramatically
  reduces the cost of adding/editing rules; lets the rule library
  self-describe over an API (e.g., a future `--list-rules --json` CLI).

**Atomic-commit decomposition.**

- **#11a — Add metadata methods to `Rule` / `ProtocolRule` with empty
  defaults.** `description() -> &'static str { "" }`, `rfc_reference() ->
  Option<&'static str> { None }`, `examples() -> &'static [Example] { &[] }`.
  Add the `Compliance` enum and `Example` struct in the rule crate (per the
  modularity constraint above). No rule changes. ~80–120 lines.
- **#11b — Add a `gendocs` binary.** `cargo run --bin gendocs` reads each
  rule's metadata and writes `docs/rules/<id>.md` and `docs/rules.md`.
  Initially produces near-empty files since defaults are empty. ~150–250
  lines.
- **#11c — Fill in per-rule metadata.** Override the metadata methods on
  every rule with real content. ~1–2 k lines; batchable by category
  (`client_*`, `server_*`, `message_*`, `stateful_*`, `semantic_*`,
  `protocol`) if a single commit is too large for review.
- **#11d — Add CI gate that fails on docs drift.** A test (or workflow
  step) that runs `gendocs` to a temp directory and `diff`s against
  `docs/rules/`. ~30 lines + CI config.

---

## Tier 3 — Robustness & Hygiene

### 12. Replace verbose poison-handling with `parking_lot` (or helpers)

`StateStore` (`src/state.rs`) and `ProtocolEventStore` repeat the pattern
```rust
match self.store.read() {
    Ok(g) => ...,
    Err(_) => { tracing::warn!("... lock poisoned during read"); ... },
}
```
~6–8 times over `std::sync::RwLock`. Tests deliberately poison the locks to
exercise the recovery paths, padding the file with cases that test
infrastructure rather than behaviour.

**Proposed:**

- Switch to `parking_lot::RwLock`, which has no poisoning. Drop all the
  poison-recovery branches and their tests.
- If `std::sync::RwLock` is preferred, extract a small helper:
  `fn read_or_warn<T, R>(&self, op: impl FnOnce(&T) -> R) -> Option<R>`.

- **Size:** S
- **Complexity:** Low.
- **Gains:** Shrinks `state.rs` (currently ~950 lines), removes test theater,
  and is marginally faster (parking_lot is faster on contention).

### 13. Live captures stream / control endpoint

The proxy already exposes `/_lint_http/cert`. Adding a Server-Sent-Events or
WebSocket endpoint at `/_lint_http/stream` that pushes each `CaptureRecord` as
JSONL would make the dev loop substantially better — no more `tail -f
captures.jsonl`, and external dashboards become trivial.

This pairs naturally with the writer task in #4: one `mpsc::Sender` feeds disk,
another (or a `tokio::broadcast`) feeds live subscribers.

- **Size:** M
- **Complexity:** Low.
- **Gains:** Significant developer-experience improvement; opens the door to a
  small TUI/web UI without changes to the rule engine.

### 14. Consolidate the outbound HTTP client + cache the root cert store

Two outbound paths exist:
- A `LegacyClient` (`hyper-rustls` + native roots) built once at proxy startup
  (`src/proxy/mod.rs`) for normal forwarding.
- `connect_upstream_for_upgrade` (`src/proxy/websocket.rs`) builds a fresh
  `RootCertStore` from `rustls_native_certs::load_native_certs()` on **every**
  WebSocket-upgrade connection.

The per-request rebuild is pure waste, and the two outbound shapes duplicate
trust-store and TLS-config construction with no shared home. (Note: the upgrade
path already degrades gracefully — it returns an `anyhow::Err` when no certs
load rather than panicking, so the old "startup `expect` panic" concern no
longer applies.)

**Proposed:**

- Build the `RootCertStore` once in `Shared` and reuse it for both code paths.
- Wrap the two outbound shapes in a single `Upstream` enum or struct so future
  features (HTTP/3 outbound, connection pooling tweaks, mTLS) have one home.
- Optional hardening: fall back to `webpki-roots` with a warn-level log when
  native trust is unavailable, so a developer tool never hard-fails on a
  missing platform trust store.

- **Size:** S–M
- **Complexity:** Low.
- **Gains:** Removes a per-request rebuild of the trust store and structural
  duplication between the two outbound paths.

### 15. Connection accept controls + graceful shutdown

`run_proxy_with_limit` (`src/proxy/mod.rs`) accepts unconditionally and spawns a
task per connection, with no concurrency cap, no graceful shutdown beyond the
`accept_limit` test counter, and no signal handling (the comment in `main.rs`
even says "no signal handling here"). A 60-second cleanup interval task runs,
but nothing drains in-flight work on exit. On burst load, memory and FD
pressure are unbounded.

**Proposed:**

- A `tokio::sync::Semaphore` bounding live connections (configurable; default
  generous like 1024).
- A `CancellationToken` (or `tokio::select!` against `tokio::signal::ctrl_c`)
  that lets the accept loop and outstanding handlers drain on shutdown,
  flushing the capture writer before exit.
- Optional: per-IP rate limit (token bucket) for hardening.

- **Size:** M
- **Complexity:** Medium.
- **Gains:** Predictable resource use under load, clean shutdown (no truncated
  capture lines, no orphaned tokio tasks), and a foundation for an integration
  test harness that exercises shutdown.

### 16. `Arc<HttpTransaction>` in state to remove deep clones

`StateStore::record_transaction` does `deque.push_front(tx.clone())`, cloning
the entire transaction (headers, trailers, body bytes) on push, and
`get_history*` clones again (`.cloned()`) on read. Bodies are `Bytes` (cheap),
but `HeaderMap` clone is real, and at high `max_history` this matters.

**Proposed:**

- Store `Arc<HttpTransaction>` in the deque. `record_transaction` takes
  `Arc<HttpTransaction>` (or wraps internally); queries return
  `Vec<Arc<HttpTransaction>>`.
- Optionally trim what state holds: rules don't need bodies post-record;
  storing only headers + small fields would shave more.

- **Size:** S
- **Complexity:** Low (touches one signature plus query layer).
- **Gains:** Lower allocation pressure on hot path; modest CPU win; trivial to
  measure.

---

## Tier 4 — Hygiene

### 17. CLI / packaging polish

Five independent hygiene items collected here. Each is its own atomic commit.

- **#17a — Move `make_temp_captures_path` and `make_temp_config_path`
  behind `#[cfg(test)]`** (or under a `test-utils` Cargo feature). They're
  test fixtures currently exposed as `pub` in `lib.rs`. ~10–20 lines.
- **#17b — Lower `cognitive-complexity-threshold` to clippy default and
  refactor the offenders.** `clippy.toml` sets the threshold to 30 (twice
  the default). After #1 and #8 land the offender list shrinks; what's left
  should be refactored rather than have the budget expanded.
  ~50–150 lines.
- **#17c — Reconcile the coverage threshold mismatch.** `.cargo/config.toml`
  says `--fail-under 95`, `docs/development.md` says "Minimum **90%**".
  Pick one and update the other. ~5 lines.
- **#17d — Decide CHANGELOG.md fate.** It says "Three built-in rules" and
  is otherwise stale (the catalogue is now 184 rules). Either delete it or
  wire up `git-cliff` / `release-please` to populate it from commit history.
  ~10–80 lines depending on the choice.
- **#17e — Audit Cargo.toml feature flags.** `tokio = { features = ["full"] }`
  and `hyper = { features = ["full"] }` are broad opt-ins. Trim to
  actually-used features. ~30–80 lines.

- **Size:** S each (collectively still S–M).
- **Complexity:** Low.
- **Gains:** Smaller surface area, less drift, faster builds.

### 18. CLI subcommands

The binary takes only `--config` (`src/main.rs`). Useful subcommands fall out
naturally and each is its own atomic commit.

- **#18a — Clap subcommand scaffold.** Restructure `main.rs` so today's
  behaviour lives under `lint-http run --config ...`, with `clap` parsing
  subcommands. No new functionality, just routing. ~80 lines.
- **#18b — `lint-http lint <captures.jsonl>`.** Re-runs rules over an
  existing capture file (no proxy). Depends on #5 (lossless capture schema)
  to round-trip headers correctly and on #8c (engine-free `lint_transaction`)
  to drive the engine without a `RuleConfigEngine`. ~150–250 lines.
- **#18c — `lint-http rules list [--format json]`.** Iterates the rule
  registry and prints id / scope / metadata; depends on #11a. ~80 lines.
- **#18d — `lint-http gendocs`.** Wires the binary from #11b into the CLI
  surface. ~30 lines.

- **Size:** M aggregate, S each.
- **Complexity:** Low.
- **Gains:** Brings `lint-http` closer to a generic HTTP linter usable in CI
  pipelines, not just a runtime proxy. This is the single biggest win for
  positioning the project as a "linter" rather than a "proxy that lints".

---

## Suggested ordering

The center of gravity is **#2** (workspace split into `lint-http-core`,
`lint-http-rules`, `lint-http-proxy`). Everything below either *enables* that
split by stripping engine concerns out of the rule trait, or *exploits* it
once the boundary lands. Land the rule-engine cleanups first so the split
itself reduces to a `Cargo.toml` exercise plus visibility tightening, not a
mid-flight redesign.

**Path A — Rule-library hardening.** Each numbered step is one atomic commit
that compiles and passes tests on its own. Sub-step labels (`8a`, `8b`, …)
correspond to the decompositions in the relevant item bodies above.

1. ~~**#1** — split `proxy.rs`~~ ✅ done.
2. ~~**#6** — wire `RuleScope` into dispatch~~ ✅ done.
3. ~~**#8a** — Add a `check(&self, tx, history, cfg, engine)` method to
   `Rule`/`ProtocolRule` with a delegating default impl; engine dispatch
   switches to call it~~ ✅ done (commit `9514afc`).
4. **#8b** — *(next)* Migrate every rule to override `check` directly (drop
   `check_transaction`, set `type Config = ()`, parse inline). Tests
   migrate from passing parsed `RuleConfig` / custom configs to passing a
   `&Config`. Single bulk commit if reviewable; otherwise batch by category
   (`client_*`, `server_*`, `message_*`, `stateful_*`, `semantic_*`,
   `protocol`) — each batch is independently atomic thanks to #8a's bridge.
5. ~~**#8c** — Delete legacy machinery (`type Config`, `validate_and_box`,
   legacy `check_transaction`/`check_event`, `RuleConfigValidator`,
   `RuleConfigEngine`, `ProtocolRuleConfigValidator`, cascading `engine`
   parameter); rename `check` → `check_transaction`/`check_event`; add
   object-safe `Rule::validate`.~~ ✅ done.
6. **#7** — *(next)* Stateful query needs off the trait (pair-the-slice or
   `StatefulRule` companion). Easier after #8 because the trait is
   `dyn`-clean.
7. **#9a** — Wire `linkme` infrastructure alongside the existing `RULES`
   const; engine still uses the const.
8. **#9b** — Migrate rules to self-register; delete the hand-maintained
   const and `pub mod` declarations (with `build.rs` discovering modules
   from the directory listing).
9. **#10** — `proxy::TransactionPipeline` collapses the three duplicated
   `lint → record → capture` call-sites without dragging IO into the rule
   crate.
10. **#11a** — Add `description()` / `rfc_reference()` / `examples()` to
    `Rule`/`ProtocolRule` with empty defaults; introduce `Compliance` and
    `Example` types in the rule crate.
11. **#11b** — Add `gendocs` binary that consumes the metadata.
12. **#11c** — Fill per-rule metadata. Single commit if reviewable;
    otherwise batched by rule category.
13. **#11d** — CI gate that fails on `docs/rules/` drift vs. regenerated
    output.
14. **#2** — Workspace split into `lint-http-core`, `lint-http-rules`,
    `lint-http-proxy`. The payoff: rule crate's public API now has no
    engine-shaped types and the split reduces to a `Cargo.toml` exercise plus
    visibility tightening.

**Path B — Independent tracks.** Don't touch the rule trait; can run in
parallel with Path A. One atomic commit each unless noted.

- **#5** — Lossless capture schema. The silent header-collapsing bug is a
  correctness issue, not just architecture; worth fixing before more
  captures pile up in the wild. Touches capture and serde only. May want to
  ship a one-shot migrator as a follow-up commit.
- **#3** — Streaming proxy body pipeline. XL change touching every error
  path; if needed, split into "introduce bounded body type + capture-prefix
  tee" and "swap body collection sites" as two atomic commits.
- **#4** — Dedicated capture writer task with bounded mpsc.

**Path C — Opportunistic (Tier 3/4), one atomic commit per item:**

- **#12** — Replace verbose poison-handling with `parking_lot` (or helpers).
- **#13** — Live captures stream / control endpoint.
- **#14** — Consolidate the outbound HTTP client + cache the root cert store.
- **#15** — Connection accept controls + graceful shutdown.
- **#16** — `Arc<HttpTransaction>` in state to remove deep clones.
- **#17a–#17e** — Hygiene polish (five separate commits, see #17 above).
- **#18a–#18d** — CLI subcommands (four separate commits, see #18 above).
  Plan **#18b** *after* #2 and #8c so it exercises the new crate boundary
  and the engine-free `lint_transaction`, rather than reaching across them.
